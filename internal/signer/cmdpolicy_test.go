package signer

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestCommandPolicyDecideAllowlist(t *testing.T) {
	t.Parallel()
	cp := CommandPolicy{
		Mode:  CmdPolicyAllowlist,
		Allow: []string{`^systemctl (status|restart) `, `^journalctl`},
	}
	allowed, _, _, err := (PolicySet{cp}).Decide("systemctl status nginx")
	if err != nil || !allowed {
		t.Errorf("systemctl status debe permitirse (allowed=%v err=%v)", allowed, err)
	}
	allowed, _, rule, err := (PolicySet{cp}).Decide("rm -rf /")
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Error("rm -rf / no debe permitirse en allowlist")
	}
	if rule != "allowlist:no-match" {
		t.Errorf("rule = %q, quiero allowlist:no-match", rule)
	}
}

func TestCommandPolicyDecideDenylist(t *testing.T) {
	t.Parallel()
	cp := CommandPolicy{
		Mode: CmdPolicyDenylist,
		Deny: []string{`rm\s+-rf`, `:\(\)\{`}, // rm -rf y fork bomb
	}
	if allowed, _, _, _ := (PolicySet{cp}).Decide("ls -la"); !allowed {
		t.Error("ls -la debe permitirse en denylist")
	}
	allowed, _, rule, _ := (PolicySet{cp}).Decide("sudo rm -rf /var")
	if allowed {
		t.Error("rm -rf debe denegarse")
	}
	if rule == "" {
		t.Error("debe reportar la regla que casó")
	}
}

func TestCommandPolicyDecideOff(t *testing.T) {
	t.Parallel()
	cp := CommandPolicy{} // empty Mode = off
	if allowed, _, _, _ := (PolicySet{cp}).Decide("cualquier cosa"); !allowed {
		t.Error("modo off debe permitir todo")
	}
}

func TestCommandPolicyRequireApproval(t *testing.T) {
	t.Parallel()
	cp := CommandPolicy{
		Mode:            CmdPolicyAllowlist,
		Allow:           []string{`^systemctl `},
		RequireApproval: []string{`^systemctl restart `},
	}
	// Permitido y sin aprobación.
	allowed, approval, _, _ := (PolicySet{cp}).Decide("systemctl status nginx")
	if !allowed || approval {
		t.Errorf("status: allowed=%v approval=%v", allowed, approval)
	}
	// Permitido pero requiere aprobación.
	allowed, approval, rule, _ := (PolicySet{cp}).Decide("systemctl restart nginx")
	if !allowed || !approval {
		t.Errorf("restart: allowed=%v approval=%v", allowed, approval)
	}
	if rule != "require_approval:^systemctl restart " {
		t.Errorf("rule = %q", rule)
	}
}

func TestCommandPolicyBadRegex(t *testing.T) {
	t.Parallel()
	cp := CommandPolicy{Mode: CmdPolicyAllowlist, Allow: []string{`(unclosed`}}
	if _, _, _, err := (PolicySet{cp}).Decide("x"); err == nil {
		t.Error("esperaba error por regex inválida")
	}
}

func TestCommandPolicyRestricts(t *testing.T) {
	t.Parallel()
	if (CommandPolicy{}).Restricts() {
		t.Error("política vacía no restringe")
	}
	if !(CommandPolicy{Mode: CmdPolicyAllowlist}).Restricts() {
		t.Error("allowlist restringe")
	}
	if !(CommandPolicy{RequireApproval: []string{"x"}}).Restricts() {
		t.Error("require_approval restringe (sesiones no verificables)")
	}
}

// --- Integración con Resolve ---

func cmdPolicyTable() PolicyTable {
	return PolicyTable{
		"locked": {
			Principal: "host:locked", MaxTTL: 2 * time.Minute,
			CommandPolicy: CommandPolicy{Mode: CmdPolicyAllowlist, Allow: []string{`^uptime$`}},
		},
		"approval": {
			Principal: "host:approval", MaxTTL: 2 * time.Minute,
			CommandPolicy: CommandPolicy{RequireApproval: []string{`^reboot`}},
		},
	}
}

func TestResolveCommandAllowed(t *testing.T) {
	t.Parallel()
	d, err := cmdPolicyTable().Resolve(Intent{
		Caller: "x", Host: "locked", Role: RoleTarget, Purpose: PurposeOneshot,
		Command: "uptime", RequestedTTL: time.Minute,
	}, 5*time.Minute)
	if err != nil {
		t.Fatalf("uptime debe permitirse: %v", err)
	}
	if d.Constraints.ForceCommand != "uptime" {
		t.Errorf("force-command = %q", d.Constraints.ForceCommand)
	}
}

func TestResolveCommandDenied(t *testing.T) {
	t.Parallel()
	_, err := cmdPolicyTable().Resolve(Intent{
		Caller: "x", Host: "locked", Role: RoleTarget, Purpose: PurposeOneshot,
		Command: "rm -rf /", RequestedTTL: time.Minute,
	}, 5*time.Minute)
	if err == nil {
		t.Fatal("rm -rf / debe denegarse por command_policy")
	}
}

func TestResolveCommandPolicyRejectsSession(t *testing.T) {
	t.Parallel()
	// Sessions are not verifiable on hosts with command_policy.
	_, err := cmdPolicyTable().Resolve(Intent{
		Caller: "x", Host: "locked", Role: RoleTarget, Purpose: PurposeSession,
		RequestedTTL: time.Minute,
	}, 5*time.Minute)
	if err == nil {
		t.Fatal("sesión debe rechazarse en host con command_policy")
	}
}

func TestResolveCommandRequireApprovalSurfaced(t *testing.T) {
	t.Parallel()
	d, err := cmdPolicyTable().Resolve(Intent{
		Caller: "x", Host: "approval", Role: RoleTarget, Purpose: PurposeOneshot,
		Command: "reboot now", RequestedTTL: time.Minute,
	}, 5*time.Minute)
	if err != nil {
		t.Fatalf("reboot está permitido (mode off) pero requiere aprobación: %v", err)
	}
	if !d.RequireApproval {
		t.Error("Decision.RequireApproval debe ser true")
	}
}

// testCASigner creates an ssh.Signer to use as CA in issuance tests.
func testCASigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// testEphemeralPub generates an ephemeral public key for the intent.
func testEphemeralPub(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return sshPub
}

func TestSignIntentApprovalGate(t *testing.T) {
	t.Parallel()
	policy := PolicyTable{
		"approval": {
			Principal: "host:approval", MaxTTL: time.Minute,
			CommandPolicy: CommandPolicy{RequireApproval: []string{`^reboot`}},
		},
	}
	l := NewLocal(testCASigner(t), policy, time.Minute)
	base := Intent{
		Host: "approval", Role: RoleTarget, Purpose: PurposeOneshot,
		Command: "reboot now", RequestedTTL: time.Minute, PublicKey: testEphemeralPub(t),
	}

	// Without approval: requires approval → no certificate issued.
	noApproval := base
	issued, err := l.SignIntent(context.Background(), noApproval)
	if err != nil {
		t.Fatalf("must not error, must return decision: %v", err)
	}
	if issued.Certificate != nil {
		t.Error("without approval no certificate must be issued")
	}
	if issued.Decision == nil || !issued.Decision.RequireApproval {
		t.Errorf("decision must set require_approval: %+v", issued.Decision)
	}

	// With approval: certificate is issued.
	approved := base
	approved.Approved = true
	issued2, err := l.SignIntent(context.Background(), approved)
	if err != nil {
		t.Fatal(err)
	}
	if issued2.Certificate == nil {
		t.Error("with approval a certificate must be issued")
	}
}

func TestCommandPolicyShellParse(t *testing.T) {
	t.Parallel()

	allowPs := CommandPolicy{
		Mode:       CmdPolicyAllowlist,
		Allow:      []string{`^ps aux$`},
		ShellParse: true,
	}
	allowPsAndGrep := CommandPolicy{
		Mode:       CmdPolicyAllowlist,
		Allow:      []string{`^ps aux$`, `^grep `},
		ShellParse: true,
	}
	denylistParse := CommandPolicy{
		Mode:       CmdPolicyDenylist,
		Deny:       []string{`^kill `},
		ShellParse: true,
	}

	tests := []struct {
		name        string
		cp          CommandPolicy
		command     string
		wantAllowed bool
		wantErrNil  bool
	}{
		// Simple command → passes just like without shell_parse.
		{"simple allowed", allowPs, "ps aux", true, true},
		// Compound: ps pasa pero kill no → denegado.
		{"compound &&", allowPs, "ps aux && kill -9 1", false, true},
		// Compound con ;
		{"compound ;", allowPs, "ps aux; rm -rf /", false, true},
		// Pipe: ps pasa pero grep no está en la allowlist → denegado.
		{"pipe grep not in allow", allowPs, "ps aux | grep nginx", false, true},
		// Pipe: ambos comandos en allowlist → permitido.
		{"pipe both allowed", allowPsAndGrep, "ps aux | grep nginx", true, true},
		// Subshell → denegado incondicionalmente (error de parse estructural).
		{"cmdsubst denied", allowPs, "$(cat /etc/passwd)", false, false},
		// Redirect a archivo → denegado.
		{"file redirect denied", allowPs, "ps aux > /tmp/out", false, false},
		// Redirect fd→fd (2>&1) → permitido siempre que el comando pase.
		{"fd redirect allowed", allowPs, "ps aux 2>&1", true, true},
		// Denylist con shell_parse: kill en pipeline → denegado.
		{"denylist pipeline kill", denylistParse, "ps aux | kill -9 1", false, true},
		// Denylist con shell_parse: comando limpio → permitido.
		{"denylist pipeline clean", denylistParse, "ps aux | grep nginx", true, true},
		// Backward compat: shell_parse=false, compound pasa sin analizar.
		{"no shell_parse backward compat", CommandPolicy{
			Mode: CmdPolicyAllowlist, Allow: []string{`^ps`}, ShellParse: false,
		}, "ps aux && kill -9 1", true, true},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			allowed, _, _, err := PolicySet{tc.cp}.Decide(tc.command)
			if tc.wantErrNil && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tc.wantErrNil && err == nil {
				t.Fatal("expected error but got nil")
			}
			if allowed != tc.wantAllowed {
				t.Errorf("allowed=%v, want %v (err=%v)", allowed, tc.wantAllowed, err)
			}
		})
	}
}

func TestCommandPolicyShellParseApprovalAccumulates(t *testing.T) {
	t.Parallel()
	cp := CommandPolicy{
		Mode:            CmdPolicyAllowlist,
		Allow:           []string{`^systemctl `},
		RequireApproval: []string{`^systemctl restart `},
		ShellParse:      true,
	}

	// El comando que requiere aprobación va primero: el segundo comando de la
	// cadena no debe "limpiar" el flag (regresión: needsApproval se
	// sobrescribía en cada iteración en vez de acumularse).
	allowed, needsApproval, rule, err := (PolicySet{cp}).Decide("systemctl restart nginx && systemctl status nginx")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !allowed {
		t.Fatal("chain must be allowed")
	}
	if !needsApproval {
		t.Error("needsApproval must survive a later command that does not require approval")
	}
	if rule != "require_approval:^systemctl restart " {
		t.Errorf("rule = %q, want the matched approval rule", rule)
	}

	// Orden inverso: también debe requerir aprobación.
	_, needsApproval, _, err = PolicySet{cp}.Decide("systemctl status nginx && systemctl restart nginx")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !needsApproval {
		t.Error("needsApproval must be set when a later command requires approval")
	}

	// Sin comando de aprobación en la cadena → no requiere aprobación.
	_, needsApproval, _, err = PolicySet{cp}.Decide("systemctl status nginx && systemctl status redis")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if needsApproval {
		t.Error("needsApproval must be false when no command matches require_approval")
	}
}

func TestResolveDryRunInfoViaLocal(t *testing.T) {
	t.Parallel()
	// SignIntent en dry-run no debe emitir cert y debe reportar la decisión.
	l := NewLocal(nil, cmdPolicyTable(), 5*time.Minute)
	// Comando denegado → Allowed=false, sin error.
	issued, err := l.SignIntent(context.Background(), Intent{
		Host: "locked", Role: RoleTarget, Purpose: PurposeOneshot,
		Command: "halt", RequestedTTL: time.Minute, DryRun: true,
	})
	if err != nil {
		t.Fatalf("dry-run no debe devolver error de política: %v", err)
	}
	if issued.Certificate != nil {
		t.Error("dry-run no debe emitir certificado")
	}
	if issued.Decision == nil || issued.Decision.Allowed {
		t.Errorf("decisión debe ser denegada: %+v", issued.Decision)
	}
}

func TestCommandPolicyValidate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		cp      CommandPolicy
		wantErr bool
	}{
		{"empty ok", CommandPolicy{}, false},
		{"valid allowlist", CommandPolicy{Mode: CmdPolicyAllowlist, Allow: []string{"^ps$", "^df -h"}}, false},
		{"valid denylist + approval", CommandPolicy{Mode: CmdPolicyDenylist, Deny: []string{"rm -rf"}, RequireApproval: []string{"^reboot"}}, false},
		{"bad allow regex", CommandPolicy{Mode: CmdPolicyAllowlist, Allow: []string{"("}}, true},
		{"bad deny regex", CommandPolicy{Mode: CmdPolicyDenylist, Deny: []string{"[z-a]"}}, true},
		{"bad require_approval regex", CommandPolicy{RequireApproval: []string{"*"}}, true},
		{"unknown mode", CommandPolicy{Mode: "blocklist"}, true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.cp.Validate()
			if tc.wantErr && err == nil {
				t.Fatalf("%s: expected error", tc.name)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("%s: unexpected error: %v", tc.name, err)
			}
		})
	}
}
