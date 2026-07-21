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

func TestResolveCommandPolicySessions(t *testing.T) {
	t.Parallel()
	// Exec sessions are allowed to open; each command is checked separately by
	// the broker through the same policy path.
	if _, err := cmdPolicyTable().Resolve(Intent{
		Caller: "x", Host: "locked", Role: RoleTarget, Purpose: PurposeSession,
		SessionMode: SessionModeExec, RequestedTTL: time.Minute,
	}, 5*time.Minute); err != nil {
		t.Fatalf("exec session open must be allowed on command_policy hosts: %v", err)
	}

	// Stateful shell/pty sessions remain rejected.
	_, err := cmdPolicyTable().Resolve(Intent{
		Caller: "x", Host: "locked", Role: RoleTarget, Purpose: PurposeSession,
		SessionMode:  SessionModeShell,
		RequestedTTL: time.Minute,
	}, 5*time.Minute)
	if err == nil {
		t.Fatal("shell session must be rejected on command_policy hosts")
	}

	// A per-command exec preflight enforces the policy.
	_, err = cmdPolicyTable().Resolve(Intent{
		Caller: "x", Host: "locked", Role: RoleTarget, Purpose: PurposeSession,
		SessionMode: SessionModeExec, Command: "rm -rf /", RequestedTTL: time.Minute,
	}, 5*time.Minute)
	if err == nil {
		t.Fatal("exec session command must be denied by command_policy")
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

// boolPtr returns a pointer to b, for the three-state CommandPolicy.ShellParse
// field (nil = parse on by default; &false = explicit opt-out).
func boolPtr(b bool) *bool { return &b }

func TestCommandPolicyShellParse(t *testing.T) {
	t.Parallel()

	allowPs := CommandPolicy{
		Mode:       CmdPolicyAllowlist,
		Allow:      []string{`^ps aux$`},
		ShellParse: boolPtr(true),
	}
	allowPsAndGrep := CommandPolicy{
		Mode:       CmdPolicyAllowlist,
		Allow:      []string{`^ps aux$`, `^grep `},
		ShellParse: boolPtr(true),
	}
	denylistParse := CommandPolicy{
		Mode:       CmdPolicyDenylist,
		Deny:       []string{`^kill `},
		ShellParse: boolPtr(true),
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
		// fd→fd variants must stay allowed: 1>&2 (dup) and 2>&- (close).
		{"fd dup 1>&2 allowed", allowPs, "ps aux 1>&2", true, true},
		{"fd close 2>&- allowed", allowPs, "ps aux 2>&-", true, true},
		// #175 vector 1: >&FILE is a FILE WRITE (bash/zsh), not an fd dup. The
		// operator alone must not classify it as safe — it must be rejected like
		// any file redirect, or it bypasses the allowlist and the baked
		// force-command writes the file (arbitrary write / RCE).
		{"dup-fd to file denied (>&)", allowPs, "ps aux >& /tmp/out", false, false},
		{"dup-fd to file denied (<&)", allowPs, "ps aux <& /tmp/in", false, false},
		// #175 vector 2: environment mutations before an allowed command are
		// invisible to the allowlist but baked into the force-command, where they
		// change how the following command runs (GIT_SSH_COMMAND, LD_PRELOAD, …).
		{"standalone assignment denied", allowPs, "GIT_SSH_COMMAND=x; ps aux", false, false},
		{"export denied", allowPs, "export LD_PRELOAD=/tmp/e.so; ps aux", false, false},
		{"declare denied", allowPs, "declare -x PATH=/tmp/evil; ps aux", false, false},
		// Denylist con shell_parse: kill en pipeline → denegado.
		{"denylist pipeline kill", denylistParse, "ps aux | kill -9 1", false, true},
		// Denylist con shell_parse: comando limpio → permitido.
		{"denylist pipeline clean", denylistParse, "ps aux | grep nginx", true, true},
		// Explicit opt-out: shell_parse=false restores raw-string matching, so a
		// compound command rides past an allowlist that only matches its prefix.
		{"explicit opt-out (shell_parse:false)", CommandPolicy{
			Mode: CmdPolicyAllowlist, Allow: []string{`^ps`}, ShellParse: boolPtr(false),
		}, "ps aux && kill -9 1", true, true},
		// Default (shell_parse absent → nil) now PARSES: the same compound command
		// against the same allowlist is denied (#211). Contrast with the case above.
		{"default parses compound (#211)", CommandPolicy{
			Mode: CmdPolicyAllowlist, Allow: []string{`^ps`},
		}, "ps aux && kill -9 1", false, true},
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

// TestCommandPolicyQuotingBypassClosed is the #277 acceptance criterion: the
// deny/require_approval firewall must match the DECODED command, not the
// caller's quoting. The target shell strips quotes/encoding at exec time, so a
// wrapped command name (or an $IFS/inline-env trick) must not slip past a rule
// the executed command would hit. Decoding is symmetric: a legitimately quoted
// command that decodes to an allowed/approval form is still allowed/gated.
func TestCommandPolicyQuotingBypassClosed(t *testing.T) {
	t.Parallel()

	deny := CommandPolicy{Mode: CmdPolicyDenylist, Deny: []string{`^rm `, `^reboot`}}
	allow := CommandPolicy{Mode: CmdPolicyAllowlist, Allow: []string{`^ps aux$`}}
	approval := CommandPolicy{Mode: CmdPolicyDenylist, RequireApproval: []string{`^reboot`}}

	tests := []struct {
		name         string
		cp           CommandPolicy
		command      string
		wantAllowed  bool
		wantApproval bool
		wantErrNil   bool
	}{
		// Denylist ^rm : every quoting/encoding of the command name must be denied.
		{"plain rm denied", deny, "rm -rf /data", false, false, true},
		{"single-quoted rm denied", deny, "'rm' -rf /data", false, false, true},
		{"partial-quoted rm denied", deny, `r"m" -rf /data`, false, false, true},
		{"double-quoted rm denied", deny, `"rm" -rf /data`, false, false, true},
		{"ansi-c rm denied", deny, `$'\x72\x6d' -rf /data`, false, false, true},
		// $IFS and inline env are unknowable/invisible to the policy → fail closed
		// (rejected with an error, hence denied).
		{"IFS-separated rm rejected", deny, "rm$IFS-rf /data", false, false, false},
		{"inline env prefix rejected", deny, "LD_PRELOAD=/e.so rm -rf /data", false, false, false},
		{"quoted reboot denied", deny, "'reboot'", false, false, true},
		// Allowlist ^ps aux$: a legitimately quoted command that decodes to the
		// allowed form is still allowed (decoding is symmetric, no false denial).
		{"plain ps allowed", allow, "ps aux", true, false, true},
		{"quoted ps allowed", allow, "'ps' aux", true, false, true},
		{"quoted-arg ps allowed", allow, `ps "aux"`, true, false, true},
		// require_approval ^reboot: quoting must not drop the approval gate.
		{"plain reboot needs approval", approval, "reboot", true, true, true},
		{"quoted reboot needs approval", approval, "'reboot'", true, true, true},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			allowed, approval, _, err := PolicySet{tc.cp}.Decide(tc.command)
			if tc.wantErrNil && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tc.wantErrNil && err == nil {
				t.Fatal("expected a fail-closed error but got nil")
			}
			if allowed != tc.wantAllowed {
				t.Errorf("allowed=%v, want %v (err=%v)", allowed, tc.wantAllowed, err)
			}
			if approval != tc.wantApproval {
				t.Errorf("approval=%v, want %v", approval, tc.wantApproval)
			}
		})
	}
}

// TestCommandPolicyDefaultParsesChainedCommands is the #211 acceptance criterion:
// with default config (no shell_parse set) an allowlist that matches only the
// first word must not let a chained command ride past it.
func TestCommandPolicyDefaultParsesChainedCommands(t *testing.T) {
	t.Parallel()
	cp := CommandPolicy{Mode: CmdPolicyAllowlist, Allow: []string{`^kubectl get `}}

	allowed, _, rule, err := (PolicySet{cp}).Decide("kubectl get pods; rm -rf /etc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if allowed {
		t.Fatalf("chained command must be denied by default (rule=%q)", rule)
	}
	// The allowlisted simple command alone still passes.
	if a, _, _, err := (PolicySet{cp}).Decide("kubectl get pods"); err != nil || !a {
		t.Errorf("the allowlisted simple command must still be allowed (allowed=%v err=%v)", a, err)
	}
}

func TestCommandPolicyShellParseApprovalAccumulates(t *testing.T) {
	t.Parallel()
	cp := CommandPolicy{
		Mode:            CmdPolicyAllowlist,
		Allow:           []string{`^systemctl `},
		RequireApproval: []string{`^systemctl restart `},
		ShellParse:      boolPtr(true),
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

func TestCommandPolicyAuditAllowsWithWarning(t *testing.T) {
	t.Parallel()
	policy := PolicyTable{
		"shadow": {
			Principal: "host:shadow", MaxTTL: time.Minute,
			CommandPolicy: CommandPolicy{
				Mode:        CmdPolicyAllowlist,
				Enforcement: CmdPolicyAudit,
				Allow:       []string{`^uptime$`},
			},
		},
	}
	d, err := policy.Resolve(Intent{
		Caller: "x", Host: "shadow", Role: RoleTarget, Purpose: PurposeOneshot,
		Command: "rm -rf /", RequestedTTL: time.Minute,
	}, 5*time.Minute)
	if err != nil {
		t.Fatalf("audit mode must not block command_policy denials: %v", err)
	}
	if d.CommandPolicyEnforcement != CmdPolicyAudit {
		t.Fatalf("enforcement=%q, want audit", d.CommandPolicyEnforcement)
	}
	if !d.WouldDeny || d.Warning == "" {
		t.Fatalf("audit decision must carry would-deny warning: %+v", d)
	}
	if d.Constraints.ForceCommand != "rm -rf /" {
		t.Errorf("force-command = %q", d.Constraints.ForceCommand)
	}
}

func TestCommandPolicyAuditSuppressesApprovalGate(t *testing.T) {
	t.Parallel()
	policy := PolicyTable{
		"shadow": {
			Principal: "host:shadow", MaxTTL: time.Minute,
			CommandPolicy: CommandPolicy{
				Enforcement:     CmdPolicyAudit,
				RequireApproval: []string{`^reboot`},
			},
		},
	}
	d, err := policy.Resolve(Intent{
		Caller: "x", Host: "shadow", Role: RoleTarget, Purpose: PurposeOneshot,
		Command: "reboot now", RequestedTTL: time.Minute,
	}, 5*time.Minute)
	if err != nil {
		t.Fatalf("audit mode must not gate require_approval: %v", err)
	}
	if d.RequireApproval {
		t.Fatal("audit mode must not require approval")
	}
	if !d.WouldRequireApproval || d.Warning == "" {
		t.Fatalf("audit decision must carry would-require-approval warning: %+v", d)
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
		// A pattern that its mode never evaluates is a silently-dropped control:
		// reject rather than ignore (regression guard for the k8s deny bug).
		{"deny on allowlist rejected", CommandPolicy{Mode: CmdPolicyAllowlist, Allow: []string{"^ps$"}, Deny: []string{"^rm "}}, true},
		{"allow on denylist rejected", CommandPolicy{Mode: CmdPolicyDenylist, Deny: []string{"^rm "}, Allow: []string{"^ps$"}}, true},
		{"unknown mode", CommandPolicy{Mode: "blocklist"}, true},
		{"unknown enforcement", CommandPolicy{Enforcement: "shadow"}, true},
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

// TestDirectArgv locks the classifier that decides whether an elevated command
// bypasses the /bin/sh -c wrapper (#306): only one statement of statically
// known words qualifies; every shell-semantic shape must fail closed to the
// wrapper. The argv must be the DECODED words (caller quoting removed), since
// that is what sudo will compare against the sudoers rule.
func TestDirectArgv(t *testing.T) {
	t.Parallel()
	simple := []struct {
		command string
		want    []string
	}{
		{"id", []string{"id"}},
		{"systemctl restart nginx.service", []string{"systemctl", "restart", "nginx.service"}},
		{"echo 'hello world'", []string{"echo", "hello world"}},
		{`echo "hi"`, []string{"echo", "hi"}},
		{"journalctl -u nginx --since -1h", []string{"journalctl", "-u", "nginx", "--since", "-1h"}},
		{"id;", []string{"id"}},                 // one statement, just terminated
		{`echo "a b"`, []string{"echo", "a b"}}, // quoted word keeps its space
		{`echo ""`, []string{"echo", ""}},       // empty word survives decode
		{"id # c", []string{"id"}},              // comment dropped, exactly as sh -c would
	}
	for _, c := range simple {
		argv, ok := directArgv(c.command)
		if !ok {
			t.Errorf("directArgv(%q) must classify as simple", c.command)
			continue
		}
		if len(argv) != len(c.want) {
			t.Errorf("directArgv(%q) = %q, want %q", c.command, argv, c.want)
			continue
		}
		for i := range argv {
			if argv[i] != c.want[i] {
				t.Errorf("directArgv(%q)[%d] = %q, want %q", c.command, i, argv[i], c.want[i])
			}
		}
	}

	compound := []string{
		"id | wc -l",           // pipe
		"id; id",               // sequence
		"id && id",             // and-list
		"id || id",             // or-list
		"id &",                 // background
		"! id",                 // negation
		"echo x > /tmp/f",      // file redirect
		"journalctl -u x 2>&1", // even fd-dup: without a shell nothing interprets it
		"FOO=1 id",             // inline env assignment
		"FOO=bar",              // standalone assignment
		"echo $HOME",           // parameter expansion
		"echo $(id)",           // command substitution
		"ls *.log",             // glob
		"cat {a,b}",            // brace expansion
		"ls ~/x",               // tilde expansion
		"(id)",                 // subshell
		"",                     // empty
		`touch a\\ b`,          // unquoted backslash escape (decode divergence)
		`echo \\$HOME`,         // escaped $ — literal to us, consumed by the shell
		"9=x systemctl status", // invalid-identifier assignment: sudo would eat it
		"=x id",                // ditto, leading '='
		"cd /tmp",              // shell-only builtin: no binary for sudo to exec
		"umask 022",            // ditto
		"export FOO=1",         // DeclClause, not a CallExpr
	}
	for _, cmd := range compound {
		if argv, ok := directArgv(cmd); ok {
			t.Errorf("directArgv(%q) must NOT classify as simple, got argv=%q", cmd, argv)
		}
	}
}
