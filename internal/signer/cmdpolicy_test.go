package signer

import (
	"testing"
	"time"
)

func TestCommandPolicyDecideAllowlist(t *testing.T) {
	cp := CommandPolicy{
		Mode:  CmdPolicyAllowlist,
		Allow: []string{`^systemctl (status|restart) `, `^journalctl`},
	}
	allowed, _, _, err := cp.Decide("systemctl status nginx")
	if err != nil || !allowed {
		t.Errorf("systemctl status debe permitirse (allowed=%v err=%v)", allowed, err)
	}
	allowed, _, rule, err := cp.Decide("rm -rf /")
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
	cp := CommandPolicy{
		Mode: CmdPolicyDenylist,
		Deny: []string{`rm\s+-rf`, `:\(\)\{`}, // rm -rf y fork bomb
	}
	if allowed, _, _, _ := cp.Decide("ls -la"); !allowed {
		t.Error("ls -la debe permitirse en denylist")
	}
	allowed, _, rule, _ := cp.Decide("sudo rm -rf /var")
	if allowed {
		t.Error("rm -rf debe denegarse")
	}
	if rule == "" {
		t.Error("debe reportar la regla que casó")
	}
}

func TestCommandPolicyDecideOff(t *testing.T) {
	cp := CommandPolicy{} // Mode vacío = off
	if allowed, _, _, _ := cp.Decide("cualquier cosa"); !allowed {
		t.Error("modo off debe permitir todo")
	}
}

func TestCommandPolicyRequireApproval(t *testing.T) {
	cp := CommandPolicy{
		Mode:            CmdPolicyAllowlist,
		Allow:           []string{`^systemctl `},
		RequireApproval: []string{`^systemctl restart `},
	}
	// Permitido y sin aprobación.
	allowed, approval, _, _ := cp.Decide("systemctl status nginx")
	if !allowed || approval {
		t.Errorf("status: allowed=%v approval=%v", allowed, approval)
	}
	// Permitido pero requiere aprobación.
	allowed, approval, rule, _ := cp.Decide("systemctl restart nginx")
	if !allowed || !approval {
		t.Errorf("restart: allowed=%v approval=%v", allowed, approval)
	}
	if rule != "require_approval:^systemctl restart " {
		t.Errorf("rule = %q", rule)
	}
}

func TestCommandPolicyBadRegex(t *testing.T) {
	cp := CommandPolicy{Mode: CmdPolicyAllowlist, Allow: []string{`(unclosed`}}
	if _, _, _, err := cp.Decide("x"); err == nil {
		t.Error("esperaba error por regex inválida")
	}
}

func TestCommandPolicyRestricts(t *testing.T) {
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
	_, err := cmdPolicyTable().Resolve(Intent{
		Caller: "x", Host: "locked", Role: RoleTarget, Purpose: PurposeOneshot,
		Command: "rm -rf /", RequestedTTL: time.Minute,
	}, 5*time.Minute)
	if err == nil {
		t.Fatal("rm -rf / debe denegarse por command_policy")
	}
}

func TestResolveCommandPolicyRejectsSession(t *testing.T) {
	// Las sesiones no son verificables en hosts con command_policy.
	_, err := cmdPolicyTable().Resolve(Intent{
		Caller: "x", Host: "locked", Role: RoleTarget, Purpose: PurposeSession,
		RequestedTTL: time.Minute,
	}, 5*time.Minute)
	if err == nil {
		t.Fatal("sesión debe rechazarse en host con command_policy")
	}
}

func TestResolveCommandRequireApprovalSurfaced(t *testing.T) {
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

func TestResolveDryRunInfoViaLocal(t *testing.T) {
	// SignIntent en dry-run no debe emitir cert y debe reportar la decisión.
	l := NewLocal(nil, cmdPolicyTable(), 5*time.Minute)
	// Comando denegado → Allowed=false, sin error.
	issued, err := l.SignIntent(Intent{
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
