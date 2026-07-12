package signer

import (
	"testing"
	"time"
)

// helper policies reused across the table tests.
var (
	allowUptime = CommandPolicy{Mode: CmdPolicyAllowlist, Allow: []string{"^uptime$"}}
	allowFree   = CommandPolicy{Mode: CmdPolicyAllowlist, Allow: []string{"^free( .*)?$"}}
	allowDocker = CommandPolicy{Mode: CmdPolicyAllowlist, Allow: []string{"^docker ps$"}}
	denyDocker  = CommandPolicy{Mode: CmdPolicyDenylist, Deny: []string{"^docker "}}
	denyRm      = CommandPolicy{Mode: CmdPolicyDenylist, Deny: []string{"^rm "}}
	approveRst  = CommandPolicy{RequireApproval: []string{"^systemctl restart "}}
)

func TestPolicySetDecideCompose(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name         string
		set          PolicySet
		command      string
		wantAllowed  bool
		wantApproval bool
		wantRulePart string // substring expected in rule ("" = skip)
	}{
		{"empty allows everything", PolicySet{}, "rm -rf /", true, false, ""},
		{"only denylist default-allows", PolicySet{denyRm}, "ls -la", true, false, ""},
		// Union of two allowlists: a command allowed by EITHER passes.
		{"union first allowlist", PolicySet{allowUptime, allowFree}, "uptime", true, false, "allow:"},
		{"union second allowlist", PolicySet{allowUptime, allowFree}, "free -h", true, false, "allow:"},
		{"union neither allowlist", PolicySet{allowUptime, allowFree}, "ls", false, false, "allowlist:no-match"},
		// Deny wins over an allowlist that would permit.
		{"deny overrides allow", PolicySet{allowDocker, denyDocker}, "docker ps", false, false, "deny:"},
		// Approval surfaces on an allowed command (union of require_approval).
		{"approval on allowed cmd", PolicySet{
			CommandPolicy{Mode: CmdPolicyAllowlist, Allow: []string{"^systemctl restart .*"}}, approveRst,
		}, "systemctl restart nginx", true, true, "require_approval:"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			allowed, approval, rule, err := tc.set.Decide(tc.command)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if allowed != tc.wantAllowed || approval != tc.wantApproval {
				t.Fatalf("Decide(%q) = (allowed=%v, approval=%v); want (%v, %v) [rule=%q]",
					tc.command, allowed, approval, tc.wantAllowed, tc.wantApproval, rule)
			}
			if tc.wantRulePart != "" && !contains(rule, tc.wantRulePart) {
				t.Fatalf("rule = %q; want to contain %q", rule, tc.wantRulePart)
			}
		})
	}
}

func TestPolicySetShellParseOR(t *testing.T) {
	t.Parallel()
	// The second member explicitly opts out (shell_parse:false), but the first
	// member's parsing must still apply to the whole set (stricter wins).
	set := PolicySet{
		CommandPolicy{Mode: CmdPolicyAllowlist, Allow: []string{"^ps( .*)?$"}, ShellParse: boolPtr(true)},
		CommandPolicy{Mode: CmdPolicyAllowlist, Allow: []string{"^head( .*)?$"}, ShellParse: boolPtr(false)},
	}
	if a, _, _, err := set.Decide("ps aux | head -n 5"); err != nil || !a {
		t.Fatalf("pipeline of allowed segments must pass: allowed=%v err=%v", a, err)
	}
	if a, _, r, _ := set.Decide("ps aux | awk '{print $1}'"); a {
		t.Fatalf("an un-allowed pipe segment must block the chain (rule=%q)", r)
	}
	if a, _, r, _ := set.Decide("ps aux > /tmp/x"); a || !contains(r, "shell-parse:") {
		t.Fatalf("a file redirect must be rejected by shell-parse: allowed=%v rule=%q", a, r)
	}
}

func TestPolicySetEnforcement(t *testing.T) {
	t.Parallel()
	auditAllow := CommandPolicy{Mode: CmdPolicyAllowlist, Enforcement: CmdPolicyAudit, Allow: []string{"^uptime$"}}
	enforceDeny := CommandPolicy{Mode: CmdPolicyDenylist, Deny: []string{"^rm "}}

	if got := (PolicySet{auditAllow}).Enforcement(); got != CmdPolicyAudit {
		t.Fatalf("single audit policy enforcement = %q, want audit", got)
	}
	if got := (PolicySet{auditAllow, enforceDeny}).Enforcement(); got != CmdPolicyEnforce {
		t.Fatalf("enforce must win over audit, got %q", got)
	}
	if got := (PolicySet{}).Enforcement(); got != CmdPolicyEnforce {
		t.Fatalf("empty policy defaults to enforce, got %q", got)
	}
}

// TestPolicySetSingleElement verifies a one-element PolicySet evaluates a lone
// inline policy as expected, so single-policy hosts behave as configured.
func TestPolicySetSingleElement(t *testing.T) {
	t.Parallel()
	cases := []struct {
		cp          CommandPolicy
		command     string
		wantAllowed bool
		wantApprove bool
	}{
		{allowUptime, "uptime", true, false},
		{allowUptime, "rm -rf /", false, false},
		{denyRm, "ls -la", true, false},
		{denyRm, "rm -rf /", false, false},
		{approveRst, "systemctl restart nginx", true, true},
		{approveRst, "uptime", true, false},
		{CommandPolicy{}, "anything goes", true, false}, // off
	}
	for _, tc := range cases {
		a, n, _, err := PolicySet{tc.cp}.Decide(tc.command)
		if err != nil {
			t.Errorf("Decide(%q) error: %v", tc.command, err)
		}
		if a != tc.wantAllowed || n != tc.wantApprove {
			t.Errorf("Decide(%q) = (allowed=%v, approve=%v), want (%v, %v)",
				tc.command, a, n, tc.wantAllowed, tc.wantApprove)
		}
	}
}

func TestCompileHostPoliciesCompose(t *testing.T) {
	t.Parallel()
	lib := map[string]CommandPolicy{
		"ro":        allowUptime,
		"dk":        allowDocker,
		"no-danger": denyRm,
	}
	groups := map[string][]string{
		"_default":   {"no-danger"},
		"monitoring": {"ro"},
		"docker":     {"dk"},
	}
	hosts := PolicyTable{
		"web1":  {Groups: []string{"monitoring", "docker"}},
		"plain": {}, // no groups: only _default applies
	}
	compiled, err := CompileHostPolicies(hosts, lib, groups)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	web1 := compiled["web1"].Policies
	if a, _, _, _ := web1.Decide("uptime"); !a {
		t.Error("web1 should allow uptime (monitoring group)")
	}
	if a, _, _, _ := web1.Decide("docker ps"); !a {
		t.Error("web1 should allow docker ps (docker group)")
	}
	if a, _, _, _ := web1.Decide("ls"); a {
		t.Error("web1 should deny ls (allowlists present, no match)")
	}
	if a, _, r, _ := web1.Decide("rm -rf /"); a || !contains(r, "deny:") {
		t.Errorf("web1 should deny rm via _default (rule=%q)", r)
	}

	// _default applies even to a host with no groups (and no allowlist => default-allow).
	plain := compiled["plain"].Policies
	if a, _, _, _ := plain.Decide("ls"); !a {
		t.Error("plain host with only a _default denylist should allow ls")
	}
	if a, _, _, _ := plain.Decide("rm -rf /"); a {
		t.Error("plain host should deny rm via _default")
	}
}

func TestCompileHostPoliciesDedup(t *testing.T) {
	t.Parallel()
	lib := map[string]CommandPolicy{"ro": allowUptime}
	groups := map[string][]string{"g1": {"ro"}, "g2": {"ro"}}
	hosts := PolicyTable{"h": {Groups: []string{"g1", "g2"}}}
	compiled, err := CompileHostPolicies(hosts, lib, groups)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(compiled["h"].Policies); got != 1 {
		t.Fatalf("policy reached via two groups must be deduped: len=%d want 1", got)
	}
}

func TestCompileHostPoliciesErrors(t *testing.T) {
	t.Parallel()
	t.Run("unknown policy ref", func(t *testing.T) {
		t.Parallel()
		_, err := CompileHostPolicies(PolicyTable{"h": {}}, nil, map[string][]string{"g": {"missing"}})
		if err == nil {
			t.Fatal("unknown policy reference must error")
		}
	})
	t.Run("bad regex in library", func(t *testing.T) {
		t.Parallel()
		lib := map[string]CommandPolicy{"bad": {Mode: CmdPolicyAllowlist, Allow: []string{"("}}}
		_, err := CompileHostPolicies(PolicyTable{}, lib, nil)
		if err == nil {
			t.Fatal("bad regex in the library must error")
		}
	})
	t.Run("bastion plus composed restriction", func(t *testing.T) {
		t.Parallel()
		lib := map[string]CommandPolicy{"ro": allowUptime}
		groups := map[string][]string{"g": {"ro"}}
		hosts := PolicyTable{"bas": {AllowAsBastion: true, Groups: []string{"g"}}}
		_, err := CompileHostPolicies(hosts, lib, groups)
		if err == nil {
			t.Fatal("a bastion that gains a command policy via a group must be rejected")
		}
	})
}

// TestComposedPolicyThroughResolve proves the composed policy is enforced
// end-to-end via PolicyTable.Resolve (the signing path), not only in PolicySet.
func TestComposedPolicyThroughResolve(t *testing.T) {
	t.Parallel()
	lib := map[string]CommandPolicy{"ro": allowUptime, "dk": allowDocker}
	groups := map[string][]string{"mon": {"ro"}, "dock": {"dk"}}
	compiled, err := CompileHostPolicies(
		PolicyTable{"web1": {Principal: "host:web1", MaxTTL: 2 * time.Minute, Groups: []string{"mon", "dock"}}},
		lib, groups)
	if err != nil {
		t.Fatal(err)
	}
	mk := func(cmd string) Intent {
		return Intent{Caller: "x", Host: "web1", Role: RoleTarget, Purpose: PurposeOneshot, Command: cmd, RequestedTTL: time.Minute}
	}
	if _, err := compiled.Resolve(mk("uptime"), 5*time.Minute); err != nil {
		t.Errorf("uptime (mon group) should resolve: %v", err)
	}
	if _, err := compiled.Resolve(mk("docker ps"), 5*time.Minute); err != nil {
		t.Errorf("docker ps (dock group) should resolve via union: %v", err)
	}
	if _, err := compiled.Resolve(mk("rm -rf /"), 5*time.Minute); err == nil {
		t.Error("rm must be denied by the composed allowlists")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
