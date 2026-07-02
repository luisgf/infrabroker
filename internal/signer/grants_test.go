package signer

import (
	"testing"
	"time"
)

// compiledWithDeny builds a policy table where web01 is allowlist-active
// (inline allow ^uptime$) AND carries a group denylist (^rm ), and db01 is
// unrestricted (default-allow). Used to exercise grant injection.
func compiledWithDeny(t *testing.T) PolicyTable {
	t.Helper()
	hosts := PolicyTable{
		"web01": {Principal: "host:web01", Groups: []string{"danger"}, CommandPolicy: CommandPolicy{
			Mode: CmdPolicyAllowlist, Allow: []string{"^uptime$"},
		}},
		"db01": {Principal: "host:db01"},
	}
	library := map[string]CommandPolicy{"no-danger": {Mode: CmdPolicyDenylist, Deny: []string{"^rm "}}}
	groups := map[string][]string{"danger": {"no-danger"}}
	compiled, err := CompileHostPolicies(hosts, library, groups)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return compiled
}

func oneshot(host, cmd string) Intent {
	return Intent{Host: host, Role: RoleTarget, Purpose: PurposeOneshot, Command: cmd}
}

// allowed reports whether resolve permits cmd on host given the grant store.
func allowed(t *testing.T, p PolicyTable, store GrantProvider, host, cmd string) bool {
	t.Helper()
	_, err := p.resolve(oneshot(host, cmd), 5*time.Minute, store)
	return err == nil
}

func TestGrantStoreAddListRevoke(t *testing.T) {
	t.Parallel()
	s := NewGrantStore()
	now := time.Now()

	id, err := s.Add(Grant{Host: "web01", Allow: []string{"^systemctl restart nginx$"}, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if id == "" {
		t.Fatal("empty grant id")
	}
	if got := s.List(now); len(got) != 1 || got[0].ID != id {
		t.Fatalf("list should show the grant: %+v", got)
	}
	if ok, err := s.Revoke(id); err != nil || !ok {
		t.Fatalf("revoke of existing grant should return true: ok=%v err=%v", ok, err)
	}
	if ok, err := s.Revoke(id); err != nil || ok {
		t.Fatalf("revoke of an already-removed grant should return false: ok=%v err=%v", ok, err)
	}
	if got := s.List(now); len(got) != 0 {
		t.Fatalf("list should be empty after revoke: %+v", got)
	}

	// Validation: empty allow and bad regex are rejected at Add.
	if _, err := s.Add(Grant{Host: "web01", ExpiresAt: now.Add(time.Hour)}); err == nil {
		t.Error("grant with no allow patterns should be rejected")
	}
	if _, err := s.Add(Grant{Host: "web01", Allow: []string{"("}, ExpiresAt: now.Add(time.Hour)}); err == nil {
		t.Error("grant with an invalid regex should be rejected")
	}
}

func TestGrantStoreExpiryAndScope(t *testing.T) {
	t.Parallel()
	s := NewGrantStore()
	now := time.Now()

	// Expired grant: present in the map but never live.
	expID, _ := s.Add(Grant{Host: "web01", Allow: []string{"^x$"}, ExpiresAt: now.Add(-time.Minute)})
	// Scoped grants.
	_, _ = s.Add(Grant{Host: "web01", Allow: []string{"^a$"}, ExpiresAt: now.Add(time.Hour)})                     // host-wide
	_, _ = s.Add(Grant{Host: "web01", Allow: []string{"^b$"}, Caller: "broker-1", ExpiresAt: now.Add(time.Hour)}) // caller-scoped
	_, _ = s.Add(Grant{Host: "web01", Allow: []string{"^c$"}, EndUser: "alice", ExpiresAt: now.Add(time.Hour)})   // end-user-scoped

	// List purges the expired one and keeps the three live grants.
	if got := s.List(now); len(got) != 3 {
		t.Fatalf("List should drop the expired grant: %d live", len(got))
	}
	if ok, _ := s.Revoke(expID); ok {
		t.Error("expired grant should have been purged by List")
	}

	// host-wide caller/user sees only ^a$ (1 grant).
	if ps := s.GrantsFor("web01", Intent{Host: "web01"}, now); len(ps) != 1 {
		t.Fatalf("anonymous intent should match only the host-wide grant: %d", len(ps))
	}
	// broker-1 sees host-wide + caller-scoped (2).
	if ps := s.GrantsFor("web01", Intent{Host: "web01", Caller: "broker-1"}, now); len(ps) != 2 {
		t.Fatalf("broker-1 should match host-wide + caller-scoped: %d", len(ps))
	}
	// alice sees host-wide + end-user-scoped (2).
	if ps := s.GrantsFor("web01", Intent{Host: "web01", EndUser: "alice"}, now); len(ps) != 2 {
		t.Fatalf("alice should match host-wide + end-user-scoped: %d", len(ps))
	}
	// A different host matches nothing.
	if ps := s.GrantsFor("db01", Intent{Host: "db01", Caller: "broker-1", EndUser: "alice"}, now); len(ps) != 0 {
		t.Fatalf("grants are host-scoped: %d", len(ps))
	}
}

func TestGrantWidensAllowlistHost(t *testing.T) {
	t.Parallel()
	p := compiledWithDeny(t)
	s := NewGrantStore()

	// Baseline: uptime allowed, systemctl denied (allowlist no-match).
	if !allowed(t, p, s, "web01", "uptime") {
		t.Error("baseline: uptime should be allowed")
	}
	if allowed(t, p, s, "web01", "systemctl restart nginx") {
		t.Error("baseline: systemctl should be denied (allowlist no-match)")
	}

	// A live grant widens the allowlist: systemctl now allowed.
	id, _ := s.Add(Grant{Host: "web01", Allow: []string{"^systemctl restart nginx$"}, ExpiresAt: time.Now().Add(time.Hour)})
	if !allowed(t, p, s, "web01", "systemctl restart nginx") {
		t.Error("a live grant should widen the allowlist to permit the command")
	}

	// Deny wins: a grant cannot override a baseline denylist.
	_, _ = s.Add(Grant{Host: "web01", Allow: []string{"^rm -rf /tmp/x$"}, ExpiresAt: time.Now().Add(time.Hour)})
	if allowed(t, p, s, "web01", "rm -rf /tmp/x") {
		t.Error("a grant must NOT override a baseline deny (deny wins)")
	}

	// Revoke restores the baseline denial.
	_, _ = s.Revoke(id)
	if allowed(t, p, s, "web01", "systemctl restart nginx") {
		t.Error("after revoke the command should be denied again")
	}
}

func TestExpiredGrantDoesNotWiden(t *testing.T) {
	t.Parallel()
	p := compiledWithDeny(t)
	s := NewGrantStore()
	_, _ = s.Add(Grant{Host: "web01", Allow: []string{"^systemctl restart nginx$"}, ExpiresAt: time.Now().Add(-time.Second)})
	if allowed(t, p, s, "web01", "systemctl restart nginx") {
		t.Error("an expired grant must not widen the policy")
	}
}

// TestGrantSuppressedOnDefaultAllowHost is the inversion guard: a grant present
// for a default-allow host must NOT turn it allowlist (which would invert it to
// default-deny). A non-granted command stays allowed.
func TestGrantSuppressedOnDefaultAllowHost(t *testing.T) {
	t.Parallel()
	p := compiledWithDeny(t)
	s := NewGrantStore()
	_, _ = s.Add(Grant{Host: "db01", Allow: []string{"^uptime$"}, ExpiresAt: time.Now().Add(time.Hour)})
	// db01 is default-allow; the grant must be suppressed, so an UNRELATED command
	// is still allowed (the host was not inverted to an allowlist).
	if !allowed(t, p, s, "db01", "systemctl restart nginx") {
		t.Error("grant on a default-allow host must not invert it to default-deny")
	}
}

// compiledWithApproval builds a table exercising approval waivers: web02 is an
// allowlist host with a require_approval rule, and gw01 is DEFAULT-ALLOW with only
// a require_approval rule (the case an allow-grant cannot serve — not allowlist-active).
func compiledWithApproval(t *testing.T) PolicyTable {
	t.Helper()
	hosts := PolicyTable{
		"web02": {Principal: "host:web02", CommandPolicy: CommandPolicy{
			Mode:            CmdPolicyAllowlist,
			Allow:           []string{"^systemctl restart [a-z]+$", "^uptime$"},
			RequireApproval: []string{"^systemctl restart "},
		}},
		"gw01": {Principal: "host:gw01", CommandPolicy: CommandPolicy{
			RequireApproval: []string{"^reboot$"},
		}},
	}
	compiled, err := CompileHostPolicies(hosts, nil, nil)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return compiled
}

// approvalRequired reports whether resolve flags cmd as require_approval on host.
func approvalRequired(t *testing.T, p PolicyTable, store GrantProvider, host, cmd string) bool {
	t.Helper()
	d, err := p.resolve(oneshot(host, cmd), 5*time.Minute, store)
	if err != nil {
		t.Fatalf("resolve %q on %s: %v", cmd, host, err)
	}
	return d.RequireApproval
}

func waiver(host string, patterns ...string) Grant {
	return Grant{Host: host, WaiveApproval: patterns, ExpiresAt: time.Now().Add(time.Hour)}
}

func TestWaiverClearsApprovalOnAllowlistHost(t *testing.T) {
	t.Parallel()
	p := compiledWithApproval(t)
	s := NewGrantStore()
	const cmd = "systemctl restart nginx"

	if !approvalRequired(t, p, s, "web02", cmd) {
		t.Fatal("baseline: command should require approval")
	}
	id, err := s.Add(waiver("web02", "^systemctl restart nginx$"))
	if err != nil {
		t.Fatalf("add waiver: %v", err)
	}
	if approvalRequired(t, p, s, "web02", cmd) {
		t.Error("a live waiver should clear require_approval")
	}
	_, _ = s.Revoke(id)
	if !approvalRequired(t, p, s, "web02", cmd) {
		t.Error("after revoke the approval gate should return")
	}
}

// TestWaiverOnDefaultAllowHost covers the case allow-grants cannot: gw01 is
// default-allow with a require_approval rule (not allowlist-active).
func TestWaiverOnDefaultAllowHost(t *testing.T) {
	t.Parallel()
	p := compiledWithApproval(t)
	s := NewGrantStore()
	if !approvalRequired(t, p, s, "gw01", "reboot") {
		t.Fatal("baseline: reboot should require approval on gw01")
	}
	if _, err := s.Add(waiver("gw01", "^reboot$")); err != nil {
		t.Fatal(err)
	}
	if approvalRequired(t, p, s, "gw01", "reboot") {
		t.Error("a waiver should clear approval even on a default-allow host")
	}
}

func TestExpiredWaiverDoesNotClearApproval(t *testing.T) {
	t.Parallel()
	p := compiledWithApproval(t)
	s := NewGrantStore()
	_, _ = s.Add(Grant{Host: "web02", WaiveApproval: []string{"^systemctl restart nginx$"}, ExpiresAt: time.Now().Add(-time.Second)})
	if !approvalRequired(t, p, s, "web02", "systemctl restart nginx") {
		t.Error("an expired waiver must not clear require_approval")
	}
}

// TestWaiverNeverUnDenies: a waiver only un-gates an ALREADY-allowed command; it
// cannot make a denied command run.
func TestWaiverNeverUnDenies(t *testing.T) {
	t.Parallel()
	p := compiledWithApproval(t)
	s := NewGrantStore()
	// "rm -rf /" is denied on web02 (allowlist no-match). A waiver for it must not
	// allow it (resolve still returns an error).
	if _, err := s.Add(waiver("web02", "^rm -rf /$")); err != nil {
		t.Fatal(err)
	}
	if _, err := p.resolve(oneshot("web02", "rm -rf /"), 5*time.Minute, s); err == nil {
		t.Error("a waiver must not turn a denied command into an allowed one")
	}
}

// TestWaiverIsSudoScoped: a waiver minted for one elevation must not un-gate a
// different elevation (no privilege escalation/descent across the approval).
func TestWaiverIsSudoScoped(t *testing.T) {
	t.Parallel()
	s := NewGrantStore()
	now := time.Now()
	_, _ = s.Add(Grant{Host: "web02", WaiveApproval: []string{"^systemctl restart nginx$"}, Sudo: true, ExpiresAt: now.Add(time.Hour)})

	sudo := Intent{Host: "web02", Command: "systemctl restart nginx", Sudo: true}
	nonSudo := Intent{Host: "web02", Command: "systemctl restart nginx", Sudo: false}
	if !s.WaiverMatches("web02", sudo, now) {
		t.Error("a sudo waiver should match the matching sudo request")
	}
	if s.WaiverMatches("web02", nonSudo, now) {
		t.Error("a sudo waiver must NOT match the non-sudo variant")
	}

	// sudo_user must match exactly too.
	_, _ = s.Add(Grant{Host: "web02", WaiveApproval: []string{"^x$"}, Sudo: true, SudoUser: "deploy", ExpiresAt: now.Add(time.Hour)})
	if s.WaiverMatches("web02", Intent{Host: "web02", Command: "x", Sudo: true, SudoUser: "root"}, now) {
		t.Error("sudo_user must match exactly")
	}
	if !s.WaiverMatches("web02", Intent{Host: "web02", Command: "x", Sudo: true, SudoUser: "deploy"}, now) {
		t.Error("a matching sudo_user should match")
	}

	// Empty sudo_user and "root" are the same effective elevation.
	_, _ = s.Add(Grant{Host: "web02", WaiveApproval: []string{"^root-default$"}, Sudo: true, ExpiresAt: now.Add(time.Hour)})
	if !s.WaiverMatches("web02", Intent{Host: "web02", Command: "root-default", Sudo: true, SudoUser: "root"}, now) {
		t.Error("empty sudo_user waiver should match an explicit root request")
	}
	foundCanonical := false
	for _, g := range s.List(now) {
		if len(g.WaiveApproval) == 1 && g.WaiveApproval[0] == "^root-default$" && g.SudoUser != "root" {
			t.Errorf("stored sudo_user should be canonical root, got %q", g.SudoUser)
		}
		if len(g.WaiveApproval) == 1 && g.WaiveApproval[0] == "^root-default$" {
			foundCanonical = true
		}
	}
	if !foundCanonical {
		t.Error("expected to find the canonical root-default waiver")
	}
}

func TestWaiverIsCallerAndEndUserScoped(t *testing.T) {
	t.Parallel()
	s := NewGrantStore()
	now := time.Now()
	_, _ = s.Add(Grant{
		Host: "web02", Caller: "broker-1", EndUser: "alice",
		WaiveApproval: []string{"^systemctl restart nginx$"},
		ExpiresAt:     now.Add(time.Hour),
	})

	matching := Intent{Host: "web02", Caller: "broker-1", EndUser: "alice", Command: "systemctl restart nginx"}
	otherCaller := Intent{Host: "web02", Caller: "broker-2", EndUser: "alice", Command: "systemctl restart nginx"}
	otherUser := Intent{Host: "web02", Caller: "broker-1", EndUser: "bob", Command: "systemctl restart nginx"}
	if !s.WaiverMatches("web02", matching, now) {
		t.Error("waiver should match the approved caller/end-user scope")
	}
	if s.WaiverMatches("web02", otherCaller, now) {
		t.Error("waiver must not match a different caller")
	}
	if s.WaiverMatches("web02", otherUser, now) {
		t.Error("waiver must not match a different end user")
	}
}

func TestSupersedeWaiverDedups(t *testing.T) {
	t.Parallel()
	s := NewGrantStore()
	g := Grant{Host: "web02", WaiveApproval: []string{"^x$"}, ExpiresAt: time.Now().Add(time.Hour)}
	s.SupersedeWaiver(g)
	_, _ = s.Add(g)
	s.SupersedeWaiver(g) // should revoke the first
	id2, _ := s.Add(g)
	if live := s.List(time.Now()); len(live) != 1 || live[0].ID != id2 {
		t.Errorf("supersede should keep only the latest identical waiver: %+v", live)
	}
}

func TestAddValidatesWaiveApproval(t *testing.T) {
	t.Parallel()
	s := NewGrantStore()
	now := time.Now()
	// A grant with only a waiver (no allow) is valid.
	if _, err := s.Add(Grant{Host: "web02", WaiveApproval: []string{"^x$"}, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Errorf("waiver-only grant should be valid: %v", err)
	}
	// Neither allow nor waiver → rejected.
	if _, err := s.Add(Grant{Host: "web02", ExpiresAt: now.Add(time.Hour)}); err == nil {
		t.Error("a grant with neither allow nor waive_approval should be rejected")
	}
	// Bad waiver regex → rejected.
	if _, err := s.Add(Grant{Host: "web02", WaiveApproval: []string{"("}, ExpiresAt: now.Add(time.Hour)}); err == nil {
		t.Error("an invalid waive_approval regex should be rejected")
	}
}

func TestHasAllowlist(t *testing.T) {
	t.Parallel()
	if (PolicySet{{Mode: CmdPolicyDenylist, Deny: []string{"^rm "}}}).hasAllowlist() {
		t.Error("a denylist-only set has no allowlist")
	}
	if !(PolicySet{{Mode: CmdPolicyAllowlist, Allow: []string{"^x$"}}}).hasAllowlist() {
		t.Error("an allowlist set should report hasAllowlist")
	}
	if (PolicySet{}).hasAllowlist() {
		t.Error("empty set has no allowlist")
	}
}
