package signer

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func testPolicy() PolicyTable {
	return PolicyTable{
		"web01":   {Principal: "host:web01", SourceAddress: "10.0.0.1", MaxTTL: 2 * time.Minute},
		"bastion": {Principal: "host:bastion", AllowAsBastion: true},
		"locked":  {Principal: "host:locked", AllowedCallers: []string{"broker-a"}},
		"sudohost": {
			Principal: "host:sudohost", SourceAddress: "10.0.0.3", MaxTTL: 2 * time.Minute,
			AllowSudo: true, AllowedSudoUsers: []string{"root", "deploy"}, AllowPTY: true,
		},
		"nosudohost": {Principal: "host:nosudohost", SourceAddress: "10.0.0.4", MaxTTL: 2 * time.Minute},
	}
}

func TestResolveTargetOneshot(t *testing.T) {
	t.Parallel()
	d, err := testPolicy().Resolve(Intent{
		Caller: "x", Host: "web01", Role: RoleTarget, Purpose: PurposeOneshot,
		Command: "uptime", RequestedTTL: time.Minute,
	}, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	c := d.Constraints
	if c.ForceCommand != "uptime" {
		t.Errorf("force-command = %q, want uptime", c.ForceCommand)
	}
	if c.AllowPortForwarding {
		t.Error("target must not have port-forwarding")
	}
	if c.SourceAddress != "10.0.0.1" || c.Principal != "host:web01" {
		t.Errorf("constraints = %+v", c)
	}
}

func TestResolveSessionNoForceCommand(t *testing.T) {
	t.Parallel()
	d, _ := testPolicy().Resolve(Intent{
		Caller: "x", Host: "web01", Role: RoleTarget, Purpose: PurposeSession,
		Command: "ignorado", RequestedTTL: time.Minute,
	}, 5*time.Minute)
	if d.Constraints.ForceCommand != "" {
		t.Errorf("session must not carry force-command, has %q", d.Constraints.ForceCommand)
	}
}

func TestResolveBastionForwarding(t *testing.T) {
	t.Parallel()
	d, err := testPolicy().Resolve(Intent{
		Caller: "x", Host: "bastion", Role: RoleBastion, Purpose: PurposeSession,
		RequestedTTL: time.Minute,
	}, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Constraints.AllowPortForwarding {
		t.Error("bastion must allow port-forwarding")
	}
}

func TestResolveTTLCap(t *testing.T) {
	t.Parallel()
	d, _ := testPolicy().Resolve(Intent{
		Caller: "x", Host: "web01", Role: RoleTarget, Purpose: PurposeOneshot,
		RequestedTTL: time.Hour, // greater than MaxTTL=2m
	}, 5*time.Minute)
	if d.Constraints.TTL != 2*time.Minute {
		t.Errorf("TTL = %s, want capped at 2m", d.Constraints.TTL)
	}
}

func TestResolveAuthz(t *testing.T) {
	t.Parallel()
	p := testPolicy()
	if _, err := p.Resolve(Intent{Caller: "broker-b", Host: "locked", Role: RoleTarget, Purpose: PurposeOneshot, RequestedTTL: time.Minute}, time.Minute); err == nil {
		t.Error("expected denial for unauthorised caller")
	}
	if _, err := p.Resolve(Intent{Caller: "broker-a", Host: "locked", Role: RoleTarget, Purpose: PurposeOneshot, RequestedTTL: time.Minute}, time.Minute); err != nil {
		t.Errorf("authorised caller must not fail: %v", err)
	}
}

func TestResolveErrors(t *testing.T) {
	t.Parallel()
	p := testPolicy()
	if _, err := p.Resolve(Intent{Caller: "x", Host: "inexistente", Role: RoleTarget, RequestedTTL: time.Minute}, time.Minute); err == nil {
		t.Error("expected error for host with no policy")
	}
	// web01 has no AllowAsBastion → cannot be used as a bastion.
	if _, err := p.Resolve(Intent{Caller: "x", Host: "web01", Role: RoleBastion, RequestedTTL: time.Minute}, time.Minute); err == nil {
		t.Error("expected error: web01 not allowed as bastion")
	}
}

// --- Elevation tests (sudo NOPASSWD) ---

func TestResolveSudoOneshotRoot(t *testing.T) {
	t.Parallel()
	d, err := testPolicy().Resolve(Intent{
		Caller: "x", Host: "sudohost", Role: RoleTarget, Purpose: PurposeOneshot,
		Command: "id", RequestedTTL: time.Minute,
		Sudo: true, // empty SudoUser = root
	}, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	// One-shot: the prefix goes in ForceCommand, not in elevPrefix.
	if d.ElevationPrefix != "" {
		t.Errorf("elevPrefix must be empty in one-shot, got %q", d.ElevationPrefix)
	}
	want := "sudo -n -- /bin/sh -c 'id'"
	if d.Constraints.ForceCommand != want {
		t.Errorf("force-command = %q, want %q", d.Constraints.ForceCommand, want)
	}
}

func TestResolveSudoOneshotUser(t *testing.T) {
	t.Parallel()
	d, err := testPolicy().Resolve(Intent{
		Caller: "x", Host: "sudohost", Role: RoleTarget, Purpose: PurposeOneshot,
		Command: "whoami", RequestedTTL: time.Minute,
		Sudo: true, SudoUser: "deploy",
	}, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	want := "sudo -n -u deploy -- /bin/sh -c 'whoami'"
	if d.Constraints.ForceCommand != want {
		t.Errorf("force-command = %q, want %q", d.Constraints.ForceCommand, want)
	}
}

func TestResolveSudoSessionReturnsPrefix(t *testing.T) {
	t.Parallel()
	d, err := testPolicy().Resolve(Intent{
		Caller: "x", Host: "sudohost", Role: RoleTarget, Purpose: PurposeSession,
		RequestedTTL: time.Minute, Sudo: true,
	}, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if d.ElevationPrefix != "sudo -n" {
		t.Errorf("elevPrefix = %q, want 'sudo -n'", d.ElevationPrefix)
	}
}

func TestResolveSudoDeniedNoPolicy(t *testing.T) {
	t.Parallel()
	_, err := testPolicy().Resolve(Intent{
		Caller: "x", Host: "nosudohost", Role: RoleTarget, Purpose: PurposeOneshot,
		Command: "id", RequestedTTL: time.Minute, Sudo: true,
	}, 5*time.Minute)
	if err == nil {
		t.Error("expected denial because allow_sudo=false")
	}
}

func TestResolveSudoUserNotAllowed(t *testing.T) {
	t.Parallel()
	_, err := testPolicy().Resolve(Intent{
		Caller: "x", Host: "sudohost", Role: RoleTarget, Purpose: PurposeOneshot,
		Command: "id", RequestedTTL: time.Minute,
		Sudo: true, SudoUser: "notallowed",
	}, 5*time.Minute)
	if err == nil {
		t.Error("expected denial: user not in allowlist")
	}
}

func TestResolveSudoUserMalicious(t *testing.T) {
	t.Parallel()
	// Injection attempts.
	for _, bad := range []string{"-rf /", "root; rm -rf /", "../etc/passwd", "root --option"} {
		_, err := testPolicy().Resolve(Intent{
			Caller: "x", Host: "sudohost", Role: RoleTarget, Purpose: PurposeOneshot,
			Command: "id", RequestedTTL: time.Minute, Sudo: true, SudoUser: bad,
		}, 5*time.Minute)
		if err == nil {
			t.Errorf("expected error for malicious sudo_user %q", bad)
		}
	}
}

func TestResolveSudoOneshotCommandWithQuotes(t *testing.T) {
	t.Parallel()
	// Quoting must escape single quotes in the command.
	d, err := testPolicy().Resolve(Intent{
		Caller: "x", Host: "sudohost", Role: RoleTarget, Purpose: PurposeOneshot,
		Command: "echo 'hello world'", RequestedTTL: time.Minute, Sudo: true,
	}, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	want := `sudo -n -- /bin/sh -c 'echo '\''hello world'\'''`
	if d.Constraints.ForceCommand != want {
		t.Errorf("force-command = %q, want %q", d.Constraints.ForceCommand, want)
	}
}

// --- PTY tests ---

func TestResolvePTYAllowed(t *testing.T) {
	t.Parallel()
	d, err := testPolicy().Resolve(Intent{
		Caller: "x", Host: "sudohost", Role: RoleTarget, Purpose: PurposeSession,
		RequestedTTL: time.Minute, PTY: true,
	}, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Constraints.AllowPTY {
		t.Error("AllowPTY must be true when requested and the policy allows it")
	}
}

func TestResolvePTYDenied(t *testing.T) {
	t.Parallel()
	_, err := testPolicy().Resolve(Intent{
		Caller: "x", Host: "nosudohost", Role: RoleTarget, Purpose: PurposeSession,
		RequestedTTL: time.Minute, PTY: true,
	}, 5*time.Minute)
	if err == nil {
		t.Error("expected denial because allow_pty=false")
	}
}

// --- Group RBAC tests (HostSetForCaller) ---

func testGroupPolicy() PolicyTable {
	return PolicyTable{
		"web01":     {Principal: "host:web01", Groups: []string{"prod-web"}},
		"web02":     {Principal: "host:web02", Groups: []string{"prod-web"}},
		"bastion":   {Principal: "host:bastion", Groups: []string{"prod-web"}, AllowAsBastion: true},
		"db01":      {Principal: "host:db01", Groups: []string{"databases"}},
		"shared":    {Principal: "host:shared", Groups: []string{"prod-web", "databases"}},
		"ungrouped": {Principal: "host:ungrouped"},
	}
}

func TestHostSetForCallerNotInTable(t *testing.T) {
	t.Parallel()
	_, restricted := HostSetForCaller("unknown-broker", testGroupPolicy(), CallerTable{
		"broker-prod": {AllowedGroups: []string{"prod-web"}},
	})
	if restricted {
		t.Error("caller not in CallerTable must not be restricted")
	}
}

func TestHostSetForCallerWithGroup(t *testing.T) {
	t.Parallel()
	set, restricted := HostSetForCaller("broker-prod", testGroupPolicy(), CallerTable{
		"broker-prod": {AllowedGroups: []string{"prod-web"}},
	})
	if !restricted {
		t.Fatal("broker-prod must have a restriction")
	}
	for _, want := range []string{"web01", "web02", "bastion", "shared"} {
		if _, ok := set[want]; !ok {
			t.Errorf("host %q must be in the set", want)
		}
	}
	for _, notWant := range []string{"db01", "ungrouped"} {
		if _, ok := set[notWant]; ok {
			t.Errorf("host %q must not be in the set", notWant)
		}
	}
}

func TestHostSetForCallerEmptyGroups(t *testing.T) {
	t.Parallel()
	set, restricted := HostSetForCaller("broker-limited", testGroupPolicy(), CallerTable{
		"broker-limited": {AllowedGroups: []string{}},
	})
	if !restricted {
		t.Fatal("caller with empty allowed_groups must be restricted")
	}
	if len(set) != 0 {
		t.Errorf("set must be empty, has %d hosts", len(set))
	}
}

func TestHostSetForCallerMultipleGroups(t *testing.T) {
	t.Parallel()
	set, restricted := HostSetForCaller("broker-all", testGroupPolicy(), CallerTable{
		"broker-all": {AllowedGroups: []string{"prod-web", "databases"}},
	})
	if !restricted {
		t.Fatal("broker-all must have a restriction")
	}
	for _, want := range []string{"web01", "web02", "bastion", "db01", "shared"} {
		if _, ok := set[want]; !ok {
			t.Errorf("host %q must be in the set", want)
		}
	}
	if _, ok := set["ungrouped"]; ok {
		t.Error("ungrouped must not be in the set")
	}
}

func TestHostSetForCallerUnknownGroup(t *testing.T) {
	t.Parallel()
	set, restricted := HostSetForCaller("broker-x", testGroupPolicy(), CallerTable{
		"broker-x": {AllowedGroups: []string{"nonexistent-group"}},
	})
	if !restricted {
		t.Fatal("broker-x must have a restriction")
	}
	if len(set) != 0 {
		t.Errorf("nonexistent group must not add hosts, has %d", len(set))
	}
}

func TestHostSetForCallerSharedHost(t *testing.T) {
	t.Parallel()
	// 'shared' belongs to prod-web and databases; both callers must see it.
	for _, cn := range []string{"broker-prod", "broker-db"} {
		callers := CallerTable{
			"broker-prod": {AllowedGroups: []string{"prod-web"}},
			"broker-db":   {AllowedGroups: []string{"databases"}},
		}
		set, _ := HostSetForCaller(cn, testGroupPolicy(), callers)
		if _, ok := set["shared"]; !ok {
			t.Errorf("%s must see the shared host", cn)
		}
	}
}

func TestShellQuote(t *testing.T) {
	t.Parallel()
	cases := []struct{ in, want string }{
		{"hello", "'hello'"},
		{"it's", `'it'\''s'`},
		{"a'b'c", `'a'\''b'\''c'`},
		{"", "''"},
	}
	for _, tc := range cases {
		got := shellQuote(tc.in)
		if got != tc.want {
			t.Errorf("shellQuote(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// --- Multi-CA helpers ---

// newTestCAKey generates a fresh Ed25519 SSH signer for use as a CA in tests.
func newTestCAKey(t *testing.T) ssh.Signer {
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

// newTestPub generates a fresh Ed25519 SSH public key to use as the ephemeral
// key in SignIntent calls.
func newTestPub(t *testing.T) ssh.PublicKey {
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

// testMultiCAPolicy returns a PolicyTable with two grouped hosts and one
// ungrouped host, suitable for multi-CA tests.
func testMultiCAPolicy() PolicyTable {
	return PolicyTable{
		"web01":  {Principal: "host:web01", MaxTTL: 5 * time.Minute, Groups: []string{"prod-web"}},
		"db01":   {Principal: "host:db01", MaxTTL: 5 * time.Minute, Groups: []string{"databases"}},
		"legacy": {Principal: "host:legacy", MaxTTL: 5 * time.Minute},
	}
}

// --- caKeyFor tests ---

// TestCAKeyForNilGroupCAs verifies that NewLocal (no groupCAs) always returns
// defaultCA regardless of the host's group membership.
func TestCAKeyForNilGroupCAs(t *testing.T) {
	t.Parallel()
	defaultCA := newTestCAKey(t)
	l := NewLocal(defaultCA, testGroupPolicy(), time.Minute)
	for name, hp := range testGroupPolicy() {
		if got := l.caKeyFor(hp); got != defaultCA {
			t.Errorf("host %q: expected defaultCA with nil groupCAs, got different signer", name)
		}
	}
}

// TestCAKeyForGroupMatch verifies the per-group CA selection and the
// first-match rule when a host belongs to multiple groups.
func TestCAKeyForGroupMatch(t *testing.T) {
	t.Parallel()
	defaultCA := newTestCAKey(t)
	webCA := newTestCAKey(t)
	dbCA := newTestCAKey(t)

	l := NewLocalWithGroupCAs(defaultCA, map[string]ssh.Signer{
		"prod-web":  webCA,
		"databases": dbCA,
	}, testGroupPolicy(), time.Minute)

	p := testGroupPolicy()

	// web01 is in prod-web → webCA
	if got := l.caKeyFor(p["web01"]); got != webCA {
		t.Error("web01 (prod-web): expected webCA")
	}
	// db01 is in databases → dbCA
	if got := l.caKeyFor(p["db01"]); got != dbCA {
		t.Error("db01 (databases): expected dbCA")
	}
	// ungrouped has no groups → defaultCA
	if got := l.caKeyFor(p["ungrouped"]); got != defaultCA {
		t.Error("ungrouped: expected defaultCA")
	}
	// shared is in ["prod-web", "databases"]; first match = prod-web → webCA
	if got := l.caKeyFor(p["shared"]); got != webCA {
		t.Error("shared (first group prod-web): expected webCA, not dbCA")
	}
}

// --- SignIntent multi-CA end-to-end test ---

// TestSignIntentMultiCA verifies that SignIntent selects the right CA for each
// host: hosts in a group use the group CA, hosts without a matching group fall
// back to defaultCA.
func TestSignIntentMultiCA(t *testing.T) {
	t.Parallel()

	defaultCA := newTestCAKey(t)
	webCA := newTestCAKey(t)
	dbCA := newTestCAKey(t)

	policy := testMultiCAPolicy()
	l := NewLocalWithGroupCAs(defaultCA, map[string]ssh.Signer{
		"prod-web":  webCA,
		"databases": dbCA,
	}, policy, 5*time.Minute)

	ephPub := newTestPub(t)

	cases := []struct {
		host   string
		wantCA ssh.Signer
	}{
		{"web01", webCA},
		{"db01", dbCA},
		{"legacy", defaultCA},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.host, func(t *testing.T) {
			t.Parallel()
			issued, err := l.SignIntent(context.Background(), Intent{
				Caller: "test-broker", Host: tc.host,
				Role: RoleTarget, Purpose: PurposeSession,
				RequestedTTL: time.Minute,
				PublicKey:    ephPub,
			})
			if err != nil {
				t.Fatalf("SignIntent: %v", err)
			}
			if issued.Certificate == nil {
				t.Fatal("expected non-nil certificate")
			}
			// Confirm the cert was signed by the expected CA.
			caPub := tc.wantCA.PublicKey()
			checker := &ssh.CertChecker{
				IsUserAuthority: func(k ssh.PublicKey) bool {
					return string(k.Marshal()) == string(caPub.Marshal())
				},
			}
			principal := policy[tc.host].Principal
			if cerr := checker.CheckCert(principal, issued.Certificate); cerr != nil {
				t.Errorf("cert for %q not signed by expected CA: %v", tc.host, cerr)
			}
		})
	}
}
