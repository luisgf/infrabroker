package signer

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testClusterFiles creates a throwaway CA PEM and minter token file.
func testClusterFiles(t *testing.T) (caPath, tokPath string) {
	t.Helper()
	dir := t.TempDir()
	caPath = filepath.Join(dir, "ca.crt")
	tokPath = filepath.Join(dir, "minter.token")
	if err := os.WriteFile(caPath, []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokPath, []byte("minter"), 0o600); err != nil {
		t.Fatal(err)
	}
	return caPath, tokPath
}

func testCluster(t *testing.T, rules []K8sRule) ClusterPolicy {
	t.Helper()
	ca, tok := testClusterFiles(t)
	return ClusterPolicy{
		APIServer: "https://10.0.0.5:6443",
		CACert:    ca,
		TokenFile: tok,
		Groups:    []string{"platform"},
		SABindings: []SABinding{
			{Groups: []string{"platform"}, Namespace: "agents", ServiceAccount: "broker-platform"},
			{Namespace: "agents", ServiceAccount: "broker-default"}, // default binding
		},
		Rules: rules,
	}
}

func compileOne(t *testing.T, cp ClusterPolicy) ClusterTable {
	t.Helper()
	ct, err := CompileClusterPolicies(ClusterTable{"prod-k8s": cp}, nil)
	if err != nil {
		t.Fatalf("CompileClusterPolicies: %v", err)
	}
	return ct
}

// fakeMinter records the last mint and returns a fixed token.
type fakeMinter struct {
	cluster, ns, sa string
	ttl             time.Duration
	fail            bool
}

func (m *fakeMinter) MintToken(_ context.Context, cluster, ns, sa string, ttl time.Duration) (string, time.Time, error) {
	m.cluster, m.ns, m.sa, m.ttl = cluster, ns, sa, ttl
	if m.fail {
		return "", time.Time{}, context.DeadlineExceeded
	}
	return "tok-" + sa, time.Now().Add(ttl), nil
}

func k8sIntent(action K8sAction) Intent {
	return Intent{
		TargetType: TargetTypeK8s,
		Host:       "prod-k8s",
		Role:       RoleTarget,
		Purpose:    PurposeOneshot,
		Caller:     "broker-1",
		K8s:        &action,
		Command:    action.Canonical(),
	}
}

func TestCompileClusterPoliciesValidation(t *testing.T) {
	t.Parallel()
	base := func(t *testing.T) ClusterPolicy {
		return testCluster(t, []K8sRule{{Verbs: []string{"get"}, Resources: []string{"pods"}, Effect: "allow"}})
	}
	cases := []struct {
		name   string
		mutate func(*ClusterPolicy)
		hosts  PolicyTable
		want   string
	}{
		{"http api server", func(c *ClusterPolicy) { c.APIServer = "http://x:6443" }, nil, "https"},
		{"missing token file", func(c *ClusterPolicy) { c.TokenFile = "/nonexistent" }, nil, "token_file"},
		{"ttl below min", func(c *ClusterPolicy) { c.TokenTTLSeconds = 300 }, nil, "token_ttl_seconds"},
		{"ttl above max", func(c *ClusterPolicy) { c.TokenTTLSeconds = 3600 }, nil, "token_ttl_seconds"},
		{"no bindings", func(c *ClusterPolicy) { c.SABindings = nil }, nil, "sa_binding"},
		{"no rules", func(c *ClusterPolicy) { c.Rules = nil }, nil, "allow"},
		{"deny-only rules", func(c *ClusterPolicy) {
			c.Rules = []K8sRule{{Verbs: []string{"*"}, Resources: []string{"secrets"}, Effect: "deny"}}
		}, nil, "at least one allow"},
		{"unknown effect", func(c *ClusterPolicy) { c.Rules[0].Effect = "audit" }, nil, "effect"},
		{"unknown verb", func(c *ClusterPolicy) { c.Rules[0].Verbs = []string{"exec"} }, nil, "verb"},
		{"unknown resource", func(c *ClusterPolicy) { c.Rules[0].Resources = []string{"widgets"} }, nil, "unknown k8s resource"},
		{"host name collision", nil, PolicyTable{"prod-k8s": HostPolicy{}}, "collides"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cp := base(t)
			if tc.mutate != nil {
				tc.mutate(&cp)
			}
			_, err := CompileClusterPolicies(ClusterTable{"prod-k8s": cp}, tc.hosts)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestResolveK8sDecisions(t *testing.T) {
	t.Parallel()
	ct := compileOne(t, testCluster(t, []K8sRule{
		{Verbs: []string{"get", "list", "logs"}, Resources: []string{"pods", "deployments"}, Effect: "allow"},
		{Verbs: []string{"apply"}, Resources: []string{"deployments"}, Namespaces: []string{"staging"}, Effect: "allow"},
		{Verbs: []string{"delete"}, Resources: []string{"pods"}, Namespaces: []string{"prod"}, Effect: "require_approval"},
		{Verbs: []string{"*"}, Resources: []string{"secrets"}, Effect: "deny"},
	}))

	cases := []struct {
		name     string
		action   K8sAction
		allowed  bool
		approval bool
	}{
		{"read allowed anywhere", K8sAction{Verb: "get", Resource: "pods", Namespace: "prod", Name: "web-1"}, true, false},
		{"list cluster-wide", K8sAction{Verb: "list", Resource: "deployments", Group: "apps"}, true, false},
		{"apply scoped to staging", K8sAction{Verb: "apply", Resource: "deployments", Group: "apps", Namespace: "staging", Name: "api"}, true, false},
		{"apply outside scope denied", K8sAction{Verb: "apply", Resource: "deployments", Group: "apps", Namespace: "prod", Name: "api"}, false, false},
		{"delete gated by approval", K8sAction{Verb: "delete", Resource: "pods", Namespace: "prod", Name: "web-1"}, true, true},
		{"delete outside scope denied", K8sAction{Verb: "delete", Resource: "pods", Namespace: "staging", Name: "web-1"}, false, false},
		{"default-deny unmatched", K8sAction{Verb: "delete", Resource: "deployments", Namespace: "prod", Name: "api"}, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, _, err := ct.resolveK8s(k8sIntent(tc.action), nil)
			if tc.allowed && err != nil {
				t.Fatalf("must be allowed: %v", err)
			}
			if !tc.allowed && err == nil {
				t.Fatal("must be denied")
			}
			if tc.allowed && d.RequireApproval != tc.approval {
				t.Errorf("RequireApproval = %v, want %v", d.RequireApproval, tc.approval)
			}
		})
	}

	// Deny wins even over an explicit allow: reads are allowed for pods and
	// deployments, but a secrets rule can never be out-escaped.
	if _, _, err := ct.resolveK8s(k8sIntent(K8sAction{Verb: "get", Resource: "secrets", Namespace: "prod", Name: "db"}), nil); err == nil {
		t.Error("deny must win for secrets")
	}
}

func TestResolveK8sRejectsSSHKnobsAndMismatch(t *testing.T) {
	t.Parallel()
	ct := compileOne(t, testCluster(t, []K8sRule{{Verbs: []string{"get"}, Resources: []string{"pods"}, Effect: "allow"}}))
	base := K8sAction{Verb: "get", Resource: "pods", Namespace: "prod", Name: "x"}

	mutations := []struct {
		name string
		mut  func(*Intent)
	}{
		{"sudo", func(in *Intent) { in.Sudo = true }},
		{"pty", func(in *Intent) { in.PTY = true }},
		{"file transfer", func(in *Intent) { in.FileTransfer = true }},
		{"session", func(in *Intent) { in.Purpose = PurposeSession; in.SessionMode = SessionModeExec }},
		{"bastion role", func(in *Intent) { in.Role = RoleBastion }},
		{"command mismatch", func(in *Intent) { in.Command = "get pods prod/other" }},
		{"non-normalized group", func(in *Intent) {
			// The broker must canonicalize with the RESOLVED group; a bare
			// "deployments" command string is a mismatch.
			in.K8s = &K8sAction{Verb: "get", Resource: "deployments", Namespace: "p", Name: "x"}
			in.Command = "get deployments p/x"
		}},
		{"no action", func(in *Intent) { in.K8s = nil }},
		{"unsafe end user", func(in *Intent) { in.EndUser = "alice evil=1" }},
	}
	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			in := k8sIntent(base)
			tc.mut(&in)
			if _, _, err := ct.resolveK8s(in, nil); err == nil {
				t.Error("must be rejected")
			}
		})
	}
}

func TestResolveK8sRBAC(t *testing.T) {
	t.Parallel()
	cp := testCluster(t, []K8sRule{{Verbs: []string{"get"}, Resources: []string{"pods"}, Effect: "allow"}})
	cp.AllowedCallers = []string{"broker-1"}
	ct := compileOne(t, cp)
	action := K8sAction{Verb: "get", Resource: "pods", Namespace: "p", Name: "x"}

	// Caller allowlist.
	in := k8sIntent(action)
	in.Caller = "rogue"
	if _, _, err := ct.resolveK8s(in, nil); err == nil {
		t.Error("allowed_callers must gate the cluster")
	}
	// Per-user groups: nil = no filter; non-intersecting = denied.
	in = k8sIntent(action)
	in.EndUserGroups = []string{"web"}
	if _, _, err := ct.resolveK8s(in, nil); err == nil {
		t.Error("end-user groups must gate the cluster")
	}
	in.EndUserGroups = []string{"platform"}
	if _, _, err := ct.resolveK8s(in, nil); err != nil {
		t.Errorf("intersecting groups must pass: %v", err)
	}
}

func TestResolveK8sGrantsAndWaivers(t *testing.T) {
	t.Parallel()
	ct := compileOne(t, testCluster(t, []K8sRule{
		{Verbs: []string{"get"}, Resources: []string{"pods"}, Effect: "allow"},
		{Verbs: []string{"delete"}, Resources: []string{"pods"}, Effect: "require_approval"},
	}))
	grants := NewGrantStore()
	now := time.Now()

	// A widen-only grant admits an action the baseline denies (clusters are
	// always allowlist-active, so grants apply with no special case).
	restart := K8sAction{Verb: "apply", Resource: "deployments", Group: "apps", Namespace: "prod", Name: "api"}
	if _, _, err := ct.resolveK8s(k8sIntent(restart), grants); err == nil {
		t.Fatal("baseline must deny apply")
	}
	if _, err := grants.Add(Grant{Host: "prod-k8s", Allow: []string{`^apply deployments\.apps prod/api$`},
		GrantedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ct.resolveK8s(k8sIntent(restart), grants); err != nil {
		t.Errorf("grant must widen the cluster allowlist: %v", err)
	}

	// An approve-and-learn waiver un-gates require_approval for the exact
	// canonical action.
	del := K8sAction{Verb: "delete", Resource: "pods", Namespace: "prod", Name: "web-1"}
	d, _, err := ct.resolveK8s(k8sIntent(del), grants)
	if err != nil || !d.RequireApproval {
		t.Fatalf("delete must be approval-gated: %+v, %v", d, err)
	}
	if _, err := grants.Add(Grant{Host: "prod-k8s",
		WaiveApproval: []string{"^" + regexpQuote(del.Canonical()) + "$"},
		Caller:        "broker-1",
		GrantedAt:     now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	d, _, err = ct.resolveK8s(k8sIntent(del), grants)
	if err != nil || d.RequireApproval {
		t.Errorf("waiver must un-gate the approved action: %+v, %v", d, err)
	}
}

func regexpQuote(s string) string {
	return strings.NewReplacer(`.`, `\.`, `/`, `/`).Replace(s)
}

func TestSignK8sMintsBoundToken(t *testing.T) {
	t.Parallel()
	ct := compileOne(t, testCluster(t, []K8sRule{
		{Verbs: []string{"get"}, Resources: []string{"pods"}, Effect: "allow"},
		{Verbs: []string{"delete"}, Resources: []string{"pods"}, Effect: "require_approval"},
	}))
	minter := &fakeMinter{}
	l := NewLocal(nil, nil, time.Minute).WithK8s(ct, minter)

	// Allowed read for a platform user → token minted for the platform SA.
	in := k8sIntent(K8sAction{Verb: "get", Resource: "pods", Namespace: "prod", Name: "web-1"})
	in.EndUser, in.EndUserGroups = "alice", []string{"platform"}
	issued, err := l.SignIntent(context.Background(), in)
	if err != nil {
		t.Fatalf("SignIntent: %v", err)
	}
	if issued.K8sToken != "tok-broker-platform" || issued.Certificate != nil {
		t.Errorf("expected a bound token for the platform binding: %+v", issued)
	}
	if issued.Serial == 0 || issued.K8sTokenExpiry.IsZero() {
		t.Errorf("audit serial and expiry must be set: %+v", issued)
	}
	if minter.cluster != "prod-k8s" || minter.ns != "agents" || minter.ttl != 600*time.Second {
		t.Errorf("mint parameters: %+v", minter)
	}

	// No end-user identity → the default binding.
	in = k8sIntent(K8sAction{Verb: "get", Resource: "pods", Namespace: "prod", Name: "web-1"})
	issued, err = l.SignIntent(context.Background(), in)
	if err != nil || issued.K8sToken != "tok-broker-default" {
		t.Errorf("default binding must serve identity-less callers: %+v, %v", issued, err)
	}

	// Approval gate: no token before approval; token after (forwarder sets it).
	del := k8sIntent(K8sAction{Verb: "delete", Resource: "pods", Namespace: "prod", Name: "web-1"})
	issued, err = l.SignIntent(context.Background(), del)
	if err != nil {
		t.Fatal(err)
	}
	if issued.K8sToken != "" || issued.Decision == nil || !issued.Decision.RequireApproval {
		t.Errorf("approval-gated action must return decision without a token: %+v", issued)
	}
	del.Approved = true
	issued, err = l.SignIntent(context.Background(), del)
	if err != nil || issued.K8sToken == "" {
		t.Errorf("approved action must mint: %+v, %v", issued, err)
	}

	// Dry run returns the decision and never mints.
	minter.cluster = ""
	dry := k8sIntent(K8sAction{Verb: "get", Resource: "pods", Namespace: "prod", Name: "web-1"})
	dry.DryRun = true
	issued, err = l.SignIntent(context.Background(), dry)
	if err != nil || issued.K8sToken != "" || issued.Decision == nil || !issued.Decision.Allowed {
		t.Errorf("dry-run: %+v, %v", issued, err)
	}
	if minter.cluster != "" {
		t.Error("dry-run must not mint a token")
	}
	// Dry-run denial is a result, not an error (same contract as SSH).
	dry.K8s = &K8sAction{Verb: "apply", Resource: "configmaps", Namespace: "p", Name: "x"}
	dry.Command = dry.K8s.Canonical()
	issued, err = l.SignIntent(context.Background(), dry)
	if err != nil || issued.Decision == nil || issued.Decision.Allowed {
		t.Errorf("dry-run denial: %+v, %v", issued, err)
	}
}

func TestSignK8sBindingSelection(t *testing.T) {
	t.Parallel()
	cp := testCluster(t, []K8sRule{{Verbs: []string{"get"}, Resources: []string{"pods"}, Effect: "allow"}})
	cp.SABindings = []SABinding{{Groups: []string{"platform"}, Namespace: "agents", ServiceAccount: "sa-platform"}}
	l := NewLocal(nil, nil, time.Minute).WithK8s(compileOne(t, cp), &fakeMinter{})

	// The cluster group gate passes (nil groups = unrestricted), but no binding
	// matches an identity-less caller when there is no default binding.
	in := k8sIntent(K8sAction{Verb: "get", Resource: "pods", Namespace: "p", Name: "x"})
	if _, err := l.SignIntent(context.Background(), in); err == nil || !strings.Contains(err.Error(), "sa_binding") {
		t.Errorf("no matching binding must fail closed: %v", err)
	}
}

func TestHostAllowlistActiveCoversClusters(t *testing.T) {
	t.Parallel()
	ct := compileOne(t, testCluster(t, []K8sRule{{Verbs: []string{"get"}, Resources: []string{"pods"}, Effect: "allow"}}))
	l := NewLocal(nil, PolicyTable{}, time.Minute).WithK8s(ct, &fakeMinter{})

	exists, allowlist := l.HostAllowlistActive("prod-k8s")
	if !exists || !allowlist {
		t.Errorf("clusters must be grant-eligible (allowlist-active): exists=%v allowlist=%v", exists, allowlist)
	}
}
