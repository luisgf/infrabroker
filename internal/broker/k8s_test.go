package broker

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luisgf/infrabroker/internal/audit"
	"github.com/luisgf/infrabroker/internal/signer"
)

// openTestAudit opens an audit log in a temp file for a test.
func openTestAudit(t *testing.T) *audit.Log {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.log")
	al, err := audit.Open(path, ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)))
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	t.Cleanup(func() { al.Close() })
	t.Cleanup(func() { auditPaths[t.Name()] = path })
	auditPaths[t.Name()] = path
	return al
}

// auditPaths maps a test name to its audit log path so readAuditLog can find
// it without threading the path through the engine.
var auditPaths = map[string]string{}

// readAuditLog returns the audit log lines written by the engine under test.
func readAuditLog(t *testing.T, _ *Engine) []string {
	t.Helper()
	f, err := os.Open(auditPaths[t.Name()])
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 256*1024), 256*1024)
	for sc.Scan() {
		if s := strings.TrimSpace(sc.Text()); s != "" {
			lines = append(lines, s)
		}
	}
	return lines
}

// fakeK8sSigner is a signer.Signer that authorises a fixed set of canonical
// actions and returns a bound token; anything else is denied. It records the
// last intent for assertions.
type fakeK8sSigner struct {
	allow    map[string]bool // canonical → allowed
	approval map[string]bool // canonical → requires approval
	last     signer.Intent
}

func (f *fakeK8sSigner) SignIntent(_ context.Context, in signer.Intent) (*signer.Issued, error) {
	f.last = in
	if in.TargetType != signer.TargetTypeK8s {
		return nil, context.Canceled
	}
	canonical := in.K8s.Canonical()
	if in.Command != canonical {
		return nil, errString("canonical mismatch")
	}
	if !f.allow[canonical] {
		if in.DryRun {
			return &signer.Issued{Decision: &signer.DecisionInfo{Allowed: false, Reason: "denied"}}, nil
		}
		return nil, errString("not allowed by cluster policy")
	}
	if f.approval[canonical] && !in.Approved {
		return &signer.Issued{Decision: &signer.DecisionInfo{Allowed: true, RequireApproval: true}}, nil
	}
	if in.DryRun {
		return &signer.Issued{Decision: &signer.DecisionInfo{Allowed: true}}, nil
	}
	return &signer.Issued{K8sToken: "ephemeral", K8sTokenExpiry: time.Now().Add(time.Minute), Serial: 7,
		Decision: &signer.DecisionInfo{Allowed: true}}, nil
}

type errString string

func (e errString) Error() string { return string(e) }

// newK8sEngine builds an engine wired to the fake signer and a fake API
// server, with one cluster in the cache.
func newK8sEngine(t *testing.T, sgn signer.Signer) (*Engine, *fakeAPIServer) {
	t.Helper()
	api := newFakeAPIServer(t)
	al := openTestAudit(t)
	e := &Engine{
		cfg:      &Config{},
		sgn:      sgn,
		auditLog: al,
		maxTTL:   time.Minute,
		clusters: map[string]signer.ClusterInfo{
			"prod-k8s": {APIServer: api.srv.URL, CACertPEM: api.caPEM, Groups: []string{"platform"}},
		},
	}
	return e, api
}

// fakeAPIServer records the last path and returns a canned body.
type fakeAPIServer struct {
	srv     *httptest.Server
	caPEM   string
	lastURL string
}

func newFakeAPIServer(t *testing.T) *fakeAPIServer {
	t.Helper()
	f := &fakeAPIServer{}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.lastURL = r.URL.String()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"kind":"Pod","metadata":{"name":"web-1"}}`))
	}))
	t.Cleanup(f.srv.Close)
	f.caPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw}))
	return f
}

func TestK8sExecuteHappyPath(t *testing.T) {
	sgn := &fakeK8sSigner{allow: map[string]bool{"get pods prod/web-1": true}}
	e, api := newK8sEngine(t, sgn)

	res, err := e.K8sExecute(context.Background(), Caller{ID: "alice", Groups: []string{"platform"}},
		"prod-k8s", signer.K8sAction{Verb: "get", Resource: "pods", Namespace: "prod", Name: "web-1"},
		nil, false, K8sExecuteOpts{})
	if err != nil {
		t.Fatalf("K8sExecute: %v", err)
	}
	if !strings.Contains(res.Output, "web-1") || res.Serial != 7 {
		t.Errorf("unexpected result: %+v", res)
	}
	if api.lastURL != "/api/v1/namespaces/prod/pods/web-1" {
		t.Errorf("API path = %q", api.lastURL)
	}
	// The intent the signer saw must carry the k8s target and canonical command.
	if sgn.last.TargetType != signer.TargetTypeK8s || sgn.last.Command != "get pods prod/web-1" {
		t.Errorf("intent: %+v", sgn.last)
	}
	if sgn.last.EndUser != "alice" {
		t.Errorf("end user not propagated: %+v", sgn.last)
	}
}

func TestK8sExecuteGroupNormalization(t *testing.T) {
	// The caller omits the group; the broker must fill in "apps" from the table
	// so the canonical form matches what the signer authorises.
	sgn := &fakeK8sSigner{allow: map[string]bool{"get deployments.apps prod/api": true}}
	e, _ := newK8sEngine(t, sgn)

	if _, err := e.K8sExecute(context.Background(), Caller{},
		"prod-k8s", signer.K8sAction{Verb: "get", Resource: "deployments", Namespace: "prod", Name: "api"},
		nil, false, K8sExecuteOpts{}); err != nil {
		t.Fatalf("K8sExecute: %v", err)
	}
	if sgn.last.Command != "get deployments.apps prod/api" {
		t.Errorf("broker must normalize the group into the canonical command: %q", sgn.last.Command)
	}
}

func TestK8sExecuteClusterScopedNamespaceDropped(t *testing.T) {
	// A cluster-scoped resource (nodes) takes no namespace. A client-supplied
	// namespace must be dropped so the canonical the signer authorises, the
	// audit records, and the approver sees reflects the TRUE cluster-wide scope
	// — not a namespaced-looking action that runs cluster-wide anyway (blast-
	// radius misrepresentation + namespaced-deny evasion). resourcePath already
	// omits the namespace for these; this keeps the canonical honest.
	sgn := &fakeK8sSigner{allow: map[string]bool{"delete nodes -/node-1": true}}
	e, api := newK8sEngine(t, sgn)

	if _, err := e.K8sExecute(context.Background(), Caller{ID: "alice", Groups: []string{"platform"}},
		"prod-k8s", signer.K8sAction{Verb: "delete", Resource: "nodes", Namespace: "kube-system", Name: "node-1"},
		nil, false, K8sExecuteOpts{}); err != nil {
		t.Fatalf("K8sExecute: %v", err)
	}
	if sgn.last.Command != "delete nodes -/node-1" {
		t.Errorf("client namespace on a cluster-scoped resource must be dropped from the canonical: got %q", sgn.last.Command)
	}
	if sgn.last.K8s.Namespace != "" {
		t.Errorf("namespace must be cleared on the signed action: got %q", sgn.last.K8s.Namespace)
	}
	if api.lastURL != "/api/v1/nodes/node-1" {
		t.Errorf("execution must be cluster-wide: API path = %q", api.lastURL)
	}
	for _, line := range readAuditLog(t, e) {
		if strings.Contains(line, "kube-system") {
			t.Errorf("audit must not misrepresent scope with the dropped namespace: %s", line)
		}
	}
}

func TestK8sExecuteDenied(t *testing.T) {
	sgn := &fakeK8sSigner{allow: map[string]bool{}}
	e, _ := newK8sEngine(t, sgn)

	if _, err := e.K8sExecute(context.Background(), Caller{},
		"prod-k8s", signer.K8sAction{Verb: "delete", Resource: "pods", Namespace: "prod", Name: "web-1"},
		nil, false, K8sExecuteOpts{}); err == nil {
		t.Fatal("a denied action must error")
	}
}

func TestK8sExecuteApprovalGate(t *testing.T) {
	sgn := &fakeK8sSigner{
		allow:    map[string]bool{"delete pods prod/web-1": true},
		approval: map[string]bool{"delete pods prod/web-1": true},
	}
	e, _ := newK8sEngine(t, sgn)

	// Without approval the token is withheld → surfaced as an approval error.
	_, err := e.K8sExecute(context.Background(), Caller{},
		"prod-k8s", signer.K8sAction{Verb: "delete", Resource: "pods", Namespace: "prod", Name: "web-1"},
		nil, false, K8sExecuteOpts{})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "approval") {
		t.Fatalf("approval-gated action must surface an approval error, got %v", err)
	}
}

func TestK8sExecuteDryRun(t *testing.T) {
	sgn := &fakeK8sSigner{allow: map[string]bool{"get pods prod/web-1": true}}
	e, api := newK8sEngine(t, sgn)

	res, err := e.K8sExecute(context.Background(), Caller{},
		"prod-k8s", signer.K8sAction{Verb: "get", Resource: "pods", Namespace: "prod", Name: "web-1"},
		nil, true, K8sExecuteOpts{})
	if err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	if res.DryRun == nil || !res.DryRun.Allowed {
		t.Errorf("dry-run must return the decision: %+v", res)
	}
	if api.lastURL != "" {
		t.Error("dry-run must not call the API server")
	}
}

func TestK8sExecuteUnknownCluster(t *testing.T) {
	sgn := &fakeK8sSigner{}
	e, _ := newK8sEngine(t, sgn)
	if _, err := e.K8sExecute(context.Background(), Caller{},
		"nope", signer.K8sAction{Verb: "get", Resource: "pods", Namespace: "p", Name: "x"},
		nil, false, K8sExecuteOpts{}); err == nil {
		t.Fatal("unknown cluster must error")
	}
}

func TestK8sExecuteApplyAuditsBodyHash(t *testing.T) {
	sgn := &fakeK8sSigner{allow: map[string]bool{"apply configmaps prod/cfg": true}}
	e, _ := newK8sEngine(t, sgn)
	manifest := []byte(`{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"cfg","namespace":"prod"},"data":{"k":"v"}}`)

	if _, err := e.K8sExecute(context.Background(), Caller{},
		"prod-k8s", signer.K8sAction{Verb: "apply", Resource: "configmaps", Namespace: "prod", Name: "cfg"},
		manifest, false, K8sExecuteOpts{}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	// The manifest must never appear verbatim in the audit log; its sha256 does.
	entries := readAuditLog(t, e)
	var found bool
	for _, line := range entries {
		if strings.Contains(line, `"k":"v"`) {
			t.Fatal("manifest body leaked into the audit log")
		}
		if strings.Contains(line, `"body_sha256"`) && strings.Contains(line, "apply configmaps prod/cfg") {
			found = true
		}
	}
	if !found {
		t.Error("apply audit entry must record body_sha256")
	}
}

func TestK8sClustersFilteredByGroups(t *testing.T) {
	e, _ := newK8sEngine(t, &fakeK8sSigner{})
	// A user in the platform group sees the cluster; a user in another group
	// does not; a caller with no groups (nil) sees all.
	if got := e.K8sClusters(Caller{Groups: []string{"platform"}}); len(got) != 1 {
		t.Errorf("platform user must see the cluster: %v", got)
	}
	if got := e.K8sClusters(Caller{Groups: []string{"web"}}); len(got) != 0 {
		t.Errorf("non-member must see no clusters: %v", got)
	}
	if got := e.K8sClusters(Caller{}); len(got) != 1 {
		t.Errorf("identity-less caller sees all clusters: %v", got)
	}
}
