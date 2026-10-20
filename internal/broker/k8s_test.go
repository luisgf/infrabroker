package broker

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
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
	mintErr  error           // when set, an allowed non-dry-run sign fails like a mint failure
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
	if f.mintErr != nil {
		return nil, f.mintErr
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
	status  int    // when non-zero, answer with this status and respond as the body
	respond string // body for a non-zero status
}

func newFakeAPIServer(t *testing.T) *fakeAPIServer {
	t.Helper()
	f := &fakeAPIServer{}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.lastURL = r.URL.String()
		w.Header().Set("Content-Type", "application/json")
		if f.status != 0 {
			w.WriteHeader(f.status)
			w.Write([]byte(f.respond))
			return
		}
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
	// … and audited as approval_required, the k8s sibling of #469 (#599): an
	// agent retrying an approval-gated action must leave a trace, not zero
	// lines. The record names the canonical and is not a dry-run.
	lines := readAuditLog(t, e)
	if len(lines) != 1 {
		t.Fatalf("want exactly one audit line (approval_required), got %d: %v", len(lines), lines)
	}
	for _, want := range []string{`"outcome":"approval_required"`, `"command":"target=k8s action=delete pods prod/web-1"`, `"target_type":"k8s"`} {
		if !strings.Contains(lines[0], want) {
			t.Errorf("approval_required record missing %s: %s", want, lines[0])
		}
	}
	if strings.Contains(lines[0], `"dry_run":true`) {
		t.Errorf("approval_required record must not be flagged dry_run: %s", lines[0])
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
	// A denied dry-run is a decision too, not an error.
	res, err = e.K8sExecute(context.Background(), Caller{},
		"prod-k8s", signer.K8sAction{Verb: "delete", Resource: "pods", Namespace: "prod", Name: "web-1"},
		nil, true, K8sExecuteOpts{})
	if err != nil || res.DryRun == nil || res.DryRun.Allowed {
		t.Fatalf("denied dry-run must return the decision: %+v, %v", res, err)
	}
	// Both dry-run records carry Entry.DryRun like the SSH path, so
	// broker-ctl audit show renders [dry-run] for k8s simulations (#599).
	lines := readAuditLog(t, e)
	if len(lines) != 2 {
		t.Fatalf("want two dry-run audit lines, got %d: %v", len(lines), lines)
	}
	for i, want := range []string{`"outcome":"dry_run_allowed"`, `"outcome":"dry_run_denied"`} {
		if !strings.Contains(lines[i], want) {
			t.Errorf("line %d: missing %s: %s", i, want, lines[i])
		}
		if !strings.Contains(lines[i], `"dry_run":true`) {
			t.Errorf("line %d: k8s dry-run record must set dry_run=true: %s", i, lines[i])
		}
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

// TestK8sExecuteLogsNonPodRejected pins #458: runK8sAction always reads
// /pods/<name>/log for logs, so an action naming any other resource must be
// refused by the grammar before the signer is asked (even when a rule would
// allow "logs configmaps …") and before the API server is called.
func TestK8sExecuteLogsNonPodRejected(t *testing.T) {
	sgn := &fakeK8sSigner{allow: map[string]bool{"logs configmaps prod/web": true, "logs deployments.apps prod/web": true}}
	e, api := newK8sEngine(t, sgn)
	for _, a := range []signer.K8sAction{
		{Verb: "logs", Resource: "configmaps", Namespace: "prod", Name: "web"},
		{Verb: "logs", Resource: "deployments", Namespace: "prod", Name: "web"},
	} {
		_, err := e.K8sExecute(context.Background(), Caller{ID: "alice", Groups: []string{"platform"}},
			"prod-k8s", a, nil, false, K8sExecuteOpts{})
		if err == nil || !strings.Contains(err.Error(), "pod logs only") {
			t.Fatalf("logs on %q must be rejected by the grammar, got %v", a.Resource, err)
		}
		if sgn.last.Command != "" {
			t.Fatalf("signer must not be asked for a logs action on %q: %+v", a.Resource, sgn.last)
		}
		if api.lastURL != "" {
			t.Fatalf("API server must not be called for a logs action on %q: %s", a.Resource, api.lastURL)
		}
	}
}

// TestK8sExecuteValidationFailuresAudited pins #459: every failure that
// precedes the signer round-trip (unknown cluster, action grammar, resource
// table, resource resolution) leaves one "denied" entry with the constant
// Command "target=k8s" and the detail in the structured err field — the
// unvalidated fields are never spliced into the token stream — so an agent
// cannot probe cluster/resource names or charsets unaudited.
func TestK8sExecuteValidationFailuresAudited(t *testing.T) {
	sgn := &fakeK8sSigner{allow: map[string]bool{}}
	e, api := newK8sEngine(t, sgn)
	// A cluster whose cached extra_resources collide with the core table makes
	// resourceTable fail.
	e.clusters["broken-k8s"] = signer.ClusterInfo{APIServer: "https://broken.internal:6443",
		ExtraResources: []signer.ResourceDef{{Resource: "pods", Version: "v1", Kind: "Pod", Namespaced: true}}}
	caller := Caller{ID: "alice", Groups: []string{"platform"}}

	cases := []struct {
		name     string
		cluster  string
		action   signer.K8sAction
		wantErr  string // substring of the returned error and the audit err
		wantHost string
	}{
		{"unknown cluster", "nope", signer.K8sAction{Verb: "get", Resource: "pods", Namespace: "p", Name: "x"}, "unknown cluster", "nope"},
		{"grammar: charset", "prod-k8s", signer.K8sAction{Verb: "get", Resource: "Pods", Namespace: "p", Name: "x"}, "invalid k8s resource", api.srv.URL},
		{"grammar: verb", "prod-k8s", signer.K8sAction{Verb: "exec", Resource: "pods", Namespace: "p", Name: "x"}, "unknown k8s verb", api.srv.URL},
		{"resource table", "broken-k8s", signer.K8sAction{Verb: "get", Resource: "pods", Namespace: "p", Name: "x"}, "extra_resources", "https://broken.internal:6443"},
		{"resolve: unknown resource", "prod-k8s", signer.K8sAction{Verb: "get", Resource: "secrets2", Namespace: "p", Name: "x"}, "unknown k8s resource", api.srv.URL},
		{"resolve: wrong group", "prod-k8s", signer.K8sAction{Verb: "get", Resource: "pods", Group: "apps", Namespace: "p", Name: "x"}, "belongs to group", api.srv.URL},
	}
	for _, tc := range cases {
		before := len(readAuditLog(t, e))
		_, err := e.K8sExecute(context.Background(), caller, tc.cluster, tc.action, nil, false, K8sExecuteOpts{})
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Fatalf("%s: want error containing %q, got %v", tc.name, tc.wantErr, err)
		}
		if sgn.last.Command != "" {
			t.Fatalf("%s: the signer must not be reached: %+v", tc.name, sgn.last)
		}
		lines := readAuditLog(t, e)
		if len(lines) != before+1 {
			t.Fatalf("%s: want exactly one audit entry, got %d", tc.name, len(lines)-before)
		}
		var ent struct {
			Caller     string `json:"caller"`
			Host       string `json:"host"`
			Command    string `json:"command"`
			Outcome    string `json:"outcome"`
			Err        string `json:"err"`
			TargetType string `json:"target_type"`
		}
		if err := json.Unmarshal([]byte(lines[len(lines)-1]), &ent); err != nil {
			t.Fatalf("%s: audit line not JSON: %v", tc.name, err)
		}
		if ent.Outcome != "denied" || ent.Command != "target=k8s" || ent.TargetType != signer.TargetTypeK8s {
			t.Errorf("%s: entry = %+v, want outcome denied, command \"target=k8s\", target_type k8s", tc.name, ent)
		}
		if ent.Caller != "alice" || ent.Host != tc.wantHost {
			t.Errorf("%s: caller/host = %q/%q, want alice/%q", tc.name, ent.Caller, ent.Host, tc.wantHost)
		}
		if !strings.Contains(ent.Err, tc.wantErr) {
			t.Errorf("%s: audit err = %q, want it to contain %q", tc.name, ent.Err, tc.wantErr)
		}
	}
}

// TestK8sExecuteRedactsBoundServiceAccountFromForbidden pins #669 at the
// broker: the layer-B Forbidden message the model receives does not name the
// bound ServiceAccount, while the broker's audit record keeps the unredacted
// text for the operator.
func TestK8sExecuteRedactsBoundServiceAccountFromForbidden(t *testing.T) {
	sgn := &fakeK8sSigner{allow: map[string]bool{"get secrets prod/db": true}}
	e, api := newK8sEngine(t, sgn)
	api.status = http.StatusForbidden
	api.respond = `{"kind":"Status","reason":"Forbidden","code":403,"message":"secrets \"db\" is forbidden: User \"system:serviceaccount:agents:broker-platform\" cannot get resource \"secrets\" in API group \"\" in the namespace \"prod\""}`

	_, err := e.K8sExecute(context.Background(), Caller{ID: "alice"}, "prod-k8s",
		signer.K8sAction{Verb: "get", Resource: "secrets", Namespace: "prod", Name: "db"}, nil, false, K8sExecuteOpts{})
	if err == nil {
		t.Fatal("expected the layer-B denial")
	}
	if strings.Contains(err.Error(), "system:serviceaccount:") || strings.Contains(err.Error(), "broker-platform") {
		t.Errorf("model-facing error leaks the bound ServiceAccount: %v", err)
	}
	if !strings.Contains(err.Error(), `cannot get resource "secrets"`) {
		t.Errorf("model-facing error lost the denial text: %v", err)
	}
	lines := readAuditLog(t, e)
	last := lines[len(lines)-1]
	if !strings.Contains(last, `"outcome":"error"`) || !strings.Contains(last, "system:serviceaccount:agents:broker-platform") {
		t.Errorf("the audit record must keep the unredacted API message: %s", last)
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

// TestK8sExecuteApplyEmptyManifestDeniedBeforeSigner pins #671: a live
// k8s_apply with an empty or whitespace-only manifest is refused before the
// signer round-trip — no bound token is minted (the signer would audit
// "issued" for a request that can never run) and no approval is requested —
// and leaves exactly one denied pre-signer record. A dry run is only a policy
// preview and is not affected.
func TestK8sExecuteApplyEmptyManifestDeniedBeforeSigner(t *testing.T) {
	canonical := "apply configmaps prod/cfg"
	for _, tc := range []struct {
		name     string
		manifest []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"whitespace", []byte(" \n\t ")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sgn := &fakeK8sSigner{
				allow:    map[string]bool{canonical: true},
				approval: map[string]bool{canonical: true},
			}
			e, api := newK8sEngine(t, sgn)
			before := len(readAuditLog(t, e))
			_, err := e.K8sExecute(context.Background(), Caller{ID: "alice"}, "prod-k8s",
				signer.K8sAction{Verb: "apply", Resource: "configmaps", Namespace: "prod", Name: "cfg"},
				tc.manifest, false, K8sExecuteOpts{})
			if err == nil || !strings.Contains(err.Error(), "k8s apply requires a manifest") {
				t.Fatalf("want 'k8s apply requires a manifest', got %v", err)
			}
			var appErr *ApprovalRequiredError
			if errors.As(err, &appErr) {
				t.Fatal("an empty manifest must not request an approval")
			}
			if sgn.last.Command != "" {
				t.Fatalf("the signer must never be called for an empty manifest: %+v", sgn.last)
			}
			if api.lastURL != "" {
				t.Errorf("the cluster must not be called, got %q", api.lastURL)
			}
			lines := readAuditLog(t, e)
			if len(lines) != before+1 {
				t.Fatalf("want exactly one audit entry, got %d", len(lines)-before)
			}
			var ent struct {
				Host    string `json:"host"`
				Command string `json:"command"`
				Outcome string `json:"outcome"`
				Err     string `json:"err"`
			}
			if err := json.Unmarshal([]byte(lines[len(lines)-1]), &ent); err != nil {
				t.Fatalf("audit line not JSON: %v", err)
			}
			if ent.Outcome != "denied" || ent.Command != "target=k8s" || ent.Host != api.srv.URL ||
				!strings.Contains(ent.Err, "k8s apply requires a manifest") {
				t.Errorf("entry = %+v, want a denied pre-signer record naming the missing manifest", ent)
			}
		})
	}

	// A dry run is a policy preview: it still reaches the signer.
	sgn := &fakeK8sSigner{allow: map[string]bool{canonical: true}}
	e, _ := newK8sEngine(t, sgn)
	res, err := e.K8sExecute(context.Background(), Caller{}, "prod-k8s",
		signer.K8sAction{Verb: "apply", Resource: "configmaps", Namespace: "prod", Name: "cfg"},
		nil, true, K8sExecuteOpts{})
	if err != nil || res.DryRun == nil || !res.DryRun.Allowed {
		t.Fatalf("a dry-run apply must still preview the decision: res=%+v err=%v", res, err)
	}
}

func TestK8sExecuteAuditDoesNotSpliceCallerIntoCommand(t *testing.T) {
	// c.ID is the OIDC user-claim value and is not charset-validated at the
	// broker. It must never be spliced into the space-delimited audit Command
	// stream, or a whitespace-bearing identity could forge tokens into a
	// hash-chained entry (the class the signer guards, cf. #67). It rides in the
	// structured caller field instead.
	sgn := &fakeK8sSigner{allow: map[string]bool{"get pods prod/web-1": true}}
	e, _ := newK8sEngine(t, sgn)

	forged := "alice outcome=executed action=delete pods"
	if _, err := e.K8sExecute(context.Background(), Caller{ID: forged, Groups: []string{"platform"}},
		"prod-k8s", signer.K8sAction{Verb: "get", Resource: "pods", Namespace: "prod", Name: "web-1"},
		nil, false, K8sExecuteOpts{}); err != nil {
		t.Fatalf("K8sExecute: %v", err)
	}
	var checked bool
	for _, line := range readAuditLog(t, e) {
		var ent struct {
			Caller  string `json:"caller"`
			Command string `json:"command"`
		}
		if err := json.Unmarshal([]byte(line), &ent); err != nil {
			t.Fatalf("audit line not JSON: %v", err)
		}
		if !strings.HasPrefix(ent.Command, "target=k8s") {
			continue
		}
		checked = true
		if ent.Command != "target=k8s action=get pods prod/web-1" {
			t.Errorf("caller identity spliced into the audit Command: %q", ent.Command)
		}
		// The identity is preserved, safely, in the structured caller field.
		if ent.Caller != forged {
			t.Errorf("caller field = %q, want the raw identity %q", ent.Caller, forged)
		}
	}
	if !checked {
		t.Fatal("no k8s audit entry found")
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

// TestK8sExecuteMintFailureAuditedAsUpstreamError locks in #455 on the broker:
// a bound-token mint failure (local mode: *signer.K8sMintError; remote mode: a
// signer 5xx → ErrSignerUnavailable) is an infrastructure error — surfaced as
// ErrUpstream, audited "error" (not "denied"), and never carrying the SA
// binding or TokenRequest path to the model.
func TestK8sExecuteMintFailureAuditedAsUpstreamError(t *testing.T) {
	for name, mintErr := range map[string]error{
		"local mint error": &signer.K8sMintError{Cluster: "prod-k8s",
			Detail: errString("k8s: POST /api/v1/namespaces/agents/serviceaccounts/broker-platform/token: 401 Unauthorized")},
		"remote signer 5xx": fmt.Errorf("%w (502): cluster \"prod-k8s\": token minting failed", signer.ErrSignerUnavailable),
	} {
		t.Run(name, func(t *testing.T) {
			sgn := &fakeK8sSigner{allow: map[string]bool{"get pods prod/web-1": true}, mintErr: mintErr}
			e, _ := newK8sEngine(t, sgn)
			_, err := e.K8sExecute(context.Background(), Caller{},
				"prod-k8s", signer.K8sAction{Verb: "get", Resource: "pods", Namespace: "prod", Name: "web-1"},
				nil, false, K8sExecuteOpts{})
			if !errors.Is(err, ErrUpstream) {
				t.Fatalf("a mint failure must be an upstream error, got %v", err)
			}
			if strings.Contains(err.Error(), "serviceaccounts") {
				t.Errorf("SA binding leaked to the caller: %q", err.Error())
			}
			lines := readAuditLog(t, e)
			if len(lines) == 0 {
				t.Fatal("no audit entry")
			}
			last := lines[len(lines)-1]
			if !strings.Contains(last, `"outcome":"error"`) || strings.Contains(last, `"outcome":"denied"`) {
				t.Errorf("mint failure must be audited as error, got %s", last)
			}
		})
	}
}
