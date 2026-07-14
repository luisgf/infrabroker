package k8s

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeAPI records the last request and answers with a canned body.
type fakeAPI struct {
	srv      *httptest.Server
	caPEM    []byte
	lastReq  *http.Request
	lastBody []byte
	status   int
	respond  string
}

func newFakeAPI(t *testing.T) *fakeAPI {
	t.Helper()
	f := &fakeAPI{status: 200, respond: `{"ok":true}`}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io_ReadAll(r)
		f.lastReq = r.Clone(context.Background())
		f.lastBody = body
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(f.status)
		w.Write([]byte(f.respond))
	}))
	t.Cleanup(f.srv.Close)
	f.caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw})
	return f
}

func io_ReadAll(r *http.Request) ([]byte, error) {
	defer r.Body.Close()
	buf := make([]byte, 0, 1024)
	tmp := make([]byte, 1024)
	for {
		n, err := r.Body.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			return buf, nil
		}
	}
}

func (f *fakeAPI) client(t *testing.T) *Client {
	t.Helper()
	c, err := NewClient(Target{APIServer: f.srv.URL, CAPEM: f.caPEM}, "test-token", 5*time.Second)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func mustDef(t *testing.T, resource string) ResourceDef {
	t.Helper()
	table, err := Resources(nil)
	if err != nil {
		t.Fatal(err)
	}
	def, err := Resolve(table, resource, "")
	if err != nil {
		t.Fatal(err)
	}
	return def
}

func TestClientPathsAndAuth(t *testing.T) {
	f := newFakeAPI(t)
	c := f.client(t)
	ctx := context.Background()

	// Core namespaced resource.
	if _, err := c.Get(ctx, mustDef(t, "pods"), "prod", "web-1"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got := f.lastReq.URL.Path; got != "/api/v1/namespaces/prod/pods/web-1" {
		t.Errorf("core path = %q", got)
	}
	if got := f.lastReq.Header.Get("Authorization"); got != "Bearer test-token" {
		t.Errorf("auth header = %q", got)
	}

	// Grouped resource.
	if _, err := c.Get(ctx, mustDef(t, "deployments"), "prod", "api"); err != nil {
		t.Fatal(err)
	}
	if got := f.lastReq.URL.Path; got != "/apis/apps/v1/namespaces/prod/deployments/api" {
		t.Errorf("grouped path = %q", got)
	}

	// Cluster-scoped list has no namespaces segment; selectors and limit ride
	// in the query.
	if _, err := c.List(ctx, mustDef(t, "nodes"), "", ListOptions{LabelSelector: "role=worker", Limit: 5}); err != nil {
		t.Fatal(err)
	}
	if got := f.lastReq.URL.Path; got != "/api/v1/nodes" {
		t.Errorf("cluster-scoped path = %q", got)
	}
	if q := f.lastReq.URL.Query(); q.Get("labelSelector") != "role=worker" || q.Get("limit") != "5" {
		t.Errorf("list query = %v", f.lastReq.URL.Query())
	}

	// Logs endpoint with a default tail bound.
	if _, err := c.Logs(ctx, "prod", "web-1", LogOptions{Container: "app"}); err != nil {
		t.Fatal(err)
	}
	if got := f.lastReq.URL.Path; got != "/api/v1/namespaces/prod/pods/web-1/log" {
		t.Errorf("logs path = %q", got)
	}
	if q := f.lastReq.URL.Query(); q.Get("tailLines") != "200" || q.Get("container") != "app" {
		t.Errorf("logs query = %v", f.lastReq.URL.Query())
	}

	// Delete.
	if _, err := c.Delete(ctx, mustDef(t, "pods"), "prod", "web-1"); err != nil {
		t.Fatal(err)
	}
	if f.lastReq.Method != http.MethodDelete {
		t.Errorf("delete method = %q", f.lastReq.Method)
	}
}

func TestClientApply(t *testing.T) {
	f := newFakeAPI(t)
	c := f.client(t)
	manifest := []byte(`{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"api","namespace":"prod"}}`)

	if _, err := c.Apply(context.Background(), mustDef(t, "deployments"), "prod", "api", manifest); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if f.lastReq.Method != http.MethodPatch {
		t.Errorf("apply method = %q", f.lastReq.Method)
	}
	if ct := f.lastReq.Header.Get("Content-Type"); ct != "application/apply-patch+yaml" {
		t.Errorf("apply content-type = %q", ct)
	}
	if q := f.lastReq.URL.Query(); q.Get("fieldManager") != FieldManager || q.Get("force") != "" {
		t.Errorf("apply query = %v", f.lastReq.URL.Query())
	}
	if string(f.lastBody) != string(manifest) {
		t.Errorf("apply body = %s", f.lastBody)
	}
}

func TestClientSurfacesStatusMessage(t *testing.T) {
	f := newFakeAPI(t)
	f.status = 404
	f.respond = `{"kind":"Status","message":"pods \"nope\" not found","reason":"NotFound"}`
	c := f.client(t)

	_, err := c.Get(context.Background(), mustDef(t, "pods"), "prod", "nope")
	if err == nil || !strings.Contains(err.Error(), `pods "nope" not found`) {
		t.Fatalf("expected the API status message, got %v", err)
	}
}

func TestClientRequiresParsableCA(t *testing.T) {
	// No system roots and no TOFU: a client without a parsable cluster CA must
	// not be constructible at all (fail-closed).
	if _, err := NewClient(Target{APIServer: "https://x", CAPEM: []byte("not a pem")}, "t", time.Second); err == nil {
		t.Fatal("an unparsable cluster CA must fail NewClient")
	}
	if _, err := NewClient(Target{APIServer: "https://x"}, "t", time.Second); err == nil {
		t.Fatal("an empty cluster CA must fail NewClient")
	}
}

func TestMinter(t *testing.T) {
	f := newFakeAPI(t)
	expiry := time.Now().Add(10 * time.Minute).UTC().Truncate(time.Second)
	respond, _ := json.Marshal(map[string]any{
		"status": map[string]any{"token": "ephemeral-tok", "expirationTimestamp": expiry},
	})
	f.respond = string(respond)

	tokFile := filepath.Join(t.TempDir(), "minter.token")
	if err := os.WriteFile(tokFile, []byte("minter-credential\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := NewMinter(map[string]MinterTarget{
		"prod-cluster": {Target: Target{APIServer: f.srv.URL, CAPEM: f.caPEM}, TokenFile: tokFile},
	})

	tok, exp, err := m.MintToken(context.Background(), "prod-cluster", "agents", "infrabroker-agent", 10*time.Minute)
	if err != nil {
		t.Fatalf("MintToken: %v", err)
	}
	if tok != "ephemeral-tok" || !exp.Equal(expiry) {
		t.Errorf("token/expiry = %q/%v", tok, exp)
	}
	if got := f.lastReq.URL.Path; got != "/api/v1/namespaces/agents/serviceaccounts/infrabroker-agent/token" {
		t.Errorf("token path = %q", got)
	}
	if got := f.lastReq.Header.Get("Authorization"); got != "Bearer minter-credential" {
		t.Errorf("minter auth = %q (must be the trimmed file content)", got)
	}
	var body struct {
		Spec struct {
			ExpirationSeconds int `json:"expirationSeconds"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(f.lastBody, &body); err != nil || body.Spec.ExpirationSeconds != 600 {
		t.Errorf("TokenRequest body = %s", f.lastBody)
	}

	if _, _, err := m.MintToken(context.Background(), "nope", "a", "b", time.Minute); err == nil {
		t.Error("unknown cluster must fail")
	}
}

func TestResourcesTable(t *testing.T) {
	t.Parallel()
	// Extra resources extend the table; collisions and incomplete entries fail.
	table, err := Resources([]ResourceDef{{Resource: "certificates", Group: "cert-manager.io", Version: "v1", Kind: "Certificate", Namespaced: true}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Resolve(table, "certificates", ""); err != nil {
		t.Errorf("extra resource must resolve: %v", err)
	}
	if _, err := Resolve(table, "pods", "apps"); err == nil {
		t.Error("group mismatch must fail")
	}
	if _, err := Resolve(table, "unknownthings", ""); err == nil {
		t.Error("unknown resource must fail")
	}
	if _, err := Resources([]ResourceDef{{Resource: "pods", Version: "v2", Kind: "Pod"}}); err == nil {
		t.Error("a collision with the core table must fail")
	}
	if _, err := Resources([]ResourceDef{{Resource: "widgets"}}); err == nil {
		t.Error("an incomplete extra resource must fail")
	}
}

// TestResourcesTableRejectsInvalidCharset pins #281: a resource/group identifier
// that is not a valid RFC 1123 label/subdomain (a space, a slash, uppercase)
// must be rejected at config load, so it can never flow into the signer's
// canonical action string "<verb> <resource[.group]> <ns>/<name>" and break the
// space/slash-free anti-mismatch guarantee.
func TestResourcesTableRejectsInvalidCharset(t *testing.T) {
	t.Parallel()
	bad := []ResourceDef{
		{Resource: "my crd", Version: "v1", Kind: "X"},                    // space in resource
		{Resource: "my/crd", Version: "v1", Kind: "X"},                    // slash in resource
		{Resource: "Widgets", Version: "v1", Kind: "X"},                   // uppercase resource
		{Resource: "widgets", Group: "foo/bar", Version: "v1", Kind: "X"}, // slash in group
		{Resource: "widgets", Group: "foo bar", Version: "v1", Kind: "X"}, // space in group
	}
	for _, r := range bad {
		if _, err := Resources([]ResourceDef{r}); err == nil {
			t.Errorf("extra_resources %+v must be rejected (invalid RFC 1123 charset)", r)
		}
	}
	// A valid subdomain group (dots) is still accepted.
	if _, err := Resources([]ResourceDef{{Resource: "certificates", Group: "cert-manager.io", Version: "v1", Kind: "Certificate", Namespaced: true}}); err != nil {
		t.Errorf("a valid extra_resources entry must be accepted: %v", err)
	}
}
