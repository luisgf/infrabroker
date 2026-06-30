package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/luisgf/ssh-broker/internal/audit"
	"github.com/luisgf/ssh-broker/internal/signer"
)

// grantTestServer builds a server with web01 (allowlist ^uptime$), db01
// (default-allow), an in-memory grant store, reload_callers={admin}, and an
// optional grant-TTL cap. The Local has a nil CA — fine because every assertion
// uses a dry-run intent, which resolves the policy without issuing a cert.
func grantTestServer(t *testing.T, maxGrantTTL time.Duration) *server {
	t.Helper()
	hosts := signer.PolicyTable{
		"web01": {Principal: "host:web01", CommandPolicy: signer.CommandPolicy{Mode: signer.CmdPolicyAllowlist, Allow: []string{"^uptime$"}}},
		"db01":  {Principal: "host:db01"},
	}
	compiled, err := signer.CompileHostPolicies(hosts, nil, nil)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	store := signer.NewGrantStore()
	local := signer.NewLocalWithGrants(nil, nil, compiled, 5*time.Minute, store)

	seed := make([]byte, ed25519.SeedSize) // deterministic test signing key
	auditLog, err := audit.Open(filepath.Join(t.TempDir(), "audit.log"), ed25519.NewKeyFromSeed(seed))
	if err != nil {
		t.Fatalf("audit open: %v", err)
	}
	t.Cleanup(func() { auditLog.Close() })

	return &server{
		local:       local,
		hosts:       compiled,
		audit:       auditLog,
		reloadCN:    map[string]struct{}{"admin": {}},
		grants:      store,
		maxGrantTTL: maxGrantTTL,
	}
}

func grantMux(s *server) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/policy/hosts/{host}/grants", s.handleGrantCreate)
	mux.HandleFunc("GET /v1/policy/grants", s.handleGrantList)
	mux.HandleFunc("DELETE /v1/policy/grants/{id}", s.handleGrantRevoke)
	return mux
}

func grantRequest(method, target, cn string, body any) *http.Request {
	var rdr *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, target, rdr)
	if cn != "" {
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: cn}}}}
	}
	return req
}

// dryRunAllowed reports whether the signer would allow cmd on host right now,
// going through the same SignIntent path the /v1/sign handler uses (so it sees
// the live grant store).
func dryRunAllowed(t *testing.T, s *server, host, cmd string) bool {
	t.Helper()
	local, _, _, _ := s.snapshot()
	issued, err := local.SignIntent(context.Background(), signer.Intent{
		Host: host, Role: signer.RoleTarget, Purpose: signer.PurposeOneshot, Command: cmd, DryRun: true,
	})
	if err != nil {
		t.Fatalf("dry-run sign: %v", err)
	}
	return issued.Decision != nil && issued.Decision.Allowed
}

// TestGrantRevokeRejectsTokenInjectionInID is the regression test for audit
// token forgery via the revoke {id} path: ServeMux percent-decodes the segment,
// so a "%20" yields a literal space that auditGrant would splice into Command.
// A real grant id is system-generated hex, so a whitespace-bearing id must be
// rejected with 400 before any audit write, while a clean id still reaches the
// revoke logic (404 for an unknown one).
func TestGrantRevokeRejectsTokenInjectionInID(t *testing.T) {
	t.Parallel()
	srv := grantTestServer(t, 0)
	mux := grantMux(srv)

	// %20 → literal spaces in PathValue("id"): must be rejected with 400 before
	// the pre-authz grant-denied audit could record the forged tokens.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, grantRequest(http.MethodDelete, "/v1/policy/grants/abc%20user=victim%20elev=sudo:root", "admin", nil))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("whitespace id: status = %d, want 400", rec.Code)
	}

	// A clean (hex-shaped) id passes the gate and reaches Revoke → 404 unknown.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, grantRequest(http.MethodDelete, "/v1/policy/grants/deadbeefdeadbeef", "admin", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("clean unknown id: status = %d, want 404 (gate must not over-reject)", rec.Code)
	}
}

// TestGrantEndpointsEndToEnd drives the grant HTTP surface and asserts the live
// effect on the decision: create flips a denied command to allowed, revoke flips
// it back. Mirrors the v1.17.0 mutation-API e2e.
func TestGrantEndpointsEndToEnd(t *testing.T) {
	t.Parallel()
	srv := grantTestServer(t, 0)
	mux := grantMux(srv)
	const cmd = "systemctl restart nginx"

	// Baseline: web01 is an allowlist that does not permit systemctl.
	if dryRunAllowed(t, srv, "web01", cmd) {
		t.Fatal("baseline: systemctl should be denied on web01")
	}

	// Create a grant as the authorised admin.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, grantRequest(http.MethodPost, "/v1/policy/hosts/web01/grants", "admin",
		map[string]any{"allow": []string{"^systemctl restart nginx$"}, "ttl_seconds": 3600}))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: status = %d, want 201 (%s)", rec.Code, rec.Body)
	}
	var created struct {
		ID        string `json:"id"`
		Host      string `json:"host"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	if created.ID == "" || created.Host != "web01" || created.ExpiresAt == "" {
		t.Fatalf("create response incomplete: %+v", created)
	}

	// The grant widened the allowlist: the command is now allowed.
	if !dryRunAllowed(t, srv, "web01", cmd) {
		t.Fatal("after grant: systemctl should be allowed on web01")
	}

	// List shows the grant.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, grantRequest(http.MethodGet, "/v1/policy/grants", "admin", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("list: status = %d, want 200", rec.Code)
	}
	var grants []signer.Grant
	if err := json.Unmarshal(rec.Body.Bytes(), &grants); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(grants) != 1 || grants[0].ID != created.ID || grants[0].Approver != "admin" {
		t.Fatalf("list should show the created grant with its approver: %+v", grants)
	}

	// Revoke it; the command is denied again.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, grantRequest(http.MethodDelete, "/v1/policy/grants/"+created.ID, "admin", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke: status = %d, want 200", rec.Code)
	}
	if dryRunAllowed(t, srv, "web01", cmd) {
		t.Fatal("after revoke: systemctl should be denied again")
	}
}

func TestGrantEndpointAuthAndValidation(t *testing.T) {
	t.Parallel()
	srv := grantTestServer(t, time.Hour) // cap grant TTL at 1h
	mux := grantMux(srv)
	goodBody := map[string]any{"allow": []string{"^systemctl restart nginx$"}, "ttl_seconds": 600}

	cases := []struct {
		name   string
		method string
		target string
		cn     string
		body   any
		want   int
	}{
		{"unauthenticated", http.MethodPost, "/v1/policy/hosts/web01/grants", "", goodBody, http.StatusUnauthorized},
		{"not-authorised", http.MethodPost, "/v1/policy/hosts/web01/grants", "broker-1", goodBody, http.StatusForbidden},
		{"unknown-host", http.MethodPost, "/v1/policy/hosts/ghost/grants", "admin", goodBody, http.StatusNotFound},
		{"non-allowlist-host", http.MethodPost, "/v1/policy/hosts/db01/grants", "admin", goodBody, http.StatusConflict},
		{"bad-regex", http.MethodPost, "/v1/policy/hosts/web01/grants", "admin", map[string]any{"allow": []string{"("}, "ttl_seconds": 600}, http.StatusBadRequest},
		{"ttl-over-cap", http.MethodPost, "/v1/policy/hosts/web01/grants", "admin", map[string]any{"allow": []string{"^x$"}, "ttl_seconds": 7200}, http.StatusBadRequest},
		{"no-allow", http.MethodPost, "/v1/policy/hosts/web01/grants", "admin", map[string]any{"ttl_seconds": 600}, http.StatusBadRequest},
		{"list-not-authorised", http.MethodGet, "/v1/policy/grants", "broker-1", nil, http.StatusForbidden},
		{"revoke-unknown", http.MethodDelete, "/v1/policy/grants/nope", "admin", nil, http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, grantRequest(tc.method, tc.target, tc.cn, tc.body))
			if rec.Code != tc.want {
				t.Errorf("status = %d, want %d (%s)", rec.Code, tc.want, rec.Body)
			}
		})
	}
}
