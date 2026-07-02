package main

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/luisgf/ssh-broker/internal/audit"
	"github.com/luisgf/ssh-broker/internal/signer"
)

// policyReadHosts is a raw (uncompiled) table exercising every JSON-visible
// HostPolicy field, so the round-trip assertion proves the endpoint leaks
// nothing and loses nothing.
func policyReadHosts() signer.PolicyTable {
	return signer.PolicyTable{
		"web01": {
			Addr:             "10.0.0.1:22",
			User:             "deploy",
			HostKey:          "ssh-ed25519 AAAAC3Nza...",
			Jump:             "bastion",
			Principal:        "host:web01",
			SourceAddress:    "203.0.113.10",
			MaxTTLSeconds:    120,
			AllowAsBastion:   false,
			AllowedCallers:   []string{"broker-1"},
			AllowSudo:        true,
			AllowedSudoUsers: []string{"root", "deploy"},
			AllowPTY:         true,
			Groups:           []string{"prod-web"},
			CommandPolicy: signer.CommandPolicy{
				Mode:            signer.CmdPolicyAllowlist,
				ShellParse:      true,
				Allow:           []string{"^uptime$", "^systemctl restart [a-z0-9_.-]+$"},
				RequireApproval: []string{"^systemctl restart "},
			},
		},
		"bastion": {
			Addr:           "203.0.113.10:22",
			User:           "jump",
			HostKey:        "ssh-ed25519 AAAAC3Nzb...",
			Principal:      "host:bastion",
			MaxTTLSeconds:  60,
			AllowAsBastion: true,
			Groups:         []string{"prod-web"},
		},
	}
}

func policyReadTestServer(t *testing.T, reloadCN map[string]struct{}) *server {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize) // deterministic test signing key
	auditLog, err := audit.Open(filepath.Join(t.TempDir(), "audit.log"), ed25519.NewKeyFromSeed(seed))
	if err != nil {
		t.Fatalf("audit open: %v", err)
	}
	t.Cleanup(func() { auditLog.Close() })

	return &server{
		hosts:    policyReadHosts(),
		audit:    auditLog,
		reloadCN: reloadCN,
	}
}

func policyReadMux(s *server) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/policy/hosts", s.handlePolicyHostsRead)
	return mux
}

// TestPolicyHostsReadRoundTrip: an authorised CN gets the full table back,
// field for field — including the internal policy fields that GET /v1/hosts
// deliberately withholds (principal, source_address, max_ttl_seconds,
// allowed_callers, command_policy).
func TestPolicyHostsReadRoundTrip(t *testing.T) {
	t.Parallel()
	srv := policyReadTestServer(t, map[string]struct{}{"admin": {}})
	mux := policyReadMux(srv)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, grantRequest(http.MethodGet, "/v1/policy/hosts", "admin", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}

	var got signer.PolicyTable
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if want := policyReadHosts(); !reflect.DeepEqual(got, want) {
		t.Errorf("round-trip mismatch:\n got: %+v\nwant: %+v", got, want)
	}
}

// TestPolicyHostsReadAuth: the endpoint shares the reload_callers tier —
// unknown CN → 403, no client cert → 401, empty reload_callers → 403 for
// everyone (endpoint effectively disabled), non-GET → 405 from the mux.
func TestPolicyHostsReadAuth(t *testing.T) {
	t.Parallel()
	srv := policyReadTestServer(t, map[string]struct{}{"admin": {}})
	mux := policyReadMux(srv)

	cases := []struct {
		name   string
		method string
		cn     string
		want   int
	}{
		{"authorised", http.MethodGet, "admin", http.StatusOK},
		{"not-authorised", http.MethodGet, "broker-1", http.StatusForbidden},
		{"unauthenticated", http.MethodGet, "", http.StatusUnauthorized},
		{"post", http.MethodPost, "admin", http.StatusMethodNotAllowed},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, grantRequest(tc.method, "/v1/policy/hosts", tc.cn, nil))
		if rec.Code != tc.want {
			t.Errorf("%s: status = %d, want %d", tc.name, rec.Code, tc.want)
		}
	}

	// Empty reload_callers: nobody is authorised, matching the mutation APIs.
	empty := policyReadTestServer(t, map[string]struct{}{})
	rec := httptest.NewRecorder()
	policyReadMux(empty).ServeHTTP(rec, grantRequest(http.MethodGet, "/v1/policy/hosts", "admin", nil))
	if rec.Code != http.StatusForbidden {
		t.Errorf("empty reload_callers: status = %d, want 403", rec.Code)
	}
}

// TestPolicyHostsReadFreshness: the endpoint serves the in-memory table, so a
// hot-reload (simulated by swapping s.hosts under the lock) is visible on the
// next request without a restart.
func TestPolicyHostsReadFreshness(t *testing.T) {
	t.Parallel()
	srv := policyReadTestServer(t, map[string]struct{}{"admin": {}})
	mux := policyReadMux(srv)

	srv.mu.Lock()
	srv.hosts = signer.PolicyTable{"onlyone": {Principal: "host:onlyone", MaxTTLSeconds: 30}}
	srv.mu.Unlock()

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, grantRequest(http.MethodGet, "/v1/policy/hosts", "admin", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var got signer.PolicyTable
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if len(got) != 1 || got["onlyone"].Principal != "host:onlyone" {
		t.Errorf("response does not reflect the reloaded table: %+v", got)
	}
}
