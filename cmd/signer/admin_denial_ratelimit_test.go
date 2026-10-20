package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/luisgf/infrabroker/internal/audit"
	"github.com/luisgf/infrabroker/internal/signer"
)

// countAuditOutcome returns how many records of the audit log at path carry
// the given outcome.
func countAuditOutcome(t *testing.T, path, outcome string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0
		}
		t.Fatal(err)
	}
	n := 0
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var e audit.Entry
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatalf("parse audit line: %v", err)
		}
		if e.Outcome == outcome {
			n++
		}
	}
	return n
}

// adminDenialTestServer builds a signer with the admin tier limited to "admin"
// and the per-CN sign budget set to limit, so an unauthorised CN's denials on
// the admin endpoints share that budget (#464).
func adminDenialTestServer(t *testing.T, limit int) (*server, string) {
	t.Helper()
	auditPath := filepath.Join(t.TempDir(), "audit.log")
	auditLog, err := audit.Open(auditPath, auditSeed())
	if err != nil {
		t.Fatalf("audit open: %v", err)
	}
	t.Cleanup(func() { auditLog.Close() })
	return &server{
		hosts:       policyReadHosts(),
		audit:       auditLog,
		reloadCN:    map[string]struct{}{"admin": {}},
		signRateMin: limit,
		rateLimiter: signer.NewRateLimiter(),
		grants:      signer.NewGrantStore(),
		freezes:     signer.NewFreezeStore(),
	}, auditPath
}

func adminDenialMux(s *server) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/policy/hosts", s.handlePolicyHostsRead)
	mux.HandleFunc("POST /v1/policy/hosts/{host}/allow", s.handlePolicyAllow)
	mux.HandleFunc("POST /v1/policy/hosts/{host}/grants", s.handleGrantCreate)
	mux.HandleFunc("DELETE /v1/policy/grants/{id}", s.handleGrantRevoke)
	mux.HandleFunc("POST /v1/reload", s.handleReload)
	return mux
}

// TestAdminDenialAuditRateLimited pins #464: an unauthorised CN looping an admin
// endpoint must not be able to force one signed+fsynced audit record per
// request. With sign_rate_limit_per_min = limit, N > limit unauthorised
// GET /v1/policy/hosts produce at most limit policy-read-denied entries; the
// first limit answers stay 403 (audited as before) and the excess is 429 with
// Retry-After, exactly like a rate-limited /v1/sign, and is not audited.
func TestAdminDenialAuditRateLimited(t *testing.T) {
	t.Parallel()
	const limit, n = 3, 10
	srv, auditPath := adminDenialTestServer(t, limit)
	mux := adminDenialMux(srv)

	var forbidden, tooMany int
	for i := 0; i < n; i++ {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, grantRequest(http.MethodGet, "/v1/policy/hosts", "broker-1", nil))
		switch rec.Code {
		case http.StatusForbidden:
			forbidden++
		case http.StatusTooManyRequests:
			tooMany++
			if rec.Header().Get("Retry-After") == "" {
				t.Errorf("request %d: 429 without Retry-After", i)
			}
		default:
			t.Fatalf("request %d: status = %d, want 403 or 429", i, rec.Code)
		}
	}
	if forbidden != limit || tooMany != n-limit {
		t.Errorf("got %d x 403 and %d x 429, want %d and %d", forbidden, tooMany, limit, n-limit)
	}
	if got := countAuditOutcome(t, auditPath, "policy-read-denied"); got > limit {
		t.Errorf("%d policy-read-denied audit records for %d requests, want <= %d", got, n, limit)
	}

	// The budget is per CN: another unauthorised CN is still denied and audited.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, grantRequest(http.MethodGet, "/v1/policy/hosts", "broker-2", nil))
	if rec.Code != http.StatusForbidden {
		t.Errorf("other CN: status = %d, want 403", rec.Code)
	}
	// An authorised admin is never gated by the denial budget.
	for i := 0; i < n; i++ {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, grantRequest(http.MethodGet, "/v1/policy/hosts", "admin", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("admin request %d: status = %d, want 200", i, rec.Code)
		}
	}
}

// TestAdminDenialAuditRateLimitSharedAcrossEndpoints: the four admin denial
// paths (policy read, policy mutation, grants, reload) all draw on the same
// per-CN bucket, so alternating endpoints does not multiply the budget.
func TestAdminDenialAuditRateLimitSharedAcrossEndpoints(t *testing.T) {
	t.Parallel()
	const limit = 4
	srv, auditPath := adminDenialTestServer(t, limit)
	mux := adminDenialMux(srv)

	reqs := []func() *http.Request{
		func() *http.Request { return grantRequest(http.MethodGet, "/v1/policy/hosts", "broker-1", nil) },
		func() *http.Request {
			return grantRequest(http.MethodPost, "/v1/policy/hosts/web01/allow", "broker-1", map[string]any{"pattern": "^uptime$"})
		},
		func() *http.Request {
			return grantRequest(http.MethodPost, "/v1/policy/hosts/web01/grants", "broker-1", map[string]any{"allow": []string{"^uptime$"}, "ttl_seconds": 60})
		},
		func() *http.Request { return grantRequest(http.MethodDelete, "/v1/policy/grants/abc", "broker-1", nil) },
		func() *http.Request { return grantRequest(http.MethodPost, "/v1/reload", "broker-1", nil) },
	}
	var tooMany int
	for round := 0; round < 3; round++ {
		for i, mk := range reqs {
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, mk())
			switch rec.Code {
			case http.StatusForbidden:
			case http.StatusTooManyRequests:
				tooMany++
			default:
				t.Fatalf("round %d request %d: status = %d, want 403 or 429", round, i, rec.Code)
			}
		}
	}
	if tooMany != 3*len(reqs)-limit {
		t.Errorf("got %d x 429, want %d", tooMany, 3*len(reqs)-limit)
	}
	denied := 0
	for _, outcome := range []string{"policy-read-denied", "policy-denied", "grant-denied", "reload-denied"} {
		denied += countAuditOutcome(t, auditPath, outcome)
	}
	if denied > limit {
		t.Errorf("%d denial audit records, want <= %d", denied, limit)
	}
}

// TestAdminDenialAuditUnlimitedWhenDisabled: sign_rate_limit_per_min = 0 keeps
// the pre-#464 behaviour (every denial audited, always 403), matching the
// opt-in nature of the sign-path cap.
func TestAdminDenialAuditUnlimitedWhenDisabled(t *testing.T) {
	t.Parallel()
	srv, auditPath := adminDenialTestServer(t, 0)
	mux := adminDenialMux(srv)
	const n = 5
	for i := 0; i < n; i++ {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, grantRequest(http.MethodGet, "/v1/policy/hosts", "broker-1", nil))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("request %d: status = %d, want 403", i, rec.Code)
		}
	}
	if got := countAuditOutcome(t, auditPath, "policy-read-denied"); got != n {
		t.Errorf("%d policy-read-denied audit records, want %d", got, n)
	}
}
