package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/luisgf/infrabroker/internal/signer"
)

func discoveryDenialMux(s *server) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/hosts", s.handleHosts)
	mux.HandleFunc("GET /v1/clusters", s.handleClusters)
	mux.HandleFunc("/v1/sign", s.handleSign)
	return mux
}

// freezeCaller freezes a caller CN directly in the server's freeze store.
func freezeCaller(t *testing.T, s *server, cn string) {
	t.Helper()
	if _, err := s.freezes.Add(signer.FreezeSubject{Kind: signer.FreezeCaller, Value: cn}, "", "admin", time.Now()); err != nil {
		t.Fatalf("freeze %s: %v", cn, err)
	}
}

// TestDiscoveryFrozenDenialAuditRateLimited pins #828 (sibling of #464): a frozen
// caller looping GET /v1/hosts or GET /v1/clusters must not force one signed +
// fsynced frozen_denied record per request. With sign_rate_limit_per_min =
// limit, every request is still answered 403 (frozen, never 429) but only the
// first limit denials per minute are audited (the probe stays visible). An
// unfrozen caller is unaffected.
func TestDiscoveryFrozenDenialAuditRateLimited(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"/v1/hosts", "/v1/clusters"} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			const limit, n = 5, 100
			srv, auditPath := adminDenialTestServer(t, limit)
			srv.local = &captureLocalSigner{}
			freezeCaller(t, srv, "broker-1")
			mux := discoveryDenialMux(srv)

			for i := 0; i < n; i++ {
				rec := httptest.NewRecorder()
				mux.ServeHTTP(rec, grantRequest(http.MethodGet, path, "broker-1", nil))
				if rec.Code != http.StatusForbidden {
					t.Fatalf("request %d: status = %d, want 403", i, rec.Code)
				}
			}
			if got := countAuditOutcome(t, auditPath, "frozen_denied"); got != limit {
				t.Errorf("%d frozen_denied audit records for %d requests, want %d", got, n, limit)
			}

			// An unfrozen caller is unaffected.
			for i := 0; i < 10; i++ {
				rec := httptest.NewRecorder()
				mux.ServeHTTP(rec, grantRequest(http.MethodGet, path, "broker-2", nil))
				if rec.Code != http.StatusOK {
					t.Fatalf("unfrozen caller request %d: status = %d, want 200", i, rec.Code)
				}
			}
		})
	}
}

// TestDiscoveryFrozenDenialSharedBudget: hosts and clusters draw on the same
// per-frozen-subject budget, so alternating them does not double the audited
// denials.
func TestDiscoveryFrozenDenialSharedBudget(t *testing.T) {
	t.Parallel()
	const limit = 4
	srv, auditPath := adminDenialTestServer(t, limit)
	srv.local = &captureLocalSigner{}
	freezeCaller(t, srv, "broker-1")
	mux := discoveryDenialMux(srv)
	for i := 0; i < 20; i++ {
		path := "/v1/hosts"
		if i%2 == 1 {
			path = "/v1/clusters"
		}
		mux.ServeHTTP(httptest.NewRecorder(), grantRequest(http.MethodGet, path, "broker-1", nil))
	}
	if got := countAuditOutcome(t, auditPath, "frozen_denied"); got != limit {
		t.Errorf("%d frozen_denied records, want %d", got, limit)
	}
}

// TestDiscoveryFrozenDenialUnlimitedWhenDisabled: sign_rate_limit_per_min = 0
// audits every denial, as before.
func TestDiscoveryFrozenDenialUnlimitedWhenDisabled(t *testing.T) {
	t.Parallel()
	srv, auditPath := adminDenialTestServer(t, 0)
	srv.local = &captureLocalSigner{}
	freezeCaller(t, srv, "broker-1")
	mux := discoveryDenialMux(srv)
	const n = 8
	for i := 0; i < n; i++ {
		for _, path := range []string{"/v1/hosts", "/v1/clusters"} {
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, grantRequest(http.MethodGet, path, "broker-1", nil))
			if rec.Code != http.StatusForbidden {
				t.Fatalf("%s request %d: status = %d, want 403", path, i, rec.Code)
			}
		}
	}
	if got := countAuditOutcome(t, auditPath, "frozen_denied"); got != 2*n {
		t.Errorf("%d frozen_denied records, want %d", got, 2*n)
	}
}

// TestDiscoveryFrozenDenialDoesNotDrainForwarderSignBudget: behind a trusted
// forwarder the peer CN is the control plane. A frozen downstream broker's
// discovery polling must neither be answered 429 nor consume the forwarder's
// /v1/sign bucket (#828).
func TestDiscoveryFrozenDenialDoesNotDrainForwarderSignBudget(t *testing.T) {
	t.Parallel()
	const limit, n = 5, 100
	srv, auditPath := adminDenialTestServer(t, limit)
	srv.local = &captureLocalSigner{}
	srv.forwarders = map[string]struct{}{"control-plane": {}}
	freezeCaller(t, srv, "broker-1")
	mux := discoveryDenialMux(srv)

	for i := 0; i < n; i++ {
		for _, path := range []string{"/v1/hosts", "/v1/clusters"} {
			req := grantRequest(http.MethodGet, path, "control-plane", nil)
			req.Header.Set(signer.HeaderOnBehalfOf, "broker-1")
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("%s request %d: status = %d, want 403", path, i, rec.Code)
			}
		}
	}
	if got := countAuditOutcome(t, auditPath, "frozen_denied"); got != limit {
		t.Errorf("%d frozen_denied records, want %d", got, limit)
	}

	// The forwarder's own sign bucket is untouched: `limit` sign requests for an
	// unfrozen broker are none of them rate-limited.
	for i := 0; i < limit; i++ {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, grantRequest(http.MethodPost, "/v1/sign", "control-plane", signer.WireRequest{
			Host: "web01", Role: signer.RoleTarget, Purpose: signer.PurposeOneshot,
			Command: "uptime", OnBehalfOf: "broker-2",
		}))
		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("sign %d from forwarder rate-limited after frozen discovery polling", i)
		}
	}
}
