package main

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luisgf/infrabroker/internal/audit"
	"github.com/luisgf/infrabroker/internal/signer"
	"github.com/luisgf/infrabroker/internal/statedb"
)

// freezeAuditLog opens a throwaway signed audit log for a freeze test server.
func freezeAuditLog(t *testing.T) *audit.Log {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	l, err := audit.Open(filepath.Join(t.TempDir(), "audit.log"), ed25519.NewKeyFromSeed(seed))
	if err != nil {
		t.Fatalf("audit open: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

// freezeTestServer builds a minimal server with a state-db-backed freeze store,
// an in-memory grant store, and reload_callers={admin}. The sign path's freeze
// check runs before host/pubkey resolution, so no CA or host policy is needed to
// exercise a frozen denial. The store is db-backed (not memory-only) so the
// volatile-freeze gate is satisfied — that gate is covered by TestFreezeVolatileGate.
func freezeTestServer(t *testing.T) *server {
	t.Helper()
	db, err := statedb.Open(filepath.Join(t.TempDir(), "state.db"), signer.StateMigrations())
	if err != nil {
		t.Fatalf("state db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	freezes, err := signer.NewFreezeStoreDB(db)
	if err != nil {
		t.Fatalf("freeze store: %v", err)
	}
	return &server{
		audit:    freezeAuditLog(t),
		reloadCN: map[string]struct{}{"admin": {}},
		grants:   signer.NewGrantStore(),
		freezes:  freezes,
	}
}

func freezeMux(s *server) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/freeze", s.handleFreeze)
	mux.HandleFunc("POST /v1/unfreeze", s.handleUnfreeze)
	mux.HandleFunc("GET /v1/revocations", s.handleRevocations)
	mux.HandleFunc("/v1/sign", s.handleSign)
	return mux
}

// TestFreezeVolatileGate covers the state_db-less path: a memory-only freeze
// store fails open (freezes vanish on restart), so POST /v1/freeze must refuse a
// freeze unless the caller opts in with allow_volatile.
func TestFreezeVolatileGate(t *testing.T) {
	t.Parallel()
	srv := &server{
		audit:    freezeAuditLog(t),
		reloadCN: map[string]struct{}{"admin": {}},
		grants:   signer.NewGrantStore(),
		freezes:  signer.NewFreezeStore(), // memory-only → Volatile()==true
	}
	mux := freezeMux(srv)

	// Without allow_volatile: refused (409), nothing frozen.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, grantRequest(http.MethodPost, "/v1/freeze", "admin", map[string]any{"kind": "caller", "value": "brk2"}))
	if rec.Code != http.StatusConflict {
		t.Fatalf("volatile freeze without opt-in: status = %d, want 409 (body %s)", rec.Code, rec.Body.String())
	}
	if n := len(srv.freezes.List()); n != 0 {
		t.Fatalf("a refused volatile freeze must not freeze anything, have %d", n)
	}

	// With allow_volatile: accepted (200), subject frozen.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, grantRequest(http.MethodPost, "/v1/freeze", "admin", map[string]any{"kind": "caller", "value": "brk2", "allow_volatile": true}))
	if rec.Code != http.StatusOK {
		t.Fatalf("volatile freeze with opt-in: status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if n := len(srv.freezes.List()); n != 1 {
		t.Fatalf("an opted-in volatile freeze must freeze the subject, have %d", n)
	}
}

func TestFreezeEndpointRequiresReloadCN(t *testing.T) {
	t.Parallel()
	mux := freezeMux(freezeTestServer(t))

	// A non-admin CN may not freeze.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, grantRequest(http.MethodPost, "/v1/freeze", "brk1", map[string]any{"kind": "caller", "value": "brk2"}))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("freeze as non-admin: status = %d, want 403", rec.Code)
	}

	// admin may.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, grantRequest(http.MethodPost, "/v1/freeze", "admin", map[string]any{"kind": "caller", "value": "brk2"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("freeze as admin: status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
}

func TestFreezeDeniesSignAndUnfreezeRestores(t *testing.T) {
	t.Parallel()
	srv := freezeTestServer(t)
	mux := freezeMux(srv)

	signAs := func(cn string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, grantRequest(http.MethodPost, "/v1/sign", cn, signer.WireRequest{
			Host: "web01", Role: signer.RoleTarget, Purpose: signer.PurposeOneshot, Command: "uptime",
		}))
		return rec
	}

	// Freeze caller brk1.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, grantRequest(http.MethodPost, "/v1/freeze", "admin", map[string]any{"kind": "caller", "value": "brk1"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("freeze: status = %d", rec.Code)
	}

	// brk1 can no longer sign.
	if rec := signAs("brk1"); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "frozen") {
		t.Fatalf("sign as frozen brk1: status = %d body = %q, want 403 + frozen", rec.Code, rec.Body.String())
	}
	// A different caller is unaffected by brk1's freeze (it fails later, not on the freeze gate).
	if rec := signAs("brk2"); strings.Contains(rec.Body.String(), "subject is frozen") {
		t.Errorf("sign as brk2 must not be frozen-denied; body = %q", rec.Body.String())
	}

	// revocations lists brk1; a non-admin broker (brk2) sees the subject but not
	// the freezing admin's CN — provenance is reload_callers-only (#221).
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, grantRequest(http.MethodGet, "/v1/revocations", "brk2", nil))
	var frozen []signer.FrozenEntry
	if err := json.Unmarshal(rec.Body.Bytes(), &frozen); err != nil {
		t.Fatalf("decode revocations: %v", err)
	}
	if len(frozen) != 1 || frozen[0].Kind != signer.FreezeCaller || frozen[0].Value != "brk1" {
		t.Fatalf("revocations = %+v, want one caller=brk1", frozen)
	}
	if frozen[0].FrozenBy != "" {
		t.Errorf("a non-admin must not see frozen_by, got %q", frozen[0].FrozenBy)
	}

	// Unfreeze restores brk1 (freeze gate no longer fires).
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, grantRequest(http.MethodPost, "/v1/unfreeze", "admin", map[string]any{"kind": "caller", "value": "brk1"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("unfreeze: status = %d", rec.Code)
	}
	if rec := signAs("brk1"); strings.Contains(rec.Body.String(), "subject is frozen") {
		t.Errorf("brk1 must not be frozen-denied after unfreeze; body = %q", rec.Body.String())
	}
}

// TestRevocationsProvenanceAdminOnly pins #221: GET /v1/revocations exposes the
// free-text reason and the freezing admin's CN only to the reload_callers tier;
// an ordinary broker sees the subject (kind+value) but not the provenance.
func TestRevocationsProvenanceAdminOnly(t *testing.T) {
	t.Parallel()
	srv := freezeTestServer(t)
	mux := freezeMux(srv)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, grantRequest(http.MethodPost, "/v1/freeze", "admin",
		map[string]any{"kind": "caller", "value": "brk1", "reason": "compromised-key"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("freeze: status = %d (body %s)", rec.Code, rec.Body.String())
	}

	get := func(cn string) signer.FrozenEntry {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, grantRequest(http.MethodGet, "/v1/revocations", cn, nil))
		var f []signer.FrozenEntry
		if err := json.Unmarshal(rec.Body.Bytes(), &f); err != nil {
			t.Fatalf("decode revocations for %s: %v", cn, err)
		}
		if len(f) != 1 {
			t.Fatalf("want 1 entry for %s, got %d", cn, len(f))
		}
		return f[0]
	}

	// admin (reload_callers) sees full provenance.
	if a := get("admin"); a.Reason != "compromised-key" || a.FrozenBy != "admin" {
		t.Errorf("admin must see provenance, got reason=%q frozen_by=%q", a.Reason, a.FrozenBy)
	}
	// A non-admin broker sees the subject but neither the reason nor the admin CN.
	b := get("brk2")
	if b.Kind != signer.FreezeCaller || b.Value != "brk1" {
		t.Errorf("non-admin must still see the subject, got %+v", b)
	}
	if b.Reason != "" || b.FrozenBy != "" {
		t.Errorf("non-admin must not see provenance, got reason=%q frozen_by=%q", b.Reason, b.FrozenBy)
	}
}

func TestFreezeRevokesSubjectGrants(t *testing.T) {
	t.Parallel()
	srv := freezeTestServer(t)
	mux := freezeMux(srv)

	// A grant scoped to brk1 and a host-wide grant.
	if _, err := srv.grants.Add(signer.Grant{Host: "web01", Allow: []string{"^ls"}, Caller: "brk1", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatalf("add scoped grant: %v", err)
	}
	if _, err := srv.grants.Add(signer.Grant{Host: "web01", Allow: []string{"^df"}, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatalf("add host-wide grant: %v", err)
	}

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, grantRequest(http.MethodPost, "/v1/freeze", "admin", map[string]any{"kind": "caller", "value": "brk1"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("freeze: status = %d", rec.Code)
	}
	var result struct {
		GrantsRevoked int `json:"grants_revoked"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &result)
	if result.GrantsRevoked != 1 {
		t.Errorf("grants_revoked = %d, want 1", result.GrantsRevoked)
	}
	if got := len(srv.grants.List(time.Now())); got != 1 {
		t.Errorf("remaining grants = %d, want 1 (host-wide survives)", got)
	}
}

// TestFreezeRejectsTokenInjection: a value carrying whitespace would splice
// forged key=value tokens into the audit stream, so it must be rejected with 400
// before any audit write.
func TestFreezeRejectsTokenInjection(t *testing.T) {
	t.Parallel()
	mux := freezeMux(freezeTestServer(t))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, grantRequest(http.MethodPost, "/v1/freeze", "admin",
		map[string]any{"kind": "caller", "value": "brk1 grants_revoked=0 reason=pwned"}))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("freeze with whitespace value: status = %d, want 400", rec.Code)
	}
}
