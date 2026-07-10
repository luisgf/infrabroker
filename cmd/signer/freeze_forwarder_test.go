package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luisgf/infrabroker/internal/signer"
)

// forwarderFreezeMux wires the endpoints whose freeze coverage #203 fixes: the
// sign path plus the two read endpoints a frozen caller must not reach.
func forwarderFreezeMux(s *server) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/freeze", s.handleFreeze)
	mux.HandleFunc("/v1/sign", s.handleSign)
	mux.HandleFunc("GET /v1/hosts", s.handleHosts)
	mux.HandleFunc("GET /v1/clusters", s.handleClusters)
	return mux
}

// TestFreezeForwarderCNBlocksOnBehalfOf pins #203: the freeze check must run on
// the raw mTLS peer CN, so freezing a trusted forwarder denies /v1/sign and
// /v1/hosts even though its requests always carry on_behalf_of. The pre-#203
// check ran only on the resolved (on_behalf_of) caller, making a forwarder
// freeze a no-op.
func TestFreezeForwarderCNBlocksOnBehalfOf(t *testing.T) {
	t.Parallel()
	srv := freezeTestServer(t)
	srv.forwarders = map[string]struct{}{"control-plane": {}}
	srv.local = &captureLocalSigner{}
	mux := forwarderFreezeMux(srv)

	// A control BEFORE the freeze: the forwarder acting on behalf of broker-web is
	// not frozen-denied (it fails later, on pubkey/host resolution, never here).
	signOnBehalf := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, grantRequest(http.MethodPost, "/v1/sign", "control-plane", signer.WireRequest{
			Host: "web01", Role: signer.RoleTarget, Purpose: signer.PurposeOneshot,
			Command: "uptime", OnBehalfOf: "broker-web",
		}))
		return rec
	}
	hostsOnBehalf := func() *httptest.ResponseRecorder {
		req := grantRequest(http.MethodGet, "/v1/hosts", "control-plane", nil)
		req.Header.Set(signer.HeaderOnBehalfOf, "broker-web")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}

	if rec := signOnBehalf(); strings.Contains(rec.Body.String(), "subject is frozen") {
		t.Fatalf("pre-freeze sign must not be frozen-denied; body = %q", rec.Body.String())
	}

	// Freeze the FORWARDER's own CN (the break-glass scenario: the control plane
	// is compromised), not the downstream broker it acts for.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, grantRequest(http.MethodPost, "/v1/freeze", "admin",
		map[string]any{"kind": "caller", "value": "control-plane"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("freeze forwarder: status = %d (body %s)", rec.Code, rec.Body.String())
	}

	// Now both the sign and the hosts request carrying on_behalf_of are denied on
	// the freeze gate, keyed on the raw forwarder CN.
	if rec := signOnBehalf(); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "frozen") {
		t.Fatalf("sign as frozen forwarder (on_behalf_of): status = %d body = %q, want 403 + frozen", rec.Code, rec.Body.String())
	}
	if rec := hostsOnBehalf(); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "frozen") {
		t.Fatalf("hosts as frozen forwarder (on_behalf_of): status = %d body = %q, want 403 + frozen", rec.Code, rec.Body.String())
	}
}

// TestFreezeDeniesClusters pins the /v1/clusters half of #203: a frozen caller
// (directly, or a frozen forwarder acting via on_behalf_of) is denied the
// cluster connectivity it previously could still enumerate.
func TestFreezeDeniesClusters(t *testing.T) {
	t.Parallel()
	srv := freezeTestServer(t)
	srv.forwarders = map[string]struct{}{"control-plane": {}}
	srv.local = &captureLocalSigner{}
	mux := forwarderFreezeMux(srv)

	getClusters := func(cn, onBehalf string) *httptest.ResponseRecorder {
		req := grantRequest(http.MethodGet, "/v1/clusters", cn, nil)
		if onBehalf != "" {
			req.Header.Set(signer.HeaderOnBehalfOf, onBehalf)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}

	// Baseline: an unfrozen direct caller is not frozen-denied.
	if rec := getClusters("brk1", ""); strings.Contains(rec.Body.String(), "subject is frozen") {
		t.Fatalf("pre-freeze clusters must not be frozen-denied; body = %q", rec.Body.String())
	}

	// Freeze a direct caller.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, grantRequest(http.MethodPost, "/v1/freeze", "admin",
		map[string]any{"kind": "caller", "value": "brk1"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("freeze brk1: status = %d (body %s)", rec.Code, rec.Body.String())
	}
	if rec := getClusters("brk1", ""); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "frozen") {
		t.Fatalf("clusters as frozen brk1: status = %d body = %q, want 403 + frozen", rec.Code, rec.Body.String())
	}

	// Freeze the forwarder CN too: a frozen forwarder acting via on_behalf_of is
	// denied even though the resolved caller is not itself frozen.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, grantRequest(http.MethodPost, "/v1/freeze", "admin",
		map[string]any{"kind": "caller", "value": "control-plane"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("freeze forwarder: status = %d (body %s)", rec.Code, rec.Body.String())
	}
	if rec := getClusters("control-plane", "broker-web"); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "frozen") {
		t.Fatalf("clusters as frozen forwarder (on_behalf_of): status = %d body = %q, want 403 + frozen", rec.Code, rec.Body.String())
	}
}
