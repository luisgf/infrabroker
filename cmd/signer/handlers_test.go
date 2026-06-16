package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/luisgf/ssh-broker/internal/signer"
)

func hostsRequestAs(cn string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/v1/hosts", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: cn}}},
	}
	return req
}

// TestHandleHostsAppliesAllowedCallers verifies that GET /v1/hosts hides hosts
// the caller CN is excluded from via per-host allowed_callers, matching the
// /v1/sign authorization. Previously /v1/hosts applied only the group filter
// and leaked the connectivity (addr/user/host_key/topology) of hosts the CN
// could never obtain a certificate for.
func TestHandleHostsAppliesAllowedCallers(t *testing.T) {
	t.Parallel()
	hosts := signer.PolicyTable{
		"open":   {Addr: "10.0.0.1:22", User: "deploy", Principal: "host:open"},
		"locked": {Addr: "10.0.0.2:22", User: "deploy", Principal: "host:locked", AllowedCallers: []string{"broker-prod"}},
	}
	srv := &server{hosts: hosts}

	// broker-dev is not in locked's allowed_callers and is not group-restricted.
	rec := httptest.NewRecorder()
	srv.handleHosts(rec, hostsRequestAs("broker-dev"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var got map[string]signer.WireHostInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if _, ok := got["open"]; !ok {
		t.Error("an unrestricted host must be visible")
	}
	if _, ok := got["locked"]; ok {
		t.Error("a host with allowed_callers must be hidden from a CN not in the list")
	}

	// broker-prod IS allowed and sees both.
	rec = httptest.NewRecorder()
	srv.handleHosts(rec, hostsRequestAs("broker-prod"))
	var got2 map[string]signer.WireHostInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &got2); err != nil {
		t.Fatal(err)
	}
	if _, ok := got2["locked"]; !ok {
		t.Error("a host with allowed_callers must be visible to a CN in the list")
	}
}
