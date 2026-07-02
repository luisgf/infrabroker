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
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/luisgf/ssh-broker/internal/audit"
	"github.com/luisgf/ssh-broker/internal/ca"
	"github.com/luisgf/ssh-broker/internal/signer"
)

func hostsRequestAs(cn string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/v1/hosts", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: cn}}},
	}
	return req
}

type captureLocalSigner struct {
	got signer.Intent
}

func (c *captureLocalSigner) SignIntent(_ context.Context, in signer.Intent) (*signer.Issued, error) {
	c.got = in
	return &signer.Issued{Decision: &signer.DecisionInfo{Allowed: true}}, nil
}

func (c *captureLocalSigner) HostAllowlistActive(string) (bool, bool) {
	return false, false
}

func signRequestAs(t *testing.T, cn string, body signer.WireRequest) *http.Request {
	t.Helper()
	_, pub, err := ca.GenerateEphemeralKey()
	if err != nil {
		t.Fatalf("ephemeral key: %v", err)
	}
	body.PublicKey = string(ssh.MarshalAuthorizedKey(pub))
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/sign", bytes.NewReader(b))
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: cn}}},
	}
	return req
}

func testAudit(t *testing.T) *audit.Log {
	t.Helper()
	al, err := audit.Open(filepath.Join(t.TempDir(), "audit.log"), ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)))
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	t.Cleanup(func() { al.Close() })
	return al
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

// TestHandleSignRejectsTokenInjectionInAuditFields is the regression test for
// the audit-record token-forgery gap: auditEmission concatenates role / purpose
// / session_mode / end_user / sudo_user into a space-separated key=value token
// stream, and it is reached on the denial path (before authorizeIntent), the
// SignIntent-error path, and the issued path (where session_mode is never
// whitespace-checked). The handler's input gate must reject a whitespace-bearing
// value in any of these with 400 before any auditEmission and before the signer.
func TestHandleSignRejectsTokenInjectionInAuditFields(t *testing.T) {
	t.Parallel()
	cap := &captureLocalSigner{}
	srv := &server{
		local: cap,
		hosts: signer.PolicyTable{"web01": {Addr: "10.0.0.1:22", User: "deploy", Principal: "host:web01"}},
		audit: testAudit(t),
	}
	cases := []struct {
		name string
		mut  func(*signer.WireRequest)
	}{
		{"session_mode", func(r *signer.WireRequest) { r.SessionMode = "exec user=victim elev=sudo:root" }},
		{"end_user", func(r *signer.WireRequest) { r.EndUser = "alice elev=sudo:root" }},
		{"role", func(r *signer.WireRequest) { r.Role = "target role=bastion" }},
		{"purpose", func(r *signer.WireRequest) { r.Purpose = "oneshot pty=1" }},
		{"sudo_user", func(r *signer.WireRequest) { r.Sudo = true; r.SudoUser = "root pty=1" }},
	}
	for _, tc := range cases {
		body := signer.WireRequest{Host: "web01", Role: signer.RoleTarget, Purpose: signer.PurposeOneshot, Command: "uptime"}
		tc.mut(&body)
		rec := httptest.NewRecorder()
		srv.handleSign(rec, signRequestAs(t, "broker-1", body))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400 (token-injection field must be rejected)", tc.name, rec.Code)
		}
	}
	if cap.got.Host != "" {
		t.Error("a token-injection request must be rejected before reaching the signer")
	}
}

// TestHandleSignRejectsTokenInjectionInOnBehalfOf is the regression test for the
// on_behalf_of gap: a trusted forwarder's on_behalf_of becomes the resolved
// caller and lands verbatim in Entry.Caller on the denial/error/dry-run paths,
// so a whitespace-laden value would plant a misleading attribution in the
// tamper-evident log before authorizeIntent rejects it. The resolved-caller gate
// must reject it with 400 before any auditEmission and before the signer.
func TestHandleSignRejectsTokenInjectionInOnBehalfOf(t *testing.T) {
	t.Parallel()
	cap := &captureLocalSigner{}
	srv := &server{
		local:      cap,
		hosts:      signer.PolicyTable{"web01": {Addr: "10.0.0.1:22", User: "deploy", Principal: "host:web01"}},
		forwarders: map[string]struct{}{"control-plane": {}},
		audit:      testAudit(t),
	}
	rec := httptest.NewRecorder()
	srv.handleSign(rec, signRequestAs(t, "control-plane", signer.WireRequest{
		Host: "web01", Role: signer.RoleTarget, Purpose: signer.PurposeOneshot, Command: "uptime",
		OnBehalfOf: "victim host=db role=bastion elev=sudo:root",
	}))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (whitespace on_behalf_of must be rejected): %s", rec.Code, rec.Body.String())
	}
	if cap.got.Host != "" {
		t.Error("a rejected on_behalf_of request must not reach the signer")
	}
}

// TestAuditPolicyKeepsPatternOutOfCommand is the regression test for audit token
// forgery via a policy allowlist pattern: a command-policy regex legitimately
// contains spaces, so it must be accepted, but it must NOT be concatenated into
// Command (the space-separated key=value token stream). It belongs in the
// discrete PolicyRule field, where its content cannot splice forged tokens.
func TestAuditPolicyKeepsPatternOutOfCommand(t *testing.T) {
	t.Parallel()
	auditPath := filepath.Join(t.TempDir(), "audit.log")
	al, err := audit.Open(auditPath, ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)))
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	srv := &server{audit: al}

	// A regex with legitimate spaces that also mimics the execution token stream.
	const pattern = "^x$ user=victim elev=sudo:root pty=1"
	srv.auditPolicy("admin", "web01", pattern, true, "policy-changed", nil)
	al.Close()

	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	var e audit.Entry
	if err := json.Unmarshal(bytes.TrimSpace(data), &e); err != nil {
		t.Fatalf("parse audit line: %v", err)
	}
	if e.Command != "policy-allow-add" {
		t.Errorf("Command = %q, want %q (the pattern must not splice tokens into Command)", e.Command, "policy-allow-add")
	}
	if e.PolicyRule != "allow:"+pattern {
		t.Errorf("PolicyRule = %q, want the full pattern preserved", e.PolicyRule)
	}
}

func TestHandleSignPropagatesPreflight(t *testing.T) {
	t.Parallel()
	cap := &captureLocalSigner{}
	srv := &server{
		local: cap,
		hosts: signer.PolicyTable{
			"web01": {Addr: "10.0.0.1:22", User: "deploy", Principal: "host:web01"},
		},
		audit: testAudit(t),
	}

	rec := httptest.NewRecorder()
	srv.handleSign(rec, signRequestAs(t, "broker-1", signer.WireRequest{
		Host:        "web01",
		Role:        signer.RoleTarget,
		Purpose:     signer.PurposeSession,
		SessionMode: signer.SessionModeExec,
		Command:     "uptime",
		DryRun:      true,
		Preflight:   true,
	}))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if !cap.got.DryRun || !cap.got.Preflight {
		t.Fatalf("handler must propagate dry_run/preflight to signer intent: %+v", cap.got)
	}
	if cap.got.Purpose != signer.PurposeSession || cap.got.SessionMode != signer.SessionModeExec {
		t.Fatalf("unexpected session intent: %+v", cap.got)
	}
}

// TestHandleSignRateLimitPerCN verifies the per-CN token bucket on /v1/sign:
// requests beyond the per-minute budget get 429 with a Retry-After hint, other
// CNs keep their own budget, and a zero limit disables the check entirely.
func TestHandleSignRateLimitPerCN(t *testing.T) {
	t.Parallel()
	body := signer.WireRequest{
		Host:    "web01",
		Role:    signer.RoleTarget,
		Purpose: signer.PurposeOneshot,
		Command: "uptime",
	}
	newSrv := func(limit int) *server {
		return &server{
			local: &captureLocalSigner{},
			hosts: signer.PolicyTable{
				"web01": {Addr: "10.0.0.1:22", User: "deploy", Principal: "host:web01"},
			},
			audit:       testAudit(t),
			signRateMin: limit,
			rateLimiter: signer.NewRateLimiter(),
		}
	}

	srv := newSrv(2)
	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		srv.handleSign(rec, signRequestAs(t, "broker-1", body))
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d within budget: status = %d, want 200: %s", i+1, rec.Code, rec.Body.String())
		}
	}
	rec := httptest.NewRecorder()
	srv.handleSign(rec, signRequestAs(t, "broker-1", body))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("request beyond budget: status = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("429 must carry a Retry-After hint")
	}

	// Another CN has its own bucket.
	rec = httptest.NewRecorder()
	srv.handleSign(rec, signRequestAs(t, "broker-2", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("another CN must have its own budget: status = %d", rec.Code)
	}

	// Limit 0 disables the check (and must not touch the limiter).
	srv = newSrv(0)
	for i := 0; i < 10; i++ {
		rec := httptest.NewRecorder()
		srv.handleSign(rec, signRequestAs(t, "broker-1", body))
		if rec.Code != http.StatusOK {
			t.Fatalf("limit 0 must never rate limit: status = %d", rec.Code)
		}
	}
}
