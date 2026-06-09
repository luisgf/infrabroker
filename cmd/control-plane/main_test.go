package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/luisgf/ssh-broker/internal/audit"
	"github.com/luisgf/ssh-broker/internal/ca"
	"github.com/luisgf/ssh-broker/internal/control"
	"github.com/luisgf/ssh-broker/internal/signer"
)

// stubSigner returns a fake signer (plain HTTP) that issues a cert for all
// commands except "reboot*" without approved, for which it responds with
// "requires approval" (no cert).
func stubSigner(t *testing.T) *httptest.Server {
	t.Helper()
	_, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	caSigner, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req signer.WireRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		needsApproval := strings.HasPrefix(req.Command, "reboot")
		// Dry-run: return only the decision (no cert), like the real signer.
		if req.DryRun {
			_ = json.NewEncoder(w).Encode(signer.WireResponse{
				Decision: &signer.DecisionInfo{Allowed: true, RequireApproval: needsApproval},
			})
			return
		}
		if needsApproval && !req.Approved {
			_ = json.NewEncoder(w).Encode(signer.WireResponse{
				Decision: &signer.DecisionInfo{Allowed: true, RequireApproval: true, MatchedRule: "require_approval:^reboot"},
			})
			return
		}
		pub, _ := signer.ParsePublicKey(req.PublicKey)
		cert, serial, err := ca.BuildAndSign(context.Background(), caSigner, pub, ca.Constraints{Principal: "host:x", TTL: time.Minute})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(signer.WireResponse{
			Certificate: string(ssh.MarshalAuthorizedKey(cert)), Serial: serial,
		})
	}))
}

func testServer(t *testing.T, signerURL string) *server {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	al, err := audit.Open(filepath.Join(t.TempDir(), "cp_audit.log"), ed25519.NewKeyFromSeed(seed))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { al.Close() })
	return &server{
		remote:    signer.NewRemote(signerURL, nil, time.Second),
		registry:  control.NewRegistry(time.Minute),
		notifier:  control.LogNotifier{},
		behavior:  control.NewBehaviorTracker(control.BehaviorConfig{}), // off by default
		audit:     al,
		approveCN: map[string]struct{}{"broker-admin": {}},
	}
}

// req builds a request with a synthetic mTLS client CN.
func req(t *testing.T, method, target, cn string, body any) *http.Request {
	t.Helper()
	var r *http.Request
	if body != nil {
		b, _ := json.Marshal(body)
		r = httptest.NewRequest(method, target, bytes.NewReader(b))
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: cn}}}}
	return r
}

// signReq builds a POST /v1/sign request with the given WireRequest.
func signReq(t *testing.T, cn string, body signer.WireRequest) *http.Request {
	t.Helper()
	return req(t, "POST", "/v1/sign", cn, body)
}

func wireReq(t *testing.T, command string) signer.WireRequest {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sshPub, _ := ssh.NewPublicKey(pub)
	return signer.WireRequest{
		Host: "web01", Role: signer.RoleTarget, Purpose: signer.PurposeOneshot,
		Command: command, PublicKey: string(ssh.MarshalAuthorizedKey(sshPub)),
	}
}

func TestControlPlaneForwardsAllowed(t *testing.T) {
	sig := stubSigner(t)
	defer sig.Close()
	s := testServer(t, sig.URL)

	w := httptest.NewRecorder()
	s.handleSign(w, req(t, "POST", "/v1/sign", "broker-1", wireReq(t, "uptime")))
	if w.Code != http.StatusOK {
		t.Fatalf("allowed command must return 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp signer.WireResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Certificate == "" {
		t.Error("must return a certificate")
	}
}

func TestControlPlaneApprovalFlow(t *testing.T) {
	sig := stubSigner(t)
	defer sig.Close()
	s := testServer(t, sig.URL)

	// 1. Request requiring approval → 202 + approval_id.
	w := httptest.NewRecorder()
	s.handleSign(w, req(t, "POST", "/v1/sign", "broker-1", wireReq(t, "reboot now")))
	if w.Code != http.StatusAccepted {
		t.Fatalf("must return 202, got %d: %s", w.Code, w.Body.String())
	}
	var acc struct {
		ApprovalID string `json:"approval_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &acc); err != nil || acc.ApprovalID == "" {
		t.Fatalf("invalid 202 response: %s", w.Body.String())
	}

	// 2. Poll before approval → 202 (pending).
	w = httptest.NewRecorder()
	rr := req(t, "GET", "/v1/sign/result/"+acc.ApprovalID, "broker-1", nil)
	rr.SetPathValue("id", acc.ApprovalID)
	s.handleResult(w, rr)
	if w.Code != http.StatusAccepted {
		t.Fatalf("pending must return 202, got %d", w.Code)
	}

	// 3. Approve with an authorised CN.
	w = httptest.NewRecorder()
	dr := req(t, "POST", "/v1/approvals/"+acc.ApprovalID, "broker-admin", map[string]bool{"approve": true})
	dr.SetPathValue("id", acc.ApprovalID)
	s.handleApprovalDecide(w, dr)
	if w.Code != http.StatusOK {
		t.Fatalf("approval must return 200, got %d: %s", w.Code, w.Body.String())
	}

	// 4. Poll after approval → 200 with certificate.
	w = httptest.NewRecorder()
	rr = req(t, "GET", "/v1/sign/result/"+acc.ApprovalID, "broker-1", nil)
	rr.SetPathValue("id", acc.ApprovalID)
	s.handleResult(w, rr)
	if w.Code != http.StatusOK {
		t.Fatalf("after approval must return 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp signer.WireResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Certificate == "" {
		t.Error("must return certificate after approval")
	}

	// 5. Second poll after consuming → 410 Gone.
	w = httptest.NewRecorder()
	rr = req(t, "GET", "/v1/sign/result/"+acc.ApprovalID, "broker-1", nil)
	rr.SetPathValue("id", acc.ApprovalID)
	s.handleResult(w, rr)
	if w.Code != http.StatusGone {
		t.Errorf("second poll must return 410, got %d", w.Code)
	}
}

func TestControlPlaneApprovalDenied(t *testing.T) {
	sig := stubSigner(t)
	defer sig.Close()
	s := testServer(t, sig.URL)

	w := httptest.NewRecorder()
	s.handleSign(w, req(t, "POST", "/v1/sign", "broker-1", wireReq(t, "reboot now")))
	var acc struct {
		ApprovalID string `json:"approval_id"`
	}
	json.Unmarshal(w.Body.Bytes(), &acc)

	// Deny.
	w = httptest.NewRecorder()
	dr := req(t, "POST", "/v1/approvals/"+acc.ApprovalID, "broker-admin", map[string]bool{"approve": false})
	dr.SetPathValue("id", acc.ApprovalID)
	s.handleApprovalDecide(w, dr)
	if w.Code != http.StatusOK {
		t.Fatalf("decision must return 200, got %d", w.Code)
	}

	// Poll after denial → 403.
	w = httptest.NewRecorder()
	rr := req(t, "GET", "/v1/sign/result/"+acc.ApprovalID, "broker-1", nil)
	rr.SetPathValue("id", acc.ApprovalID)
	s.handleResult(w, rr)
	if w.Code != http.StatusForbidden {
		t.Errorf("denied must return 403, got %d", w.Code)
	}
}

func TestControlPlaneApproverAuthz(t *testing.T) {
	sig := stubSigner(t)
	defer sig.Close()
	s := testServer(t, sig.URL)

	w := httptest.NewRecorder()
	s.handleSign(w, req(t, "POST", "/v1/sign", "broker-1", wireReq(t, "reboot now")))
	var acc struct {
		ApprovalID string `json:"approval_id"`
	}
	json.Unmarshal(w.Body.Bytes(), &acc)

	// An unauthorised CN cannot approve.
	w = httptest.NewRecorder()
	dr := req(t, "POST", "/v1/approvals/"+acc.ApprovalID, "broker-1", map[string]bool{"approve": true})
	dr.SetPathValue("id", acc.ApprovalID)
	s.handleApprovalDecide(w, dr)
	if w.Code != http.StatusForbidden {
		t.Errorf("non-approver CN must receive 403, got %d", w.Code)
	}
}

func TestControlPlaneBehaviorEnforceEscalates(t *testing.T) {
	sig := stubSigner(t)
	defer sig.Close()
	s := testServer(t, sig.URL)
	s.behavior = control.NewBehaviorTracker(control.BehaviorConfig{Mode: control.BehaviorEnforce})

	// 1st request: baseline → issued normally (200 with cert).
	w := httptest.NewRecorder()
	s.handleSign(w, req(t, "POST", "/v1/sign", "broker-1", wireReq(t, "uptime")))
	if w.Code != http.StatusOK {
		t.Fatalf("baseline must issue cert (200), got %d: %s", w.Code, w.Body.String())
	}

	// 2nd request to a new host (uptime is a known command, db99 is a new host)
	// → anomaly → in enforce mode escalates to approval (202).
	w = httptest.NewRecorder()
	r := wireReq(t, "uptime")
	r.Host = "db99"
	s.handleSign(w, signReq(t, "broker-1", r))
	if w.Code != http.StatusAccepted {
		t.Fatalf("new host in enforce must escalate to approval (202), got %d: %s", w.Code, w.Body.String())
	}
}

func TestControlPlaneBehaviorRateLimit(t *testing.T) {
	sig := stubSigner(t)
	defer sig.Close()
	s := testServer(t, sig.URL)
	s.behavior = control.NewBehaviorTracker(control.BehaviorConfig{Mode: control.BehaviorEnforce, RateLimitPerMin: 2})

	codes := make([]int, 0, 3)
	for i := 0; i < 3; i++ {
		w := httptest.NewRecorder()
		s.handleSign(w, signReq(t, "broker-1", wireReq(t, "uptime")))
		codes = append(codes, w.Code)
	}
	// First two pass; third exceeds the limit → 429.
	if codes[2] != http.StatusTooManyRequests {
		t.Errorf("3rd request must be 429 (limit 2/min), got %v", codes)
	}
}

func TestControlPlaneBehaviorObserveDoesNotBlock(t *testing.T) {
	sig := stubSigner(t)
	defer sig.Close()
	s := testServer(t, sig.URL)
	s.behavior = control.NewBehaviorTracker(control.BehaviorConfig{Mode: control.BehaviorObserve, RateLimitPerMin: 1})

	// Even when the limit is exceeded, observe does NOT block: both return cert.
	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		s.handleSign(w, signReq(t, "broker-1", wireReq(t, "uptime")))
		if w.Code != http.StatusOK {
			t.Fatalf("observe must not block, request %d got %d", i, w.Code)
		}
	}
}

func TestControlPlaneResultOwnerOnly(t *testing.T) {
	sig := stubSigner(t)
	defer sig.Close()
	s := testServer(t, sig.URL)

	w := httptest.NewRecorder()
	s.handleSign(w, req(t, "POST", "/v1/sign", "broker-1", wireReq(t, "reboot now")))
	var acc struct {
		ApprovalID string `json:"approval_id"`
	}
	json.Unmarshal(w.Body.Bytes(), &acc)

	// A different broker cannot collect the result.
	w = httptest.NewRecorder()
	rr := req(t, "GET", "/v1/sign/result/"+acc.ApprovalID, "broker-2", nil)
	rr.SetPathValue("id", acc.ApprovalID)
	s.handleResult(w, rr)
	if w.Code != http.StatusForbidden {
		t.Errorf("other broker must receive 403, got %d", w.Code)
	}
}
