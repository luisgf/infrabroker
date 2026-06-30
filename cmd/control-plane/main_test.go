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
	"os"
	"path/filepath"
	"strings"
	"sync"
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
		remote:     signer.NewRemote(signerURL, nil, time.Second),
		registry:   control.NewRegistry(time.Minute),
		notifier:   control.LogNotifier{},
		behavior:   control.NewBehaviorTracker(control.BehaviorConfig{}), // off by default
		audit:      al,
		approveCN:  map[string]struct{}{"broker-admin": {}},
		forwarders: map[string]struct{}{}, // no trusted forwarders by default
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

// TestControlPlaneApproveAndLearn verifies that approving with learn=true makes
// the control plane forward the approved sign carrying the learn intent
// (learn_ttl_seconds + approver + approval id), so the signer can mint a waiver.
func TestControlPlaneApproveAndLearn(t *testing.T) {
	var mu sync.Mutex
	var captured signer.WireRequest
	_, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	caSigner, _ := ssh.NewSignerFromKey(caPriv)
	sig := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var rq signer.WireRequest
		_ = json.NewDecoder(r.Body).Decode(&rq)
		w.Header().Set("Content-Type", "application/json")
		if strings.HasPrefix(rq.Command, "reboot") && !rq.Approved {
			_ = json.NewEncoder(w).Encode(signer.WireResponse{Decision: &signer.DecisionInfo{Allowed: true, RequireApproval: true}})
			return
		}
		mu.Lock()
		captured = rq // the approved forward
		mu.Unlock()
		pub, _ := signer.ParsePublicKey(rq.PublicKey)
		cert, serial, _ := ca.BuildAndSign(context.Background(), caSigner, pub, ca.Constraints{Principal: "host:x", TTL: time.Minute})
		_ = json.NewEncoder(w).Encode(signer.WireResponse{Certificate: string(ssh.MarshalAuthorizedKey(cert)), Serial: serial})
	}))
	defer sig.Close()
	s := testServer(t, sig.URL)

	// 1. Command requiring approval.
	w := httptest.NewRecorder()
	s.handleSign(w, req(t, "POST", "/v1/sign", "broker-1", wireReq(t, "reboot now")))
	var acc struct {
		ApprovalID string `json:"approval_id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &acc)
	if acc.ApprovalID == "" {
		t.Fatalf("no approval id: %s", w.Body.String())
	}

	// 2. Approve WITH --learn (ttl 2h).
	w = httptest.NewRecorder()
	dr := req(t, "POST", "/v1/approvals/"+acc.ApprovalID, "broker-admin",
		map[string]any{"approve": true, "learn": true, "ttl_seconds": 7200})
	dr.SetPathValue("id", acc.ApprovalID)
	s.handleApprovalDecide(w, dr)
	if w.Code != http.StatusOK {
		t.Fatalf("approve+learn must return 200, got %d: %s", w.Code, w.Body.String())
	}

	// 3. Poll → the control plane forwards the approved sign with the learn intent.
	w = httptest.NewRecorder()
	rr := req(t, "GET", "/v1/sign/result/"+acc.ApprovalID, "broker-1", nil)
	rr.SetPathValue("id", acc.ApprovalID)
	s.handleResult(w, rr)
	if w.Code != http.StatusOK {
		t.Fatalf("poll after approval must return 200, got %d: %s", w.Code, w.Body.String())
	}

	mu.Lock()
	got := captured
	mu.Unlock()
	if !got.Approved {
		t.Error("forwarded request must be approved")
	}
	if got.LearnTTLSeconds != 7200 {
		t.Errorf("forwarded LearnTTLSeconds = %d, want 7200", got.LearnTTLSeconds)
	}
	if got.LearnApprover != "broker-admin" {
		t.Errorf("forwarded LearnApprover = %q, want broker-admin", got.LearnApprover)
	}
	if got.LearnApprovalID != acc.ApprovalID {
		t.Errorf("forwarded LearnApprovalID = %q, want %q", got.LearnApprovalID, acc.ApprovalID)
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

// TestControlPlaneLoadConfigRejectsUnknownKey verifies the runtime loader fails
// closed on a typo in a security control instead of silently ignoring it.
func TestControlPlaneLoadConfigRejectsUnknownKey(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "cp.json")

	// A typo'd sign_callers must be rejected, not silently dropped (which would
	// leave the sign path more open than intended).
	if err := os.WriteFile(path, []byte(`{"listen":":7443","sign_caller":["broker-1"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil {
		t.Error("loadConfig must reject an unknown key (sign_caller typo)")
	}

	// A valid config with a comment key (the "_*_comment" convention) and the real
	// field loads fine.
	if err := os.WriteFile(path, []byte(`{"_comment":"doc","listen":":7443","sign_callers":["broker-1"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err != nil {
		t.Errorf("loadConfig must accept comments + known keys: %v", err)
	}
}

// TestControlPlaneForwardsHostGroups verifies GET /v1/hosts forwards each host's
// Groups, so a broker can apply per-user group filtering (otherwise an OIDC user
// with groups sees zero hosts behind the control plane).
func TestControlPlaneForwardsHostGroups(t *testing.T) {
	sig := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/hosts" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]signer.WireHostInfo{
			"web01": {Addr: "10.0.0.1:22", User: "deploy", Groups: []string{"prod-web"}},
		})
	}))
	defer sig.Close()
	s := testServer(t, sig.URL)

	w := httptest.NewRecorder()
	s.handleHosts(w, req(t, "GET", "/v1/hosts", "broker-1", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	var out map[string]signer.WireHostInfo
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if h := out["web01"]; len(h.Groups) != 1 || h.Groups[0] != "prod-web" {
		t.Errorf("host Groups must be forwarded; got %v", h.Groups)
	}
}

// TestControlPlaneSignCallerRoleSeparation covers the broker/approver role
// separation on the signing path: by default an approver CN cannot sign, and an
// explicit sign_callers list is an exact allowlist.
func TestControlPlaneSignCallerRoleSeparation(t *testing.T) {
	sig := stubSigner(t)
	defer sig.Close()
	s := testServer(t, sig.URL) // approveCN = {broker-admin}, no sign_callers

	// An approver CN is denied the sign path by default (role separation).
	w := httptest.NewRecorder()
	s.handleSign(w, req(t, "POST", "/v1/sign", "broker-admin", wireReq(t, "uptime")))
	if w.Code != http.StatusForbidden {
		t.Errorf("approver CN on /v1/sign must be 403, got %d", w.Code)
	}
	// /v1/hosts is gated the same way.
	w = httptest.NewRecorder()
	s.handleHosts(w, req(t, "GET", "/v1/hosts", "broker-admin", nil))
	if w.Code != http.StatusForbidden {
		t.Errorf("approver CN on /v1/hosts must be 403, got %d", w.Code)
	}
	// A plain broker CN (not an approver) may sign.
	w = httptest.NewRecorder()
	s.handleSign(w, req(t, "POST", "/v1/sign", "broker-1", wireReq(t, "uptime")))
	if w.Code == http.StatusForbidden {
		t.Errorf("a non-approver broker must not be 403 on /v1/sign")
	}

	// With an explicit sign_callers allowlist, only listed CNs may sign.
	s.signCN = map[string]struct{}{"broker-1": {}}
	w = httptest.NewRecorder()
	s.handleSign(w, req(t, "POST", "/v1/sign", "broker-2", wireReq(t, "uptime")))
	if w.Code != http.StatusForbidden {
		t.Errorf("CN not in sign_callers must be 403, got %d", w.Code)
	}
}

func TestControlPlaneSelfApprovalRejected(t *testing.T) {
	sig := stubSigner(t)
	defer sig.Close()
	s := testServer(t, sig.URL)
	// A dual-role CN (broker AND approver) must be explicitly allowed on the sign
	// path via sign_callers; the four-eyes guard then still blocks self-approval.
	s.signCN = map[string]struct{}{"broker-admin": {}}

	// broker-admin is both a broker and an approver: it originates a request
	// requiring approval...
	w := httptest.NewRecorder()
	s.handleSign(w, req(t, "POST", "/v1/sign", "broker-admin", wireReq(t, "reboot now")))
	if w.Code != http.StatusAccepted {
		t.Fatalf("must return 202, got %d: %s", w.Code, w.Body.String())
	}
	var acc struct {
		ApprovalID string `json:"approval_id"`
	}
	json.Unmarshal(w.Body.Bytes(), &acc)

	// ...and must NOT be able to approve its own request.
	w = httptest.NewRecorder()
	dr := req(t, "POST", "/v1/approvals/"+acc.ApprovalID, "broker-admin", map[string]bool{"approve": true})
	dr.SetPathValue("id", acc.ApprovalID)
	s.handleApprovalDecide(w, dr)
	if w.Code != http.StatusForbidden {
		t.Fatalf("self-approval must return 403, got %d: %s", w.Code, w.Body.String())
	}

	// The request must remain pending (decidable by another approver later).
	w = httptest.NewRecorder()
	rr := req(t, "GET", "/v1/sign/result/"+acc.ApprovalID, "broker-admin", nil)
	rr.SetPathValue("id", acc.ApprovalID)
	s.handleResult(w, rr)
	if w.Code != http.StatusAccepted {
		t.Errorf("after rejected self-approval the request must stay pending (202), got %d", w.Code)
	}
}

func TestGuardrailSubject(t *testing.T) {
	t.Parallel()
	s := &server{forwarders: map[string]struct{}{"trusted-broker": {}}}
	tests := []struct {
		name     string
		brokerCN string
		endUser  string
		want     string
	}{
		{"untrusted-ignores-enduser", "broker-1", "alice", "broker-1"},
		{"untrusted-no-enduser", "broker-1", "", "broker-1"},
		{"trusted-qualifies-enduser", "trusted-broker", "alice", "trusted-broker:alice"},
		{"trusted-empty-enduser", "trusted-broker", "", "trusted-broker"},
	}
	for _, tc := range tests {
		tc := tc // capture range variable
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := s.guardrailSubject(tc.brokerCN, tc.endUser); got != tc.want {
				t.Errorf("guardrailSubject(%q, %q) = %q, want %q", tc.brokerCN, tc.endUser, got, tc.want)
			}
		})
	}
}

func TestControlPlaneBehaviorSubjectIgnoresUntrustedEndUser(t *testing.T) {
	sig := stubSigner(t)
	defer sig.Close()
	s := testServer(t, sig.URL)
	s.behavior = control.NewBehaviorTracker(control.BehaviorConfig{Mode: control.BehaviorEnforce, RateLimitPerMin: 2})

	// broker-1 is NOT a trusted forwarder: rotating end_user must not reset
	// the rate-limit window (all requests share the broker-1 subject).
	endUsers := []string{"alice", "bob", "carol"}
	codes := make([]int, 0, 3)
	for _, eu := range endUsers {
		r := wireReq(t, "uptime")
		r.EndUser = eu
		w := httptest.NewRecorder()
		s.handleSign(w, signReq(t, "broker-1", r))
		codes = append(codes, w.Code)
	}
	if codes[2] != http.StatusTooManyRequests {
		t.Errorf("rotating end_user must not evade the rate limit (3rd request must be 429), got %v", codes)
	}
}

func TestControlPlaneBehaviorSubjectTrustedForwarder(t *testing.T) {
	sig := stubSigner(t)
	defer sig.Close()
	s := testServer(t, sig.URL)
	s.behavior = control.NewBehaviorTracker(control.BehaviorConfig{Mode: control.BehaviorEnforce, RateLimitPerMin: 2})
	s.forwarders = map[string]struct{}{"broker-1": {}}

	// broker-1 IS a trusted forwarder: distinct end users get separate
	// per-subject windows, so three requests with different end_user pass.
	for _, eu := range []string{"alice", "bob", "carol"} {
		r := wireReq(t, "uptime")
		r.EndUser = eu
		w := httptest.NewRecorder()
		s.handleSign(w, signReq(t, "broker-1", r))
		if w.Code != http.StatusOK {
			t.Fatalf("trusted forwarder: end_user %q must get its own window (200), got %d: %s", eu, w.Code, w.Body.String())
		}
	}

	// The same end user is still rate-limited within its window.
	for i, want := range []int{http.StatusOK, http.StatusTooManyRequests} {
		r := wireReq(t, "uptime")
		r.EndUser = "alice"
		w := httptest.NewRecorder()
		s.handleSign(w, signReq(t, "broker-1", r))
		if w.Code != want {
			t.Errorf("repeat request %d for alice: got %d, want %d", i, w.Code, want)
		}
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
