package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/luisgf/infrabroker/internal/audit"
	"github.com/luisgf/infrabroker/internal/ca"
	"github.com/luisgf/infrabroker/internal/control"
	"github.com/luisgf/infrabroker/internal/signer"
)

// stubSignerApprovedStatus is a signer that asks for approval on "reboot*"
// and, once the approved forward arrives, answers the given HTTP status with
// the given body instead of a certificate (#576).
func stubSignerApprovedStatus(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	_, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	caSigner, _ := ssh.NewSignerFromKey(caPriv)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var rq signer.WireRequest
		_ = json.NewDecoder(r.Body).Decode(&rq)
		if strings.HasPrefix(rq.Command, "reboot") {
			if rq.Approved {
				http.Error(w, body, status)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(signer.WireResponse{
				Decision: &signer.DecisionInfo{Allowed: true, RequireApproval: true},
			})
			return
		}
		pub, _ := signer.ParsePublicKey(rq.PublicKey)
		cert, serial, err := ca.BuildAndSign(context.Background(), caSigner, pub, ca.Constraints{Principal: "host:x", TTL: time.Minute})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(signer.WireResponse{Certificate: string(ssh.MarshalAuthorizedKey(cert)), Serial: serial})
	}))
}

// testServerWithAudit is testServer with the audit log path exposed so tests
// can read the records back.
func testServerWithAudit(t *testing.T, signerURL string) (*server, string) {
	t.Helper()
	s := testServer(t, signerURL)
	path := filepath.Join(t.TempDir(), "cp_audit.log")
	al, err := audit.Open(path, ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { al.Close() })
	s.audit = al
	return s, path
}

func lastAuditEntry(t *testing.T, path string) audit.Entry {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	var e audit.Entry
	if err := json.Unmarshal(lines[len(lines)-1], &e); err != nil {
		t.Fatalf("parse audit line %q: %v", lines[len(lines)-1], err)
	}
	return e
}

// approveReboot drives a "reboot now" request through 202 + approval and
// returns the approval id.
func approveReboot(t *testing.T, s *server) string {
	t.Helper()
	w := httptest.NewRecorder()
	s.handleSign(w, signReq(t, "broker-1", wireReq(t, "reboot now")))
	if w.Code != http.StatusAccepted {
		t.Fatalf("must return 202, got %d: %s", w.Code, w.Body.String())
	}
	var acc struct {
		ApprovalID string `json:"approval_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &acc); err != nil || acc.ApprovalID == "" {
		t.Fatalf("invalid 202 response: %s", w.Body.String())
	}
	w = httptest.NewRecorder()
	dr := req(t, "POST", "/v1/approvals/"+acc.ApprovalID, "broker-admin", map[string]bool{"approve": true})
	dr.SetPathValue("id", acc.ApprovalID)
	s.handleApprovalDecide(w, dr)
	if w.Code != http.StatusOK {
		t.Fatalf("approval must return 200, got %d: %s", w.Code, w.Body.String())
	}
	return acc.ApprovalID
}

func pollResult(t *testing.T, s *server, id string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	rr := req(t, "GET", "/v1/sign/result/"+id, "broker-1", nil)
	rr.SetPathValue("id", id)
	s.handleResult(w, rr)
	return w
}

// TestControlPlaneResultSignerDenialIs403Denied: a signer 403 on the approved
// forward (subject frozen after the human approved, policy changed) is a
// policy decision — relayed as 403 with the signer's reason and audited
// "denied" with the approval attribution, not 502 + "error" (#576).
func TestControlPlaneResultSignerDenialIs403Denied(t *testing.T) {
	sig := stubSignerApprovedStatus(t, http.StatusForbidden, "frozen: caller broker-1 is frozen")
	defer sig.Close()
	s, auditPath := testServerWithAudit(t, sig.URL)
	id := approveReboot(t, s)

	w := pollResult(t, s, id)
	if w.Code != http.StatusForbidden {
		t.Fatalf("signer denial after approval must be 403, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "frozen: caller broker-1 is frozen") {
		t.Errorf("body must carry the signer's reason, got %q", w.Body.String())
	}
	e := lastAuditEntry(t, auditPath)
	if e.Outcome != "denied" {
		t.Errorf("outcome = %q, want denied", e.Outcome)
	}
	if e.ApprovalID != id || e.ApprovedBy != "broker-admin" {
		t.Errorf("denial must carry the approval attribution, got approval_id=%q approved_by=%q", e.ApprovalID, e.ApprovedBy)
	}
	if !strings.Contains(e.Err, "frozen") {
		t.Errorf("audit err must carry the signer's reason, got %q", e.Err)
	}
	// Consume-once semantics unchanged: the failed forward does not burn the
	// approval, so a later poll claims it again rather than answering 410.
	if w := pollResult(t, s, id); w.Code == http.StatusGone {
		t.Errorf("a refused forward must not consume the approval (got 410)")
	}
}

// TestControlPlaneResultSignerOutageIs502Error: a signer 5xx on the approved
// forward stays an infrastructure error — 502 + audited "error" — so the
// broker classifies it exactly as a direct-path outage (#455).
func TestControlPlaneResultSignerOutageIs502Error(t *testing.T) {
	sig := stubSignerApprovedStatus(t, http.StatusInternalServerError, "ca backend down")
	defer sig.Close()
	s, auditPath := testServerWithAudit(t, sig.URL)
	id := approveReboot(t, s)

	w := pollResult(t, s, id)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("signer 5xx after approval must be 502, got %d: %s", w.Code, w.Body.String())
	}
	e := lastAuditEntry(t, auditPath)
	if e.Outcome != "error" {
		t.Errorf("outcome = %q, want error", e.Outcome)
	}
	if e.ApprovalID != id {
		t.Errorf("error must carry the approval id, got %q", e.ApprovalID)
	}
	if w := pollResult(t, s, id); w.Code == http.StatusGone {
		t.Errorf("a transient failure must not consume the approval (got 410)")
	}
}

// TestControlPlaneResultSignerRateLimitRelayed locks in #745: a signer 429 on
// the approved forward is relayed as 429, unaudited (no "denied" with the
// approver's attribution), and the approval stays claimable so the next poll
// retries without a second human decision.
func TestControlPlaneResultSignerRateLimitRelayed(t *testing.T) {
	sig := stubSignerApprovedStatus(t, http.StatusTooManyRequests, "rate limit exceeded")
	defer sig.Close()
	s, auditPath := testServerWithAudit(t, sig.URL)
	id := approveReboot(t, s)
	before := auditLineCount(t, auditPath)

	for i := 0; i < 2; i++ {
		w := pollResult(t, s, id)
		if w.Code != http.StatusTooManyRequests {
			t.Fatalf("poll %d: signer 429 after approval must be relayed as 429, got %d %s", i, w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "rate limit exceeded") {
			t.Errorf("poll %d: body must carry the signer's text, got %q", i, w.Body.String())
		}
	}
	if after := auditLineCount(t, auditPath); after != before {
		t.Errorf("a relayed signer 429 must not be audited: %d -> %d records", before, after)
	}
	if a, ok := s.registry.Get(id); !ok || a.Status != control.StatusApproved {
		t.Errorf("approval must stay approved and claimable after a 429, got %+v", a)
	}
}

// TestControlPlaneResultDeniedAuditedOnce locks in #746: the result route makes
// no signer call and runs outside every rate limiter, so a broker re-polling a
// decided approval must not append a signed audit record per poll. The first
// poll audits approval-denied; the next ones answer 403 unaudited.
func TestControlPlaneResultDeniedAuditedOnce(t *testing.T) {
	sig := stubSigner(t)
	defer sig.Close()
	s, auditPath := testServerWithAudit(t, sig.URL)

	w := httptest.NewRecorder()
	s.handleSign(w, signReq(t, "broker-1", wireReq(t, "reboot now")))
	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202 approval-required, got %d %s", w.Code, w.Body.String())
	}
	var acc struct {
		ApprovalID string `json:"approval_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &acc); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	dr := req(t, "POST", "/v1/approvals/"+acc.ApprovalID, "broker-admin", map[string]bool{"approve": false})
	dr.SetPathValue("id", acc.ApprovalID)
	s.handleApprovalDecide(w, dr)
	if w.Code != http.StatusOK {
		t.Fatalf("deny: %d %s", w.Code, w.Body.String())
	}

	before := auditLineCount(t, auditPath)
	for i := 0; i < 20; i++ {
		if w := pollResult(t, s, acc.ApprovalID); w.Code != http.StatusForbidden {
			t.Fatalf("poll %d: expected 403, got %d %s", i, w.Code, w.Body.String())
		}
	}
	if got := auditLineCount(t, auditPath) - before; got != 1 {
		t.Fatalf("20 polls of a denied approval appended %d audit records, want exactly 1", got)
	}
	if e := lastAuditEntry(t, auditPath); e.Outcome != "approval-denied" || e.ApprovalID != acc.ApprovalID || e.ApprovedBy != "broker-admin" {
		t.Errorf("unexpected record: %+v", e)
	}
}
