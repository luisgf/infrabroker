package main

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/luisgf/infrabroker/internal/audit"
	"github.com/luisgf/infrabroker/internal/control"
	"github.com/luisgf/infrabroker/internal/signer"
)

// brokenControlPlaneAudit opens a control-plane audit log and removes its backing
// directory so every Append fails — the trigger for the fail-closed gate.
func brokenControlPlaneAudit(t *testing.T) *audit.Log {
	t.Helper()
	dir := t.TempDir()
	al, err := audit.Open(filepath.Join(dir, "cp_audit.log"), ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)))
	if err != nil {
		t.Fatalf("audit open: %v", err)
	}
	al.Close()
	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("remove audit dir: %v", err)
	}
	return al
}

// TestApprovalDecisionAuditFailMode pins #205: with audit_fail_mode=closed (the
// default), an approval whose audit append fails is rejected rather than granted;
// audit_fail_mode=open degrades the same broken audit to log-and-continue. Before
// this fix the control plane always swallowed the audit error and granted anyway,
// leaving the "who approved" record only on stderr.
func TestApprovalDecisionAuditFailMode(t *testing.T) {
	sig := stubSigner(t)
	defer sig.Close()

	newSrv := func(failClosed bool) *server {
		return &server{
			remote:          signer.NewRemote(sig.URL, nil, time.Second),
			registry:        control.NewRegistry(time.Minute),
			notifier:        control.LogNotifier{},
			behavior:        control.NewBehaviorTracker(control.BehaviorConfig{}),
			audit:           brokenControlPlaneAudit(t),
			auditFailClosed: failClosed,
			approveCN:       map[string]struct{}{"broker-admin": {}},
			forwarders:      map[string]struct{}{},
		}
	}
	// createApproval drives a require_approval command to a pending request and
	// returns its id. The approval-required record is best-effort, so a broken
	// audit does not block creation.
	createApproval := func(s *server) string {
		w := httptest.NewRecorder()
		s.handleSign(w, req(t, "POST", "/v1/sign", "broker-1", wireReq(t, "reboot now")))
		if w.Code != http.StatusAccepted {
			t.Fatalf("expected 202 creating approval, got %d: %s", w.Code, w.Body.String())
		}
		var acc struct {
			ApprovalID string `json:"approval_id"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &acc); err != nil || acc.ApprovalID == "" {
			t.Fatalf("bad 202 response: %s", w.Body.String())
		}
		return acc.ApprovalID
	}
	decide := func(s *server, id string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		dr := req(t, "POST", "/v1/approvals/"+id, "broker-admin", map[string]bool{"approve": true})
		dr.SetPathValue("id", id)
		s.handleApprovalDecide(w, dr)
		return w
	}

	// Fail-closed (default): the allow decision whose audit append fails is
	// rejected (503), not granted.
	closed := newSrv(true)
	if w := decide(closed, createApproval(closed)); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("fail-closed: an approval whose audit append fails must be rejected (503), got %d: %s", w.Code, w.Body.String())
	}

	// Fail-open: the same broken audit degrades to log-and-continue; the decision
	// is accepted (200).
	open := newSrv(false)
	if w := decide(open, createApproval(open)); w.Code != http.StatusOK {
		t.Fatalf("fail-open: decision must proceed despite a broken audit, got %d: %s", w.Code, w.Body.String())
	}
}
