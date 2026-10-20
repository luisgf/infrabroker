package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/luisgf/infrabroker/internal/control"
	"github.com/luisgf/infrabroker/internal/signer"
)

// stubSealedSigner is a signer that rides a sealed-exec envelope on every
// dry-run response (the session-exec preflight of a sealed host) and issues
// nothing else — the control plane must relay that envelope untouched (#573).
func stubSealedSigner(t *testing.T, envelope string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var rq signer.WireRequest
		if err := json.NewDecoder(r.Body).Decode(&rq); err != nil {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if !rq.DryRun {
			http.Error(w, "stub only answers dry-runs", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(signer.WireResponse{
			Decision: &signer.DecisionInfo{Allowed: true, MatchedRule: "allow:.*"},
			Envelope: envelope,
		})
	}))
}

func preflightReq(t *testing.T) signer.WireRequest {
	t.Helper()
	r := wireReq(t, "uptime")
	r.Purpose = signer.PurposeSession
	r.SessionMode = signer.SessionModeExec
	r.DryRun = true
	r.Preflight = true
	return r
}

func decodeWire(t *testing.T, w *httptest.ResponseRecorder) signer.WireResponse {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp signer.WireResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid response %q: %v", w.Body.String(), err)
	}
	return resp
}

// TestControlPlaneDryRunCarriesEnvelope: the pure dry-run and the executable
// preflight both relay the signer's envelope to the broker. Dropping it makes
// the broker send the raw command to a host whose force-command is the shim,
// which refuses anything that is not a signed envelope (#573).
func TestControlPlaneDryRunCarriesEnvelope(t *testing.T) {
	const envelope = "SEALED-ENVELOPE"
	sig := stubSealedSigner(t, envelope)
	defer sig.Close()
	s := testServer(t, sig.URL)

	// Pure dry-run (guardrails skipped).
	r := wireReq(t, "uptime")
	r.DryRun = true
	w := httptest.NewRecorder()
	s.handleSign(w, signReq(t, "broker-1", r))
	if got := decodeWire(t, w).Envelope; got != envelope {
		t.Errorf("pure dry-run: envelope = %q, want %q", got, envelope)
	}

	// Executable preflight with guardrails on (observe mode): the second
	// handleSign dry-run branch.
	s.behavior = control.NewBehaviorTracker(control.BehaviorConfig{Mode: control.BehaviorObserve})
	w = httptest.NewRecorder()
	s.handleSign(w, signReq(t, "broker-1", preflightReq(t)))
	if got := decodeWire(t, w).Envelope; got != envelope {
		t.Errorf("preflight: envelope = %q, want %q", got, envelope)
	}
}

// TestControlPlaneApprovedPreflightCarriesEnvelope: a session-exec preflight
// escalated to approval by the behaviour guardrails (enforce mode) must still
// hand the broker the envelope when it collects the approved result (#573).
func TestControlPlaneApprovedPreflightCarriesEnvelope(t *testing.T) {
	const envelope = "SEALED-ENVELOPE"
	sig := stubSealedSigner(t, envelope)
	defer sig.Close()
	s := testServer(t, sig.URL)
	s.behavior = control.NewBehaviorTracker(control.BehaviorConfig{Mode: control.BehaviorEnforce})

	// Baseline on web01.
	w := httptest.NewRecorder()
	s.handleSign(w, signReq(t, "broker-1", preflightReq(t)))
	if got := decodeWire(t, w).Envelope; got != envelope {
		t.Fatalf("baseline preflight: envelope = %q, want %q", got, envelope)
	}

	// New host → anomaly → escalated to approval.
	r := preflightReq(t)
	r.Host = "db99"
	w = httptest.NewRecorder()
	s.handleSign(w, signReq(t, "broker-1", r))
	if w.Code != http.StatusAccepted {
		t.Fatalf("new host in enforce must escalate (202), got %d: %s", w.Code, w.Body.String())
	}
	var acc struct {
		ApprovalID string `json:"approval_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &acc); err != nil || acc.ApprovalID == "" {
		t.Fatalf("approval response missing id: %v body=%s", err, w.Body.String())
	}

	w = httptest.NewRecorder()
	dr := req(t, "POST", "/v1/approvals/"+acc.ApprovalID, "broker-admin", map[string]bool{"approve": true})
	dr.SetPathValue("id", acc.ApprovalID)
	s.handleApprovalDecide(w, dr)
	if w.Code != http.StatusOK {
		t.Fatalf("approval decision failed: %d %s", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	rr := req(t, "GET", "/v1/sign/result/"+acc.ApprovalID, "broker-1", nil)
	rr.SetPathValue("id", acc.ApprovalID)
	s.handleResult(w, rr)
	resp := decodeWire(t, w)
	if resp.Envelope != envelope {
		t.Errorf("approved preflight: envelope = %q, want %q", resp.Envelope, envelope)
	}
	if resp.Decision == nil || !resp.Decision.Allowed {
		t.Errorf("approved preflight must carry the allowed decision, got %+v", resp.Decision)
	}
}
