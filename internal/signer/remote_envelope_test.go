package signer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestRemotePollApprovalCarriesEnvelope: when the control plane answers 202 to
// a session-exec preflight (behaviour escalation) and the approved result is
// decision-only (no certificate — a dry-run by construction), pollApproval
// must keep the sealed-exec envelope that rides on it (#573).
func TestRemotePollApprovalCarriesEnvelope(t *testing.T) {
	const envelope = "SEALED-ENVELOPE"
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/sign":
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(map[string]string{"approval_id": "ap-1", "status": "pending"})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/sign/result/"):
			_ = json.NewEncoder(w).Encode(WireResponse{
				Decision: &DecisionInfo{Allowed: true},
				Envelope: envelope,
			})
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusNotFound)
		}
	}))
	defer cp.Close()

	rm := NewRemote(cp.URL, nil, 5*time.Second)
	rm.SetApprovalWait(30 * time.Second)
	issued, err := rm.SignIntent(context.Background(), Intent{
		Host: "sealed", Role: RoleTarget, Purpose: PurposeSession, SessionMode: SessionModeExec,
		Command: "uptime", DryRun: true, Preflight: true,
	})
	if err != nil {
		t.Fatalf("SignIntent: %v", err)
	}
	if issued.Envelope != envelope {
		t.Errorf("Envelope = %q, want %q", issued.Envelope, envelope)
	}
	if issued.Decision == nil || !issued.Decision.Allowed {
		t.Errorf("Decision = %+v, want allowed", issued.Decision)
	}
}
