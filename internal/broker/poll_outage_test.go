package broker

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/luisgf/infrabroker/internal/signer"
)

// #811: a control-plane outage while polling an approval result must reach the
// frontends as ErrUpstream (masked) and be audited as "error", not "denied".
// Drives Execute against a real signer.Remote talking to a stub control plane
// that approves-pending on POST /v1/sign and drops the connection on the poll.
func TestExecuteApprovalPollOutageIsUpstream(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/v1/sign" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(map[string]string{"approval_id": "abc123", "status": "pending"})
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Error("ResponseWriter is not a Hijacker")
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		_ = conn.Close()
	}))
	defer srv.Close()

	e := policyDenialEngine(t)
	rm := signer.NewRemote(srv.URL, nil, 5*time.Second)
	rm.SetApprovalWait(30 * time.Second)
	e.sgn = rm

	// The default poll interval (2s) applies before the first poll.
	_, err := e.Execute(context.Background(), Caller{ID: "tester"}, "locked", "uptime", 0, ExecOptions{})
	if !errors.Is(err, ErrUpstream) {
		t.Fatalf("an approval-poll outage must be an upstream failure, got %v", err)
	}
	ent := lastAuditEntry(t, e)
	if ent.Outcome != "error" {
		t.Errorf("outcome = %q, want error (err %q)", ent.Outcome, ent.Err)
	}
}
