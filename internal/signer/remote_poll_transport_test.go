package signer

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// dropOnPollCP answers 202 with an approval id on POST /v1/sign and hijacks +
// closes the connection on every GET /v1/sign/result/…, simulating a control
// plane outage while an approval is being awaited.
func dropOnPollCP(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
}

// #811: a transport failure while polling the approval result must be
// classified as ErrSignerUnavailable (like the POST /v1/sign path) so the
// broker masks it and audits it as an infrastructure error, not a denial.
func TestPollApprovalTransportErrorIsSignerUnavailable(t *testing.T) {
	srv := dropOnPollCP(t)
	defer srv.Close()
	rm := pollingRemote(srv.URL)
	_, err := rm.SignIntent(context.Background(), approvalIntent())
	if err == nil {
		t.Fatal("expected an error")
	}
	if !errors.Is(err, ErrSignerUnavailable) {
		t.Fatalf("poll transport failure must wrap ErrSignerUnavailable, got %v", err)
	}
}

// A cancelled context still surfaces as its own error (and without the
// control-plane URL), not as a signer outage.
func TestPollApprovalCancelledContextKeepsCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(map[string]string{"approval_id": "abc123", "status": "pending"})
			return
		}
		<-r.Context().Done() // hang until the client gives up
	}))
	defer srv.Close()
	rm := pollingRemote(srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	_, err := rm.SignIntent(ctx, approvalIntent())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want DeadlineExceeded, got %v", err)
	}
	if errors.Is(err, ErrSignerUnavailable) {
		t.Errorf("a cancelled ctx is not a signer outage: %v", err)
	}
	if strings.Contains(err.Error(), srv.URL) {
		t.Errorf("error leaks the control-plane URL: %v", err)
	}
}
