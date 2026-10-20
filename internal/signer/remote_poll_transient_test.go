package signer

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/luisgf/infrabroker/internal/ca"
)

// transientCP is a stub control plane: POST /v1/sign answers 202, and each
// GET /v1/sign/result/{id} answers failStatus for the first failures polls,
// then 200 with a certificate. It counts the result polls.
func transientCP(t *testing.T, failStatus, failures int, polls *atomic.Int32) *httptest.Server {
	t.Helper()
	_, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	caSigner, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sshPub, _ := ssh.NewPublicKey(pub)
	cert, serial, err := ca.BuildAndSign(context.Background(), caSigner, sshPub, ca.Constraints{Principal: "host:web01", TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/sign":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(map[string]string{"approval_id": "ap-1", "status": "pending"})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/sign/result/"):
			if n := polls.Add(1); int(n) <= failures {
				http.Error(w, "signing after approval failed", failStatus)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(WireResponse{Certificate: string(ssh.MarshalAuthorizedKey(cert)), Serial: serial})
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusNotFound)
		}
	}))
}

func pollingRemote(url string) *Remote {
	rm := NewRemote(url, nil, 5*time.Second)
	rm.SetApprovalWait(30 * time.Second)
	rm.pollInterval = 5 * time.Millisecond
	return rm
}

func approvalIntent() Intent {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sshPub, _ := ssh.NewPublicKey(pub)
	return Intent{Host: "web01", Role: RoleTarget, Purpose: PurposeOneshot, Command: "reboot now", PublicKey: sshPub}
}

// TestRemotePollApprovalRetriesTransient: a 502/503 while collecting an
// approved result is transient — the control plane keeps the approval
// collectable — so pollApproval keeps polling and returns the certificate the
// next poll yields, instead of failing and making the human approve twice
// (#663).
func TestRemotePollApprovalRetriesTransient(t *testing.T) {
	for _, status := range []int{http.StatusBadGateway, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var polls atomic.Int32
			cp := transientCP(t, status, 1, &polls)
			defer cp.Close()

			issued, err := pollingRemote(cp.URL).SignIntent(context.Background(), approvalIntent())
			if err != nil {
				t.Fatalf("a transient %d must be retried, got error: %v", status, err)
			}
			if issued.Certificate == nil {
				t.Fatalf("want the certificate from the retried poll, got %+v", issued)
			}
			if got := polls.Load(); got != 2 {
				t.Errorf("result polls = %d, want 2 (one %d, then 200)", got, status)
			}
		})
	}
}

// TestRemotePollApprovalTransientBounded: past maxTransientPolls consecutive
// 502s pollApproval gives up with the last error rather than polling until
// the approval wait runs out (#663).
func TestRemotePollApprovalTransientBounded(t *testing.T) {
	var polls atomic.Int32
	cp := transientCP(t, http.StatusBadGateway, maxTransientPolls+1, &polls)
	defer cp.Close()

	_, err := pollingRemote(cp.URL).SignIntent(context.Background(), approvalIntent())
	if err == nil {
		t.Fatal("11 consecutive 502s must end in an error")
	}
	if !strings.Contains(err.Error(), "502") {
		t.Errorf("error must carry the last status, got %v", err)
	}
	if got := polls.Load(); got != maxTransientPolls+1 {
		t.Errorf("result polls = %d, want %d", got, maxTransientPolls+1)
	}
}

// TestRemotePollApprovalTerminal4xx: a 403 (denied) on the result poll stays
// terminal — no retry (#663 keeps the 4xx semantics).
func TestRemotePollApprovalTerminal4xx(t *testing.T) {
	var polls atomic.Int32
	cp := transientCP(t, http.StatusForbidden, 5, &polls)
	defer cp.Close()

	if _, err := pollingRemote(cp.URL).SignIntent(context.Background(), approvalIntent()); err == nil {
		t.Fatal("a 403 on the result poll must be an error")
	}
	if got := polls.Load(); got != 1 {
		t.Errorf("result polls = %d, want 1 (403 is terminal)", got)
	}
}
