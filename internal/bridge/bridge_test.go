package bridge

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luisgf/infrabroker/internal/control"
)

// fakeCP is a scriptable ControlPlane. List returns whatever pending is set to;
// Decide records calls and signals on decided.
type fakeCP struct {
	mu      sync.Mutex
	pending []control.Approval
	decided chan [2]any // {id, approve}
}

func (f *fakeCP) setPending(a []control.Approval) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pending = a
}

func (f *fakeCP) List(context.Context) ([]control.Approval, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]control.Approval, len(f.pending))
	copy(out, f.pending)
	return out, nil
}

func (f *fakeCP) Decide(_ context.Context, id string, approve bool) error {
	f.decided <- [2]any{id, approve}
	// A decided request is no longer pending.
	f.mu.Lock()
	kept := f.pending[:0]
	for _, a := range f.pending {
		if a.ID != id {
			kept = append(kept, a)
		}
	}
	f.pending = kept
	f.mu.Unlock()
	return nil
}

// fakeAdapter records posts and lets the test inject decisions.
type fakeAdapter struct {
	posted    chan string
	decisions chan Decision
	mu        sync.Mutex
	lastCmd   string // the command of the most recently presented approval
}

func (a *fakeAdapter) Post(_ context.Context, ap control.Approval) error {
	a.mu.Lock()
	a.lastCmd = ap.Command
	a.mu.Unlock()
	a.posted <- ap.ID
	return nil
}

func (a *fakeAdapter) lastCommand() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lastCmd
}
func (a *fakeAdapter) Decisions() <-chan Decision { return a.decisions }
func (a *fakeAdapter) Name() string               { return "fake" }

func TestBridgePresentsAndRelays(t *testing.T) {
	t.Parallel()
	cp := &fakeCP{decided: make(chan [2]any, 1)}
	ad := &fakeAdapter{posted: make(chan string, 4), decisions: make(chan Decision, 1)}
	cp.setPending([]control.Approval{{ID: "a1", Host: "web01", Command: "systemctl restart nginx"}})

	b := New(cp, ad, 20*time.Millisecond, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = b.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	// The pending request is presented on the platform.
	select {
	case id := <-ad.posted:
		if id != "a1" {
			t.Fatalf("posted %q, want a1", id)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("bridge did not present the pending approval")
	}

	// A human approves on the platform; the bridge relays it to the control plane.
	ad.decisions <- Decision{ID: "a1", Approve: true, By: "U123"}
	select {
	case got := <-cp.decided:
		if got[0] != "a1" || got[1] != true {
			t.Fatalf("Decide got %v, want [a1 true]", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("bridge did not relay the decision to the control plane")
	}
}

// TestBridgeRejectsSelfApprovalViaIdentityMap pins #214: with an identity map
// configured, the bridge refuses an approval whose platform clicker maps to the
// request's originating end user (four-eyes for the platform path, which the
// control plane's bridge-CN check cannot enforce), while a different approver is
// relayed normally.
func TestBridgeRejectsSelfApprovalViaIdentityMap(t *testing.T) {
	t.Parallel()
	cp := &fakeCP{decided: make(chan [2]any, 1)}
	ad := &fakeAdapter{posted: make(chan string, 4), decisions: make(chan Decision, 2)}
	cp.setPending([]control.Approval{{ID: "a1", Host: "web01", Command: "reboot", EndUser: "alice@corp.com"}})

	// Alice originated the request; both Alice and Bob can click in the channel.
	b := New(cp, ad, 20*time.Millisecond, map[string]string{"U_ALICE": "alice@corp.com", "U_BOB": "bob@corp.com"})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = b.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	// Wait until presented, so poll() has recorded the request's originator.
	select {
	case <-ad.posted:
	case <-time.After(2 * time.Second):
		t.Fatal("bridge did not present the approval")
	}

	// Alice — the originator — clicks Approve: four-eyes must refuse it (no relay).
	ad.decisions <- Decision{ID: "a1", Approve: true, By: "U_ALICE"}
	select {
	case got := <-cp.decided:
		t.Fatalf("self-approval must not be relayed, but Decide got %v", got)
	case <-time.After(300 * time.Millisecond):
		// Good: the decision was refused at the bridge.
	}

	// Bob — a different human — approves the same request: relayed normally.
	ad.decisions <- Decision{ID: "a1", Approve: true, By: "U_BOB"}
	select {
	case got := <-cp.decided:
		if got[0] != "a1" || got[1] != true {
			t.Fatalf("Decide got %v, want [a1 true]", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a non-originator approval must be relayed")
	}
}

// TestBridgeRedactsCommandBeforePresenting: a secret passed inline in a
// require_approval command must be masked before it reaches the off-host chat
// platform, matching the control plane's webhook/Teams notifier sink (section
// 8). GET /v1/approvals serves the original command for the human mTLS UI, so
// the redaction has to happen at the bridge.
func TestBridgeRedactsCommandBeforePresenting(t *testing.T) {
	t.Parallel()
	cp := &fakeCP{decided: make(chan [2]any, 1)}
	ad := &fakeAdapter{posted: make(chan string, 4), decisions: make(chan Decision, 1)}
	cp.setPending([]control.Approval{{ID: "a1", Host: "db01", Command: "mysql -u root --password=HUNTER2 proddb"}})

	b := New(cp, ad, 20*time.Millisecond, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = b.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	select {
	case <-ad.posted:
	case <-time.After(2 * time.Second):
		t.Fatal("bridge did not present the approval")
	}
	got := ad.lastCommand()
	if strings.Contains(got, "HUNTER2") {
		t.Errorf("inline secret leaked to the platform unredacted: %q", got)
	}
	if !strings.Contains(got, "[REDACTED:") {
		t.Errorf("command was not redacted before presenting: %q", got)
	}
}

// TestBridgeDedupesAndForgets: a still-pending request is presented once (not
// re-posted every poll), and once it is gone the id is forgotten.
func TestBridgeDedupesAndForgets(t *testing.T) {
	t.Parallel()
	cp := &fakeCP{decided: make(chan [2]any, 1)}
	ad := &fakeAdapter{posted: make(chan string, 8), decisions: make(chan Decision, 1)}
	cp.setPending([]control.Approval{{ID: "a1"}})

	b := New(cp, ad, 10*time.Millisecond, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = b.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	<-ad.posted // first presentation
	// Let several polls elapse; a still-pending request must NOT be re-posted.
	time.Sleep(60 * time.Millisecond)
	select {
	case id := <-ad.posted:
		t.Fatalf("re-posted %q; a pending request must be presented once", id)
	default:
	}

	// It disappears (decided elsewhere) then reappears with the same id: because
	// the bridge forgot it, it is presented again.
	cp.setPending(nil)
	time.Sleep(30 * time.Millisecond)
	cp.setPending([]control.Approval{{ID: "a1"}})
	select {
	case id := <-ad.posted:
		if id != "a1" {
			t.Fatalf("re-presented %q, want a1", id)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a reappeared request should be presented again after being forgotten")
	}
}
