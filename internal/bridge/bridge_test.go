package bridge

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/slack-go/slack"

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
	last      Card // the most recently presented card
}

func (a *fakeAdapter) Post(_ context.Context, c Card) error {
	a.mu.Lock()
	a.last = c
	a.mu.Unlock()
	a.posted <- c.ID
	return nil
}

func (a *fakeAdapter) lastCommand() string {
	return a.lastCard().Command
}

func (a *fakeAdapter) lastCard() Card {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.last
}
func (a *fakeAdapter) Decisions() <-chan Decision { return a.decisions }
func (a *fakeAdapter) Name() string               { return "fake" }
func (a *fakeAdapter) CommandMax() int            { return control.SlackCommandMax }

func TestBridgePresentsAndRelays(t *testing.T) {
	t.Parallel()
	cp := &fakeCP{decided: make(chan [2]any, 1)}
	ad := &fakeAdapter{posted: make(chan string, 4), decisions: make(chan Decision, 1)}
	cp.setPending([]control.Approval{{ID: "a1", Status: control.StatusPending, Host: "web01", Command: "systemctl restart nginx"}})

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
	cp.setPending([]control.Approval{{ID: "a1", Status: control.StatusPending, Host: "web01", Command: "reboot", EndUser: "alice@corp.com"}})

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

// TestBridgeSelfApprovalGuardIsCaseInsensitiveOnClickerID pins #667: the loader
// upper-cases the identity map keys (Slack user ids are upper-case), so a click
// whose platform id arrives in another case must still hit the four-eyes guard.
func TestBridgeSelfApprovalGuardIsCaseInsensitiveOnClickerID(t *testing.T) {
	t.Parallel()
	b := New(nil, nil, 0, map[string]string{"U0123ABC": "alice@corp.com"})
	b.origins["a1"] = "alice@corp.com"
	for _, by := range []string{"U0123ABC", "u0123abc", "U0123abc"} {
		if !b.isSelfApproval(Decision{ID: "a1", Approve: true, By: by}) {
			t.Errorf("clicker %q must be recognised as the originator", by)
		}
	}
	if b.isSelfApproval(Decision{ID: "a1", Approve: true, By: "U0456DEF"}) {
		t.Error("an unmapped clicker must still fail open")
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
	cp.setPending([]control.Approval{{ID: "a1", Status: control.StatusPending, Host: "db01", Command: "mysql -u root --password=HUNTER2 proddb"}})

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
	cp.setPending([]control.Approval{{ID: "a1", Status: control.StatusPending}})

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
	cp.setPending([]control.Approval{{ID: "a1", Status: control.StatusPending}})
	select {
	case id := <-ad.posted:
		if id != "a1" {
			t.Fatalf("re-presented %q, want a1", id)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a reappeared request should be presented again after being forgotten")
	}
}

// TestBridgeRunReturnsWhenAdapterStops pins #452: when the adapter closes its
// Decisions stream (the Slack Socket Mode loop died — clicks can never arrive),
// Run must return promptly with ErrAdapterStopped — a failure distinguishable
// from a signal-driven stop (context.Canceled) and from nil, so main exits
// non-zero — instead of polling on and posting cards nobody can answer.
func TestBridgeRunReturnsWhenAdapterStops(t *testing.T) {
	t.Parallel()
	cp := &fakeCP{decided: make(chan [2]any, 1)}
	ad := &fakeAdapter{posted: make(chan string, 4), decisions: make(chan Decision, 1)}
	cp.setPending([]control.Approval{{ID: "a1", Status: control.StatusPending, Host: "web01", Command: "uptime"}})

	b := New(cp, ad, 10*time.Millisecond, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- b.Run(ctx) }()

	select {
	case <-ad.posted:
	case <-time.After(2 * time.Second):
		t.Fatal("bridge did not present the pending approval")
	}

	// The adapter stops: its decisions stream closes.
	close(ad.decisions)
	var err error
	select {
	case err = <-result:
	case <-time.After(2 * time.Second):
		t.Fatal("Run kept running after the adapter closed Decisions (#452)")
	}
	if !errors.Is(err, ErrAdapterStopped) {
		t.Fatalf("Run returned %v, want ErrAdapterStopped", err)
	}
	if errors.Is(err, context.Canceled) {
		t.Fatalf("an adapter stop must not look like a clean signal-driven stop: %v", err)
	}
	// And no further poll posts anything after Run returned.
	time.Sleep(50 * time.Millisecond)
	select {
	case id := <-ad.posted:
		t.Fatalf("bridge posted %q after the adapter stopped", id)
	default:
	}
}

// TestBridgeSkipsNonPending pins #356: GET /v1/approvals returns decided
// requests too; after a bridge restart those must not be re-posted to chat.
func TestBridgeSkipsNonPending(t *testing.T) {
	t.Parallel()
	cp := &fakeCP{decided: make(chan [2]any, 1)}
	ad := &fakeAdapter{posted: make(chan string, 4), decisions: make(chan Decision, 1)}
	cp.setPending([]control.Approval{
		{ID: "done", Status: control.StatusApproved, Host: "web01", Command: "rm -rf /"},
		{ID: "dead", Status: control.StatusDenied, Host: "web01", Command: "rm -rf /"},
		{ID: "live", Status: control.StatusPending, Host: "web01", Command: "uptime"},
	})

	b := New(cp, ad, 15*time.Millisecond, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = b.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	select {
	case id := <-ad.posted:
		if id != "live" {
			t.Fatalf("posted %q, want only the pending id live", id)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pending approval was not posted")
	}
	time.Sleep(50 * time.Millisecond)
	select {
	case id := <-ad.posted:
		t.Fatalf("extra post of %q; non-pending must not be presented", id)
	default:
	}
}

// startBridge runs a bridge over one pending approval and waits for its card.
func startBridge(t *testing.T, a control.Approval) (*fakeCP, *fakeAdapter) {
	t.Helper()
	cp := &fakeCP{decided: make(chan [2]any, 1)}
	ad := &fakeAdapter{posted: make(chan string, 4), decisions: make(chan Decision, 2)}
	cp.setPending([]control.Approval{a})
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
	return cp, ad
}

// cardControls reports which buttons a rendered Slack card offers and whether
// it carries the deny-only notice.
func cardControls(c Card) (approve, deny, notice bool) {
	for _, blk := range buildApprovalBlocks(c) {
		switch v := blk.(type) {
		case *slack.ActionBlock:
			for _, el := range v.Elements.ElementSet {
				if be, ok := el.(*slack.ButtonBlockElement); ok {
					approve = approve || be.ActionID == actionApprove
					deny = deny || be.ActionID == actionDeny
				}
			}
		case *slack.SectionBlock:
			if v.Text != nil && v.Text.Type == slack.PlainTextType && v.Text.Text == DenyOnlyNotice {
				notice = true
			}
		}
	}
	return approve, deny, notice
}

func expectNoRelay(t *testing.T, cp *fakeCP, what string) {
	t.Helper()
	select {
	case got := <-cp.decided:
		t.Fatalf("%s must not be relayed, but Decide got %v", what, got)
	case <-time.After(300 * time.Millisecond):
	}
}

func expectRelay(t *testing.T, cp *fakeCP, id string, approve bool) {
	t.Helper()
	select {
	case got := <-cp.decided:
		if got[0] != id || got[1] != approve {
			t.Fatalf("Decide got %v, want [%s %v]", got, id, approve)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("decision approve=%v for %s was not relayed", approve, id)
	}
}

// TestBridgeMaskedCommandIsDenyOnly pins #829: the requester chooses the span a
// default redaction pattern masks, so a card whose command was masked shows the
// approver something other than what the signer would authorize. Such a card
// must offer Deny only (plus the notice pointing at the approval UI), and an
// Approve arriving for its id — a forged or stale interactive payload — must
// not be relayed; Deny still is.
func TestBridgeMaskedCommandIsDenyOnly(t *testing.T) {
	t.Parallel()
	for _, cmd := range []string{
		// an ordinary inline secret: any masking makes the card deny-only.
		"mysql -u root --password=HUNTER2 proddb",
		"systemctl restart nginx ; deploy --token 'two words' ; systemctl stop auditd",
	} {
		t.Run(cmd, func(t *testing.T) {
			t.Parallel()
			cp, ad := startBridge(t, control.Approval{ID: "a1", Status: control.StatusPending, Host: "web01", Command: cmd})
			c := ad.lastCard()
			if !c.DenyOnly {
				t.Fatalf("masked command %q (presented %q) must make the card deny-only", cmd, c.Command)
			}
			approve, deny, notice := cardControls(c)
			if approve || !deny || !notice {
				t.Fatalf("card controls approve=%v deny=%v notice=%v; want no Approve, a Deny and the notice", approve, deny, notice)
			}
			ad.decisions <- Decision{ID: "a1", Approve: true, By: "U1"}
			expectNoRelay(t, cp, "an Approve for a deny-only card")
			ad.decisions <- Decision{ID: "a1", Approve: false, By: "U1"}
			expectRelay(t, cp, "a1", false)
		})
	}
}

// TestBridgeIssue829ReproNeverApprovableWhenHidden runs the issue's two
// reproductions: a requester-planted redaction trigger must never yield an
// Approve control next to text that differs from the command the signer would
// authorize. Either the card shows the original verbatim (redaction no longer
// swallows the later stages) or it is deny-only and an Approve is refused.
func TestBridgeIssue829ReproNeverApprovableWhenHidden(t *testing.T) {
	t.Parallel()
	for _, cmd := range []string{
		"systemctl restart nginx ; echo -----BEGIN PRIVATE KEY----- ; systemctl stop auditd ; iptables -F",
		`systemctl restart nginx ; echo '--token "' ; systemctl stop auditd ; iptables -F ; echo '"'`,
	} {
		t.Run(cmd, func(t *testing.T) {
			t.Parallel()
			cp, ad := startBridge(t, control.Approval{ID: "a1", Status: control.StatusPending, Host: "web01", Command: cmd})
			c := ad.lastCard()
			approve, deny, notice := cardControls(c)
			if c.Command != cmd {
				if !c.DenyOnly || approve || !deny || !notice {
					t.Fatalf("presented %q differs from the original but the card is DenyOnly=%v approve=%v deny=%v notice=%v", c.Command, c.DenyOnly, approve, deny, notice)
				}
				ad.decisions <- Decision{ID: "a1", Approve: true, By: "U1"}
				expectNoRelay(t, cp, "an Approve for a card hiding part of the command")
				return
			}
			if c.DenyOnly || !approve || notice {
				t.Fatalf("a verbatim card must keep Approve, got DenyOnly=%v approve=%v notice=%v", c.DenyOnly, approve, notice)
			}
		})
	}
}

// TestBridgeTruncatedCommandIsDenyOnly: a command over the adapter's CommandMax
// is truncated on the card (#666), so it is deny-only for the same reason as a
// masked one (#829); a command exactly at the bound is shown whole.
func TestBridgeTruncatedCommandIsDenyOnly(t *testing.T) {
	t.Parallel()
	cp, ad := startBridge(t, control.Approval{ID: "a1", Status: control.StatusPending, Host: "web01", Command: strings.Repeat("a", control.SlackCommandMax+1)})
	c := ad.lastCard()
	if !c.DenyOnly {
		t.Fatal("a command over CommandMax must make the card deny-only")
	}
	if approve, deny, notice := cardControls(c); approve || !deny || !notice {
		t.Fatalf("card controls approve=%v deny=%v notice=%v; want no Approve, a Deny and the notice", approve, deny, notice)
	}
	ad.decisions <- Decision{ID: "a1", Approve: true, By: "U1"}
	expectNoRelay(t, cp, "an Approve for a truncated card")

	_, ad = startBridge(t, control.Approval{ID: "a2", Status: control.StatusPending, Host: "web01", Command: strings.Repeat("a", control.SlackCommandMax)})
	if ad.lastCard().DenyOnly {
		t.Fatal("a command exactly at CommandMax is shown whole and must keep Approve")
	}
}

// TestBridgeUnmaskedCommandKeepsApprove: a short command redaction leaves
// untouched is presented verbatim with both buttons, and Approve relays.
func TestBridgeUnmaskedCommandKeepsApprove(t *testing.T) {
	t.Parallel()
	cp, ad := startBridge(t, control.Approval{ID: "a1", Status: control.StatusPending, Host: "web01", Command: "systemctl restart nginx"})
	c := ad.lastCard()
	if c.DenyOnly || c.Command != "systemctl restart nginx" {
		t.Fatalf("unmasked command must be presented verbatim and approvable, got %+v", c)
	}
	if approve, deny, notice := cardControls(c); !approve || !deny || notice {
		t.Fatalf("card controls approve=%v deny=%v notice=%v; want both buttons and no notice", approve, deny, notice)
	}
	ad.decisions <- Decision{ID: "a1", Approve: true, By: "U1"}
	expectRelay(t, cp, "a1", true)
}

// TestBridgeRefusesApproveForUnpresentedID: an Approve for an id this bridge
// never posted an Approve control for (a forged interactive payload, or a card
// from before a restart that has not been re-presented) is refused; a Deny for
// it is still relayed (#829).
func TestBridgeRefusesApproveForUnpresentedID(t *testing.T) {
	t.Parallel()
	cp, ad := startBridge(t, control.Approval{ID: "a1", Status: control.StatusPending, Host: "web01", Command: "uptime"})
	ad.decisions <- Decision{ID: "ghost", Approve: true, By: "U1"}
	expectNoRelay(t, cp, "an Approve for an id never presented with an Approve control")
	ad.decisions <- Decision{ID: "ghost", Approve: false, By: "U1"}
	expectRelay(t, cp, "ghost", false)
}
