package bridge

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/slack-go/slack"
	"github.com/slack-go/slack/socketmode"

	"github.com/luisgf/infrabroker/internal/control"
)

// TestSlackApprovalRendersUntrustedFieldsAsPlainText pins #239: the broker-
// supplied command/host/identity must render literally in a plain_text block,
// never in a mrkdwn block where a crafted value could inject a clickable link
// (<url|text>), a bare-URL auto-link, or formatting into the human approver's
// card (approver phishing — the Slack sibling of the Teams #174 escaping).
func TestSlackApprovalRendersUntrustedFieldsAsPlainText(t *testing.T) {
	const inject = "x` <https://evil.example|Approve here> *urgent*"
	ap := control.Approval{ID: "ap1", Caller: "brk1", Host: "web01", Command: inject}

	blocks := buildApprovalBlocks(ap)

	var plainText string
	for _, blk := range blocks {
		sb, ok := blk.(*slack.SectionBlock)
		if !ok || sb.Text == nil {
			continue
		}
		if sb.Text.Type == slack.MarkdownType && strings.Contains(sb.Text.Text, "evil.example") {
			t.Errorf("untrusted command must not appear in a mrkdwn block (link-injectable): %q", sb.Text.Text)
		}
		if sb.Text.Type == slack.PlainTextType {
			plainText += sb.Text.Text
		}
	}
	if !strings.Contains(plainText, inject) {
		t.Errorf("the command must render literally in a plain_text block; got %q", plainText)
	}
}

// TestSlackSendDecisionDropsAfterStop pins #402: once the bridge has shut down
// (Stop), a click arriving with a full decisions buffer must be dropped rather
// than block the socket-mode goroutine forever. The send fills the buffer, Stop
// fires, and a further send must return immediately instead of wedging.
func TestSlackSendDecisionDropsAfterStop(t *testing.T) {
	t.Parallel()
	a := &SlackAdapter{
		decisions: make(chan Decision, 32),
		done:      make(chan struct{}),
	}
	for i := range 32 {
		a.sendDecision(Decision{ID: string(rune('a' + i))})
	}
	// Buffer full: a pre-Stop send would block. Stop must un-wedge it.
	done := make(chan struct{})
	go func() {
		a.sendDecision(Decision{ID: "spill"})
		close(done)
	}()
	a.Stop()
	select {
	case <-done:
		// send returned (dropped after Stop) — good
	case <-time.After(2 * time.Second):
		t.Fatal("sendDecision blocked past Stop: the socket-mode goroutine would leak (#402)")
	}
}

// newTestSlackAdapter builds an adapter around an injected Socket Mode runner
// and event source (no network), with listen running under ctx.
func newTestSlackAdapter(t *testing.T, run func(ctx context.Context) error) (*SlackAdapter, chan socketmode.Event) {
	t.Helper()
	events := make(chan socketmode.Event)
	ctx, cancel := context.WithCancel(context.Background())
	a := &SlackAdapter{
		decisions: make(chan Decision, 32),
		done:      make(chan struct{}),
		run:       run,
		events:    events,
		cancel:    cancel,
	}
	go a.listen(ctx)
	t.Cleanup(a.Stop)
	return a, events
}

// TestSlackListenClosesDecisionsWhenSocketModeExits pins #452: slack-go's
// RunContext returns permanently on invalid_auth / token_revoked / HTTP 404
// and never closes Events, so the adapter must treat the loop's exit as fatal —
// stop and close Decisions so Bridge.Run returns — instead of leaving the bridge
// polling and posting cards whose buttons can never be answered.
func TestSlackListenClosesDecisionsWhenSocketModeExits(t *testing.T) {
	t.Parallel()
	a, events := newTestSlackAdapter(t, func(ctx context.Context) error {
		return errors.New("invalid_auth")
	})

	select {
	case _, ok := <-a.Decisions():
		if ok {
			t.Fatal("unexpected decision before the loop exited")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Decisions was not closed after the socket-mode loop exited (#452)")
	}
	// Stop fired (done closed): a late click must still be dropped, not wedge
	// the loop goroutine (#402 guarantee kept), and nothing may panic.
	select {
	case <-a.done:
	default:
		t.Fatal("Stop was not applied after the socket-mode loop exited")
	}
	a.sendDecision(Decision{ID: "late"})
	if a.connected.Load() {
		t.Fatal("adapter must not report connected after the loop exited")
	}
	// The event source is still open (slack-go never closes it) and nobody reads
	// it any more: that is exactly the state the fix detects, not a problem.
	select {
	case events <- socketmode.Event{Type: socketmode.EventTypeConnected}:
		t.Fatal("listen must have stopped consuming events")
	case <-time.After(50 * time.Millisecond):
	}
}

// TestSlackListenStopClosesDecisions: a Stop from the bridge side (normal
// shutdown) cancels the Socket Mode runner and closes Decisions too.
func TestSlackListenStopClosesDecisions(t *testing.T) {
	t.Parallel()
	cancelled := make(chan struct{})
	a, _ := newTestSlackAdapter(t, func(ctx context.Context) error {
		<-ctx.Done()
		close(cancelled)
		return ctx.Err()
	})
	a.Stop()
	select {
	case <-cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not cancel the socket-mode runner's context")
	}
	select {
	case _, ok := <-a.Decisions():
		if ok {
			t.Fatal("unexpected decision")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Decisions was not closed after Stop")
	}
}

// TestSlackPostRefusedWhileDisconnected pins the #452 Post gate: a card is only
// posted while the Socket Mode link is up (set by EventTypeConnected, cleared by
// a connection error, invalid auth, or disconnect), so approvers never see
// buttons whose clicks cannot reach the bridge. Clicks on the connected link
// still flow through as decisions.
func TestSlackPostRefusedWhileDisconnected(t *testing.T) {
	t.Parallel()
	a, events := newTestSlackAdapter(t, func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	})
	ap := control.Approval{ID: "ap1", Host: "web01", Command: "uptime"}

	// Not yet connected: Post is refused before any Web API call (api is nil).
	if err := a.Post(context.Background(), ap); !errors.Is(err, errSlackDisconnected) {
		t.Fatalf("Post before connect: got %v, want errSlackDisconnected", err)
	}

	events <- socketmode.Event{Type: socketmode.EventTypeConnected, Data: &socketmode.ConnectedEvent{}}
	// A click on the live link becomes a decision (proves the event was consumed
	// in order, so connected is now set).
	cb := slack.InteractionCallback{Type: slack.InteractionTypeBlockActions}
	cb.User.ID = "U1"
	cb.ActionCallback.BlockActions = []*slack.BlockAction{{ActionID: actionDeny, Value: "ap1"}}
	events <- socketmode.Event{Type: socketmode.EventTypeInteractive, Data: cb}
	select {
	case d := <-a.Decisions():
		if d.ID != "ap1" || d.Approve || d.By != "U1" {
			t.Fatalf("decision %+v, want deny of ap1 by U1", d)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("click was not turned into a decision")
	}
	if !a.connected.Load() {
		t.Fatal("EventTypeConnected must mark the adapter connected")
	}

	for _, tc := range []socketmode.Event{
		{Type: socketmode.EventTypeConnectionError, Data: &slack.ConnectionErrorEvent{Attempt: 1, Backoff: time.Second, ErrorObj: errors.New("dial tcp: i/o timeout")}},
		{Type: socketmode.EventTypeInvalidAuth, Data: &slack.InvalidAuthEvent{}},
		{Type: socketmode.EventTypeDisconnect},
	} {
		events <- socketmode.Event{Type: socketmode.EventTypeConnected}
		events <- tc
		// Drain through the listen goroutine: a further event is only consumed
		// once the previous one was handled.
		events <- socketmode.Event{Type: socketmode.EventTypeHello}
		if a.connected.Load() {
			t.Fatalf("%s must clear the connected state", tc.Type)
		}
		if err := a.Post(context.Background(), ap); !errors.Is(err, errSlackDisconnected) {
			t.Fatalf("Post after %s: got %v, want errSlackDisconnected", tc.Type, err)
		}
	}
}
