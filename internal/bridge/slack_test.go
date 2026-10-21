package bridge

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
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

// TestSlackApprovalShowsStrippedEndUserAndSudoTarget pins #747 (the Slack
// sibling of #668/#468): a request whose asserted end user the control plane
// dropped must say so on the card — it is exactly the request the identity-map
// four-eyes guard cannot attribute — and an elevation must name its target
// account like the Teams card does.
func TestSlackApprovalShowsStrippedEndUserAndSudoTarget(t *testing.T) {
	plain := func(ap control.Approval) string {
		var out string
		for _, blk := range buildApprovalBlocks(ap) {
			if sb, ok := blk.(*slack.SectionBlock); ok && sb.Text != nil && sb.Text.Type == slack.PlainTextType {
				out += sb.Text.Text
			}
		}
		return out
	}
	stripped := plain(control.Approval{ID: "ap1", Caller: "brk1", Host: "web01", Command: "reboot", EndUserStripped: true, Sudo: true, SudoUser: "postgres"})
	if !strings.Contains(stripped, "user (asserted by an untrusted broker, dropped)") {
		t.Errorf("stripped end user must be surfaced on the card, got %q", stripped)
	}
	if !strings.Contains(stripped, "sudo → postgres") {
		t.Errorf("elevation must name the target account, got %q", stripped)
	}
	root := plain(control.Approval{ID: "ap2", Caller: "brk1", Host: "web01", Command: "reboot", EndUser: "alice", Sudo: true})
	if !strings.Contains(root, "user alice") || strings.Contains(root, "dropped") {
		t.Errorf("a trusted end user renders as before, got %q", root)
	}
	if !strings.Contains(root, "sudo → root") {
		t.Errorf("sudo without a user is root, got %q", root)
	}
	none := plain(control.Approval{ID: "ap3", Caller: "brk1", Host: "web01", Command: "reboot"})
	if strings.Contains(none, "user") || strings.Contains(none, "sudo") {
		t.Errorf("a request with no end user and no sudo shows neither, got %q", none)
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
// a connection error, invalid auth, or — #574 — the EventTypeConnecting that
// slack-go emits with ConnectionCount > 0 when it reconnects after a dropped
// WebSocket, ping timeout or Slack-requested disconnect; the library never
// emits EventTypeDisconnect to consumers), so approvers never see buttons whose
// clicks cannot reach the bridge. Clicks on the connected link still flow
// through as decisions, and the next Connected reopens the gate.
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
		// What slack-go v0.30 actually emits after a drop: RunContext reconnects
		// and the second connection starts with Connecting{ConnectionCount: 1}.
		{Type: socketmode.EventTypeConnecting, Data: &slack.ConnectingEvent{Attempt: 1, ConnectionCount: 1}},
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
		// The gate stays shut through the reconnect attempt (slack-go emits a
		// further Connecting per retry) and reopens only on the next Connected.
		events <- socketmode.Event{Type: socketmode.EventTypeConnecting, Data: &slack.ConnectingEvent{Attempt: 2, ConnectionCount: 1}}
		events <- socketmode.Event{Type: socketmode.EventTypeHello}
		if err := a.Post(context.Background(), ap); !errors.Is(err, errSlackDisconnected) {
			t.Fatalf("Post during the reconnect after %s: got %v, want errSlackDisconnected", tc.Type, err)
		}
		events <- socketmode.Event{Type: socketmode.EventTypeConnected, Data: &socketmode.ConnectedEvent{ConnectionCount: 1}}
		events <- socketmode.Event{Type: socketmode.EventTypeHello}
		if !a.connected.Load() {
			t.Fatalf("the Connected after %s must reopen the gate", tc.Type)
		}
	}
}

// TestSlackInitialConnectingKeepsState pins the #574 distinction: the
// very first Connecting (ConnectionCount 0, no link existed yet) is not a drop,
// and a Connecting event without typed data is ignored rather than mis-read.
func TestSlackInitialConnectingKeepsState(t *testing.T) {
	t.Parallel()
	a, events := newTestSlackAdapter(t, func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	})
	events <- socketmode.Event{Type: socketmode.EventTypeConnecting, Data: &slack.ConnectingEvent{Attempt: 1, ConnectionCount: 0}}
	events <- socketmode.Event{Type: socketmode.EventTypeConnected, Data: &socketmode.ConnectedEvent{ConnectionCount: 0}}
	events <- socketmode.Event{Type: socketmode.EventTypeHello}
	if !a.connected.Load() {
		t.Fatal("the initial Connecting/Connected sequence must leave the adapter connected")
	}
	// A Connecting with no typed payload (nothing slack-go sends today) must not
	// flip the gate either way.
	events <- socketmode.Event{Type: socketmode.EventTypeConnecting}
	events <- socketmode.Event{Type: socketmode.EventTypeHello}
	if !a.connected.Load() {
		t.Fatal("a Connecting event without a ConnectingEvent payload must be ignored")
	}
}

// TestSlackPostReturnsWithinTheWebAPITimeout pins #575: the Slack Web API
// client carries an http.Client timeout, so a peer that accepts the connection
// and never answers chat.postMessage cannot wedge Bridge.Run's single select
// loop (which calls Post inline). The adapter is built through the same
// constructor path as NewSlackAdapter, pointed at a never-responding server.
func TestSlackPostReturnsWithinTheWebAPITimeout(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Never answer: hold the request until the client gives up (its
		// timeout closes the connection, which cancels r.Context()) or the
		// test ends.
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(func() { close(release); srv.Close() })

	const timeout = 200 * time.Millisecond
	a := &SlackAdapter{
		api:       newSlackWebAPI("xoxb-test", "xapp-test", timeout, slack.OptionAPIURL(srv.URL+"/")),
		channel:   "C0TEST",
		decisions: make(chan Decision, 32),
		done:      make(chan struct{}),
	}
	a.connected.Store(true)

	errc := make(chan error, 1)
	start := time.Now()
	go func() {
		errc <- a.Post(context.Background(), control.Approval{ID: "ap1", Host: "web01", Command: "uptime"})
	}()
	select {
	case err := <-errc:
		var nerr net.Error
		if err == nil || !(errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &nerr) && nerr.Timeout())) {
			t.Fatalf("Post against a stalled Web API: got %v, want a timeout error", err)
		}
		if took := time.Since(start); took > 10*timeout {
			t.Fatalf("Post took %s, want about the %s client timeout", took, timeout)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Post never returned against a never-responding Web API: the bridge loop would wedge (#575)")
	}
}

// TestSlackApprovalBoundsLongCommand pins #666: Slack rejects a section text over
// 3000 characters (invalid_blocks), which would leave the bridge retrying an
// approval the approver never sees. A 64 KiB command is truncated so the section
// stays within the limit; a short command is unchanged.
func TestSlackApprovalBoundsLongCommand(t *testing.T) {
	sectionText := func(ap control.Approval) string {
		for _, blk := range buildApprovalBlocks(ap) {
			if sb, ok := blk.(*slack.SectionBlock); ok && sb.Text != nil && sb.Text.Type == slack.PlainTextType {
				return sb.Text.Text
			}
		}
		t.Fatal("no plain_text section")
		return ""
	}

	long := control.Approval{ID: "ap1", Caller: "brk1", Host: "web01", EndUser: "alice@example.com", Sudo: true, Rule: "^x", Command: strings.Repeat("é", 32*1024)}
	got := sectionText(long)
	if n := len([]rune(got)); n > 3000 {
		t.Errorf("section text is %d chars for a 64 KiB command; Slack rejects > 3000", n)
	}
	if !strings.Contains(got, "truncated: 65536 bytes total") || !strings.Contains(got, "caller brk1") {
		t.Errorf("want the truncation marker and the rest of the card kept, got %.120s...", got)
	}

	short := control.Approval{ID: "ap1", Caller: "brk1", Host: "web01", Command: "uptime"}
	if got := sectionText(short); got != "run uptime on web01\ncaller brk1" {
		t.Errorf("a short command must be unchanged, got %q", got)
	}
}
