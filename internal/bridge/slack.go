package bridge

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/slack-go/slack"
	"github.com/slack-go/slack/socketmode"

	"github.com/luisgf/infrabroker/internal/control"
)

// Slack button action ids; the button value carries the approval request id.
const (
	actionApprove = "infrabroker_approve"
	actionDeny    = "infrabroker_deny"
)

// errSlackDisconnected is returned by Post while the Socket Mode connection is
// down: a card posted then would show Approve/Deny buttons whose clicks cannot
// reach the bridge (#452). The bridge logs it and retries on its next poll.
var errSlackDisconnected = errors.New("slack socket mode is not connected; the card is withheld until it reconnects")

// SlackAdapter presents approvals in a Slack channel and receives Allow/Deny
// button clicks over Socket Mode — an outbound WebSocket, so the bridge needs no
// inbound endpoint, no public URL, and no signing-secret verification path.
type SlackAdapter struct {
	api     *slack.Client
	sm      *socketmode.Client
	channel string
	// decisions is closed by listen — and only by listen, after its last send —
	// when the Socket Mode loop has exited or Stop was called, so Bridge.Run
	// returns instead of polling and posting cards nobody can answer (#452).
	decisions chan Decision
	// done is closed by Stop: decision sends select on it so a click arriving
	// after the bridge's Run has exited cannot block the socket-mode loop
	// forever (the decisions channel is buffered, not unbounded, #402).
	done     chan struct{}
	stopOnce sync.Once

	// run is the Socket Mode loop (socketmode.Client.RunContext in production;
	// injectable for tests). slack-go's RunContext retries recoverable connect
	// errors itself but returns permanently on invalid_auth / account_inactive /
	// not_authed / token_revoked / HTTP 404 — and never closes events — so its
	// return is the only signal that clicks can no longer arrive.
	run    func(ctx context.Context) error
	events <-chan socketmode.Event
	ack    func(req socketmode.Request) error
	cancel context.CancelFunc
	// connected tracks the Socket Mode link: set on EventTypeConnected, cleared
	// the moment slack-go starts a reconnect (EventTypeConnecting with
	// ConnectionCount > 0 — the only event the library emits for a dropped
	// WebSocket, a ping timeout or a Slack-requested disconnect, #574), on a
	// failed reconnect attempt (connection error) and on invalid auth. Post
	// refuses to present a card while it is down.
	connected atomic.Bool
}

// slackWebAPITimeout bounds every Slack Web API call (chat.postMessage from
// Post, apps.connections.open from the Socket Mode loop). slack-go's default
// http.Client has no timeout and DefaultTransport no ResponseHeaderTimeout, so a
// peer that accepts the TLS handshake and never answers would block Post — and
// Post runs inline in Bridge.Run's select loop, so the whole bridge (polls and
// decision relays alike) would wedge while the process stayed up (#575). Same
// bound as the bridge's control-plane client.
const slackWebAPITimeout = 15 * time.Second

// newSlackWebAPI builds the Slack Web API client with the #575 timeout applied;
// extra options (a test's OptionAPIURL) are appended after it.
func newSlackWebAPI(botToken, appToken string, timeout time.Duration, extra ...slack.Option) *slack.Client {
	opts := append([]slack.Option{
		slack.OptionAppLevelToken(appToken),
		slack.OptionHTTPClient(&http.Client{Timeout: timeout}),
	}, extra...)
	return slack.New(botToken, opts...)
}

// NewSlackAdapter connects with a bot token (xoxb-) and an app-level token
// (xapp-, for Socket Mode) and posts to channel. It starts the Socket Mode loop.
func NewSlackAdapter(botToken, appToken, channel string) (*SlackAdapter, error) {
	if botToken == "" || appToken == "" || channel == "" {
		return nil, fmt.Errorf("slack adapter needs a bot token, an app-level token, and a channel")
	}
	api := newSlackWebAPI(botToken, appToken, slackWebAPITimeout)
	sm := socketmode.New(api)
	ctx, cancel := context.WithCancel(context.Background())
	a := &SlackAdapter{
		api:       api,
		sm:        sm,
		channel:   channel,
		decisions: make(chan Decision, 32),
		done:      make(chan struct{}),
		run:       sm.RunContext,
		events:    sm.Events,
		ack:       func(req socketmode.Request) error { return sm.Ack(req) },
		cancel:    cancel,
	}
	go a.listen(ctx)
	return a, nil
}

// Stop releases the adapter: the Socket Mode loop is cancelled, pending and
// future decision sends are dropped, and listen closes the decisions channel on
// its way out so Bridge.Run returns. Idempotent.
func (a *SlackAdapter) Stop() {
	a.stopOnce.Do(func() {
		close(a.done)
		if a.cancel != nil {
			a.cancel()
		}
	})
}

// Name identifies the platform.
func (a *SlackAdapter) Name() string { return "slack" }

// Decisions streams button clicks as decisions; closed when the adapter stops.
func (a *SlackAdapter) Decisions() <-chan Decision { return a.decisions }

// Post renders the approval as a Block Kit message with Approve / Deny buttons
// whose value carries the request id. While the Socket Mode link is down the
// card is withheld (errSlackDisconnected) rather than posted with buttons whose
// clicks could not arrive; the bridge retries on its next poll (#452).
func (a *SlackAdapter) Post(ctx context.Context, ap control.Approval) error {
	if !a.connected.Load() {
		return errSlackDisconnected
	}
	_, _, err := a.api.PostMessageContext(ctx, a.channel, slack.MsgOptionBlocks(buildApprovalBlocks(ap)...))
	return err
}

// buildApprovalBlocks renders the approval as Block Kit blocks: a static mrkdwn
// header, then the broker-supplied fields (command, host, caller, end user, rule)
// in a PLAIN-TEXT block, and the Approve/Deny buttons. The fields are rendered as
// plain_text — not mrkdwn — so a crafted command/host/identity renders literally
// and cannot inject a clickable link (`<url|text>`), a bare-URL auto-link, or
// formatting into the approver's card (#239). Slack mrkdwn has no backslash escape
// for `*`/`_`/backtick, so escaping (as the Teams Adaptive Card does, #174) is not
// enough here — plain_text is the faithful, injection-free rendering, and it still
// shows the approver the exact command.
func buildApprovalBlocks(ap control.Approval) []slack.Block {
	var b strings.Builder
	target := ap.Host
	if ap.TargetLabel() == "Cluster" {
		target = "cluster " + ap.Host // a k8s request names a cluster, not a host (#664)
	}
	fmt.Fprintf(&b, "run %s on %s\ncaller %s", control.PresentedCommand(ap.Command, control.SlackCommandMax), target, ap.Caller)
	if ap.EndUser != "" {
		fmt.Fprintf(&b, " · user %s", ap.EndUser)
	}
	if ap.Sudo {
		b.WriteString(" · sudo")
	}
	if ap.Rule != "" {
		fmt.Fprintf(&b, " · rule %s", ap.Rule)
	}
	header := slack.NewSectionBlock(slack.NewTextBlockObject(slack.MarkdownType, "*Approval requested*", false, false), nil, nil)
	body := slack.NewSectionBlock(slack.NewTextBlockObject(slack.PlainTextType, b.String(), false, false), nil, nil)
	approve := slack.NewButtonBlockElement(actionApprove, ap.ID, slack.NewTextBlockObject(slack.PlainTextType, "Approve", false, false))
	approve.Style = slack.StylePrimary
	deny := slack.NewButtonBlockElement(actionDeny, ap.ID, slack.NewTextBlockObject(slack.PlainTextType, "Deny", false, false))
	deny.Style = slack.StyleDanger
	actions := slack.NewActionBlock("infrabroker_"+ap.ID, approve, deny)
	return []slack.Block{header, body, actions}
}

// listen runs the Socket Mode loop under ctx and turns button clicks into
// Decisions. The interaction is acknowledged immediately (Slack requires an ack
// within 3s); the bridge relays the decision to the control plane asynchronously.
//
// The loop's exit is fatal for the bridge (#452): slack-go returns permanently
// on a revoked/invalid app-level token or an HTTP 404 and never closes events,
// so once run returns no click can ever arrive again. listen then stops the
// adapter and closes decisions, which makes Bridge.Run return ErrAdapterStopped
// instead of polling on and posting cards whose buttons do nothing. Connection
// state changes are logged as warnings so a bad SLACK_APP_TOKEN is visible at
// startup rather than only through timed-out approvals.
func (a *SlackAdapter) listen(ctx context.Context) {
	// Sole closer of decisions, and the sole sender (sendDecision runs on this
	// goroutine only), so the close can never race a send (#402 stays intact).
	defer close(a.decisions)
	runErr := make(chan error, 1)
	go func() { runErr <- a.run(ctx) }()
	for {
		select {
		case <-a.done:
			return
		case err := <-runErr:
			a.connected.Store(false)
			log.Printf("approval-bridge: slack socket mode exited: %v; button clicks can no longer arrive, stopping the bridge", err)
			a.Stop()
			return
		case evt := <-a.events:
			a.handle(evt)
		}
	}
}

// handle processes one Socket Mode event: connection-state events are logged
// and tracked for Post's gate; interactive button clicks become decisions.
//
// slack-go (v0.30) never surfaces a lost connection as its own event: a dropped
// WebSocket, a ping timeout or a Slack-requested `disconnect` frame all make its
// run loop return and RunContext reconnect, and the only thing the Events
// channel sees is EventTypeConnecting with ConnectionCount > 0 (the library
// swallows the disconnect request as an internal error, so EventTypeDisconnect
// never reaches a consumer). That Connecting event is therefore the drop signal
// the gate keys on; a ConnectionCount of 0 is the initial connect, before any
// link existed (#574).
func (a *SlackAdapter) handle(evt socketmode.Event) {
	switch evt.Type {
	case socketmode.EventTypeConnected:
		a.connected.Store(true)
		log.Printf("approval-bridge: slack socket mode connected")
		return
	case socketmode.EventTypeConnecting:
		ce, ok := evt.Data.(*slack.ConnectingEvent)
		if ok && ce != nil && ce.ConnectionCount > 0 {
			a.connected.Store(false)
			log.Printf("approval-bridge: warning: slack socket mode link lost, reconnecting (connection %d, attempt %d); cards are withheld until it is back", ce.ConnectionCount+1, ce.Attempt)
		}
		return
	case socketmode.EventTypeConnectionError:
		a.connected.Store(false)
		if ce, ok := evt.Data.(*slack.ConnectionErrorEvent); ok && ce != nil {
			log.Printf("approval-bridge: warning: slack socket mode connection error (attempt %d, retrying in %s): %v", ce.Attempt, ce.Backoff, ce.ErrorObj)
		} else {
			log.Printf("approval-bridge: warning: slack socket mode connection error, retrying")
		}
		return
	case socketmode.EventTypeInvalidAuth:
		a.connected.Store(false)
		log.Printf("approval-bridge: warning: slack socket mode rejected the app-level token (SLACK_APP_TOKEN invalid or revoked)")
		return
	case socketmode.EventTypeInteractive:
	default:
		return
	}
	cb, ok := evt.Data.(slack.InteractionCallback)
	if !ok {
		return
	}
	if evt.Request != nil && a.ack != nil {
		_ = a.ack(*evt.Request)
	}
	if cb.Type != slack.InteractionTypeBlockActions {
		return
	}
	for _, action := range cb.ActionCallback.BlockActions {
		switch action.ActionID {
		case actionApprove:
			a.sendDecision(Decision{ID: action.Value, Approve: true, By: cb.User.ID})
		case actionDeny:
			a.sendDecision(Decision{ID: action.Value, Approve: false, By: cb.User.ID})
		}
	}
}

// sendDecision pushes a click onto the decisions channel without ever blocking
// past shutdown (#402): once Stop has closed done (the bridge exited, e.g. on
// ctx cancellation with queued clicks), the send is dropped instead of wedging
// the socket-mode loop goroutine. done is checked first because decisions is
// closed (by listen, after done) once the adapter has stopped (#452): a send
// after Stop must be dropped, never attempted on the closed channel.
func (a *SlackAdapter) sendDecision(d Decision) {
	select {
	case <-a.done:
		return
	default:
	}
	select {
	case a.decisions <- d:
	case <-a.done:
	}
}
