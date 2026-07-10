package bridge

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/slack-go/slack"
	"github.com/slack-go/slack/socketmode"

	"github.com/luisgf/infrabroker/internal/control"
)

// Slack button action ids; the button value carries the approval request id.
const (
	actionApprove = "infrabroker_approve"
	actionDeny    = "infrabroker_deny"
)

// SlackAdapter presents approvals in a Slack channel and receives Allow/Deny
// button clicks over Socket Mode — an outbound WebSocket, so the bridge needs no
// inbound endpoint, no public URL, and no signing-secret verification path.
type SlackAdapter struct {
	api       *slack.Client
	sm        *socketmode.Client
	channel   string
	decisions chan Decision
}

// NewSlackAdapter connects with a bot token (xoxb-) and an app-level token
// (xapp-, for Socket Mode) and posts to channel. It starts the Socket Mode loop.
func NewSlackAdapter(botToken, appToken, channel string) (*SlackAdapter, error) {
	if botToken == "" || appToken == "" || channel == "" {
		return nil, fmt.Errorf("slack adapter needs a bot token, an app-level token, and a channel")
	}
	api := slack.New(botToken, slack.OptionAppLevelToken(appToken))
	a := &SlackAdapter{
		api:       api,
		sm:        socketmode.New(api),
		channel:   channel,
		decisions: make(chan Decision, 32),
	}
	go a.listen()
	return a, nil
}

// Name identifies the platform.
func (a *SlackAdapter) Name() string { return "slack" }

// Decisions streams button clicks as decisions.
func (a *SlackAdapter) Decisions() <-chan Decision { return a.decisions }

// Post renders the approval as a Block Kit message with Approve / Deny buttons
// whose value carries the request id.
func (a *SlackAdapter) Post(ctx context.Context, ap control.Approval) error {
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
	fmt.Fprintf(&b, "run %s on %s\ncaller %s", ap.Command, ap.Host, ap.Caller)
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

// listen runs the Socket Mode loop, turning button clicks into Decisions. The
// interaction is acknowledged immediately (Slack requires an ack within 3s); the
// bridge relays the decision to the control plane asynchronously.
func (a *SlackAdapter) listen() {
	go func() {
		if err := a.sm.Run(); err != nil {
			log.Printf("approval-bridge: slack socket mode stopped: %v", err)
		}
	}()
	for evt := range a.sm.Events {
		if evt.Type != socketmode.EventTypeInteractive {
			continue
		}
		cb, ok := evt.Data.(slack.InteractionCallback)
		if !ok {
			continue
		}
		if evt.Request != nil {
			_ = a.sm.Ack(*evt.Request)
		}
		if cb.Type != slack.InteractionTypeBlockActions {
			continue
		}
		for _, action := range cb.ActionCallback.BlockActions {
			switch action.ActionID {
			case actionApprove:
				a.decisions <- Decision{ID: action.Value, Approve: true, By: cb.User.ID}
			case actionDeny:
				a.decisions <- Decision{ID: action.Value, Approve: false, By: cb.User.ID}
			}
		}
	}
}
