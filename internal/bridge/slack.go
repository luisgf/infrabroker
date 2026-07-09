package bridge

import (
	"context"
	"fmt"
	"log"

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
	summary := fmt.Sprintf("*Approval requested* — run `%s` on `%s`", ap.Command, ap.Host)
	detail := fmt.Sprintf("caller `%s`", ap.Caller)
	if ap.EndUser != "" {
		detail += fmt.Sprintf(" · user `%s`", ap.EndUser)
	}
	if ap.Sudo {
		detail += " · sudo"
	}
	if ap.Rule != "" {
		detail += fmt.Sprintf(" · rule `%s`", ap.Rule)
	}
	section := slack.NewSectionBlock(slack.NewTextBlockObject(slack.MarkdownType, summary+"\n"+detail, false, false), nil, nil)
	approve := slack.NewButtonBlockElement(actionApprove, ap.ID, slack.NewTextBlockObject(slack.PlainTextType, "Approve", false, false))
	approve.Style = slack.StylePrimary
	deny := slack.NewButtonBlockElement(actionDeny, ap.ID, slack.NewTextBlockObject(slack.PlainTextType, "Deny", false, false))
	deny.Style = slack.StyleDanger
	actions := slack.NewActionBlock("infrabroker_"+ap.ID, approve, deny)
	_, _, err := a.api.PostMessageContext(ctx, a.channel, slack.MsgOptionBlocks(section, actions))
	return err
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
