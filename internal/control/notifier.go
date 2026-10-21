package control

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

// Command-length bounds for the chat/webhook notifiers (#666), in bytes of the
// raw command before any platform escaping. Slack's section text is capped at
// 3000 characters and the rest of the card (host, caller, rule) shares it, so
// 2000 leaves room; Teams doubles worst-case through markdown escaping and its
// webhook rejects oversized cards, so 8000 keeps the escaped fact under ~16 KB.
const (
	SlackCommandMax = 2000
	TeamsCommandMax = 8000
)

// PresentedCommand bounds the command a chat/webhook notifier puts in a message
// (#666). Slack rejects a section text over 3000 characters and Teams rejects an
// oversized card, so a long multi-line script (the control plane accepts 64 KiB
// request bodies) would never be presented and the approver would see nothing.
// It returns cmd unchanged when len(cmd) <= max, else the first max bytes cut on
// a rune boundary plus a marker naming the total size and where the full command
// is shown. Only the notification is shortened; the mTLS UI and the forwarded
// request keep the full command.
func PresentedCommand(cmd string, max int) string {
	if len(cmd) <= max {
		return cmd
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(cmd[cut]) {
		cut--
	}
	return fmt.Sprintf("%s ... [truncated: %d bytes total; full command in /ui/approvals/<id>]", cmd[:cut], len(cmd))
}

// Notifier alerts an external channel that an approval request is pending.
// Implementations must not block for extended periods.
type Notifier interface {
	Notify(a Approval) error
}

// LogNotifier writes the request to the process log. Useful in development and
// as a fallback: the approver can use `broker-ctl approval list`.
type LogNotifier struct{}

// Notify implements Notifier.
func (LogNotifier) Notify(a Approval) error {
	// Surface the elevation: the certificate issued on approval bakes sudo into
	// its force-command, so the approver must see it to make an informed decision.
	elev := "none"
	if a.Sudo {
		su := a.SudoUser
		if su == "" {
			su = "root"
		}
		elev = "sudo:" + su
	}
	user := a.EndUser
	if user == "" && a.EndUserStripped {
		user = "(stripped)" // asserted by an untrusted broker and dropped (#451, #668)
	}
	log.Printf("[approval] PENDING id=%s caller=%s user=%s %s=%s cmd=%q elevation=%s rule=%s",
		a.ID, a.Caller, user, strings.ToLower(a.TargetLabel()), a.Host, a.Command, elev, a.Rule)
	return nil
}

// WebhookNotifier POSTs the request (JSON) to a URL. Intended for chat/alert
// integrations (Slack-compatible via a simple receiver).
type WebhookNotifier struct {
	URL    string
	client *http.Client
}

// NewWebhookNotifier creates a webhook notifier with a short timeout.
func NewWebhookNotifier(url string) *WebhookNotifier {
	return &WebhookNotifier{URL: url, client: newNotifierClient()}
}

// newNotifierClient returns the http.Client shared by the outbound notifiers:
// a short timeout and NO redirect following. The https-only guard (#44/#401)
// validates only the configured URL; the default client would transparently
// follow a 307/308 to an http:// or private-network Location and re-POST the
// approval payload (host, command, caller, end user) there. Returning the 3xx
// as-is makes the >= 300 status check in Notify fail loudly instead (#453).
func newNotifierClient() *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// Notify implements Notifier.
func (w *WebhookNotifier) Notify(a Approval) error {
	body, err := json.Marshal(a)
	if err != nil {
		return fmt.Errorf("serialising notification: %w", err)
	}
	resp, err := w.client.Post(w.URL, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("sending webhook: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %d", resp.StatusCode)
	}
	return nil
}
