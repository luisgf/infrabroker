package control

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

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
	log.Printf("[approval] PENDING id=%s caller=%s user=%s host=%s cmd=%q elevation=%s rule=%s",
		a.ID, a.Caller, a.EndUser, a.Host, a.Command, elev, a.Rule)
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
	return &WebhookNotifier{URL: url, client: &http.Client{Timeout: 5 * time.Second}}
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
