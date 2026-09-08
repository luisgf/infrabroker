package bridge

import (
	"strings"
	"testing"
	"time"

	"github.com/slack-go/slack"

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
