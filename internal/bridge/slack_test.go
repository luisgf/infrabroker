package bridge

import (
	"strings"
	"testing"

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
