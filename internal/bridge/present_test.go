package bridge

import (
	"strings"
	"testing"

	"github.com/slack-go/slack"

	"github.com/luisgf/infrabroker/internal/control"
)

// bodyText returns the plain_text body section of the card (the first one).
func bodyText(t *testing.T, c Card) string {
	t.Helper()
	for _, blk := range buildApprovalBlocks(c) {
		if sb, ok := blk.(*slack.SectionBlock); ok && sb.Text != nil && sb.Text.Type == slack.PlainTextType {
			return sb.Text.Text
		}
	}
	t.Fatal("no plain_text section")
	return ""
}

// TestBridgeEscapesFormatControlsWithoutDenyOnly pins #830: Unicode format and
// control characters in requester-controlled fields are rendered as visible
// \u{XXXX} escapes on the card, no raw one is emitted, and because that
// rendering is faithful (nothing hidden) it does not turn the card deny-only:
// the core compares the ORIGINAL with the redacted command, before escaping.
func TestBridgeEscapesFormatControlsWithoutDenyOnly(t *testing.T) {
	t.Parallel()
	cmd := "systemctl restart nginx \u202e ; rm -rf /srv/data #\u202c \u2066 \u009b31m café 日本語"
	cp, ad := startBridge(t, control.Approval{ID: "a1", Status: control.StatusPending, Host: "web\u202e01",
		Caller: "br\u2066k", EndUser: "al\u200fice", Sudo: true, SudoUser: "ro\u202eot", Rule: "ru\u061cle", Command: cmd})
	c := ad.lastCard()
	if c.DenyOnly || c.Command != cmd {
		t.Fatalf("escaping must not make the card deny-only nor alter the core's command, got DenyOnly=%v %q", c.DenyOnly, c.Command)
	}
	if approve, deny, notice := cardControls(c); !approve || !deny || notice {
		t.Fatalf("controls approve=%v deny=%v notice=%v; want both buttons", approve, deny, notice)
	}
	got := bodyText(t, c)
	for _, r := range got {
		if r == '\u202e' || r == '\u202c' || r == '\u2066' || r == '\u009b' || r == '\u200f' || r == '\u061c' {
			t.Fatalf("raw format/control rune U+%04X on the card: %q", r, got)
		}
	}
	for _, want := range []string{`\u{202e}`, `\u{202c}`, `\u{2066}`, `\u{9b}`, `\u{200f}`, `\u{61c}`, "café 日本語"} {
		if !strings.Contains(got, want) {
			t.Errorf("card missing %q: %q", want, got)
		}
	}
	ad.decisions <- Decision{ID: "a1", Approve: true, By: "U1"}
	expectRelay(t, cp, "a1", true)
}

// TestBridgeEscapedOverflowIsDenyOnly: escaping can grow a command past what
// the card fits. The core measures the ESCAPED length against CommandMax, so a
// command whose raw bytes fit but whose escaped form would be truncated is
// deny-only and its Approve is refused: an Approve is never shown beside a
// command the approver cannot fully read.
func TestBridgeEscapedOverflowIsDenyOnly(t *testing.T) {
	t.Parallel()
	// 3 raw bytes per rune (1800 <= 2000) but 8 bytes each once escaped (4800).
	cmd := strings.Repeat("\u202e", 600)
	cp, ad := startBridge(t, control.Approval{ID: "a1", Status: control.StatusPending, Host: "web01", Command: cmd})
	c := ad.lastCard()
	if len(cmd) > control.SlackCommandMax || !c.DenyOnly {
		t.Fatalf("raw %d bytes (limit %d), DenyOnly=%v; the escaped overflow must make the card deny-only", len(cmd), control.SlackCommandMax, c.DenyOnly)
	}
	if approve, deny, notice := cardControls(c); approve || !deny || !notice {
		t.Fatalf("controls approve=%v deny=%v notice=%v; want no Approve", approve, deny, notice)
	}
	ad.decisions <- Decision{ID: "a1", Approve: true, By: "U1"}
	expectNoRelay(t, cp, "an Approve for a card whose escaped command is truncated")
}

// TestSlackAdapterNeverApprovesTruncatedEscapedCommand: even handed a
// non-deny-only card, the adapter falls back to deny-only rendering when its
// own (escaped) rendering would be truncated.
func TestSlackAdapterNeverApprovesTruncatedEscapedCommand(t *testing.T) {
	t.Parallel()
	c := Card{Approval: control.Approval{ID: "a1", Host: "web01", Command: strings.Repeat("\u202e", 600)}}
	if approve, deny, notice := cardControls(c); approve || !deny || !notice {
		t.Fatalf("controls approve=%v deny=%v notice=%v; want deny-only", approve, deny, notice)
	}
}
