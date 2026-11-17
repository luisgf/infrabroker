package main

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/luisgf/infrabroker/internal/signer"
)

// TestEscapeTextUnicode pins #815: escapeText must neutralise UTF-8-encoded C1
// controls (8-bit CSI included), bidi/format controls and invalid UTF-8, keep
// the #748 C0 forms, and leave printable non-ASCII text alone.
func TestEscapeTextUnicode(t *testing.T) {
	t.Parallel()
	cases := []struct{ name, in, want string }{
		{"plain", "ls -la /tmp", "ls -la /tmp"},
		{"empty", "", ""},
		{"c0 newline cr tab", "a\nb\rc\td", `a\nb\rc\td`},
		{"c0 esc bel nul del", "\x1b]0;x\x07\x00\x7f", `\x1b]0;x\x07\x00\x7f`},
		{"c1 csi", "ok\u009b1A\u009b2Kforged", `ok\u{9b}1A\u{9b}2Kforged`},
		{"c1 range edges", "\u0080\u009f", `\u{80}\u{9f}`},
		{"nbsp is printable", "a b", "a b"},
		{"bidi override", "x‮y", `x\u{202e}y`},
		{"bidi isolates", "⁦a⁩", `\u{2066}a\u{2069}`},
		{"lrm rlm alm", "‎‏؜", `\u{200e}\u{200f}\u{61c}`},
		{"line and paragraph separator", "a b c", `a\u{2028}b\u{2029}c`},
		{"bom", "\xef\xbb\xbfx", `\u{feff}x`},
		{"invalid utf8", "a\xffb\xc3", `a\xffb\xc3`},
		{"lone continuation byte", "\x9b", `\x9b`},
		{"accents", "ünïcode ok", "ünïcode ok"},
		{"cjk", "日本語のコマンド", "日本語のコマンド"},
		{"emoji", "echo 🚀", "echo 🚀"},
		{"mixed", "é\u009bé\x1b", `é\u{9b}é\x1b`},
	}
	for _, c := range cases {
		if got := escapeText(c.in); got != c.want {
			t.Errorf("%s: escapeText(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
	// The issue's reproduction: nothing in the output may be a control/format rune.
	out := escapeText("ok\x1b[1A\x1b[2Kforged‮\u009b")
	for _, r := range out {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			t.Errorf("output still holds control/format rune %U: %q", r, out)
		}
	}
}

// hostile carries a CSI, a bidi override and a newline.
const hostile = "x\u009b1A‮\ny"

func assertCleanLine(t *testing.T, what, line string) {
	t.Helper()
	if !utf8.ValidString(line) {
		t.Errorf("%s: invalid UTF-8 in %q", what, line)
	}
	for _, r := range line {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			t.Errorf("%s: raw control/format rune %U in %q", what, r, line)
		}
	}
}

func TestApprovalListEscapesServerStrings(t *testing.T) {
	t.Parallel()
	out := formatApprovalItem(approvalListItem{
		ID: hostile, Status: hostile, Caller: hostile, EndUser: hostile, Host: hostile,
		SudoUser: hostile, Sudo: true, Command: hostile, Rule: hostile,
	})
	// The item is two lines by design (header + cmd line).
	if n := strings.Count(out, "\n"); n != 2 {
		t.Errorf("approval item should be exactly 2 lines, got %d: %q", n, out)
	}
	for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		assertCleanLine(t, "approval list", line)
	}
	if !strings.Contains(out, `\u{9b}`) || !strings.Contains(out, `\u{202e}`) {
		t.Errorf("approval list lacks the escaped forms: %q", out)
	}
}

func TestRevocationsEscapesServerStrings(t *testing.T) {
	t.Parallel()
	out := formatFrozenRow(signer.FrozenEntry{
		FreezeSubject: signer.FreezeSubject{Kind: "caller", Value: hostile},
		FrozenBy:      hostile, Reason: hostile,
	})
	if n := strings.Count(out, "\n"); n != 1 {
		t.Errorf("revocations row should be one line, got %d newlines: %q", n, out)
	}
	assertCleanLine(t, "revocations", strings.TrimSuffix(out, "\n"))
	if !strings.Contains(out, `\u{9b}`) {
		t.Errorf("revocations lacks the escaped form: %q", out)
	}
}

func TestPolicyGrantsEscapesServerStrings(t *testing.T) {
	t.Parallel()
	out := formatGrantRow(signer.Grant{
		ID: hostile, Host: hostile, Caller: hostile, EndUser: hostile,
		Allow: []string{hostile}, WaiveApproval: []string{hostile},
	})
	if n := strings.Count(out, "\n"); n != 1 {
		t.Errorf("grants row should be one line, got %d newlines: %q", n, out)
	}
	assertCleanLine(t, "policy grants", strings.TrimSuffix(out, "\n"))
	if !strings.Contains(out, `\u{202e}`) {
		t.Errorf("policy grants lacks the escaped form: %q", out)
	}
}
