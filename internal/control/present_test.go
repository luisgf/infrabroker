package control

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"
	"unicode"
)

func TestPresentText(t *testing.T) {
	cases := []struct{ name, in, text, line string }{
		{"plain", "systemctl restart nginx", "systemctl restart nginx", "systemctl restart nginx"},
		{"non-ascii kept", "echo café 日本語 🙂", "echo café 日本語 🙂", "echo café 日本語 🙂"},
		{"bidi override", "a\u202eb\u202cc", `a\u{202e}b\u{202c}c`, `a\u{202e}b\u{202c}c`},
		{"isolate", "a\u2066b\u2069", `a\u{2066}b\u{2069}`, `a\u{2066}b\u{2069}`},
		{"c1 csi", "a\u009b31m", `a\u{9b}31m`, `a\u{9b}31m`},
		{"line sep", "a\u2028b\u2029", `a\u{2028}b\u{2029}`, `a\u{2028}b\u{2029}`},
		{"bom zwj", "\ufeffa\u200d", `\u{feff}a\u{200d}`, `\u{feff}a\u{200d}`},
		{"c0", "a\x1b[0m\x00\x7f", `a\x1b[0m\x00\x7f`, `a\x1b[0m\x00\x7f`},
		{"layout", "a\nb\tc\rd", "a\nb\tc" + `\r` + "d", `a\nb\tc\rd`},
		{"invalid utf8", "a\xffb", `a\xffb`, `a\xffb`},
	}
	for _, c := range cases {
		if got := PresentText(c.in); got != c.text {
			t.Errorf("%s: PresentText = %q, want %q", c.name, got, c.text)
		}
		if got := PresentLine(c.in); got != c.line {
			t.Errorf("%s: PresentLine = %q, want %q", c.name, got, c.line)
		}
	}
}

// noRawControls fails when s still carries a rune the presenter must have
// escaped (Cf, C1, U+2028/9).
func noRawControls(t *testing.T, where, s string) {
	t.Helper()
	for _, r := range s {
		if r == '\n' || r == '\t' {
			continue
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029' {
			t.Errorf("%s emitted raw rune U+%04X in %q", where, r, s)
		}
	}
}

// Not parallel: it redirects the global logger.
func TestLogNotifierEscapesRequesterFields(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	_ = LogNotifier{}.Notify(Approval{ID: "a1", Caller: "br\u202eoker", EndUser: "al\nice\u2066", Host: "h\u009b1",
		Command: "ls \u202e ; rm -rf /\u2066 \x1b[2J", SudoUser: "ro\u202eot", Sudo: true, Rule: "r\u200fule\r\nforged"})
	out := buf.String()
	noRawControls(t, "log", strings.TrimSuffix(out, "\n"))
	for _, want := range []string{`br\u{202e}oker`, `al\nice\u{2066}`, `h\u{9b}1`, `\u202e`, `ro\u{202e}ot`, `r\u{200f}ule\r\nforged`} {
		if !strings.Contains(out, want) {
			t.Errorf("log line missing %q: %s", want, out)
		}
	}
	if strings.Count(out, "\n") != 1 {
		t.Errorf("log entry must stay one line: %q", out)
	}
}

func TestTeamsCardsEscapeRequesterFields(t *testing.T) {
	a := sampleApproval()
	a.Command = "systemctl restart nginx \u202e ; rm -rf /srv/data #\u202c \u009b31m"
	a.Host = "web\u2066"
	a.Caller = "cal\u202el"
	a.EndUser = "us\u200fer"
	a.Sudo, a.SudoUser = true, "ro\u202eot"
	a.Rule = "ru\u061cle"
	tn := NewTeamsNotifier("https://example.invalid/h", "", "")
	for name, card := range map[string]map[string]any{"adaptive": tn.buildAdaptiveCard(a), "message": tn.buildMessageCard(a)} {
		raw := fmt.Sprint(card) // every string in the card
		noRawControls(t, name, raw)
		for _, want := range []string{`u{202e}`, `u{9b}`, `u{2066}`, `u{200f}`, `u{61c}`} {
			if !strings.Contains(raw, want) {
				t.Errorf("%s card missing %q: %s", name, want, raw)
			}
		}
	}
	// Ordinary non-ASCII is unchanged.
	b := sampleApproval()
	b.Command = "echo café 日本語"
	if raw := fmt.Sprint(tn.buildAdaptiveCard(b)); !strings.Contains(raw, "echo café 日本語") {
		t.Errorf("non-ASCII altered: %s", raw)
	}
}
