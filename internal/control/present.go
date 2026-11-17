package control

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// PresentText renders requester-controlled text (a command) for a human
// approver's screen: the web UI, the Slack and Teams cards. The signer rejects
// only CR/LF in a command, so it may carry Unicode format characters (category
// Cf: bidi overrides/isolates U+202A-202E and U+2066-2069, LRM/RLM/ALM, BOM,
// ZWJ...) that a bidi-aware renderer would use to display a destructive stage
// reordered as a trailing comment (#830). Those, C1 controls and U+2028/2029
// become visible \u{XXXX} escapes, invalid UTF-8 bytes and the C0 controls
// other than newline and tab (and DEL) become \xNN, and a carriage return
// becomes \r. Newline and tab are kept: they are layout the surfaces render,
// and a faithful multi-line command stays readable. Ordinary printable text,
// including accents, CJK and emoji, is unchanged.
//
// Presentation only: the stored approval, the request forwarded to the signer
// and the JSON API are untouched, and the escaping is a faithful, visible
// rendering (nothing is hidden), so it is applied AFTER the bridge core's
// DenyOnly comparison and does not by itself make a card deny-only; the core
// does measure the escaped length against the adapter's CommandMax, because the
// escapes are what the adapter would have to fit and truncate.
func PresentText(s string) string { return present(s, false) }

// PresentLine is PresentText for a field shown on one line (host, caller, end
// user, rule, sudo user, a log line): newline and tab are escaped too, using
// the same convention as broker-ctl (\n, \r, \t).
func PresentLine(s string) string { return present(s, true) }

func present(s string, line bool) string {
	clean := utf8.ValidString(s)
	if clean {
		for _, r := range s {
			if presentEscapes(r, line) {
				clean = false
				break
			}
		}
	}
	if clean {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 16)
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case r == '\r':
			b.WriteString(`\r`)
		case (r == '\n' || r == '\t') && !line:
			b.WriteRune(r)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		case presentEscapes(r, line):
			fmt.Fprintf(&b, `\u{%x}`, r)
		default:
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}

// presentEscapes reports whether r must not reach an approver raw.
func presentEscapes(r rune, line bool) bool {
	if (r == '\n' || r == '\t') && !line {
		return false
	}
	return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029'
}
