package main

import (
	"net/http/httptest"
	"strings"
	"testing"
	"unicode"

	"github.com/luisgf/infrabroker/internal/signer"
)

// TestUIEscapesFormatControls pins #830: html/template does not neutralise
// Unicode format characters, so a command with a bidi override/isolate or a C1
// control reached the approver raw and a bidi-aware browser displayed the
// destructive stage reordered as a trailing comment. The list and detail pages
// must show them as visible \u{XXXX} escapes (and the other requester-controlled
// fields too), leave ordinary non-ASCII text alone, and not touch the stored
// approval.
func TestUIEscapesFormatControls(t *testing.T) {
	t.Parallel()
	s := testServer(t, "http://unused")
	cmd := "systemctl restart nginx \u202e ; rm -rf /srv/data #\u202c \u2066 \u009b31m café 日本語"
	a, err := s.registry.Create(signer.WireRequest{Host: "web\u202e01", Command: cmd, Sudo: true, SudoUser: "ro\u2066ot"},
		"bro\u200fker", &signer.DecisionInfo{MatchedRule: "require_approval:^re\u061cboot"})
	if err != nil {
		t.Fatal(err)
	}

	check := func(name, body string, wants ...string) {
		t.Helper()
		for _, r := range body {
			if r != '\n' && r != '\t' && (unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029') {
				t.Fatalf("%s emitted raw rune U+%04X", name, r)
			}
		}
		for _, want := range append([]string{`\u{202e}`, `\u{202c}`, `\u{2066}`, `\u{9b}`, `\u{200f}`, "café 日本語"}, wants...) {
			if !strings.Contains(body, want) {
				t.Errorf("%s missing %q", name, want)
			}
		}
	}

	w := httptest.NewRecorder()
	s.handleUIList(w, req(t, "GET", "/ui/approvals", "broker-admin", nil))
	check("list", w.Body.String()) // the list does not show the rule

	w = httptest.NewRecorder()
	r := req(t, "GET", "/ui/approvals/"+a.ID, "broker-admin", nil)
	r.SetPathValue("id", a.ID)
	s.handleUIDetail(w, r)
	check("detail", w.Body.String(), `\u{61c}`)

	if got, ok := s.registry.Get(a.ID); !ok || got.Command != cmd {
		t.Error("the stored approval must keep the original command")
	}
}
