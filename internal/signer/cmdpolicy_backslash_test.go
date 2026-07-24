package signer

import (
	"strings"
	"testing"
)

// TestCommandPolicyRejectsUnquotedBackslash is the regression for the last
// decode gap in the command-policy bypass class (#308, sibling of #277's
// quoting/encoding and GHSA-937v-rmqp-j3hx's glob/brace/tilde): the signer
// decided the policy on a form in which an UNQUOTED backslash was kept LITERAL,
// while the target host's `$SHELL -c` (and the sealed-exec shim) consume it as
// an escape. An obfuscated command therefore dodged a deny / require_approval
// rule the executed command would hit — "r\m -rf /srv/data" decodes to the
// policy string `r\m -rf /srv/data` but the shell runs `rm -rf /srv/data`.
// With shell_parse on (the default) such words are now rejected fail-closed.
// Quoted backslashes decode exactly as the shell decodes them and must keep
// working.
func TestCommandPolicyRejectsUnquotedBackslash(t *testing.T) {
	t.Parallel()

	deny := PolicySet{{Mode: CmdPolicyDenylist, Deny: []string{`(^|/)rm(\s|$)`, `/etc/shadow`, `(^|/)reboot(\s|$)`}}}

	denied := func(cmd, why string) {
		t.Helper()
		if allowed, _, _, err := deny.Decide(cmd); allowed && err == nil {
			t.Errorf("%s: %q must be blocked, was ALLOWED", why, cmd)
		}
	}
	allowed := func(cmd string) {
		t.Helper()
		if a, _, _, err := deny.Decide(cmd); !a || err != nil {
			t.Errorf("legitimate command %q must be allowed, got allowed=%v err=%v", cmd, a, err)
		}
	}

	// The literal forms are (and stay) denied by their rules.
	denied(`/bin/rm -rf /srv/data`, "literal rm")
	denied(`cat /etc/shadow`, "literal shadow")

	// The backslash-obfuscated forms must no longer slip through: every one of
	// these reaches the denied command once the target shell strips the escape.
	denied(`r\m -rf /srv/data`, `r\m dodges the rm deny`)
	denied(`\rm -rf /srv/data`, `leading backslash dodges the rm deny`)
	denied(`/bin/r\m -rf /srv/data`, `path-qualified r\m dodges the rm deny`)
	denied(`cat /etc/sha\dow`, `sha\dow dodges the /etc/shadow deny`)
	denied(`/sbin/rebo\ot`, `rebo\ot dodges the reboot deny`)

	// Legitimate literal commands are unaffected.
	allowed("uptime")
	allowed("systemctl restart nginx.service")
	allowed("cat /etc/hosts")

	// A QUOTED backslash is decoded by expand.Literal exactly as the target shell
	// decodes it, so it must not be over-rejected. Control cases, verified against
	// the pinned mvdan.cc/sh: '...' and "..." keep `a\b`, "a\$b" becomes `a$b`,
	// $'a\tb' becomes a real tab, and a"\\"b becomes `a\b`.
	allowed(`echo 'a\b'`)
	allowed(`echo "a\b"`)
	allowed(`echo "a\$b"`)
	allowed(`echo $'a\tb'`)
	allowed(`echo a"\\"b`)

	// require_approval is bypassable by exactly the same trick, so it must be
	// closed too: the gate exists to put a human in front of the command.
	appr := PolicySet{{Mode: CmdPolicyDenylist, RequireApproval: []string{`(^|/)systemctl\s+restart`}}}
	if _, needs, _, err := appr.Decide("systemctl restart nginx"); !needs || err != nil {
		t.Fatalf("literal command must require approval, got needs=%v err=%v", needs, err)
	}
	a, needs, _, err := appr.Decide(`systemctl\ restart nginx`)
	if a && !needs && err == nil {
		t.Error(`require_approval: "systemctl\ restart nginx" must not run unapproved`)
	}

	// Allowlist mode stays fail-closed: a backslash form never matched a literal
	// allow rule, and it must not become an error-free allow either.
	allow := PolicySet{{Mode: CmdPolicyAllowlist, Allow: []string{`^cat /etc/hosts$`}}}
	if a, _, _, err := allow.Decide(`cat /etc/host\s`); a && err == nil {
		t.Error("allowlist: a backslash-escaped command must not be allowed")
	}
	if a, _, _, err := allow.Decide("cat /etc/hosts"); !a || err != nil {
		t.Errorf("allowlist: the exact allowed command must pass, got allowed=%v err=%v", a, err)
	}
}

// TestUnquotedBackslashErrorIsActionable checks the rejection explains what to
// do: an operator hitting it on a legitimate command needs to know that quoting
// the word is the fix, not that "the command was denied".
func TestUnquotedBackslashErrorIsActionable(t *testing.T) {
	t.Parallel()

	_, err := extractCommands(`touch a\ b`)
	if err == nil {
		t.Fatal("an unquoted backslash escape must be rejected")
	}
	if !strings.Contains(err.Error(), "unquoted backslash") || !strings.Contains(err.Error(), "quote it") {
		t.Errorf("error must name the cause and the remedy, got: %v", err)
	}
}
