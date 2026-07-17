package signer

import "testing"

// TestCommandPolicyRejectsShellExpansion is the regression for the command-policy
// bypass (GHSA / CodeQL go/command-injection): the signer decided the policy on a
// glob/brace/tilde-LITERAL form while the target shell (`$SHELL -c`) expands those
// metacharacters at exec time, so an obfuscated command dodged a deny /
// require_approval rule the executed command would hit — e.g. "/bin/r[m] -rf x"
// globs back to "/bin/rm -rf x", "cat /etc/{a,shadow}" brace-expands to read
// /etc/shadow. With shell_parse on (the default) such words are now rejected
// fail-closed. Quoted metacharacters do NOT expand and must still be allowed.
func TestCommandPolicyRejectsShellExpansion(t *testing.T) {
	t.Parallel()

	deny := PolicySet{{Mode: CmdPolicyDenylist, Deny: []string{`(^|/)rm(\s|$)`, `/etc/shadow`, `/root/`, `(^|/)reboot(\s|$)`}}}

	denied := func(cmd, why string) {
		if allowed, _, _, err := deny.Decide(cmd); allowed && err == nil {
			t.Errorf("%s: %q must be blocked, was ALLOWED", why, cmd)
		}
	}
	allowed := func(cmd string) {
		if a, _, _, err := deny.Decide(cmd); !a || err != nil {
			t.Errorf("legitimate command %q must be allowed, got allowed=%v err=%v", cmd, a, err)
		}
	}

	// The literal forms are (and stay) denied by their rules.
	denied("/bin/rm -rf /srv/data", "literal rm")
	denied("cat /etc/shadow", "literal shadow")

	// The obfuscated forms must no longer slip through: char-class and ? globbing,
	// brace expansion, and tilde expansion all reach the same command at runtime.
	denied("/bin/r[m] -rf /srv/data", "char-class glob dodges rm deny")
	denied("/sbin/reboo?", "? glob dodges reboot approval/deny")
	denied("/bin/rm* -rf /x", "* glob")
	denied("cat /etc/{passwd,shadow}", "brace dodges shadow deny")
	denied("cat /roo{t,}/secret", "brace dodges /root/ deny")
	denied("cat ~/.ssh/id_rsa", "tilde expands to home")
	denied("cat ~root/.ssh/id_rsa", "tilde-user")

	// Legitimate literal commands are unaffected.
	allowed("uptime")
	allowed("systemctl status nginx")
	allowed("cat /etc/hosts")

	// A QUOTED metacharacter does not expand on the remote shell, so it must not
	// be over-rejected: the quotes are decoded away and the literal is matched.
	allowed("cat '/etc/[x]'")
	allowed(`echo "a*b"`)
	allowed("echo '~notahome'")

	// Allowlist mode stays fail-closed: a glob that does not match an allow rule
	// literally is denied (it never had a way in), and one that tries to sneak a
	// metacharacter past a literal allow is rejected too.
	allow := PolicySet{{Mode: CmdPolicyAllowlist, Allow: []string{`^cat /etc/hosts$`}}}
	if a, _, _, err := allow.Decide("cat /et[c]/hosts"); a && err == nil {
		t.Error("allowlist: a glob command must not be allowed")
	}
	if a, _, _, err := allow.Decide("cat /etc/hosts"); !a || err != nil {
		t.Errorf("allowlist: the exact allowed command must pass, got allowed=%v err=%v", a, err)
	}
}
