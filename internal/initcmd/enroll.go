package initcmd

import "fmt"

// enrollSnippet returns copy-paste shell to enrol a managed host's sshd: trust
// the generated SSH CA and map the certificate principal to a login account. Run
// once per managed host. caPub is the contents of pki/ssh_ca.pub (it already ends
// in a newline).
func enrollSnippet(caPub []byte, user, principal string) string {
	return fmt.Sprintf(`# On each managed host (as root): trust the infrabroker SSH CA and map the
# certificate principal to the login account.

sudo tee /etc/ssh/infrabroker_ca.pub >/dev/null <<'CAKEY'
%sCAKEY

sudo install -d -m 755 /etc/ssh/auth_principals
echo %s | sudo tee /etc/ssh/auth_principals/%s >/dev/null

# Add to /etc/ssh/sshd_config (or a drop-in under sshd_config.d/) and reload sshd:
#   TrustedUserCAKeys /etc/ssh/infrabroker_ca.pub
#   AuthorizedPrincipalsFile /etc/ssh/auth_principals/%%u
#   LogLevel VERBOSE
# The login account (%s) must exist on the host; for sudo access add a NOPASSWD
# sudoers entry (e.g. "%s ALL=(root) NOPASSWD: ALL").
`, caPub, principal, user, user, user)
}
