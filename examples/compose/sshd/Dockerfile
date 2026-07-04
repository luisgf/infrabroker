# Toy SSH target for the demo: trusts the demo CA via TrustedUserCAKeys and
# accepts certificate logins as user "demo". It also carries curl so the
# docs' verification commands (mTLS curl against the broker, reading the
# audit logs) can run from inside the demo network.
FROM alpine:3.22

RUN apk add --no-cache openssh-server curl \
    && adduser -D -s /bin/sh demo \
    # adduser -D leaves the account locked ("!"); sshd refuses logins for
    # locked accounts even with certificate auth. "*" = no password, unlocked.
    && sed -i 's/^demo:!/demo:*/' /etc/shadow

# Config and host key live in the shared /demo volume (written by pki-init).
ENTRYPOINT ["/usr/sbin/sshd", "-D", "-e", "-f", "/demo/sshd/sshd_config"]
