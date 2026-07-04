# One-shot provisioner for the demo: generates the SSH CA, the mTLS PKI and
# the service configs into the shared /demo volume, then exits.
FROM alpine:3.22

RUN apk add --no-cache openssh-keygen openssl

COPY pki-init.sh /usr/local/bin/pki-init.sh
RUN chmod 0755 /usr/local/bin/pki-init.sh

ENTRYPOINT ["/usr/local/bin/pki-init.sh"]
