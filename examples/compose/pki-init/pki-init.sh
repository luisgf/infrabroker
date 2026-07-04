#!/bin/sh
# Provision the infrabroker demo volume (/demo): SSH CA, demo sshd material,
# mTLS PKI (signer<->broker and agent->broker) and the three service configs.
# Idempotent: a marker file makes repeated `compose up` runs a no-op, so the
# pinned host key and issued material stay stable until `compose down -v`.
#
# Ownership model (the trap of this demo): this container runs as root, but
# signer/broker run as distroless nonroot (uid 65532) and the sshd container
# runs as root. OpenSSH's default StrictModes then requires the host key to be
# owned by root and not group/world-writable, so PKI/state/configs are chowned
# to 65532 while everything under /demo/sshd stays root-owned 0600.
set -eu

DEMO=/demo
MARKER="$DEMO/.provisioned"

if [ -f "$MARKER" ]; then
    echo "pki-init: $MARKER exists, nothing to do"
    exit 0
fi

mkdir -p "$DEMO/pki" "$DEMO/sshd" "$DEMO/state"

echo "== 1. SSH CA + demo host key + sshd config =="
ssh-keygen -t ed25519 -N '' -C infrabroker-demo-ca -f "$DEMO/pki/ssh_ca" >/dev/null
ssh-keygen -t ed25519 -N '' -f "$DEMO/sshd/host" >/dev/null
printf 'host:demo\n' > "$DEMO/sshd/principals"

cat > "$DEMO/sshd/sshd_config" <<EOF
Port 22
ListenAddress 0.0.0.0
HostKey $DEMO/sshd/host
TrustedUserCAKeys $DEMO/pki/ssh_ca.pub
AuthorizedPrincipalsFile $DEMO/sshd/principals
PasswordAuthentication no
KbdInteractiveAuthentication no
AllowUsers demo
LogLevel VERBOSE
EOF

echo "== 2. mTLS PKI (SANs are compose service names) =="
P="$DEMO/pki"
san() { printf "subjectAltName=DNS:%s" "$1" > /tmp/san.cnf; }

# signer server CA + cert (validates the signer towards the broker)
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$P/signer_ca.key" \
    -out "$P/signer_ca.crt" -days 7 -subj "/CN=demo-signer-ca" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout "$P/signer.key" \
    -out /tmp/signer.csr -subj "/CN=signer" 2>/dev/null
san signer
openssl x509 -req -in /tmp/signer.csr -CA "$P/signer_ca.crt" \
    -CAkey "$P/signer_ca.key" -CAcreateserial -days 7 \
    -out "$P/signer.crt" -extfile /tmp/san.cnf 2>/dev/null

# brokers CA + broker client cert (CN=broker-1 identifies the broker to the signer)
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$P/brokers_ca.key" \
    -out "$P/brokers_ca.crt" -days 7 -subj "/CN=demo-brokers-ca" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout "$P/broker_client.key" \
    -out /tmp/broker_client.csr -subj "/CN=broker-1" 2>/dev/null
openssl x509 -req -in /tmp/broker_client.csr -CA "$P/brokers_ca.crt" \
    -CAkey "$P/brokers_ca.key" -CAcreateserial -days 7 \
    -out "$P/broker_client.crt" 2>/dev/null

# agents CA + broker HTTP server cert + demo agent client cert
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$P/agents_ca.key" \
    -out "$P/agents_ca.crt" -days 7 -subj "/CN=demo-agents-ca" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout "$P/broker_server.key" \
    -out /tmp/broker_server.csr -subj "/CN=broker" 2>/dev/null
san broker
openssl x509 -req -in /tmp/broker_server.csr -CA "$P/agents_ca.crt" \
    -CAkey "$P/agents_ca.key" -CAcreateserial -days 7 \
    -out "$P/broker_server.crt" -extfile /tmp/san.cnf 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout "$P/agent.key" \
    -out /tmp/agent.csr -subj "/CN=demo-agent" 2>/dev/null
openssl x509 -req -in /tmp/agent.csr -CA "$P/agents_ca.crt" \
    -CAkey "$P/agents_ca.key" -CAcreateserial -days 7 \
    -out "$P/agent.crt" 2>/dev/null

echo "== 3. audit seeds + service configs =="
head -c 32 /dev/urandom > "$DEMO/state/signer_audit.seed"
head -c 32 /dev/urandom > "$DEMO/state/broker_audit.seed"
head -c 32 /dev/urandom > "$DEMO/state/mcp_audit.seed"

HOST_PUB="$(cat "$DEMO/sshd/host.pub")"

# Signer: CA custody + policy, and the single source of truth for hosts —
# in remote mode the broker takes its host table from GET /v1/hosts, so the
# full definition (addr, user, host_key) lives here. Only broker-1 may
# request certs for "demo". No source_address pin: container IPs are
# dynamic in the demo network.
cat > "$DEMO/signer.json" <<EOF
{
  "listen": ":9443",
  "server_cert": "$P/signer.crt",
  "server_key": "$P/signer.key",
  "client_ca": "$P/brokers_ca.crt",
  "ca_key": "$P/ssh_ca",
  "audit_log": "$DEMO/state/signer_audit.log",
  "audit_key": "$DEMO/state/signer_audit.seed",
  "monitor_listen": "0.0.0.0:9160",
  "max_ttl_seconds": 120,
  "hosts": {
    "demo": {
      "addr": "sshd:22",
      "user": "demo",
      "host_key": "$HOST_PUB",
      "principal": "host:demo",
      "max_ttl_seconds": 120,
      "allowed_callers": ["broker-1"]
    }
  }
}
EOF

# Broker (HTTP+mTLS frontend): no ca_key and no hosts — remote signing, and
# the host table comes from the signer.
cat > "$DEMO/broker.json" <<EOF
{
  "listen": ":8443",
  "server_cert": "$P/broker_server.crt",
  "server_key": "$P/broker_server.key",
  "client_ca": "$P/agents_ca.crt",
  "audit_log": "$DEMO/state/broker_audit.log",
  "audit_key": "$DEMO/state/broker_audit.seed",
  "monitor_listen": "0.0.0.0:9180",
  "max_ttl_seconds": 120,
  "signer": {
    "url": "https://signer:9443",
    "client_cert": "$P/broker_client.crt",
    "client_key": "$P/broker_client.key",
    "ca": "$P/signer_ca.crt"
  }
}
EOF

# stdio MCP config (for `docker run -i ... mcp-broker` joined to this network).
cat > "$DEMO/mcp.json" <<EOF
{
  "audit_log": "$DEMO/state/mcp_audit.log",
  "audit_key": "$DEMO/state/mcp_audit.seed",
  "max_ttl_seconds": 120,
  "signer": {
    "url": "https://signer:9443",
    "client_cert": "$P/broker_client.crt",
    "client_key": "$P/broker_client.key",
    "ca": "$P/signer_ca.crt"
  }
}
EOF

echo "== 4. ownership: 65532 (distroless nonroot) except sshd material =="
chown -R 65532:65532 "$DEMO/pki" "$DEMO/state" \
    "$DEMO/signer.json" "$DEMO/broker.json" "$DEMO/mcp.json"
chmod 600 "$P"/*.key "$P/ssh_ca" "$DEMO/state/"*.seed
chmod 644 "$P"/*.crt "$P/ssh_ca.pub"
chown root:root "$DEMO/sshd" "$DEMO/sshd/host" "$DEMO/sshd/host.pub" \
    "$DEMO/sshd/principals" "$DEMO/sshd/sshd_config"
chmod 600 "$DEMO/sshd/host"
chmod 644 "$DEMO/sshd/host.pub" "$DEMO/sshd/principals" "$DEMO/sshd/sshd_config"

touch "$MARKER"
echo "pki-init: demo volume provisioned"
