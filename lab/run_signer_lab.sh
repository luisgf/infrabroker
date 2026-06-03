#!/usr/bin/env bash
# Laboratorio e2e de la variante B: servicio de firma externo con política.
# El broker arranca SIN clave de CA; pide certs al servicio (mTLS). Verifica:
#   1. ssh_execute/sesiones funcionan con cert emitido en remoto.
#   2. el servicio impone política: un host no autorizado al broker es DENEGADO.
#   3. doble auditoría correlada (emisión en el servicio + ejecución en el broker).
#   4. el broker no tiene ca_key en su config.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LAB="$ROOT/lab/work-signer"
USER_NAME="$(id -un)"
SSHD_PORT=2227
SIGNER_PORT=9443

rm -rf "$LAB"; mkdir -p "$LAB/sshd" "$LAB/pki"

echo "== 1. CA SSH + host key + sshd que confía en la CA =="
ssh-keygen -t ed25519 -N '' -C ssh-ca -f "$LAB/ssh_ca" >/dev/null
ssh-keygen -t ed25519 -N '' -f "$LAB/sshd/host" >/dev/null
printf 'host:lab\n' > "$LAB/sshd/principals"
chmod 600 "$LAB/sshd/host" "$LAB/sshd/principals"
cat > "$LAB/sshd/sshd_config" <<EOF
Port $SSHD_PORT
ListenAddress 127.0.0.1
HostKey $LAB/sshd/host
TrustedUserCAKeys $LAB/ssh_ca.pub
AuthorizedPrincipalsFile $LAB/sshd/principals
PidFile $LAB/sshd/sshd.pid
LogLevel VERBOSE
PasswordAuthentication no
UsePAM no
StrictModes no
EOF
"$(command -v sshd || echo /usr/sbin/sshd)" -f "$LAB/sshd/sshd_config" -E "$LAB/sshd/sshd.log"
sleep 1
SSHD_PID="$(cat "$LAB/sshd/sshd.pid")"

echo "== 2. PKI mTLS broker<->signer (RSA) =="
P="$LAB/pki"
# CA del servidor de firma (valida al signer ante el broker)
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$P/signer_ca.key" -out "$P/signer_ca.crt" \
  -days 1 -subj "/CN=signer-ca" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -keyout "$P/signer.key" -out "$P/signer.csr" \
  -subj "/CN=localhost" >/dev/null 2>&1
openssl x509 -req -in "$P/signer.csr" -CA "$P/signer_ca.crt" -CAkey "$P/signer_ca.key" \
  -CAcreateserial -days 1 -out "$P/signer.crt" \
  -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1") >/dev/null 2>&1
# CA de brokers (valida a los brokers ante el signer) + cert de broker CN=broker-1
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$P/brokers_ca.key" -out "$P/brokers_ca.crt" \
  -days 1 -subj "/CN=brokers-ca" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -keyout "$P/broker.key" -out "$P/broker.csr" \
  -subj "/CN=broker-1" >/dev/null 2>&1
openssl x509 -req -in "$P/broker.csr" -CA "$P/brokers_ca.crt" -CAkey "$P/brokers_ca.key" \
  -CAcreateserial -days 1 -out "$P/broker.crt" >/dev/null 2>&1

echo "== 3. config del SIGNER (custodia CA + política; lab autoriza solo a broker-1 en 'lab') =="
head -c 32 /dev/urandom > "$LAB/signer_audit.seed"
cat > "$LAB/signer.json" <<EOF
{
  "listen": ":$SIGNER_PORT",
  "server_cert": "$P/signer.crt",
  "server_key": "$P/signer.key",
  "client_ca": "$P/brokers_ca.crt",
  "ca_key": "$LAB/ssh_ca",
  "audit_log": "$LAB/signer_audit.log",
  "audit_key": "$LAB/signer_audit.seed",
  "max_ttl_seconds": 120,
  "hosts": {
    "lab": {
      "principal": "host:lab",
      "source_address": "127.0.0.1",
      "max_ttl_seconds": 120,
      "allowed_callers": ["broker-1"]
    }
  }
}
EOF

echo "== 4. config del BROKER (SIN ca_key; solo conexión + bloque signer) =="
head -c 32 /dev/urandom > "$LAB/broker_audit.seed"
cat > "$LAB/broker.json" <<EOF
{
  "audit_log": "$LAB/broker_audit.log",
  "audit_key": "$LAB/broker_audit.seed",
  "max_ttl_seconds": 120,
  "signer": {
    "url": "https://localhost:$SIGNER_PORT",
    "client_cert": "$P/broker.crt",
    "client_key": "$P/broker.key",
    "ca": "$P/signer_ca.crt"
  },
  "hosts": {
    "lab":    { "addr": "127.0.0.1:$SSHD_PORT", "user": "$USER_NAME", "host_key": "$(cat "$LAB/sshd/host.pub")" },
    "secret": { "addr": "127.0.0.1:$SSHD_PORT", "user": "$USER_NAME", "host_key": "$(cat "$LAB/sshd/host.pub")" }
  }
}
EOF

echo "   ¿broker.json contiene ca_key?  -> $(grep -c ca_key "$LAB/broker.json") (esperado 0)"

echo "== 5. arrancar signer + ejecutar escenario MCP (target=lab, denegado=secret) =="
( cd "$ROOT" && go build -o "$LAB/signer" ./cmd/signer && go build -o "$LAB/mcp-broker" ./cmd/mcp-broker )
"$LAB/signer" -config "$LAB/signer.json" >"$LAB/signer.out" 2>&1 &
SIGNER_PID=$!
trap 'kill "$SSHD_PID" "$SIGNER_PID" 2>/dev/null || true' EXIT
sleep 1
( cd "$ROOT" && go run ./lab/mcpclient "$LAB/mcp-broker" "$LAB/broker.json" lab secret )

echo
echo "== 6. auditoría de EMISIÓN (servicio de firma) =="
cat "$LAB/signer_audit.log"
echo
echo "== 7. auditoría de EJECUCIÓN (broker) =="
cat "$LAB/broker_audit.log"
echo
echo "== 8. sshd: certs aceptados =="
grep -E "Accepted certificate" "$LAB/sshd/sshd.log" | sed 's/^/   /' || true

rm -rf "$LAB"
echo "Lab signer OK."
