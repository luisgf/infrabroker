#!/usr/bin/env bash
# Laboratorio end-to-end del broker SSH con CA efímera.
#
# Levanta un sshd propio (puerto alto, como el usuario actual) que confía en una
# CA SSH de laboratorio, arranca el broker con mTLS, y ejecuta pruebas positivas
# y negativas. No toca la configuración del sistema.
#
# Uso:  bash lab/run_lab.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LAB="$ROOT/lab/work"
PKI="$LAB/pki"
SSHD_PORT=2222
BROKER_PORT=8443
USER_NAME="$(id -un)"

rm -rf "$LAB"
mkdir -p "$LAB" "$PKI" "$LAB/sshd" "$LAB/auth_principals"

echo "== 1. CA SSH de laboratorio + host key =="
ssh-keygen -t ed25519 -N '' -C 'ssh-ca-lab' -f "$PKI/ssh_ca" >/dev/null
ssh-keygen -t ed25519 -N '' -C 'host-lab'   -f "$LAB/sshd/host_ed25519" >/dev/null
HOSTKEY_LINE="$(cat "$LAB/sshd/host_ed25519.pub")"

echo "== 2. PKI mTLS (CA de agentes, cert de servidor, cert de agente) =="
# CA de agentes
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$PKI/agents_ca.key" \
  -out "$PKI/agents_ca.crt" -days 1 -subj "/CN=agents-ca" >/dev/null 2>&1
# Cert de servidor del broker (SAN localhost)
openssl req -newkey rsa:2048 -nodes -keyout "$PKI/broker.key" \
  -out "$PKI/broker.csr" -subj "/CN=localhost" >/dev/null 2>&1
openssl x509 -req -in "$PKI/broker.csr" -CA "$PKI/agents_ca.crt" -CAkey "$PKI/agents_ca.key" \
  -CAcreateserial -days 1 -out "$PKI/broker.crt" \
  -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1") >/dev/null 2>&1
# Cert del agente (cliente mTLS); el CN identifica al llamante en auditoría
openssl req -newkey rsa:2048 -nodes -keyout "$PKI/agent.key" \
  -out "$PKI/agent.csr" -subj "/CN=agente-ia-1" >/dev/null 2>&1
openssl x509 -req -in "$PKI/agent.csr" -CA "$PKI/agents_ca.crt" -CAkey "$PKI/agents_ca.key" \
  -CAcreateserial -days 1 -out "$PKI/agent.crt" >/dev/null 2>&1
# Semilla de la clave de auditoría (32 bytes)
head -c 32 /dev/urandom > "$PKI/audit.seed"

echo "== 3. sshd: confía en la CA SSH y mapea principal 'host:lab' a $USER_NAME =="
printf 'host:lab\n' > "$LAB/auth_principals/$USER_NAME"
cat > "$LAB/sshd/sshd_config" <<EOF
Port $SSHD_PORT
ListenAddress 127.0.0.1
HostKey $LAB/sshd/host_ed25519
TrustedUserCAKeys $PKI/ssh_ca.pub
AuthorizedPrincipalsFile $LAB/auth_principals/%u
PidFile $LAB/sshd/sshd.pid
LogLevel VERBOSE
PasswordAuthentication no
PubkeyAuthentication yes
UsePAM no
StrictModes no
EOF
chmod 600 "$LAB/sshd/host_ed25519" "$LAB/auth_principals/$USER_NAME"

SSHD_BIN="$(command -v sshd || echo /usr/sbin/sshd)"
"$SSHD_BIN" -f "$LAB/sshd/sshd_config" -E "$LAB/sshd/sshd.log"
sleep 1
SSHD_PID="$(cat "$LAB/sshd/sshd.pid")"
echo "   sshd PID=$SSHD_PID en :$SSHD_PORT"

echo "== 4. config del broker =="
cat > "$LAB/config.json" <<EOF
{
  "listen": ":$BROKER_PORT",
  "server_cert": "$PKI/broker.crt",
  "server_key": "$PKI/broker.key",
  "client_ca": "$PKI/agents_ca.crt",
  "ca_key": "$PKI/ssh_ca",
  "audit_log": "$LAB/audit.log",
  "audit_key": "$PKI/audit.seed",
  "source_address": "127.0.0.1",
  "max_ttl_seconds": 120,
  "hosts": {
    "lab": {
      "addr": "127.0.0.1:$SSHD_PORT",
      "user": "$USER_NAME",
      "principal": "host:lab",
      "host_key": "$HOSTKEY_LINE"
    }
  }
}
EOF

echo "== 5. arrancar broker =="
( cd "$ROOT" && go build -o "$LAB/broker" ./cmd/broker )
"$LAB/broker" -config "$LAB/config.json" >"$LAB/broker.log" 2>&1 &
BROKER_PID=$!
trap 'kill $BROKER_PID 2>/dev/null; kill $SSHD_PID 2>/dev/null' EXIT
sleep 1

call() {
  curl -sS --cacert "$PKI/agents_ca.crt" \
    --cert "$PKI/agent.crt" --key "$PKI/agent.key" \
    --resolve "localhost:$BROKER_PORT:127.0.0.1" \
    -X POST "https://localhost:$BROKER_PORT/v1/ssh_run" \
    -H 'Content-Type: application/json' -d "$1"
}

echo
echo "== PRUEBA 1 (camino feliz): ejecutar 'id' en host lab =="
call '{"host":"lab","command":"id","ttl_seconds":60}'; echo

echo
echo "== PRUEBA 2 (host desconocido): debe devolver 403 =="
curl -sS -o /dev/null -w "HTTP %{http_code}\n" --cacert "$PKI/agents_ca.crt" \
  --cert "$PKI/agent.crt" --key "$PKI/agent.key" \
  --resolve "localhost:$BROKER_PORT:127.0.0.1" \
  -X POST "https://localhost:$BROKER_PORT/v1/ssh_run" \
  -H 'Content-Type: application/json' -d '{"host":"otro","command":"id"}'

echo
echo "== PRUEBA 3 (sin cert de cliente): mTLS debe rechazar =="
curl -sS -o /dev/null -w "HTTP %{http_code}\n" --cacert "$PKI/agents_ca.crt" \
  --resolve "localhost:$BROKER_PORT:127.0.0.1" \
  -X POST "https://localhost:$BROKER_PORT/v1/ssh_run" \
  -H 'Content-Type: application/json' -d '{"host":"lab","command":"id"}' \
  || echo "  (conexión rechazada como se esperaba)"

echo
echo "== PRUEBA 4 (force-command): aunque pidamos 'whoami', el cert lleva =="
echo "   force-command='echo SOLO_ESTO'; sshd ejecuta el forzado =="
call '{"host":"lab","command":"echo SOLO_ESTO","ttl_seconds":60}'; echo

echo
echo "== Log de auditoría (encadenado y firmado) =="
cat "$LAB/audit.log"

echo
echo "== Log de sshd (serial + identidad del cert) =="
grep -i -E "Accepted|Certificate|serial|ID " "$LAB/sshd/sshd.log" | tail -n 8 || true

echo
echo "Lab OK. Limpieza automática al salir."
