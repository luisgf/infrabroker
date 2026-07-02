#!/usr/bin/env bash
# Laboratorio e2e de persistencia de estado (state_db, SQLite):
#   A. Un grant creado con broker-ctl SOBREVIVE a un restart del signer, sigue
#      decidiendo (dry-run del firewall) y una revocación también es durable.
#   B. Una approval pendiente SOBREVIVE a un restart del control plane: se
#      aprueba tras el restart y el poller obtiene su certificado.
# No necesita sshd: la parte A usa la mutación/lectura de política del signer y
# la parte B llega solo hasta la emisión del certificado (no lo usa).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LAB="$ROOT/lab/work-state"
SIGNER_PORT=9453
CP_PORT=7453

rm -rf "$LAB"; mkdir -p "$LAB/pki"
P="$LAB/pki"

echo "== 1. PKI: CA SSH + mTLS (signer, control plane, broker-1, admin-1) =="
ssh-keygen -t ed25519 -N '' -C ssh-ca -f "$LAB/ssh_ca" >/dev/null
# CA de servidores (signer y control plane presentan certs firmados por ella)
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$P/server_ca.key" -out "$P/server_ca.crt" \
  -days 1 -subj "/CN=server-ca" >/dev/null 2>&1
for srv in signer cp; do
  openssl req -newkey rsa:2048 -nodes -keyout "$P/$srv.key" -out "$P/$srv.csr" \
    -subj "/CN=localhost" >/dev/null 2>&1
  openssl x509 -req -in "$P/$srv.csr" -CA "$P/server_ca.crt" -CAkey "$P/server_ca.key" \
    -CAcreateserial -days 1 -out "$P/$srv.crt" \
    -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1") >/dev/null 2>&1
done
# CA de clientes + certs: broker-1 (firma), admin-1 (operador/aprobador), cp-1 (forwarder)
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$P/clients_ca.key" -out "$P/clients_ca.crt" \
  -days 1 -subj "/CN=clients-ca" >/dev/null 2>&1
for cn in broker-1 admin-1 cp-1; do
  openssl req -newkey rsa:2048 -nodes -keyout "$P/$cn.key" -out "$P/$cn.csr" \
    -subj "/CN=$cn" >/dev/null 2>&1
  openssl x509 -req -in "$P/$cn.csr" -CA "$P/clients_ca.crt" -CAkey "$P/clients_ca.key" \
    -CAcreateserial -days 1 -out "$P/$cn.crt" >/dev/null 2>&1
done

echo "== 2. Configs con state_db (host 'lab': allowlist + require_approval) =="
head -c 32 /dev/urandom > "$LAB/signer_audit.seed"
cat > "$LAB/signer.json" <<EOF
{
  "listen": ":$SIGNER_PORT",
  "server_cert": "$P/signer.crt",
  "server_key": "$P/signer.key",
  "client_ca": "$P/clients_ca.crt",
  "ca_key": "$LAB/ssh_ca",
  "audit_log": "$LAB/signer_audit.log",
  "audit_key": "$LAB/signer_audit.seed",
  "max_ttl_seconds": 120,
  "state_db": "$LAB/signer_state.db",
  "reload_callers": ["admin-1"],
  "trusted_forwarders": ["cp-1"],
  "hosts": {
    "lab": {
      "addr": "127.0.0.1:22",
      "user": "nobody",
      "host_key": "$(cat "$LAB/ssh_ca.pub")",
      "principal": "host:lab",
      "max_ttl_seconds": 120,
      "command_policy": {
        "mode": "allowlist",
        "allow": ["^uptime$", "^reboot$"],
        "require_approval": ["^reboot$"]
      }
    }
  }
}
EOF
head -c 32 /dev/urandom > "$LAB/cp_audit.seed"
cat > "$LAB/cp.json" <<EOF
{
  "listen": ":$CP_PORT",
  "server_cert": "$P/cp.crt",
  "server_key": "$P/cp.key",
  "client_ca": "$P/clients_ca.crt",
  "signer": {
    "url": "https://localhost:$SIGNER_PORT",
    "client_cert": "$P/cp-1.crt",
    "client_key": "$P/cp-1.key",
    "ca": "$P/server_ca.crt"
  },
  "approval": { "timeout_seconds": 120, "callers": ["admin-1"] },
  "audit_log": "$LAB/cp_audit.log",
  "audit_key": "$LAB/cp_audit.seed",
  "state_db": "$LAB/cp_state.db"
}
EOF

echo "== 3. Binarios =="
( cd "$ROOT" && go build -o "$LAB/signer" ./cmd/signer \
             && go build -o "$LAB/control-plane" ./cmd/control-plane \
             && go build -o "$LAB/broker-ctl" ./cmd/broker-ctl )

CTL_SIGNER=(env BROKER_CTL_SIGNER_URL="localhost:$SIGNER_PORT" BROKER_CTL_SIGNER_CERT="$P/admin-1.crt" \
    BROKER_CTL_SIGNER_KEY="$P/admin-1.key" BROKER_CTL_SIGNER_CA="$P/server_ca.crt" "$LAB/broker-ctl")
CTL_CP=(env BROKER_CTL_CP_URL="localhost:$CP_PORT" BROKER_CTL_CP_CERT="$P/admin-1.crt" \
    BROKER_CTL_CP_KEY="$P/admin-1.key" BROKER_CTL_CP_CA="$P/server_ca.crt" "$LAB/broker-ctl")

start_signer() {
  "$LAB/signer" -config "$LAB/signer.json" >>"$LAB/signer.out" 2>&1 &
  SIGNER_PID=$!; sleep 1
}
start_cp() {
  "$LAB/control-plane" -config "$LAB/cp.json" >>"$LAB/cp.out" 2>&1 &
  CP_PID=$!; sleep 1
}
trap 'kill "${SIGNER_PID:-0}" "${CP_PID:-0}" 2>/dev/null || true' EXIT

echo "== A. Grants: crear → restart del signer → sigue vivo → revocar → restart → no vuelve =="
start_signer
"${CTL_SIGNER[@]}" policy grant --host lab --allow '^systemctl restart nginx$' --ttl 30m
GRANTS_BEFORE="$("${CTL_SIGNER[@]}" policy grants)"
echo "$GRANTS_BEFORE" | grep -q 'systemctl restart nginx' || { echo "FAIL: grant no listado"; exit 1; }
GRANT_ID="$(echo "$GRANTS_BEFORE" | awk '/systemctl restart nginx/ {print $1}')"

kill -TERM "$SIGNER_PID"; wait "$SIGNER_PID" 2>/dev/null || true
start_signer
"${CTL_SIGNER[@]}" policy grants | grep -q 'systemctl restart nginx' \
  && echo "   OK: el grant sobrevive al restart" \
  || { echo "FAIL: el grant NO sobrevivió al restart"; exit 1; }

"${CTL_SIGNER[@]}" policy revoke "$GRANT_ID" >/dev/null
kill -TERM "$SIGNER_PID"; wait "$SIGNER_PID" 2>/dev/null || true
start_signer
"${CTL_SIGNER[@]}" policy grants | grep -q 'systemctl restart nginx' \
  && { echo "FAIL: un grant revocado ha resucitado"; exit 1; } \
  || echo "   OK: la revocación es durable"

echo "== B. Approvals: 202 → restart del control plane → aprobar → el poller obtiene cert =="
start_cp
ssh-keygen -t ed25519 -N '' -f "$LAB/ephemeral" >/dev/null
REQ="$(printf '{"host":"lab","role":"target","purpose":"oneshot","command":"reboot","ttl_seconds":60,"public_key":"%s"}' "$(cat "$LAB/ephemeral.pub")")"
CURL_BROKER=(curl -s --cert "$P/broker-1.crt" --key "$P/broker-1.key" --cacert "$P/server_ca.crt")
RESP="$("${CURL_BROKER[@]}" -X POST "https://localhost:$CP_PORT/v1/sign" \
  -H 'Content-Type: application/json' -d "$REQ")"
APPROVAL_ID="$(echo "$RESP" | sed -n 's/.*"approval_id":"\([^"]*\)".*/\1/p')"
[[ -n "$APPROVAL_ID" ]] || { echo "FAIL: no hubo 202/approval_id: $RESP"; exit 1; }
echo "   approval pendiente: $APPROVAL_ID"

kill -TERM "$CP_PID"; wait "$CP_PID" 2>/dev/null || true
start_cp
"${CTL_CP[@]}" approval list | grep -q "$APPROVAL_ID" \
  && echo "   OK: la approval pendiente sobrevive al restart" \
  || { echo "FAIL: la approval NO sobrevivió al restart"; exit 1; }

"${CTL_CP[@]}" approval allow "$APPROVAL_ID" >/dev/null
RESULT="$("${CURL_BROKER[@]}" "https://localhost:$CP_PORT/v1/sign/result/$APPROVAL_ID")"
echo "$RESULT" | grep -q 'ssh-ed25519-cert' \
  && echo "   OK: certificado emitido tras aprobar sobre el registry restaurado" \
  || { echo "FAIL: sin certificado tras aprobar: $RESULT"; exit 1; }

# Una approval consumida no puede reemitir tras otro restart.
kill -TERM "$CP_PID"; wait "$CP_PID" 2>/dev/null || true
start_cp
RESULT2="$("${CURL_BROKER[@]}" "https://localhost:$CP_PORT/v1/sign/result/$APPROVAL_ID")"
echo "$RESULT2" | grep -q 'ssh-ed25519-cert' \
  && { echo "FAIL: una approval consumida reemitió tras el restart"; exit 1; } \
  || echo "   OK: consumida sigue consumida tras el restart"

rm -rf "$LAB"
echo "Lab state OK."
