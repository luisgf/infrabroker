#!/usr/bin/env bash
# Laboratorio e2e del broker MCP con ProxyJump + sesiones.
# Levanta DOS sshd locales: bastión (:2225) y destino (:2226), ambos confiando en
# la CA. El host "target" se alcanza vía "bastion" (Jump). Verifica:
#   1. ssh_execute one-shot a través del bastión.
#   2. sesión exec: dos comandos reutilizan UNA conexión (un solo cert aceptado).
#   3. sesión shell: estado persiste (cd /tmp -> pwd).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LAB="$ROOT/lab/work-mcp"
USER_NAME="$(id -un)"
B_PORT=2225  # bastión
T_PORT=2226  # destino

rm -rf "$LAB"; mkdir -p "$LAB/b" "$LAB/t"

echo "== 1. CA + host keys + principals =="
ssh-keygen -t ed25519 -N '' -C ca -f "$LAB/ssh_ca" >/dev/null
ssh-keygen -t ed25519 -N '' -f "$LAB/b/host" >/dev/null
ssh-keygen -t ed25519 -N '' -f "$LAB/t/host" >/dev/null
printf 'host:bastion\n' > "$LAB/b/principals"
printf 'host:target\n'  > "$LAB/t/principals"
chmod 600 "$LAB/b/host" "$LAB/t/host" "$LAB/b/principals" "$LAB/t/principals"

mksshd() {  # $1=dir $2=port  (bastión permite forwarding por defecto)
  cat > "$1/sshd_config" <<EOF
Port $2
ListenAddress 127.0.0.1
HostKey $1/host
TrustedUserCAKeys $LAB/ssh_ca.pub
AuthorizedPrincipalsFile $1/principals
PidFile $1/sshd.pid
LogLevel VERBOSE
PasswordAuthentication no
UsePAM no
StrictModes no
EOF
  "$(command -v sshd || echo /usr/sbin/sshd)" -f "$1/sshd_config" -E "$1/sshd.log"
}

echo "== 2. arrancar bastión y destino =="
mksshd "$LAB/b" "$B_PORT"; mksshd "$LAB/t" "$T_PORT"; sleep 1
B_PID="$(cat "$LAB/b/sshd.pid")"; T_PID="$(cat "$LAB/t/sshd.pid")"
trap 'kill "$B_PID" "$T_PID" 2>/dev/null || true' EXIT

echo "== 3. config del broker (target con Jump=bastion) =="
head -c 32 /dev/urandom > "$LAB/audit.seed"
cat > "$LAB/config.json" <<EOF
{
  "ca_key": "$LAB/ssh_ca",
  "audit_log": "$LAB/audit.log",
  "audit_key": "$LAB/audit.seed",
  "source_address": "127.0.0.1",
  "max_ttl_seconds": 120,
  "session_idle_seconds": 120,
  "session_max_seconds": 600,
  "hosts": {
    "bastion": {
      "addr": "127.0.0.1:$B_PORT", "user": "$USER_NAME",
      "principal": "host:bastion", "host_key": "$(cat "$LAB/b/host.pub")"
    },
    "target": {
      "addr": "127.0.0.1:$T_PORT", "user": "$USER_NAME",
      "principal": "host:target", "host_key": "$(cat "$LAB/t/host.pub")",
      "jump": "bastion", "source_address": "127.0.0.1"
    }
  }
}
EOF

echo "== 4. compilar y ejecutar escenario MCP =="
( cd "$ROOT" && go build -o "$LAB/mcp-broker" ./cmd/mcp-broker )
( cd "$ROOT" && go run ./lab/mcpclient "$LAB/mcp-broker" "$LAB/config.json" target )

echo
echo "== 5. auditoría (firmada) =="
cat "$LAB/audit.log"

echo
echo "== 6. bastión: ¿abrió canal direct-tcpip al destino? =="
grep -iE "direct-tcpip|forwarding|Accepted" "$LAB/b/sshd.log" | tail -4 | sed 's/^/   /' || true

echo
echo "== 7. destino: certs aceptados (cada session_open = 1 cert) =="
grep -E "Accepted certificate" "$LAB/t/sshd.log" | sed 's/^/   /' || true

rm -rf "$LAB"
echo "Lab MCP OK."
