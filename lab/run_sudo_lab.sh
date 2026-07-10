#!/usr/bin/env bash
# Lab e2e de la ruta de ELEVACIÓN (sudo + PTY) del broker MCP.
# Cubre el hueco: sudo/PTY están en tests unitarios pero no en un lab e2e.
#
# Levanta UN sshd local (destino, :2227) que confía en la CA; el host permite
# allow_sudo + allow_pty. En vez de configurar NOPASSWD sudoers reales (que
# requieren root), instala un SHIM de `sudo` en el PATH de la sesión vía
# `SetEnv PATH` del sshd: el shim imita `sudo -n [-u user] -- CMD` ejecutando CMD
# y registrando cada invocación. Así el lab ejercita la ruta REAL del broker
# —cert con elevación → sesión → la línea `sudo -n -- /bin/sh -c ...` ejecutada
# en el host— sin necesitar privilegio de root en la máquina que corre el lab.
#
# Verifica:
#   1. ssh_execute(sudo=true) one-shot corre a través de la línea sudo.
#   2. sesión pty con sudo=true: el shell se lanza bajo sudo.
#   3. el `sudo` del host se invocó de verdad (shim log) y la auditoría firmada
#      registra la etiqueta de elevación (sudo:root).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LAB="$ROOT/lab/work-sudo"
USER_NAME="$(id -un)"
T_PORT=2227

rm -rf "$LAB"; mkdir -p "$LAB/t" "$LAB/shim"

echo "== 1. CA + host key + principal + shim de sudo =="
ssh-keygen -t ed25519 -N '' -C ca -f "$LAB/ssh_ca" >/dev/null
ssh-keygen -t ed25519 -N '' -f "$LAB/t/host" >/dev/null
printf 'host:target\n' > "$LAB/t/principals"
chmod 600 "$LAB/t/host" "$LAB/t/principals"

# Shim NOPASSWD: registra la invocación (ruta baked al generar) y ejecuta el
# comando restante, imitando `sudo -n [-u user] -- CMD` sin privilegio real.
: > "$LAB/sudo-shim.log"
cat > "$LAB/shim/sudo" <<SHIM
#!/bin/sh
echo "sudo-shim invoked: \$*" >> "$LAB/sudo-shim.log"
while [ \$# -gt 0 ]; do case "\$1" in -n) shift;; -u) shift 2;; --) shift; break;; *) break;; esac; done
exec "\$@"
SHIM
chmod +x "$LAB/shim/sudo"

echo "== 2. arrancar sshd destino (SetEnv PATH → el shim gana a /usr/bin/sudo) =="
cat > "$LAB/t/sshd_config" <<EOF
Port $T_PORT
ListenAddress 127.0.0.1
HostKey $LAB/t/host
TrustedUserCAKeys $LAB/ssh_ca.pub
AuthorizedPrincipalsFile $LAB/t/principals
PidFile $LAB/t/sshd.pid
LogLevel VERBOSE
PasswordAuthentication no
UsePAM no
StrictModes no
SetEnv PATH=$LAB/shim:/usr/bin:/bin
EOF
"$(command -v sshd || echo /usr/sbin/sshd)" -f "$LAB/t/sshd_config" -E "$LAB/t/sshd.log"
sleep 1
T_PID="$(cat "$LAB/t/sshd.pid")"
trap 'kill "$T_PID" 2>/dev/null || true; rm -rf "$LAB"' EXIT

echo "== 3. config del broker (target con allow_sudo + allow_pty) =="
head -c 32 /dev/urandom > "$LAB/audit.seed"
cat > "$LAB/config.json" <<EOF
{
  "ca_key": "$LAB/ssh_ca",
  "audit_log": "$LAB/audit.log",
  "audit_key": "$LAB/audit.seed",
  "source_address": "127.0.0.1",
  "max_ttl_seconds": 120,
  "hosts": {
    "target": {
      "addr": "127.0.0.1:$T_PORT", "user": "$USER_NAME",
      "principal": "host:target", "host_key": "$(cat "$LAB/t/host.pub")",
      "source_address": "127.0.0.1",
      "allow_sudo": true, "allow_pty": true
    }
  }
}
EOF

echo "== 4. compilar y ejecutar el escenario de elevación (LAB_SUDO=1) =="
( cd "$ROOT" && go build -o "$LAB/mcp-broker" ./cmd/mcp-broker )
( cd "$ROOT" && LAB_SUDO=1 go run ./lab/mcpclient "$LAB/mcp-broker" "$LAB/config.json" target )

echo
echo "== 5. el sudo del host se invocó de verdad (shim log) =="
if [ ! -s "$LAB/sudo-shim.log" ]; then
  echo "FAIL: el shim de sudo no se invocó — la línea de elevación no llegó al host" >&2
  exit 1
fi
sed 's/^/   /' "$LAB/sudo-shim.log"

echo
echo "== 6. auditoría firmada: etiqueta de elevación (sudo:root) =="
if ! grep -q 'sudo:root' "$LAB/audit.log"; then
  echo "FAIL: la auditoría no registró la elevación (sudo:root)" >&2
  cat "$LAB/audit.log" >&2
  exit 1
fi
grep -o '"elevation":"sudo:root"' "$LAB/audit.log" | head -3 | sed 's/^/   /'

echo "Lab sudo/PTY OK."
