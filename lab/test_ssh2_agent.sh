#!/usr/bin/env bash
# Test puntual: ¿la librería ssh2 (la que usa mcp-ssh-manager) autentica con un
# CERTIFICADO servido por el agente SSH, sin clave privada en disco para ssh2?
# Decide la viabilidad de la Opción A (sign-to-agent).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LAB="$ROOT/lab/work-agent"
SSHD_PORT=2223
USER_NAME="$(id -un)"
SSH2_NM="/Users/luislgf/.npm/_npx/3d57f84eefed011c/node_modules"

rm -rf "$LAB"; mkdir -p "$LAB/sshd" "$LAB/auth_principals"

echo "== 1. CA SSH + clave de usuario + CERT firmado (host:lab) =="
ssh-keygen -t ed25519 -N '' -C ca -f "$LAB/ssh_ca" >/dev/null
ssh-keygen -t ed25519 -N '' -C user -f "$LAB/id_user" >/dev/null
# Firma un cert efímero de usuario (genera id_user-cert.pub junto a la clave)
ssh-keygen -s "$LAB/ssh_ca" -I "agent-test" -n "host:lab" -V +2m \
  -O source-address=127.0.0.1 "$LAB/id_user.pub" >/dev/null
echo "   cert:"; ssh-keygen -L -f "$LAB/id_user-cert.pub" | grep -E "Type|Valid|Principals|source-address" | sed 's/^/     /'

echo "== 2. sshd que confía en la CA =="
ssh-keygen -t ed25519 -N '' -f "$LAB/sshd/host_ed25519" >/dev/null
printf 'host:lab\n' > "$LAB/auth_principals/$USER_NAME"
cat > "$LAB/sshd/sshd_config" <<EOF
Port $SSHD_PORT
ListenAddress 127.0.0.1
HostKey $LAB/sshd/host_ed25519
TrustedUserCAKeys $LAB/ssh_ca.pub
AuthorizedPrincipalsFile $LAB/auth_principals/%u
PidFile $LAB/sshd/sshd.pid
LogLevel VERBOSE
PasswordAuthentication no
UsePAM no
StrictModes no
EOF
chmod 600 "$LAB/sshd/host_ed25519" "$LAB/auth_principals/$USER_NAME"
"$(command -v sshd || echo /usr/sbin/sshd)" -f "$LAB/sshd/sshd_config" -E "$LAB/sshd/sshd.log"
sleep 1
SSHD_PID="$(cat "$LAB/sshd/sshd.pid")"

echo "== 3. agente efímero + ssh-add (carga clave Y cert con TTL) =="
eval "$(ssh-agent -s)" >/dev/null
trap 'kill "$SSHD_PID" 2>/dev/null; ssh-agent -k >/dev/null 2>&1 || true' EXIT
ssh-add -t 120 "$LAB/id_user" >/dev/null 2>&1
echo "   identidades en el agente:"; ssh-add -l | sed 's/^/     /'

echo "== 4. cliente ssh2 SOLO con agent (sin privateKey) =="
cat > "$LAB/test.mjs" <<JS
import { createRequire } from 'module';
const require = createRequire('$SSH2_NM/x.js');
const { Client } = require('ssh2');
const c = new Client();
c.on('ready', () => {
  c.exec('id', (err, stream) => {
    if (err) { console.error('EXEC FAIL', err.message); process.exit(1); }
    let out = '';
    stream.on('data', d => out += d);
    stream.on('close', () => { console.log('SSH2_OK:', out.trim()); c.end(); });
  });
}).on('error', e => { console.error('SSH2_FAIL:', e.message); process.exit(2); })
  .connect({
    host: '127.0.0.1',
    port: Number(process.env.PORT),
    username: process.env.UNAME,
    agent: process.env.SSH_AUTH_SOCK,   // <-- única vía de auth
  });
JS
NODE_PATH="$SSH2_NM" PORT="$SSHD_PORT" UNAME="$USER_NAME" node "$LAB/test.mjs" || true

echo
echo "== 5. ¿sshd aceptó por CERTIFICADO? =="
grep -E "Accepted|Certificate|ID \"agent-test\"" "$LAB/sshd/sshd.log" | tail -3 | sed 's/^/   /' || echo "   (sin línea de aceptación)"
rm -rf "$LAB"
