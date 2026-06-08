# Handoff: SSH Broker con CA Efímera para Agentes de IA

> Documento de traspaso para retomar la sesión de desarrollo. Última actualización: 2026-06-08 (v1.8.0 — Teams notifier: Adaptive Card + MessageCard + approval_url_template; diseño de Fase 2 (bridge de aprobación bidireccional) documentado como decisión #15).

---

## Qué se construyó y por qué

El problema de partida: un modelo de IA necesita ejecutar comandos en hosts Linux por SSH, pero las claves SSH estáticas son exfiltrables (prompt injection, volcado de memoria) y una vez robadas sirven para siempre.

La solución es un **broker SSH** que actúa como intermediario: el modelo nunca recibe ninguna credencial, solo el resultado de la ejecución (`stdout / stderr / exit_code`). Por cada operación el broker genera un par Ed25519 efímero **en memoria** (nunca toca disco), obtiene un certificado SSH firmado por una CA de corta duración, abre la conexión SSH con ese cert, y descarta el material al terminar.

El sistema opera en **modo remoto (producción)**: un servicio independiente (`cmd/signer`) custodia la clave CA y la política. El broker solo recibe el cert firmado. Un broker comprometido no puede robar la llave.

A partir de v1.4.0 existe un **tercer frontend** (`cmd/mcp-broker-http`) que expone el broker por HTTP protegido con OAuth2/OIDC, para despliegues multiusuario por red. La identidad OIDC del usuario se propaga al signer para RBAC por usuario final.

> El modo local (single-binary, `ca_key` en el broker) sigue soportado en código pero ya no es la configuración activa. Ver `config.example.json` y la sección `buildSigner` en `engine.go`.

---

## Estado actual del código

```
/home/luislgf/sources/ssh-broker/
├── cmd/
│   ├── mcp-broker/main.go        # servidor MCP (stdio) — interfaz local para el modelo
│   │                             # tools: ssh_execute, ssh_session_open/exec/close,
│   │                             # ssh_list_servers. Soporta sudo, sudo_user, pty.
│   ├── mcp-broker-http/main.go   # servidor MCP remoto (Streamable HTTP + OAuth2/OIDC)
│   │                             # mismas tools que stdio, con bearer token OIDC
│   │                             # publica /.well-known/oauth-protected-resource (RFC 9728)
│   ├── signer/main.go            # servicio de firma externo (HTTPS+mTLS)
│   │                             # endpoints: POST /v1/sign, GET /v1/hosts, POST /v1/reload
│   │                             # reload en caliente (hosts/max_ttl/ca_key) + SIGHUP
│   │                             # /v1/sign: end_user/end_user_groups (RBAC usuario),
│   │                             # command policy + gate de aprobación, trusted_forwarders
│   ├── control-plane/main.go     # PEP entre broker y signer (HTTPS+mTLS)
│   │                             # reenvía /v1/sign,/v1/hosts (on_behalf_of); orquesta
│   │                             # aprobación: 202+polling, /v1/approvals, /v1/sign/result
│   │                             # guardrails de comportamiento (observe/enforce, rate)
│   │                             # NO custodia clave CA
│   ├── broker-ctl/main.go        # CLI de gestión de signer.json
│   │                             # host add/list/remove, reload (SIGHUP local o HTTP mTLS)
│   │                             # approval list/allow/deny (mTLS al control plane)
│   │                             # preserva campos _comment al editar el JSON
│   │                             # audit tail/show/verify (incluyendo verificación Ed25519)
│   ├── broker-ctl/main_test.go   # tests verifyLog (cadena, firmas, gaps, hash, manipulación),
│   │                             #   lastNLines, parseAuditTime, splitComma, boolStr, auditDetail
│   └── broker/main.go            # frontend HTTP+mTLS alternativo (one-shot)
├── internal/
│   ├── ca/
│   │   ├── sign.go               # GenerateEphemeralKey + BuildAndSign(Constraints)
│   │   │                         # Constraints: AllowPTY → permit-pty en el cert
│   │   └── sign_test.go
│   ├── signer/
│   │   ├── signer.go             # Signer interface, Local, PolicyTable.Resolve
│   │   │                         # Intent: Sudo/SudoUser/PTY + EndUser/EndUserGroups
│   │   │                         # HostPolicy: allow_sudo/allowed_sudo_users/allow_pty/groups
│   │   │                         # CallerPolicy/CallerTable: RBAC por grupos (CN→allowed_groups)
│   │   │                         # RBAC por usuario: EndUserGroups ∩ hp.Groups (si no-nil)
│   │   │                         # HostSetForCaller, groupsIntersect
│   │   │                         # Resolve → (Constraints, elevationPrefix, error)
│   │   ├── remote.go             # Remote: SignIntent + FetchHosts + WireHostInfo
│   │   │                         # WireRequest: sudo/sudo_user/pty/end_user/end_user_groups
│   │   │                         # WireResponse: elevation_prefix
│   │   ├── signer_test.go        # tests: TTL, authz, sudo, PTY, inyección, shellQuote,
│   │   │                         #        HostSetForCaller (grupos/denegación/múltiples/etc.)
│   │   └── rbac_user_test.go     # tests RBAC por usuario final (EndUserGroups)
│   ├── broker/
│   │   ├── engine.go             # Engine: Caller{ID,Groups}, ExecOptions{Sudo,SudoUser,PTY},
│   │   │                         # Execute, buildHops, buildHopsWithPrefix,
│   │   │                         # OAuthConfig, Config.OAuth/ResourceURL
│   │   ├── engine_test.go        # tests de resolveChain (ciclos, cadenas) y dry-run
│   │   ├── session.go            # sessionManager, OpenSession, SessionExec, CloseSession
│   │   │                         # (firmas actualizadas a Caller)
│   │   └── session_test.go       # tests sessionManager (add/get/remove, límites M2,
│   │                             #   reaper); seguridad C1 (ownership SessionExec/Close);
│   │                             #   inyección M5 (newlines shell/pty); helpers internos
│   ├── mcpserver/
│   │   ├── server.go             # New(eng, callerFn) — construye *mcp.Server
│   │   └── tools.go              # Register: 5 tools compartidas por stdio y HTTP
│   │                             # CallerFunc(ctx) → broker.Caller
│   ├── oauth/
│   │   ├── verifier.go           # Verifier: NewVerifier (go-oidc, descubrimiento JWKS)
│   │   │                         # Verify → auth.TokenInfo (UserID, Scopes, groups)
│   │   └── verifier_test.go      # tests con IdP OIDC falso (httptest + go-jose RSA)
│   ├── ssh/
│   │   ├── run.go                # Hop, Conn, Dial(hops), ExecOnce(opts...), Run
│   │   │                         # ExecOptions{PTY, Term, Rows, Cols}
│   │   └── shell.go              # OpenShell(client, shellCmd) — sin PTY, parametrizable
│   │                             # OpenShellPTY(client, shellCmd, opts) — con PTY
│   ├── audit/log.go              # Entry: Elevation string + PTY bool (omitempty)
│   │                             # log append-only firmado y encadenado (Ed25519)
│   ├── audit/log_test.go         # tests cadena criptográfica: Seq, PrevHash, firma Ed25519,
│   │                             #   restoreChain (nuevo/vacío/reinicio/JSON roto),
│   │                             #   maybeRotate (rotación activa y deshabilitada), Close
│   └── auth/mtls.go              # ServerTLSConfig, ClientTLSConfig, CallerCN
│                                 # ServerTLSConfigNoClientAuth (para frontend HTTP+OAuth)
├── lab/
│   ├── run_lab.sh            # lab e2e frontend HTTP+mTLS (modo local)
│   ├── run_mcp_lab.sh        # lab e2e MCP con ProxyJump (bastión + destino)
│   ├── run_signer_lab.sh     # lab e2e MCP con servicio de firma externo
│   └── mcpclient/main.go     # cliente MCP de prueba (labtest)
├── pki/                      # PKI generada localmente (NO subir a git)
│   ├── ssh_ca                # clave privada CA SSH (Ed25519, PEM)
│   ├── ssh_ca.pub            # clave pública CA SSH
│   ├── mtls_ca.{key,crt}     # CA TLS local para mTLS broker↔signer
│   ├── signer.{key,crt}      # cert del servidor signer (SAN: 127.0.0.1, localhost)
│   ├── broker.{key,crt}      # cert del cliente broker (CN=broker-1)
│   ├── audit.seed            # semilla Ed25519 para el log del broker (32 bytes)
│   └── signer_audit.seed     # semilla Ed25519 para el log del signer (32 bytes)
├── deploy/sshd_config.snippet  # sshd_config + sudoers NOPASSWD para hosts gestionados
├── config.json               # config activa del broker (modo remoto)
├── config.example.json       # referencia con ambos modos + allow_sudo/allow_pty
├── signer.json               # config activa del signer (fuente de verdad única)
├── signer.example.json       # referencia con allow_sudo/allowed_sudo_users/allow_pty/groups + callers
├── signer.sh                 # script de gestión del signer (start/stop/status/restart/log)
├── go.mod                    # github.com/luisgf/ssh-broker, Go 1.26
└── HANDOFF.md

## Cómo usar broker-ctl

```bash
# Compilar
go build -o ~/bin/broker-ctl ./cmd/broker-ctl

# Añadir host (con ssh-keyscan automático)
broker-ctl host add --name web01 --addr 10.0.0.1:22 --user deploy --scan \
  --sudo --pty --groups prod-web --callers broker-1

# Añadir host con key manual
broker-ctl host add --name web01 --addr 10.0.0.1:22 --user deploy \
  --host-key "ssh-ed25519 AAAA..." --ttl 120

# Listar hosts configurados
broker-ctl host list

# Actualizar un host existente
broker-ctl host add --name web01 --addr 10.0.0.1:22 --user deploy --scan --force

# Eliminar host
broker-ctl host remove web01

# Recargar el signer (SIGHUP si corre local, POST /v1/reload si no hay PID file)
broker-ctl reload

# Usar config alternativa
broker-ctl --config /ruta/signer.json host list

# ── Auditoría ────────────────────────────────────────────────────────────────

# Seguir el log del broker en tiempo real (muestra las últimas 20 líneas primero)
broker-ctl audit tail --log audit.log
broker-ctl audit tail --log audit.log -n 50

# Seguir el log del signer (emisiones de certificados)
broker-ctl audit tail --log signer_audit.log

# Filtrar entradas (host, caller, outcome, fecha; combinables)
broker-ctl audit show --log audit.log --host web01
broker-ctl audit show --log audit.log --outcome denied
broker-ctl audit show --log signer_audit.log --outcome issued --since 2026-06-05
broker-ctl audit show --log audit.log --host db01 --outcome denied --limit 20

# Salida JSON para pipelines jq
broker-ctl audit show --log audit.log --outcome denied --json | jq .
broker-ctl audit show --log audit.log --json | jq 'select(.serial==1042)'
broker-ctl audit show --log audit.log --json \
  | jq 'select(.elevation != null and .elevation != "")'

# Verificar integridad de la cadena de hash
broker-ctl audit verify --log audit.log
broker-ctl audit verify --log signer_audit.log

# Verificar cadena + firmas Ed25519
broker-ctl audit verify --log audit.log        --key pki/audit.seed
broker-ctl audit verify --log signer_audit.log --key pki/signer_audit.seed
```

**Flags completos de `host add`:**

| Flag | Obligatorio | Default | Descripción |
|---|---|---|---|
| `--name` | ✓ | — | Nombre lógico del host |
| `--addr` | ✓ | — | `host:port` del servidor SSH |
| `--user` | ✓ | — | Cuenta SSH remota |
| `--host-key` | ✓* | — | Host key (authorized_keys). `-` = leer stdin |
| `--scan` | ✓* | — | Obtener key con `ssh-keyscan` (alternativa a `--host-key`) |
| `--principal` | | `host:<name>` | Principal SSH en el certificado |
| `--ttl` | | `120` | `max_ttl_seconds` |
| `--jump` | | — | Nombre del bastión previo |
| `--source-address` | | — | IP/CIDR de egreso del bastión |
| `--sudo` | | false | `allow_sudo=true` |
| `--sudo-users` | | — | `allowed_sudo_users` (comas) |
| `--pty` | | false | `allow_pty=true` |
| `--groups` | | — | Grupos RBAC (comas) |
| `--callers` | | — | CNs permitidos (comas) |
| `--bastion` | | false | `allow_as_bastion=true` |
| `--force` | | false | Sobrescribir si ya existe |

\* Se requiere `--host-key` o `--scan`, pero no ambos.
```

**Binarios compilados:** `~/bin/mcp-broker` · `~/bin/mcp-broker-http` · `~/bin/signer` · `~/bin/broker-ctl`

**Estado de compilación y tests:** `go build ./...` ✅ · `go vet ./...` ✅ · `go test ./...` ✅ (83 casos pre-existentes + 47 v1.7.1 + 18 v1.8.0 = 148 casos en total)

**MCP registrado en OpenCode:** `~/.config/opencode/opencode.json`

---

## Arquitectura en una página

```
Modelo de IA (Claude / OpenCode)
    │                           │
    │  stdio MCP (local)        │  HTTP+Bearer MCP (red)
    │                           │  Authorization: Bearer <token OIDC>
    ▼                           ▼
cmd/mcp-broker                cmd/mcp-broker-http        ← nunca tienen clave CA
~/bin/mcp-broker              ~/bin/mcp-broker-http
    │  mismas 5 tools          │  valida JWT vía JWKS (go-oidc)
    │  caller="mcp-stdio"      │  caller={sub, groups del token}
    │                           │  propaga EndUser+EndUserGroups al signer
    └─────────────┬─────────────┘
                  │
    │  al arrancar: GET /v1/hosts → cache
    │  cada 30s:    GET /v1/hosts → recarga   ← hosts_refresh_seconds (configurable)
    │
    │  genera par Ed25519 efímero              ← priv se queda aquí
    │  envía Intent{host, role,
    │    purpose, command, pubkey,
    │    sudo?, sudo_user?, pty?,
    │    end_user?, end_user_groups?}
    │
    │  HTTPS + mTLS  (pki/broker.crt, CN=broker-1)
    ▼
cmd/signer  ~/bin/signer                      ← única custodia de la clave CA
    │  al arrancar: GET /v1/hosts → cache
    │  cada 30s:    GET /v1/hosts → recarga   ← hosts_refresh_seconds (configurable)
    │
    │  genera par Ed25519 efímero              ← priv se queda aquí
    │  envía Intent{host, role,
    │    purpose, command, pubkey,
    │    sudo?, sudo_user?, pty?}
    │
    │  HTTPS + mTLS  (pki/broker.crt, CN=broker-1)
    ▼
cmd/signer  ~/bin/signer                      ← única custodia de la clave CA
    │  GET /v1/hosts  → devuelve {addr, user, host_key, jump} por host
    │                   filtrado por grupos del caller (RBAC)
    │                   (política nunca sale: principal, source_address,
    │                    allow_sudo, allowed_sudo_users, allow_pty, groups, etc.)
    │  POST /v1/sign  → check RBAC grupo (HostSetForCaller)
    │               → PolicyTable.Resolve(Intent)
    │    → Constraints (principal, source-address,
    │      force-cmd [con sudo si aplica], port-fwd,
    │      permit-pty, TTL)
    │    → ElevationPrefix (para sesiones)
    │  ca.BuildAndSign(caKey, pubkey, c)
    │  audit: issued / denied (con elevation/PTY)
    │  POST /v1/reload → relee signer.json en caliente (hosts/max_ttl/ca_key)
    │                    solo CNs en reload_callers; o vía SIGHUP (local)
    │                    audit: reloaded / reload-denied / reload-failed
    │
    └──► devuelve {Certificate, Serial, ElevationPrefix?}
    │
    │  SSH con cert efímero
    ▼
[Bastión :22]                                 ← cert con permit-port-forwarding
    │  direct-tcpip
    ▼
[Destino :22]                                 ← cert con force-command (one-shot)
    │                                            o sin force-cmd (sesión)
    │                                            permit-pty si PTY solicitado
    └──► stdout/stderr/exit_code
         ← broker → modelo
```

Auditoría triple correlada por `serial`:
1. `cmd/signer` → log de emisión (caller, **host=FQDN**, **user**, **principal**, role, purpose, elevation, pty, serial)
2. `cmd/mcp-broker` → log de ejecución (caller, host, user, cmd, exit_code, serial, session_id, elevation, pty)
3. `sshd` → `Accepted certificate ID "agent=... host=... elev=sudo:root pty=1" (serial XXXX)`

---

## Herramientas MCP expuestas al modelo

| Tool | Parámetros | Descripción |
|---|---|---|
| `ssh_list_servers` | — | Lista hosts con capacidades (`allow_sudo`, `allow_pty`, `jump`). **Llamar siempre antes de ejecutar.** |
| `ssh_execute` | `server, command [, sudo, sudo_user, pty, ttl_seconds]` | Un disparo. Cert con `force-command` (incluye sudo si procede). |
| `ssh_session_open` | `server [, mode, sudo, sudo_user, ttl_seconds]` | Abre sesión persistente. `mode`: `exec` \| `shell` \| `pty`. |
| `ssh_session_exec` | `session_id, command` | Ejecuta en sesión reusando conexión. |
| `ssh_session_close` | `session_id` | Cierra y libera. |

**Flujo recomendado:** llamar a `ssh_list_servers` primero para conocer qué hosts existen y si soportan `sudo`/`pty`, luego ejecutar con los parámetros adecuados.

### Parámetros de elevación y PTY

| Parámetro | Dónde | Descripción |
|---|---|---|
| `sudo: true` | `ssh_execute`, `ssh_session_open` | Eleva el comando/sesión con `sudo -n` (NOPASSWD). Requiere `allow_sudo: true` en la política del host. |
| `sudo_user: "deploy"` | `ssh_execute`, `ssh_session_open` | Usuario destino del sudo. Vacío = root. Debe estar en `allowed_sudo_users`. |
| `pty: true` | `ssh_execute` | Solicita PTY para el comando (streams mezclados). Requiere `allow_pty: true`. |
| `mode: "pty"` | `ssh_session_open` | Abre sesión con PTY. Implica `pty: true`. |

---

## Cómo funciona la elevación (sudo NOPASSWD)

La autorización es **policy-gated en el signer**; el broker nunca decide elevar por su cuenta.

### One-shot (`ssh_execute` con `sudo=true`)

```
broker → Intent{sudo=true, sudo_user="root", command="id", purpose=oneshot}
signer → PolicyTable.Resolve → force-command = "sudo -n -- /bin/sh -c 'id'"
       → cert con force-command horneado
sshd   → impone el force-command; el broker no puede modificarlo
```

### Sesión `exec` con `sudo=true`

```
broker → Intent{sudo=true, purpose=session} → signer devuelve ElevationPrefix="sudo -n"
       → ElevationPrefix guardado en liveSession.elevationPrefix
SessionExec("ls /root") → comando efectivo: "sudo -n -- /bin/sh -c 'ls /root'"
```

### Sesión `shell`/`pty` con `sudo=true`

```
broker → OpenShell(client, "sudo -n -- /bin/sh")   ← shell completo elevado
       → toda la sesión corre como root en un solo proceso sudo
```

### Configuración host-side (`/etc/sudoers.d/broker`)

```sudoers
# Cuenta SSH 'deploy', sudo a root sin contraseña:
deploy ALL=(root) NOPASSWD: ALL

# Restringido a comandos concretos (recomendado en producción):
deploy ALL=(root) NOPASSWD: /usr/bin/systemctl, /usr/bin/journalctl

# Sudo a usuario específico:
deploy ALL=(appuser) NOPASSWD: ALL
```

Verificar:
```bash
sudo -n -u root -- /bin/sh -c 'id'   # debe imprimir uid=0(root) ...
```

---

## Cómo arrancar el sistema

```bash
cd /home/luislgf/sources/ssh-broker

# 1. Arrancar el signer (debe estar corriendo antes de que el broker arranque)
./signer.sh start        # lanza en background, PID en signer.pid, log en signer.log
./signer.sh status       # comprueba si está corriendo
./signer.sh log          # tail -f signer.log
./signer.sh stop
./signer.sh restart

# 2. El MCP (mcp-broker) lo arranca OpenCode automáticamente al conectar.
#    Requiere que el signer esté corriendo: si no puede hacer GET /v1/hosts,
#    el broker falla al arrancar.

# 3. Recompilar tras cambios
go build -o ~/bin/signer     ./cmd/signer
go build -o ~/bin/mcp-broker ./cmd/mcp-broker
```

---

## Cómo añadir un host

Solo hay que editar **`signer.json`** — es la única fuente de verdad. El broker recargará el cambio en ≤30 segundos (sin reiniciar).

```json
"hosts": {
  "web01": {
    "addr":            "10.0.0.21:22",
    "user":            "deploy",
    "host_key":        "ssh-ed25519 AAAA...",
    "principal":       "host:web01",
    "source_address":  "",
    "max_ttl_seconds": 120,
    "allow_as_bastion": false,

    "groups": ["prod-web"],           // RBAC: grupos a los que pertenece este host

    "allow_sudo": true,
    "allowed_sudo_users": ["root", "deploy"],
    "allow_pty": true
  }
},
"callers": {
  "broker-1": { "allowed_groups": ["prod-web"] }  // CN → grupos permitidos
}
```

> **Nota sobre bastiones:** si el host usa `"jump": "bastion"`, el bastión debe estar en los mismos grupos que el host, o el broker no podrá resolver la cadena de salto.

> **Backward compatible:** un CN ausente de `callers` no tiene restricción de grupos y ve todos los hosts (comportamiento anterior).

Obtener la `host_key`:
```bash
ssh-keyscan -t ed25519 <ip-o-hostname>
# Copiar solo la parte "ssh-ed25519 AAAA..." (sin el prefijo del hostname)
```

**Nota:** El signer necesita reiniciarse para releer `signer.json`. El broker NO necesita reiniciarse.

```bash
./signer.sh restart
```

### Configuración en el servidor remoto

En `/etc/ssh/sshd_config` del host destino:

```
TrustedUserCAKeys /etc/ssh/ssh_broker_ca.pub   # copiar pki/ssh_ca.pub
AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
LogLevel VERBOSE
AllowTcpForwarding no   # sí en bastiones
X11Forwarding no
PermitTunnel no
# PermitTTY yes          # es el default; descomentar solo si se deshabilitó
```

Crear `/etc/ssh/auth_principals/<usuario>` con el `principal` del host (p. ej. `host:web01`).

Para elevación, añadir la entrada sudoers como se describe en la sección anterior.

---

## Decisiones de diseño críticas

### 1. `signer.json` como única fuente de verdad para hosts

El broker no declara hosts. Al arrancar llama a `GET /v1/hosts` (mTLS) y cachea `{addr, user, host_key, jump, allow_sudo, allow_pty}`. Recarga cada `hosts_refresh_seconds` (actualmente 30s para desarrollo). Si la recarga falla, mantiene el cache anterior. La política (`principal`, `source_address`, `allowed_callers`, `allow_sudo`, etc.) nunca sale del signer.

**Implicación operativa:** añadir un host = editar `signer.json` + reiniciar el signer. El broker lo ve en ≤30s sin reiniciar.

### 2. Por qué un MCP propio y no mcp-ssh-manager

`mcp-ssh-manager` usa la librería Node `ssh2 1.17` que **no soporta certificados de cliente SSH**. Con clave + cert en el agente SSH, `ssh2` ofrece al `sshd` solo la clave pelada (`ED25519`, no `ED25519-CERT`), que el sshd rechaza. Se construyó el broker MCP propio en Go (`golang.org/x/crypto/ssh` sí soporta certs de cliente correctamente).

### 3. `force-command` solo en one-shot, no en sesiones

El cert de un disparo lleva `force-command=<cmd>` (incluye el prefijo sudo si se pidió elevación). En sesiones el cert autentica la **conexión** y los comandos van como canales `exec` separados → el cert no puede llevar `force-command`. La defensa en sesiones recae en TTL + `source-address` + principal + la política sudoers del host.

### 4. `source-address` en cadenas de salto

Cuando hay ProxyJump, el TCP al destino **sale del bastión**, no del broker. El cert del **destino** debe pinnear la IP de egreso del **bastión**. Se controla con `source_address` por host en `signer.json`.

### 5. Shell con estado: sin PTY vs. con PTY

- **Sin PTY** (`mode=shell`): `OpenShell(client, shellCmd)` arranca `/bin/sh` (o `sudo -n -- /bin/sh` si hay elevación). No hay eco ni prompt. Stdout y stderr van separados. Marcadores para detectar fin de comando y exit code.
- **Con PTY** (`mode=pty`): `OpenShellPTY(client, shellCmd, opts)` solicita `RequestPty`, arranca el shell con `stty -echo; PS1=''` para silenciar el eco, y reutiliza el mismo protocolo de marcadores. Stdout y stderr se **mezclan** en el canal PTY.

### 6. Bug de concurrencia en ShellSession (resuelto)

Primera versión: goroutine lectora nueva por llamada sobre el mismo `bufio.Reader` compartido → race condition. Fix: **una única goroutine lectora persistente** que alimenta un canal `chan lineRes`. Cada llamada a `Exec()` consume del canal directamente.

### 7. Separación broker/signer

El broker envía una *intención* (host, role, purpose, command, pubkey, sudo?, sudo_user?, pty?). El signer decide todos los constraints del cert. La clave privada efímera se genera en el broker y nunca sale. Al signer solo viaja la pubkey → devuelve el cert + ElevationPrefix (en sesiones).

### 8. `AllowAsBastion` en política

Por defecto un host no puede usarse como salto ProxyJump. Hay que marcarlo explícitamente `allow_as_bastion: true` en `signer.json` (habilita `permit-port-forwarding` en su cert).

### 9. Elevación policy-gated en el signer

La autorización de `sudo` vive en el signer (`allow_sudo`, `allowed_sudo_users`). Un broker comprometido no puede elevar en hosts que no lo tengan habilitado. La validación incluye:
- Regex sobre `sudo_user` (`^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,31}$`) — rechaza flags y metacaracteres.
- Whitelist `allowed_sudo_users` (vacía = solo root).
- El comando se envuelve siempre como `prefix -- /bin/sh -c <shellQuote(cmd)>` para evitar inyección.

### 14. AI-action firewall: command policy + dry-run (v1.5.0, Fase A)

Roadmap estratégico para diferenciarse: el broker no solo gatea *acceso* sino *qué comando se ejecuta*, defendiendo contra un **agente comprometido** (no solo robo de credenciales). Plan completo de 3 fases en `/Users/luislgf/.claude/plans/si-quisiesemos-destacar-sobre-tidy-hummingbird.md`.

**Decisión de arquitectura (con el usuario):** el componente que custodia la clave CA debe permanecer mínimo. Por tanto:
- **Command policy → en el signer** (autoritativa: el `force-command` horneado por la clave CA es inevadible; sin estado).
- **Approval + behavior → futuro `cmd/control-plane` separado** (Fases B/C): tienen estado y superficie de red nueva, no necesitan la clave CA. Patrón PEP/PDP zero-trust. Topología futura: `broker → control-plane → signer`.

**Fase A implementada (v1.5.0):**
- `internal/signer/cmdpolicy.go` — `CommandPolicy{Mode, Allow, Deny, RequireApproval}` + `Decide()`. Regex RE2 con caché a nivel de paquete (copiable por valor; vive en `HostPolicy`). `Active()`/`Restricts()`.
- `PolicyTable.Resolve` ahora devuelve `(Decision, error)` en lugar de `(ca.Constraints, string, error)`. `Decision{Constraints, ElevationPrefix, RequireApproval, MatchedRule}`.
- Command policy autoritativa en one-shot (allow/deny → error si denegado). Hosts con cualquier regla **rechazan sesiones** (el comando no llega al firmante al firmar). `require_approval` se *surface* pero no se actúa todavía (lo hará el control plane en Fase B).
- Dry-run: `Intent.DryRun`/`WireRequest.dry_run`/`ExecOptions.DryRun` + `WireResponse.decision` (`DecisionInfo`). En dry-run no se emite cert; una denegación es resultado (`Allowed=false`), no error. MCP: parámetro `dry_run` en `ssh_execute` (`Engine.dryRun` corta antes de `Dial`; solo evalúa el destino).
- Audit: campos `policy_rule`, `dry_run`; outcomes `dry_run_allowed`/`dry_run_denied`.
- Config: `command_policy` por host. Modo remoto → `signer.json` (ver `web02` en `signer.example.json`). Modo local → `config.json` del broker (campo `command_policy` en `HostConfig`, mapeado en `policyFromHosts`; ver `web01` en `config.example.json`).

**Fase B implementada (v1.6.0): control plane + aprobación humana.**
- `cmd/control-plane/main.go` — PEP entre broker y signer. Reenvía `/v1/sign` y `/v1/hosts` al signer propagando la identidad del broker; orquesta aprobación. NO custodia la clave CA.
- `internal/control/approval.go` — `Registry` (estado en memoria, TTL, `Consume` para una sola emisión por aprobación). `internal/control/notifier.go` — `Notifier` interface, `LogNotifier`, `WebhookNotifier`. `internal/control/teams.go` — `TeamsNotifier` (Adaptive Card v1.4 / MessageCard legacy, `approval_url_template`).
- **Modelo de confianza**: `signer.json` gana `trusted_forwarders` (CN del control plane). El signer honra `on_behalf_of` (cuerpo en /v1/sign; cabecera `X-On-Behalf-Of` en /v1/hosts) y `approved` SOLO desde forwarders de confianza → la aprobación y la suplantación de identidad son inevadibles. `resolveCaller` en cmd/signer.
- **Gate de aprobación en el signer** (autoritativo): `Local.SignIntent` no emite cert si `RequireApproval && !Approved` (devuelve Issued con cert nil + Decision). Un broker directo no puede auto-aprobarse.
- **Flujo async** (sin conexiones colgadas): broker→control plane `POST /v1/sign` → si requiere aprobación, 202 `{approval_id}`; el broker hace polling `GET /v1/sign/result/{id}`; humano aprueba con `broker-ctl approval allow <id>` (`POST /v1/approvals/{id}`); siguiente poll reenvía con `approved=true` y devuelve el cert. `Remote.SetApprovalWait` + `signer.approval_wait_seconds`.
- **broker-ctl approval** `list|allow|deny` (mTLS al control plane, cert aprobador).
- Audit (control plane, log encadenado propio): `forwarded`/`approval-required`/`approval-granted`/`approval-denied`/`approval-timeout`/`approval-decision-allow`; campos `approval_id`/`approved_by`.
- Config: `control-plane.example.json` (nuevo); `trusted_forwarders` en `signer.example.json`; broker apunta `signer.url` al control plane + `approval_wait_seconds` en `config.example.json`.
- Tests: `internal/control/approval_test.go`, `internal/control/teams_test.go` (18 casos: formatos, facts, URL template, seguridad, errores HTTP), `cmd/control-plane/main_test.go` (flujo e2e de aprobación con signer stub), `cmd/signer/main_test.go` (`resolveCaller`/CN pinning), gate en `internal/signer/cmdpolicy_test.go`.

**Fase C implementada (v1.7.0): guardrails de comportamiento + rate limiting.**
- `internal/control/behavior.go` — `BehaviorTracker` (estado en memoria por sujeto). Detecta: pico de tasa, host nunca usado por el agente, comando fuera del histórico (fingerprint = primer token vía `firstToken`). Estadístico/reglas, sin ML. La primera petición de un sujeto fija la línea base (no se marca).
- **Sujeto**: usuario final OIDC si la petición lo porta; si no, el CN del broker.
- **Modos** (`behavior.mode` en `control-plane.json`): `off` (default) / `observe` (audita `anomaly`, no bloquea) / `enforce` (anomalías escalan a aprobación reusando Fase B; rate excedido → 429). `rate_limit_per_min` da el rate limiting por sujeto.
- Integrado en `handleSign` del control plane ANTES de reenviar; dry-run no pasa por los guardrails. Helper `requireApproval` compartido por command-policy y behavior.
- Audit: campo `anomaly`; outcomes `anomaly` (observe) y `rate-limited` (enforce). Escaladas por comportamiento se auditan como `approval-required` con `policy_rule="behavior"`.
- Config: bloque `behavior` en `control-plane.example.json`.
- Tests: `internal/control/behavior_test.go` (rate/new-host/new-command/baseline/aislamiento por sujeto), `cmd/control-plane/main_test.go` (observe no bloquea, enforce escala, rate→429).

**AI-action firewall COMPLETO (A+B+C).** Rama Fase C: `feature/behavior-guardrails`.

**Pendiente operativo**: generar el cert del control plane (CN=`control-plane-1`) firmado por `pki/mtls_ca.crt` y añadirlo a `trusted_forwarders`. Lab e2e shell de aprobación/behavior (`lab/`) aún no escrito (el flujo está cubierto por tests Go de integración).

### 15. Mecanismos de notificación y aprobación extensibles (v1.8.0 + Fase 2 — pendiente)

#### Fase 1 implementada (v1.8.0): Teams notifier

`TeamsNotifier` en `internal/control/teams.go` implementa la interfaz `Notifier` existente. Se activa con `notifier: "teams"` en `control-plane.json`. Reutiliza `webhook_url` como destino (Incoming Webhook de Power Automate / M365 Connector).

Configuración completa:
```json
"approval": {
  "notifier": "teams",
  "webhook_url": "https://...webhook.office.com/webhookb2/...",
  "teams_format": "workflow",
  "approval_url_template": "https://approvals.example.com/requests/{id}",
  "timeout_seconds": 120,
  "callers": ["broker-admin"]
}
```

- `teams_format: "workflow"` (default) — Adaptive Card v1.4 en sobre Power Automate. Recomendado.
- `teams_format: "messagecard"` — MessageCard legacy para tenants sin Workflow. Microsoft retira este formato; migrar cuando sea posible.
- `approval_url_template` — URL con `{id}` que se incrusta como botón "View request" en la card. Dejar vacío hasta tener el bridge de Fase 2 desplegado.

**Importante (investigación Microsoft Docs, 2026-06-08):** los botones `Action.Submit` / `HttpPOST` de Adaptive Cards **no están soportados** vía Incoming Webhook simple. Solo `Action.OpenUrl`, `Action.ShowCard` y `Action.ToggleVisibility`. La aprobación bidireccional desde Teams (pulsar botón "Approve" en la card) requiere el bridge de Fase 2.

#### Fase 2 — Diseño pendiente de implementación: bridge de aprobación bidireccional

**Problema:** el control-plane exige `POST /v1/approvals/{id}` con **mTLS + CN en `approval.callers`**. Teams no puede presentar un certificado de cliente. La notificación de Fase 1 es unidireccional; aprobar sigue requiriendo `broker-ctl approval allow <id>`.

**Componente propuesto: `cmd/approval-bridge`**

```
Teams (Adaptive Card, botón "Approve" / "Deny")
   │  HttpPOST con token de identidad Entra del usuario (Bot Framework)
   ▼
Approval Bridge  ── valida identidad Entra ID del aprobador (JWT del token de Bot Framework)
   │              ── comprueba que el usuario está en el grupo Entra de aprobadores
   │              ── mapea acción (approve/deny) → decisión
   │  mTLS (cert bridge, CN ∈ approval.callers del control-plane)
   ▼
control-plane  POST /v1/approvals/{id}  {"approve": true/false}
```

- **Por qué un servicio separado:** el control-plane exige mTLS y no tiene visibilidad de Entra; el bridge es el único componente con el cert aprobador y la lógica de autenticación federada. No toca el gate del signer.
- **Atribución real:** `DecidedBy` reflejaría la identidad Entra (UPN / `preferred_username`) del humano que pulsó, cerrando el círculo con el RBAC por usuario de `mcp-broker-http`.
- **Bot Framework / Adaptive Cards bidireccionales:** los botones con acción en Adaptive Cards requieren registro de un Bot en Azure y el uso del canal de Bot Framework, no un webhook simple.
- `approval_url_template` ya está preparado para apuntar al endpoint del bridge (p. ej. `https://bridge.internal/requests/{id}`).

**Abstracción de configuración propuesta para el futuro (no implementada):**

```json
"notifiers": [
  { "type": "teams",   "webhook_url": "...", "teams_format": "workflow", "approval_url_template": "..." },
  { "type": "log" }
],
"approval_channels": [
  { "type": "mtls-cli", "callers": ["broker-admin"] },
  { "type": "teams-bot", "entra_group": "ssh-approvers", "cert": "pki/bridge.crt" }
]
```

Evoluciona el bloque `approval` actual hacia listas: múltiples notificadores simultáneos + múltiples canales de entrada de decisión, cada uno con su mapeo de identidad y autorización.

**Trade-offs registrados:**

| Opción | Descripción | Atribución | Coste |
|---|---|---|---|
| **A — Bot + bridge** | Bot Framework + `cmd/approval-bridge` + Entra group check | Real (UPN del aprobador) | Alto: nuevo servicio, registro Bot en Azure, ciclo de vida Adaptive Cards |
| **B — Token firmado de un uso** | El control-plane embebe un HMAC en la URL del botón; Teams POST sin cert | Ninguna (anónimo del canal) | Bajo: solo endpoint nuevo en control-plane sin mTLS |
| **C — Solo notificación** | Fase 1 actual: Teams notifica, aprobador ejecuta `broker-ctl` | CN mTLS del aprobador | Cero (ya entregado) |

**Recomendación:** Opción A (bot + bridge) cuando se quiera aprobar desde móvil/Teams con identidad real. Opción C es el estado actual y suficiente para muchos despliegues.

### 13. Hardening de seguridad v1.4.1 (revisión MCP/Snyk)

Doce hallazgos corregidos en orden de criticidad (C → A → M → L):

| ID | Severidad | Archivo(s) | Cambio |
|---|---|---|---|
| C1 | Crítica | `internal/broker/session.go` | `SessionExec`/`CloseSession` verifican `s.caller != c.ID` antes de operar; evita que un caller opere sesiones de otro. `CloseSession` hace `get`-antes-de-`delete` para no borrar sesiones ajenas. |
| A1 | Alta | `cmd/signer/main.go`, `cmd/mcp-broker-http/main.go` | `ReadTimeout`, `WriteTimeout` (solo signer), `IdleTimeout` en `http.Server`. |
| A2 | Alta | `cmd/signer/main.go`, `internal/signer/remote.go` | `http.MaxBytesReader(64KiB)` en `handleSign`; `io.LimitReader(1MiB)` en ambos `io.ReadAll` de `remote.go`. |
| A3 | Alta | `internal/ssh/run.go`, `internal/ssh/shell.go` | `defaultExecTimeout=10min`; `maxOutputBytes=10MiB`; `limitedWriter`; `session.Signal(SIGTERM)` en timeout; shell/pty descarta bytes excedentes. |
| A4 | Alta | `internal/audit/log.go` | `restoreChain()` con `bufio.Scanner` (buffer 256KiB) restaura `seq`+`prevHash` del último registro al reiniciar. |
| M1 | Media | `internal/broker/engine.go`, `cmd/signer/main.go` | Errores de `auditLog.Append` ya no silenciados con `_ =`; se registran con `log.Printf`. |
| M2 | Media | `internal/broker/session.go` | `maxSessionsGlobal=200`, `maxSessionsPerCaller=20`; `sessionManager.add()` retorna `error`. |
| M3 | Media | `internal/oauth/verifier.go`, `internal/broker/engine.go`, `cmd/mcp-broker-http/main.go` | Campo `MaxTokenAge time.Duration` en `Config`/`Verifier`; valida `iat` claim si `maxTokenAge > 0`; `OAuthConfig.MaxTokenAgeSeconds` (recomendado: 3600). |
| M5 | Media | `internal/broker/session.go` | `SessionExec` rechaza comandos con `\n` o `\r` (evita command injection vía newlines). |
| L1 | Baja | `internal/ca/sign.go` | `LoadCAFromPEM` emite `[WARN]` en runtime indicando que solo es apto para laboratorio. |
| L2 | Baja | `internal/audit/log.go` | `maybeRotate()`: cuando el log supera `AuditLogMaxSize=100MiB` renombra a `<path>.20060102T150405Z` y abre fichero nuevo. |
| L4 | Baja | `internal/mcpserver/tools.go` | `validateInput(fields)`: limita campos a 64KiB y rechaza bytes nulos; llamada en los 4 tool handlers antes de llegar al engine. |

**`go build ./...` ✅ · `go vet ./...` ✅ · `go test ./...` ✅**

### 10. Frontend HTTP+OAuth2/OIDC (v1.4.0)

La spec del MCP indica explícitamente que OAuth aplica solo a **transportes HTTP remotos**, no a stdio. `cmd/mcp-broker-http` implementa el flujo completo (RFC 9728 + OAuth 2.1):

1. Sin token → `401 WWW-Authenticate: Bearer resource_metadata="…/.well-known/oauth-protected-resource"`.
2. El cliente descubre el Authorization Server, hace Authorization Code + PKCE y reintenta con bearer token.
3. El broker valida el JWT **localmente** contra el JWKS del issuer (`go-oidc`, con cache/rotación). Sin round-trip por petición; sin client_secret.
4. `TokenInfo.UserID` (`sub` o `preferred_username`) → `Caller.ID` → `audit.Entry.Caller`.
5. Si el token porta un `groups_claim`, los grupos van en `Caller.Groups` → `Intent.EndUserGroups` → RBAC por usuario en `PolicyTable.Resolve`.

Las tools y la lógica son idénticas a stdio: compartidas por `internal/mcpserver.Register`. La única diferencia entre frontends es `CallerFunc(ctx) → broker.Caller`.

### 11. RBAC por usuario final (EndUser/EndUserGroups)

Añadido en v1.4.0 al signer. Cuando `Intent.EndUserGroups` no es nil (petición desde frontend HTTP+OIDC), `Resolve` exige que `hp.Groups ∩ EndUserGroups ≠ ∅`. Si es nil (stdio/mTLS), el filtro no se aplica — compatibilidad total.

El `EndUser` también aparece en el `KeyID` del cert para trazabilidad en `sshd`. El RBAC se aplica a todos los hops (bastión + destino).

### 12. RBAC por grupos: visibilidad y firma filtradas por CN

Cada host declara los grupos a los que pertenece (`"groups": [...]` en su política). La sección `callers` del signer mapea el CN del cert mTLS de cada broker a los grupos que puede usar (`"allowed_groups": [...]`).

El enforcement es doble:
- **`GET /v1/hosts`**: el signer filtra la respuesta — un broker restringido solo recibe los hosts cuyos `groups` intersectan con sus `allowed_groups`.
- **`POST /v1/sign`**: antes de llamar a `Resolve()`, el signer verifica que el host solicitado esté en el conjunto accesible para ese CN; si no, devuelve 403 y audita `"denied"`.

Un CN ausente de `callers` no tiene restricción de grupo (backward compatible). El mecanismo es aditivo con `allowed_callers` por host: para acceder, un broker debe superar ambas validaciones.

Implementado en:
- `internal/signer/signer.go` — `HostPolicy.Groups`, `CallerPolicy`, `CallerTable`, `HostSetForCaller`
- `cmd/signer/main.go` — `Config.Callers`, `server.callers`, `snapshot()` (3 valores), filtrado en `handleHosts()` y check en `handleSign()`

### 11. Campos de auditoría en el signer: FQDN, user y principal

El log del signer (`signer_audit.log`) usa la PolicyTable (ya disponible en `handleSign()` tras `snapshot()`) para enriquecer cada Entry:
- `host` → `hp.Addr` (FQDN/addr real, p.ej. `"web01.prod.example.com:22"`) en lugar del nombre lógico corto
- `user` → `hp.User` (cuenta SSH remota)
- `principal` → `hp.Principal` (principal del cert, p.ej. `"host:web01"`)

Si el host no existe en la tabla (denegación por grupo antes de `Resolve()`), se usa el nombre lógico como fallback — mejor nombre corto que vacío.

El broker (`engine.go`) tiene su propio mecanismo (`auditE()`) que rellena `user` desde el cache de hosts; ambos logs son consistentes.

---

## PKI local generada

| Archivo | Descripción | Renovar cuando |
|---|---|---|
| `pki/ssh_ca` | Clave privada CA SSH (Ed25519) | Rotación de CA |
| `pki/mtls_ca.{key,crt}` | CA TLS (autofirmada, 10 años) | 2036 |
| `pki/signer.{key,crt}` | Cert servidor signer (SAN: 127.0.0.1) | 2036 |
| `pki/broker.{key,crt}` | Cert cliente broker (CN=broker-1) | 2036 |
| `pki/audit.seed` | Semilla HMAC del log del broker | No rotar (rompe cadena) |
| `pki/signer_audit.seed` | Semilla HMAC del log del signer | No rotar (rompe cadena) |

> ⚠️ **No subir `pki/` a git.** Contiene claves privadas.

---

## Pendientes para producción

### Alta prioridad

- [ ] **Clave CA en HSM/KMS/Secure Enclave**: el seam ya está preparado. `ca.LoadCAFromPEM` devuelve un `ssh.Signer`; basta sustituirlo por `ssh.NewSignerFromSigner(kmsClient)` donde `kmsClient` implementa `crypto.Signer`.
- [ ] **Rate limiting por CN de broker** en el signer: límite de peticiones por ventana de tiempo.
- [x] **Timeouts HTTP y límites de payload** (v1.4.1): `http.Server` con `ReadTimeout`/`WriteTimeout`/`IdleTimeout`; `MaxBytesReader` en `/v1/sign`; `LimitReader` en `remote.go`.
- [x] **Límite de sesiones activas** (v1.4.1): `maxSessionsGlobal=200`, `maxSessionsPerCaller=20` en `sessionManager`.
- [x] **Timeout de ejecución SSH + límite de salida** (v1.4.1): `defaultExecTimeout=10min`, `maxOutputBytes=10MiB`.
- [x] **Validación de iat en JWT** (v1.4.1): `OAuthConfig.MaxTokenAgeSeconds`; recomendado 3600 (1h) en producción.
- [x] **Rotación y restauración de cadena de auditoría** (v1.4.1): `maybeRotate()` a los 100MiB; `restoreChain()` al reiniciar.
- [ ] **Una CA por grupo de hosts**: la config del signer acepta una sola `ca_key` global. Para aislar el compromiso de una CA a un subconjunto de hosts, añadir `group → ca_key` en el signer. Los grupos RBAC ya existen como concepto; habría que vincular cada grupo a una CA diferente.
- [x] **Auditoría del signer enriquecida**: `auditEmission()` ahora registra `host=FQDN` (en lugar del nombre lógico corto), `user` y `principal` en todos los eventos `issued`/`denied`. El signer hace lookup en la PolicyTable para obtener los valores reales; si el host no existe en la tabla (denegación por grupo), usa el nombre lógico como fallback.
- [x] **RBAC por grupos**: implementado. Campo `groups` por host + sección `callers` en `signer.json`. `GET /v1/hosts` filtra por grupos del caller; `POST /v1/sign` rechaza (403) hosts fuera del grupo antes de llegar a `Resolve()`. Backward compatible: CN ausente de `callers` = sin restricción.
- [x] **Recarga de `signer.json` sin reinicio**: implementado. `POST /v1/reload` (mTLS, gated por `reload_callers`) y `SIGHUP` recargan en caliente política de hosts, `max_ttl_seconds` y `ca_key`. Si la nueva config es inválida, se conserva el estado anterior. `listen`/TLS/`audit_log` siguen requiriendo reinicio. Auditado como `reloaded`/`reload-denied`/`reload-failed`.

### Media prioridad

- [ ] **KRL (Key Revocation List)**: añadir `RevokedKeys /etc/ssh/krl` en sshd y un endpoint `/v1/revoke` en el signer que genere la KRL por serial.
- [ ] **Logs a almacenamiento WORM**: enviar el log de auditoría (ya firmado y encadenado) a S3, GCS, Loki o SIEM en tiempo real.
- [ ] **Sesiones multi-instancia**: hoy el `sessionManager` es in-process. Con varias réplicas del broker hay que externalizar el estado a Redis con TTL.
- [x] **Autenticación del modelo ante el broker (HTTP)**: `cmd/mcp-broker-http` (v1.4.0) valida bearer token OIDC. Para stdio el aislamiento sigue siendo el proceso.
- [ ] **Lab e2e para sudo + PTY**: extender `lab/run_mcp_lab.sh` con un escenario que levante un `sshd` con `sudoers NOPASSWD` y verifique one-shot elevado, sesión `shell` elevada y sesión `pty`.

### Baja prioridad

- [ ] **Hosts dinámicos (sin declarar en signer.json)**: actualmente todos los hosts deben estar declarados. Se podría añadir un modo `allow_dynamic_hosts: true` en `config.json` donde el modelo suministra `addr/user/host_key/principal` en la llamada. Requiere cambios en el schema MCP, en `engine.go` y en el signer (política inline o wildcard `"*"`).
- [ ] **Grabación de sesión**: redirigir stdout/stderr de `mode=shell`/`mode=pty` a un grabador antes de devolverlos al broker.
- [ ] **Dashboard de auditoría**: visualizar los logs de emisión + ejecución correlados por `serial` (incluyendo los campos `elevation` y `pty`).
- [x] **Whitelist de comandos por host (AI-action firewall)**: implementado en v1.5.0 (Fase A) como `command_policy` (allowlist/denylist + require_approval) en `signer.json` (modo remoto) y en `config.json` (modo local). Autoritativo para one-shot. Complementa la restricción de `sudoers` del host con una segunda capa en el signer. Ver decisión de diseño #14.

---

## Flujo de trabajo y versioning

### Ramas

- Toda **funcionalidad nueva** se desarrolla en una rama propia (`feature/<nombre>`) o corrección (`fix/<nombre>`).
- La rama se fusiona en `main` solo si la funcionalidad se considera válida.
- Commits de mantenimiento menores (docs, config) pueden ir directamente a `main`.

### Esquema de versión `X.Y.Z`

| Componente | Cuándo se incrementa | Reset al incrementar |
|---|---|---|
| `X` (major) | Cambio de arquitectura o ruptura de compatibilidad | `Y=0`, `Z=0` |
| `Y` (minor) | Automáticamente al fusionar una rama en `main` | `Z=0` |
| `Z` (build)  | Cada commit en `main` | — |

- Versión inicial: **v1.0.0**
- Los tags `vX.Y.Z` se crean **solo en `main`** (no en ramas de desarrollo).

### Paso obligatorio antes de cada commit

**Antes de cualquier commit que modifique código, configuración o comportamiento**, actualizar:

1. **`CHANGELOG.md`** — añadir una entrada al principio con el formato:
   ```markdown
   ## [vX.Y.Z] - YYYY-MM-DD
   ### Added / Changed / Fixed / Security / Removed
   - …
   ```
2. **`README.md`** — reflejar cualquier cambio en la interfaz pública, configuración, opciones nuevas, secciones de seguridad o estado de pendientes.
3. **`API.md`** — si se añadió, eliminó, renombró o cambió el esquema de request/response de algún endpoint HTTP, actualizar `API.md` para reflejar el cambio. Aplica a todos los servicios: signer (`/v1/sign`, `/v1/hosts`, `/v1/reload`), broker HTTP (`/v1/ssh_run`) y MCP HTTP (incluyendo firmas de tools MCP).
4. **`USAGE.md`** — si se añadió, eliminó, renombró o cambió el comportamiento de alguna tool MCP (parámetros, valores de retorno, restricciones), actualizar `USAGE.md` para que los ejemplos reflejen el estado actual.

Estos archivos son la **documentación viva del proyecto**: un commit sin ellos asume que nada visible cambió (solo refactors internos sin efecto externo). Si el cambio es puramente interno (renombrado de variable, refactoring sin impacto en interfaz), puede omitirse con justificación explícita en el mensaje del commit.

**Language:** all commit messages, new documentation files (`README.md`, `API.md`, guides, etc.) and comments in new code must be written in **English**. Existing internal files (`HANDOFF.md`, `CHANGELOG.md`, comments in existing Go code) may remain in Spanish.

### Procedimiento: commit en `main` (docs, config, hotfix)

```bash
# 1. Ver la versión actual
git describe --tags --abbrev=0        # ej. v1.0.3

# 2. Actualizar CHANGELOG.md y README.md (obligatorio — ver arriba)
# 3. Comitear
git commit -m "descripción del cambio"

# 4. Etiquetar con Z+1
git tag v1.0.4
```

### Procedimiento: merge de rama de funcionalidad → `main`

```bash
# En main, tras el merge (Y+1, Z=0):
git merge feature/mi-funcionalidad

# Actualizar CHANGELOG.md y README.md (obligatorio — ver arriba)
git add CHANGELOG.md README.md
git commit -m "chore: merge feature/mi-funcionalidad → v1.1.0"
git tag v1.1.0
```

### CHANGELOG.md

- Cada entrada nueva se añade **al principio** del archivo.
- Formato:

```markdown
## [vX.Y.Z] - YYYY-MM-DD

### Added / Changed / Fixed / Removed
- …
```

---

## Archivos de configuración de referencia

**`config.json`** — config activa del broker (modo remoto, rutas absolutas a `pki/`)
**`config.example.json`** — referencia con modo local y remoto documentados; incluye `allow_sudo`/`allow_pty`/`command_policy` y `approval_wait_seconds`
**`signer.json`** — config activa del signer (fuente de verdad única de hosts)
**`signer.example.json`** — referencia con `allow_sudo`/`allowed_sudo_users`/`allow_pty`/`groups`/`command_policy` por host + secciones `callers` y `trusted_forwarders`
**`control-plane.example.json`** — referencia del control plane (cmd/control-plane): bloque `signer`, `approval` (notifier/callers/timeout), mTLS
**`deploy/sshd_config.snippet`** — fragmento de `sshd_config` + sudoers NOPASSWD para hosts gestionados

---

## Análisis competitivo (referencia)

Incorporado en `README.md` (sección *Comparison with existing solutions*). Resumen ejecutivo:

| Herramienta | Similitud | Diferencia clave |
|---|---|---|
| **Teleport** | Certs efímeros + MCP AI (2025) + RBAC | Control-plane cluster; órdenes de magnitud más pesado. Su *Agentic Identity Framework* (ene 2026) cubre el mismo threat model. |
| **Vault SSH engine** | CA efímera + soporte HSM/KMS | Solo firma; sin capa de ejecución ni MCP nativo propio. Mucho más pesado operativamente. |
| **Smallstep SSH CA** | CA efímera + OIDC/SSO | Solo firma; sin broker MCP ni capa de ejecución. |
| **StrongDM** | Oculta credenciales al modelo | Usa secretos de larga duración (no certs efímeros); más débil ante exfiltración. |
| **ssh-mcp** | MCP + control SSH | Clave SSH estática — el problema exacto que este broker resuelve. |
| **CyberArk PAM** | Cert-por-sesión + auditoría | Enterprise cerrado; orientado a operadores humanos, no a agentes IA. |

**Conclusión:** ssh-broker cubre un nicho específico — MCP nativo + certs efímeros en memoria + signer separado + log de auditoría encadenado criptográficamente — en un binario Go sin cluster. Los referentes de producción para los pendientes abiertos son:
- **HSM/KMS para la clave CA:** ver [Vault SSH con managed keys](https://developer.hashicorp.com/vault/docs/enterprise/managed-keys/ssh-secret-engine) y la implementación de Teleport como referencia de diseño.
- **Rate limiting:** Teleport y Vault ambos lo implementan por identidad de cliente.
- **Una CA por grupo:** Vault soporta roles de CA independientes por política; Teleport por host role.

---

## Estado del plan de pruebas (v1.7.1)

130 casos totales en 11 paquetes. Resumen por componente:

| Paquete | Casos | Cobertura |
|---|---|---|
| `internal/ca` | 4 | ✅ Completa: sign, bastion, TTL, cert verify |
| `internal/signer` | 39 | ✅ Completa: policy, RBAC, sudo, PTY, dry-run, approval gate |
| `internal/control` | 39 | ✅ **Ampliado (v1.8.0)**: approval registry, behavior tracker, Teams notifier (18 casos: formatos, facts, URL template, seguridad, errores HTTP) |
| `internal/oauth` | 5 | ✅ Completa: valid/expired/wrong-aud/bad-sig/missing-claim |
| `internal/audit` | 11 | ✅ **Nuevo (v1.7.1)**: cadena hash, firmas Ed25519, restoreChain, maybeRotate |
| `internal/broker` | 25 | ✅ **Ampliado (v1.7.1)**: sessionManager, límites M2, C1 ownership, M5 newlines, helpers |
| `cmd/control-plane` | 8 | ✅ Completa: forwarding, approval flow, behavior, ownership |
| `cmd/signer` | 4 | ✅ resolveCaller (4 sub-tests) |
| `cmd/mcp-broker-http` | 3 | ✅ OAuth auth, 401, RFC 9728 metadata |
| `cmd/broker-ctl` | 17 | ✅ **Nuevo (v1.7.1)**: verifyLog (7 casos), lastNLines, parseAuditTime, splitComma, boolStr, auditDetail |

### Gaps conocidos pendientes (media/baja prioridad)

- **`cmd/signer/main.go` — handlers HTTP** (`handleSign`, `handleHosts`, `handleReload`): solo `resolveCaller` tiene test. Los handlers se ejercitan indirectamente a través del `stubSigner` en `cmd/control-plane`, pero no el signer real. Patrón para implementarlos: `httptest.Server` + TLS sintético, igual que `cmd/control-plane/main_test.go`.
- **`internal/ssh` (con sshd embebido)**: `limitedWriter` y helpers de shell son puramente unitarios y sencillos; el protocolo de marcadores de `ShellSession.Exec`, `OpenShell` y `OpenShellPTY` requieren un servidor SSH real o la librería `gliderlabs/ssh`.
- **`cmd/broker-ctl` — subcomandos restantes**: `cmdHostAdd`, `cmdHostList`, `cmdHostRemove`, `cmdReload`, `cmdApprovalDecide` y `sshKeyscan` no tienen tests (requieren ficheros reales o mocks de `exec.Command`).



1. **El signer debe estar corriendo** antes de arrancar el broker (o de que OpenCode conecte al MCP). Arrancar siempre con `./signer.sh start` antes de abrir OpenCode.
2. **`hosts_refresh_seconds: 30`** está configurado para desarrollo. En producción subir a 300 (5 min) o más.
3. El primer paso para un **caso real de integración** es añadir un host con `broker-ctl host add` y configurar el sshd del servidor remoto con la `pki/ssh_ca.pub` como `TrustedUserCAKeys`. Después ejecutar `broker-ctl reload`.
4. **Recarga sin reinicio (implementado)**: tras editar `signer.json`, aplicar con `kill -HUP "$(cat signer.pid)"` o `POST /v1/reload` (mTLS, desde un CN en `reload_callers`). Recarga hosts/`max_ttl`/`ca_key`; `listen`/TLS/`audit_log` siguen necesitando `./signer.sh restart`.
5. La **separación física broker/signer** (máquinas distintas) requeriría: nuevo SAN en el cert del signer con la IP/hostname real, y actualizar `config.json` del broker con esa URL.
6. Para usar **elevación en un host real**: añadir `allow_sudo: true` en `signer.json` para ese host, recargar el signer (`kill -HUP` o `/v1/reload`), y configurar `sudoers NOPASSWD` en el host remoto. Verificar con `ssh_execute(server, "id", sudo=true)`.
7. Para usar **PTY**: añadir `allow_pty: true` en `signer.json` para ese host, recargar el signer (`kill -HUP` o `/v1/reload`). Usar `ssh_execute(..., pty=true)` para one-shot o `ssh_session_open(server, mode="pty")` para sesión interactiva.
8. Para usar **RBAC por grupos (broker mTLS)**: añadir `"groups": ["nombre-grupo"]` en cada host de `signer.json`, y una sección `"callers": { "CN-del-broker": { "allowed_groups": ["nombre-grupo"] } }`. Recargar con `kill -HUP "$(cat signer.pid)"`. Un CN ausente de `callers` no tiene restricción (backward compatible). Para un nuevo broker restringido: emitir un cert con nuevo CN firmado por `pki/mtls_ca.crt` y añadirlo a `callers`. Si un host tiene `"jump": "bastion"`, incluir el bastión en los mismos grupos.
9. Para usar **frontend HTTP+OAuth** (`cmd/mcp-broker-http`): configurar el bloque `oauth` y `resource_url` en `config.json` (ver `config.example.json`). Compilar con `go build -o ~/bin/mcp-broker-http ./cmd/mcp-broker-http`. Proveer certificado TLS (`server_cert`/`server_key`) — no hace falta `client_ca` porque la autenticación la aporta el bearer token. Para RBAC por usuario añadir `"groups_claim": "groups"` en el bloque `oauth` y añadir el campo `groups` a los hosts en `signer.json` correspondientes.
