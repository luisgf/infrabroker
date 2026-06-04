# Handoff: SSH Broker con CA Efímera para Agentes de IA

> Documento de traspaso para retomar la sesión de desarrollo. Última actualización: 2026-06-04 (fix auditoría signer).

---

## Qué se construyó y por qué

El problema de partida: un modelo de IA necesita ejecutar comandos en hosts Linux por SSH, pero las claves SSH estáticas son exfiltrables (prompt injection, volcado de memoria) y una vez robadas sirven para siempre.

La solución es un **broker SSH** que actúa como intermediario: el modelo nunca recibe ninguna credencial, solo el resultado de la ejecución (`stdout / stderr / exit_code`). Por cada operación el broker genera un par Ed25519 efímero **en memoria** (nunca toca disco), obtiene un certificado SSH firmado por una CA de corta duración, abre la conexión SSH con ese cert, y descarta el material al terminar.

El sistema opera en **modo remoto (producción)**: un servicio independiente (`cmd/signer`) custodia la clave CA y la política. El broker solo recibe el cert firmado. Un broker comprometido no puede robar la llave.

> El modo local (single-binary, `ca_key` en el broker) sigue soportado en código pero ya no es la configuración activa. Ver `config.example.json` y la sección `buildSigner` en `engine.go`.

---

## Estado actual del código

```
/home/luislgf/sources/ssh-broker/
├── cmd/
│   ├── mcp-broker/main.go    # servidor MCP (stdio) — interfaz para el modelo
│   │                         # tools: ssh_execute, ssh_session_open/exec/close,
│   │                         # ssh_list_servers. Soporta sudo, sudo_user, pty.
│   ├── signer/main.go        # servicio de firma externo (HTTPS+mTLS)
│   │                         # endpoints: POST /v1/sign, GET /v1/hosts, POST /v1/reload
│   │                         # reload en caliente (hosts/max_ttl/ca_key) + SIGHUP
│   ├── broker-ctl/main.go    # CLI de gestión de signer.json
│   │                         # host add/list/remove, reload (SIGHUP local o HTTP mTLS)
│   │                         # preserva campos _comment al editar el JSON
│   └── broker/main.go        # frontend HTTP+mTLS alternativo (one-shot)
├── internal/
│   ├── ca/
│   │   ├── sign.go           # GenerateEphemeralKey + BuildAndSign(Constraints)
│   │   │                     # Constraints: AllowPTY → permit-pty en el cert
│   │   └── sign_test.go
│   ├── signer/
│   │   ├── signer.go         # Signer interface, Local, PolicyTable.Resolve
│   │   │                     # Intent: Sudo/SudoUser/PTY
│   │   │                     # HostPolicy: allow_sudo/allowed_sudo_users/allow_pty/groups
│   │   │                     # CallerPolicy/CallerTable: RBAC por grupos (CN→allowed_groups)
│   │   │                     # HostSetForCaller: calcula hosts accesibles por CN
│   │   │                     # Issued: ElevationPrefix (sesiones)
│   │   │                     # Resolve → (Constraints, elevationPrefix, error)
│   │   │                     # helpers: buildElevatedCommand, shellQuote, validación
│   │   ├── remote.go         # Remote: SignIntent + FetchHosts + WireHostInfo
│   │   │                     # WireRequest: sudo/sudo_user/pty
│   │   │                     # WireResponse: elevation_prefix
│   │   └── signer_test.go    # tests: TTL, authz, sudo, PTY, inyección, shellQuote,
│   │                         #        HostSetForCaller (grupos/denegación/múltiples/etc.)
│   ├── broker/
│   │   ├── engine.go         # Engine: ExecOptions{Sudo,SudoUser,PTY},
│   │   │                     # Execute, buildHops, buildHopsWithPrefix,
│   │   │                     # policyFromHosts (mapea allow_sudo/allow_pty)
│   │   ├── engine_test.go    # tests de resolveChain (ciclos, cadenas)
│   │   └── session.go        # sessionManager, OpenSession (mode=exec|shell|pty),
│   │                         # liveSession.elevationPrefix/.pty, SessionExec
│   ├── ssh/
│   │   ├── run.go            # Hop, Conn, Dial(hops), ExecOnce(opts...), Run
│   │   │                     # ExecOptions{PTY, Term, Rows, Cols}
│   │   └── shell.go          # OpenShell(client, shellCmd) — sin PTY, parametrizable
│   │                         # OpenShellPTY(client, shellCmd, opts) — con PTY
│   ├── audit/log.go          # Entry: Elevation string + PTY bool (omitempty)
│   │                         # log append-only firmado y encadenado (Ed25519)
│   └── auth/mtls.go          # ServerTLSConfig, ClientTLSConfig, CallerCN
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

**Binarios compilados:** `~/bin/mcp-broker` · `~/bin/signer` · `~/bin/broker-ctl`

**Estado de compilación y tests:** `go build ./...` ✅ · `go vet ./...` ✅ · `go test ./...` ✅

**MCP registrado en OpenCode:** `~/.config/opencode/opencode.json`

---

## Arquitectura en una página

```
Modelo de IA (Claude / OpenCode)
    │
    │  stdio MCP
    ▼
cmd/mcp-broker  ~/bin/mcp-broker              ← nunca tiene clave CA
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
| `ssh_execute` | `server, command [, sudo, sudo_user, pty, ttl_seconds]` | Un disparo. Cert con `force-command` (incluye sudo si procede). |
| `ssh_session_open` | `server [, mode, sudo, sudo_user, ttl_seconds]` | Abre sesión persistente. `mode`: `exec` \| `shell` \| `pty`. |
| `ssh_session_exec` | `session_id, command` | Ejecuta en sesión reusando conexión. |
| `ssh_session_close` | `session_id` | Cierra y libera. |
| `ssh_list_servers` | — | Lista hosts configurados (leídos del cache). |

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

El broker no declara hosts. Al arrancar llama a `GET /v1/hosts` (mTLS) y cachea `{addr, user, host_key, jump}`. Recarga cada `hosts_refresh_seconds` (actualmente 30s para desarrollo). Si la recarga falla, mantiene el cache anterior. La política (`principal`, `source_address`, `allowed_callers`, `allow_sudo`, etc.) nunca sale del signer.

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

### 10. RBAC por grupos: visibilidad y firma filtradas por CN

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
- [ ] **Una CA por grupo de hosts**: la config del signer acepta una sola `ca_key` global. Para aislar el compromiso de una CA a un subconjunto de hosts, añadir `group → ca_key` en el signer. Los grupos RBAC ya existen como concepto; habría que vincular cada grupo a una CA diferente.
- [x] **Auditoría del signer enriquecida**: `auditEmission()` ahora registra `host=FQDN` (en lugar del nombre lógico corto), `user` y `principal` en todos los eventos `issued`/`denied`. El signer hace lookup en la PolicyTable para obtener los valores reales; si el host no existe en la tabla (denegación por grupo), usa el nombre lógico como fallback.
- [x] **RBAC por grupos**: implementado. Campo `groups` por host + sección `callers` en `signer.json`. `GET /v1/hosts` filtra por grupos del caller; `POST /v1/sign` rechaza (403) hosts fuera del grupo antes de llegar a `Resolve()`. Backward compatible: CN ausente de `callers` = sin restricción.
- [x] **Recarga de `signer.json` sin reinicio**: implementado. `POST /v1/reload` (mTLS, gated por `reload_callers`) y `SIGHUP` recargan en caliente política de hosts, `max_ttl_seconds` y `ca_key`. Si la nueva config es inválida, se conserva el estado anterior. `listen`/TLS/`audit_log` siguen requiriendo reinicio. Auditado como `reloaded`/`reload-denied`/`reload-failed`.

### Media prioridad

- [ ] **KRL (Key Revocation List)**: añadir `RevokedKeys /etc/ssh/krl` en sshd y un endpoint `/v1/revoke` en el signer que genere la KRL por serial.
- [ ] **Logs a almacenamiento WORM**: enviar el log de auditoría (ya firmado y encadenado) a S3, GCS, Loki o SIEM en tiempo real.
- [ ] **Sesiones multi-instancia**: hoy el `sessionManager` es in-process. Con varias réplicas del broker hay que externalizar el estado a Redis con TTL.
- [ ] **Autenticación del modelo ante el broker**: en el modo MCP+stdio el aislamiento lo da el proceso. Para entornos multi-tenant añadir un token de sesión.
- [ ] **Lab e2e para sudo + PTY**: extender `lab/run_mcp_lab.sh` con un escenario que levante un `sshd` con `sudoers NOPASSWD` y verifique one-shot elevado, sesión `shell` elevada y sesión `pty`.

### Baja prioridad

- [ ] **Hosts dinámicos (sin declarar en signer.json)**: actualmente todos los hosts deben estar declarados. Se podría añadir un modo `allow_dynamic_hosts: true` en `config.json` donde el modelo suministra `addr/user/host_key/principal` en la llamada. Requiere cambios en el schema MCP, en `engine.go` y en el signer (política inline o wildcard `"*"`).
- [ ] **Grabación de sesión**: redirigir stdout/stderr de `mode=shell`/`mode=pty` a un grabador antes de devolverlos al broker.
- [ ] **Dashboard de auditoría**: visualizar los logs de emisión + ejecución correlados por `serial` (incluyendo los campos `elevation` y `pty`).
- [ ] **`allowed_sudo_commands` por host**: hoy la restricción de comandos la gestiona `sudoers` en el host. Se podría añadir una whitelist de comandos en la política del signer como segunda capa de defensa.

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

### Procedimiento: commit en `main` (docs, config, hotfix)

```bash
# 1. Ver la versión actual
git describe --tags --abbrev=0        # ej. v1.0.3

# 2. Comitear
git commit -m "descripción del cambio"

# 3. Etiquetar con Z+1
git tag v1.0.4
```

### Procedimiento: merge de rama de funcionalidad → `main`

```bash
# En main, tras el merge (Y+1, Z=0):
git merge feature/mi-funcionalidad

# Actualizar CHANGELOG.md con la nueva entrada vX.(Y+1).0
git add CHANGELOG.md
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
**`config.example.json`** — referencia con modo local y remoto documentados; incluye `allow_sudo`/`allow_pty`
**`signer.json`** — config activa del signer (fuente de verdad única de hosts)
**`signer.example.json`** — referencia con `allow_sudo`/`allowed_sudo_users`/`allow_pty`/`groups` por host + sección `callers`
**`deploy/sshd_config.snippet`** — fragmento de `sshd_config` + sudoers NOPASSWD para hosts gestionados

---

## Puntos de atención para la próxima sesión

1. **El signer debe estar corriendo** antes de arrancar el broker (o de que OpenCode conecte al MCP). Arrancar siempre con `./signer.sh start` antes de abrir OpenCode.
2. **`hosts_refresh_seconds: 30`** está configurado para desarrollo. En producción subir a 300 (5 min) o más.
3. El primer paso para un **caso real de integración** es añadir un host con `broker-ctl host add` y configurar el sshd del servidor remoto con la `pki/ssh_ca.pub` como `TrustedUserCAKeys`. Después ejecutar `broker-ctl reload`.
4. **Recarga sin reinicio (implementado)**: tras editar `signer.json`, aplicar con `kill -HUP "$(cat signer.pid)"` o `POST /v1/reload` (mTLS, desde un CN en `reload_callers`). Recarga hosts/`max_ttl`/`ca_key`; `listen`/TLS/`audit_log` siguen necesitando `./signer.sh restart`.
5. La **separación física broker/signer** (máquinas distintas) requeriría: nuevo SAN en el cert del signer con la IP/hostname real, y actualizar `config.json` del broker con esa URL.
6. Para usar **elevación en un host real**: añadir `allow_sudo: true` en `signer.json` para ese host, recargar el signer (`kill -HUP` o `/v1/reload`), y configurar `sudoers NOPASSWD` en el host remoto. Verificar con `ssh_execute(server, "id", sudo=true)`.
7. Para usar **PTY**: añadir `allow_pty: true` en `signer.json` para ese host, recargar el signer (`kill -HUP` o `/v1/reload`). Usar `ssh_execute(..., pty=true)` para one-shot o `ssh_session_open(server, mode="pty")` para sesión interactiva.
8. Para usar **RBAC por grupos**: añadir `"groups": ["nombre-grupo"]` en cada host de `signer.json`, y una sección `"callers": { "CN-del-broker": { "allowed_groups": ["nombre-grupo"] } }`. Recargar con `kill -HUP "$(cat signer.pid)"`. Un CN ausente de `callers` no tiene restricción (backward compatible). Para un nuevo broker restringido: emitir un cert con nuevo CN firmado por `pki/mtls_ca.crt` y añadirlo a `callers`. Si un host tiene `"jump": "bastion"`, incluir el bastión en los mismos grupos.
