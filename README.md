# ssh-broker

Broker de acceso SSH con **CA efímera** para agentes de IA. El modelo **nunca
recibe una credencial**: pide ejecutar un comando en un host y el broker firma un
certificado SSH efímero y acotado, abre la conexión él mismo y devuelve **solo la
salida del comando**.

Tres frontends sobre el mismo motor (`internal/broker`) y la misma superficie de tools
(`internal/mcpserver`):

- **MCP stdio (local, recomendado para uso personal)** — `cmd/mcp-broker`. Tools:
  - `ssh_execute(server, command [, sudo, sudo_user, pty])` — un disparo, cert con `force-command`.
  - `ssh_session_open(server, mode [, sudo, sudo_user])` / `ssh_session_exec(session_id, command)` /
    `ssh_session_close(session_id)` — sesión persistente (reuso de conexión).
  - `ssh_list_servers()`.
  Sin autenticación de transporte: el aislamiento lo da que el proceso lo arranca el
  propio usuario (modelo que recomienda la spec del MCP para stdio).
- **MCP HTTP+OAuth2/OIDC (remoto, multiusuario)** — `cmd/mcp-broker-http`, Streamable HTTP.
  Mismas tools, pero cada cliente se autentica con un **bearer token OIDC** que el broker
  valida localmente contra el JWKS del issuer. La identidad del usuario (`sub`/
  `preferred_username`) sustituye a `mcp-stdio` en la auditoría y, si el token porta grupos,
  se propaga al signer para **RBAC por usuario**. Publica `/.well-known/oauth-protected-resource`
  (RFC 9728) para el descubrimiento del cliente. Ver [Frontend MCP remoto](#frontend-mcp-remoto-oauth2oidc).
- **HTTP+mTLS** — `cmd/broker`, `POST /v1/ssh_run` (un disparo), para agentes por red
  autenticados con certificado de cliente.

## Modo de firma: local o servicio externo

El broker obtiene los certs a través de la interfaz `internal/signer`:

- **Local (single-binary):** el broker custodia la clave de CA (`ca_key`) y firma en
  proceso. La política (principal/source-address/allow_sudo/allow_pty) va inline en `hosts`. Sencillo.
- **Externo (recomendado para producción):** un **servicio de firma** (`cmd/signer`)
  custodia la clave de CA **y la política**; el broker le pide certs por HTTP+mTLS
  enviando una *intención* `{host, role, purpose, command?, sudo?, sudo_user?, pty?, ttl, pubkey}` y recibe el
  cert firmado. **El broker nunca tiene la clave de CA.** Se activa con el bloque
  `signer{ url, client_cert, client_key, ca }` en la config del broker.

Invariante: la **clave privada efímera se genera y se queda en el broker**; al
servicio solo viaja la pubkey. La política (principal, source-address, force-command
por propósito, port-forwarding de bastión, TTL, autorización por CN del broker,
autorización de sudo y PTY) la impone el servicio → un broker comprometido no puede
saltársela ni robar la llave.
Auditoría doble e independiente: emisión en el servicio + ejecución en el broker,
correladas por `serial`. Custodia de la clave: PEM hoy, `crypto.Signer` de
KMS/HSM/Secure Enclave después (seam en `ca.LoadCAFromPEM` / `signer.Local`).

Ver `signer.example.json` y el bloque `_signer_remoto_example` de `config.example.json`.

## ProxyJump y sesiones

- **ProxyJump/bastión:** un host con `"jump": "<otro-host>"` se alcanza a través de
  ese bastión (encadenable). El broker firma **un cert por salto** y abre canales
  `direct-tcpip`. El cert del bastión lleva `permit-port-forwarding`; el del destino
  no. ⚠️ El `source_address` del **destino** debe ser la IP de egreso del **bastión**
  (no del broker) — configúralo con el override `source_address` por host.
- **Sesiones (pool/mux):** una sesión es una conexión retenida; **un cert por
  conexión** (sin `force-command`) y los comandos van como canales sobre ella.
  - `mode=exec` (def.): cada comando aislado, stdout/stderr separados.
  - `mode=shell`: un `sh` que mantiene estado (`cd`, variables). Limitaciones: nada
    de comandos interactivos que pidan entrada ni salida binaria.
  - `mode=pty`: shell con PTY (pseudo-terminal). Para programas que comprueban
    `isatty()` o requieren TTY real. Stdout y stderr se mezclan.
  - El reaper cierra por `session_idle_seconds` / `session_max_seconds`.

## Elevación de privilegio (sudo NOPASSWD) y PTY

### sudo NOPASSWD

El broker soporta elevación de privilegio mediante `sudo -n` (no interactivo,
NOPASSWD). La autorización es **policy-gated en el signer**: un broker comprometido
no puede elevar en hosts que no lo permitan.

**Configuración (por host):**

| Campo (signer/config) | Descripción |
|---|---|
| `allow_sudo: true` | Habilita elevación en este host |
| `allowed_sudo_users: ["root","deploy"]` | Usuarios destino permitidos. Vacío = solo root |
| `allow_pty: true` | Permite `permit-pty` en el cert (necesario para `pty=true` / `mode=pty`) |

**Host-side** (`/etc/sudoers.d/broker`):

```
# Cuenta SSH 'deploy', elevación a root sin contraseña:
deploy ALL=(root) NOPASSWD: ALL

# Restringido a comandos concretos (recomendado en producción):
deploy ALL=(root) NOPASSWD: /usr/bin/systemctl, /usr/bin/journalctl
```

**Cómo funciona:**

- **One-shot** (`ssh_execute` con `sudo=true`): el signer hornea `sudo -n [- u U] -- /bin/sh -c '<cmd>'` en el `force-command` del cert. `sshd` lo impone; el broker no puede modificarlo. El prefijo forma parte del audit de emisión.
- **Sesión `exec`** con `sudo=true`: el signer devuelve `elevation_prefix`; el broker lo antepone a cada comando individualmente.
- **Sesión `shell`/`pty`** con `sudo=true`: el shell completo se lanza bajo `sudo -n [- u U] -- /bin/sh`. Toda la sesión es elevada.

### PTY

Un PTY es necesario para programas que llaman `isatty()` (editores, herramientas
interactivas, algunos scripts de diagnóstico).

- En `ssh_execute`: pasar `pty=true` (requiere `allow_pty=true` en la política).
- En `ssh_session_open`: usar `mode=pty` (implica `pty=true` automáticamente).
- Nota: con PTY `stdout` y `stderr` se **mezclan**; `Result.Stderr` estará vacío.

## Por qué

- **Anti-exfiltración (prompt injection):** la clave/cert efímeros viven solo en
  memoria del broker; nunca entran en el contexto del modelo.
- **Anti-reuso:** cada cert lleva TTL de minutos, `source-address` (IP del broker)
  y `force-command` (el comando solicitado, incluyendo el prefijo sudo si aplica). Inútil fuera de host/tiempo/IP.
- **Elevación controlada:** `allow_sudo` y `allowed_sudo_users` viven en el signer;
  el broker no puede escalar privilegios en hosts que no los tengan autorizados.
- **Robo de la CA acotado:** una CA por grupo de hosts; la clave de firma puede
  vivir en HSM/KMS vía `crypto.Signer` (`ca.NewFromSSHSigner`).
- **Auditoría/no repudio:** log append-only encadenado y firmado (Ed25519); campos
  `elevation` y `pty` en cada entrada; `sshd` con `LogLevel VERBOSE` correla por serial.

## Autenticación del cliente al broker

Tres frontends, tres mecanismos:

```
┌──────────────────────┬──────────────────────────────────┬────────────────────────┐
│  MCP stdio (local)   │  MCP HTTP+OAuth2/OIDC (red)      │  HTTP+mTLS (red)       │
│  cmd/mcp-broker      │  cmd/mcp-broker-http             │  cmd/broker            │
├──────────────────────┼──────────────────────────────────┼────────────────────────┤
│  Sin token.          │  Bearer token OIDC               │  Certificado TLS de    │
│  Aislamiento por     │  validado localmente             │  cliente (mTLS).       │
│  proceso (spec MCP). │  contra el JWKS del issuer.      │  CN del cert = caller. │
├──────────────────────┼──────────────────────────────────┼────────────────────────┤
│  Caller.ID =         │  Caller.ID = user_claim          │  Caller.ID = CN        │
│  "mcp-stdio"         │  Caller.Groups = groups_claim    │  del cert cliente      │
└──────────────────────┴──────────────────────────────────┴────────────────────────┘
```

### Flujo OAuth2/OIDC (cmd/mcp-broker-http)

```
  Cliente MCP                mcp-broker-http               IdP (OIDC Issuer)
  ───────────                ───────────────               ─────────────────
       │                           │                              │
       │── POST /mcp ─────────────►│                              │
       │                           │                              │
       │◄── 401 ───────────────────│                              │
       │    WWW-Authenticate:      │                              │
       │    Bearer resource_       │                              │
       │    metadata="https://…/   │                              │
       │    .well-known/oauth-     │                              │
       │    protected-resource"    │                              │
       │                           │                              │
       │── GET /.well-known/… ────►│                              │
       │◄── { authorization_       │                              │
       │      servers: [issuer] }  │                              │
       │                           │                              │
       │──── Authorization Code + PKCE ──────────────────────────►│
       │◄─── access_token (JWT) ──────────────────────────────────│
       │                           │                              │
       │── POST /mcp ─────────────►│                              │
       │   Authorization: Bearer   │── (al arrancar) GET JWKS ───►│
       │   <JWT>                   │   cacheado; rotación auto.   │
       │                           │                              │
       │                           │  Verifier.Verify(JWT)        │
       │                           │  ├─ firma (JWKS local,       │
       │                           │  │  sin round-trip)          │
       │                           │  ├─ iss / aud / exp          │
       │                           │  ├─ iat ≤ max_token_age      │
       │                           │  ├─ user_claim → UserID      │
       │                           │  └─ groups_claim → Groups    │
       │                           │                              │
       │◄── respuesta MCP ─────────│                              │
```

### Identidad propagada al signer

```
  Caller.ID     ──► audit log del broker (trazabilidad)
  Caller.Groups ──► Intent.EndUserGroups
                              │
                              │  HTTPS + mTLS (pki/broker.crt, CN=broker-1)
                              ▼
                         cmd/signer
                         POST /v1/sign
                         ├── RBAC por CN del broker
                         │   CallerTable: CN → allowed_groups
                         │
                         ├── RBAC por usuario (solo si EndUserGroups != nil)
                         │   hp.Groups ∩ EndUserGroups ≠ ∅
                         │
                         └── firma cert SSH efímero
```

## Autenticación del broker al servidor SSH

### ① Generación del par efímero

Por cada hop (bastión o destino) el broker genera un par Ed25519 en memoria:

```
  ca.GenerateEphemeralKey()
  ├── priv (Ed25519) ──► queda en broker, NUNCA sale del proceso
  └── pub            ──► se envía al signer junto con la intención
```

### ② El signer firma el certificado (HTTPS + mTLS)

```
  Intent ──────────────────────────────────────────► cmd/signer
  ├── host, role (bastion | target)                      │
  ├── command, sudo?, sudo_user?, pty?                   │ RBAC por CN del broker
  ├── end_user = Caller.ID                               │ RBAC por usuario
  ├── end_user_groups = Caller.Groups                    │ PolicyTable.Resolve
  └── pub (clave pública efímera)                        │
                                                         │ ca.BuildAndSign(caKey, pub, constraints)
  Certificate ◄────────────────────────────────────────── │
  ├── ValidPrincipals: ["host:web01"]      ← principal
  ├── ValidAfter / ValidBefore             ← TTL (≤ 15 min)
  ├── source-address: "10.0.1.5"          ← IP del broker (o del bastión)
  ├── force-command: "sudo -n -- /bin/sh…"← one-shot; vacío en sesiones
  ├── permit-port-forwarding              ← solo cert del bastión
  └── permit-pty                          ← si allow_pty y pty solicitado
```

### ③ Conexión SSH al servidor final

```
  broker                                        sshd (servidor destino :22)
  ──────                                        ──────────────────────────
     │
     │  TCP :22
     │─────────────────────────────────────────►
     │
     │  broker verifica host key del sshd
     │  FixedHostKey(hp.HostKey)                ← pinned en signer.json;
     │  rechaza si no coincide                    sin TOFU
     │
     │  presenta: certSigner{priv, cert}         sshd verifica:
     │─────────────────────────────────────────► ├─ firma del cert (TrustedUserCAKeys)
     │                                           ├─ principal ∈ AuthorizedPrincipals/<user>
     │                                           ├─ now ∈ [ValidAfter, ValidBefore]
     │                                           ├─ source-address = IP real del broker
     │                                           └─ impone force-command (si presente)
     │
     │◄── stdout / stderr / exit_code ───────────
```

### ④ ProxyJump: un certificado independiente por salto

```
  broker               bastión :22                 destino :22
  ──────               ───────────                 ───────────
     │                      │                            │
     │  TCP                 │                            │
     │─────────────────────►│                            │
     │  cert bastión:       │  sshd verifica:            │
     │  - principal         │  TrustedUserCAKeys,        │
     │  - sin force-cmd     │  principal, TTL,           │
     │  - permit-port-fwd   │  source-address            │
     │                      │                            │
     │  direct-tcpip ────────────────────────────────────►
     │  cert destino:                                     │  sshd verifica:
     │  - principal                                       │  TrustedUserCAKeys,
     │  - force-command (one-shot)                        │  principal, TTL,
     │  - source-address = IP del bastión                 │  source-address
     │  - sin permit-port-fwd                             │  = IP bastión
     │                                                    │
     │◄──────── stdout / stderr / exit_code ──────────────│
```

 y no integrarlo en `mcp-ssh-manager`

`mcp-ssh-manager` usa la librería Node **`ssh2` 1.17**, que **no soporta
autenticación de cliente por certificado** (verificado: con clave y cert en el
agente, `ssh2` ofrece solo la clave pelada, nunca el `ssh-ed25519-cert-v01`). Por
eso el broker se expone como su propio servidor MCP, que sí firma y presenta
certificados correctamente (probado contra OpenSSH `sshd` en `lab/`).

## Estructura

| Ruta | Función |
|------|---------|
| `internal/broker/engine.go` | Núcleo: config + cadena de saltos + ejecuta+audita (ExecOptions: Sudo/SudoUser/PTY) |
| `internal/broker/session.go` | Registro de sesiones (pool) + reaper + elevación en sesiones |
| `internal/signer/*` | Interfaz `Signer`, `Local`/`Remote`, política e intención (allow_sudo, allow_pty) |
| `cmd/signer/main.go` | Servicio de firma externo (HTTP+mTLS) + audit de emisión (elevación) |
| `internal/ca/sign.go` | `GenerateEphemeralKey` + `BuildAndSign` (permit-pty, permit-port-forwarding) |
| `internal/ssh/run.go` | Dial multi-salto (`Dial`/`Conn`) + ejecución one-shot con/sin PTY |
| `internal/ssh/shell.go` | Shell con estado: sin PTY (`OpenShell`) y con PTY (`OpenShellPTY`) |
| `internal/audit/log.go` | Log firmado y encadenado (campos `elevation`, `pty`) |
| `internal/auth/mtls.go` | mTLS del frontend HTTP + TLS solo-servidor para HTTP+OAuth; identidad del llamante |
| `internal/mcpserver/*` | Registro compartido de tools (stdio y HTTP) parametrizado por la identidad del llamante |
| `internal/oauth/verifier.go` | Validación de bearer tokens OIDC vía JWKS (go-oidc); extrae usuario y grupos |
| `cmd/mcp-broker/main.go` | Servidor MCP (stdio): tools con Sudo/SudoUser/PTY |
| `cmd/mcp-broker-http/main.go` | Servidor MCP remoto (Streamable HTTP + OAuth2/OIDC) con PRM (RFC 9728) |
| `cmd/broker/main.go` | Frontend HTTP `POST /v1/ssh_run` (mTLS) con Sudo/SudoUser/PTY |
| `deploy/sshd_config.snippet` | Config a aplicar en cada host gestionado (PTY + sudoers) |
| `lab/run_mcp_lab.sh` | Laboratorio e2e del MCP |
| `lab/run_lab.sh` | Laboratorio e2e del frontend HTTP/mTLS |

## Registrar el MCP en Claude Code

```bash
go build -o ~/bin/mcp-broker ./cmd/mcp-broker
```

En `~/.claude.json` (o `claude mcp add`):

```json
"ssh-broker": {
  "type": "stdio",
  "command": "/Users/<tú>/bin/mcp-broker",
  "args": ["-config", "/ruta/segura/config.json"]
}
```

El modelo entonces dispone de `ssh_execute(server, command [, sudo, sudo_user, pty])` y `ssh_list_servers`.
Ver `config.example.json` para el formato de hosts (el frontend HTTP usa los mismos
campos más los de TLS).

## Registrar el MCP en OpenCode

```bash
go build -o ~/bin/mcp-broker ./cmd/mcp-broker
```

En `~/.config/opencode/opencode.json`:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "ssh-broker": {
      "type": "local",
      "command": ["/home/<tú>/bin/mcp-broker", "-config", "/ruta/segura/config.json"],
      "enabled": true
    }
  }
}
```

La diferencia respecto a Claude Code: `type` es `"local"` (no `"stdio"`) y `command` es un array donde el primer elemento es el binario y el resto son los argumentos.

## Frontend MCP remoto (OAuth2/OIDC)

Para exponer el broker por red a varios usuarios, `cmd/mcp-broker-http` sirve las mismas
tools sobre **Streamable HTTP** y exige un **bearer token OIDC**. Encaja con la
[spec de autorización del MCP](https://modelcontextprotocol.io/docs/tutorials/security/authorization),
que reserva OAuth a los transportes HTTP (en stdio el aislamiento lo da el proceso, no OAuth).

Flujo:

1. El cliente MCP (VS Code, Claude Code, …) conecta; el broker responde `401` con
   `WWW-Authenticate` apuntando a `/.well-known/oauth-protected-resource` (RFC 9728).
2. El cliente descubre el Authorization Server (issuer) y hace **Authorization Code + PKCE**.
3. El cliente reintenta con `Authorization: Bearer <token>`. El broker valida el JWT
   **localmente** contra el JWKS del issuer (firma, `iss`, `aud`, `exp`) — sin round-trip
   por petición ni client_secret.
4. La identidad del token (`user_claim`, p. ej. `preferred_username`) se registra en la
   auditoría. Si el token porta `groups_claim`, esos grupos se **propagan al signer**, que
   exige que el host solicitado comparta alguno de los grupos del usuario (RBAC por usuario,
   adicional al RBAC por CN mTLS del broker).

Config (bloque `oauth` + `resource_url` en la config del broker, ver `config.example.json`):

```json
"listen": ":8443",
"server_cert": "pki/broker.crt",
"server_key": "pki/broker.key",
"resource_url": "https://ssh-broker.example.com",
"oauth": {
  "issuer": "https://keycloak.example.com/realms/infra",
  "audience": "https://ssh-broker.example.com",
  "required_scopes": ["mcp:tools"],
  "user_claim": "preferred_username",
  "groups_claim": "groups",
  "max_token_age_seconds": 3600
}
```

```bash
go build -o ~/bin/mcp-broker-http ./cmd/mcp-broker-http
~/bin/mcp-broker-http -config /ruta/segura/config.json
```

El RBAC por usuario solo se activa cuando el token trae grupos; las peticiones stdio y mTLS
(sin grupos de usuario) siguen autorizándose como hasta ahora (compatibilidad).

## Recarga en caliente del signer

El servicio de firma puede releer su `signer.json` sin reiniciar, sustituyendo
atómicamente la **política de hosts**, `max_ttl_seconds` y la **clave de CA**. Si
la nueva config es inválida, el estado anterior se conserva intacto. `listen`, el
TLS y `audit_log` requieren reinicio (reabren sockets/ficheros).

Dos disparadores:

- **`POST /v1/reload`** (mTLS): solo los CNs listados en `reload_callers` pueden
  invocarlo (resto → 403). Si `reload_callers` está vacío, el endpoint HTTP queda
  deshabilitado. Respuesta: `{"status":"ok","hosts":N}`.
- **`SIGHUP`** (`kill -HUP <pid>`): recarga local al host, no pasa por la
  allowlist. Útil desde `signer.sh`.

Toda recarga se audita (`reloaded` / `reload-denied` / `reload-failed`).

```bash
# vía endpoint (cert de un CN en reload_callers)
curl --cert broker-admin.crt --key broker-admin.key --cacert signer_ca.crt \
     -X POST https://127.0.0.1:9443/v1/reload
# vía señal
kill -HUP "$(cat signer.pid)"
```

## Seguridad (v1.4.1)

Doce controles de hardening añadidos en v1.4.1 (revisión MCP/Snyk):

| Control | Archivo(s) | Detalle |
|---|---|---|
| Verificación de propietario de sesión (C1) | `internal/broker/session.go` | `SessionExec`/`CloseSession` verifican que el caller sea el propietario de la sesión antes de operar. |
| Timeouts HTTP (A1) | `cmd/signer/main.go`, `cmd/mcp-broker-http/main.go` | `ReadTimeout`, `WriteTimeout` (solo signer), `IdleTimeout` en `http.Server`. |
| Límite de payload (A2) | `cmd/signer/main.go`, `internal/signer/remote.go` | `MaxBytesReader(64 KiB)` en `/v1/sign`; `LimitReader(1 MiB)` en las respuestas de `remote.go`. |
| Timeout de ejecución SSH + límite de salida (A3) | `internal/ssh/run.go`, `internal/ssh/shell.go` | Timeout por defecto 10 min; salida limitada a 10 MiB; `SIGTERM` en timeout. |
| Restauración de cadena de auditoría (A4) | `internal/audit/log.go` | Al reiniciar, `restoreChain()` recupera `seq`+`prevHash` del último registro vía `bufio.Scanner`. |
| Errores de auditoría visibles (M1) | `internal/broker/engine.go`, `cmd/signer/main.go` | `auditLog.Append` ya no silencia errores con `_ =`; se registran con `log.Printf`. |
| Límite de sesiones activas (M2) | `internal/broker/session.go` | `maxSessionsGlobal=200`, `maxSessionsPerCaller=20`. |
| Validación de antigüedad del JWT (M3) | `internal/oauth/verifier.go` | `OAuthConfig.MaxTokenAgeSeconds` valida el claim `iat`; recomendado 3600 s en producción. |
| Rechazo de newlines en comandos (M5) | `internal/broker/session.go` | `SessionExec` rechaza comandos con `\n`/`\r`. |
| Aviso en carga de CA desde PEM (L1) | `internal/ca/sign.go` | `LoadCAFromPEM` emite `[WARN]` en runtime. |
| Rotación del log de auditoría (L2) | `internal/audit/log.go` | `maybeRotate()` rota el fichero al superar 100 MiB. |
| Pre-validación de inputs MCP (L4) | `internal/mcpserver/tools.go` | `validateInput()` limita campos a 64 KiB y rechaza bytes nulos antes de llegar al engine. |

## Probar

```bash
bash lab/run_signer_lab.sh # servicio de firma externo: broker SIN ca_key + política + denegación
bash lab/run_mcp_lab.sh    # bastión + destino (Jump) + escenario MCP (one-shot, exec, shell)
bash lab/run_lab.sh        # frontend HTTP/mTLS
go test ./...              # cert build, política del firmante (autz/TTL/sudo/PTY), resolución de saltos
```

## Producción: pendientes

- Respaldar la clave de CA del servicio con un `crypto.Signer` de
  HSM/KMS/Secure Enclave (seam en `ca.LoadCAFromPEM` → `ssh.Signer`).
- Rate limit por CN de broker en el servicio de firma (límite anti-DoS/abuso).
- Una CA distinta por grupo de hosts (selección por `host` en config).
- KRL para revocación de emergencia por serial (ver `deploy/sshd_config.snippet`).
- Rotación/segregación de la clave de auditoría; envío del log a almacenamiento
  WORM o servicio externo.
- Escenario de lab e2e para sudo + PTY (`lab/run_mcp_lab.sh`).
