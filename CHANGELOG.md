# Changelog

## [v1.5.0] - 2026-06-06

### Added
- **AI-action firewall — command-level policy (Phase A).** Hosts may now declare a `command_policy` (in `signer.json` for external mode, or in the broker's `config.json` for local mode) that restricts which commands a one-shot `ssh_execute` may run:
  - `mode: "allowlist"` — the command must match at least one `allow` regex.
  - `mode: "denylist"` — the command must not match any `deny` regex.
  - `require_approval: [...]` — regexes marking commands that will require human approval (orchestrated by the control plane in Phase B; the signer surfaces the flag).
  - Enforcement is **authoritative for one-shot** (the signer bakes the command into the cert's `force-command`; a compromised broker cannot evade it). Rules are RE2 regexes (linear time, no catastrophic backtracking).
  - Hosts with any `command_policy` rule **reject persistent sessions** (the command is not verifiable at signing time).
  - Implemented in new `internal/signer/cmdpolicy.go` (shared library) + `HostPolicy.CommandPolicy`; `PolicyTable.Resolve` now returns a richer `Decision` struct.
- **Dry-run / simulation mode.** New `dry_run` parameter on `ssh_execute`: resolves host policy (allow/deny + whether approval would be required) and returns the decision **without connecting or executing**. Lets the model preview an action before committing. Threaded through `Intent.DryRun` → `WireRequest.dry_run` → `WireResponse.decision`; the broker short-circuits before dialing.
- Audit: new `policy_rule` and `dry_run` fields on audit entries; new outcomes `dry_run_allowed` / `dry_run_denied`.
- `signer.example.json`: `web02` now demonstrates a `command_policy` (allowlist + `require_approval`).

### Changed
- `PolicyTable.Resolve` signature changed from `(ca.Constraints, string, error)` to `(Decision, error)` (internal API; all call sites and tests updated).

## [v1.4.6] - 2026-06-05

### Added
- `cmd/broker-ctl`: `audit` subcommand with three sub-subcommands:
  - `audit tail --log <path> [-n N]` — streams new audit log entries in real time (polls every 500 ms, handles log rotation by size decrease); shows last N lines before following.
  - `audit show --log <path> [--host] [--caller] [--outcome] [--serial] [--since] [--limit] [--json]` — searches and filters audit entries; `--json` emits raw JSON lines compatible with `jq`.
  - `audit verify --log <path> [--key seed]` — verifies SHA-256 hash chain integrity; optionally verifies Ed25519 signatures when `--key` is provided. Exits 1 and prints affected sequence numbers on failure.
- `USAGE.md` §7 "Reviewing audit logs": live tail usage, filter examples, `jq` pipelines for correlation by `serial`, `verify` examples with and without `--key`, and full audit entry field reference table.
- `HANDOFF.md`: broker-ctl section expanded with all `audit` subcommand examples (tail, show, show --json, verify with/without key).

## [v1.4.5] - 2026-06-05

### Added
- `USAGE.md`: practical usage guide for all five MCP tools (`ssh_list_servers`, `ssh_execute`, `ssh_session_open`, `ssh_session_exec`, `ssh_session_close`). Covers one-shot commands, persistent sessions (exec/shell/pty modes), sudo escalation, PTY usage, common operational patterns, error handling, and a quick-reference table.
- `HANDOFF.md`: added mandatory `USAGE.md` update rule (step 4 in "Paso obligatorio antes de cada commit") — must be updated when a tool is added, removed, renamed, or its parameters/behaviour change.

## [v1.4.4] - 2026-06-05

### Added
- `API.md`: new dedicated API reference document (English) covering all HTTP endpoints across all three services — signer (`POST /v1/sign`, `GET /v1/hosts`, `POST /v1/reload`), broker HTTP (`POST /v1/ssh_run`), and MCP HTTP (`GET /.well-known/oauth-protected-resource` + Streamable HTTP tools). Each endpoint documents auth requirements, request/response schemas, error codes, and audit outcomes. Includes audit log field reference, outcome value table, `jq` correlation examples, and Ed25519 chain integrity description.
- `README.md`: `## API Reference` section replaced with a summary table + link to `API.md`.
- `HANDOFF.md`: added mandatory `API.md` update rule (step 3 in "Paso obligatorio antes de cada commit") and English language rule for all new commit messages, documentation files, and code comments.

### Changed
- `README.md`: full rewrite in English. All sections translated; broken `## Por qué un MCP propio` heading fixed; content reorganized to match current feature set (v1.4.3).

## [v1.4.3] - 2026-06-05

### Added
- `README.md`: sección `## Autenticación del cliente al broker` con tabla comparativa de los tres frontends, flujo OAuth2/OIDC paso a paso y diagrama de propagación de identidad al signer.
- `README.md`: sección `## Autenticación del broker al servidor SSH` con diagramas de generación del par efímero, firma del certificado por el signer (campos del cert: principal, TTL, source-address, force-command, permit-pty), handshake SSH con verificación de host key pinned y verificaciones del sshd; y flujo ProxyJump con un certificado independiente por salto.

### Fixed
- `README.md`: añadido header `## Probar` faltante sobre el bloque bash de laboratorio.

## [v1.4.2] - 2026-06-05

### Added
- `README.md`: sección "Registrar el MCP en OpenCode" con la config correcta para `~/.config/opencode/opencode.json` (`type: "local"`, `command` como array).

## [v1.4.1] - 2026-06-05

### Security
- **C1 (crítica)** `internal/broker/session.go`: `SessionExec` y `CloseSession` verifican que el caller sea el propietario de la sesión antes de operar; `CloseSession` hace get-antes-de-delete para no borrar sesiones ajenas.
- **A1 (alta)** `cmd/signer/main.go`, `cmd/mcp-broker-http/main.go`: `ReadTimeout`, `WriteTimeout` (solo signer), `IdleTimeout` en `http.Server`.
- **A2 (alta)** `cmd/signer/main.go`, `internal/signer/remote.go`: `http.MaxBytesReader(64 KiB)` en `/v1/sign`; `io.LimitReader(1 MiB)` en ambos `io.ReadAll` de `remote.go`.
- **A3 (alta)** `internal/ssh/run.go`, `internal/ssh/shell.go`: `defaultExecTimeout=10 min`; `maxOutputBytes=10 MiB`; `limitedWriter`; `session.Signal(SIGTERM)` en timeout; shell/pty descarta bytes excedentes.
- **A4 (alta)** `internal/audit/log.go`: `restoreChain()` con `bufio.Scanner` (buffer 256 KiB) restaura `seq`+`prevHash` del último registro al reiniciar; sin esta corrección el broker rompía la cadena de auditoría en cada reinicio.
- **M1 (media)** `internal/broker/engine.go`, `cmd/signer/main.go`: errores de `auditLog.Append` ya no silenciados con `_ =`; se registran con `log.Printf`.
- **M2 (media)** `internal/broker/session.go`: `maxSessionsGlobal=200`, `maxSessionsPerCaller=20`; `sessionManager.add()` retorna `error`.
- **M3 (media)** `internal/oauth/verifier.go`, `internal/broker/engine.go`, `cmd/mcp-broker-http/main.go`: campo `MaxTokenAge` en `Config`/`Verifier`; valida el claim `iat` si `maxTokenAge > 0`; `OAuthConfig.MaxTokenAgeSeconds` (recomendado: 3600).
- **M5 (media)** `internal/broker/session.go`: `SessionExec` rechaza comandos con `\n` o `\r`.
- **L1 (baja)** `internal/ca/sign.go`: `LoadCAFromPEM` emite `[WARN]` en runtime indicando que solo es apto para laboratorio.
- **L2 (baja)** `internal/audit/log.go`: `maybeRotate()` rota el fichero de auditoría al superar 100 MiB, renombrando a `<path>.20060102T150405Z`.
- **L4 (baja)** `internal/mcpserver/tools.go`: `validateInput()` limita todos los campos de entrada a 64 KiB y rechaza bytes nulos; se invoca en los 4 tool handlers antes de llegar al engine.

## [v1.4.0] - 2026-06-04

### Added
- Frontend MCP remoto `cmd/mcp-broker-http`: Streamable HTTP + OAuth2/OIDC (RFC 9728 + Authorization Code + PKCE)
- Validación de bearer tokens OIDC **localmente** contra el JWKS del issuer (`go-oidc`): sin round-trip por petición, sin `client_secret`
- Identidad OIDC (`user_claim`, p. ej. `preferred_username`) como `Caller.ID` en la auditoría del broker
- RBAC por usuario final: si el token porta `groups_claim`, los grupos se propagan al signer como `EndUserGroups`; el signer exige `hp.Groups ∩ EndUserGroups ≠ ∅` (adicional al RBAC por CN mTLS)
- `/.well-known/oauth-protected-resource` (RFC 9728) para descubrimiento del Authorization Server por el cliente MCP
- `internal/mcpserver`: tools extraídas a paquete compartido; ambos frontends (stdio y HTTP) usan exactamente el mismo `Register(eng, callerFn)`
- `internal/oauth/verifier.go`: `NewVerifier` + `Verify` con extracción de `UserID`, `Scopes` y grupos; tests con IdP OIDC falso (`httptest` + `go-jose` RSA)
- `internal/auth/mtls.go`: `ServerTLSConfigNoClientAuth` para el frontend HTTP+OAuth (TLS sin mTLS)
- `OAuthConfig` y `ResourceURL` en `broker.Config`; `CallerFunc` inyectable en `mcpserver.New`



### Changed
- Descripciones de tools MCP mejoradas para reducir errores del modelo:
  - `ssh_execute` y `ssh_session_open`: guía explícita de no reintentar cuando `allow_sudo`/`allow_pty` es false
  - `executeOutput`: documentados `exit_code` (fallo de comando ≠ error de tool), `stderr` (vacío con pty) y `serial` (solo auditoría)
  - `ttl_seconds`: clarificado como opcional; se usa el máximo de la política del host si se omite
  - Cross-reference `ssh_execute` vs `ssh_session_open`: cuándo preferir cada uno
  - `ssh_session_open`/`ssh_session_close`: advertencia de cerrar siempre la sesión
  - `ssh_session_exec`: documenta persistencia de estado por modo
  - `ssh_list_servers`: explica qué implica `allow_sudo`/`allow_pty` false
  - `sessionOpenInput.mode`: describe los tres modos con casos de uso concretos
- Versión `Implementation` del servidor MCP sincronizada: `0.2.0` → `1.2.0`

## [v1.2.0] - 2026-06-04

### Added
- `ssh_list_servers` ahora devuelve capacidades por host: `allow_sudo`, `allow_pty` y `jump`, para que el modelo pueda elegir la estrategia de ejecución correcta sin intentar y fallar
- `GET /v1/hosts` del signer incluye `allow_sudo` y `allow_pty` en la respuesta (`WireHostInfo`)
- `HostInfo` y `ServerInfo` (broker interno) propagan `AllowSudo`/`AllowPTY` desde ambos modos (local y remoto)
- Descriptions de `ssh_execute` y `ssh_session_open` actualizadas para instruir al modelo a consultar capacidades antes de usar `sudo`/`pty`

## [v1.1.1] - 2026-06-04

### Fixed
- Auditoría del signer: el campo `host` ahora registra el FQDN/addr real (`hp.Addr`) en lugar del nombre lógico corto
- Auditoría del signer: los campos `user` y `principal` ahora se rellenan correctamente en eventos `issued` y `denied`

## [v1.1.0] - 2026-06-04

### Added
- CLI `broker-ctl` (`cmd/broker-ctl`) para gestión de `signer.json` sin editar JSON a mano
  - `host add`: añade o actualiza un host con todos sus parámetros; `--scan` ejecuta `ssh-keyscan` automáticamente
  - `host list`: tabla formateada de hosts con addr, user, principal, TTL, sudo, PTY, groups
  - `host remove`: elimina un host de la configuración
  - `reload`: SIGHUP si el signer corre en local (detecta `signer.pid`), POST `/v1/reload` mTLS como fallback
  - Preserva campos `_comment` y anotaciones del JSON al escribir (escritura atómica vía rename)

## [v1.0.0] - 2026-06-03

### Added
- Broker SSH con generación de claves Ed25519 efímeras en memoria (nunca tocan disco)
- Servicio de firma externo (`cmd/signer`) con custodia exclusiva de la clave CA SSH vía HTTPS+mTLS
- Interfaz MCP stdio (`cmd/mcp-broker`): herramientas `ssh_execute`, `ssh_session_open`, `ssh_session_exec`, `ssh_session_close`, `ssh_list_servers`
- Soporte de ProxyJump (cadenas de salto a través de bastión)
- Elevación `sudo NOPASSWD` policy-gated en el signer: `allow_sudo`, `allowed_sudo_users`, sanitización anti-inyección
- Sesiones persistentes con tres modos: `exec`, `shell` (sin PTY) y `pty` (con PTY)
- Soporte de PTY en one-shot y sesiones: `allow_pty` por host, `permit-pty` en el certificado
- Recarga en caliente de `signer.json` sin reinicio: `SIGHUP` y `POST /v1/reload` (mTLS, gated por `reload_callers`)
- Auditoría triple firmada y encadenada por `serial` (Ed25519 + SHA-256): signer, broker y sshd correlados
- RBAC por grupos: campo `groups` por host y sección `callers` en `signer.json`; `GET /v1/hosts` filtra por grupos del caller, `POST /v1/sign` rechaza hosts fuera del grupo antes de `Resolve()`
- Frontend HTTP+mTLS alternativo (`cmd/broker`) para uso one-shot sin MCP
- PKI local generada: CA SSH Ed25519, CA mTLS, certs servidor/cliente, semillas de auditoría
- Scripts de laboratorio e2e: `lab/run_mcp_lab.sh`, `lab/run_signer_lab.sh`
