# API Reference — ssh-broker

This document describes all HTTP endpoints exposed by the `ssh-broker` services.
Keep this file up to date whenever an endpoint is added, removed, renamed, or its
request/response schema changes.

---

## Table of Contents

- [Signer API](#signer-api) — `cmd/signer` · HTTPS + mTLS · default `:9443`
  - [POST /v1/sign](#post-v1sign)
  - [GET /v1/hosts](#get-v1hosts)
  - [POST /v1/reload](#post-v1reload)
- [Broker HTTP API](#broker-http-api) — `cmd/broker` · HTTPS + mTLS
  - [POST /v1/ssh\_run](#post-v1ssh_run)
- [MCP HTTP API](#mcp-http-api) — `cmd/mcp-broker-http` · HTTPS + OAuth2/OIDC · default `:8443`
  - [GET /.well-known/oauth-protected-resource](#get-well-knownoauth-protected-resource)
  - [MCP Streamable HTTP — tools](#mcp-streamable-http--tools)

---

## Signer API

**Service:** `cmd/signer`  
**Transport:** HTTPS + mutual TLS (mTLS)  
**Default listen address:** `:9443` (configurable via `listen` in `signer.json`)  
**Auth:** every request requires a valid TLS client certificate signed by the
configured `client_ca`. The Common Name (CN) of the certificate is the caller
identity used for RBAC and audit logging.

---

### POST /v1/sign

Request an ephemeral SSH certificate for an intent. The signer validates the
request against the host policy, signs the ephemeral public key, and returns a
scoped certificate.

**Auth:** mTLS client certificate. CN identifies the broker.  
**Content-Type:** `application/json`  
**Max body size:** 64 KiB

**Request body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `host` | string | ✓ | Logical host name as declared in `signer.json`. |
| `role` | string | ✓ | `"bastion"` or `"target"`. |
| `purpose` | string | ✓ | `"oneshot"` or `"session"`. |
| `command` | string | oneshot only | Command to lock into the cert's `force-command`. Must not contain `\n` or `\r`. |
| `ttl_seconds` | int | | Requested TTL in seconds. Capped by per-host `max_ttl_seconds` (global default: 5 min). |
| `public_key` | string | ✓ | Ephemeral Ed25519 public key in `authorized_keys` format. |
| `sudo` | bool | | Request NOPASSWD elevation via `sudo -n`. Requires `allow_sudo: true` on the host policy. |
| `sudo_user` | string | | Target user for sudo. Empty = `root`. Must match `allowed_sudo_users` if that list is set. |
| `pty` | bool | | Request `permit-pty` in the certificate. Requires `allow_pty: true` on the host policy. |
| `dry_run` | bool | | If true, resolve policy and return the `decision` **without** issuing a usable certificate. The response carries `decision` and omits `certificate`/`serial`. A policy denial in dry-run is reported as `decision.allowed=false` (HTTP 200), not a 403. |
| `end_user` | string | | OIDC identity of the end user (propagated by the HTTP frontend). Recorded in the audit log and embedded in the cert `KeyId` for `sshd` traceability. |
| `end_user_groups` | []string | | OIDC groups of the end user. When non-nil, activates per-user RBAC: the host's `groups` field must intersect with this list. |

**Response body (200 OK):**

| Field | Type | Description |
|---|---|---|
| `certificate` | string | Signed SSH certificate in `authorized_keys` format. Omitted in dry-run. |
| `serial` | uint64 | Certificate serial number. Correlates with the signer audit log and `sshd` logs. Omitted in dry-run. |
| `elevation_prefix` | string | Sudo prefix to prepend to commands in persistent sessions (e.g., `"sudo -n"`). Empty for one-shot intents — the prefix is already baked into `force-command`. |
| `decision` | object | Policy decision (always present in dry-run; optional otherwise). See below. |

**`decision` object:**

| Field | Type | Description |
|---|---|---|
| `allowed` | bool | Whether the command would be authorized. |
| `reason` | string | Denial reason (empty if allowed). |
| `require_approval` | bool | Whether the command requires human approval (command policy `require_approval` matched). |
| `matched_rule` | string | The `command_policy` rule that drove the decision (e.g., `allow:^uptime$`, `deny:rm -rf`, `require_approval:^reboot`). |
| `force_command` | string | The `force-command` that would be baked into the cert (includes the sudo prefix). |
| `ttl_seconds` | int | TTL the issued cert would carry. |
| `elevation` | string | Elevation prefix that would apply (sessions). |

**Host `command_policy` (in `signer.json`, never exposed over the wire):** `mode` (`"allowlist"`/`"denylist"`/`"off"`), `allow` (regexes), `deny` (regexes), `require_approval` (regexes). Enforced authoritatively for one-shot; hosts with any rule reject `purpose: "session"`.

**Error responses:**

| Status | Condition |
|---|---|
| `400 Bad Request` | Malformed JSON body or invalid `public_key` format. |
| `401 Unauthorized` | Missing or invalid mTLS client certificate. |
| `403 Forbidden` | Host not in caller's allowed groups (RBAC); or policy denied (sudo not allowed, PTY not allowed, TTL cap exceeded, invalid `sudo_user`, etc.). |
| `405 Method Not Allowed` | Request method is not `POST`. |

**Audit outcomes:** `issued` on success, `denied` on any authorization or policy failure, `dry_run_allowed` / `dry_run_denied` for dry-run simulations.

---

### GET /v1/hosts

Return the connectivity data and capabilities for all hosts accessible to the
caller. The broker calls this endpoint at startup and periodically
(`hosts_refresh_seconds`) to cache the host list.

**Auth:** mTLS client certificate.  
**No request body.**

**Response body (200 OK):**

JSON object mapping host name → host info object.

| Field | Type | Description |
|---|---|---|
| `addr` | string | SSH server address in `host:port` form. |
| `user` | string | SSH account on the remote host. |
| `host_key` | string | Pinned host key in `authorized_keys` format. No TOFU — the broker rejects any key that does not match. |
| `jump` | string | Logical name of the bastion host to use as ProxyJump. Empty if the host is direct. |
| `allow_sudo` | bool | Whether NOPASSWD sudo elevation is allowed on this host. |
| `allow_pty` | bool | Whether PTY allocation is allowed on this host. |

**Notes:**

- The response is filtered by the caller's `allowed_groups` in the `callers`
  section of `signer.json`. A caller with no entry in `callers` receives all
  hosts (backward compatible).
- Policy-internal fields (`principal`, `source_address`, `allowed_callers`,
  `max_ttl_seconds`, etc.) are **never** returned.

**Error responses:**

| Status | Condition |
|---|---|
| `401 Unauthorized` | Missing or invalid mTLS client certificate. |
| `405 Method Not Allowed` | Request method is not `GET`. |

---

### POST /v1/reload

Hot-reload `signer.json` without restarting the service. Atomically replaces
the hosts policy, `max_ttl_seconds`, `reload_callers`, and the CA key in memory.
If the new config is invalid, the current state is preserved intact.

**Auth:** mTLS client certificate. The CN must be listed in `reload_callers`.  
**No request body.**

**Response body (200 OK):**

| Field | Type | Description |
|---|---|---|
| `status` | string | Always `"ok"` on success. |
| `hosts` | int | Number of hosts loaded from the new config. |

**Notes:**

- `listen`, TLS configuration, and `audit_log` require a full restart — they are
  **not** reloaded by this endpoint.
- If `reload_callers` is empty in `signer.json`, this endpoint always returns
  `403`. HTTP reload is effectively disabled; `SIGHUP` still works locally.
- Alternative trigger: `kill -HUP <pid>` (or `./signer.sh restart`). The
  `SIGHUP` handler bypasses the `reload_callers` allowlist because it is local
  to the host.

**Error responses:**

| Status | Condition |
|---|---|
| `401 Unauthorized` | Missing or invalid mTLS client certificate. |
| `403 Forbidden` | Caller CN not in `reload_callers`, or `reload_callers` is empty. |
| `500 Internal Server Error` | Config file unreadable, JSON invalid, or CA key unreadable. Current state preserved. |
| `405 Method Not Allowed` | Request method is not `POST`. |

**Audit outcomes:** `reloaded` on success, `reload-denied` on 403, `reload-failed` on 500.

---

## Broker HTTP API

**Service:** `cmd/broker`  
**Transport:** HTTPS + mutual TLS (mTLS)  
**Auth:** mTLS client certificate. The CN becomes `Caller.ID` in the audit log.

---

### POST /v1/ssh\_run

Execute a one-shot SSH command on a managed host. The broker requests an
ephemeral certificate from the signer, opens the SSH connection, runs the
command, and discards the credential — all within the request lifetime.

**Auth:** mTLS client certificate.  
**Content-Type:** `application/json`

**Request body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `host` | string | ✓ | Logical host name. Must be known to the signer. |
| `command` | string | ✓ | Command to execute on the remote host. |
| `ttl_seconds` | int | | Requested certificate TTL in seconds. |
| `sudo` | bool | | Elevate with `sudo -n` (NOPASSWD). Requires `allow_sudo: true` on the host. |
| `sudo_user` | string | | Target user for sudo. Empty = `root`. |
| `pty` | bool | | Allocate a PTY for the command. Requires `allow_pty: true` on the host. When `true`, `stderr` in the response will be empty (stdout and stderr merge in the PTY). |

**Response body (200 OK):**

| Field | Type | Description |
|---|---|---|
| `stdout` | string | Standard output of the command. |
| `stderr` | string | Standard error. Empty when `pty: true`. |
| `exit_code` | int | Remote process exit code. A non-zero value is **not** an API-level error. |
| `serial` | uint64 | Certificate serial for audit log correlation with the signer log and `sshd`. |

**Error responses:**

| Status | Condition |
|---|---|
| `400 Bad Request` | Malformed JSON body. |
| `401 Unauthorized` | Missing or invalid mTLS client certificate. |
| `403 Forbidden` | Unknown host, signer rejected the request, or policy denied. |
| `405 Method Not Allowed` | Request method is not `POST`. |

---

## MCP HTTP API

**Service:** `cmd/mcp-broker-http`  
**Transport:** HTTPS (server-only TLS, no mTLS — authentication is via bearer token)  
**Default listen address:** `:8443` (configurable via `listen` in `config.json`)  
**Auth:** OIDC JWT bearer token, validated locally against the issuer's JWKS.

---

### GET /.well-known/oauth-protected-resource

Protected Resource Metadata endpoint (RFC 9728). MCP clients fetch this document
to discover the Authorization Server (OIDC issuer) and initiate the OAuth2
Authorization Code + PKCE flow before connecting.

**Auth:** None — this endpoint is intentionally public.  
**No request body.**

**Response body (200 OK):**

| Field | Type | Description |
|---|---|---|
| `resource` | string | Canonical URL of this resource server (`resource_url` from `config.json`). |
| `authorization_servers` | []string | List containing the configured OIDC issuer URL. |
| `scopes_supported` | []string | Required scopes from `oauth.required_scopes` in `config.json`. |
| `bearer_methods_supported` | []string | Always `["header"]`. |
| `resource_name` | string | Always `"SSH Broker (MCP)"`. |

---

### MCP Streamable HTTP — tools

All paths except `/.well-known/oauth-protected-resource` are handled by the MCP
Streamable HTTP transport (`go-sdk`).

**Auth:** `Authorization: Bearer <OIDC JWT>`

If the token is missing or invalid, the server responds with:
```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="<resource_url>/.well-known/oauth-protected-resource"
```

**Token validation (performed locally on every request):**

| Check | Detail |
|---|---|
| Signature | Verified against the JWKS endpoint (cached at startup, auto-rotated). No round-trip to the IdP per request. |
| Claims | `iss`, `aud`, `exp` validated. `iat` validated if `max_token_age_seconds > 0`. |
| Scopes | All scopes in `oauth.required_scopes` must be present. |
| Identity | `user_claim` (e.g., `preferred_username` or `sub`) → `Caller.ID` → broker audit log. |
| Groups | `groups_claim` (if configured) → `Caller.Groups` → forwarded to signer as `end_user_groups` for per-user RBAC. |

---

#### Tool: `ssh_list_servers`

List all SSH hosts accessible to the caller.

**Parameters:** none.

**Returns:** array of objects.

| Field | Type | Description |
|---|---|---|
| `name` | string | Logical host name. |
| `addr` | string | SSH server address (`host:port`). |
| `user` | string | SSH account on the remote host. |
| `jump` | string | Bastion host name. Empty if direct. |
| `allow_sudo` | bool | Whether sudo elevation is available on this host. |
| `allow_pty` | bool | Whether PTY allocation is available on this host. |

**Note:** always call `ssh_list_servers` first to discover available hosts and
their capabilities before attempting to execute commands.

---

#### Tool: `ssh_execute`

Execute a single command on a host. Issues a one-shot certificate with
`force-command` baked in. The credential is discarded after the command completes.

**Parameters:**

| Name | Type | Required | Description |
|---|---|---|---|
| `server` | string | ✓ | Logical host name. |
| `command` | string | ✓ | Command to run on the remote host. |
| `sudo` | bool | | Elevate via `sudo -n` (NOPASSWD). Do not retry if `allow_sudo` is `false`. |
| `sudo_user` | string | | Sudo target user. Empty = `root`. |
| `pty` | bool | | Allocate a PTY. `stderr` will be empty. Do not use if `allow_pty` is `false`. |
| `ttl_seconds` | int | | Certificate TTL override. Defaults to the host policy maximum. |

**Returns:**

| Field | Type | Description |
|---|---|---|
| `stdout` | string | Command standard output. |
| `stderr` | string | Standard error. Empty when `pty: true`. |
| `exit_code` | int | Remote process exit code. Non-zero is not a tool error. |
| `serial` | uint64 | Certificate serial for audit correlation. |

---

#### Tool: `ssh_session_open`

Open a persistent SSH session (connection reuse). Returns a `session_id` to use
with `ssh_session_exec` and `ssh_session_close`. One certificate is issued per
session (no `force-command`).

**Parameters:**

| Name | Type | Required | Description |
|---|---|---|---|
| `server` | string | ✓ | Logical host name. |
| `mode` | string | | Session mode. One of `"exec"` (default), `"shell"`, `"pty"`. |
| `sudo` | bool | | Elevate the session. |
| `sudo_user` | string | | Sudo target user. Empty = `root`. |
| `ttl_seconds` | int | | Certificate TTL override. |

**Session modes:**

| Mode | Description |
|---|---|
| `exec` | Each `ssh_session_exec` call runs in an isolated channel. `stdout`/`stderr` are separate. Best for automation and scripting. |
| `shell` | A single stateful `/bin/sh` process. `cd`, variables, and environment state persist across calls. Not suitable for interactive programs that require input or binary output. |
| `pty` | Shell with a PTY. Use for programs that call `isatty()` or require a real terminal. `stdout` and `stderr` are merged in the PTY stream. |

**Returns:**

| Field | Type | Description |
|---|---|---|
| `session_id` | string | Opaque session identifier. Required by `ssh_session_exec` and `ssh_session_close`. |
| `elevation_prefix` | string | Sudo prefix applied automatically by the broker to each command (informational only). |

---

#### Tool: `ssh_session_exec`

Execute a command on an existing persistent session.

**Parameters:**

| Name | Type | Required | Description |
|---|---|---|---|
| `session_id` | string | ✓ | Session identifier returned by `ssh_session_open`. |
| `command` | string | ✓ | Command to execute. Must not contain `\n` or `\r` (rejected with an error). |

**Returns:**

| Field | Type | Description |
|---|---|---|
| `stdout` | string | Command output. |
| `stderr` | string | Standard error. Empty in `pty` mode. |
| `exit_code` | int | Remote process exit code. |
| `serial` | uint64 | Certificate serial for audit correlation. |

---

#### Tool: `ssh_session_close`

Close a persistent session and release its SSH connection.

**Parameters:**

| Name | Type | Required | Description |
|---|---|---|---|
| `session_id` | string | ✓ | Session identifier returned by `ssh_session_open`. |

**Returns:**

| Field | Type | Description |
|---|---|---|
| `ok` | bool | Always `true` on success. |

**Note:** always close sessions when done. Sessions are automatically reaped
after `session_idle_seconds` or `session_max_seconds` (configured in
`config.json`), but explicit closure is recommended to free resources promptly.

---

## Audit Log Correlation

Every certificate issuance produces an entry in the signer's audit log with a
`serial` field. The broker's audit log records the same `serial` for each
execution. OpenSSH `sshd` (with `LogLevel VERBOSE`) includes the certificate
serial in the `Accepted certificate` log line.

**Audit log entry fields:**

| Field | Description |
|---|---|
| `time` | RFC3339 timestamp. |
| `seq` | Monotonically increasing sequence number (restores across restarts). |
| `caller` | Broker CN (mTLS) or OIDC user identity (HTTP frontend). |
| `host` | SSH server address (FQDN:port) in the signer log; logical name in the broker log. |
| `user` | SSH account on the remote host. |
| `principal` | SSH principal used in the certificate. |
| `command` | Command requested (one-shot) or session metadata. |
| `ttl` | Certificate validity window issued. |
| `serial` | Certificate serial number. |
| `session_id` | Persistent session ID (omitted for one-shot). |
| `outcome` | See table below. |
| `exit_code` | Remote process exit code (broker log only). |
| `elevation` | Sudo target, e.g., `"sudo:root"` or `"sudo:deploy"` (omitted if no escalation). |
| `pty` | `true` if a PTY was allocated (omitted otherwise). |
| `policy_rule` | `command_policy` rule that drove the decision (omitted if none). |
| `dry_run` | `true` if the entry is a dry-run simulation (nothing executed). |
| `err` | Error message on denial or failure (omitted on success). |
| `prev_hash` | SHA-256 hex of the previous log line (chain integrity). |
| `sig` | Ed25519 signature over the canonical JSON of this entry (tamper evidence). |

**Outcome values:**

| Outcome | Service | Meaning |
|---|---|---|
| `issued` | Signer | Certificate successfully issued. |
| `denied` | Signer | Request rejected by policy or RBAC. |
| `dry_run_allowed` | Signer | Dry-run simulation: command would be allowed. |
| `dry_run_denied` | Signer | Dry-run simulation: command would be denied. |
| `reloaded` | Signer | `signer.json` successfully reloaded. |
| `reload-denied` | Signer | Reload rejected (caller not in `reload_callers`). |
| `reload-failed` | Signer | Reload attempted but config invalid; previous state preserved. |
| `executed` | Broker | One-shot command completed. |
| `dry_run_allowed` | Broker | Dry-run: command would be allowed (nothing executed). |
| `dry_run_denied` | Broker | Dry-run: command would be denied (nothing executed). |
| `denied` | Broker | Request rejected before execution. |
| `error` | Broker | Execution failed (SSH error, timeout, etc.). |
| `session_open` | Broker | Persistent session opened. |
| `session_exec` | Broker | Command executed in a persistent session. |
| `session_close` | Broker | Persistent session closed. |

**Correlating an execution end-to-end:**

```bash
# Find a serial in the broker audit log
jq 'select(.serial == 12345)' broker_audit.log

# Find the matching issuance in the signer audit log
jq 'select(.serial == 12345)' signer_audit.log

# In sshd logs (journalctl or /var/log/auth.log)
grep "serial 12345" /var/log/auth.log
```

**Verifying chain integrity:**

Each entry's `prev_hash` is the SHA-256 hex of the previous raw JSON line.
Each entry's `sig` is the Ed25519 signature over the canonical JSON of the entry
with `sig=""` (empty string placeholder). Any deletion, reordering, or
modification breaks the chain and can be detected by replaying the hashes.
