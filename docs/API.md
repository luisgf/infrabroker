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
  - [POST·DELETE /v1/policy/hosts/{host}/allow](#post-v1policyhostshostallow--delete-v1policyhostshostallow)
  - [Runtime grants: POST /v1/policy/hosts/{host}/grants · GET /v1/policy/grants · DELETE /v1/policy/grants/{id}](#runtime-grants)
- [Control Plane API](#control-plane-api) — `cmd/control-plane` · HTTPS + mTLS · default `:7443`
  - [POST /v1/sign](#post-v1sign-control-plane)
  - [GET /v1/sign/result/{id}](#get-v1signresultid)
  - [GET /v1/approvals](#get-v1approvals)
  - [POST /v1/approvals/{id}](#post-v1approvalsid)
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
| `session_mode` | string | session with command policy | `"exec"`, `"shell"` or `"pty"`. Required to open a command-policy host as a session; only `"exec"` is allowed because each `ssh_session_exec` can be preflighted. |
| `command` | string | oneshot or session exec preflight | Command to lock into the cert's `force-command` for one-shot, or to evaluate before `ssh_session_exec` in `mode=exec`. Must not contain `\n` or `\r` when command policy is evaluated. |
| `ttl_seconds` | int | | Requested TTL in seconds. Capped by per-host `max_ttl_seconds` (global default: 5 min). |
| `public_key` | string | ✓ | Ephemeral Ed25519 public key in `authorized_keys` format. |
| `sudo` | bool | | Request NOPASSWD elevation via `sudo -n`. Requires `allow_sudo: true` on the host policy. |
| `sudo_user` | string | | Target user for sudo. Empty = `root`. Must match `allowed_sudo_users` if that list is set. |
| `pty` | bool | | Request `permit-pty` in the certificate. Requires `allow_pty: true` on the host policy. |
| `dry_run` | bool | | If true, resolve policy and return the `decision` **without** issuing a usable certificate. The response carries `decision` and omits `certificate`/`serial`. A policy denial in dry-run is reported as `decision.allowed=false` (HTTP 200), not a 403. |
| `preflight` | bool | | Internal broker/control-plane signal, only meaningful with `dry_run=true`: this decision authorizes an imminent execution such as `ssh_session_exec` in `mode=exec`. The signer still issues no certificate, but the control plane applies behavioral guardrails and rate limits as it would for execution. |
| `on_behalf_of` | string | | CN of the broker a trusted forwarder (control plane) is acting for. Honored **only** if the mTLS CN is in `trusted_forwarders`; otherwise the request is rejected (403). Used as the effective caller for RBAC. |
| `approved` | bool | | Marks a `require_approval` command as approved. Honored **only** from a trusted forwarder. Without it, a `require_approval` command returns 200 with no certificate (see below). |
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
| `enforcement` | string | Effective command-policy enforcement mode: `"enforce"` or `"audit"`. |
| `warning` | string | Audit-mode warning, e.g. `command_policy audit: would deny (allowlist:no-match)`. |
| `would_deny` | bool | In audit mode, true when the command would have been denied in enforce mode. |
| `would_require_approval` | bool | In audit mode, true when the command would have required approval in enforce mode. |

**Host `command_policy` (in `signer.json`, never exposed over the wire):** `mode` (`"allowlist"`/`"denylist"`/`"off"`), `enforcement` (`"enforce"` default, or `"audit"`), `allow` (regexes), `deny` (regexes), `require_approval` (regexes), `shell_parse` (bool, default `false`). When `shell_parse: true`, the command is parsed as POSIX sh (via `mvdan.cc/sh/v3`) before regex evaluation: each simple command is evaluated separately, and dangerous nodes (command substitution, process substitution, file redirects) are rejected in enforce mode or reported as warnings in audit mode. Pipe commands are allowed but every stage must pass the policy independently. One-shot is signer-authoritative via `force-command`. Session `mode=exec` is broker-preflighted before every `ssh_session_exec`; session `shell`/`pty` remains rejected on command-policy hosts.

**Composable policies by group (config-only):** a named library `command_policies` plus `group_command_policies` (`group → [policy names]`, reserved group `_default` applies to every host) lets a host's *effective* policy be the composition of its inline `command_policy` and the policies of all its groups — additive: deny wins, allow is a union, `require_approval` is a union, `shell_parse` is OR. Enforcement composes conservatively: any `"enforce"` policy makes the effective policy enforcing; a host is audit-only only when every restricting policy is `"audit"`. This is transparent over the wire: `matched_rule` may carry the rule of any contributing policy (`deny:…`, `allow:…`, `allowlist:no-match`).

**Error responses:**

| Status | Condition |
|---|---|
| `400 Bad Request` | Malformed JSON body or invalid `public_key` format. |
| `401 Unauthorized` | Missing or invalid mTLS client certificate. |
| `403 Forbidden` | Host not in caller's allowed groups (RBAC); or policy denied (sudo not allowed, PTY not allowed, invalid `sudo_user`, `shell`/`pty` session requested on a host with `command_policy`, `role: "bastion"` requested for a host with a `command_policy`, control characters in `caller`/`end_user`, etc.). Note: a `ttl_seconds` above the host cap is silently clamped to the cap, not rejected. |
| `405 Method Not Allowed` | Request method is not `POST`. |

**Approval-required response (200 OK, no certificate):** when the command matches
`command_policy.require_approval` and `approved` is not set (or not from a trusted
forwarder), the signer returns 200 with `decision.require_approval=true` and **no**
`certificate`. The control plane interprets this and orchestrates approval; a
direct broker treats it as an error. In `command_policy.enforcement: "audit"`,
the signer does not create an approval gate; the decision carries
`would_require_approval=true` and `warning` while allowing the command.

**`GET /v1/hosts`** also honors `X-On-Behalf-Of` (header) from trusted forwarders,
so the control plane can fetch the host list filtered by the original broker's groups.

**Audit outcomes:** `issued` on success, `denied` on any authorization or policy failure, `approval-required` when a command needs approval and was not issued, `dry_run_allowed` / `dry_run_denied` for dry-run simulations.

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
| `groups` | []string | RBAC groups the host belongs to. The broker uses them to filter the host list shown to an end user by the user's OIDC groups (consistent with the per-user check at signing time). |

**Notes:**

- The response is filtered by the caller's `allowed_groups` in the `callers`
  section of `signer.json`. A caller with no entry in `callers` receives all
  hosts (backward compatible).
- The response is **also** filtered by each host's `allowed_callers` (v1.13.0):
  a host is omitted when its `allowed_callers` is non-empty and does not include
  the caller CN, matching the per-host authorization `POST /v1/sign` enforces.
  Previously `/v1/hosts` applied only the group filter and leaked the
  connectivity of hosts the CN could not sign for.
- Policy-internal fields (`principal`, `source_address`, `allowed_callers`,
  `max_ttl_seconds`, command policy, etc.) are **never** returned. Group
  names are labels, not secrets; the broker already asserts
  `end_user_groups`, so exposing them adds no trust.

**Error responses:**

| Status | Condition |
|---|---|
| `401 Unauthorized` | Missing or invalid mTLS client certificate. |
| `405 Method Not Allowed` | Request method is not `GET`. |

---

### POST /v1/reload

Hot-reload `signer.json` without restarting the service. Atomically replaces
the hosts policy, `max_ttl_seconds`, `reload_callers`, the CA key (`ca_key`),
and all per-group CA keys (`ca_keys`) in memory.
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
| `500 Internal Server Error` | Config file unreadable, JSON invalid, CA key(s) unreadable or unreachable (AKV). Current state preserved. |
| `405 Method Not Allowed` | Request method is not `POST`. |

**Audit outcomes:** `reloaded` on success, `reload-denied` on 403, `reload-failed` on 500.

---

### POST /v1/policy/hosts/{host}/allow · DELETE /v1/policy/hosts/{host}/allow

Add (`POST`) or remove (`DELETE`) a single `command_policy` **allow** regex for
`{host}`, mutating `signer.json` and the running policy together — without a hand
edit or a separate reload. The signer **validates by building the new state**
(`CompileHostPolicies` + CA load) *before* persisting or applying: an invalid
regex, an unknown host, or a config that would not compile is rejected and nothing
changes. On success the file is written atomically (temp+rename; top-level keys and
other hosts preserved verbatim) and the in-memory policy is swapped. Adding the
first allow rule turns the host into an `allowlist`; removing the last leaves an
empty allowlist (which denies every command — by design).

**Auth:** mTLS client certificate; the CN must be in `reload_callers` (same trust
tier as `/v1/reload`). **Request body:** `{ "pattern": "<RE2 regex>" }`.

**Response (200 OK):** `{ "status": "ok", "host": "<host>", "hosts": <int> }`.

| Status | Condition |
|---|---|
| `401 Unauthorized` | Missing or invalid mTLS client certificate. |
| `403 Forbidden` | Caller CN not in `reload_callers`. |
| `400 Bad Request` | Missing/invalid body or an invalid regex. |
| `404 Not Found` | Unknown host. |
| `409 Conflict` | Pattern already present (add) or absent (remove) — no change. |
| `500 Internal Server Error` | The edited config failed to build (validation); nothing persisted. |

**Audit outcomes:** `policy-changed` on success, `policy-denied` on 403,
`policy-failed` on a rejected change (recorded as `policy-allow-add` /
`policy-allow-remove` with the pattern). CLI: `broker-ctl policy add|remove
--host <h> --allow <regex>`.

---

<a id="runtime-grants"></a>
### Runtime grants — POST /v1/policy/hosts/{host}/grants · GET /v1/policy/grants · DELETE /v1/policy/grants/{id}

A **runtime grant** temporarily **widens** a host's allowlist without editing
`signer.json`: a set of `allow` patterns that **expire on their own** after a TTL.
Unlike the mutation API above (which edits the durable file), grants live **in
memory only** — they are the dynamic overlay on top of the file baseline, intended
for "let this command through on `web01` for the next 2 hours" without a config
change. They are lost on a signer restart (TTL'd anyway), and they survive config
reloads.

**Widen-only, by construction.** A grant carries only `allow` patterns (never
`deny` / `require_approval`), and the signer applies it **only on a host that is
already allowlist-active**. On a default-allow or denylist-only host a grant is a
no-op — and injecting an allowlist there would *invert* the host to default-deny —
so the signer **refuses it** (`409`). A grant can never override a baseline `deny`
(deny still wins) nor remove an approval requirement. Creation is **operator-only**
(`reload_callers`); the broker/agent can never create one. Every operation is in
the signed audit log.

**Auth (all three):** mTLS client certificate; the CN must be in `reload_callers`.

#### Create — `POST /v1/policy/hosts/{host}/grants`

**Request body:**

| Field | Type | Required | Meaning |
|---|---|---|---|
| `allow` | `[]string` | yes | RE2 allow patterns to grant (≥1). |
| `ttl_seconds` | `int` | yes | Lifetime; must be `> 0` and `≤ max_grant_ttl_seconds` if that cap is set. |
| `caller` | `string` | no | Scope: only this broker CN benefits (`""` = host-wide). |
| `end_user` | `string` | no | Scope: only this OIDC end user benefits (`""` = host-wide). |

```bash
# Host-wide grant for 2 hours (mTLS client cert whose CN is in reload_callers)
curl --cert admin.crt --key admin.key --cacert signer-ca.crt \
  -X POST https://signer:9443/v1/policy/hosts/web01/grants \
  -d '{"allow":["^systemctl restart nginx$"],"ttl_seconds":7200}'
# → 201 Created
# {"id":"42d1eabd7c73b474c85e75a7","host":"web01","expires_at":"2026-06-19T14:00:00Z"}
```

**Response (201 Created):** `{ "id": "<hex>", "host": "<host>", "expires_at": "<RFC3339>" }`.

| Status | Condition |
|---|---|
| `201 Created` | Grant accepted and live. |
| `401 Unauthorized` | Missing or invalid mTLS client certificate. |
| `403 Forbidden` | Caller CN not in `reload_callers`. |
| `400 Bad Request` | Empty `allow`, `ttl_seconds ≤ 0`, an invalid regex, or `ttl_seconds` above `max_grant_ttl_seconds`. |
| `404 Not Found` | Unknown host. |
| `409 Conflict` | Host is not allowlist-active (a widen-only grant would be a no-op / would invert it). |

#### List — `GET /v1/policy/grants`

Returns the active (non-expired) grants. Operator-only (the list reveals the
current widening posture).

```bash
curl --cert admin.crt --key admin.key --cacert signer-ca.crt \
  https://signer:9443/v1/policy/grants
# → 200 OK
# [{"id":"42d1...","host":"web01","allow":["^systemctl restart nginx$"],
#   "approver":"admin","granted_at":"2026-06-19T12:00:00Z","expires_at":"2026-06-19T14:00:00Z"}]
```

#### Revoke — `DELETE /v1/policy/grants/{id}`

Removes a grant immediately (the command is denied again at once). `404` if the id
is unknown (already expired/revoked).

```bash
curl --cert admin.crt --key admin.key --cacert signer-ca.crt \
  -X DELETE https://signer:9443/v1/policy/grants/42d1eabd7c73b474c85e75a7
# → 200 OK   {"status":"ok","id":"42d1eabd7c73b474c85e75a7"}
```

**Audit outcomes:** `grant-created` / `grant-revoked` on success, `grant-denied`
on 403, `grant-failed` on a rejected create or an unknown revoke (recorded as
`grant <id>` with the allow patterns in `policy_rule`).

**Scope examples** (each is one `POST` body field):

| Intent | Body fragment | Who it applies to |
|---|---|---|
| Host-wide | *(omit `caller`/`end_user`)* | Any caller/user on the host. |
| One broker | `"caller":"broker-1"` | Only requests from CN `broker-1`. |
| One end user | `"end_user":"alice"` | Only requests carrying end user `alice`. |

**Worked scenario (incident response).** An allowlist host `web01` denies
`systemctl restart nginx`. During an incident an operator grants it for 2 hours;
the agent's next `ssh_execute` (or a `--dry_run` preview) is now allowed; two hours
later the grant expires and the command is denied again — no second action, and the
durable `signer.json` was never touched. CLI equivalents:
`broker-ctl policy grant --host web01 --allow '^systemctl restart nginx$' --ttl 2h`,
`broker-ctl policy grants`, `broker-ctl policy revoke <id>`.

#### Approve-and-learn waivers (the second kind of grant)

A grant can also carry a **`waive_approval`** dimension: patterns whose
`require_approval` is **suppressed** for the TTL. This is the *approve-and-learn*
overlay — distinct from `allow`:

- `allow` **widens** what is permitted (only on an allowlist-active host).
- `waive_approval` **un-gates** an *already-allowed* command (skips the human
  approval for the TTL). It never allows anything new and never overrides a `deny`,
  so it has **no inversion risk** and applies on **any** host (including default-allow
  hosts that carry a `require_approval` rule). A waiver is bound to the **exact command
  and elevation** that was approved — approving the non-`sudo` form does not waive the
  `sudo` (root) form, and vice versa. Re-learning the same command refreshes the single
  waiver instead of accumulating duplicates.

Waivers are **not** created through this endpoint — they are minted by the signer as
a side-effect of an **approved sign that asked to learn** (see
[`POST /v1/approvals/{id}`](#post-v1approvalsid) with `learn`). They live in the same
store, so they appear in `GET /v1/policy/grants` (with a `waive_approval` field) and
are revoked by `DELETE /v1/policy/grants/{id}` like any grant. Audit outcomes:
`approval-waiver-created` / `approval-waiver-failed`, carrying the originating
`approval_id` and approver.

---

## Control Plane API

**Service:** `cmd/control-plane`
**Transport:** HTTPS + mutual TLS (mTLS)
**Default listen address:** `:7443` (configurable via `listen` in `control-plane.json`)
**Auth:** every request requires a valid TLS client certificate signed by the
configured `client_ca`, with a non-empty CN free of control characters (an empty or
malformed CN is rejected, not treated as an identity). The CN identifies the broker
(for `/v1/sign`, `/v1/hosts`, `/v1/sign/result`) or the approver (for `/v1/approvals`).

**Role separation (signing path).** `/v1/sign`, `/v1/hosts`, and `/v1/sign/result`
are restricted to *brokers*: with a non-empty `sign_callers` list only those CNs are
allowed; with no list, any CN is allowed **except** one in `approval.callers` (an
approver is not a broker — denied the sign path, secure by default). This prevents an
approver certificate, signed by the same `client_ca`, from originating signing requests.

The control plane speaks the **same wire protocol** as the signer for `/v1/sign`
and `/v1/hosts` (it forwards to the signer, adding the broker's identity), and adds
the approval endpoints below. The CA key lives only in the signer.

---

### POST /v1/sign (control plane)

Same request body as the [signer `POST /v1/sign`](#post-v1sign). The control plane
forwards to the signer on behalf of the calling broker (`on_behalf_of` = broker CN).

**Responses:**

| Status | Meaning |
|---|---|
| `200 OK` | Issued (allowed, no approval needed) — body is the signer's `WireResponse` with `certificate`. Or, for `dry_run`, the `decision`. |
| `202 Accepted` | Approval required (command policy `require_approval`, or a behavior anomaly in `enforce` mode). Body: `{"approval_id": "...", "status": "pending"}`. The broker must poll `/v1/sign/result/{id}`. |
| `403 Forbidden` | Denied by policy/RBAC at the signer. |
| `429 Too Many Requests` | Behavioral rate limit exceeded for the subject (`behavior.mode=enforce`). |

**Behavioral guardrails:** when `behavior.mode` is `observe` or `enforce`, the
control plane checks each request against the subject's baseline (rate spike, new
host, new command). In `observe` it only audits (`outcome=anomaly`); in `enforce`
a rate excess returns `429` and other anomalies escalate to approval (`202`).
Pure dry-run requests bypass the guardrails. Executable preflights
(`dry_run=true`, `preflight=true`) are checked because the broker will execute
the command if the decision is allowed. Config: `behavior.mode`,
`behavior.rate_limit_per_min` in `control-plane.json`.

---

### GET /v1/sign/result/{id}

Polled by the broker after a `202`. Only the broker that created the request (same
mTLS CN) may read it.

| Status | Meaning |
|---|---|
| `202 Accepted` | Still pending. Body: `{"status":"pending"}`. Keep polling. |
| `200 OK` | Approved and signed — body is the `WireResponse` with `certificate`. Served once (the approval is then consumed). |
| `403 Forbidden` | Approval denied, or caller is not the request owner. |
| `408 Request Timeout` | Approval expired (TTL `approval.timeout_seconds`). |
| `410 Gone` | Approval already consumed (certificate already issued). |
| `404 Not Found` | Unknown approval id — including requests purged from memory ~2× `approval.timeout_seconds` after creation. |

---

### GET /v1/approvals

Lists approval requests. **Auth:** CN must be in `approval.callers`.

**Response (200 OK):** JSON array of `{id, caller, end_user, host, command, sudo, sudo_user, rule, status, created_at, decided_by, decided_at}` (the ephemeral public key is never exposed). Includes non-pending entries (approved/denied/expired) still held in memory.

---

### POST /v1/approvals/{id}

Resolve a pending request. **Auth:** CN must be in `approval.callers`.

**Request body:** `{"approve": true}` (or `false` to deny).

**Approve-and-learn** (allow only): add `"learn": true` and `"ttl_seconds": N` to
also **waive re-approval** for this exact command for `N` seconds. On the next
(approved) forward to the signer, the control plane carries the learn intent and the
signer mints a host-wide [approval waiver](#runtime-grants) (honored only because the
control plane is a `trusted_forwarder`). So the same command runs **without prompting
again** until the waiver expires; revoke it early with `broker-ctl policy revoke <id>`.

```json
{ "approve": true, "learn": true, "ttl_seconds": 7200 }
```

| Status | Meaning |
|---|---|
| `200 OK` | Decision recorded; body is the updated approval object. |
| `400 Bad Request` | `learn` without `ttl_seconds > 0`. |
| `403 Forbidden` | Caller not in `approval.callers`. |
| `409 Conflict` | Request not pending (already decided or expired). |

**Audit outcomes (control plane log):** `forwarded`, `approval-required`, `approval-decision-allow`, `approval-decision-allow-learn`, `approval-denied`, `approval-granted`, `approval-timeout`, `denied`. The signer additionally logs `approval-waiver-created` when the waiver is minted.

CLI: `broker-ctl approval allow <id> --learn --ttl 2h`.

---

## Outbound Notifications — Notifier contracts

When a command requires approval, the control plane sends an outbound notification
via the configured notifier. This is a **fire-and-forget POST**; failure only
produces a warning and does not block the `202` response to the broker.

### Notifier types

| `notifier` value | Target | Format |
|---|---|---|
| `log` (default) | Process log (`stderr`) | Plain text line |
| `webhook` | `webhook_url` | Raw `Approval` JSON |
| `teams` | `webhook_url` (Teams Incoming Webhook / Power Automate Workflow) | Adaptive Card or MessageCard — see below |

### `notifier: "teams"` — payload contracts

The `teams` notifier sends a POST to `webhook_url` with `Content-Type: application/json`.
The exact payload depends on `teams_format`.

#### Format `workflow` / `adaptivecard` (default, recommended)

Wraps an Adaptive Card v1.4 in the Power Automate Workflow message envelope:

```json
{
  "type": "message",
  "attachments": [
    {
      "contentType": "application/vnd.microsoft.card.adaptive",
      "contentUrl": null,
      "content": {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.4",
        "body": [
          { "type": "TextBlock", "size": "Medium", "weight": "Bolder",
            "text": "SSH Broker — Approval Required", "color": "Warning" },
          { "type": "TextBlock",
            "text": "An AI agent action is waiting for human approval before a certificate is issued." },
          { "type": "FactSet", "facts": [ ... ] }
        ],
        "actions": [
          { "type": "Action.OpenUrl", "title": "View request", "url": "<rendered approval_url_template>" }
        ]
      }
    }
  ]
}
```

The `actions` array is **only present** when `approval_url_template` is non-empty.

#### Format `messagecard` (legacy M365 Connectors — deprecated by Microsoft)

```json
{
  "@type": "MessageCard",
  "@context": "http://schema.org/extensions",
  "themeColor": "FFA500",
  "summary": "Approval required: <command> on <host>",
  "sections": [
    {
      "activityTitle": "SSH Broker — Approval Required",
      "activitySubtitle": "An AI agent action is waiting for human approval.",
      "facts": [ ... ],
      "markdown": true
    }
  ],
  "potentialAction": [
    { "@type": "OpenUri", "name": "View request",
      "targets": [{"os": "default", "uri": "<rendered approval_url_template>"}] }
  ]
}
```

`potentialAction` is only present when `approval_url_template` is non-empty.

#### Facts included in every card

| Fact name | Source field | Always present |
|---|---|---|
| `Approval ID` | `approval.id` | Yes |
| `Status` | `approval.status` | Yes |
| `Created` | `approval.created_at` (RFC3339 UTC) | Yes |
| `Host` | `approval.host` | Yes |
| `Command` | `approval.command` | Yes |
| `Caller (broker)` | `approval.caller` | Yes |
| `End user` | `approval.end_user` | Only if non-empty |
| `Elevation` | derived from `sudo`/`sudo_user` | Only if `sudo=true` |
| `Policy rule` | `approval.rule` | Only if non-empty |

> **Security note:** the card never contains the ephemeral public key or any
> field from the internal `WireRequest`. The `req` field of `Approval` is
> unexported and excluded from serialization by design.

### `approval_url_template`

An optional URL string where `{id}` is replaced with the approval ID at
notification time. Intended as a forward-compatible hook for the Phase 2
approval bridge (`cmd/approval-bridge`, not yet implemented), which will
expose a UI for approving/denying from Teams without the `broker-ctl` CLI.

Example: `"https://approvals.internal.example.com/requests/{id}"`

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
**Max body size:** 64 KiB

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
| `warnings` | []string | Optional advisory warnings, e.g. command-policy audit mode would have denied or required approval in enforce mode. |

**Error responses:**

| Status | Condition |
|---|---|
| `400 Bad Request` | Malformed JSON body, or an empty `command`. |
| `401 Unauthorized` | Missing or invalid mTLS client certificate. |
| `403 Forbidden` | Policy/authorization denial (RBAC, sudo/PTY not allowed, command policy, …). The error text describes the denial. |
| `404 Not Found` | Host not known to the broker. |
| `405 Method Not Allowed` | Request method is not `POST`. |
| `502 Bad Gateway` | Upstream failure: SSH dial/exec error, or the signing service unreachable / returning 5xx. The body is a generic `upstream failure` (internal addresses are not leaked; the full error is in the audit log). |

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
| Claims | `iss`, `aud`, `exp` validated. With `max_token_age_seconds > 0`, `iat` is required and validated — a token without a numeric `iat` is rejected (fail-closed). |
| Scopes | All scopes in `oauth.required_scopes` must be present. |
| Identity | `user_claim` (e.g., `preferred_username` or `sub`) → `Caller.ID` → broker audit log. |
| Groups | `groups_claim` (if configured) → `Caller.Groups` → forwarded to signer as `end_user_groups` for per-user RBAC. Fail-closed: a token **without** the configured claim is rejected (401); an empty list is forwarded as-is (denies every host). |

---

#### Tool: `ssh_list_servers`

List the SSH hosts accessible to the caller. When the OIDC token carries
groups (`groups_claim`), the list only includes hosts sharing at least one of
the user's groups — the same filter the signer applies at signing time, so the
model is never offered a host it cannot use. Callers without groups (stdio,
mTLS) see every host.

**Parameters:** none.

**Returns:** array of objects. Connectivity data (`addr`, `user`, `host_key`)
is **not** exposed to the model — only the logical name and capabilities.

| Field | Type | Description |
|---|---|---|
| `name` | string | Logical host name. |
| `allow_sudo` | bool | Whether sudo elevation is available on this host. |
| `allow_pty` | bool | Whether PTY allocation is available on this host. |
| `jump` | string | Bastion host name. Empty if direct. |

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
| `command` | string | ✓ | Command to run on the remote host. Must not contain `\n` or `\r` (the signer rejects it); compose with `;` or `&&` instead. |
| `sudo` | bool | | Elevate via `sudo -n` (NOPASSWD). Do not retry if `allow_sudo` is `false`. |
| `sudo_user` | string | | Sudo target user. Empty = `root`. |
| `pty` | bool | | Allocate a PTY. `stderr` will be empty. Do not use if `allow_pty` is `false`. |
| `ttl_seconds` | int | | Certificate TTL override. Defaults to the host policy maximum. |
| `dry_run` | bool | | Simulate: resolve the host policy and return the decision (allow/deny, approval requirement, matched rule, force-command, TTL) **without** connecting or executing. |

**Returns:**

| Field | Type | Description |
|---|---|---|
| `stdout` | string | Command standard output. |
| `stderr` | string | Standard error. Empty when `pty: true`. |
| `exit_code` | int | Remote process exit code. Non-zero is not a tool error. |
| `serial` | uint64 | Certificate serial for audit correlation. |
| `warnings` | []string | Optional advisory warnings, e.g. command-policy audit mode would have denied or required approval in enforce mode. |

With `dry_run: true` the tool returns the rendered policy decision as text
(`[dry-run] ALLOWED` / `[dry-run] DENIED: <reason>` plus rule, force-command,
and TTL) instead of execution output.

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
| `serial` | uint64 | Certificate serial of the session connection, for audit correlation. |

The sudo elevation prefix authorised by the signer is applied automatically by
the broker (per command in `exec` mode; to the shell process in `shell`/`pty`
mode) — it is not returned to the model.

---

#### Tool: `ssh_session_exec`

Execute a command on an existing persistent session.

**Parameters:**

| Name | Type | Required | Description |
|---|---|---|---|
| `session_id` | string | ✓ | Session identifier returned by `ssh_session_open`. |
| `command` | string | ✓ | Command to execute. In `shell`/`pty` sessions it must not contain `\n` or `\r` (rejected — a newline would inject extra commands into the persistent shell). `exec` sessions run each command in an isolated channel and have no such restriction. |

**Returns:**

| Field | Type | Description |
|---|---|---|
| `stdout` | string | Command output. |
| `stderr` | string | Standard error. Empty in `pty` mode. |
| `exit_code` | int | Remote process exit code. |
| `serial` | uint64 | Certificate serial for audit correlation. |
| `warnings` | []string | Optional advisory warnings from per-command preflight, e.g. command-policy audit mode would have denied or required approval in enforce mode. |

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

**Session recording:** when `session_recording_dir` is set in `config.json`,
`shell` and `pty` sessions are recorded to ASCIIcast v2 files in that directory.
Each file is named `<session_id>.cast` and contains stdin, stdout, and stderr
events with millisecond timestamps. See USAGE.md §8 for details.

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
| `warning` | Advisory warning, e.g. command-policy audit mode would have denied or required approval. |
| `approval_id` | Approval request id (control plane log; omitted if none). |
| `approved_by` | CN of the approver (control plane log; omitted if none). |
| `anomaly` | Behavioral anomalies detected (control plane log): `rate-exceeded`, `new-host:<h>`, `new-command:<c>`. |
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
| `session_exec_denied` | Broker | `mode=exec` session command blocked by command-policy preflight. |
| `session_close` | Broker | Persistent session closed. |
| `forwarded` | Control plane | Request forwarded to the signer and issued (no approval needed). |
| `approval-required` | Control plane / Signer | Command needs human approval; request recorded. |
| `approval-decision-allow` | Control plane | Approver allowed a pending request. |
| `approval-denied` | Control plane | Approver denied the request (or poll after denial). |
| `approval-granted` | Control plane | Certificate issued after approval. |
| `approval-timeout` | Control plane | Approval expired before being decided. |
| `anomaly` | Control plane | Behavioral anomaly detected (`observe` mode; not blocked). |
| `rate-limited` | Control plane | Request denied — rate limit exceeded (`enforce` mode). |

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
