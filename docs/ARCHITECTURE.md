# Architecture — ssh-broker

How the system is built and **why**. For the threat model (actors, trust
boundaries, explicit gaps) see [THREAT_MODEL.md](THREAT_MODEL.md); for the
operational runbook see [OPERATIONS.md](OPERATIONS.md).

---

## What it is, in one paragraph

An AI model needs to run commands on Linux hosts over SSH, but static SSH keys
are exfiltratable (prompt injection, memory dump) and, once stolen, valid
forever. The **SSH broker** is an intermediary: the model never receives any
credential, only the result of the execution (`stdout / stderr / exit_code`).
For every operation the broker generates an ephemeral Ed25519 key pair **in
memory** (never on disk), obtains a short-lived SSH certificate signed by a CA,
opens the SSH connection with that cert, and discards the material when done.

In **remote mode (production)** a separate service (`cmd/signer`) holds the CA
key and the policy; the broker only ever receives the signed cert, so a
compromised broker cannot steal the key. A **third frontend**
(`cmd/mcp-broker-http`, v1.4.0) exposes the broker over HTTP protected by
OAuth2/OIDC for multi-user network deployments; the user's OIDC identity is
propagated to the signer for per-user RBAC.

> Local mode (single binary, `ca_key` in the broker) is still supported in code
> but is no longer the active configuration. See `config.example.json` and the
> `buildSigner` function in `engine.go`.

---

## Architecture on one page

```
AI model (Claude / OpenCode)
    │                           │
    │  stdio MCP (local)        │  HTTP+Bearer MCP (network)
    │                           │  Authorization: Bearer <OIDC token>
    ▼                           ▼
cmd/mcp-broker                cmd/mcp-broker-http        ← never hold the CA key
    │  same 5 tools            │  validates JWT via JWKS (go-oidc)
    │  caller="mcp-stdio"      │  caller={sub, groups from token}
    │                          │  propagates EndUser+EndUserGroups to the signer
    └─────────────┬────────────┘
                  │
    │  on startup:  GET /v1/hosts → cache
    │  every 30s:   GET /v1/hosts → refresh   ← hosts_refresh_seconds (configurable)
    │
    │  generates ephemeral Ed25519 pair        ← private key stays here
    │  sends Intent{host, role, purpose,
    │    command, pubkey, sudo?, sudo_user?,
    │    pty?, end_user?, end_user_groups?}
    │
    │  HTTPS + mTLS  (pki/broker.crt, CN=broker-1)
    ▼
[cmd/control-plane]  (optional PEP)            ← no CA key
    │  forwards /v1/sign, /v1/hosts (on_behalf_of)
    │  orchestrates human approval (202 + polling)
    │  behavior guardrails (observe/enforce, rate)
    │
    │  HTTPS + mTLS
    ▼
cmd/signer  ~/bin/signer                       ← sole custodian of the CA key
    │  GET /v1/hosts  → returns {addr, user, host_key, jump,
    │                   allow_sudo, allow_pty, groups} per host,
    │                   filtered by the caller's groups (RBAC)
    │                   (policy never leaves: principal, source_address,
    │                    allowed_callers, allowed_sudo_users, max_ttl,
    │                    command_policy)
    │  POST /v1/sign  → check group RBAC (HostSetForCaller)
    │               → PolicyTable.Resolve(Intent)
    │    → Constraints (principal, source-address,
    │      force-command [with sudo if applicable],
    │      port-forwarding, permit-pty, TTL)
    │    → ElevationPrefix (for sessions)
    │  ca.BuildAndSign(caKey, pubkey, c)
    │  audit: issued / denied (with elevation/PTY)
    │  POST /v1/reload → hot-reload signer.json (hosts/max_ttl/ca_keys)
    │                    only CNs in reload_callers; or via SIGHUP (local)
    │
    └──► returns {Certificate, Serial, ElevationPrefix?}
    │
    │  SSH with ephemeral cert
    ▼
[Bastion :22]                                  ← cert with permit-port-forwarding
    │  direct-tcpip
    ▼
[Target :22]                                   ← cert with force-command (one-shot)
    │                                             or without force-command (session)
    │                                             permit-pty if PTY requested
    └──► stdout/stderr/exit_code
         ← broker → model
```

Triple audit correlated by `serial`:

1. `cmd/signer` → issuance log (caller, **host=FQDN**, **user**, **principal**,
   role, purpose, elevation, pty, serial)
2. `cmd/mcp-broker` → execution log (caller, host, user, cmd, exit_code, serial,
   session_id, elevation, pty)
3. `sshd` → `Accepted certificate ID "agent=... host=... elev=sudo:root pty=1" (serial XXXX)`

---

## Request flow

1. The model calls an MCP tool (`ssh_execute`, `ssh_session_open`, …).
2. The frontend derives the caller identity (`mcp-stdio`, mTLS CN, or OIDC
   sub+groups) and forwards it to the engine.
3. The engine resolves the hop chain (target → … → bastion) and, per hop,
   generates an ephemeral key pair and requests a cert from the signer.
4. The signer applies RBAC, resolves the policy into certificate constraints,
   signs with the CA key, and returns the cert.
5. The engine dials the SSH chain with the ephemeral private keys + certs, runs
   the command (or opens a persistent session), and audits the result.
6. The ephemeral material is discarded; the model receives only the output.

---

## Privilege elevation (sudo NOPASSWD)

Authorization is **policy-gated in the signer**; the broker never decides to
elevate on its own. Validation (`internal/signer/signer.go`):

- Regex over `sudo_user` (`^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,31}$`) — rejects flags
  and metacharacters.
- Allowlist `allowed_sudo_users` (empty = root only).
- The command is always wrapped as `prefix -- /bin/sh -c <shellQuote(cmd)>` to
  prevent injection.

### One-shot (`ssh_execute` with `sudo=true`)

```
broker → Intent{sudo=true, sudo_user="root", command="id", purpose=oneshot}
signer → PolicyTable.Resolve → force-command = "sudo -n -- /bin/sh -c 'id'"
       → cert with force-command baked in
sshd   → enforces the force-command; the broker cannot modify it
```

### Session `exec` with `sudo=true`

```
broker → Intent{sudo=true, purpose=session} → signer returns ElevationPrefix="sudo -n"
       → ElevationPrefix stored in liveSession.elevationPrefix
SessionExec("ls /root") → effective command: "sudo -n -- /bin/sh -c 'ls /root'"
```

### Session `shell`/`pty` with `sudo=true`

```
broker → OpenShell(client, "sudo -n -- /bin/sh")   ← whole shell elevated
       → the entire session runs as root in a single sudo process
```

Host-side config (`/etc/sudoers.d/broker`):

```sudoers
# SSH account 'deploy', sudo to root without password:
deploy ALL=(root) NOPASSWD: ALL

# Restricted to specific commands (recommended in production):
deploy ALL=(root) NOPASSWD: /usr/bin/systemctl, /usr/bin/journalctl

# Sudo to a specific user:
deploy ALL=(appuser) NOPASSWD: ALL
```

---

## Design decisions, grouped by theme

### Credential custody & component separation

**Broker/signer separation.** The broker sends an *intent* (host, role, purpose,
command, pubkey, sudo?, sudo_user?, pty?). The signer decides every certificate
constraint. The ephemeral private key is generated in the broker and never
leaves it; only the pubkey travels to the signer, which returns the cert (+
ElevationPrefix for sessions). A compromised broker cannot mint certificates or
elevate where policy forbids it.

**`signer.json` as the single source of truth for hosts.** The broker does not
declare hosts. On startup it calls `GET /v1/hosts` (mTLS) and caches
`{addr, user, host_key, jump, allow_sudo, allow_pty, groups}` (groups since
v1.12.0, used to filter `ssh_list_servers` by the end user's OIDC groups). It
refreshes every `hosts_refresh_seconds`; on failure it keeps the previous cache.
The internal policy (`principal`, `source_address`, `allowed_callers`,
`allowed_sudo_users`, `max_ttl`, `command_policy`) never leaves the signer.
*Operational implication:* adding a host = edit `signer.json` + reload the
signer. The broker sees it in ≤ the refresh interval without a restart.

**Why a custom MCP and not mcp-ssh-manager.** `mcp-ssh-manager` uses the Node
`ssh2 1.17` library, which **does not support SSH client certificates**. With a
key + cert in the SSH agent, `ssh2` offers `sshd` only the bare key
(`ED25519`, not `ED25519-CERT`), which sshd rejects. The custom Go broker uses
`golang.org/x/crypto/ssh`, which supports client certs correctly.

### One-shot vs sessions

**`force-command` only in one-shot, not in sessions.** A one-shot cert carries
`force-command=<cmd>` (including the sudo prefix when elevation is requested).
In sessions the cert authenticates the **connection** and commands travel as
separate channels → the cert cannot carry a force-command. The broker preflights
every `ssh_session_exec` against the current signer policy before opening the
SSH exec channel, so signer reloads affect sessions that were already open:
host access, end-user groups, sudo, sudo_user and PTY are revalidated. The
broker also compares the session's original physical SSH chain
(`addr`/`user`/`host_key`/`jump`) with the current signer host view before each
session command; if it changed, the command is rejected and a new session must be
opened. For hosts with a `command_policy`, `mode=exec` commands are checked and
`shell`/`pty` commands are rejected because stateful command streams are not
independently verifiable. This is weaker than one-shot against a compromised
broker, because the host does not enforce the per-command decision — see
THREAT_MODEL.md.

**Stateful shell: without PTY vs with PTY.**
- *Without PTY* (`mode=shell`): `OpenShell(client, shellCmd)` starts `/bin/sh`
  (or `sudo -n -- /bin/sh` if elevated). No echo or prompt. Stdout and stderr
  stay separate. Markers detect end-of-command and exit code.
- *With PTY* (`mode=pty`): `OpenShellPTY(client, shellCmd, opts)` requests a PTY,
  starts the shell with `stty -echo; PS1=''` to silence echo, and reuses the
  same marker protocol. Stdout and stderr are **merged** in the PTY channel.

**Concurrency bug in ShellSession (resolved).** First version: a new reader
goroutine per call over the same shared `bufio.Reader` → race condition. Fix: a
single persistent reader goroutine feeding a `chan lineRes`; each `Exec()`
consumes from the channel directly.

### Routing / bastions

**`source-address` on jump chains.** With ProxyJump, the TCP to the target
**leaves the bastion**, not the broker. The **target** cert must pin the
bastion's egress IP. Controlled per host via `source_address` in `signer.json`.

**`AllowAsBastion` in policy.** By default a host cannot be used as a ProxyJump
hop. It must be explicitly marked `allow_as_bastion: true` (enables
`permit-port-forwarding` in its cert). Local single-binary mode honors the same
gate (v1.13.0): only hosts explicitly marked, or referenced as another host's
`jump` target, are bastionable — previously local mode forced it on for every
host.

### RBAC

**Per-end-user RBAC (EndUser/EndUserGroups).** When `Intent.EndUserGroups` is
non-nil (HTTP+OIDC frontend), `Resolve` requires `hp.Groups ∩ EndUserGroups ≠ ∅`.
If nil (stdio/mTLS), the filter is not applied — fully compatible. The `EndUser`
also appears in the cert `KeyID` for `sshd` traceability. Applied to all hops
(bastion + target). **Fail-closed (v1.11.2):** with `groups_claim` configured, a
token without the claim is rejected (the verifier never produces nil groups by
omission).

**Per-group RBAC (mTLS CN → allowed_groups).** Each host declares its `groups`;
the `callers` section maps each broker's mTLS CN to the groups it may use.
Double enforcement: `GET /v1/hosts` filters the response, and `POST /v1/sign`
rejects (403) hosts outside the caller's group set before reaching `Resolve()`.
A CN absent from `callers` has no group restriction (compatible). Additive with
per-host `allowed_callers`: a broker must pass both.

**Enriched signer audit (FQDN, user, principal).** `auditEmission()` logs
`host=hp.Addr` (real FQDN/addr instead of the short logical name), `user`, and
`principal` on every `issued`/`denied` event, via a PolicyTable lookup. If the
host is absent (group denial before `Resolve()`), the logical name is the
fallback.

### AI-action firewall

**Command policy + dry-run (v1.5.0, Phase A).** Beyond gating *access*, the
signer gates *what command runs* — defending against a **compromised agent**.
`internal/signer/cmdpolicy.go`: `CommandPolicy{Mode, Allow, Deny, RequireApproval,
ShellParse, Enforcement}` + `Decide()`, RE2 regexes (linear time) with a
package-level cache. Authoritative for one-shot (the allowed command is baked
into the `force-command` by the CA key — inevadible). Dry-run (`Intent.DryRun`)
resolves the policy and returns the decision without issuing a cert; an enforce
denial is a result (`Allowed=false`), not an error. `enforcement: "audit"` turns
would-deny and would-require-approval outcomes into warnings so operators can
collect a baseline before switching to `enforce`; in composed policies,
`enforce` wins over `audit`. A command-policy host rejects `role=bastion`
(v1.13.0): the signer refuses a config that marks it both `command_policy` and
`allow_as_bastion`. A bastion certificate carries no force-command (and grants
port-forwarding), so without this the firewall could be bypassed by requesting a
bastion-role cert for a command-restricted host.

**Command firewall for sessions.** A session open on a command-policy host must
declare `session_mode="exec"`; `shell` and `pty` are rejected. The open cert
still has no `force-command`, but every `ssh_session_exec` performs a signer
dry-run with `purpose=session`, the live `session_mode`, the exact command, and
the session's sudo/sudo_user/PTY state. This also covers sessions opened before a
policy reload: an existing `exec` session starts enforcing the new policy on the
next command, while an existing `shell`/`pty` session is rejected on the next
command. If the decision is denied or approval-gated in `enforce`, the broker
refuses to send the SSH request. If the effective policy is `audit`, the broker
sends the command and returns/audits the warning. When routed through the
control plane, this dry-run carries `preflight=true`, so behavioral guardrails
and rate limits are applied because execution follows an allowed decision.

**Anchoring, shell metacharacters & `shell_parse` (v1.9.2).** `Decide()`
evaluates the command as a **whole string** against each regex. Without shell
parsing, `&&`, `;`, `|`, `` ` `` and `$()` are transparent to the evaluator
(e.g. allowlist `["^ps"]` lets `ps aux && kill -9 1` through). `ShellParse: true`
activates POSIX-sh AST parsing (`mvdan.cc/sh/v3`) before evaluation: each simple
command is checked separately, and dangerous nodes (command/process
substitution, arithmetic, file redirects) are rejected unconditionally; pipes
and `&&`/`;`/`fd→fd` redirects are allowed if every part passes. **Newlines
(v1.11.2):** `\n`/`\r` in one-shot commands are rejected by `PolicyTable.Resolve`
on every host — a newline would smuggle extra command lines past the regexes
(`^ps` also matches `"ps\nrm -rf /"`, and the remote shell runs both lines).

**Composable policies by group (v1.14.0).** Beyond the per-host inline
`command_policy`, a **named policy library** (`command_policies`) can be attached
to groups (`group_command_policies: group → [policy names]`). A host's *effective*
firewall is the **composition** of its inline policy plus every policy of every
group it belongs to — `internal/signer/policyset.go`: `PolicySet` +
`CompileHostPolicies` (resolved and validated at config load, stored on
`HostPolicy.Policies`; a one-element set reproduces `CommandPolicy.Decide`
exactly, so single-policy hosts are unchanged). Composition is **additive**:
**deny wins** (a deny match in any policy blocks), **allow is a union** (if any
contributing policy is an allowlist, the command must match the union of all of
them), **require_approval is a union**, and **shell_parse is OR**. The reserved
group `_default` applies to every host (a global guardrail, mirroring ca_keys
`_default`). Reuse of the host's existing `groups` field means group membership
now also grants firewall capabilities — assigning a group can *widen* a host's
allow-set. `broker-ctl policy explain --host <h> [--command <c>]` prints a host's
composed policy and evaluates a command offline.

**Dynamic policy operations (v1.17.0).** The file stays the source of truth, but
three additions remove the edit-and-reload friction: the **recommender**
(`internal/policyrec` + `broker-ctl policy recommend`) mines the audit for
promote/dead-rule/friction suggestions (read-only, advisory); opt-in **auto-reload**
(`auto_reload_seconds`) polls the config mtime and hot-reloads via the validated,
atomic path; and the **validated mutation API** (`POST/DELETE
/v1/policy/hosts/{host}/allow`) edits an allow rule by *building the new state
before persisting it*, then writes `signer.json` atomically and swaps the
in-memory policy — auth `reload_callers`, audited.

**Runtime grants & the two-layer model (v1.18.0).** Grants add a **dynamic
overlay** on top of the durable file baseline, composed at decision time:
`internal/signer/grants.go` `GrantStore` (in-memory, `GrantProvider`) holds
time-boxed `allow` patterns that **expire on their own**; `resolveCommandPolicy`
appends the host's live grants to its effective `PolicySet` per request
(`Local.SignIntent → resolve(in, ttl, grants)`). The store is created once and
shared into every rebuilt `Local`, so grants **survive config reloads**; they are
in-memory only, so a restart drops them — which fails safe (the decision falls back
to the more-restrictive file baseline, because grants only widen). Creation is
**operator-only** (`reload_callers`), every operation is audited, and the broker/
agent can never create one. CLI: `broker-ctl policy grant|grants|revoke`; API under
[Runtime grants](API.md).

The single hard invariant is **widen-only**, and it is *enforced*, not assumed.
`PolicySet.decideOne` flips a **default-allow** host to **default-deny** the instant
any allowlist member appears (step 3: `hasAllowlist`). So composing an allowlist
overlay onto a permissive host would *invert* it — the opposite of "grant". The
grant layer blocks that three ways: grants carry **only `allow`** (structurally
additive); they are injected **only when the baseline is already allowlist-active**
(`eff.hasAllowlist()` — on a default-allow/denylist host a grant is a no-op and is
**refused at creation** with `409`); and **deny still wins** (a grant can't override
a baseline `deny` or drop an approval requirement). Example of the prevented
inversion: host `db01` is default-allow (`uptime`, `ls`, everything runs). Naively
injecting a grant `allow: ["^uptime$"]` would make `hasAllowlist` true and turn
`db01` into an allowlist that *denies* `ls` — strictly narrower. The guard suppresses
the injection (and the create returns `409`), so `db01` stays default-allow.

**Approve-and-learn — TTL'd approval waivers (v1.18.0).** The second grant dimension
closes the loop with human approval. `require_approval` is **orthogonal** to allow/deny
(`decideOne` step 2, before allow): a flagged command is one that is *already allowed*
but gated for a human. So a widen-only *allow*-grant cannot lift that gate — and a
`require_approval` rule can sit on a `denylist`/`off` host too, where an allow-grant
would even be refused. Approve-and-learn is therefore a **`WaiveApproval` overlay**:
patterns whose `require_approval` is suppressed for a TTL, applied in
`resolveCommandPolicy` *after* the `!allowed` guard — so it only ever un-gates an
already-allowed command, never allows something new, never overrides a `deny` (no
inversion risk, any host). The waiver is minted **signer-internally**: when a reviewer
approves with `broker-ctl approval allow <id> --learn --ttl 2h`, the control plane
carries the learn intent (`learn_ttl_seconds`/approver/approval-id) on the *approved*
sign, and the signer mints a host-wide waiver — honored only because the control plane
is a `trusted_forwarder` (exactly like `Approved`). No new auth tier; policy authority
stays in the signer; a broker can neither self-approve nor self-learn. A waiver is bound
to the exact **command and elevation** (`sudo`/`sudo_user`) that was approved — so
approving a non-sudo command never waives its root variant — its `waive_approval` regex
is compiled onto the grant (not the shared cache, so an unbounded stream of learned
commands can't pollute it), and re-learning a command refreshes the single waiver rather
than accumulating duplicates. Waivers live in the same `GrantStore` (listed/revoked via
`policy grants`/`revoke`), are TTL'd, periodically purged, and dropped on restart
(fail-safe: the gate returns); every mint is audited and linked to its `ApprovalID`.

### Human-in-the-loop & control plane

**Control plane + human approval (v1.6.0, Phase B).** `cmd/control-plane` is a
PEP between broker and signer: it forwards `/v1/sign` and `/v1/hosts` propagating
the broker identity (`on_behalf_of`) and orchestrates approval, **without holding
the CA key**. Trust model: `signer.json` gains `trusted_forwarders` (the control
plane's CN). The signer honors `on_behalf_of` and `approved` **only** from
trusted forwarders → approval and impersonation are unavoidable. Approval gate
in the signer is authoritative: `SignIntent` issues no cert if
`RequireApproval && !Approved`. Async flow (no held connections): broker → control
plane `POST /v1/sign` → 202 `{approval_id}` → broker polls
`GET /v1/sign/result/{id}` → human approves via `broker-ctl approval allow <id>`
→ next poll forwards with `approved=true` and returns the cert. Pending requests
expire after the approval TTL from creation; approved-but-uncollected requests
expire after the same TTL from the human decision. Approvals are consumed once and
purged 2×TTL after creation.

**Behavior guardrails + rate limiting (v1.7.0, Phase C).**
`internal/control/behavior.go`: a per-subject in-memory tracker detecting rate
spikes, never-before-used hosts, and out-of-history commands (first-token
fingerprint). Subject = the authenticated **broker CN**; the OIDC end user only
qualifies the subject (`<broker CN>:<end_user>`) when the broker CN is in the
control plane's `trusted_forwarders` (v1.12.6). Modes (`behavior.mode`): `off` /
`observe` (audits `anomaly`, never blocks) / `enforce` (anomalies escalate to
approval; rate excess → 429). **Caveat:** for trusted forwarders the `end_user`
half is still broker-asserted, so behavior is detection, not containment — see
THREAT_MODEL.md.

**Extensible notification & approval (v1.8.0 + Phase 2 pending).**
`TeamsNotifier` (`internal/control/teams.go`) implements the `Notifier`
interface; `notifier: "teams"` sends an Adaptive Card v1.4 (Power Automate
Workflow) or legacy MessageCard. Bidirectional approval from Teams (pressing
"Approve" in the card) requires the Phase 2 `cmd/approval-bridge` (not
implemented): Teams cannot present a client certificate, and Incoming Webhooks do
not support `Action.Submit`/`HttpPOST`. `approval_url_template` is the
forward-compatible hook for it.

### Multi-CA & Azure Key Vault (v1.11.0)

The signer and broker accept a `ca_keys map[string]CAKeyConfig`. Each entry maps
a host-group name to its own CA key — a local PEM file or an Azure Key Vault
(AKV) key. CA selection: `caKeyFor(hp)` returns the first `hp.Groups[i]` present
in `groupCAs`, else `defaultCA`. `ca_keys["_default"]` overrides the legacy
`ca_key` when both are present. `internal/ca/loader.go` (`LoadGroupCAs`,
30s timeout) is shared by `cmd/signer` and `internal/broker`. AKV
(`internal/ca/akv.go`) backs `crypto.Signer` with RSA and EC P-256/P-384/P-521
(Ed25519 only in local PEM mode); EC raw `R‖S` signatures are converted to DER.

### Session recording (v1.10.0)

`shell` and `pty` sessions are recorded to **ASCIIcast v2** (`.cast`) files in
`session_recording_dir`, one per session (`<session_id>.cast`, correlatable with
the audit log). Captures stdin (`"i"`), stdout (`"o"`), stderr (`"e"`); in PTY
mode stdout/stderr merge into `"o"`. `exec` and one-shot are not recorded (their
output is already in the MCP response / audit log). `internal/recording/recorder.go`
is thread-safe; permissions `0o600`. No automatic rotation.

### Code quality

**Hardening v1.4.1 (MCP/Snyk review).** Twelve findings fixed C→A→M→L: session
ownership check (C1); HTTP timeouts (A1) and body/read limits (A2); SSH exec
timeout + output cap (A3); audit chain restore on restart (A4); audit errors
logged not swallowed (M1); session limits (M2); `iat` validation (M3); newline
rejection in session exec (M5); PEM CA runtime warning (L1); audit log rotation
(L2); MCP input validation (L4). The A1/A2 pass was extended to `cmd/broker` in
v1.12.0.

**Quality phases F1–F5 (v1.8.1–v1.9.3).** gofmt hygiene; `t.Parallel()` in 63
unit tests; `context.Context` threaded through the broker/signer request path and
SSH network I/O (minor interface bump on `Signer.SignIntent`; `crypto.Signer`
backends such as AKV enforce their own signing timeout); long-function refactor
(no body > 80 lines); full English normalization of comments/errors/CLI strings.
`CODING_STYLE.md` codifies the rules with mechanical checks.

### OAuth/OIDC frontend

**HTTP+OAuth2/OIDC frontend (v1.4.0).** The MCP spec reserves OAuth for HTTP
transports (stdio relies on process isolation). `cmd/mcp-broker-http` implements
RFC 9728 + OAuth 2.1: no token → `401 WWW-Authenticate` pointing at
`/.well-known/oauth-protected-resource`; the client does Authorization Code +
PKCE and retries with a bearer token; the broker validates the JWT **locally**
against the issuer's JWKS (`go-oidc`, cached/rotated) — no per-request round-trip,
no client_secret. `TokenInfo.UserID` → `Caller.ID` → audit; `groups_claim` →
`Caller.Groups` → `Intent.EndUserGroups` → per-user RBAC. Tools and logic are
shared with stdio via `internal/mcpserver.Register`; the only difference is
`CallerFunc(ctx) → broker.Caller`. **Fail-closed (v1.11.2):** missing groups
claim (when configured) or missing `iat` (when `max_token_age_seconds > 0`)
rejects the token.

---

## Component map

| Component | Holds CA key? | Holds state? | Role |
|---|---|---|---|
| `cmd/mcp-broker` (stdio) | no | sessions | local MCP frontend for the model |
| `cmd/mcp-broker-http` | no | sessions | network MCP frontend (OAuth2/OIDC) |
| `cmd/broker` | no | sessions | HTTP+mTLS one-shot frontend |
| `cmd/control-plane` | **no** | approvals, behavior | optional PEP (approval + guardrails) |
| `cmd/signer` | **yes** | none | sole CA custodian; policy + RBAC + signing |
| `cmd/broker-ctl` | no | none | operator CLI for `signer.json` + audit + approvals |

See [OPERATIONS.md](OPERATIONS.md) for how to run and configure each, and the
file tree in [HANDOFF.md](https://github.com/luisgf/ssh-broker/blob/main/docs/HANDOFF.md) for the package layout.
