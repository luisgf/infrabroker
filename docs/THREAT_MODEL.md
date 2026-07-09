# Threat Model — infrabroker

What this system defends, against whom, and — explicitly — what it does **not**
cover. For how the mechanisms work see [ARCHITECTURE.md](ARCHITECTURE.md); to
report a vulnerability see [SECURITY.md](SECURITY.md).

---

## Premise

An AI agent needs to run commands on Linux hosts over SSH. The naive approach —
hand the agent a static SSH key — fails because the key is exfiltratable (prompt
injection, memory dump, a leaked tool log) and, once stolen, is valid until
manually revoked. infrabroker removes the long-lived credential from the agent's
reach: the agent receives only command **output**, never key material, and every
operation uses a fresh, narrowly-scoped, minutes-long certificate.

The design defends two distinct threats:

1. **Credential theft** — an attacker who reads the agent's memory/logs/traffic
   should gain nothing reusable.
2. **A compromised agent** — an agent under prompt injection should not be able
   to run arbitrary commands, only those the operator's policy permits.

The first is fully addressed. The second is addressed for one-shot execution and
partially for sessions — see the gaps below.

---

## Assets

| Asset | Why it matters |
|---|---|
| **CA private key** | Signs every SSH certificate. Whoever holds it can mint access to any managed host. The crown jewel. |
| **Ephemeral key pairs** | One per operation, in broker memory only. Short-lived; their value is bounded by the cert TTL. |
| **Audit log integrity** | The forensic record. Tampering would hide abuse. |
| **Host access** | The ultimate target: shell on production Linux hosts. |
| **Policy & RBAC config** (`signer.json`) | Defines who may reach what. Its integrity equals the access boundary. |

---

## Actors & trust levels

| Actor | Trust | Notes |
|---|---|---|
| **AI model** | Untrusted | Assumed subject to prompt injection. Sees only output; never holds credentials. |
| **Broker** (`mcp-broker`, `mcp-broker-http`, `broker`) | Semi-trusted — *may be compromised* | Holds ephemeral private keys transiently. Never holds the CA key. Authenticates to the signer with its own mTLS CN. |
| **Control plane** (`control-plane`) | Semi-trusted (PEP) | Orchestrates approval and behavior guardrails. **No CA key.** Trusted by the signer only for `on_behalf_of`/`approved` if its CN is in `trusted_forwarders`. |
| **Signer** (`signer`) | Trusted | **Sole custodian of the CA key.** Authoritative for policy, RBAC, and the approval gate. Kept deliberately minimal and stateless. |
| **Operator** | Trusted | Edits `signer.json`, approves out-of-band, holds approver/reload certs. |
| **Remote host `sshd`** | Trusted endpoint | Enforces `force-command`, `source-address`, principals, and sudoers — the last line of defense. |

The central design choice follows from this table: **keep the CA key in the
smallest, most-trusted component** (the signer) and let everything else operate
without it. A compromised broker or control plane cannot forge certificates.

---

## Trust boundaries & guarantees

### Model → broker
- The model never receives key material — only `stdout/stderr/exit_code`.
- **stdio:** isolation is the OS process (the MCP client launches the broker).
- **HTTP:** OIDC bearer token, validated locally against the issuer JWKS
  (signature, `iss`, `aud`, `exp`, and `iat` when a max age is set). **Fail-closed
  (v1.11.2):** a missing groups claim (when `groups_claim` is configured) or a
  missing `iat` (when `max_token_age_seconds > 0`) rejects the token, so a
  misconfiguration cannot silently disable per-user RBAC.

### Broker → signer (and via control plane)
- **mTLS with TLS 1.3 minimum.** The caller identity is the client-cert CN — not
  assertable by the broker in the request body.
- **The broker sends an intent, not constraints.** The signer derives every
  certificate constraint from policy; the broker cannot widen its own grant.
- **Per-group RBAC** (broker CN → `allowed_groups`) and optional per-host
  `allowed_callers` both gate access; a broker must pass both.
- **Impersonation is unforgeable:** `on_behalf_of` and `approved` are honored
  **only** when the mTLS CN is in `trusted_forwarders` (the control plane).

### Signer → host
- **One-shot:** the command is baked into the cert's `force-command` by the CA
  key. sshd enforces it; the broker cannot alter it. This is the strongest
  guarantee in the system — it survives a fully compromised broker.
- **Scope pinning:** `source-address` (bastion egress IP on jump chains),
  `ValidPrincipals`, and a minutes-long TTL bound where, as whom, and how long a
  cert is usable. No agent/X11 forwarding extensions.
- **Command policy** (allowlist/denylist/require-approval, optionally with
  `shell_parse` AST checking) restricts *what* one-shot command may run, and
  newlines are rejected so extra lines cannot be smuggled past the regexes.

### Approval & audit
- **Approval gate is authoritative and unavoidable:** the signer issues no cert
  for a `require_approval` command unless `approved` arrives from a trusted
  forwarder. A direct broker cannot self-approve, and the originator of a
  request cannot decide its own approval (four-eyes, even if its CN is an
  approver). Each approval is consumed once.
- **Approval-bridge trust (`cmd/approval-bridge`, #120).** The chat bridge
  decides with a **single approver CN**, so its residual dilutions are, by
  design: (1) *who may approve* moves partly from the mTLS `approval.callers`
  allowlist to **chat channel membership** run by an external SaaS — anyone who
  can click a button in that channel can approve; (2) approver attribution is
  **bridge-asserted** — the signed audit records the bridge's approver CN; the
  platform user id who clicked is written only to the bridge's own process log
  (operational, not tamper-evident), so the decision is not tied to a
  cryptographically verified approver; (3) the CN-level
  four-eyes guard still holds (the bridge CN differs from any broker CN), but
  per-human approver certs collapse into that one CN. The control plane's
  consumed-once and four-eyes guards are unchanged. For a single operator,
  #118's in-chat elicitation avoids the bridge entirely; for stronger
  attribution, approve via `broker-ctl` / the web UI (per-human mTLS certs).
- **Audit log** is append-only, SHA-256 hash-chained, and Ed25519-signed per
  entry; any deletion/reordering/modification is detectable by replaying the
  chain. The chain stays continuous **across log rotation** — each rotated-to
  file's first entry links to the previous file's last hash — so dropping a
  whole rotated segment (or truncating the active file and restarting, which
  re-anchors to genesis) is detectable with **`broker-ctl audit verify --all`**,
  which verifies the whole segment set and the cross-file linkage. Note that
  single-file `verify` accepts the first entry's `prev_hash` as an unchecked
  seed, so cross-segment integrity requires `--all` (v1.13.0). Three logs
  (signer, broker, sshd) correlate by cert `serial`.

---

## Defense in depth (one-shot)

A single malicious one-shot command must pass, in order:

1. Frontend auth (process / OIDC token).
2. Broker→signer mTLS + group RBAC + `allowed_callers`.
3. Per-user RBAC (OIDC groups ∩ host groups), if applicable.
4. Command policy (allow/deny, `shell_parse`, newline rejection).
5. Approval gate (if `require_approval`).
6. Behavior guardrails (if the control plane is in `enforce`).
7. On the host: `force-command`, `source-address`, principal, **sudoers**.

Layers 4–7 are what make this more than a credential vault.

**Process isolation on a colocated host.** The reference deployment
(`deploy/`) runs each service as its **own system user** with a per-service
PKI subdirectory and per-service config group. A compromised broker frontend
therefore cannot read the signer's CA key (`pem` custody), policy, grant
state, audit seed, or mTLS key — nor impersonate the signer, the control
plane, or the admin CLI (whose material is root-only). Writes were already
contained by the systemd sandbox; the user split contains reads. Running the
signer on a separate host remains the stronger posture.

---

## Explicit non-goals & gaps

These are deliberate limits, not oversights. Naming them is the point of this
document — they define where additional controls (or a different tool) are
needed.

### 1. Session command firewall is broker-enforced, not host-enforced
`force-command` only applies to one-shot. In a session the cert authenticates
the connection and commands flow as separate channels; the host does not see the
signer's per-command decision. The broker preflights every `ssh_session_exec`
against the current signer policy, so policy reloads affect sessions that were
already open. The preflight revalidates target access, bastion access, end-user
groups, sudo, sudo_user, PTY, and the physical SSH chain
(`addr`/`user`/`host_key`/`jump`); if the host route changed since the session
was opened, the broker rejects the next command and the caller must open a fresh
session. On command-policy hosts,
`mode=exec` commands are also checked before execution, and `shell`/`pty` session
commands are rejected because stateful command streams are not independently
verifiable. This protects against a compromised/prompt-injected model using the
normal broker tool path. It does **not** survive a compromised broker that obtains
a session cert and skips the preflight. On hosts without a command policy, the
command text itself is not restricted by infrabroker; it can run anything the
host's sudoers/principal allow.
- **Mitigation today:** prefer `ssh_execute` on sensitive hosts when you need the
  host-enforced `force-command` guarantee; use `mode=exec` sessions only when
  connection reuse matters and broker-side preflight is an acceptable control.
  Keep `source-address` + principal + restrictive sudoers. Note the certificate
  TTL bounds *one-shot* exposure but **not** an open session: OpenSSH validates
  the certificate only at authentication, so an established session lives until
  the reaper closes it — bound by `session_idle_seconds` / `session_max_seconds`,
  which is the value to set as the session exposure window.
- **Possible future control:** host-side command wrappers or short-lived
  per-command tokens could make session exec filtering host-enforced too.
- **Composition note (v1.14.0):** a host's effective firewall is the composition
  of its inline `command_policy` and the policies of all its groups (additive:
  deny wins, allow is a union). This makes **group membership security-relevant**:
  assigning a host to a group can *widen* its allow-set, not only narrow it. Treat
  `group_command_policies` as part of the firewall config, keep allowlists minimal,
  and use the `_default` group (applies to every host) for global denylist
  guardrails (e.g. `^rm `, `^reboot`). A host left out of every allowlist group but
  carrying a `_default` denylist is default-allow except for the denied patterns —
  use an allowlist group for true least-privilege.

### 2. Behavior guardrails are detection, not containment
The guardrail subject is the **authenticated broker CN** (the mTLS client
certificate). For guardrail keying, the client-supplied `end_user` only
qualifies the subject (`<broker CN>:<end_user>`) when the broker CN is listed
in the control plane's `trusted_forwarders` — i.e. a broker the operator
trusts to authenticate end users (e.g. via OIDC). For any other CN the control
plane ignores the unauthenticated `end_user` when keying baselines and rate
limits, so a client **cannot** reset them by rotating it (fixed in v1.12.6);
the residual guardrail gap is a *trusted* forwarder that is itself compromised
rotating the `end_user` half of its own subject.
In `enforce`, a novel host/command is not learned while it is pending approval;
retrying the same unapproved anomaly remains anomalous. Behavior remains a
detection layer, not the authoritative containment boundary: the hard controls
are the signer-side policy and approval gate, which a broker cannot bypass.

Note the scope of that gating: it protects the **guardrail subject only**. The
signer itself accepts `end_user` / `end_user_groups` verbatim from **every**
authenticated caller CN — its `trusted_forwarders` list gates only `approved`
and `on_behalf_of`, not identity. End-user identity is verified where the
OIDC token lives (the `mcp-broker-http` frontend); by the time an intent
reaches the signer it is a caller-asserted label. Concretely, for any CN in
`callers`:

- The asserted `end_user` is stamped verbatim (charset-sanitised, never
  authenticated) into the certificate `KeyID` (`user=`) and the signed audit
  trail: a compromised or malicious broker can attribute its actions to an
  arbitrary end user. The audit log proves *which CN* asserted the identity,
  not that the identity is real.
- Asserted `end_user_groups` select the Kubernetes `sa_binding` and, when
  omitted (`null`), skip the per-user host-group narrowing. They can never
  widen access beyond the caller CN's own allowlist, but with
  group-differentiated `sa_bindings` the choice of ServiceAccount rests on a
  claim the signer does not verify.
- A grant or waiver scoped only by `end_user` (its `caller` field left empty)
  matches any caller CN asserting that name.

The identity boundary at the signer is therefore the **mTLS caller CN**;
`end_user` is attribution within it, trustworthy exactly as far as the
asserting broker is. Keep the `callers` table minimal, scope grants by
`caller` (not only `end_user`), and treat group-differentiated `sa_bindings`
as trusting every CN authorised for that cluster.
- **Possible future control:** signer-side re-validation of the end user's
  OIDC token (deriving `end_user`/groups from the verified JWT rather than
  the broker's assertion) would move end-user authenticity inside the trust
  boundary.

### 3. No certificate revocation (KRL)
Mitigation is the short TTL (minutes). A certificate leaked within its validity
window is usable until it expires; there is no way to cut *that individual
issued cert* short.

The **kill switch** (#117) addresses the exposures a KRL would, at the policy
layer rather than by distributing revocation lists to every `sshd`. A frozen
subject (`broker CN`, `end_user`, `session_id`, or certificate `serial`,
`POST /v1/freeze`, `reload_callers` only):
- is denied every new certificate at `POST /v1/sign` and all connectivity at
  `GET /v1/hosts` — so one-shot, session-open, and each session-exec preflight
  fail immediately — and has its runtime grants and approve-and-learn waivers
  revoked. This is enforced by the signer today.
- is streamed to brokers via `GET /v1/revocations`, which every broker polls
  (`revocation_poll_seconds`, default 10s). A matching session is force-closed
  **including one with a command in flight** — the kill overrides the reaper's
  never-close-a-busy-session rule — so a compromised subject is bound to one
  poll interval rather than the session lifetime. `session_id`/`serial` target a
  specific session/cert; a frozen `end_user` closes all of that user's sessions;
  a frozen broker `caller` CN closes every session that broker holds.

The freeze set is fail-closed persistent (`state_db`): unlike a grant, a freeze
that failed to load would fail *open*, so the signer refuses to start on a load
error rather than silently un-freezing a blocked subject. Freezing requires
`state_db` to survive a signer restart.

- **Residual:** an already-issued **one-shot** cert stays valid for its
  remaining window (`<= max_ttl`, minutes) — a freeze denies the *next* sign and
  ends *sessions*, but does not recall a one-shot cert already handed to a live
  connection. A truly compromised broker can also ignore the revocation poll and
  skip its own session kills (though it still gets no *new* certificates); the
  signer-side deny is the hard guarantee, the broker kill is best-effort
  containment. An OpenSSH KRL by serial (roadmap) would close the one-shot gap.

### 4. Rate limiting on the signer is opt-in
The signer supports a per-CN token-bucket rate limit on `POST /v1/sign`
(`sign_rate_limit_per_min`, hot-reloadable): keyed on the authenticated mTLS
peer CN, enforced before body parsing, excess requests get `429` with a
`Retry-After` hint, and rejections are deliberately not audited so the
tamper-evident log cannot become the flooding amplifier. The residual gap is
that the cap is opt-in (0/absent = disabled, backward compatible) — set it in
production. The control plane additionally applies its own per-subject
behavioral rate limit on the forwarded path.

### 5. In-memory state → single instance
Sessions, approvals, grants, and behavior baselines live in process memory.
Running multiple broker or control-plane replicas would split this state.
Horizontal scaling requires externalizing it (e.g. Redis with TTL).
- **Mitigation (restart survival, not multi-instance):** the opt-in `state_db`
  (SQLite, write-through) persists the signer's runtime grants/waivers and the
  control plane's approval registry across restarts. The in-memory state
  remains the only state consulted on the decision path; live SSH sessions and
  behaviour baselines are intentionally not persisted (a TCP connection cannot
  be resurrected; the baseline re-learns).
- **Residual risk (crash window):** an approval is marked consumed with a
  best-effort write *after* the certificate is issued. A crash (or a state-db
  write failure, counted by `statedb_errors_total`) in that window re-exposes
  the approval as consumable once more after the restart — bounded by the
  approval TTL and the certificate TTL. Grant revocation takes the opposite
  trade: the db delete is mandatory, so a revoked grant can never resurrect.

### 6. `callers` is default-open unless `_default` is set
A broker CN absent from the `callers` table has **no** group restriction (it
sees and can sign for every host). This is backward-compatible by design, but it
means forgetting to list a CN fails open, not closed.
- **Mitigation (opt-in default-deny):** add a reserved
  `"_default": {"allowed_groups": []}` entry to `callers`
  (`broker-ctl callers add --name _default --groups ""`); unlisted CNs then
  inherit it and are denied every host. The residual gap is that the closed
  default itself is opt-in, kept for backward compatibility.
- **Mitigation:** list every broker CN explicitly; per-host `allowed_callers`
  can pin sensitive hosts regardless.
- **Control-plane role separation:** the control plane separates the broker role
  from the approver role on the signing path (`/v1/sign`, `/v1/hosts`,
  `/v1/sign/result`). With no `sign_callers` list a CN in `approval.callers` is
  denied the sign path (an approver is not a broker — secure by default); a
  non-empty `sign_callers` is an exact allowlist. An empty or control-character
  client-certificate CN is rejected (fail-closed) rather than treated as an
  unlisted, default-open identity.

### 7. CA key custody depends on deployment
Local/lab mode loads the CA key from a PEM file into process memory (a runtime
`[WARN]` flags this). Production should use a non-PEM backend behind the custody
seam: **`akv`** (Azure Key Vault; RSA/EC only) or **`agent`** — the CA private
key in a running ssh-agent backed by a YubiKey PIV slot / SoftHSM / TPM
(`ssh-add -s`), with no cgo in the signer and support for **Ed25519** CA keys
(which AKV lacks). The private key never leaves the backend. Using PEM in
production is an operator error the code warns about but cannot prevent.

### 8. Secrets in commands: redaction is opt-in and best-effort
A command is written to the broker and signer audit logs and, for `shell`/`pty`
sessions, to the ASCIIcast recording; the control plane additionally sends it
in approval notifications (log/webhook/Teams). A credential passed inline —
`mysql -psecret`, `PGPASSWORD=… pg_dump`, `curl -H "Authorization: Bearer …"` —
would otherwise persist in plaintext in every one of those sinks.
- **Mitigation:** the opt-in `redact` config block (signer, broker, control
  plane) masks secrets at every persistent/outbound sink — audit log free-text
  fields, session recordings, and the approval notification payload — using
  built-in patterns plus operator-defined RE2 rules, replacing the secret with
  `[REDACTED:<rule>]` **before** the audit entry is signed (verification is
  unaffected; the original is irrecoverable). The `approval-bridge` reads the
  original command from the control plane's `/v1/approvals` (an mTLS approver
  like any other) but masks it with the **built-in default patterns** before
  presenting it on the chat platform — an off-host sink of the same class as the
  webhook/Teams notifier — so a chat channel is never sent a secret the Teams
  notifier would have masked. Redaction never touches the decision path: the
  signer, the certificate force-command, and the mTLS approval UI (`broker-ctl` /
  the web UI) see the original command.
- **Residual risk:** pattern matching is best-effort, not DLP (see
  [SECURITY.md](SECURITY.md#redaction-is-best-effort)) — an unanticipated
  secret format survives, and output recorded in `.cast` files arrives in
  arbitrary chunks that can split a secret across two events. Prefer
  credential-free invocations (env files on the host, `~/.pgpass`, secret
  managers) and keep treating audit logs / recordings as sensitive at rest
  (`0600`, restricted directories).

### 9. Audit failure is fail-open
If writing an audit entry fails (disk full, I/O error), the failure is logged
but the operation **still proceeds** — issuance and execution are not blocked.
This favors availability over a hard guarantee that every action is recorded. A
compliance deployment that requires "no audit, no action" would need a
fail-closed toggle (not yet implemented).
- **Mitigation today:** every service exposes the
  `audit_append_failures_total` counter on its `monitor_listen` endpoint
  (`/metrics`) — alert on any increase; it is the machine-readable signal that
  the trail has a gap. The process log also carries `error writing audit log`
  warnings. Keep the audit volume healthy.

### 10. Kubernetes: token grants the SA's RBAC, not a single call
The Kubernetes target (v1.34.0) is a **credential-broker**: for an authorised
action the signer mints a bound ServiceAccount token and the broker runs the
one API call with it. Two structural differences from SSH follow, by design:
- **No inevadible per-call firewall.** SSH bakes a `force-command` into the
  certificate and sshd enforces it, so the credential does exactly one thing.
  A Kubernetes token instead carries the **whole RBAC** of its ServiceAccount
  for its lifetime (600–900s), so within that window it can do anything that SA
  may do — not only the approved action. Granularity is therefore the SA's
  native RBAC (layer B) refined by the broker's action policy (layer A), not
  "only this exact object". **Mitigation:** scope each agent ServiceAccount to
  least privilege (the layer-A default-deny policy bounds what the broker will
  *request*, but layer B is what the token actually *grants*); keep the bound
  TTL at the 600s floor; do not add `secrets` to an allow rule unless required.
- **The signer holds a standing cluster credential.** The per-cluster minter
  token (`token_file`) is a long-lived credential — unlike the SSH CA, which
  signs but never authenticates as a principal. Its RBAC is deliberately
  minimal (only `create` on `serviceaccounts/token` for the bound SAs), so a
  signer compromise yields token-minting for those SAs, not cluster-admin.
  **Mitigation:** the minter SA's Role must grant nothing else; rotate the
  `token_file` out-of-band (the signer re-reads it per mint).

The reused control plane keeps its guarantees: the action's canonical string is
recomputed by the signer and must match the structured request (so the approver
and the audit log see what runs), a `k8s_apply` manifest is never logged
verbatim (only its sha256), and `require_approval`, grants, and approve-and-learn
apply to k8s actions exactly as to shell commands.
- **Corollary for `k8s_apply` — approval gates the target, not the payload.**
  Because the manifest never leaves the broker (only its sha256 is audited), an
  approval for `apply deployments prod/api` authorizes an **arbitrary manifest
  spec** for that object — image, privileges, replicas, env — that no human
  reviewed. The API server binds the path to `metadata.name`/`namespace`, but
  not the rest of the spec, so the approver sees only the verb/resource/
  namespace/name, not *what* is applied. **Mitigation:** scope `apply` rules
  narrowly (pin `namespaces`/`names`) and reserve them for trusted flows;
  prefer `require_approval` on `apply` only where the target coordinates alone
  are a sufficient gate. This is the deliberate cost of not shipping (possibly
  secret-bearing) manifests through the control plane.

### 11. Out of scope entirely
- Confidentiality of command **output** beyond transport TLS (the model sees it
  by design).
- Compromise of the **signer host** or the **operator's** credentials (top of
  the trust chain — if the CA key host is owned, the model is moot).
- Supply-chain integrity of the Go dependencies.
- Network-level DoS below the application layer.

---

## Summary

| Threat | Status |
|---|---|
| Credential exfiltration from the agent | **Mitigated** — no reusable credential ever reaches the model |
| Compromised agent, one-shot commands | **Mitigated** — policy + force-command + approval, signer-authoritative |
| Compromised agent, sessions | **Partial** — every `ssh_session_exec` is broker-preflighted; `shell`/`pty` rejected once policy is active; host-enforced guarantee remains one-shot only |
| Compromised broker forging access | **Mitigated** — no CA key; signer derives all constraints |
| Stolen cert reuse within TTL | **Accepted risk** — no revocation; bounded by minutes-long TTL |
| Compromised agent, Kubernetes actions | **Partial** — layer-A default-deny action policy + approval; layer-B is the SA's RBAC (a bound token grants the SA's whole RBAC for its TTL, not one call — gap #10) |
| Signer/operator compromise | **Out of scope** — trusted root |

The credential-custody story is strong and complete. The action-control story is
strong for one-shot and weaker for sessions because per-command filtering is
broker-enforced, not host-enforced. Closing gaps #1 and #3 would be the
highest-value security investments.
