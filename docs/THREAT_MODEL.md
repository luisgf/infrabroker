# Threat Model — ssh-broker

What this system defends, against whom, and — explicitly — what it does **not**
cover. For how the mechanisms work see [ARCHITECTURE.md](ARCHITECTURE.md); to
report a vulnerability see [SECURITY.md](SECURITY.md).

---

## Premise

An AI agent needs to run commands on Linux hosts over SSH. The naive approach —
hand the agent a static SSH key — fails because the key is exfiltratable (prompt
injection, memory dump, a leaked tool log) and, once stolen, is valid until
manually revoked. ssh-broker removes the long-lived credential from the agent's
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
already open. The preflight revalidates host access, end-user groups, sudo,
sudo_user, PTY, and the physical SSH chain (`addr`/`user`/`host_key`/`jump`);
if the host route changed since the session was opened, the broker rejects the
next command and the caller must open a fresh session. On command-policy hosts,
`mode=exec` commands are also checked before execution, and `shell`/`pty` session
commands are rejected because stateful command streams are not independently
verifiable. This protects against a compromised/prompt-injected model using the
normal broker tool path. It does **not** survive a compromised broker that obtains
a session cert and skips the preflight. On hosts without a command policy, the
command text itself is not restricted by ssh-broker; it can run anything the
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
certificate). The client-supplied `end_user` only qualifies the subject
(`<broker CN>:<end_user>`) when the broker CN is listed in the control plane's
`trusted_forwarders` — i.e. a broker the operator trusts to authenticate end
users (e.g. via OIDC). For any other CN the unauthenticated `end_user` is
ignored, so a client **cannot** reset baselines or rate limits by rotating it
(fixed in v1.12.6). The residual gap is narrower: a *trusted* forwarder that is
itself compromised can still rotate the `end_user` half of its own subject.
In `enforce`, a novel host/command is not learned while it is pending approval;
retrying the same unapproved anomaly remains anomalous. Behavior remains a
detection layer, not the authoritative containment boundary: the hard controls
are the signer-side policy and approval gate, which a broker cannot bypass.

### 3. No certificate revocation (KRL)
Mitigation is the short TTL (minutes). A certificate leaked within its validity
window is usable until it expires; there is no way to cut it short.
- **Roadmap:** a `/v1/revoke` endpoint generating an OpenSSH KRL by serial, plus
  `RevokedKeys` in sshd. Tracked in [HANDOFF.md](https://github.com/luisgf/ssh-broker/blob/main/docs/HANDOFF.md).

### 4. No rate limiting on the signer itself
The only rate limit lives in the control plane (optional, and its subject is
broker-asserted). The signer — the component that must not be DoS'd — has request
body/timeout limits but no per-CN request-rate cap.
- **Roadmap:** per-broker-CN rate limiting in the signer.

### 5. In-memory state → single instance
Sessions, approvals, and behavior baselines live in process memory. Running
multiple broker or control-plane replicas would split this state. Horizontal
scaling requires externalizing it (e.g. Redis with TTL).

### 6. `callers` is default-open
A broker CN absent from the `callers` table has **no** group restriction (it
sees and can sign for every host). This is backward-compatible by design, but it
means forgetting to list a CN fails open, not closed.
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
`[WARN]` flags this). Production should use AKV (supported) or another
HSM/KMS-backed `crypto.Signer`. The seam exists; using PEM in production is an
operator error the code warns about but cannot prevent.

### 8. Secrets in commands are logged and recorded verbatim
A command is written as-is to the broker and signer audit logs and, for
`shell`/`pty` sessions, to the ASCIIcast recording. A credential passed inline —
`mysql -psecret`, `PGPASSWORD=… pg_dump`, `curl -H "Authorization: Bearer …"` —
is therefore persisted in plaintext in the chained audit log and in the `.cast`
file. There is **no redaction or masking**.
- **Mitigation today:** prefer credential-free invocations (env files on the
  host, `~/.pgpass`, secret managers) and treat audit logs / recordings as
  sensitive at rest (`0600`, restricted directories). A configurable masking
  pattern set is a roadmap item.

### 9. Audit failure is fail-open
If writing an audit entry fails (disk full, I/O error), the failure is logged
but the operation **still proceeds** — issuance and execution are not blocked.
This favors availability over a hard guarantee that every action is recorded. A
compliance deployment that requires "no audit, no action" would need a
fail-closed toggle (not yet implemented).
- **Mitigation today:** monitor the process log for `error writing audit log`
  warnings and alert on audit-write failures; keep the audit volume healthy.

### 10. Out of scope entirely
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
| Signer/operator compromise | **Out of scope** — trusted root |

The credential-custody story is strong and complete. The action-control story is
strong for one-shot and weaker for sessions because per-command filtering is
broker-enforced, not host-enforced. Closing gaps #1 and #3 would be the
highest-value security investments.
