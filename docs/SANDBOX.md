# infrabroker with a sandboxed agent (ASP)

[Agent Sandbox Platform (ASP)](https://github.com/luisgf/agent-sandbox-platform)
and infrabroker solve **different** layers of the same problem, and compose
cleanly:

- **ASP** decides *where the agent's code runs and what network it can reach*:
  one microVM per agent session, deny-by-default egress (HTTP(S) and DNS only,
  by hostname, per tenant), and the operator's credentials kept on the host —
  nothing long-lived ever enters the guest;
- **infrabroker** decides *how that agent acts on infrastructure without ever
  holding a credential*: the model requests an action, a separate signer checks
  it against per-command policy and human approval, mints a minutes-long SSH
  certificate, executes, and returns only the output.

Put together: **the agent holds no credential anywhere** — neither on the
machine that runs its code, nor for the machines it manages. The only path from
a sandbox to your infrastructure is HTTPS to a broker that does not hold the
key either.

Each project works on its own. ASP is pre-0.1.0 (no release yet); infrabroker is
released. The pairing is the reference architecture, not a requirement. The same
decision seen from the ASP side is its
[ADR-0019](https://github.com/luisgf/agent-sandbox-platform/blob/main/docs/adr/0019-acceso-a-infraestructura.md)
and the how-to
[Usar ASP con infrabroker](https://github.com/luisgf/agent-sandbox-platform/blob/main/docs/how-to/infrabroker.md)
(both in Spanish, like the rest of ASP's docs).

---

## Two facts that make the pairing work, verified in both code bases

1. **An ASP guest cannot SSH anywhere.** In `enforce` mode the node's proxy and
   nftables rules let the guest out only over HTTP(S) and DNS, to the tenant's
   allowlist of hostnames. `infrabroker serve-mcp-http` is HTTPS: it fits the
   allowlist like any other destination. The SSH connection **originates at the
   broker, outside the sandbox**; the guest never needs port 22, so ASP's
   "egress filters HTTP(S) only" limit stops mattering for infrastructure access.
2. **infrabroker's stdio mode keeps the broker's mTLS client certificate on the
   same OS that executes whatever the agent writes.** stdio isolation is "the OS
   process" ([THREAT_MODEL](THREAT_MODEL.md), *Model → broker*). ASP moves the
   hostile code to another machine — the microVM — and ASP's node, the most
   privileged host in that system (root, the VMM, every sandbox's disk), is
   where the broker must **not** live (see *Where the broker runs* below).

---

## What each layer enforces — stated precisely

| Control | Enforced by | Notes |
|---|---|---|
| The agent's code runs in a microVM, not on a host | **ASP node** (Cloud Hypervisor, KVM) | the VM is the boundary; the VMM runs unprivileged, one user per VM |
| The guest reaches only allowlisted hostnames over HTTP(S)/DNS | **ASP node** (proxy + DNS sink + nftables, `enforce`) | identifies the sandbox by source IP, never by guest headers; never dials loopback, the node's addresses or the guest subnet |
| The operator's SSH keys never enter the guest | **ASP node** (host SSH agent over vsock, sign-only, optional per-signature confirmation) | for **version control**: git fetch/push, deploy keys — not for reaching hosts (below) |
| Who the human behind the sandbox is | **ASP control plane** (workload token: `user_sub`, `sandbox_id`, `tenant_id`, signed with a published JWKS) | the guest chooses only `aud`; every other claim comes from the store |
| Which hosts an agent may reach, which commands, with approval | **infrabroker signer / control plane** | RBAC, command policy, `require_approval`, budgets — signer-authoritative, independent of the broker |
| Per-one-shot-command authorization | **the target host** (`sshd`, `force-command` baked into the cert) | survives a compromised broker |
| Per-session command filtering | **the broker** (or the target host with `sealed_exec`) | [THREAT_MODEL §1](THREAT_MODEL.md) |
| Signed, hash-chained audit of every action | **infrabroker** (signer, broker, correlated with `sshd` by `serial`) | with the end user and, when configured, the sandbox (`end_user_context`) |
| Append-only event journal of the sandbox (create, exec, stop, owner) | **ASP control plane** | `sandbox_id`, `actor_sub` |

The join key between the two audits is the workload token: **`user_sub` +
`sandbox_id`**. infrabroker records the first as `end_user` (`user=` in the
certificate KeyID and the signer's audit line) and the second as
`end_user_context` (`ctx=` in the KeyID), see *Phase 1*. On the ASP side
`user_sub` is the sandbox's **`owner_sub`**; the `actor_sub` of an ASP journal
event is whoever performed that event and can differ (an admin acting on
someone else's sandbox), so join on the sandbox's owner, not on the event's
actor. Two notes on sessions: infrabroker sessions are owned by the end user,
so two sandboxes of the same owner may reuse one session — the certificate
KeyID (in `sshd`'s log) carries the `ctx=` of the sandbox that opened it, and
each `session_exec` record carries the sandbox that ran the command. And the
context must be a non-secret identifier: it is written verbatim to the KeyID
and the structured audit field, which redaction does not cover.

### The SSH agent bridge is for git; infrastructure goes through infrabroker

ASP's host SSH agent bridge is a **signing oracle** for the operator's keys: the
guest never sees a private key, but it can ask for signatures with it, and a
signature is good for every host whose `authorized_keys` trusts that key. ASP
has no per-command policy and no per-action approval behind it (only an
optional per-signature confirmation). With ASP's `--local-net` tunnel up, the
session's whole egress leaves through the user's laptop with no port filter and
no allowlist: a hostile guest with the bridge reaches any LAN host that trusts
the key. That is exactly the "reusable key within the agent's reach" pattern
infrabroker exists to remove.

The split, written into both projects:

| Path | For | Not for |
|---|---|---|
| ASP's SSH agent bridge | version control: `git fetch`, `git push`, deploy keys | logging into hosts |
| infrabroker, over HTTPS through the allowlist | hosts and clusters: one action, one minutes-long certificate, policy, approval, signed audit | — |

### Vocabulary that collides

Both projects have a `control-plane` binary, "sessions", "approvals" and an
"audit", and they mean different things:

| Term | In ASP | In infrabroker |
|---|---|---|
| session | a microVM alive for hours (the agent's workspace) | an SSH connection reused across commands (`ssh_session_*`) |
| approval | one SSH signature from that sandbox, single-use, 30 s | one `require_approval` command: four-eyes, Slack/Teams/web UI |
| control plane | API, scheduler, OIDC issuer, node PKI | the optional PEP between broker and signer (approvals, guardrails) |
| audit | event journal (`actor_sub`) + proxy log (`sandbox_id`) | hash-chained, Ed25519-signed log keyed by `serial` |

---

## Phase 0 — the harness outside the guest (works today, zero code)

The agent harness (OpenCode or similar) runs on the user's laptop or on the ASP
node; each of the model's bash calls goes to the ASP session (`asp session
exec`); infrabroker runs **next to the harness** as a stdio MCP server, and it
is the process that opens the SSH connections. Nothing of infrabroker enters the
guest.

```
model ──bash────────────▶ harness ──asp session exec──▶ ASP control plane ──▶ microVM (no :22, no keys)
model ──ssh_execute…────▶ harness ──MCP stdio─────────▶ infrabroker serve-mcp ──mTLS──▶ signer
                                                                 └── SSH, minutes-long cert ──▶ target host
```

- What runs in the microVM: the model's shell commands, under the session's
  egress policy.
- What runs in infrabroker's process, never in the guest: `ssh_execute`,
  `ssh_session_*`, `ssh_put_file` / `ssh_get_file`, `k8s_*`, the SSH connection
  and the certificate.
- Where the keys are: none in the guest; the CA in the signer.

Setup: ASP's OpenCode integration plus an `mcp` block that launches
`infrabroker serve-mcp` (ASP ships the example,
`integrations/opencode/opencode.infrabroker.json`). Check it by asking the agent
for `hostname && id` (the guest answers), an `ssh_execute` of `uptime` on a host
(the signer logs `issued` with the `serial`, the model sees only stdout), and
`ssh <host>` from bash (it must fail in the proxy).

## Phase 1 — the agent runtime inside the sandbox

When the agent **lives in the guest** (ASP's browser/desktop variant, or any
runtime you do not want on the host), its infrabroker calls leave the sandbox:
the guest talks to `infrabroker serve-mcp-http` over HTTPS with the **ASP
workload token** as the bearer. Nothing of this is infrabroker-specific code on
the ASP side; on the infrabroker side it is configuration plus the attribution
context described below.

### Where the broker runs: on the infrabroker host, never on the ASP node

ASP's proxy refuses to dial loopback, the node's own addresses (aliases
included) and the guest subnet, by design, and no exception is opened for the
broker. So `serve-mcp-http` cannot sit on the node behind the allowlist. It
runs on **the infrabroker host** — the one this project already recommends for
the signer — and its hostname goes into the tenant's egress allowlist. This is
not only the zero-code option: the ASP node is the most privileged machine in
that system and the one that runs the hostile code; the broker's mTLS client
certificate has no business there. The sentence that sums the pairing up: *the
machine that runs the agent's code and the machine that holds the keys are
different machines.* As a bonus, every certificate's `source-address` pins to
the broker host's stable IP, as on a [mesh](MESH.md).

If the broker host has a private (RFC 1918) address, the ASP node operator has
to open that range with `--egress-allow-cidr`; a tenant's allowlist alone
cannot.

### The token

From the guest, a request to ASP's identity socket (vsock CID 2, port 26502)
with the audience infrabroker expects:

```
POST /v1/tokens/oidc   {"aud": "infrabroker"}
→ { "access_token": "<JWT>", "token_type": "Bearer", "expires_in": 300, "claims": {…} }
   claims: sub=sandbox/<id>  user_sub=<owner>  sandbox_id=<id>  tenant_id=<tenant>  (TTL ≤ 5 min)
```

The guest image ships no MCP client and no vsock HTTP client; the runtime that
needs them brings them. The token lives five minutes by default: mint one per
call, or at least one per TTL.

### The infrabroker side

The HTTP frontend with ASP's control plane as the issuer, the human owner as
the identity, and the sandbox as attribution context; the signer re-validates
the same token inside its own trust boundary. Full recipe, with the Keycloak
one next to it: [OPERATIONS § Per-agent identity](OPERATIONS.md#per-agent-identity-an-asp-sandbox-workload-token).

```jsonc
// frontend (serve-mcp-http)
"oauth": {
  "issuer":        "https://asp.example.internal",   // ASP_OIDC_ISSUER of the ASP control plane
  "audience":      "infrabroker",
  "user_claim":    "user_sub",                        // the human owner of the sandbox
  "context_claim": "sandbox_id",                      // → KeyID ctx=, audit end_user_context
  "max_token_age_seconds": 300
}
// signer.json: the same block as "end_user_oidc", and on the caller CN
"callers": { "asp-broker": { "allowed_groups": ["…"], "require_verified_end_user": true } }
```

`context_claim` is **attribution, never authorisation**: a token without the
claim is accepted and simply carries no context; with
`require_verified_end_user` the signer takes the context from the verified JWT
and discards whatever the broker asserted, so a compromised broker cannot stamp
an arbitrary `sandbox_id` into the audit of a verified request. Mirror
`context_claim` in the signer's `end_user_oidc` block: a gated caller whose
signer has no `context_claim` gets **no** context (the broker's assertion is
dropped, never kept), and the signer logs a warning saying so.

### Honest limits of Phase 1

- **Authorization is per broker CN, not per sandbox.** Any guest of that ASP
  control plane can mint `aud=infrabroker` (the guest chooses `aud`), and
  without a `groups_claim` the signer's per-user RBAC is off: every sandbox
  owner reaches whatever that broker CN may reach. The token gives
  *attribution*, not *scope*. A groups/roles claim in ASP's workload token is
  ASP's Phase 2.
- **A human approval that outlives the token fails closed.** With
  `require_verified_end_user` the signer re-validates the bearer when the
  approved request is forwarded; an ASP token is ≤ 5 minutes old by then or it
  is not, and a late approval is denied and must be requested again with a
  fresh token ([THREAT_MODEL §2](THREAT_MODEL.md)).
- **With ASP's `--local-net`** the session's default route leaves through the
  user's laptop: the broker's hostname must resolve and be reachable from that
  network, not from the node.
- Nothing of this is exercised against a real ASP node with KVM yet. The
  ASP-shaped token path is covered by `TestASPWorkloadToken`
  (`internal/brokermain`) and `lab/run_asp_oidc_lab.sh`, which run it with a toy
  issuer; Phase 0 is checked by hand.

---

## Setup checklist

1. **Phase 0:** run infrabroker as a stdio MCP server next to the harness
   (ASP's OpenCode integration + `opencode.infrabroker.json`); keep ASP's node in
   `enforce`; keep the SSH agent bridge for git only (confirmation on, or the
   bridge off, when `--local-net` is used).
2. **Phase 1:** put `serve-mcp-http` on the infrabroker host; add its hostname
   (and port, if not 443) to the ASP tenant's egress allowlist; configure
   `oauth` with ASP's issuer, `user_claim: "user_sub"`, `context_claim:
   "sandbox_id"`; mirror it as `end_user_oidc` in the signer with
   `require_verified_end_user` on the broker's CN.
3. Correlate: infrabroker's `end_user` + `end_user_context` ↔ ASP's
   `owner_sub` + `sandbox_id`.
4. Nothing else changes: policy, approvals, recording and the audit chain work
   exactly as documented in [OPERATIONS.md](OPERATIONS.md).
