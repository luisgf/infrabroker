# infrabroker over a mesh (NetBird / Tailscale)

A mesh VPN (NetBird, Tailscale, or any WireGuard overlay) and infrabroker solve
**different** layers of the same problem, and compose cleanly:

- the **mesh** provides the *network path* — it decides which machines can reach
  which, over an encrypted overlay, without exposing `sshd` to the public
  internet;
- **infrabroker** provides the *session layer* on top of that path — a per-
  operation ephemeral SSH certificate, signer-side policy and human approvals,
  endpoint session recording, and a hash-chained, Ed25519-signed audit trail.

You get the mesh's zero-trust connectivity **and** per-command authorization,
approvals, and a non-repudiable record of every action — neither tool has to
give up what it is good at.

---

## Zero code: infrabroker dials plain TCP

infrabroker does not care how the packets are routed. The broker opens an
ordinary TCP connection to the target's `sshd` — `net.Dialer.DialContext(ctx,
"tcp", addr)` in [`internal/ssh/run.go`](https://github.com/luisgf/infrabroker/blob/main/internal/ssh/run.go)
— and every hop in a `ProxyJump` chain is dialed the same way. If the mesh makes
an address reachable, infrabroker can use it. There is nothing mesh-specific to
configure and no plugin to install.

Concretely, point a host's `addr` (local mode) or the signer's host entry
(remote mode) at the target's **overlay** address instead of a public one:

```jsonc
// signer.json — the host's addr is its mesh IP / MagicDNS name
"hosts": {
  "web01": {
    "addr": "100.64.0.12:22",        // NetBird / Tailscale overlay address
    "user": "deploy",
    "host_key": "ssh-ed25519 AAAA…",
    "principal": "host:web01",
    "source_address": "100.64.0.5/32" // the broker's stable overlay IP (see below)
  }
}
```

The target's `sshd` needs no exposure beyond the mesh; the broker reaches it
over the overlay exactly as it would over a private LAN.

## Stable overlay IPs make `source_address` pinning practical

Every certificate infrabroker issues carries a `source-address` critical
option, so a stolen certificate can only be replayed from the pinned network
location — the last line of defense enforced by the target's `sshd`. On the
public internet, egress IPs are often dynamic or shared, which makes tight
pinning awkward. A mesh assigns each peer a **stable overlay IP**, so you can
pin `source_address` to the broker's overlay address (`100.64.0.5/32` above) and
have it stay correct across restarts and network changes. The mesh's stable
addressing turns a best-effort control into a precise one.

## What each layer enforces — stated precisely

It matters exactly where each control lives, because a mesh's SSH features and
infrabroker's overlap only partially:

| Control | Enforced by | Notes |
|---|---|---|
| Network reachability, peer ACLs | the mesh | who can open a TCP connection to whom |
| Per-**one-shot-command** authorization | the **target host** (`sshd`) | the command is baked into the certificate's `force-command`; a compromised broker cannot bypass it |
| Per-**session** command filtering | the **broker** (or the **target host**, with `sealed_exec`) | `ssh_session_exec` is broker-preflighted; `shell`/`pty` sessions are rejected once a command policy is active. Broker-enforced by default; set `sealed_exec` on a host to make it **host-enforced** — the shim runs only signer-signed envelopes — [THREAT_MODEL.md §1](THREAT_MODEL.md) |
| Human approval, RBAC, rate limits | the **signer / control plane** | signer-authoritative, independent of the broker |
| Session recording (asciicast) | the **broker** | one `.cast` per session, correlated with the audit log by `session_id` |
| Signed, hash-chained audit trail | the **broker** | `broker-ctl audit verify` |

The honest line: one-shot `force-command` authorization survives a compromised
broker because the **host** enforces it; session command filtering does not by
default (it is broker-enforced — [gap #1](THREAT_MODEL.md)). Use `mode=exec`
sessions, not `shell`/`pty`, on policy-restricted hosts — and where you need the
same host-enforced guarantee for sessions, turn on `sealed_exec` for that host:
its session cert is pinned to `infrabroker-shim`, which runs nothing without a
signer-signed per-command envelope.

## Better together, per mesh

### NetBird

NetBird routes and applies peer ACLs; infrabroker adds the session layer NetBird
does not have. Session recording in particular is a long-standing NetBird
request ([netbird issue #3146](https://github.com/netbirdio/netbird/issues/3146),
open since January 2025) — infrabroker records to portable asciicast files
against **stock `sshd`**, with no agent on the target beyond `TrustedUserCAKeys`.

### Tailscale

Tailscale *does* ship session recording (`tsrecorder`) and Tailscale SSH, so the
"better together" angle here is narrower and worth stating plainly: infrabroker
works with **stock `sshd`** and standard SSH certificates, so you keep per-
command authorization, approvals, and a signed audit trail **without adopting
Tailscale SSH** or its recording stack — no lock-in to one vendor's SSH
implementation. Run the broker over the tailnet for the path; keep your existing
`sshd` and CA-based access control.

---

## Setup checklist

1. Join the broker host (and every target) to the mesh; confirm the broker can
   `ssh` a target over its overlay address.
2. Set each host's `addr` to its overlay IP / MagicDNS name (local mode:
   `config.json`; remote mode: `signer.json`).
3. Pin `source_address` to the broker's stable overlay IP (`/32`).
4. Keep `sshd` bound to the overlay interface (or firewalled to mesh peers only)
   — the public internet never sees it.
5. Nothing else changes: policy, approvals, recording, and the audit chain work
   exactly as documented in [OPERATIONS.md](OPERATIONS.md).
