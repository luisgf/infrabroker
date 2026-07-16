# High availability: state inventory and design

infrabroker is **deliberately single-instance today**. This document is the
design study behind that choice ([#145](https://github.com/luisgf/infrabroker/issues/145)):
what actually blocks running two replicas, what each blocker costs, and what a
realistic first slice looks like. It is a map, not a commitment — the work is
demand-gated, and each blocker below is tracked as its own issue.

The honest summary: **multi-replica HA is a re-platforming, not a feature flag.**
It touches the persistence layer, the session model, the behavior tracker and the
audit chain, in three different processes.

## What exists today

infrabroker runs as **three separate processes**, each with its own in-memory
state and its own audit log:

| Process | Package | Holds |
|---|---|---|
| broker | `internal/broker` | live SSH sessions, host/cluster caches |
| control plane | `cmd/control-plane`, `internal/control` | approvals, behavior baselines |
| signer | `cmd/signer`, `internal/signer` | CA key, policy, grants, freezes, rate limits |

`state_db` (`internal/statedb`) exists on the **signer** and the **control plane**
only; the broker has none. It is a thin opener over `modernc.org/sqlite` (pure Go,
no CGO) against a **local file**, in WAL mode, capped at a single connection
because every consumer mutates under its own mutex.

Its architectural note is the thing to internalise before designing HA:

> the database is an **availability enhancement, not a decision-path component**:
> consumers keep their in-memory state as the source of truth on the hot path and
> mirror mutations here (write-through).

So even where state is persisted, **the in-memory map is what every request
reads**; the DB is only re-read at startup. That buys **restart survival, not
sharing** — and it is the invariant HA has to invert.

Pointing two replicas at the same SQLite file is not a shortcut: WAL needs
`-wal`/`-shm` sidecars and local POSIX locking, and the single-connection design
assumes a single writer process.

## State inventory

| Subsystem | Where state lives | Persisted? | What breaks with 2 replicas | Difficulty |
|---|---|---|---|---|
| **Live sessions** (broker) | `internal/broker/session.go` — `sessionManager{sessions map, mu}` | No (broker has no state_db) | Open on A returns a `session_id`; exec/close routed to B → "unknown or expired session". A session owns a live SSH connection/PTY. | **Hard** — not a storage problem |
| **Approvals** (control plane) | `internal/control/approval.go` — `Registry{items map, mu, db}` | Yes, write-through | Waiter polls A, approver's decision lands on B → the request times out. `issuing`/`consumed` are per-process, so four-eyes/consumed-once can double-issue. | Medium |
| **Grants** (signer) | `internal/signer/grants.go` — `GrantStore{grants map, mu, db}` | Yes, write-through | A grant added via A is invisible to B's decision path → approve-and-learn is inconsistent by which replica you hit. | Medium |
| **Freeze / kill switch** (signer) | `internal/signer/freeze.go` — `FreezeStore{frozen map, mu, db}` | Yes, durable + fail-closed | A freeze on A is unknown to B: **B keeps signing for a frozen subject**, and brokers polling B never get the kill. | **Medium-hard** (security-critical) |
| **Behavior tracker** (control plane) | `internal/control/behavior.go` — `BehaviorTracker{subjects map, mu}` | **No** — no DB variant exists | Each replica sees only its slice of traffic: baselines split-brain, and the per-subject sliding-window rate limit effectively **multiplies by replica count**. | **Hard** |
| **Rate limiter** (signer) | `internal/signer/ratelimit.go` | No | N replicas = N× the configured per-caller limit. Weakening, not a correctness break. | Easy |
| **Host-key cache** (broker) | `internal/broker/engine.go` — `sync.Map`, content-addressed | No | Nothing: deterministic, self-heals per instance. | Trivial |
| **Host/cluster caches** (broker) | `internal/broker/engine.go`, refreshed by poller | No | Nothing: the signer is the source of truth; each replica refetches. | Trivial |
| **Compiled command policy** (signer) | in-memory, rebuilt from config on reload | No (config-derived) | Nothing, as long as every replica reads the same config. | Trivial |
| **Audit chain** (all three) | `internal/audit/log.go` — single-writer `O_APPEND` file, chain head in memory | Own file | Each replica writes an **independent** hash chain, `seq` restarting at 1. No global order, no single verifiable chain. | **Hard** |

### Singleton assumptions

There is **no leader election, no file locking, no "already running" guard**
anywhere. The background goroutines (session reaper, revocation poll, grant purge,
config watchers) are per-process and harmless to run N times — but several enforce
global-looking invariants only locally.

One is worth calling out as *already* HA-shaped: the broker's revocation poll
(`GET /v1/revocations`, ~10s) is a pull/eventual-consistency propagation model
that survives multi-replica brokers **as long as the freeze set it polls is
itself global**. Behind an LB in front of multiple signers it silently breaks — so
freeze-sharing is the real dependency, not the poll loop.

Note also that N signer replicas each need CA-key access (shared Key Vault, or the
same PEM), which multiplies the trust surface and raises serial allocation.

## The four true blockers

1. **Live sessions.** The hardest item, and *not* a storage problem: a session
   owns an open SSH connection/PTY that cannot be serialised between processes.
   The realistic answer is **session affinity** — pin `session_id` back to the
   replica that dialed — not shared session state. One-shot `Execute` is already
   stateless and scales freely today.
2. **Freeze / kill switch.** Security-critical: a frozen subject must be denied on
   *every* replica, which means shared, read-committed freeze state on the sign
   path — not a local cache.
3. **Audit chains.** Per-process hash chains don't compose into one verifiable
   history. Needs a strategy decision: per-replica chains stitched by a collector,
   or an external append-only sink with a single writer/sequencer.
4. **Behavior tracker.** Purely in-memory with no persistence path at all;
   split-brain baselines and replica-multiplied rate windows.

**Medium (mechanical-ish):** approvals and grants. Both already do insert-first
write-through against `*sql.DB` and reload at startup, so the interfaces isolate
the store. The real delta is that each currently treats its **in-memory map as the
source of truth on the decision path** — HA requires read-through (or subscribing
to invalidations) plus making the `consumed`/`issuing` claims DB-transactional
rather than in-process booleans. That inverts the `statedb` invariant quoted
above, and it is the largest single piece of the work.

**Easy / leave alone:** host-key and host/cluster caches, compiled policy (all
deterministic or config-derived, re-derivable per replica). The rate limiter is
per-instance and merely loosens the global bound — accept it, or back it with a
shared counter only if a hard cap is contractually required.

## Minimum viable HA slice

In dependency order, each tracked as its own issue under the
**Medium-term: HA, durability & secure-by-default** milestone:

1. [**Shared transactional backend**](https://github.com/luisgf/infrabroker/issues/293)
   (e.g. Postgres) for **approvals + grants + freezes**, replacing local SQLite,
   with read-through on the decision path and transactional consume/four-eyes.
   *This is the core.*
2. [**Broker session affinity**](https://github.com/luisgf/infrabroker/issues/294)
   — `session_id`-based routing, not shared state.
3. [**Distributed behavior tracker**](https://github.com/luisgf/infrabroker/issues/295)
   — shared counters + shared novelty sets, or an explicit degradation to
   observe-only across replicas.
4. [**HA audit strategy**](https://github.com/luisgf/infrabroker/issues/296) —
   per-replica chains plus a central verifier, or an external sequencer.

Optional and non-blocking, [tracked together](https://github.com/luisgf/infrabroker/issues/297):
a globally shared rate limiter, and a decision on multi-signer CA custody + serial
allocation.

## Why it stays demand-gated

Single-instance is a deliberate choice, not an oversight. `state_db` already
delivers the property most deployments actually want — **restart survival** — and
the failure mode of a single broker is a bounded outage, not a security event.
Real HA buys availability at the cost of a shared datastore in the decision path
of every signature, which is a new dependency for the component whose whole job is
to fail closed. Build it when demand is observed, and build the slice above in
order.
