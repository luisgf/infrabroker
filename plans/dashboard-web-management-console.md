# Plan: Web Management & Monitoring Console (`dashboard` module)

> Status: **proposal / not started**. Captured for a future decision.
> Date: 2026-06-18. Target: deployment-agnostic core; Kubernetes, standalone/systemd
> and docker-compose are first-class deployment profiles.
>
> This is a design plan, not a commitment. See "Open items" at the end.

---

## 1. Goal

Add a web interface to manage and monitor the infrabroker solution, with:

- OAuth/OIDC integration for RBAC, with roles per functionality.
- List the hosts the user has access to.
- View open SSH sessions and close them.
- Replay interactive session recordings.
- View the audit log.
- Manage human-in-the-loop command approvals.
- Admin panel with statistics per agent, host group, blocked/allowed commands, etc.
- View (and, later, manage) the command policy.
- Serve in general as the management and monitoring console for the whole solution.

---

## 2. Design principle: deployment-agnostic core

The code does **not** assume Kubernetes. Kubernetes, standalone/systemd and
docker-compose are **first-class deployment profiles**; the same binaries run in
all three. Environment-specific behavior lives behind *seams* with a portable
default:

- **Inventory / discovery** → `BrokerInventory` interface, **static config by
  default**; native K8s discovery (EndpointSlices/API) as an optional backend.
- **State** → `internal/store` interface, **in-memory by default**; Redis/Postgres
  opt-in only (for HA).
- **Storage (audit / recordings)** → **local path by default** (a disk or a PVC);
  object storage optional later.
- **Identity** → **app-level mTLS + CN allowlist always**, in every profile; cert
  issuance is interchangeable (manual / cert-manager). A service mesh is **not** a
  substitute for application mTLS.
- **Config** → a file (real or mounted); **no Kubernetes primitives in the code**.

**Security regressions forbidden by design** (the temptations a cloud-native
deployment introduces):

- Do not terminate mTLS at an ingress/mesh and trust headers.
- Do not place Redis in the approval-gate TCB silently.
- Do not relax the CN allowlist or the fail-closed posture.
- Do not put secrets in cleartext env/ConfigMaps (use External Secrets/Vault/AKV).

This keeps the project's lightweight, self-hosted identity and avoids weakening the
security model for cloud-native convenience.

---

## 3. Fixed decisions (from review rounds)

| Topic | Decision |
|---|---|
| Deployment | **Deployment-agnostic core**; K8s, standalone/systemd and docker-compose are first-class profiles. |
| Frontend | **SPA (React/Svelte) embedded via `go:embed`**, served behind OIDC. |
| Data access | **Separated, streaming endpoints** — the dashboard never reads local files of other components. |
| Audit durability | **Per-writer local store (disk or PVC) + read endpoint**; the dashboard aggregates, verifies per-writer, correlates by `serial`. |
| State / HA | **In-memory by default; Redis/Postgres optional (opt-in for HA), documented as part of the approval-gate TCB.** |
| Live sessions | **New mTLS endpoints on the HTTP broker frontends**; **`BrokerInventory` interface — static config by default, native K8s discovery as an optional backend** — for fan-out. |
| Command policy | **Read-only** in this delivery (no `signer.json` writes from the dashboard). |

---

## 4. Why this is a new component (codebase findings)

Verified against the current code, not just the docs:

1. **No HTTP read API exists** for audit, sessions, behavior, or policy. The only
   network-consumable management surface today is the control-plane
   `GET/POST /v1/approvals` (mTLS) and the signer `GET /v1/hosts`.
2. **Data is scattered and partly in-memory per process:**
   - Audit → NDJSON files (`audit.log` broker, `signer_audit.log` signer), read by
     scanning. The read/verify logic is **trapped inside `cmd/broker-ctl`**, not a
     reusable library.
   - Live sessions → in-memory in `internal/broker.sessionManager` (unexported
     fields), **not listable or closable from outside the process**. The stdio
     broker is launched per-user by the MCP client (not network-reachable); only
     the HTTP frontends are observable.
   - Approvals → in-memory in the control-plane (`control.Registry`), but with a
     JSON API.
   - Recordings → `.cast` files (ASCIIcast v2) in `session_recording_dir`,
     self-describing via an `ssh_broker` header extension.
   - Command policy → lives in `signer.json`, edited via `broker-ctl` + `POST /v1/reload`.
3. **Two distinct auth planes:** OIDC bearer (user-facing, `internal/oauth` +
   go-sdk middleware, RBAC by groups) and mTLS-CN allowlists (signer and
   control-plane). Everything is stdlib `net/http`; no web framework, no frontend
   tooling; state is single-instance in memory.

Conclusion: the dashboard is **a new aggregator component**, and it forces (a)
extracting shared libraries for audit read/verify and for state, and (b) adding
new list/close session endpoints on the broker frontends.

---

## 5. Trust model

New component **without the CA key** (like the control-plane). Semi-trusted aggregator.

- **North (users): OIDC** reusing `internal/oauth` and the `cmd/mcp-broker-http`
  pattern (RFC 9728, fail-closed on groups/iat). RBAC by groups.
- **South (components): mTLS** with its own client cert/CN, allowlisted on signer,
  control-plane and brokers.
- It is a **high-value target** (reads audit data with secrets logged verbatim —
  gap #8 — and can close live sessions). Therefore: **fail-closed RBAC**, its **own
  action audit trail** (who viewed / approved / closed), and sensitive-data
  restriction by role.

---

## 6. RBAC roles (OIDC group → role)

| Role | Permissions |
|---|---|
| `viewer` | hosts, sessions (read), basic audit, replay, stats |
| `approver` | + approve/deny human-loop |
| `operator` | + close live SSH sessions |
| `auditor` | + full audit, integrity verification, export, unredacted view |
| `admin` | + dashboard configuration and group→role mapping |

Fail-closed: a user without a mapped group has no access (consistent with the
signer posture). Group→role mapping is dashboard configuration.

---

## 7. Implementation work

### 7.1 Refactors / new libraries

1. **`internal/auditread`** — extract from `cmd/broker-ctl` the iterate/filter/verify
   logic (SHA-256 chain + Ed25519 signatures + rotated-segment linkage). Reused by
   `broker-ctl`, the dashboard, and the streaming endpoints. `broker-ctl` becomes a
   consumer of this lib (no functional change).
2. **`internal/store`** — state abstraction behind an interface, with an **in-memory
   backend by default** (current behavior, no new trust surface) and an **optional
   `redis`/`postgres` backend (opt-in for HA)**. Refactor `control.Registry`
   (approvals) and `control.BehaviorTracker` to use it. The optional backend closes
   gap #5 but, when enabled, enters the approval-gate TCB (see §9).
3. **`internal/broker`** — export `ListSessions() []SessionInfo` and
   `ForceCloseSession(id)` (administrative close that bypasses per-caller ownership,
   audited).
4. **`internal/inventory`** — `BrokerInventory` interface to enumerate broker
   instances for fan-out. **Default backend: static list from config.** Optional
   backends: DNS/SRV and **K8s (EndpointSlices / in-cluster API, minimal RBAC)**. No
   Kubernetes primitives leak into the core; K8s is just one backend.

### 7.2 New south endpoints (mTLS, dashboard CN allowlisted)

- **Audit (signer, control-plane, broker):** `GET /v1/audit?since=<seq>` → signed
  NDJSON from the per-writer log store (disk or PVC). Reuses `auditread`.
- **Sessions (mcp-broker-http, broker):** `GET /v1/sessions`,
  `POST /v1/sessions/{id}/close`.
- **Recordings (broker):** `GET /v1/recordings`, `GET /v1/recordings/{id}`
  (stream `.cast` from the local store).
- **Approvals:** already exist (`GET/POST /v1/approvals`) — the dashboard becomes the
  long-pending `approval-bridge` from the roadmap.

### 7.3 Dashboard backend (`cmd/dashboard` + `internal/dashboard`, OIDC)

- `GET /api/hosts` (proxy to signer `/v1/hosts` with `X-On-Behalf-Of`).
- `GET /api/sessions` (fan-out to inventory brokers) ·
  `POST /api/sessions/{instance}/{id}/close`.
- `GET /api/recordings` · `GET /api/recordings/{id}` (`asciinema-player`).
- `GET /api/audit` (filters + correlation by serial) · `GET /api/audit/verify`
  (per-writer tamper-evident status).
- `GET /api/approvals` · `POST /api/approvals/{id}`.
- `GET /api/policy` · `GET /api/policy/{host}` (**read-only**).
- `GET /api/stats` (aggregation over audit streams: per agent/`caller`, host group,
  allowed vs blocked (`outcome=denied` + `policy_rule`), approvals, anomalies,
  sudo/pty, time-rate).
- `GET /api/stream` (SSE: new approvals, anomalies, integrity alerts, session changes).
- `GET /metrics` (Prometheus), `/healthz`, `/readyz`,
  `/.well-known/oauth-protected-resource`.

### 7.4 Deployment profiles & operations

The same binaries ship for three first-class profiles; operational good practices
below are profile-agnostic (they work in standalone just as in K8s):

- **Standalone / systemd (single host):** the project's current model — binaries +
  files on disk; `signer.sh`-style units; reload via SIGHUP/HTTP.
- **Docker-compose:** mid-tier deployment without a cluster; volumes for the
  per-writer audit/recording stores; a static `BrokerInventory`.
- **Kubernetes (Helm):** chart for dashboard + components; **PVC** per writer for
  audit and recordings; **NetworkPolicies** (only the dashboard and allowlists reach
  signer/control-plane/brokers; an optional Redis is isolated); **PodDisruptionBudget**;
  K8s `BrokerInventory` backend.
- Cross-profile practices: **structured JSON logs to stdout**, `GET /metrics`
  (Prometheus), liveness/readiness probes (plain HTTP endpoints), graceful shutdown
  (already in `httpserve.RunTLS`), **distroless** image, resource limits.
- **Identity is identical in every profile:** app-level mTLS + CN allowlist. Cert
  issuance is interchangeable: manual PKI (standalone) or **cert-manager** (K8s); a
  mesh is never a substitute for application mTLS. SSH CA in **AKV/KMS**; PEM secrets
  via **External Secrets/Vault**; OIDC against the corporate IdP.
- Document constraints: live sessions are **instance-local** (not migratable); a
  broker does not scale horizontally for the same session; the control-plane scales
  only when the optional Redis/Postgres backend is enabled.

---

## 8. Phases

Relative sizing per phase in §21. Milestone/PR breakdown in §19.

- **Phase 1 — monitoring + approvals:** `internal/auditread`; `GET /v1/audit`
  endpoints; dashboard skeleton (OIDC + SPA + RBAC); hosts, audit, stats and replay
  views; approvals (view + decide); **server-side secret redaction (§17)** and the
  **dashboard action audit (§18)**. High value, low risk.
- **Phase 2 — management:** `internal/store` with the **in-memory backend** (default);
  `internal/inventory` (static + K8s backends); session endpoints + sessions UI
  (list/close); behavior view; read-only policy view.
- **Phase 3 — advanced / optional:** **Redis/Postgres `store` backend for HA**
  (opt-in); SIEM/WORM forwarding and integrity anchoring; notification center;
  revocation/KRL UI once `/v1/revoke` exists (gap #3); Grafana dashboards.

> Note: secret redaction is intentionally **Phase 1**, not Phase 3 — exposing audit
> data over the web to browsers is a qualitative change in exposure (gap #8), not an
> incremental one, so the masking must ship with the first audit view.

---

## 9. Security & documentation impact

- **`THREAT_MODEL.md`:** new trust boundary (dashboard); `ForceCloseSession` as a
  mutation; allowlisted CN; per-writer integrity with serial correlation; update
  gap #5 (mitigated only when the optional store backend is enabled) and reference
  gap #8 (secrets in audit views → server-side redaction §17, raw gated to
  auditor/admin). **Explicit note:** the optional Redis/Postgres state backend,
  *when enabled*, enters the approval-gate TCB (a tampered store could make the
  control-plane forward `approved=true`), so it requires mTLS/auth and a
  NetworkPolicy; the default in-memory backend adds no new trust surface. Document
  the forbidden regressions from §2. A ready-to-paste threat-model delta is a
  pending open item (§11).
- **`API.md`:** document `GET /v1/audit`, `GET/POST /v1/sessions`,
  `GET /v1/recordings`, and the whole dashboard `/api/*` surface.
- **`ARCHITECTURE.md`:** new component + diagram, `internal/store`,
  `internal/inventory`, deployment-agnostic seams.
- **`OPERATIONS.md`:** deployment runbook for the three profiles (systemd /
  docker-compose / Helm), per-writer stores, optional Redis, cert-manager,
  NetworkPolicies, dashboard RBAC.
- **`README.md` / `USAGE.md` (or a new `DASHBOARD.md`)**, **`CHANGELOG.md`**,
  **`HANDOFF.md`** (Spanish). Versioning: `feature/dashboard` branch → minor bump on merge.
- Conventions from `CODING_STYLE` (gofmt, `ctx` first, ≤80-line functions,
  `t.Parallel`, English). Tests: `auditread`, `store` (memory + redis via miniredis),
  `inventory`, RBAC, handlers; e2e lab for each profile.

---

## 10. Additional proposals (beyond the original ask)

1. **The dashboard IS the pending `approval-bridge`** — closes a known roadmap gap;
   bidirectional web approval, deep-linked from the Teams card via
   `approval_url_template`.
2. **Audit integrity panel** — continuous per-writer chain verification + external
   head anchoring (roadmap), with a visible "tamper-evident: OK/FAIL" status.
3. **Secret redaction** in audit/recording views (gap #8): masking patterns; raw
   access gated to admin/auditor.
4. **Revocation/KRL UI** (gap #3) and an emergency "kill switch" (deny a CN by
   editing `callers`) even before `/v1/revoke` exists.
5. **Prometheus `/metrics` + Grafana** and alerting (including the audit-write-failure
   alert, gap #9).
6. **SIEM/WORM forwarding** of the audit (roadmap) — the dashboard as the shipper.
7. **Per-user timeline correlated by `serial`** across signer↔broker↔sshd (optional
   sshd ingestion).
8. **Behavior baseline visualization** (new hosts/commands per subject) with
   reset/whitelist.
9. **Multi-instance awareness** (gap #5): aggregate over a discovered inventory of
   broker/control-plane instances and document that sessions/approvals are
   per-instance unless externalized.
10. Security headers/CSP and accessibility (this is a security console).

---

## 11. Open items / future decisions

- Charts library (Recharts vs visx) and i18n approach (`react-i18next`, ES/EN) — see §12.
- **Concrete JSON schemas (B2)** for the `/api/*` and `/v1/*` surfaces — to be written
  before coding the front↔back contract.
- **Dashboard config schema (B4)** — `dashboard.json`/env (OIDC issuer, group→role map,
  instance inventory, mTLS paths, refresh intervals, redaction flags).
- **Ready-to-paste THREAT_MODEL delta (C3)** — exact wording for the new boundary/gaps.
- Redis vs Postgres for the optional `internal/store` backend, and **when/whether** to
  enable it for HA (default stays in-memory).
- Parity matrix across the three deployment profiles (systemd / docker-compose / K8s):
  which features are first-class in each and how they are tested.
- Whether command-policy management graduates from read-only to GitOps-based editing
  (PR + dry-run + four-eyes) or a mutable config-API store.
- Whether audit durability later upgrades from "per-writer store" to centralized
  object-lock/WORM + SIEM streaming.
- mTLS via cert-manager (app-level) vs service mesh (SPIFFE) identity model.

---

## 12. Frontend / UI design

### 12.1 Fixed decisions

| Topic | Decision |
|---|---|
| Framework | **React + Vite + TypeScript**, static build embedded via `go:embed`. |
| UI kit | **shadcn/ui + Tailwind + Radix** (components vendored in-repo, auditable, accessible, CSP-friendly). |
| Theme | **Dark-first**, light optional, honoring `prefers-color-scheme`. |

### 12.2 Stack

- **Build:** Vite → static output to `internal/dashboard/web/dist`, embedded with
  `go:embed` and served by the Go backend behind OIDC.
- **Routing:** React Router (one route per module).
- **Server state / fetching:** TanStack Query (cache, polling, revalidation).
- **Real-time:** `EventSource` (SSE) to `GET /api/stream` (new approvals, anomalies,
  integrity alerts, session changes).
- **Tables:** TanStack Table + `@tanstack/react-virtual` (virtualized audit view,
  thousands of rows).
- **Charts:** Recharts or visx (statistics panel) — final choice in §11.
- **Replay:** `asciinema-player` (wrapped component) for `.cast` files.
- **Auth:** OIDC Authorization Code + PKCE (public client) against the corporate IdP,
  aligned with the RFC 9728 pattern already used by `mcp-broker-http`. **Token kept in
  memory** (not localStorage).
- **i18n:** `react-i18next` (code/docs in English per `CODING_STYLE`; UI strings
  externalized for ES/EN).

### 12.3 Authentication & RBAC in the frontend

- OIDC PKCE login; the backend validates the JWT locally (reuses `internal/oauth`).
- Backend exposes `GET /api/me` → `{ user, roles, permissions, features }` (effective
  role derived from the group→role mapping).
- The frontend **renders by capabilities**, not hardcoded roles: it hides/disables
  actions based on `permissions`. **Real authorization is server-side** — the
  frontend only improves UX, never the security boundary.
- Fail-closed: no permission → explicit empty state (distinct from "no data" and
  "error").

### 12.4 Aesthetics (dark-first security console)

- Dark theme by default + optional light; medium-high, hierarchized information
  density; sans for UI (Inter/system-ui) + monospace for command/serial/hash.
- Strict, WCAG-AA-accessible color semantics: green = allowed/issued, amber =
  require-approval/anomaly, red = denied/error/integrity-FAIL, blue = info. **Color is
  never the sole carrier of meaning** (icon + text always).
- Trust components: global **audit-integrity status banner** (OK/FAIL per writer),
  role badge, environment indicator (prod/staging).

### 12.5 Structure

Console layout: sidebar navigation + topbar (user/role, environment, integrity
health, theme toggle) + content area. Navigation maps 1:1 to the requirements:

1. **Overview** — KPIs and alerts (active sessions, pending approvals, recent
   denials, integrity status, anomalies).
2. **Hosts** — accessible host list; capabilities (sudo/pty/jump); group filter. Does
   not expose addr/user/host_key to low-privilege roles.
3. **Sessions** — live SSH sessions (aggregated per broker instance); detail; **close**
   action (operator role); link to its recording.
4. **Recordings** — `.cast` index; embedded player; filter by user/host/date;
   correlation with audit by `session_id`.
5. **Audit** — virtualized table; filters (host, caller, outcome, serial, time range);
   **serial correlation** across signer/broker/control-plane; entry detail; chain
   verification; export.
6. **Approvals** — human-loop queue; view/approve/deny (approver role); server-side
   four-eyes; live SSE notification.
7. **Policy** — **read-only** command-policy view per host
   (allow/deny/require_approval/shell_parse).
8. **Statistics** — aggregates per agent, host group, allowed vs blocked, approvals
   (granted/denied/timeout), anomalies, sudo/pty, time evolution.
9. **Settings (admin)** — group→role mapping, instance inventory, detailed integrity
   status.

Folder layout:

```
internal/dashboard/web/
  src/
    main.tsx, App.tsx, router.tsx
    api/            # typed fetch client + TanStack Query hooks + SSE
    auth/           # OIDC PKCE, session, capability guard
    components/     # shared UI (tables, badges, integrity banner, layout)
    features/
      overview/  hosts/  sessions/  recordings/
      audit/  approvals/  policy/  stats/  settings/
    lib/            # formatting (serial, ttl, dates), color/status constants
    styles/         # tailwind, theme tokens
  index.html, vite.config.ts, package.json, tsconfig.json
```

### 12.6 Per-module UX

- **Audit:** virtualized table (TIME·SEQ·CALLER·HOST·OUTCOME·SERIAL·DETAIL); row click
  opens a side panel with the full entry + entries correlated by serial; filters
  persisted in the URL (shareable); optional live tail (SSE); "Verify chain" with
  per-writer result. **Secrets in commands:** redacted by default; "show raw" only for
  auditor/admin with confirmation.
- **Sessions:** activity indicator; instance/broker column; "close" asks confirmation
  (destructive) and shows the result; refresh via polling + SSE.
- **Recordings:** player with speed control, time markers; header with `.cast` metadata
  (caller/host/serial); text-only (cat) mode.
- **Approvals:** cards with command/host/caller/end_user/rule; approve/deny disabled if
  you are the originator (four-eyes); TTL countdown; live toast on arrival.
- **Stats:** selectable time range; allowed vs blocked, top denied commands, top hosts,
  approval latency; CSV/PNG export.
- Explicit empty / error / loading states per view (security-critical: distinguish "no
  data" from "no permission" from "failure").

### 12.7 Frontend security

- **Strict CSP** (no `unsafe-inline`; nonce for styles if required),
  `frame-ancestors 'none'`, plus HSTS / X-Content-Type-Options / Referrer-Policy served
  by the Go backend.
- **Token in memory**, not localStorage; refresh via the IdP; logout clears state.
- **No secrets in the bundle**; all authorization validated server-side.
- **WCAG AA** (Radix helps): visible focus, keyboard navigation, contrast, ARIA.
- Pinned dependencies; `npm audit` + `govulncheck` in CI (aligned with repo policy).
- Destructive actions (close session) and sensitive views (raw audit) require
  confirmation and are recorded in the dashboard action audit.

### 12.8 Build & Go integration

- Vite builds to static; `go:embed` packages `dist/`. Single image, true to the
  "single-binary" ethos.
- `Makefile`: `web-install` (npm ci), `web-build` (vite build); the dashboard `build`
  depends on the web build. In dev, the Vite dev-server proxies to the Go backend.
- CI: frontend lint + typecheck + test + `npm audit`, plus the embedded build; keeps
  the existing `gofmt/vet/test` flow for Go.

---

## 13. Non-goals (v1)

Deliberate scope limits for the first delivery (named on purpose, as the rest of the
repo docs do):

- **Does not edit command policy** — read-only view; changes still go through
  `broker-ctl` / GitOps.
- **Does not revoke certificates (KRL)** — depends on the roadmap `/v1/revoke` (gap #3).
- **Not multi-tenant** — single organization / single trust domain.
- **Does not replace the SIEM** — it is an operational console, not a log warehouse or
  long-term retention system (see §14).
- **Not HA by default** — in-memory state; HA only with the opt-in store backend.
- **Does not observe the stdio broker** — `cmd/mcp-broker` is launched per-user by the
  MCP client and is not network-reachable; only HTTP frontends are observable.
- **Keeps no persistent state of its own** beyond ephemeral cache — it is an aggregator,
  not a source of truth.
- **Does not terminate SSH or proxy traffic** — it only reads and triggers actions via
  the existing component APIs.

---

## 14. Positioning vs the corporate SIEM

In a corporate environment there is usually already a SIEM/observability stack
(Splunk/Elastic/Grafana). The dashboard's differentiated value is **the operational
actions a SIEM cannot perform**, not log warehousing:

- **Complements (dashboard owns):** human-loop approvals, closing live sessions,
  `.cast` replay, live integrity status, real-time operational triage.
- **Delegates (SIEM owns):** long-term retention, cross-source correlation at scale,
  historical dashboards, alerting pipelines — fed by the audit **forwarding** (§10.6).

**Consequence for module weight:** the `Audit` and `Statistics` modules are scoped as
**live operational views** (recent window, fast triage, correlation by `serial`), not as
an exhaustive historical analytics store. Deep/long-range analytics is a SIEM concern.
This keeps those modules lean and avoids reimplementing a SIEM.

---

## 15. Audit cursor & pagination model

`GET /v1/audit` must page deterministically across rotated segments and per-writer
chains. Contract:

- **Opaque cursor** encoding `{ writer_id, segment, seq }` (base64 JSON). `writer_id`
  identifies the signing component (signer / broker-N / control-plane); `segment` is the
  rotated file (active or `.<timestamp>`); `seq` is the per-file monotonic counter.
- **Request:** `GET /v1/audit?since=<cursor>&limit=<n>` (mTLS). Omitting `since` starts at
  the genesis of the oldest segment.
- **Response:**
  ```
  {
    "entries":     [ <signed audit.Entry>, ... ],
    "next_cursor": "<opaque|null>",          // null when caught up
    "integrity":   { "ok": true, "checked_to_seq": 12345, "writer_id": "broker-1" }
  }
  ```
- **Rotation handling:** when a segment is exhausted, the server advances the cursor to
  the next segment's genesis and the chain link is verified across the boundary
  (reusing `auditread` segment linkage). A gap/truncation surfaces as `integrity.ok=false`.
- **Per-writer chains:** the dashboard fans out one cursor **per writer** and merges
  client-side by `time`/`serial`; it never assumes a single global chain. Verification is
  always per writer.
- **Live tail:** after `next_cursor=null`, the dashboard switches to SSE
  (`session.changed`/new-entry events) instead of busy-polling.

Full JSON schemas for this and the rest of the API are a pending open item (B2, §11).

---

## 16. RBAC permission matrix

Authorization is **server-side**; the frontend only mirrors it for UX. Permission keys
are the source of truth, mapped to roles and enforced per endpoint.

| Permission key | viewer | approver | operator | auditor | admin |
|---|:--:|:--:|:--:|:--:|:--:|
| `hosts.read` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `sessions.read` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `sessions.close` | — | — | ✅ | — | ✅ |
| `recordings.read` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `audit.read` (redacted) | ✅ | ✅ | ✅ | ✅ | ✅ |
| `audit.read_raw` (unredacted) | — | — | — | ✅ | ✅ |
| `audit.verify` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `audit.export` | — | — | — | ✅ | ✅ |
| `approvals.read` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `approvals.decide` | — | ✅ | — | — | ✅ |
| `policy.read` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `stats.read` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `admin.settings` | — | — | — | — | ✅ |

Enforcement rules:
- Each `/api/*` handler checks the required permission key; missing → `403` (fail-closed).
- `GET /api/me` returns the resolved `permissions` set so the SPA can hide/disable
  actions, but the **API never trusts the client** for authorization.
- A user may hold multiple roles (union of permissions). No role implies write access to
  policy in v1 (see §13).

---

## 17. Secret redaction (Phase 1)

Audit entries and `.cast` recordings store commands **verbatim** (gap #8): inline
credentials (`mysql -psecret`, `PGPASSWORD=… pg_dump`, `curl -H "Authorization: Bearer …"`)
end up in plaintext. Exposing that over a web UI is a qualitative exposure jump, so
redaction ships in Phase 1.

- **Server-side masking** applied in `/api/audit` and `/api/recordings` before bytes
  leave the backend (never rely on the client to hide).
- **Configurable pattern set** (regex) with sensible defaults for common secret-bearing
  flags/env (`-p`, `--password`, `PGPASSWORD`, `Authorization: Bearer`, `?token=`, …);
  matches replaced with `••••`.
- **Raw access** (`audit.read_raw`) is gated to `auditor`/`admin`, requires explicit
  "show raw" confirmation, and the action is recorded in the dashboard action audit (§18).
- Redaction is a **view concern**, not storage — the underlying signed log is unchanged,
  so chain/signature verification still operates on the original bytes.
- A masked-vs-raw toggle never weakens integrity verification (verify runs on raw).

---

## 18. Dashboard action audit

The monitoring component cannot be the only one without traceability. The dashboard
writes its **own append-only, Ed25519-signed, hash-chained log** (reusing
`internal/audit`) for every privileged or sensitive action:

- Events: `login` / `logout`, `audit.view_raw`, `audit.export`, `session.close`,
  `approval.decide` (allow/deny), `settings.change`.
- Fields: `time`, `user` (OIDC sub), `roles`, `action`, `target` (session id / host /
  approval id), `result`, plus the standard chain fields (`seq`, `prev_hash`, `sig`).
- Stored in the dashboard's own per-writer store (disk/PVC), streamable via the same
  `GET /v1/audit` contract and correlatable with the component logs by `serial` where
  applicable.
- Verifiable with the same `auditread` tooling and surfaced in the integrity panel.

---

## 19. Delivery breakdown (PRs / milestones)

Refactors are isolated from features so the existing test suites stay the safety net.

1. **PR-1 — `internal/auditread` refactor.** Extract read/filter/verify from
   `cmd/broker-ctl`; broker-ctl becomes a consumer. **No functional change**; existing
   broker-ctl audit tests must stay green.
2. **PR-2 — `GET /v1/audit` endpoint** on signer, control-plane and broker (mTLS, cursor
   model §15). Consumable by `curl`/SIEM even without a UI — independent value.
3. **PR-3 — Dashboard skeleton.** `cmd/dashboard` + `internal/dashboard`, OIDC,
   `/api/me`, RBAC matrix (§16), SPA shell, integrity banner. No data modules yet.
4. **PR-4 — Read-only modules + redaction (§17) + action audit (§18):** hosts, audit
   viewer, stats, recordings replay, approvals (view + decide). Completes Phase 1.
5. **PR-5 — Sessions + `internal/store` (memory) + `internal/inventory`:** broker session
   endpoints, fan-out, sessions UI (list/close), behavior view, read-only policy view.
   Completes Phase 2.
6. **PR-6+ — Advanced/optional:** Redis/Postgres store backend (HA), SIEM/WORM
   forwarding, integrity anchoring, KRL UI, Grafana. Phase 3.

Each PR follows the `CONTRIBUTING` living-docs checklist and `CODING_STYLE` gates.

---

## 20. De-risking, testing & observability

### 20.1 Spikes (do early, before committing to the design)

- **Sessions concurrency:** export `ListSessions`/`ForceCloseSession` and exercise the
  `sessionManager` (mutex, reaper, `busy` flag) under `go test -race`. Confirm no races
  and that a busy session is never force-closed mid-exec.
- **Recording streaming:** stream a 100 MiB `.cast` and validate live-tail of an
  in-progress session through the player.
- **OIDC PKCE end-to-end** against the **real** corporate IdP (not just a lab Keycloak):
  RFC 9728 discovery, `aud`, key rotation, refresh, CORS.

### 20.2 Testing strategy (per package)

- `auditread`: chain, Ed25519 signatures, rotated-segment linkage, cursor paging.
- `store`: `memory` + `redis` (via `miniredis`); approval lifecycle/TTL/purge parity.
- `inventory`: static backend + a fake K8s backend.
- RBAC: the §16 matrix as a table-driven test (permission × endpoint → allow/deny).
- Handlers: fail-closed authz, redaction applied, action-audit emitted.
- E2E lab per deployment profile (systemd / docker-compose / kind).

### 20.3 Observability

- **Prometheus metrics** (names): `infrabroker_sessions_active`,
  `infrabroker_approvals_pending`, `infrabroker_approvals_decided_total{result}`,
  `infrabroker_audit_denied_total{host}`, `infrabroker_audit_write_failures_total`
  (alert source for gap #9), `infrabroker_anomalies_total{kind}`,
  `infrabroker_cert_issued_total`.
- **SSE event catalog** (`GET /api/stream`): `approval.created`, `approval.decided`,
  `anomaly`, `integrity.alert`, `session.changed`, `audit.appended`.
- **Freshness model:** push (SSE) for approvals/anomalies/integrity/sessions; polling
  (TanStack Query) as fallback for hosts/stats with conservative intervals
  (e.g. hosts 60s, stats 30s); audit uses cursor pull + SSE tail.

### 20.4 UI state taxonomy

Every view distinguishes four states explicitly (security-critical to avoid confusing
"nothing happened" with "you can't see it"): **loading**, **empty** (no data),
**no-permission** (403 → explicit message, not a generic error), **error** (failure,
with retry).

---

## 21. Effort / sizing (relative)

Indicative only; refactors are the cheap, reusable foundation, the SPA is the bulk.

| Item | Size | Notes |
|---|:--:|---|
| `internal/auditread` refactor (PR-1) | M | Reused by broker-ctl, endpoints, dashboard |
| `GET /v1/audit` ×3 services (PR-2) | S–M | Cursor model; independent value |
| Dashboard skeleton + OIDC + RBAC (PR-3) | M | Auth plane + permission matrix |
| Read-only modules + redaction + action audit (PR-4) | **L** | Bulk of Phase 1 UI |
| Sessions + `store` + `inventory` (PR-5) | M–L | Touches broker concurrency |
| Redis/Postgres backend (PR-6) | M | Phase 3, opt-in HA |
| SIEM/WORM, KRL UI, Grafana (PR-6+) | M+ | Phase 3, optional |
