# Changelog

## [Unreleased]

### Added
- **Kill switch / revocation (#117)** — the signer gained `POST /v1/freeze`
  and `POST /v1/unfreeze` (authenticated to `reload_callers`) to freeze or
  release a caller CN, end-user, session id, or certificate serial; freezing a
  caller/end-user also atomically revokes its runtime grants and
  approve-and-learn waivers. A frozen subject is denied on `/v1/sign` and
  `/v1/hosts`, and `GET /v1/revocations` streams the freeze set. Each broker
  polls it (`revocation_poll_seconds`, default 10, remote mode) and
  force-closes live sessions matching a frozen subject.
- **In-conversation approvals (#118)** — with `approval_via_elicitation` (stdio
  frontend, off by default), a `require_approval` command becomes an MCP
  elicitation the human answers in the client instead of an out-of-band denial.
- **Machine-readable dry-run decision (#119)** — `dry_run=true` on `ssh_execute`
  returns a structured decision carrying a stable `reason_code` (`allowed`,
  `needs_approval`, `command_denied`, `allowlist_no_match`, …) so an agent can
  branch on the outcome without parsing prose.
- **Approval bridge (#120)** — `cmd/approval-bridge` presents pending approvals
  on Slack (Socket Mode, outbound-only) and relays Allow/Deny under its own mTLS
  approver identity; the control plane still enforces consumed-once and
  four-eyes. A convenience, not a new trust root.
- **Per-agent IdP identity (#121)** — the OAuth HTTP frontend resolves each
  agent's `client_credentials` token to that agent's own caller identity, so
  distinct agents are never collapsed into one shared caller.
- **ssh-agent CA custody (#122)** — a new `ca_keys` backend, `type: "agent"`,
  keeps the CA private key in a running ssh-agent (YubiKey PIV / SoftHSM / TPM
  via `ssh-add -s`); `public_key_path` pins which agent key is the CA and the
  signer process never holds key bytes. Supports Ed25519 CAs (unlike AKV).
- **Startup warning for ignored local-mode config (#178)** — when the broker
  runs in remote mode (a `signer` block is set) but the config also carries
  local-mode fields — `ca_key`/`ca_keys`, `command_policies`, or per-host policy
  (`command_policy`, `allow_sudo`, `principal`, …) — it now logs a single
  aggregated warning naming them (and the host(s) they sit on). Those fields are
  silently ignored in remote mode (inventory and policy come from the signer);
  the warning stops an operator from believing a local policy is enforced when
  it is not (the same error class as the `_default` firewall gap, #82). Warning
  only — no behavior change to signing or policy resolution.
- **Mesh networking guide (#137)** — new [`docs/MESH.md`](MESH.md) on
  running infrabroker over a NetBird / Tailscale (WireGuard) overlay: the mesh
  provides the network path, infrabroker the session layer (per-op ephemeral
  certs, signer-side policy + approvals, recording, signed audit). Zero code —
  the broker dials plain TCP, so any mesh-routed path works, and stable overlay
  IPs make `source_address` pinning precise. States exactly which controls are
  host-enforced (one-shot `force-command`) versus broker-enforced (session
  command filtering, gap #1).
- **`broker-ctl doctor --security` preflight (#134)** — an offline
  production-hardening check (no keys, no network) that reads the local config
  files and reports PASS/WARN/FAIL with a one-line fix for each item of the
  `deploy/README.md` checklist: `callers._default` default-deny,
  `sign_rate_limit_per_min`, CA custody not local-PEM, `state_db`, `redact`,
  `monitor_listen` not public, and the control-plane `sign_callers` allowlist
  when approvers exist. Exits non-zero on any FAIL. The signer additionally logs
  a startup warning when `callers` has no `_default` or the sign rate limit is
  unset — the two most common fail-open omissions.
- **Single-binary local-mode quickstart (#182)** — new
  [`docs/QUICKSTART.md`](QUICKSTART.md) takes a newcomer from `git clone` to
  their first policy-gated `ssh_execute` in under 10 minutes using one binary
  (`mcp-broker`, stdio) and one `config.json` in local mode — no signer service,
  no mTLS PKI. Ships a committed `config.minimal.example.json` (validated by the
  confcheck anti-drift test), an MCP-client registration snippet, a `dry_run`
  firewall demo, and a "when to move to remote mode" graduation section. Linked
  from the README and mkdocs nav. Docs/examples only.
- **JSONC config files (#183, part 1 — load)** — every config file
  (`config.json`, `signer.json`, `control-plane.json`, `broker-ctl.json`) now
  accepts `//` and `/* */` comments and trailing commas (JWCC) when loaded — on
  startup and on every reload path — so a config can be annotated with real
  comments instead of `_*` comment keys. Plain JSON keeps loading byte-for-byte
  unchanged and a typo'd key still fails closed; the legacy `_*` comment keys keep
  working but are now deprecated in favour of real comments. (Comment-preserving
  config *rewrites* — the signer policy-mutation API and `broker-ctl` edits — and
  the conversion of the shipped `.example.json` files land in a follow-up.)
- **Comment-preserving signer policy mutations (#183, part 2 — signer writes)** —
  the signer's validated policy-mutation API (`broker-ctl policy add/remove`,
  which persists `signer.json` atomically) now rewrites the file with a
  format-preserving JSON Patch (`confcheck.Patch`, via hujson), so an operator's
  `//` comments, key order, and formatting survive an allow-rule edit instead of
  being flattened by a parse→marshal round trip. (`broker-ctl`'s own host/CA/caller
  edits and the `.example.json` conversion remain the last follow-up.)

### Changed
- **Per-agent action-budgets framing (#123)** — the README and
  `docs/OPERATIONS.md` reframe the shipped host/command/approval controls as
  per-agent action budgets; documentation only, no behavior change.

### Security
- **Command-firewall allowlist bypass with `shell_parse` (RCE)** — with
  `command_policy.shell_parse` enabled, the parser that decomposes a command for
  allowlist matching under-modeled what the baked certificate force-command
  actually runs. A `>&FILE` / `<&FILE` redirect (a file write in bash/zsh) was
  misclassified as a safe fd-duplication and stripped, and a standalone
  environment assignment or `export`/`declare` before an allowed command was
  invisible to the policy. Either let an anchored allowlist authorize `echo x` /
  `git fetch origin` while the force-command wrote an arbitrary file or injected
  `GIT_SSH_COMMAND` / `LD_PRELOAD` / `PATH` — remote code execution on the target
  host. The parser now requires an fd operand for `>&` / `<&` and rejects
  environment declarations and standalone assignments (fail-closed). Only hosts
  with `shell_parse=true` were affected.
- **Teams Adaptive Card escapes broker-supplied fields** — the default Teams
  notification format (Adaptive Card) renders `Fact.value` as Markdown, so a
  crafted command/host could inject a clickable link or hidden formatting into
  the approver's notification (phishing / command obscuring). The broker-supplied
  fact values are now Markdown-escaped, matching the `markdown:false` defense the
  legacy MessageCard path already had (default-path sibling of the earlier
  MessageCard fix).
- **Session lifetime capped at the certificate TTL (#124)** — the broker's
  reaper now closes a live session when the certificate that opened it expires,
  bounding a session's exposure to the cert TTL (≤ `max_ttl_seconds`) instead of
  the longer `session_max_seconds`.
- **approval-bridge redacts the command before the chat platform**: the
  `approval-bridge` now masks secrets in an approval's command (using the
  built-in redaction patterns) before presenting it on Slack, matching the
  control plane's webhook/Teams notifier. Previously it reposted the original
  command from `/v1/approvals` verbatim, so a secret passed inline in a
  `require_approval` command leaked in cleartext to the chat channel even with
  `redact` enabled (the Teams/webhook sink and the signed audit masked it).
- **Broker k8s audit no longer embeds the caller in the Command token stream**:
  the k8s execution audit records the caller identity only in the structured
  `caller` field, not as a ` user=` token in the space-delimited `command`
  stream. The caller id (the OIDC user-claim value) is not charset-validated at
  the broker, so a whitespace-bearing identity could otherwise have forged
  tokens into a hash-chained entry (the class the signer already guards, #67).
  Defense in depth; the identity is unchanged and still audited.

### Fixed
- **k8s cluster-scoped scope fidelity**: a client-supplied namespace on a
  cluster-scoped resource (`nodes`, `namespaces`, `persistentvolumes`) is now
  dropped before the canonical action `<verb> <resource> <ns>/<name>` is built,
  so the policy decision, the Ed25519-signed audit record, and the human
  approval reflect the true cluster-wide scope. Previously the namespace rode
  into the canonical — making a destructive action (e.g. `delete nodes`) look
  namespace-scoped to the approver and letting a namespaced deny rule be evaded
  — while execution silently ignored it. Normalized symmetrically on the broker
  and the signer, so the anti-mismatch guarantee still holds.
- **`make` builds `approval-bridge`**: the seventh binary (`cmd/approval-bridge`,
  #120) is now part of `make build` / `install` / `dist`, so the installer
  tarball ships it alongside the other binaries — matching the goreleaser
  release archive, which already did. Previously only `go install` or the
  release archive produced it, though `docs/OPERATIONS.md` documents running it.
- **Local mode rejects an over-cap `max_ttl_seconds` at load (#138)** — the
  single-binary (local) broker now validates the global `max_ttl_seconds`
  against the 15m certificate cap at startup, mirroring `cmd/signer`, instead of
  letting every issuance fail at the first sign request. (The dangling-jump,
  unknown-group and per-host TTL checks were already enforced at load via
  `CompileHostPolicies`; this closes the last divergence from the signer's
  load-time validation.)

### Internal
- **Audit chain verification moved into `internal/audit` (#177)** — the
  hash-chain, Ed25519-signature, cross-segment linkage and trailing-corruption
  logic that `broker-ctl audit verify`/`repair` relied on now lives in the same
  package that *produces* the log (`Verify`, `VerifyEntry`, `VerifySegments`,
  `FileBounds`, `TrailingCorruption`), with a producer→verifier round-trip test.
  A change to how entries are written that would break verification now fails a
  unit test next to the writer instead of surfacing later on an operator's
  machine; `broker-ctl` became a thin consumer with byte-identical output.
- **De-duplicated security-sensitive helpers across broker↔signer (#179)** —
  shell-quoting (`ShellQuote`), the elevated-command builder
  (`BuildElevatedCommand`) and the RBAC group intersection (`GroupsIntersect`)
  existed twice, once in `internal/signer` and once copied into `internal/broker`
  (behind an incorrect "circular dependency" comment). They are now single,
  exported implementations in `internal/signer`, used by both — so the `sudo`
  command line that ends up in a CA-signed force-command and the one sent on the
  session/file-transfer channel can no longer silently diverge. The retained
  quoting implementation preserves input bytes exactly (the broker's rune-copy
  variant would have mangled invalid UTF-8); no behavior change for valid input.
- **Re-established the 80-line function limit (CODING_STYLE §6, #181)** — the
  documented length check counted `func`-to-`func`, mis-attributing package-level
  code to the preceding function (it reported impossibilities like a 327-line
  `decideOne`). Replaced it with a brace-accurate check (`func` line → closing
  `}`) that also skips `main()` and an explicit `// codingstyle:long-function:
  <reason>` in-body marker. Refactored the genuinely over-long functions by
  extracting cohesive helpers — `Register`/`RegisterK8s` (one function per MCP
  tool), `OpenSession` (`openShellForMode`, `startSessionRecording`), `NewEngine`
  (`initRemoteMode`, `openAuditLog`) — and marked the few cohesive/critical ones
  (the `/v1/sign` handler, the marker-framed `ShellSession.Exec`, CLI commands)
  with a reasoned exception. Also unified `mcpserver`'s tool-error construction
  on the `toolError` helper. Pure refactor: tests unchanged, docgen output and
  the MCP tool surface byte-identical.
- **e2e elevation lab (#140)** — new `lab/run_sudo_lab.sh` exercises the sudo +
  PTY path end to end (previously only unit-tested): `ssh_execute(sudo=true)` and
  a `mode=pty` session opened with `sudo=true`. It stands up a local sshd and,
  instead of real NOPASSWD sudoers (which need root), installs a `sudo` shim on
  the session `PATH` via sshd `SetEnv`, so the broker's actual elevation line
  (`sudo -n -- /bin/sh -c …`) runs on the host and is asserted through the shim
  log plus the `sudo:root` label in the signed audit trail. `lab/mcpclient` gained
  a `LAB_SUDO=1` scenario.

## [v1.38.0] - 2026-07-04

Security & correctness audit pass, plus an explicit audit-log recovery command.

### Added
- **`broker-ctl audit repair`** — recover a signer whose audit log had its
  *final* record torn by a crash. A truncated, unparseable trailing line makes
  the signer refuse to boot (by design: on a tamper-evident, hash-chained log a
  truncated tail is indistinguishable from a truncation attack). The command is
  the explicit operator recovery path: dry-run by default; `--apply` quarantines
  the corrupt tail to `<log>.corrupt-<timestamp>` and truncates the log to the
  last well-formed record so the signer can boot, preserving the hash chain;
  `--key` verifies the kept prefix's signatures first. It refuses mid-file
  corruption (not the startup-brick case). The signer stays fail-closed —
  recovery is never automatic. Runbook in `docs/OPERATIONS.md`.

### Changed
- **`release.yml` now publishes `server.json` to the MCP Registry automatically**
  after every tagged release: a `mcp-registry` job (authenticated with GitHub
  Actions OIDC, no PAT) that runs once the `release` job has pushed the ghcr
  image, so the registry can validate OCI ownership. Manual `mcp-publisher
  publish` is no longer part of the release runbook.

### Fixed
- **k8s MCP input validation**: `k8s_list` label/field selectors and `k8s_logs`
  `container` are now length- and null-byte-validated like every other tool
  field (previously they reached the API-server query string without the input
  gate). No injection was possible — query values are percent-encoded — but the
  stdio frontend had no length bound; this closes the unbounded / null-byte gap.
- **Policy recommender double-count**: a single human approval, written to the
  audit log twice (the approval-decision and the consumption), was counted as
  support 2 in `broker-ctl policy recommend`, halving the effective `--min-count`
  for approved commands. Occurrences are now deduplicated by approval id.
- **Global `max_ttl_seconds` load check**: a global cap above the 900s
  certificate limit is now rejected at load (mirroring the per-host cap),
  instead of failing every issuance at request time for a host with no per-host
  cap.

### Internal
- Removed dead test-only session accessors and an orphaned elevation-label
  helper (coverage ported to the production ownership-gated paths).
- `.gitignore` now excludes `control-plane.json`, so a real, secret-bearing
  control-plane config cannot be accidentally committed.

## [v1.37.0] - 2026-07-04

Distribution release: prebuilt binaries, an official OCI image and a
containerized demo. Installing no longer requires a Go toolchain.

### Added
- **Prebuilt release binaries** (goreleaser): one archive per platform
  (`linux`/`darwin` × `amd64`/`arm64`) with all six binaries and the example
  configs, plus `checksums.txt`. The installer tarball for the systemd path
  (`infrabroker-v<ver>.tar.gz`, consumed by `deploy/install.sh`) is unchanged
  and still attached to every release.
- **Official OCI image** `ghcr.io/luisgf/infrabroker` (multi-arch
  linux/amd64+arm64, distroless/static, nonroot): the six binaries with
  `mcp-broker` as entrypoint. Carries the `io.modelcontextprotocol.server.name`
  label the MCP Registry uses to validate package ownership (`server.json`
  bumped to reference `ghcr.io/luisgf/infrabroker:1.37.0`).
- **Compose demo** (`examples/compose/`, `make demo`): signer + toy sshd
  target + broker with auto-provisioned PKI — run a policied command through
  the full remote-signing topology in 5 minutes, then `down -v` and it is
  gone. Works with docker compose and podman compose (rootless).
- **docs/CONTAINERS.md**: image usage (stdio MCP in a container, other
  binaries via `--entrypoint`), the demo walkthrough, podman notes, and the
  explicit demo≠production and k8s-target≠k8s-runtime boundaries.
- README **Install** section: release binaries, `go install`, container and
  one-click `claude mcp add` lines.

### Changed
- `release.yml`: goreleaser now owns the GitHub release (archives, checksums,
  image push to ghcr and multi-arch manifests); `make dist` still builds the
  installer tarball, attached via `release.extra_files`. Workflow gains
  `packages: write`.

## [v1.36.0] - 2026-07-04

The project is renamed **ssh-broker → infrabroker**: the broker outgrew SSH
(Kubernetes tools shipped in v1.2x, databases are under study) and the old name
hid half the surface. No functional changes.

### Changed
- **Rename to `infrabroker`** everywhere it is not history or an on-disk
  format: Go module path (`github.com/luisgf/infrabroker`), Makefile/dist
  artifact (`infrabroker-<version>.tar.gz`), CI workflows, docs site
  (`luisgf.github.io/infrabroker`), systemd units (`infrabroker-*.service`),
  system users/group (`infrabroker-<svc>`, `infrabroker`), and install paths
  (`/etc/infrabroker`, `/var/lib/infrabroker`). The GitHub repository is
  renamed; old URLs and `go get` paths redirect.
- **Recording header extension renamed** `ssh_broker` → `infrabroker`.
  Recordings written by older versions keep the old key — ASCIIcast players
  ignore unknown header fields either way, but `jq` review of old `.cast`
  files must still query `ssh_broker`.
- **Suggested host-side CA filename** in OPERATIONS.md is now
  `/etc/ssh/infrabroker_ca.pub`; existing hosts keep whatever
  `TrustedUserCAKeys` path they already use.
- **Not renamed**: binary names (`mcp-broker`, `broker`, `broker-ctl`,
  `signer`, `control-plane`) — they never carried the project name — and
  historical changelog entries, which describe what those releases actually
  shipped.
- **Existing deployments must migrate manually** — the installer does not
  rename users/paths/units on top of a pre-rename install. See "Upgrading from
  ssh-broker (pre-rename, ≤ v1.35)" in `deploy/README.md`.

### Added
- MCP registry manifest (`server.json`). Repo repositioning shipped alongside:
  GitHub topics, README badges and the new tagline ("Infrastructure access
  broker for AI agents — SSH & Kubernetes").

## [v1.35.0] - 2026-07-04

Deployment privilege separation, a Kubernetes authorization fix, and a hardened
docs anti-drift gate. Each service now runs as its own system user, a
Kubernetes `deny` rule now actually blocks (it was silently ignored), and the
reference-doc drift gate is enforced on a protected `main`.

### Security
- **Kubernetes `deny` rules are enforced again.** `deny`-effect ActionPolicy
  rules were compiled into an allowlist policy's deny slice, which the evaluator
  only consults for denylist-mode members — so a `deny` overlapping a broad
  `allow` (e.g. `allow get *` + `deny get secrets`) was silently ignored and the
  allow won. Deny rules are now compiled into a dedicated denylist member so
  "deny wins" holds, and `CommandPolicy.Validate` rejects a deny pattern on an
  allowlist policy (or an allow on a denylist) at config load so the class
  cannot recur. Only affects clusters whose rules carve a `deny` out of a
  broader `allow`; default-deny clusters were never exposed.
- **One system user per service** (`ssh-broker-signer`,
  `ssh-broker-control-plane`, `ssh-broker-mcp-http`) in the systemd units and
  the installer, so a compromised broker frontend can no longer read the
  signer's CA key, policy, grant state, audit seed, or mTLS key — nor
  impersonate another service or the admin CLI. The shared `ssh-broker` group
  remains only for traversing `/etc/ssh-broker` and reading the shared mTLS CA
  certificate. The legacy single `ssh-broker` user is no longer created or used.
- **Per-service PKI subdirectories**: each private key lives in
  `/etc/ssh-broker/pki/<svc>/` (`0750 root:ssh-broker-<svc>`), readable by that
  service alone; only the shared CA cert stays at the `pki/` root. Admin CLI
  material moves to `pki/admin/` (root-only) so no service can impersonate the
  admin (`broker-ctl.example.json` updated accordingly).
- **Per-service config groups**: `/etc/ssh-broker/{control-plane,config}.json`
  are readable only by their own service (they can carry secrets — OIDC
  client, webhook tokens).

### Fixed
- Secret redaction no longer masks the bare shell `PWD=` working-directory
  variable (`MYSQL_PWD=`/`DB_PWD=` still masked); it was degrading the forensic
  value of every recording and `env` dump.
- `deploy/install.sh`'s stray-key migration warning is NUL-safe (key filenames
  with spaces stay intact) and no longer swallows a `find`/`grep` failure as a
  silently-absent security warning.
- `tools/docgen` prunes orphaned reference pages, so a removed or renamed
  generator surfaces as a drift-gate failure instead of shipping a stale page.

### Changed
- `deploy/install.sh` creates the per-service users/groups, converges ownership
  of state directories and configs on upgrade (idempotent), and warns about
  private keys still flat under `pki/` that must be moved into the per-service
  subdirectories. Migration steps from the ≤ v1.34 single-user layout are in
  `deploy/README.md` §Upgrades.
- **Docs anti-drift gate hardened and enforced.** The gate now uses
  `git status --porcelain` (catching untracked and deleted generated pages, not
  just tracked edits); `main` is a protected branch with `build`, `govulncheck`
  and `check` as required status checks; and a new `make verify` target runs the
  full local pre-push gate.
- `THREAT_MODEL.md` documents the colocated-host process-isolation posture,
  `OPERATIONS.md` documents the per-service deployment layout and the
  least-privilege k8s minter-token permissions, and the deploy skill preflight
  checks the per-service key placement.

## [v1.34.0] - 2026-07-03

Kubernetes target (credential-broker): the signer can now broker access to
Kubernetes clusters, reusing the whole control plane (identity, RBAC, approval,
grants, signed audit) with a structured action grammar instead of the shell
one. The agent never holds a cluster credential — the signer mints a
short-lived bound ServiceAccount token per authorised action and the cluster's
native RBAC enforces it.

### Added
- **Six curated MCP tools**, registered only when the broker sees a cluster
  (an SSH-only deployment does not offer them): `k8s_list_clusters`,
  `k8s_get`, `k8s_list` (label/field selectors, limit), `k8s_logs`
  (container, tail, since) — read-only — plus `k8s_apply` (server-side apply)
  and `k8s_delete`, both policy- and approval-gated. No pod-exec, port-forward,
  watch, or sessions in this phase.
- **Per-cluster ActionPolicy, default-deny.** Structured rules
  (`{verbs, resources, namespaces, names, effect}`; effect `allow` | `deny` |
  `require_approval`) compile at load into the *same* `PolicySet` machinery as
  `command_policy`, over a **canonical action string**
  `<verb> <resource[.group]> <namespace>/<name>` built from charset-validated
  fields (never parsed → injection-free). So deny-wins composition, runtime
  grants, approve-and-learn waivers, and `policy recommend` all apply to k8s
  actions unchanged. The broker sends the structured fields **and** the
  canonical string; the signer recomputes it and rejects a mismatch, so the
  approver and the audit log see exactly what runs.
- **Bound ServiceAccount tokens.** The signer holds one minimal-privilege
  minter credential per cluster (`token_file`; RBAC = `create` on
  `serviceaccounts/token` for the bound SAs) and calls the TokenRequest API to
  mint a bound token (TTL 600–900s) for the SA selected by the end user's
  groups (`sa_bindings`). The token travels back over the existing mTLS channel
  like an SSH certificate.
- **Dependency-free k8s client** (`internal/k8s`): the five verbs plus
  TokenRequest as plain REST over `net/http` (no client-go), pinned to the
  cluster CA, with a curated core resource table plus per-cluster
  `extra_resources` (no API discovery).
- **New config** `kubernetes.clusters.<name>` in `signer.json` (parallel to
  `hosts`; cluster names must be disjoint from host names — grants and audit
  are indexed by that shared name). New signer endpoint `GET /v1/clusters`
  (caller-scoped connectivity, forwarded by the control plane) and
  `broker-ctl cluster list --remote`.
- `audit.Entry` gains `target_type` and `body_sha256`: a `k8s_apply` manifest
  is never logged verbatim (it can carry a Secret) — only its sha256, mirroring
  file transfers.
- New e2e lab `lab/run_k8s_lab.sh` (mock API server, no cluster needed): mints a
  bound token for an allowed action, gates a delete behind approval and issues
  the token after approval, and enforces default-deny and deny-wins.

### Security
- The Kubernetes credential-broker's structural trade is documented as
  threat-model gap #10: a bound token grants the ServiceAccount's whole RBAC
  for its TTL, not a single call (no `force-command` equivalent). Scope agent
  ServiceAccounts to least privilege; the minter credential is deliberately
  minimal (only token-minting for the bound SAs).

## [v1.33.0] - 2026-07-02

Dynamic state persists across restarts: an opt-in SQLite `state_db` (pure-Go
driver, no CGO, no system dependency) backs the signer's runtime grants and
the control plane's approval registry. Closes the deploy caveat "restarting
the control plane clears pending approvals".

### Added
- New `internal/statedb` package: opener + `user_version` migration runner
  (WAL, `busy_timeout`, single connection). A database written by a newer
  binary is refused; if `state_db` is set and cannot be opened or migrated,
  the service refuses to start (fail-closed). `statedb_errors_total` counts
  best-effort write failures (in-memory state diverged from disk until the
  next restart) — alert on any increase.
- **Signer grants/waivers persist** (`state_db` in `signer.json`).
  Write-through with the in-memory map still the only state consulted on the
  decision path (zero I/O on `/v1/sign`): `Add` is insert-first (a grant that
  cannot be persisted fails the API call), expiry/supersede sweeps are
  best-effort (an expired row is filtered out on load), and **revocation is
  deliberately hard** — the row is deleted before the in-memory grant, so a
  revoked grant can never resurrect on restart after the operator saw a
  success. Live rows are reloaded at startup with their waiver patterns
  recompiled; approve-and-learn waivers keep their caller/end-user/elevation
  binding across restarts.
- **Approval registry persists** (`state_db` in `control-plane.json`),
  including the original wire request (public material only — the broker's
  ephemeral *public* key), so a pending or approved-but-uncollected request
  survives a restart and the polling broker still collects its certificate.
  `Create` is insert-first; `Decide` and consume transitions are written
  through; terminal entries inside the purge window are restored too, so a
  poller sees `denied`/`approved` instead of a 404. The `issuing` flag is an
  intra-process concurrency gate and is intentionally not persisted: after a
  restart an approved-but-unconsumed request is consumable again — exactly
  once. Behaviour baselines stay in-memory by design (they re-learn).
- New e2e lab `lab/run_state_lab.sh` (no sshd needed): grant survives a
  signer restart and its revocation is durable; a pending approval survives a
  control-plane restart, is approved afterwards, the poller gets the
  certificate, and the consumed approval stays consumed across another
  restart.

### Documentation
- THREAT_MODEL gap #5 updated: restart-survival vs multi-instance, and the
  consume crash window (a crash between certificate issuance and the
  `consumed` write re-exposes the approval once, bounded by the approval and
  certificate TTLs). OPERATIONS "what survives a restart"; deploy checklist
  and example configs gain `state_db` (with the WAL `-wal`/`-shm` backup
  note).

### Internal
- `GrantStore.Revoke` now returns `(bool, error)`; the grant-revoke API
  answers 500 and keeps the grant when the durable delete fails.
- New dependency `modernc.org/sqlite`, confined to `internal/statedb` — the
  driver links only into `signer` and `control-plane`, not the broker
  frontends.

## [v1.32.0] - 2026-07-02

Secret redaction (threat-model gap #8): an opt-in `redact` config block on the
three services masks secrets embedded in commands at every persistent or
outbound sink, replacing them with `[REDACTED:<rule>]`.

### Added
- New `internal/redact` package: named RE2 rules, built-in defaults
  (password/token flags, the attached `mysql -p<pass>` form, `VAR=secret`
  assignments with `_`-delimited keyword matching, URI `user:pass@`,
  `Authorization` headers, JWTs, AWS/GitHub/GitLab/Slack tokens, private-key
  blocks) plus operator-defined `patterns` (a `(?P<secret>...)` group masks
  only the secret and keeps the rest of the match as forensic context;
  `disable_defaults` keeps only the operator rules). An invalid pattern is a
  startup error (fail-closed), and overlapping rules never re-mask another
  rule's marker.
- Redaction choke-points, so no call site can be missed:
  - `audit.Log`: the free-text fields (`command`, `err`, `warning`, `anomaly`)
    are masked **before the entry is signed** — the Ed25519 signature and hash
    chain cover the redacted content, `broker-ctl audit verify` is unaffected,
    and the original text is never persisted (irrecoverable by design).
  - `recording.Recorder`: every ASCIIcast event is masked. Input events carry
    one full command line per event (reliable); output arrives in arbitrary
    chunks, so a split secret can escape a pattern (documented best-effort).
  - Control-plane notifier: the approval notification payload
    (log/webhook/Teams) is masked. The approval registry keeps the original
    command — the mTLS approval UI (`/ui/approvals`) and `GET /v1/approvals`
    show the approver exactly what will run, and the approved request
    forwarded to the signer is untouched.
- `redact` config key in the broker (`config.json`), signer (`signer.json`)
  and control plane (`control-plane.json`). Present — even empty `{}` —
  enables the built-in defaults; absent = disabled (backward compatible).
  Redaction never touches the decision path: the signer and the certificate
  force-command always see the original command.

### Documentation
- New "Redaction is best-effort" section in SECURITY.md (limits: regex ≠ DLP,
  chunked output, decision path untouched by design, false-positive escape
  hatch); THREAT_MODEL gap #8 updated from "no redaction" to "opt-in,
  best-effort"; `redact` blocks in the three example configs; config reference
  regenerated.

## [v1.31.1] - 2026-07-02

### Fixed
- Deployment: the signer config moves to the service-owned state directory
  `/var/lib/ssh-broker/signer/signer.json`. v1.31.0's `ReadWritePaths` fix (#38)
  removed the systemd barrier to the durable policy-mutation API
  (`broker-ctl policy add/remove`), but the POSIX permission barrier remained —
  `/etc/ssh-broker` is `root:ssh-broker 0750`, so the `ssh-broker` service user
  could not create `signer.json.tmp` for the temp-file+rename and every durable
  mutation still failed `EACCES`. Placing the signer config where the service
  owns it (and reverting the now-unnecessary `ReadWritePaths`, keeping `/etc`
  read-only for the service) lets durable mutations persist while the PKI and
  the other services' configs stay root-owned in `/etc`. Binaries are unchanged
  from v1.31.0; this is a deploy-artifact + docs fix. The installer seeds the
  signer config to the new location; the systemd unit points `-config` there.

## [v1.31.0] - 2026-07-02

Security & correctness audit pass. Fourteen findings across the signer, control
plane, broker-ctl, deployment artifacts and docs.

### Security
- Signer rejects an empty one-shot command. An empty command baked **no**
  force-command into the certificate (an unrestricted host credential) and, on
  a denylist or approval-only host, slipped past the command firewall and the
  human-approval gate. Rejected at the authoritative layer (#37).
- The control plane no longer trusts an unauthenticated, broker-supplied
  `end_user` for the approver's display, the notifier, or the forward to the
  signer unless the broker CN is a trusted forwarder — a malicious broker could
  otherwise label a command as coming from a trusted admin to bias the human
  decision (#40).
- `broker-ctl` no longer searches the current working directory for
  `broker-ctl.json`, and a relative default cert/key/ca resolves against the
  loaded config file's directory rather than the CWD, so a planted file cannot
  redirect the CLI's mTLS endpoint or CA trust anchor (#39, #42).
- The approval webhook/Teams notifier requires an `https` URL (`http` only for a
  loopback relay), preventing cleartext leakage of approval details; the legacy
  Teams MessageCard no longer enables markdown, which could inject links into
  the approver's notification (#44, #43).

### Fixed
- The signer systemd unit adds `ReadWritePaths=/etc/ssh-broker` so the durable
  policy-mutation API can persist to `signer.json`; under `ProtectSystem=strict`
  it was failing `EROFS` while in-memory grants and SIGHUP reload masked it (#38).
- The release workflow builds via `make dist`, so the published artifact ships
  the `control-plane` binary (the shipped unit had nothing to exec), `deploy/`
  and the example configs, with the version injected (#41).
- A per-host `max_ttl_seconds` above the 900s certificate cap is rejected at
  config load instead of failing every issuance at request time (#45).
- The signer rate-limiter bucket map stays strictly bounded — least-recently-used
  eviction when pruning frees nothing (#46).

### Documentation
- `ssh_list_servers` return table documents `allow_file_transfer`; the README
  stdio bullet lists the file-transfer tools; the OPERATIONS reference-config
  table includes `broker-ctl.example.json`; `config.example.json` gains a
  `file_transfer_max_bytes` example (#47–#50).

## [v1.30.0] - 2026-07-02

### Added
- `GET /v1/policy/hosts` on the signer: full host-policy read (the current
  in-memory table, same schema as the signer.json `hosts` object, including
  the fields `GET /v1/hosts` withholds from brokers — principal, TTLs,
  `allowed_callers`, `command_policy`). Auth is the `reload_callers` tier,
  like the policy mutation APIs; every read attempt is audited
  (`policy-read` / `policy-read-denied`).
- `broker-ctl host list --remote`: renders the live policy from a running
  signer over mTLS with the same columns as the local view — the recommended
  post-deploy end-to-end check. A non-200 is a hard failure (no silent
  fallback to the reduced `/v1/hosts` view).
- broker-ctl client parameters file: the remote commands (`reload`,
  `policy add/remove/grant/grants/revoke`, `approval list/allow/deny`,
  `host list --remote`) resolve `--url/--cert/--key/--ca` with per-parameter
  precedence **flag > env > file > default**. File search order:
  `--client-config`, `$BROKER_CTL_CONFIG`, `./broker-ctl.json`,
  `~/.config/broker-ctl/config.json`, `/etc/ssh-broker/broker-ctl.json`
  (seeded by `deploy/install.sh`). Env vars:
  `BROKER_CTL_SIGNER_{URL,CERT,KEY,CA}`, `BROKER_CTL_CP_{URL,CERT,KEY,CA}`.
  New `broker-ctl.example.json`, validated against the struct in CI.
- The signer-facing remote commands accept `--url`, so none of them need a
  local `signer.json` anymore (its `listen` field remains the last-resort
  URL fallback).

## [v1.29.0] - 2026-07-02

### Added
- Production deployment artifacts under `deploy/`: hardened systemd units for
  the three daemons (`ssh-broker-signer`, `ssh-broker-control-plane`,
  `ssh-broker-mcp-http`) with full sandboxing (`ProtectSystem=strict`, empty
  capability bounding set, syscall filtering), `StateDirectory`-managed audit
  log directories under `/var/lib/ssh-broker/<svc>/`, `systemctl reload`
  (SIGHUP) wired to the signer's hot-reload, and an optional
  `EnvironmentFile=/etc/ssh-broker/<svc>.env` for `AZURE_*` credentials when
  CA custody is Azure Key Vault.
- `deploy/install.sh`: idempotent root installer — creates the `ssh-broker`
  system user, the `/etc/ssh-broker` + `/etc/ssh-broker/pki` layout, installs
  binaries and units, and seeds configs from the examples without ever
  overwriting an existing real config (safe for upgrades).
- `make dist`: release tarball (`dist/ssh-broker-<version>.tar.gz`) bundling
  the binaries, `deploy/`, and the example configs the installer seeds from.
- `deploy/README.md`: production checklist presenting **CA custody as an
  explicit operator choice** — `akv` (Azure Key Vault; the private key never
  leaves the vault; RSA/EC only) vs `pem` (local file; lab/dev) — plus
  default-deny `callers`, rate limiting, monitor binding, and upgrade caveats
  (in-memory approvals/sessions).
- Vendor-agnostic agent skill `.agents/skills/deploy/SKILL.md` (symlinked from
  `.claude/skills`): the judgment layer over the deterministic tooling —
  preflight policy checks, the custody question, reload-vs-restart decision,
  and post-deploy health verification.
- New § 8 "Production deployment" in OPERATIONS.md.

## [v1.28.0] - 2026-07-02

### Added
- Built-in approval UI on the control plane's mTLS listener:
  `GET /ui/approvals` (pending-first list, auto-refresh) and
  `GET /ui/approvals/{id}` (request context with Approve / Deny and an
  optional approve-and-learn TTL). Server-rendered `html/template`, no new
  dependency, no external assets. Decisions are same-origin JavaScript POSTs
  to the existing `/v1/approvals/{id}` API, so the audit trail, broker/approver
  role separation, and the four-eyes self-approval guard apply unchanged. Auth
  is the browser's mTLS client certificate (CN in `approval.callers`).
  `approval_url_template` can now point notification links at
  `https://<control-plane>/ui/approvals/{id}`.

### Security
- `POST /v1/approvals/{id}` requires `Content-Type: application/json` (415
  otherwise): CSRF hardening for the browser UI — mTLS client certificates are
  ambient credentials and an HTML form with `enctype=text/plain` can smuggle a
  JSON-shaped body cross-site; the media-type requirement stops forms, and a
  cross-origin `fetch` carrying it is stopped by the CORS preflight (the server
  sends no CORS headers). `broker-ctl` already sent the header.

## [v1.27.0] - 2026-07-02

### Added
- Two new MCP tools, `ssh_put_file` and `ssh_get_file`, built on the one-shot
  certificate machinery (no SFTP subsystem, no new dependency): the transfer is
  a force-command one-shot (`cat > path` / bounded `head -c` read) with content
  streamed over stdin/stdout; binary data via base64. A file larger than the
  cap is an error, not a truncation. The content's sha256, size, and path are
  recorded in dedicated `file_put`/`file_get` audit entries correlated with the
  `executed` entry by serial.
- New per-host gate `allow_file_transfer` (default **false**, secure by
  default) in the signer HostPolicy and broker local-mode HostConfig, enforced
  at signing time via the new `file_transfer` intent/wire flag, exposed in
  `GET /v1/hosts` and `ssh_list_servers`, and manageable with
  `broker-ctl host add --file-transfer`. The generated transfer command remains
  subject to the host's `command_policy`.
- Broker config `file_transfer_max_bytes` caps transfer size (default 512 KiB;
  the HTTP MCP frontend's 1 MiB body bound must fit base64-encoded content).

## [v1.26.0] - 2026-07-02

### Added
- Every service accepts an optional `monitor_listen` config key that starts a
  separate plain-HTTP listener with `/healthz` (liveness) and `/metrics`
  (Prometheus text exposition format, no new dependencies). The broker key
  covers all three broker frontends.
- Initial metric inventory, fed from the existing audit funnels:
  `signer_sign_requests_total{outcome}` (including the un-audited
  `rate-limited` outcome), `controlplane_events_total{outcome}`,
  `controlplane_approvals_pending`, `broker_events_total{outcome}`,
  `broker_sessions_active`, and `audit_append_failures_total` — the
  machine-readable signal for threat-model gap #9 (audit is fail-open); alert
  on any increase.

## [v1.25.0] - 2026-07-02

### Security
- The signer enforces an optional per-CN rate limit on `POST /v1/sign`
  (`sign_rate_limit_per_min`, hot-reloadable), closing threat-model gap #4 on
  opt-in: a token bucket keyed on the authenticated mTLS peer CN — not
  `on_behalf_of` — checked before body parsing. Excess requests get `429` with
  a `Retry-After` hint; rejections are deliberately not audited so the
  tamper-evident log cannot become the flooding amplifier. 0/absent = disabled
  (backward compatible).

## [v1.24.0] - 2026-07-02

### Security
- The `callers` RBAC table supports a reserved `"_default"` entry that unlisted
  broker CNs inherit, closing threat-model gap #6 on opt-in:
  `"_default": {"allowed_groups": []}` makes the table default-deny, so
  forgetting to list a new CN fails closed instead of open. Explicit entries
  always win over `_default`.

### Added
- `broker-ctl callers add` accepts an explicitly-empty `--groups ""` to write a
  deny-all `allowed_groups: []` entry (required to create the `_default`
  default-deny entry from the CLI; an omitted `--groups` is still a usage error).

### Documentation
- Audited the whole doc set against the code and fixed the drift (#18): the
  generated config reference now covers the broker/MCP config (docgen recurses
  into nested structs and resolves const-named routes), API status codes match
  the handlers, and stale binary/package inventories were completed.
- Refreshed handoff, architecture, and changelog notes for post-v1.23.5 audit
  hardening and the scoped approve-and-learn waiver behavior.
- Corrected runtime-grant list examples so allow-grants and approval-waivers show
  their distinct fields and match the `broker-ctl policy grants` output.

### Fixed
- Approve-and-learn approval waivers are now scoped to the effective broker caller
  and OIDC end user that were approved, instead of clearing re-approval for every
  subject that can reach the same host/command.
- Persistent shell/PTY session readers now cap a single unterminated stdout line
  before buffering it, so a remote command cannot bypass `maxOutputBytes` by
  emitting a huge line without a newline.
- `broker-ctl reload` now matches the local process basename exactly before
  sending SIGHUP, avoiding accidental signals to unrelated commands whose name
  merely contains `signer`.

## [v1.23.5] - 2026-06-30

### Documentation
- Corrected post-release documentation drift for v1.23.4 and clarified that
  session preflight revalidates authorization, elevation, PTY, and command policy.
- Corrected the context-propagation notes: `SessionExec` now uses caller context,
  while AKV signing is bounded by the signer's own timeout because `crypto.Signer`
  has no context parameter.
- Removed fixed test-count numbers from the handoff document and kept only the
  stable coverage areas.

### Fixed
- Behavior guardrails in `enforce` mode no longer learn a novel host/command
  before approval is granted. Repeating the same unapproved anomaly keeps
  returning `202` instead of silently entering the subject baseline.
- `ssh_session_exec` now revalidates every bastion hop as `role=bastion` before
  the target command preflight, so signer reloads that revoke jump-host access
  also stop already-open sessions on their next command.
- New `ssh_execute` and `ssh_session_open` calls refresh `/v1/hosts` immediately
  before building SSH hops and fail closed on refresh errors, avoiding stale
  `addr`/`host_key`/`jump` data for new connections.
- The control-plane config loader now rejects unknown `behavior.mode`,
  `approval.notifier`, and `approval.teams_format` values at startup instead of
  silently disabling guardrails or falling back to the log notifier.
- Made broker shutdown idempotent, including repeated `Engine.Close()` calls.
- Canonicalized approve-and-learn waiver elevation so `sudo_user=""` and
  `sudo_user="root"` match the same effective sudo target.
- Propagated `preflight` from the signer HTTP request into the internal signing
  intent.
- Hardened persistent shell session markers against `printf()` function
  redefinition, so `shell`/`pty` sessions cannot spoof the reported exit code by
  shadowing the marker emitter.
- Rejected `ssh_session_exec` on an already-open session when the current signer
  host route (`addr`/`user`/`host_key`/`jump`) no longer matches the route used
  to open that session.

## [v1.23.4] - 2026-06-30

### Fixed
- **Session preflight now carries PTY state.** `ssh_session_exec` preflight sends
  the live session's PTY bit to the signer, so a policy reload that disables
  `allow_pty` also stops already-open `mode=pty` sessions on their next command.

### Documentation
- `control-plane.example.json`, API, operations, architecture, and handoff docs
  now describe the approved-but-uncollected approval TTL and the current v1.23.x
  session-preflight behavior.

## [v1.23.3] - 2026-06-30

### Fixed
- **Approved requests now expire if they are not collected.** Once a human
  approves an operation, the broker must redeem it within the approval TTL; stale
  approved-but-unconsumed requests can no longer issue a certificate later.
- **Session command preflight now follows current signer policy.** Every
  `ssh_session_exec` is rechecked with `dry_run=true` + `preflight=true`, so
  signer reloads affect already-open sessions. `mode=exec` commands enforce the
  new policy on the next call, and existing `shell`/`pty` sessions are blocked
  once a command policy becomes active.

### Documentation
- Clarified that session command filtering is broker-preflighted but not
  host-enforced, fixed the persistent-session serial examples, and updated the
  session/preflight API wording.

## [v1.23.2] - 2026-06-30

### Fixed
- **Approved requests survive transient signer failures.** The control plane now
  burns an approval only after the signer returns a certificate or preflight
  decision, while still preventing concurrent double issuance.
- **Broker HTTP responses preserve audit-mode warnings.** `/v1/ssh_run` now
  includes optional `warnings` so clients can see command-policy audit findings.

### Documentation
- API/MCP return-field documentation now lists `warnings`, and the security scope
  no longer describes session command firewalling as entirely absent.

## [v1.23.1] - 2026-06-30

### Fixed
- **Session exec preflight is now scoped to command-policy hosts.** `mode=exec`
  sessions on unrestricted hosts no longer call the signer before every
  `ssh_session_exec`; hosts with `command_policy` still preflight each command.
- **Executable preflights now pass through control-plane behavior guardrails.**
  Pure dry-runs still bypass guardrails, but `dry_run=true` + `preflight=true`
  is treated as an imminent execution and can be rate-limited or escalated.

### Documentation
- Main example configs now use `enforcement: "enforce"` by default and document
  `audit` as a baseline-collection mode.
- API and architecture documentation updated for executable preflight.

## [v1.23.0] - 2026-06-30

### Added
- **Command-policy audit mode.** `command_policy.enforcement` now accepts
  `"audit"` (default remains `"enforce"`). Audit mode lets commands run while
  returning and auditing warnings such as `would_deny` and
  `would_require_approval`, so operators can collect a baseline before enforcing
  allow/deny/approval rules. In composed policies, any enforcing policy wins; a
  host is audit-only only when every restricting policy is audit.
- **Command firewall for `ssh_session_exec` in `mode=exec`.** Hosts with
  `command_policy` now allow `ssh_session_open mode=exec`; the broker preflights
  each `ssh_session_exec` with the signer before opening the SSH exec channel.
  Denied or approval-gated commands are blocked in enforce mode and returned as
  warnings in audit mode. `shell` and `pty` sessions remain rejected on
  command-policy hosts.

### Changed
- `broker-ctl host add` supports `--policy-enforcement enforce|audit` and
  preserves that field during partial `--force` command-policy updates.
- MCP execution outputs now include optional `warnings`, and audit entries can
  carry a `warning` field for audit-mode policy observations.

## [v1.22.1] - 2026-06-30

Patch release correcting the incomplete client-cancellation fix from v1.22.0 (it
only covered PTY executions) and a strict-config-validation blind spot for
`_`-prefixed map entries.

### Fixed
- **Client cancellation now aborts non-PTY SSH executions too.** The v1.22.0
  cancellation fix only reached the PTY branch of `ExecOnce`; the common non-PTY
  path (`ssh_execute` and exec-mode sessions) still ran to the 10-minute timeout
  after a client disconnect. Both branches now share a single `waitResult` core
  (unit-tested), so the cancellation and timeout handling cannot diverge again.
- **Cancelling a shell/PTY session command now tears down the SSH channel**, so the
  remote command actually stops instead of lingering until the session is closed or
  reaped.
- **Strict config validation no longer has a blind spot for `_`-prefixed map
  entries.** The strict pass stripped every `_`-prefixed key, so a typo nested inside
  an entry whose identifier starts with `_` (e.g. a host `"_x"` with a misspelled
  field) went undetected — and on default-open fields could widen access. Stripping
  now distinguishes comments (the `_*_comment` / `_*_example` convention, or a
  `_`-prefixed key with a scalar value such as an inline `_note`) from real data (a
  `_`-prefixed object/array entry, or `_default`), so data entries reach validation
  while inline comments are still ignored.

### Documentation
- THREAT_MODEL.md no longer lists the certificate TTL as a session mitigation: for an
  established session the bound is `session_idle_seconds` / `session_max_seconds`, not
  the cert TTL.

## [v1.22.0] - 2026-06-30

Config and session hardening: fixes a v1.21.0 regression that could drop real
`_`-prefixed config keys, two session-management defects (unauthorized close
refreshing the idle timer; client cancellation not aborting commands), and corrects
the session-lifetime documentation.

### Fixed
- **Strict config no longer drops real `_`-prefixed map keys.** `confcheck.Strict`
  (the runtime loader path added in v1.21.0) stripped every `_`-prefixed key before
  decoding, which would silently delete a legitimate map entry whose key begins with
  `_` — e.g. a broker CN `_ci` in `callers`, whose removal makes that CN fall back to
  default-open. The loader now loads the real value with a lenient pass and uses the
  strip+strict pass only to detect unknown struct fields (typos), so `_`-prefixed map
  data is preserved while a misspelled control is still rejected.
- **Unauthorized `CloseSession` no longer refreshes a session's idle timer.** It went
  through `get()`, which updated `lastUsed` before the ownership check, so a caller
  holding a leaked `session_id` could keep another caller's session alive against the
  idle reaper. Ownership is now checked and the session removed atomically, without
  touching `lastUsed` (C1).
- **Client cancellation now aborts in-flight SSH commands.** `SessionExec` ignored its
  context and `ExecOnce` had none, so a disconnected MCP/HTTP client left the remote
  command running until the 10-minute execution timeout. The request context is now
  threaded through `ExecOnce` and the shell/PTY `Exec`; on cancellation the command is
  signalled and the channel closed.

### Documentation
- Corrected the session-lifetime docs (USAGE.md and the `ssh_session_open` /
  `ssh_session_close` MCP descriptions): an established session is closed by
  `session_idle_seconds` / `session_max_seconds`, **not** by the certificate TTL
  (OpenSSH validates the certificate only at authentication). Set `session_max_seconds`
  to the maximum exposure window you accept.

## [v1.21.0] - 2026-06-30

Config-safety hardening: the runtime loaders now reject unknown/misspelled keys so a
typo cannot silently leave a security control open. No change to the wire protocol or
the broker's runtime behaviour.

### Security
- **Config is strictly decoded at load (fail-closed on unknown keys).** The runtime
  loaders (signer, control plane, broker — startup, reload, and the policy-mutation
  path) now reject a config with an unrecognised or misspelled key instead of silently
  ignoring it, so a typo in a security control (`sign_callers`, `allowed_callers`,
  `callers`, …) can no longer quietly leave a default-open setting. Comment keys (`_*`)
  and the reserved `_default` group are still accepted (`internal/confcheck.Strict`).

### Documentation
- OPERATIONS.md documents `sign_callers` / the broker–approver role separation and the
  strict config validation.

### Internal
- Documented why `crypto/rand.Read` errors are intentionally discarded in the id/marker
  helpers (on Go 1.24+ it never returns an error — it crashes on RNG failure — so the
  discarded return is not a fail-open path).

## [v1.20.0] - 2026-06-30

Security hardening of the control plane and the mTLS caller identity — no change to
the broker's runtime behaviour or the wire protocol.

### Security
- **Control-plane broker/approver role separation.** The signing path (`/v1/sign`,
  `/v1/hosts`, `/v1/sign/result`) is now restricted to brokers: a new `sign_callers`
  allowlist pins which CNs may sign, and with no list a CN in `approval.callers` is
  denied the sign path (an approver is not a broker — secure by default). This closes a
  role-confusion gap where an approver certificate, signed by the same `client_ca`,
  could originate signing requests.
- **mTLS rejects an empty or malformed CN.** `auth.CallerCN` now fails closed on an
  empty common name or one containing control characters, instead of treating it as an
  unlisted (default-open) identity.

### Fixed
- **Control plane forwards host `groups` on `GET /v1/hosts`.** The group labels were
  dropped when re-serialising the host list, so an OIDC user with groups saw zero hosts
  in `ssh_list_servers` behind the control plane. Restores the documented `/v1/hosts`
  contract.

## [v1.19.0] - 2026-06-30

Relicensing and documentation infrastructure: the project is now **GPL-3.0**, and the
docs are published to **GitHub Pages** with a CI pipeline that keeps them from drifting
from the code. No change to the broker's runtime behaviour, API, config, or tools.

### Changed
- **Relicensed from proprietary to GPL-3.0.** `LICENSE` is now the GNU General Public
  License v3.0; README updated accordingly.
- **Wiki mirror enabled.** The one-way docs→Wiki CI job is on (`ENABLE_WIKI_MIRROR`);
  it pushes with `GITHUB_TOKEN` (falls back to a `WIKI_TOKEN` PAT if one is set).
- **Documentation moved to `docs/` and published to GitHub Pages**, built from the
  repo's Markdown by `mkdocs-material` (single source of truth, reviewed in the same
  PR as the code). A one-way CI job optionally mirrors the docs to the read-only
  GitHub Wiki.

### Added
- **Anti-drift documentation pipeline.** `tools/docgen` regenerates
  `docs/reference/{endpoints,mcp-tools,config,cli}.md` from the actual HTTP routes,
  MCP tool schemas (enumerated from the live server), config structs, and the
  `broker-ctl` CLI; CI fails if the committed reference differs. The example configs
  are validated against their Go structs (`internal/confcheck`), and `mkdocs build
  --strict` fails on a broken link or anchor. New `make docs-gen|docs-check|docs-serve`.

## [v1.18.0] - 2026-06-19

Dynamic command policy: a runtime overlay composed on top of the file baseline so the
firewall can be loosened temporarily without editing `signer.json` — widen an allowlist
for a TTL (grants), or skip re-approval for a vouched-for command (approve-and-learn).
Both are widen-only and self-expiring; the file stays the source of truth.

### Added
- **Approve-and-learn — TTL'd approval waivers.** When a reviewer approves a
  `require_approval` command with `--learn`, the same command runs **without
  re-approval** for a TTL. Because `require_approval` is orthogonal to allow/deny, this
  is a new **`waive_approval`** grant dimension (suppress the approval gate for an
  already-allowed command), applied in `resolveCommandPolicy` after the allow check —
  so it only un-gates an allowed command, never widens allow/deny (no inversion risk;
  works on any host, incl. default-allow ones carrying a `require_approval` rule). The
  waiver is minted **signer-internally**: the control plane carries the learn intent on
  the approved sign and the signer mints a waiver scoped to the approved broker caller
  and OIDC end user, honoured only from a `trusted_forwarder` (like `approved`) — no new
  auth tier, a broker can neither self-approve nor self-learn. A waiver is bound to the
  exact command, **elevation** (`sudo`/`sudo_user`), caller, and end user that were
  approved — approving a non-sudo command never waives its root variant, and another
  subject still needs its own approval. Waivers appear in `policy grants` and are revoked
  like any grant; the TTL
  is clamped to `max_grant_ttl_seconds`; re-learning refreshes the single waiver (no
  duplicate accumulation) and expired ones are purged periodically; every mint is audited
  (`approval-waiver-created`) and linked to its approval id.

  ```bash
  broker-ctl approval allow <id> --learn --ttl 2h   # approve once, skip re-approval for 2h
  broker-ctl policy grants                          # shows waive-approval[^cmd$]
  broker-ctl policy revoke <grant-id>               # end it early
  ```

- **Runtime command-policy grants (dynamic widening overlay).** A grant temporarily
  **widens** an allowlist host without editing `signer.json` — a set of `allow`
  patterns that **expire on their own** after a TTL. Grants are the in-memory dynamic
  overlay on top of the durable file baseline, composed at decision time
  (`internal/signer/grants.go` `GrantStore` / `GrantProvider`, injected in
  `resolveCommandPolicy`). They **survive config reloads** and are dropped on a signer
  restart (TTL'd; fail-safe). New signer API (auth `reload_callers`, audited):
  - `POST /v1/policy/hosts/{host}/grants` — create `{ "allow":[...], "ttl_seconds":N, "caller":"", "end_user":"" }` → `201 { id, host, expires_at }`.
  - `GET /v1/policy/grants` — list active grants.
  - `DELETE /v1/policy/grants/{id}` — revoke.
  - `broker-ctl policy grant|grants|revoke` clients; optional `max_grant_ttl_seconds`
    config cap.

  ```bash
  broker-ctl policy grant  --host web01 --allow '^systemctl restart nginx$' --ttl 2h
  broker-ctl policy grants
  broker-ctl policy revoke <id>
  ```

  **Widen-only, enforced.** A grant carries only `allow` (never `deny` /
  `require_approval`) and is applied **only on a host that is already allowlist-active**
  — on a default-allow/denylist host it is refused (`409`), since injecting an allowlist
  there would invert the host to default-deny. `deny` still wins; creation is
  operator-only; the broker/agent can never create one.

## [v1.17.0] - 2026-06-19

Dynamic command-policy operations (Phase 0): manage the firewall without abandoning
the file as the source of truth — recommend changes from the audit, apply them with
a validated mutation API, and pick up edits automatically.

### Added
- **Validated policy mutation API on the signer.** `POST` / `DELETE
  /v1/policy/hosts/{host}/allow` add/remove a single command-policy allow regex
  for a host over mTLS, authorised by the existing `reload_callers` allowlist.
  Unlike a hand edit, the change is **validated by building the new state**
  (`CompileHostPolicies` + CA load) *before* it is persisted or applied: a bad
  regex, an unknown host, or a config that would not compile is rejected and
  nothing changes. On success the file is written **atomically** (temp+rename,
  preserving permissions, top-level keys and other hosts verbatim) and the
  in-memory policy is **swapped**, so disk and the running policy stay consistent;
  every attempt (changed / denied / failed) is recorded in the signed audit log.
  New `broker-ctl policy add|remove --host <h> --allow <regex>` client. This is the
  apply-side of `policy recommend` and the foundation for runtime grants.
- **Signer auto-reload (opt-in).** New `auto_reload_seconds` in `signer.json`: when
  > 0, the signer polls the config file's mtime and hot-reloads on change via the
  same validated, atomic, previous-state-preserving path as SIGHUP / `POST
  /v1/reload` (a half-written file mid-save is rejected and re-applied on the next
  tick). Dependency-free (mtime poll, no fsnotify). 0/absent = disabled. Removes
  the manual `broker-ctl reload` after a hand edit or a GitOps write.
- **`broker-ctl policy recommend`** — mines an audit log and prints advisory
  command-policy suggestions: **promote** (commands run or human-approved despite
  the current policy denying them — candidates for the allowlist), **dead-rule**
  (allow/deny patterns that never matched in the window — least-privilege cleanup),
  and **friction** (commands repeatedly denied). Read-only and advisory: it never
  changes policy. Attribution is by re-evaluation against the current compiled
  policy (`signer.PolicySet.Decide`), so it does not depend on the audit recording
  which rule matched. New `internal/policyrec`; `--audit <log>`, `--host`,
  `--since`, `--min-count`, `--json`.

## [v1.16.0] - 2026-06-19

Performance and maintainability pass (read-only audit of the hot-path packages,
then targeted fixes). No behaviour change to issuance, policy decisions, or the
wire protocol.

### Security
- **BehaviorTracker memory is now bounded (resource-exhaustion fix).** The
  control-plane anomaly/rate tracker kept per-subject state in maps that were
  only ever added to. A trusted forwarder rotating `end_user` values (subject =
  `<brokerCN>:<endUser>`), or any subject touching many distinct hosts/commands,
  could grow them without limit. The subject table is now capped
  (`max_subjects`, default 4096) with least-recently-seen + idle-TTL eviction
  (`subject_ttl_minutes`, default 1440), and each subject's host/command history
  is capped (`max_distinct_per_subject`, default 1024); once full, novelty
  detection for that dimension degrades to "seen" instead of growing or emitting
  unbounded approval escalations. New optional `behavior` config fields, all with
  sane defaults (`internal/control/behavior.go`).

### Changed
- **`CommandPolicy.Decide`/`decideOne` removed (single evaluator).** The request
  path has always evaluated through `PolicySet`; the parallel single-policy
  evaluator was test-only and had drifted (Spanish error strings vs the English
  `PolicySet` ones). It is deleted and its tests now run against `PolicySet{cp}`,
  leaving one source of truth for the AI-action firewall rule logic. The
  `command_policy` source (`internal/signer/cmdpolicy.go`) is also fully
  normalised to English.

### Performance
- **Parsed host keys are cached** (content-addressed by the authorized_keys
  line) instead of re-parsed per hop per request (`internal/broker/engine.go`).
- **`shellQuoteSession` rewritten** from O(n²) string concatenation to a single
  `strings.Builder` pass (`internal/broker/session.go`).
- **POSIX-shell parser pooled** (`sync.Pool`) and the AST printer hoisted out of
  the per-`CallExpr` loop in `extractCommands`; `buildConstraints` builds the
  cert KeyID with one `strings.Builder` instead of a slice + `Sprintf` + `Join`
  (byte-identical output, guarded by a test) (`internal/signer`).

### Fixed
- **Host-refresh goroutine lifecycle.** The remote-mode host-refresh goroutine
  had no stop channel and was not terminated by `Engine.Close()` (a leak in
  tests and repeated construction). It now exits on `Close`
  (`internal/broker/engine.go`).

## [v1.15.0] - 2026-06-19

### Added
- **`--version` on every binary.** All six commands (`signer`, `broker`,
  `control-plane`, `mcp-broker`, `mcp-broker-http`, `broker-ctl`) now print their
  build version and exit. Short, script-friendly form by default
  (`broker-ctl --version` → `v1.15.0`); detailed form with `--version --verbose`
  (Go toolchain, target os/arch, VCS revision and commit time). `broker-ctl` also
  gains the twin subcommand `broker-ctl version [--verbose]`. The infrastructure
  already existed (`internal/version` injected from the git tag by the Makefile);
  this wires it to the CLI. New `version.Print` and `version.Detailed` helpers.

### Changed
- **BREAKING — `broker-ctl --config` is now a global flag and must precede the
  subcommand.** Use `broker-ctl --config <f> host list` instead of
  `broker-ctl host list --config <f>`. The per-subcommand `--config` was removed
  from all subcommands (`host`, `ca-keys`, `callers`, `reload`, `policy explain`),
  so `--config` after the subcommand is now rejected. This aligns `broker-ctl`
  with the other five binaries, which already take `--config` at the top level.
  Scripts that passed `--config` after the subcommand must move it before it.

## [v1.14.0] - 2026-06-18

### Added
- **Composable command policies by group.** The AI-action firewall is no longer
  per-host only: a named policy library (`command_policies`) attaches N policies to
  a group (`group_command_policies: group → [names]`), and a host (with N groups)
  gets the **composition** of all its groups' policies plus its own inline
  `command_policy`. Composition is **additive**: deny wins (any denylist match
  blocks), allow is a **union** (if any contributing policy is an allowlist, the
  command must match the union of all of them), `require_approval` is a union, and
  `shell_parse` is OR. The reserved group `_default` applies to every host (global
  guardrail, mirroring `ca_keys` `_default`). New `internal/signer/policyset.go`
  (`PolicySet`) and `CompileHostPolicies` resolve + validate the composition at
  config load (a one-element set reproduces `CommandPolicy.Decide` exactly, so
  single-policy hosts are unchanged). Works in both the remote signer (`signer.json`)
  and the local single-binary broker (`config.json`). New
  `broker-ctl policy explain --config <f> --host <h> [--command <c>]` prints a host's
  composed policy and evaluates a command offline (no signing, no network). See
  `ARCHITECTURE.md` § AI-action firewall and the example configs.

## [v1.13.0] - 2026-06-16

Security hardening from an adversarial (red-team) review of authentication,
RBAC, privilege escalation, the command firewall, and audit integrity. Two
high-severity bypasses (command firewall via `role=bastion`; deny-all RBAC
collapsing to unrestricted on the wire) plus several medium/low fixes.

### Security
- **Command firewall could be bypassed by requesting `role=bastion`.** The
  AI-action firewall (`command_policy`) and the cert `force-command` were applied
  only for `role=target`, while `role` arrives unverified from the wire. A
  compromised broker could request `role=bastion` on a host that had both a
  `command_policy` and `allow_as_bastion`, obtaining a certificate with the
  host's real principal, **no force-command**, and `permit-port-forwarding` —
  i.e. an unrestricted credential that evades the allow/deny rules entirely,
  defeating the "one-shot policy survives a fully compromised broker" guarantee.
  `PolicyTable.Resolve` now rejects any non-`target` role on a host whose
  `command_policy` restricts, and `PolicyTable.Validate` rejects a host that sets
  both `allow_as_bastion` and a `command_policy` (the two are mutually
  exclusive — a bastion certificate carries no force-command). Defends both the
  remote signer and the broker's local mode.
- **Empty OIDC groups (deny-all) collapsed to unrestricted on the wire.** The
  OIDC verifier computes a non-nil empty `[]string{}` for an authenticated user
  with zero groups, so the signer denies every host (deny-all). But the
  broker→signer wire field used `json:",omitempty"`, which drops a length-0 slice
  entirely, so the request arrived with `end_user_groups == nil` — read by the
  signer as **unrestricted** (no per-user filter), the exact inverse of the
  intended decision. `WireRequest.EndUserGroups` no longer uses `omitempty`:
  `nil` (no end-user identity) round-trips to `nil`; `[]` (deny-all) round-trips
  to a non-nil empty slice.
- **`GET /v1/hosts` ignored per-host `allowed_callers`.** The host list applied
  only the group RBAC filter, so a broker CN excluded from a host via
  `allowed_callers` (but not group-restricted — the `callers` table is
  default-open) still received that host's `addr`/`user`/`host_key`/`jump`. The
  handler now also drops hosts whose `allowed_callers` excludes the caller,
  matching the `/v1/sign` authorization.
- **Approval requests hid sudo elevation from the human approver.** The pending
  request stores `sudo`/`sudo_user` and the issued certificate bakes the sudo
  prefix into its force-command, but `broker-ctl approval list` and the default
  `log` notifier did not display the elevation, so an approver could authorize a
  benign-looking command unaware it would run as root. Both now show
  `elevation=sudo:<user>` (the webhook already serialized the full request and
  the Teams card already rendered it).
- **Certificate KeyID accepted control characters in broker-supplied identity.**
  `end_user` and the resolved caller (`on_behalf_of` from a trusted forwarder)
  flowed verbatim into the cert KeyID, which sshd writes to its auth log; a
  newline let a compromised forwarder forge/splice lines in the host's
  `auth.log`. The signer now rejects control characters in `caller`/`end_user`.

### Fixed
- **Audit rotation is now verifiable end-to-end.** `broker-ctl audit verify`
  gains an `--all` flag that discovers the rotated segments (`<log>.<timestamp>`)
  plus the active file, verifies each, and checks the cross-file linkage
  (segment N's first `prev_hash` == SHA-256 of segment N-1's last line, earliest
  segment starts at genesis). Single-file verification accepted the first
  `prev_hash` as an unchecked seed, so dropping a whole rotated segment — or
  truncating the active file and restarting (which re-anchors to genesis) — was
  undetectable, contradicting THREAT_MODEL's rotation guarantee. `--all` detects
  both.
- **`broker-ctl host add --force` no longer wipes the whole `command_policy`.**
  A partial update that passed any one policy sub-flag rebuilt the entire policy
  object from flag defaults, so omitting `--policy-mode` silently downgraded the
  host to `mode:off` (firewall disabled, sessions re-enabled) with no warning.
  The policy is now merged field-by-field like every other host field: only the
  sub-fields whose flags were explicitly passed are overridden.
- **Session `shell`/`pty` per-command audit now records the elevation.** For an
  elevated shell/pty session the per-command `session_exec` entries recorded a
  blank elevation (the prefix lives in the shell process), understating
  privilege. The session now retains an `elevLabel` for all modes and emits it on
  every command.
- **`ssh_session_exec` checks ownership before mutating session state.** It
  marked a command in flight (`busy`/`lastUsed`) before the C1 ownership check,
  so a non-owner could refresh another caller's `lastUsed` and hold `busy>0` to
  keep the session from being reaped. Ownership is now verified under the lock
  before any mutation (new `sessionManager.checkoutOwned`).

### Changed
- **Local single-binary mode no longer marks every host as a bastion.**
  `policyFromHosts` hardcoded `allow_as_bastion=true` for every host, granting
  `permit-port-forwarding` on every cert and contradicting the documented
  default-deny bastion gate. A new `allow_as_bastion` field on the local
  `HostConfig` (default false) plus automatic enablement for hosts referenced as
  another host's `jump` target preserves existing jump chains while honoring the
  gate for leaf hosts.

## [v1.12.7] - 2026-06-13

Final batch from the logic-flaw review: the remaining low-severity findings,
plus a build-time version that can no longer go stale.

### Added
- **Build version is derived from the git tag.** New `internal/version` package
  whose value is injected via `-ldflags` from `git describe --tags`, with a
  fallback to the Go build info (module version or VCS revision) so a plain
  `go build` never reports an empty or hard-coded string. A new **`Makefile`**
  (`make build` / `make install`) wires the injection for every binary. The MCP
  server now announces this version to clients instead of the hard-coded
  `1.4.1` constant (removed).
- **OIDC clock-skew tolerance** (`oauth.clock_skew_seconds`, default 60s) for
  the HTTP frontend.

### Fixed
- **OIDC: `nbf` (not-before) is now enforced.** go-oidc validates `exp` but not
  `nbf`, so a token marked valid only from a future instant was accepted. The
  verifier now rejects not-yet-valid tokens and also rejects a token whose `iat`
  is in the future (which would read as a negative age and slip under the
  max-age bound). Both apply the configurable clock skew, avoiding spurious
  401s from minor IdP/host clock drift.
- **Shell sessions no longer drop a final unterminated output line.** When a
  command's last line lacked a trailing newline (e.g. `printf hello`), the shell
  wrote the end-of-output marker on the same line and `Exec` discarded the text
  before it, returning empty output. That text is now captured. A marker line
  with a non-numeric exit code now marks the session broken instead of silently
  reporting exit 0.
- **HTTP broker no longer maps every failure to 403.** `cmd/broker` now returns
  400 for a malformed request, 404 for an unknown host, 502 for an
  infrastructure failure (SSH dial/exec, or the signing service unreachable/5xx),
  and 403 only for an actual policy/authorization denial. Upstream (502)
  responses carry a generic message so internal addresses from dial errors are
  not leaked to the client (the full error is still audited). New error
  categories `broker.ErrBadRequest` / `ErrUnknownHost` / `ErrUpstream` and
  `signer.ErrSignerUnavailable` back the classification.
- **`broker-ctl reload` verifies the PID is the signer before SIGHUP.** A bare
  liveness check could SIGHUP a recycled PID belonging to an unrelated process;
  it now confirms the process command line looks like the signer and otherwise
  falls back to the authenticated HTTP reload (which targets the signer by URL).
- **Session recordings are size-capped** (`recording.DefaultMaxBytes`, 100 MiB,
  mirroring the audit-log rotation size). A long or abusive session can no
  longer fill the disk; the recording stops with a truncation note once the cap
  is reached.

## [v1.12.6] - 2026-06-13

Second batch from the logic-flaw review (v1.12.5 shipped the two signer
firewall bypasses). Fixes across sessions, the SSH layer, the control plane,
the audit chain, and `broker-ctl`/CA.

### Security
- **Behaviour guardrails key on the authenticated broker CN, not the
  client-supplied `end_user`.** The control plane keyed its rate limit and
  anomaly baselines on `end_user`, an unauthenticated JSON field, so a client
  could rotate it to get a fresh window / first-seen baseline on every request.
  New **`trusted_forwarders`** config (control-plane): only for CNs in that
  list does `end_user` qualify the subject (`<broker CN>:<end_user>`); every
  other CN is keyed on the broker CN alone. See [THREAT_MODEL.md](THREAT_MODEL.md)
  non-goal #2.
- **No self-approval.** The originator of an approval request can no longer
  approve or deny it (four-eyes), even if its CN is in `approval.callers`; the
  attempt is audited as `self-approval-rejected`.
- **Audit hash chain is continuous across rotation.** `maybeRotate` reset the
  chain to zero, so deleting or truncating a file at a rotation boundary was
  undetectable. The first entry of each rotated-to file now carries
  `prev_hash` = hash of the previous file's last line. `broker-ctl audit
  verify` treats a first-line `prev_hash` as the chain seed.

### Fixed
- **`broker-ctl audit verify --key` no longer reports false signature
  failures.** The CLI re-implemented the signed entry struct and was missing
  five signed fields (`policy_rule`, `dry_run`, `approval_id`, `approved_by`,
  `anomaly`), so any entry with one populated (denials, approvals, anomalies)
  verified as invalid. It now uses `internal/audit.Entry` directly; `show` /
  `tail` also render those fields.
- **`broker-ctl ca-keys add/remove` preserves all fields.** The command
  mirrored only 4 of the 7 `ca_keys` fields and re-serialised the whole map,
  silently dropping `key_version`, `tenant_id`, `client_id`, and
  `client_secret_env` from every entry (breaking AKV service-principal auth).
  It now edits only the touched entry as raw JSON.
- **Session reaper no longer kills a session with a command in flight.** The
  idle TTL (5 min) could fire under a longer exec (10 min cap), closing the
  connection mid-command. A busy counter protects in-flight sessions; the idle
  clock now counts from command completion.
- **Shell sessions fail fast after a desync.** After an exec timeout or output
  overflow, the per-session end-of-output marker was left in flight and the
  *next* exec returned the previous command's output and exit code (also
  corrupting the audit trail). Such a session is now marked broken and every
  later exec errors asking the caller to reopen it.
- **Output over the 10 MiB cap is truncated, not failed.** `limitedWriter` /
  `syncBuf` returned a short write at the cap, which aborted the SSH `io.Copy`
  with `ErrShortWrite` — erroring the command or stalling it until the 10-min
  timeout. They now consume all bytes, discard the overflow, and return the
  truncated output with a marker.
- **AKV signer pins the key version at startup.** With `key_version` empty it
  resolved "latest" on every `Sign` call; after a Key Vault rotation, certs
  were signed by the new version while the cached public key (and the cert's
  `SignatureKey`) was the old one, so sshd rejected them all. The version is
  now pinned from the KID returned at startup (rotation requires a signer
  reload/restart).
- **Intermediate ProxyJump hop dials are time-bounded.** Only the first hop had
  a dial timeout; a dead bastion could hang a connect indefinitely. Every hop's
  dial is now bounded by the request context plus a per-hop timeout, and the
  context is cancellable.
- **`broker-ctl host add --scan` honours the port** in `--addr` (passes
  `ssh-keyscan -p`) and handles IPv6 literals; it previously keyscanned port 22
  regardless, risking a wrong/hostile host key at onboarding.
- **`broker-ctl host add --force` preserves unspecified fields.** A `--force`
  update reset every field not given as a flag (sudo, groups, callers, TTL) to
  defaults; it now starts from the existing entry and overrides only the flags
  explicitly set.
- **Per-session goroutine leak removed.** `shellReader` blocked forever on its
  channel after a session closed; it now exits on a done signal.
- **Reaper close/audit moved outside the session-manager lock**, so a slow disk
  or a hung connection close no longer stalls all other session operations.

### Added
- Control-plane config field **`trusted_forwarders`** (list of broker CNs);
  documented in `control-plane.example.json`.

## [v1.12.5] - 2026-06-13

### Security
- **Signer: two command-firewall bypasses closed (found in a logic-flaw
  review).** Both are in `PolicyTable.Resolve` / `CommandPolicy.Decide`, the
  authoritative AI-action firewall:
  - **Unknown `role`/`purpose` no longer skip the firewall.** Command-policy
    evaluation is gated on `role == target` and the `force-command` is baked
    only for `purpose == oneshot`; both values arrive from the wire and were
    never validated. A caller authorised for a host with a `command_policy`
    could send `role: "x"` (or `purpose: ""`) and receive a certificate for
    the target with **no force-command and no policy check** — a full
    interactive shell. `Resolve` now rejects any role/purpose outside the
    known set (default-deny).
  - **`require_approval` is no longer dropped on chained commands.** With
    `shell_parse`, `Decide` overwrote `needsApproval` on each command of a
    chain instead of accumulating it, so `systemctl restart nginx && systemctl
    status nginx` issued the cert **without** the human approval the first
    command required. It now OR-accumulates approval across the chain and keeps
    the matched rule for the audit trail.

  Regression tests added for both.

## [v1.12.4] - 2026-06-10

### Changed
- **README trimmed to a landing page (862 → 203 lines).** After the v1.12.1
  documentation split, the README duplicated ARCHITECTURE.md, OPERATIONS.md, and
  THREAT_MODEL.md almost in full (sudo/sudoers, `broker-ctl` flag table, hot
  reload, auth diagrams, the AI-action firewall, approval/behaviour, etc.),
  which was already drifting. The README is now an orientation page: pitch,
  frontends, documentation index, "why", a one-screen "how it works", a feature
  overview table linking to the canonical docs, the competitive comparison
  (kept in full), a quickstart, the API summary, and security/testing/license
  pointers. Removed the stale `Security (v1.4.1)` table and the duplicate
  `Production roadmap` (single-sourced in THREAT_MODEL.md / HANDOFF.md).
- Repointed the two inbound links that referenced now-removed README sections
  (USAGE.md → OPERATIONS.md §4 and ARCHITECTURE.md § AI-action firewall).

Documentation only; no code changes.

## [v1.12.3] - 2026-06-10

### Security
- **Dependency & toolchain CVE fixes (found by the new govulncheck CI job).**
  Bumped `golang.org/x/net` v0.54.0 → v0.55.0 (3 vulnerabilities, incl. an idna
  issue reached via `signer.Remote.FetchHosts`) and the Go directive 1.26.3 →
  1.26.4 (two standard-library vulnerabilities in `net/textproto` and
  `crypto/x509`). `govulncheck ./...` now reports no vulnerabilities.
- **Signer validates `signer.json` on load and reload.** New
  `PolicyTable.Validate()` / `CommandPolicy.Validate()` compile every
  command-policy regex, reject unknown modes, and check that every `jump` target
  is a defined host. An invalid config is now rejected up front (preserving the
  previous good state) instead of silently breaking a host on its next request.

### Added
- **CI quality gates** (`.github/workflows/go.yml`): `gofmt -l` check, `go vet`,
  `go test -race`, and a `govulncheck` job — mirroring the CODING_STYLE /
  CONTRIBUTING pre-commit checklist that was previously manual-only. Pinned to
  Go 1.26.4.
- **Graceful shutdown** (`internal/httpserve.RunTLS`): the signer, control-plane,
  broker, and HTTP MCP frontend now drain in-flight requests on SIGINT/SIGTERM
  via `http.Server.Shutdown`, so the deferred audit-log close/flush actually
  runs (it did not when exiting through `log.Fatal` on a raw `ListenAndServeTLS`).
- **`LICENSE`** — proprietary, all-rights-reserved notice.

### Changed
- **Docs:** THREAT_MODEL.md gains two explicit non-goals — secrets logged
  verbatim in audit logs/recordings (no redaction) and audit-write fail-open.
  OPERATIONS.md gains a key/certificate rotation runbook (SSH CA via
  `TrustedUserCAKeys` two-CA transition; mTLS CA/leaf rotation).

## [v1.12.2] - 2026-06-10

### Changed
- **`make_presentation.py` brought up to date (v1.12.1 content).** Cover and
  roadmap version refreshed (`v1.11.0` → `v1.12.1`); portable output path
  (writes next to the script via `__file__` instead of a hard-coded
  `/home/luislgf/...`); slide-header comments renumbered sequentially (1–34,
  dropping stale `(was N)` / `(NEW — X)` annotations and duplicate numbers);
  dead numeric argument removed from every `slide_number()` call.
- Added two slides: **Hardening — fail-closed by default** (v1.11.2 / v1.12.0:
  fail-closed OIDC groups/iat, signer-level newline rejection, host list scoped
  to the user's OIDC groups, bounded approval state, uniform DoS limits) and
  **Security limits — what we don't claim** (the threat model's explicit
  non-goals: sessions without a command firewall, behaviour as detection not
  containment, no KRL, default-open `callers`).

## [v1.12.1] - 2026-06-10

### Changed
- **Documentation split — `HANDOFF.md` broken up by topic/reader.** The 1,100-line
  HANDOFF (architecture + design decisions + runbook + PKI + pending + versioning
  + test plan, with the design decisions numbered out of order) is now:
  - **`ARCHITECTURE.md`** (new, EN) — diagram, request flow, design decisions
    renumbered and regrouped by theme, sudo elevation mechanism.
  - **`OPERATIONS.md`** (new, EN) — runbook: startup, adding hosts, hot-reload,
    `broker-ctl`, PKI inventory, reference configs.
  - **`CONTRIBUTING.md`** (new, EN) — branches, `X.Y.Z` versioning, the mandatory
    pre-commit living-docs checklist, language rule.
  - **`HANDOFF.md`** (reduced to ~145 lines, ES) — current state, file tree,
    pending work, test-plan snapshot, resume notes, and a documentation index.
- **`CODING_STYLE.md`** — language table corrected (`CHANGELOG.md` is English
  since v1.9.3; new `*.md` docs are English; `HANDOFF.md` stays Spanish); the
  checklist now points to `CONTRIBUTING.md` for the workflow.
- **`README.md`** — added a Documentation index linking the new files.

### Added
- **`THREAT_MODEL.md`** (new, EN) — assets, actors/trust levels, trust boundaries
  and guarantees, and an explicit non-goals/gaps section (sessions without a
  command firewall, broker-asserted behavior subject, no KRL, no signer rate
  limit, in-memory single-instance state, default-open `callers`, CA custody).
- **`SECURITY.md`** (new, EN) — supported versions, private vulnerability
  reporting, scope (links to the threat model), secret-handling notes.

Documentation only; no code changes.

## [v1.12.0] - 2026-06-09

### Added
- **`ssh_list_servers` filtered by the end user's OIDC groups.** The host
  list was served from the broker's cache (fetched with its own CN), so a
  group-restricted user saw every host even though the signer would deny
  signing on most of them. `GET /v1/hosts` now includes each host's RBAC
  `groups` (labels, not secrets), and `Engine.ServerInfos(caller)` filters
  by group intersection when the caller carries groups. Nil groups
  (stdio/mTLS) = full list (compatible); empty groups = no hosts.

### Fixed
- **`cmd/broker` hardening (A1/A2).** The HTTP+mTLS one-shot frontend was
  missed by the v1.4.1 pass: `http.Server` now sets
  `ReadTimeout`/`IdleTimeout` (no `WriteTimeout` — the response waits for
  the remote command) and `/v1/ssh_run` limits the request body to 64 KiB.
- **Approval registry memory growth.** `control.Registry` never deleted
  entries; expired/denied/consumed approvals accumulated for the lifetime
  of the control plane. Entries are now purged 2×TTL after creation
  (opportunistically on `Create`/`List`); a purged id answers 404 on later
  polls instead of 408/410.
- **gofmt drift** in `cmd/broker-ctl` and `internal/ssh/shell.go` (no
  behavior change).

## [v1.11.2] - 2026-06-09

### Security
- **OIDC per-user RBAC is now fail-closed.** With `groups_claim` configured,
  a token *without* the claim is rejected (401) instead of being accepted
  with no group restriction. Previously a claim-name typo, or an IdP that
  stopped emitting the claim, silently disabled per-user RBAC for every
  user (`EndUserGroups` nil = unrestricted in the signer). An explicitly
  empty groups list is still propagated as-is (denies every host).
  (`internal/oauth/verifier.go`)
- **`iat` claim required when `max_token_age_seconds > 0`.** A token without
  a numeric `iat` was previously exempted from the max-age check (fail-open);
  it is now rejected, since its age cannot be established.
  (`internal/oauth/verifier.go`)
- **Newlines rejected in one-shot commands at the signer.** A command
  containing `\n`/`\r` could smuggle extra command lines past regex command
  policies without `shell_parse` (an allowlist `^ps` also matches
  `"ps\nrm -rf /"`, and the remote shell executes both lines of the
  force-command). `PolicyTable.Resolve` now rejects such commands
  authoritatively on every host (local and remote mode); compose with `;`
  or `&&` instead. This also makes the long-documented API.md constraint
  real. (`internal/signer/signer.go`)

### Fixed
- **Documentation coherence pass (API.md, USAGE.md, HANDOFF.md).**
  `ssh_list_servers` no longer documents `addr`/`user` fields it never
  returned; `ssh_session_open` returns `serial` (not `elevation_prefix`);
  `ssh_execute` documents `dry_run`; the 403 cause "TTL cap exceeded"
  removed (TTL is clamped, not rejected); session newline restriction
  scoped to `shell`/`pty`; USAGE examples updated to the English tool
  output (v1.9.3) and a multi-line heredoc example that the broker itself
  would reject replaced; HANDOFF duplicated architecture diagram block and
  stale "signer requires restart to reload" note fixed.

## [v1.11.1] - 2026-06-09

### Fixed
- **`cmd/broker-ctl`: critical `command_policy` silent erasure bug.**
  `host add --force` and `host remove` silently deleted `command_policy` from
  existing hosts because `hostEntry` lacked the field. Fixed by adding
  `CommandPolicy json.RawMessage \`json:"command_policy,omitempty"\`` to
  `hostEntry`, which preserves the raw JSON verbatim through any round-trip
  without broker-ctl needing to understand the internal policy structure.
  When `--force` is used without any policy flag, the existing `CommandPolicy`
  is copied to the updated entry. When policy flags are explicitly set, a new
  `CommandPolicy` is built from them (replacing the old one).

### Added
- **`broker-ctl host add`: command policy flags.**
  New flags: `--policy-mode` (allowlist|denylist|off), `--allow`,
  `--deny`, `--require-approval`, `--shell-parse`. Internally uses
  `buildCommandPolicyJSON` and `commandPolicyLabel` helpers.

- **`broker-ctl host list`: additional columns.**
  The table now shows `JUMP`, `SRC_ADDR`, `SUDO_USERS`, `CALLERS`, and
  `POLICY` (a short label such as `allowlist(2)` or `denylist(1)` derived
  from `command_policy`). The `—` placeholder is used for empty/absent fields.

- **`broker-ctl ca-keys add/list/remove`:** new subcommand group to manage
  the `ca_keys` map in `signer.json`.
  - `add --name <n> --type pem --path <f>` — adds a PEM-backed entry.
  - `add --name <n> --type akv --vault-url <u> --key-name <k>` — adds an AKV entry.
  - `list` — tabular view (NAME / TYPE / DETAIL).
  - `remove <name>` — removes an entry.
  All operations preserve all other fields in `signer.json` (atomic write
  via `.tmp` rename).

- **`broker-ctl callers add/list/remove`:** new subcommand group to manage
  the top-level `callers` RBAC table in `signer.json`.
  - `add --name <cn> --groups <g1,g2>` — adds or updates a caller entry.
  - `list` — tabular view (NAME / ALLOWED_GROUPS).
  - `remove <cn>` — removes a caller entry.

- **`writeRaw` internal helper**: shared atomic JSON write used by
  `writeHosts`, `writeCAKeys`, and `writeCallers`.

### Changed
- **`cmd/broker-ctl`: `action` variable logic corrected.** The "added" vs
  "updated" detection in `host add` now checks existence *before* the map
  assignment instead of after (the previous code always reported "updated"
  when `--force` was used).

### Tests
- `cmd/broker-ctl`: 29 cases (up from 13). New tests added with `t.Parallel()`:
  `TestCommandPolicyLabel`, `TestBuildCommandPolicyJSON*`, `TestExtractCAKeys*`,
  `TestCAKeysRoundTrip`, `TestCAKeysRemoveRoundTrip`, `TestExtractCallers*`,
  `TestCallersRoundTrip`, `TestCallersEmptyGroupsSerialisedAsArray`,
  `TestCommandPolicyPreservedOnForce`, `TestCommandPolicyErasedWhenPolicyFlagsSet`,
  `TestCommandPolicyNilWhenHostHasNone`.
- Total test count: **185** (up from 170).

## [v1.11.0] - 2026-06-09

### Added
- **Multi-CA support + Azure Key Vault (AKV) backend for CA keys.**
  The CA signing key is no longer limited to a local PEM file; any group of
  hosts can now use a dedicated CA key, and each key can be stored in Azure
  Key Vault (private key never leaves AKV).

  #### New config field `ca_keys` (signer.json and config.json)
  ```json
  "ca_keys": {
    "_default": { "type": "akv", "vault_url": "https://vault.azure.net", "key_name": "ssh-ca" },
    "prod-web":  { "type": "akv", "vault_url": "https://vault.azure.net", "key_name": "ssh-ca-web" },
    "databases": { "type": "pem", "path": "pki/db_ca" }
  }
  ```
  - `"_default"` overrides the legacy `ca_key` string when present.
  - All other keys map group names to their CA. The first group in a host's
    `groups` field that has an entry in `ca_keys` wins; other hosts fall back
    to the default CA. Backward compatible: existing `ca_key` string configs
    require no changes.
  - Supported types: `"pem"` (local PEM file; emits a warning) and `"akv"`
    (Azure Key Vault — RSA 2048/3072/4096 and EC P-256/P-384/P-521; Ed25519
    is not supported by AKV).
  - A 30-second startup timeout covers all AKV `GetKey` calls.
  - `ca_keys` participates in hot-reload (SIGHUP / `POST /v1/reload`).

  #### New packages / files
  - **`internal/ca/loader.go`** — `CAKeyConfig` struct, `LoadCA(ctx, cfg)`,
    `LoadGroupCAs(ctx, caKey, caKeys)` (shared helper used by both
    `cmd/signer` and `internal/broker`).
  - **`internal/ca/akv.go`** — `akvSigner` (`crypto.Signer` backed by AKV);
    `akvKeyOps` interface (enables mock-based unit tests without a real vault);
    `rawECSignatureToDER` converter (AKV returns raw R‖S, SSH needs DER);
    `parseAKVPublicKey` (JWK → Go crypto key).
  - **`internal/ca/loader_test.go`** — unit tests for `LoadCA` / `LoadGroupCAs`.
  - **`internal/ca/akv_test.go`** — full mock-based unit tests: EC P-256,
    RSA-2048, DER conversion, algorithm selection, end-to-end `BuildAndSign`.

  #### Modified files
  - **`internal/ca/sign.go`** — `BuildAndSign` accepts `ctx context.Context`
    as first parameter; context cancellation is checked before signing.
  - **`internal/signer/signer.go`** — `Local` gains `groupCAs` map and
    `caKeyFor(hp)` (first-match group selection). `NewLocalWithGroupCAs`
    constructor added. `SignIntent` selects the correct CA per host.
  - **`cmd/signer/main.go`** — `Config.CAKeys`; `buildState` uses
    `ca.LoadGroupCAs` and `signer.NewLocalWithGroupCAs`.
  - **`internal/broker/engine.go`** — `Config.CAKeys`; `HostConfig.Groups`
    (propagated to `signer.HostPolicy`); `buildSigner` uses `ca.LoadGroupCAs`
    and `signer.NewLocalWithGroupCAs`.
  - **`signer.example.json`** / **`config.example.json`** — documented
    `ca_keys` block with PEM and AKV examples; `groups` field added to
    example hosts in `config.example.json`.

  #### Azure Key Vault notes
  - Authentication: `DefaultAzureCredential` by default (managed identity,
    workload identity, `AZURE_*` env vars, Azure CLI). Override with
    `tenant_id` + `client_id` + `client_secret_env` in `CAKeyConfig`.
  - AKV EC signatures arrive as raw R‖S bytes; `akvSigner` converts to DER
    before returning from `crypto.Signer.Sign`.
  - Recommended key type: EC P-256 (`P-256` curve, 256-bit security). RSA
    3072 is also supported for compliance environments.
  - Ed25519 is NOT supported by AKV; use `"pem"` for Ed25519 CA keys.

## [v1.10.0] - 2026-06-09

### Added
- **Session recording in ASCIIcast v2 format.** When `session_recording_dir` is
  set in `config.json`, `shell` and `pty` sessions are recorded to `.cast` files
  in that directory. One file per session: `<session_id>.cast`.

  - **`internal/recording/recorder.go`** — new `Recorder` type (thread-safe).
    Writes ASCIIcast v2 JSONL: a header with session metadata (`session_id`,
    `caller`, `host`, `serial`, `started_at`) plus event lines
    `[delta, type, data]` where type is `"i"` (stdin), `"o"` (stdout/PTY),
    or `"e"` (stderr). Deltas in seconds from session start.
  - **Stdin captured** (`"i"` events): the command typed by the agent is
    recorded before being written to the shell's stdin channel.
  - **Stdout/PTY captured** (`"o"` events): each output line is teed to the
    recorder inside `ShellSession.Exec()`.
  - **Stderr captured** (`"e"` events, non-PTY mode only): the `syncBuf` stderr
    drain tees bytes to the recorder as they arrive.
  - File naming correlates directly with the broker audit log: the `session_id`
    field in `session_open`/`session_exec`/`session_close` audit entries matches
    the `.cast` filename, making the audit log the search index.
  - Files are written with `0o600` permissions (owner-read only).
  - `internal/recording/recorder_test.go` — 8 test cases: header fields,
    event types, delta monotonicity, concurrent writes, empty-data skipping,
    idempotent close, write-after-close no-op, default dimensions.

- **`session_recording_dir` config field** in `broker.Config`
  (JSON: `session_recording_dir`). Empty or absent = recording disabled.

### Changed
- `internal/ssh/shell.go`: `ShellSession` and `syncBuf` gain an optional
  `recorder *recording.Recorder` field; new `SetRecorder()` method propagates
  it to both stdout and stderr tee points.
- `internal/broker/session.go`: `liveSession` gains `recorder` field; recorder
  is opened in `OpenSession` (when configured), closed in `CloseSession` and the
  session reaper.
- `config.example.json`: documents `session_recording_dir`.
- `USAGE.md`: new §8 "Session recording" with setup, file format, playback, and
  storage management.
- `API.md`: session recording note added to the persistent sessions section.
- `HANDOFF.md`: recording marked as implemented; design decision #18 added.

## [v1.9.3] - 2026-06-09

### Changed
- All Go source comments, error messages, flag descriptions, and user-visible
  strings translated from Spanish to English across all packages and binaries
  (internal/, cmd/, lab/). No behaviour change.
- `signer.sh` echo strings and inline comments translated to English.
- `_comment` fields in all example JSON config files translated to English.
- `CODING_STYLE.md` section 10 updated: English is now required for all Go
  comments (including legacy code); the previous "do not change on refactors"
  exception is removed.

## [v1.9.2] - 2026-06-09

### Added
- **`shell_parse` field in `CommandPolicy`** — when `shell_parse: true`, the command is
  parsed as POSIX sh via `mvdan.cc/sh/v3/syntax` before regex evaluation. Each simple
  command in a pipeline or sequence (`&&`, `||`, `;`, `|`) is evaluated independently
  against the policy, preventing bypasses such as `ps aux && kill -9 1000` from passing
  an allowlist that only covers `ps`.

  Dangerous AST nodes are rejected unconditionally regardless of configured rules:
  `CmdSubst` (`$(...)`) , `ProcSubst` (`<(...)`), `ArithmCmd` (`$((...))`) and file
  redirects (`>`, `>>`, `<`). fd-to-fd redirections (`2>&1`) are allowed.

  Backward compatible: `shell_parse` defaults to `false`, preserving existing behavior
  for all operators that do not explicitly enable it.

- **`mvdan.cc/sh/v3 v3.13.1`** added as a direct dependency.

### Changed
- `API.md` — `command_policy` field description updated to document `shell_parse`.
- `signer.example.json` — `web02` example updated with `shell_parse: true`.
- `HANDOFF.md` — design decision #17 updated with implementation details and reference
  configuration patterns.

## [v1.8.0] - 2026-06-08

### Added
- **Microsoft Teams notifier (`notifier: "teams"`).** The control plane can now send
  approval-required notifications to a Microsoft Teams channel via an Incoming Webhook
  (Power Automate Workflow) or a legacy M365 Connector, formatted as a rich card
  instead of raw JSON.

  - **`internal/control/teams.go`** — `TeamsNotifier` implementing the existing `Notifier`
    interface. Two payload formats supported and configurable:
    - `"workflow"` / `"adaptivecard"` (default, recommended): Adaptive Card v1.4 wrapped
      in the Power Automate Workflow message envelope (`{"type":"message","attachments":[...]}`).
      Compatible with the "When a Teams webhook request is received" trigger.
    - `"messagecard"` (legacy): MessageCard format for tenants still using the M365
      Connectors classic mechanism (Microsoft is retiring this format).
  - Both formats include a `FactSet` / `facts` section with: approval ID, status,
    created timestamp, host, command, caller (broker CN), end user (if present),
    elevation target (if sudo), and policy rule (if matched).
  - **`approval_url_template`** — new optional config field. When set (e.g.
    `"https://approvals.example.com/requests/{id}"`), a "View request" button
    (`Action.OpenUrl` / `OpenUri`) is added to the card. Designed as a forward-compatible
    hook for the Phase 2 approval bridge (`cmd/approval-bridge`, not yet implemented).
    Leave empty until the bridge is deployed.
  - The card **never** contains the ephemeral public key or any `WireRequest`
    internal field (the `req` field of `Approval` is unexported and excluded from
    serialization by design).
  - `NewTeamsNotifier(url, format, approvalURLTemplate string)` — constructor; empty
    `format` defaults to `"workflow"`.

- **Config fields in `approval` block** (`control-plane.json`):
  - `"notifier": "teams"` — selects the Teams notifier (reuses `webhook_url` as target).
  - `"teams_format": "workflow"` — card format (`"workflow"` default, `"messagecard"` legacy).
  - `"approval_url_template": ""` — optional URL with `{id}` placeholder.

- **`internal/control/teams_test.go`** — 18 test cases covering both card formats,
  fact presence (host/command/caller/end-user/elevation/rule), approval URL template
  (substitution, presence/absence of action buttons per format), security (no pubkey
  leak), HTTP error handling (4xx/5xx), and minimal approval (no optional fields).

- **Design document — Phase 2 approval bridge (HANDOFF.md, design decision #15):**
  records the architecture for future bidirectional Teams approval (bot + bridge
  pattern), multi-notifier config (`notifiers: [...]`), multi-channel approval
  (`approval_channels: [...]`), and trade-off analysis (Options A/B/C).

### Changed
- `cmd/control-plane/main.go`: `Config.Approval` struct gains `TeamsFormat` and
  `ApprovalURLTemplate` fields; notifier selection is now a `switch` statement
  (extensible) instead of a single `if`.
- `control-plane.example.json`: `_approval_comment` updated to document `"teams"`,
  `teams_format`, and `approval_url_template`; new fields added with empty defaults.
- `API.md`: new section *"Outbound Notifications — Notifier contracts"* documenting
  the payload format for all notifiers, the Adaptive Card and MessageCard schemas,
  the fact table, the `approval_url_template` field, and the security guarantee.

### Added (test coverage)
- **Test suite — high-priority coverage (3 new test files, 47 new test cases).**

  **`internal/audit/log_test.go`** — first direct tests for the cryptographic audit chain (previously untested despite being the most security-critical component):
  - `Append`: sequential `Seq` increment, correct `PrevHash` chaining (SHA-256 of previous raw line), valid Ed25519 signature per entry, signature invalidation after field tampering.
  - `restoreChain`: new path (seq=0, prevHash=""), empty file, chain continuity across process restart (3 entries → close → reopen → 2 more entries → intact 5-entry chain), error on malformed last line.
  - `maybeRotate`: rotation fires when `maxFileSize=1`, rotated file exists, new log restarts at Seq=1/PrevHash=""; rotation disabled when `maxFileSize=0`.
  - `Close`: no error on normal close.

  **`internal/broker/session_test.go`** — first direct tests for session management and the two security fixes applied in v1.4.1:
  - `sessionManager`: add/get/remove happy paths, `get` updates `lastUsed`, missing-ID behaviour, global limit (`maxSessionsGlobal=200`), per-caller limit (`maxSessionsPerCaller=20`), reaper evicts idle sessions and fires `onReap`.
  - **C1 (ownership enforcement):** `SessionExec` and `CloseSession` reject callers that do not own the session; session is not deleted on unauthorized close.
  - **M5 (newline injection):** `SessionExec` rejects commands containing `\n`/`\r` in `shell` and `pty` modes; `exec` mode is unaffected.
  - Internal helpers: `buildElevatedExecCommand`, `shellQuoteSession` (including single-quote escaping), `elevationLabelFromPrefix`, `newSessionID` uniqueness.

  **`cmd/broker-ctl/main_test.go`** — first tests for the CLI verification logic and utility helpers:
  - `verifyLog`: intact chain passes without `--key`; intact chain + correct signatures pass with `--key`; wrong key detects invalid signatures; seq gap detected; wrong `prev_hash` detected; tampered field (Caller altered post-signing) detected; empty log passes cleanly.
  - `lastNLines`: ring buffer returns last N lines; requests larger than total return all; missing file errors correctly.
  - `parseAuditTime`: RFC3339 and `YYYY-MM-DD` accepted; invalid formats rejected.
  - `splitComma`, `boolStr`, `auditDetail`: all branches covered.

## [v1.7.0] - 2026-06-08

### Added
- **Behavioral guardrails + rate limiting (Phase C).** The control plane now tracks each agent's behavior and flags deviations — statistical/rule-based, no ML:
  - **Anomalies:** request-rate spike, a host the agent has never used before, and a command outside its history (fingerprint = first token). The first request for a subject establishes the baseline (not flagged).
  - **Subject:** the end-user OIDC identity when present, otherwise the broker CN.
  - **Modes** (`behavior.mode` in `control-plane.json`): `off` (default) · `observe` (audits anomalies, never blocks) · `enforce` (anomalies escalate to human approval — reusing Phase B; rate-limit excess is denied with `429`).
  - **Rate limiting per subject** (`behavior.rate_limit_per_min`) falls out of the same tracker.
  - Implemented in `internal/control/behavior.go` (`BehaviorTracker`); wired into the control plane `/v1/sign` handler before forwarding.
- Audit (control plane): new `anomaly` field; new outcomes `anomaly` (observe) and `rate-limited` (enforce). Behavior escalations are audited as `approval-required` with `policy_rule="behavior"` and the anomaly list.
- `control-plane.example.json` documents the `behavior` block.

### Changed
- Control plane `/v1/sign`: dry-run requests now bypass the behavior gate and rate limit (they execute nothing). `requireApproval` is now a shared helper used by both command-policy and behavior escalations.

## [v1.6.0] - 2026-06-06

### Added
- **Control plane (`cmd/control-plane`) — human-in-the-loop approval (Phase B).** A new service sits between the broker and the signer (`broker → control-plane → signer`), enforcing approval of commands the command policy marks `require_approval`, **without holding the CA key** (zero-trust PEP/PDP split). Flow is asynchronous (no held connections):
  1. Broker `POST /v1/sign` → control plane forwards to the signer.
  2. If the command needs approval, the signer returns no certificate; the control plane creates a request, notifies out-of-band, and responds `202 {approval_id}`.
  3. Broker polls `GET /v1/sign/result/{id}`.
  4. A human approves via `broker-ctl approval allow <id>` → `POST /v1/approvals/{id}`.
  5. The next poll re-signs with `approved=true` and returns the certificate. One approval mints exactly one certificate.
- **Approval is unavoidable.** The signer enforces the gate: a `require_approval` command is not issued unless `approved=true`, and `approved` (like `on_behalf_of`) is honoured **only from `trusted_forwarders`** (the control plane's CN). A broker going direct to the signer cannot self-approve.
- **Identity propagation + CN pinning.** `signer.json` gains `trusted_forwarders`. The control plane forwards the broker's identity via `on_behalf_of` (body, `/v1/sign`) and `X-On-Behalf-Of` (header, `/v1/hosts`); the signer honours it only from trusted forwarders, preserving per-broker RBAC through the proxy.
- **Notifiers:** `log` (default; pair with `broker-ctl approval list`) and `webhook` (POST JSON, Slack-compatible).
- `broker-ctl approval list|allow|deny` subcommands (mTLS to the control plane).
- Broker config `signer.approval_wait_seconds`: how long the broker waits on a `202` before giving up.
- Audit (control plane, own chained log): outcomes `forwarded`, `approval-required`, `approval-granted`, `approval-denied`, `approval-timeout`, `approval-decision-allow`; new entry fields `approval_id`, `approved_by`.
- New `control-plane.example.json`; `signer.example.json` documents `trusted_forwarders`; `config.example.json` shows pointing the broker at the control plane with `approval_wait_seconds`.

### Changed
- `signer.Remote` now handles a `202` response by polling the approval result; `Remote.FetchHosts` takes an `onBehalfOf` argument (broker passes `""`).
- `WireRequest` gains `dry_run` (Phase A), `on_behalf_of`, and `approved` fields; `Issued`/`WireResponse` may carry no certificate when approval is pending.

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
- `HANDOFF.md`: added mandatory `USAGE.md` update rule (step 4 in "Mandatory pre-commit checklist") — must be updated when a tool is added, removed, renamed, or its parameters/behaviour change.

## [v1.4.4] - 2026-06-05

### Added
- `API.md`: new dedicated API reference document covering all HTTP endpoints across all three services — signer (`POST /v1/sign`, `GET /v1/hosts`, `POST /v1/reload`), broker HTTP (`POST /v1/ssh_run`), and MCP HTTP (`GET /.well-known/oauth-protected-resource` + Streamable HTTP tools). Each endpoint documents auth requirements, request/response schemas, error codes, and audit outcomes. Includes audit log field reference, outcome value table, `jq` correlation examples, and Ed25519 chain integrity description.
- `README.md`: `## API Reference` section replaced with a summary table + link to `API.md`.
- `HANDOFF.md`: added mandatory `API.md` update rule (step 3 in pre-commit checklist) and English language rule for all new commit messages, documentation files, and code comments.

### Changed
- `README.md`: full rewrite in English. All sections translated; reorganized to match current feature set (v1.4.3).

## [v1.4.3] - 2026-06-05

### Added
- `README.md`: section `## Client-to-broker authentication` with a comparison table of the three frontends, step-by-step OAuth2/OIDC flow, and identity propagation diagram to the signer.
- `README.md`: section `## Broker-to-SSH-server authentication` with diagrams of ephemeral key-pair generation, certificate signing by the signer (cert fields: principal, TTL, source-address, force-command, permit-pty), SSH handshake with pinned host key verification, sshd checks, and ProxyJump flow with independent cert per hop.

### Fixed
- `README.md`: added missing `## Testing` header above the lab bash block.

## [v1.4.2] - 2026-06-05

### Added
- `README.md`: section "Registering the MCP in OpenCode" with the correct config for `~/.config/opencode/opencode.json` (`type: "local"`, `command` as array).

## [v1.4.1] - 2026-06-05

### Security
- **C1 (critical)** `internal/broker/session.go`: `SessionExec` and `CloseSession` verify that the caller owns the session before operating; `CloseSession` performs get-before-delete to avoid removing sessions owned by other callers.
- **A1 (high)** `cmd/signer/main.go`, `cmd/mcp-broker-http/main.go`: `ReadTimeout`, `WriteTimeout` (signer only), `IdleTimeout` on `http.Server`.
- **A2 (high)** `cmd/signer/main.go`, `internal/signer/remote.go`: `http.MaxBytesReader(64 KiB)` on `/v1/sign`; `io.LimitReader(1 MiB)` on both `io.ReadAll` calls in `remote.go`.
- **A3 (high)** `internal/ssh/run.go`, `internal/ssh/shell.go`: `defaultExecTimeout=10 min`; `maxOutputBytes=10 MiB`; `limitedWriter`; `session.Signal(SIGTERM)` on timeout; shell/pty silently discards excess bytes.
- **A4 (high)** `internal/audit/log.go`: `restoreChain()` with `bufio.Scanner` (256 KiB buffer) restores `seq`+`prevHash` from the last record on restart; without this fix the broker broke the audit chain on every restart.
- **M1 (medium)** `internal/broker/engine.go`, `cmd/signer/main.go`: `auditLog.Append` errors are no longer silenced with `_ =`; logged via `log.Printf`.
- **M2 (medium)** `internal/broker/session.go`: `maxSessionsGlobal=200`, `maxSessionsPerCaller=20`; `sessionManager.add()` returns `error`.
- **M3 (medium)** `internal/oauth/verifier.go`, `internal/broker/engine.go`, `cmd/mcp-broker-http/main.go`: `MaxTokenAge` field in `Config`/`Verifier`; validates the `iat` claim when `maxTokenAge > 0`; `OAuthConfig.MaxTokenAgeSeconds` (recommended: 3600).
- **M5 (medium)** `internal/broker/session.go`: `SessionExec` rejects commands containing `\n` or `\r`.
- **L1 (low)** `internal/ca/sign.go`: `LoadCAFromPEM` emits a `[WARN]` at runtime indicating lab-only use.
- **L2 (low)** `internal/audit/log.go`: `maybeRotate()` rotates the audit file when it exceeds 100 MiB, renaming to `<path>.20060102T150405Z`.
- **L4 (low)** `internal/mcpserver/tools.go`: `validateInput()` limits all input fields to 64 KiB and rejects null bytes; called in all 4 tool handlers before reaching the engine.

## [v1.4.0] - 2026-06-04

### Added
- Remote MCP frontend `cmd/mcp-broker-http`: Streamable HTTP + OAuth2/OIDC (RFC 9728 + Authorization Code + PKCE).
- Local OIDC bearer token validation against the issuer's JWKS (`go-oidc`): no round-trip per request, no `client_secret`.
- OIDC identity (`user_claim`, e.g. `preferred_username`) as `Caller.ID` in the broker's audit log.
- Per-end-user RBAC: when the token carries `groups_claim`, the groups are propagated to the signer as `EndUserGroups`; the signer requires `hp.Groups ∩ EndUserGroups ≠ ∅` (in addition to mTLS CN RBAC).
- `/.well-known/oauth-protected-resource` (RFC 9728) for Authorization Server discovery by the MCP client.
- `internal/mcpserver`: tools extracted to a shared package; both frontends (stdio and HTTP) use the same `Register(eng, callerFn)`.
- `internal/oauth/verifier.go`: `NewVerifier` + `Verify` with `UserID`, `Scopes`, and groups extraction; tests with fake OIDC IdP (`httptest` + `go-jose` RSA).
- `internal/auth/mtls.go`: `ServerTLSConfigNoClientAuth` for the HTTP+OAuth frontend (TLS without mTLS).
- `OAuthConfig` and `ResourceURL` in `broker.Config`; injectable `CallerFunc` in `mcpserver.New`.

### Changed
- MCP tool descriptions improved to reduce model errors:
  - `ssh_execute` and `ssh_session_open`: explicit guidance not to retry when `allow_sudo`/`allow_pty` is false.
  - `executeOutput`: documented `exit_code` (command failure ≠ tool error), `stderr` (empty with pty), and `serial` (audit only).
  - `ttl_seconds`: clarified as optional; the host policy maximum is used when omitted.
  - Cross-reference `ssh_execute` vs `ssh_session_open`: when to prefer each.
  - `ssh_session_open`/`ssh_session_close`: warning to always close the session.
  - `ssh_session_exec`: documents state persistence by mode.
  - `ssh_list_servers`: explains what `allow_sudo`/`allow_pty` false implies.
  - `sessionOpenInput.mode`: describes the three modes with concrete use cases.
- MCP server `Implementation` version synchronised: `0.2.0` → `1.2.0`.

## [v1.2.0] - 2026-06-04

### Added
- `ssh_list_servers` now returns per-host capabilities: `allow_sudo`, `allow_pty`, and `jump`, so the model can choose the correct execution strategy without attempting and failing.
- `GET /v1/hosts` from the signer includes `allow_sudo` and `allow_pty` in the response (`WireHostInfo`).
- `HostInfo` and `ServerInfo` (broker internal) propagate `AllowSudo`/`AllowPTY` from both modes (local and remote).
- `ssh_execute` and `ssh_session_open` descriptions updated to instruct the model to check capabilities before using `sudo`/`pty`.

## [v1.1.1] - 2026-06-04

### Fixed
- Signer audit: the `host` field now records the real FQDN/addr (`hp.Addr`) instead of the short logical name.
- Signer audit: the `user` and `principal` fields are now correctly populated in `issued` and `denied` events.

## [v1.1.0] - 2026-06-04

### Added
- CLI `broker-ctl` (`cmd/broker-ctl`) for managing `signer.json` without editing JSON by hand:
  - `host add`: adds or updates a host with all its parameters; `--scan` runs `ssh-keyscan` automatically.
  - `host list`: formatted table of hosts with addr, user, principal, TTL, sudo, PTY, groups.
  - `host remove`: removes a host from the configuration.
  - `reload`: SIGHUP when the signer runs locally (detects `signer.pid`), POST `/v1/reload` mTLS as fallback.
  - Preserves `_comment` fields and JSON annotations when writing (atomic write via rename).

## [v1.0.0] - 2026-06-03

### Added
- SSH broker with in-memory Ed25519 ephemeral key generation (keys never touch disk).
- External signing service (`cmd/signer`) with exclusive SSH CA key custody via HTTPS+mTLS.
- MCP stdio interface (`cmd/mcp-broker`): tools `ssh_execute`, `ssh_session_open`, `ssh_session_exec`, `ssh_session_close`, `ssh_list_servers`.
- ProxyJump support (multi-hop chains through a bastion).
- Policy-gated `sudo NOPASSWD` elevation in the signer: `allow_sudo`, `allowed_sudo_users`, anti-injection sanitisation.
- Persistent sessions with three modes: `exec`, `shell` (no PTY), and `pty` (with PTY).
- PTY support in one-shot and sessions: `allow_pty` per host, `permit-pty` in the certificate.
- Hot-reload of `signer.json` without restart: `SIGHUP` and `POST /v1/reload` (mTLS, gated by `reload_callers`).
- Triple signed and hash-chained audit by `serial` (Ed25519 + SHA-256): signer, broker, and sshd correlated.
- Group-based RBAC: `groups` field per host and `callers` section in `signer.json`; `GET /v1/hosts` filters by caller groups, `POST /v1/sign` rejects out-of-group hosts before `Resolve()`.
- Alternative HTTP+mTLS frontend (`cmd/broker`) for one-shot use without MCP.
- Local PKI generated: Ed25519 SSH CA, mTLS CA, server/client certs, audit seeds.
- End-to-end lab scripts: `lab/run_mcp_lab.sh`, `lab/run_signer_lab.sh`.
