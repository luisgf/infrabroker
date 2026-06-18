# Changelog

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
