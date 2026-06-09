# Changelog

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
