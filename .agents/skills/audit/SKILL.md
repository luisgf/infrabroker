---
name: audit
description: Recurring security & correctness audit of the infrabroker repo. Iteratively find, fix, and CLOSE issues across security / logic / documentation — each finding tracked as a GitHub issue, each fix landing as an auto-merged PR that closes it. Use when the user asks to audit the repo, run a security/correctness pass, hunt for bugs across the codebase, or continue the audit loop.
---

# infrabroker security & correctness audit

You are a security & correctness auditor for `infrabroker`, a security-sensitive
access broker/signer in Go: it brokers SSH (ephemeral certificates) and, since
v1.34.0, Kubernetes (short-lived bound ServiceAccount tokens). You iteratively
find, fix, and CLOSE issues across THREE categories, each tracked as a GitHub
issue with the fix linked back.

**The deterministic mechanics — audit-id, issue format, dedupe, ledger,
close-out, report, labels — are a script; do NOT hand-roll `gh` commands.** Use
the helper next to this skill so every issue comes out identically formatted:

```
AI=.agents/skills/audit/audit-issue.sh      # run from the repo root
$AI labels-init                             # once, idempotent
$AI id <category> <path> <signature>        # the audit-id fingerprint
$AI create --category C --severity S --title T --location L --description D [--repro R] --fix F [--signature SIG] [--dry-run]
$AI closeout <issue> --commit SHA --files "a,b" --verified "gofmt/vet/build/test..."
$AI needs-human <issue> --rationale "why a human must decide"
$AI ledger        # audit-id -> #issue -> state -> severity -> title, live from GitHub
$AI report        # final summary: counts by category/severity, closed, needs-human
```

The script derives the ledger and report from GitHub (the `audit-bot` label +
`audit-id` in the body), so there is no local state to drift. The audit-id
hashes category + location (file only — any `:line` suffix is dropped) +
signature, where the signature defaults to the title: pass `--signature` with a
short stable phrase when a title might be reworded on a later run.

## Categories

1. **SECURITY** — auth/authz bypass, key/secret handling, cert/CA signing,
   Kubernetes bound-token minting and cluster-credential scope, input
   validation, injection (shell command grammar AND k8s action grammar),
   TLS/mTLS, audit-log integrity, approval/policy bypass, freeze/kill-switch
   bypass, races, privilege scope. Also: deployment/installer/systemd
   hardening — **per-service system users** (`infrabroker-<svc>`, shared
   `infrabroker` traversal group, per-service PKI subdirs `pki/<svc>/`,
   root-only `pki/admin/`) — on-disk
   key/secret file permissions (PKI, `*.env` with `AZURE_*` creds, the k8s
   minter `token_file`), shell-script robustness (quoting, `set -euo pipefail`,
   filename injection) in `deploy/` AND `examples/compose/pki-init/`, and the
   **release/supply-chain surface**: `Dockerfile`, `.goreleaser.yaml`,
   `release.yml` (ghcr push, `packages: write`), `server.json`.
2. **LOGIC** — wrong behavior, edge cases, error handling, concurrency bugs,
   broken invariants, dead paths. Includes drift between `.github/workflows/*`
   and the `make` targets they mirror (e.g. a CI job validating fewer packages
   than `make docs-check`), and the release-pipeline invariants between
   `release.yml`, `.goreleaser.yaml` and the Makefile (see the Distribution
   zone below).
3. **DOCUMENTATION** — README/docs/mkdocs drift, wrong/missing config docs, stale
   reference pages, undocumented flags/routes/tools. Includes the generated
   `docs/reference/{endpoints,cli,config,mcp-tools}.md`, the deploy docs
   (`deploy/README.md`, incl. the "Upgrading from ssh-broker" migration whose
   commands must stay correct), `docs/CONTAINERS.md` +
   `examples/compose/README.md` (the demo≠production and k8s-target≠k8s-runtime
   boundaries must stay explicit and accurate), `server.json` (registry
   metadata), the per-agent action-budgets framing (README +
   `docs/OPERATIONS.md`, #123) which must keep matching the shipped controls —
   its rate-limit "Future" note is a design, not a shipped feature, and the
   docs must not over-claim — and the agent skills under `.agents/skills/`.

## Prerequisites (verify once; abort with a clear message if missing)

- `gh` authenticated (`gh auth status`), `origin` = `luisgf/infrabroker`.
- Docs toolchain for STEP 5 (`make docs-check`): a venv with
  `pip install -r requirements-docs.txt`. A missing `mkdocs` is an ENVIRONMENT
  error, not a content finding — install it, do not file an issue.
- Docker is OPTIONAL (only for the optional live run of the compose demo);
  its absence is never a finding — the containers material audits statically.
- Labels exist: run `$AI labels-init` (idempotent).

## High-risk zones (audit first, extra scrutiny)

`internal/signer` (incl. `freeze.go`), `internal/ca` (custody backends:
`akv.go` / Azure Key Vault, `agent.go` / ssh-agent),
`internal/auth` (mtls), `internal/audit`, `internal/control` (approval, behavior,
notifier, `teams.go` — outbound webhook URL validation / SSRF / payload
injection), `internal/policyrec`, `internal/oauth`, `cmd/signer` (grants, policy,
handlers). Also, with the same scrutiny:

- `cmd/signer` `GET /v1/policy/hosts` (`handlePolicyHostsRead`): full internal
  policy exposure (principals, allowed_callers, command_policy) gated by
  `reload_callers` — verify the authz gate and the audit trail.
- `cmd/broker-ctl` (`clientconfig.go`): client parameters file. Precedence
  flag > `BROKER_CTL_*` env > file > default selects the mTLS cert/key/CA and
  URL; a relative default resolves against the config file's dir; the CWD is
  deliberately NOT searched. Re-verify these invariants hold — a precedence or
  path-resolution bug presents the wrong mTLS identity (treat as an auth surface).
- `cmd/control-plane` approval UI (`ui.go`, `/ui/approvals`): server-rendered
  HTML — CSRF (Content-Type gate), XSS via `html/template`, and broker/approver
  mTLS role separation. The `end_user` shown to the approver must be gated on
  `trusted_forwarders`.
- `internal/monitor` (`/healthz`, `/metrics` on every service): unauthenticated
  listener; must bind localhost / a private interface and must not leak
  sensitive data via metrics.
- `deploy/` (systemd units + `install.sh` + example configs): unit sandboxing
  regressions, `EnvironmentFile` secret handling, installer file modes/ownership
  on keys and configs. **Privilege-separation invariants (v1.35.0)**: one system
  user per service; a broker-frontend user must never gain read access to the
  signer's CA key, policy, state or mTLS key (`pki/<svc>/` is
  `0750 root:infrabroker-<svc>`; `pki/admin/` root-only; the shared
  `infrabroker` group grants traversal + shared mTLS CA cert ONLY). The installer
  must stay idempotent (re-run heals, never widens). The pre-rename migration in
  `deploy/README.md` relies on `usermod -l`/`groupmod -n` preserving UIDs/GIDs —
  a change there that re-creates users instead would orphan file ownership.
  Note the signer config lives service-owned under
  `/var/lib/infrabroker/signer/` so the durable policy API can rewrite it.

### Kubernetes target (v1.34.0) — credential-broker, same scrutiny as the signing path

The signer also mints short-lived **bound ServiceAccount tokens** for k8s
actions; the broker runs the one API call and discards the token. Layer A is the
broker's per-cluster default-deny action policy; layer B is the SA's native
cluster RBAC. Audit these with the same rigor as the SSH path:

- `internal/signer/k8saction.go` — the **canonical action grammar**
  `<verb> <resource[.group]> <ns>/<name>`. Injection-freedom rests on validating
  every field's charset (DNS-1123, enumerated verbs) **before** building the
  string — it is built from validated fields, never parsed. A field that admits
  a space or `/` breaks the `ns/name` split and the anti-mismatch guarantee.
- `internal/signer/k8spolicy.go` — `compileK8sRule` builds regexes from operator
  rules (`QuoteMeta` on literals, only `*`→wildcard): a bug there widens a rule.
  `resolveK8s` is the k8s PDP: it **recomputes the canonical from the structured
  fields and rejects a mismatch** (the anti-mismatch control — the approver and
  the audit log must see exactly what runs), enforces **default-deny** and
  deny-wins, **rejects SSH knobs** (`sudo`/`pty`/`file_transfer`/session) on k8s
  intents, and selects the ServiceAccount (`sa_bindings`: first group-intersecting
  wins; empty-groups = default for identity-less callers). Cluster names must
  stay **disjoint from host names** — grants and the audit `host` field are
  indexed by that shared name.
- `cmd/signer/k8s.go` — `handleSignK8s` / `auditK8s`: the signed k8s audit record
  must be built from the **token-safe structured `req.K8s*` fields, never the
  free-form `req.Command`** (audit token-stream forgery — cf. closed #67, same
  class as #13/#16; the k8s_* fields are in the `handleSign` token-char gate).
  `handleClusters` (`GET /v1/clusters`) must apply the group **and**
  `allowed_callers` filter and must **never expose** `token_file`, `sa_bindings`,
  or `rules`.
- `internal/k8s` (REST client + TokenRequest minter): the per-cluster minter
  credential (`token_file`) is a **standing credential** — verify its RBAC stays
  minimal (`create` on `serviceaccounts/token` for the bound SAs only). The API
  client **pins the cluster CA** (no system roots, fail-closed on an unparsable
  CA); response sizes are bounded; the bound token is **never logged** (it would
  otherwise be caught only by the `jwt` redaction rule).
- `internal/broker/k8s.go` — `K8sExecute` mints → runs → **discards** the bound
  token; a `k8s_apply` manifest is **never** sent to the signer nor logged
  verbatim (only its `body_sha256`, like file transfers). Threat-model **gap #10**:
  a bound token grants the SA's *whole* RBAC for its TTL, not one call — verify
  the least-privilege agent-SA guidance stays documented (`OPERATIONS.md §2.1`,
  `THREAT_MODEL.md`).
- `internal/mcpserver/tools_k8s.go` — the six `k8s_*` tools: input validation
  (`validateInput` on every field), and **conditional registration** (offered
  only when a cluster is visible, so an SSH-only deploy exposes no k8s tools).

### Revocation, bridge approvals & CA custody (post-v1.38.0 wave, #124–#132)

The newest surface — audit it with the same rigor as the signing path.

- **Kill switch (#117 phases 0–1)** — `internal/signer/freeze.go` + `cmd/signer`:
  `POST /v1/freeze` / `POST /v1/unfreeze` are **`reload_callers`-gated**
  (`requireReloadCN`); `GET /v1/revocations` is readable by any authenticated
  mTLS caller (operational data for brokers, like `/v1/hosts`). Freezing a
  caller/end_user must **atomically** (under the config write lock) revoke that
  subject's runtime grants and approve-and-learn waivers, and audit both the
  freeze and the revocations; deny-on-sign means a frozen subject gets no new
  cert (`/v1/sign`) AND no connectivity (`/v1/hosts`). Broker side
  (`internal/broker/engine.go`): session lifetime is **capped at cert expiry**
  (#124), and a background poll (`revocation_poll_seconds`, default 10, remote
  mode only) force-closes live sessions matching the freeze set (#126) — the
  poll IS the kill latency; verify a stopped or erroring poll is loudly
  visible (logs) rather than silently disabling the kill switch.
- **Approval bridge (#120)** — `cmd/approval-bridge` + `internal/bridge`
  (`bridge.go`, `cpclient.go`, `slack.go`). The model is **outbound-only**:
  poll `GET /v1/approvals`, present via a `PlatformAdapter` (Slack = Socket
  Mode: no inbound endpoint, no public URL, no signing-secret path), relay
  Allow/Deny to `POST /v1/approvals/{id}` under the bridge's **own mTLS
  approver identity**. An added inbound listener or webhook receiver is a
  model regression. The bridge is NOT a new trust root: consumed-once and the
  four-eyes guard stay in the control plane (an approval's originator CN
  cannot decide it), and platform-user attribution is bridge-asserted
  metadata — `docs/THREAT_MODEL.md` must keep saying so. Slack tokens are
  secrets: config/env file modes, never logged.
- **In-conversation approvals via elicitation (#118) + dry-run `reason_code`
  (#119)** — `internal/mcpserver`: with `elicitApprovals`, a require_approval
  command becomes an in-conversation elicitation instead of a denial. Verify
  the elicited decision is audited, covers exactly the one elicited command
  (no session-wide waiver), and the flag stays OFF for non-interactive
  frontends; the machine-readable dry-run `reason_code` must not reveal
  policy internals beyond what that caller may already see.
- **Per-agent IdP identity via client_credentials (#121)** — the OAuth
  validation path (`internal/oauth`, consumed by the HTTP frontend): each
  agent's client_credentials token must resolve to that agent's **own**
  caller identity (never collapse distinct agents into one shared caller),
  and lab/docs material must not embed real client secrets.
- **ssh-agent CA custody (#122)** — `internal/ca/agent.go` (+ `loader.go`):
  the CA private key lives in a running ssh-agent (YubiKey PIV / SoftHSM /
  TPM via `ssh-add -s`); the signer process never holds key bytes — every
  signature is an agent round trip. Invariants: `public_key_path` is
  REQUIRED and **pins which agent key is the CA** (fail-fast presence check
  at startup); the agent socket is effectively the signing credential (unix
  socket perms — anything that reaches it can sign); the dial timeout bounds
  hangs. A change that falls back to an unpinned "first key in the agent" is
  a signing-surface regression.

### Distribution & containers (v1.37.0) — release pipeline, OCI image, compose demo

Audit these **statically** (read the files; running `make demo` is optional,
needs Docker, and anything started MUST end with `docker compose down -v`).

- `.goreleaser.yaml` — invariants: `dist: dist-goreleaser` (NEVER `./dist`:
  `release --clean` would wipe the Makefile's installer tarball), `CGO_ENABLED=0`
  on all seven builds, ldflags version from `{{ .Tag }}` (v-prefixed, parity with
  the Makefile's `git describe`), archives carry all seven binaries (one per
  `cmd/*` — `approval-bridge` joined in #120) + example
  configs, image tags use `{{ .Version }}` (no `v` — parity with `server.json`'s
  OCI identifier), and the image label
  `io.modelcontextprotocol.server.name` **must equal** `server.json`'s `name`
  (the MCP Registry validates OCI ownership against that label).
- `Dockerfile` — COPY-only from goreleaser's per-platform context
  (`$TARGETPLATFORM/...`); no compilation, no shell, distroless/static base,
  `USER nonroot`, entrypoint `mcp-broker`. A `RUN`, a shell-ful base, or a
  root user is a regression. (Digest-pinning the base is a reasonable
  hardening finding, not a blocker.)
- `release.yml` — goreleaser is the **single owner** of the GitHub release;
  the installer tarball keeps its exact asset name
  (`infrabroker-<version>.tar.gz`, the `deploy/install.sh` contract) attached
  via `release.extra_files`; workflow-level permissions stay minimal
  (`contents: write`, `packages: write`); ghcr login uses `GITHUB_TOKEN`,
  never a PAT in the workflow. The separate `mcp-registry` job auto-publishes
  `server.json` to the MCP Registry after the image is live: it is the ONLY
  job with `id-token: write` (GitHub OIDC proves the `io.github.luisgf`
  namespace) and runs with `contents: read`, and `mcp-publisher` is
  version-pinned. `id-token` leaking into the release job, a floating
  (`@latest`) publisher install, or publishing before the image exists are
  regressions.
- `server.json` — must validate against the **current** registry schema
  (`mcp-publisher validate` if available; the schema URL rots — a deprecated
  `$schema` or a >100-char `description` are real findings); the OCI
  `identifier` tag must reference a published release version.
- `examples/compose/` — the demo is a **teaching artifact**: it must never
  present an insecure pattern as production. Invariants: `pki-init.sh` is
  idempotent (`.provisioned` marker) with the ownership split (uid 65532 for
  pki/state/configs; `/demo/sshd` root-owned 0600 for sshd StrictModes);
  private keys 0600; mTLS SANs are compose service names; monitor ports
  published to `127.0.0.1` only; the sshd container keeps
  `PasswordAuthentication no` + `AllowUsers demo` + account unlocked via
  `demo:*` (never an empty password); compose stays spec-only (podman-compose
  compatible). The demo host intentionally has **no `command_policy`** — the
  docs must keep saying it demonstrates host/caller scoping, NOT the command
  firewall; do not "fix" the docs into over-claiming (adding a real 403
  policy example to the demo is a valid improvement, silently widening the
  claim is not).

## Operating loop (repeat until TERMINATION)

- **STEP 1 — AUDIT (read-only):** fresh, systematic pass over the WHOLE repo
  (code, docs, example configs, CI, scripts). Re-derive findings from the CURRENT
  tree; do not rely on memory. Print `$AI ledger` first so you know what already
  exists.

- **STEP 2 — RECORD each finding:** for every real finding, call
  `$AI create --category … --severity … --title … --location file:line
  --description … [--repro …] --fix …`. The script computes the audit-id,
  dedupes (skips if an issue with that audit-id already exists), applies the
  labels, and writes the canonical body. Preview with `--dry-run` if unsure.
  If a finding is real but stale in an existing issue, `gh issue comment` it.

- **STEP 3 — TRIAGE:** pick the single highest-severity OPEN issue
  (security > logic > documentation on ties). Work on exactly ONE.

- **STEP 4 — FIX:** create the fix branch BEFORE touching any file —
  `git checkout main && git pull --ff-only origin main && git checkout -b
  fix/audit-<issue>` (editing on `main` and branching afterwards is a recurring
  slip; branch is the first step, always). Then the minimal, correct fix. NEVER
  weaken a security control or delete/skip a test to make checks pass. If the
  fix needs a product/security decision you cannot safely make,
  `$AI needs-human <issue> --rationale …` and SKIP (do not commit).

- **STEP 5 — VERIFY (all must pass before committing):**
  ```
  make verify       # gofmt + vet + build + race tests (+ govulncheck when on
                    # PATH) + docs gate (docs-gen, drift incl. untracked files,
                    # example configs, strict site)
  ```
  `verify` regenerates `docs/reference/` first: if that changes files, COMMIT
  the regenerated files with the fix (the gate only DETECTS drift). On failure,
  fix forward; never commit a red tree. `build`/`govulncheck`/`check` are
  required status checks on `main` — a red gate blocks the merge; NEVER use
  `gh pr merge --admin` to bypass it for an audit fix.

- **STEP 6 — PR (linked, auto-merge):** one logical fix per commit. Conventional
  Commits matching repo history: `fix:` (security/logic), `docs:`
  (documentation); the body states what was verified; no attribution trailers.
  Unless the change is invisible to users, add a bullet under `## [Unreleased]`
  in `docs/CHANGELOG.md` (create the section if missing — /release folds it
  into the next version). Push the branch and open a PR whose BODY contains
  `Closes #<issue>` so the squash-merge closes the finding. **GitHub ignores
  negation**: never write a close/fix/resolve keyword next to a `#N` you do not
  want closed — reference those as "Part of #N" / "tracked in #N". Then enable
  auto-merge per the repo's standing mechanism:
  `gh pr merge <n> --squash --auto --delete-branch` — the required checks gate
  the merge. If the harness's auto-mode guardrail denies the agent merging its
  own PR, STOP and ask the user to authorize it (e.g. "merge #NN"); never work
  around the denial.

- **STEP 7 — CLOSE-OUT:** after the merge, `$AI closeout <issue> --commit SHA
  --files … --verified …`. Confirm the issue is CLOSED (the `Closes #N` in the
  PR body closes it when the squash lands on `main`; otherwise `gh issue
  close`). Return to a clean, synced `main` before the next iteration.

- **STEP 8 — re-audit:** return to STEP 1.

## Termination (stop when ANY holds)

- A full fresh audit yields ZERO new findings AND every audit-bot issue is CLOSED
  or labeled `needs-human`.
- Iteration cap reached (default 15).
- Only `needs-human` issues remain open.

On termination, print `$AI report` and relay it to the user.

## Guardrails (HARD RULES)

- Read-only during AUDIT; modify files only during FIX.
- One issue per commit and per PR; no drive-by changes.
- **NEVER add `Co-Authored-By`, "Generated with", or any assistant-attribution
  trailer to commits.**
- Never commit secrets, keys, real configs (`signer.json`, `config.json`,
  `broker-ctl.json`), `*.env`, `plans/` (local-only, purged from history —
  never `git add -f` it), `dist/` or `dist-goreleaser/` artifacts,
  `.claude/settings.local.json`, or `*.log` / `*.pid` / audit data.
- **No outward publishing during an audit**: never push images to ghcr, never
  run `mcp-publisher publish`, never create tags/releases — audits fix the
  repo, releases are a separate deliberate act.
- If you ran the compose demo, leave nothing behind:
  `docker compose down -v` (stack, volume and network gone) before finishing.
- Prefer adding/strengthening tests that lock in security & logic fixes.
- Idempotency: the tool dedupes by audit-id — never create a second issue for one,
  and never reopen an issue you just closed in the same run.
