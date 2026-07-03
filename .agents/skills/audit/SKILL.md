---
name: audit
description: Recurring security & correctness audit of the ssh-broker repo. Iteratively find, fix, and CLOSE issues across security / logic / documentation, tracking each as a GitHub issue and linking every fix back to it. Use when the user asks to audit the repo, run a security/correctness pass, hunt for bugs across the codebase, or continue the audit loop.
---

# ssh-broker security & correctness audit

You are a security & correctness auditor for `ssh-broker`, a security-sensitive
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
$AI create --category C --severity S --title T --location L --description D [--repro R] --fix F [--dry-run]
$AI closeout <issue> --commit SHA --files "a,b" --verified "gofmt/vet/build/test..."
$AI needs-human <issue> --rationale "why a human must decide"
$AI ledger        # audit-id -> #issue -> state -> severity -> title, live from GitHub
$AI report        # final summary: counts by category/severity, closed, needs-human
```

The script derives the ledger and report from GitHub (the `audit-bot` label +
`audit-id` in the body), so there is no local state to drift.

## Categories

1. **SECURITY** — auth/authz bypass, key/secret handling, cert/CA signing,
   Kubernetes bound-token minting and cluster-credential scope, input
   validation, injection (shell command grammar AND k8s action grammar),
   TLS/mTLS, audit-log integrity, approval/policy bypass, races, privilege
   scope. Also: deployment/installer/systemd hardening, on-disk key/secret file
   permissions (PKI, `*.env` with `AZURE_*` creds, the k8s minter `token_file`),
   and shell-script robustness (quoting, `set -euo pipefail`, filename
   injection) — the `deploy/` artifacts are in scope.
2. **LOGIC** — wrong behavior, edge cases, error handling, concurrency bugs,
   broken invariants, dead paths. Includes drift between `.github/workflows/*`
   and the `make` targets they mirror (e.g. a CI job validating fewer packages
   than `make docs-check`).
3. **DOCUMENTATION** — README/docs/mkdocs drift, wrong/missing config docs, stale
   reference pages, undocumented flags/routes/tools. Includes the generated
   `docs/reference/{endpoints,cli,config,mcp-tools}.md`, the deploy docs
   (`deploy/README.md`), and the agent skills under `.agents/skills/`.

## Prerequisites (verify once; abort with a clear message if missing)

- `gh` authenticated (`gh auth status`), `origin` = `luisgf/ssh-broker`.
- Docs toolchain for STEP 5 (`make docs-check`): a venv with
  `pip install -r requirements-docs.txt`. A missing `mkdocs` is an ENVIRONMENT
  error, not a content finding — install it, do not file an issue.
- Labels exist: run `$AI labels-init` (idempotent).

## High-risk zones (audit first, extra scrutiny)

`internal/signer`, `internal/ca` (incl. `akv.go` / Azure Key Vault),
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
  on keys and configs. Note the signer config lives service-owned under
  `/var/lib/ssh-broker/signer/` so the durable policy API can rewrite it.

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

- **STEP 4 — FIX:** minimal, correct fix. NEVER weaken a security control or
  delete/skip a test to make checks pass. If the fix needs a product/security
  decision you cannot safely make, `$AI needs-human <issue> --rationale …` and
  SKIP (do not commit).

- **STEP 5 — VERIFY (all must pass before committing):**
  ```
  gofmt -l .        # must print nothing
  go vet ./...
  go build ./...
  go test -race ./...
  make docs-gen     # FIRST when routes/tools/config/CLI changed — docs-check only DETECTS drift
  make docs-check   # only when docs/config/routes/tools changed
  ```
  On failure, fix forward; never commit a red tree.

- **STEP 6 — COMMIT (linked):** one logical fix per commit. Conventional Commits
  matching repo history: `fix:` (security/logic), `docs:` (documentation).
  The commit BODY must contain `Fixes #<issue>` so it auto-closes on merge to the
  default branch, plus what was verified. Follow the repo's branch → PR → merge
  convention.

- **STEP 7 — CLOSE-OUT:** after the merge, `$AI closeout <issue> --commit SHA
  --files … --verified …`. Confirm the issue is CLOSED (the `Fixes` link closes
  it on merge; otherwise `gh issue close`).

- **STEP 8 — re-audit:** return to STEP 1.

## Termination (stop when ANY holds)

- A full fresh audit yields ZERO new findings AND every audit-bot issue is CLOSED
  or labeled `needs-human`.
- Iteration cap reached (default 15).
- Only `needs-human` issues remain open.

On termination, print `$AI report` and relay it to the user.

## Guardrails (HARD RULES)

- Read-only during AUDIT; modify files only during FIX.
- One issue per commit; no drive-by changes.
- **NEVER add `Co-Authored-By`, "Generated with", or any assistant-attribution
  trailer to commits.**
- Never commit secrets, keys, real configs (`signer.json`, `config.json`,
  `broker-ctl.json`), `*.env`, `dist/` tarballs, `.claude/settings.local.json`,
  or `*.log` / `*.pid` / audit data.
- Prefer adding/strengthening tests that lock in security & logic fixes.
- Idempotency: the tool dedupes by audit-id — never create a second issue for one,
  and never reopen an issue you just closed in the same run.
