---
name: deps
description: Triage and land the open Dependabot PRs — verify each bump is what it claims (diff scope, release notes, breaking changes vs our actual usage), let the required checks gate it, and auto-merge one at a time. Use when the user asks to review/merge dependency updates or Dependabot PRs, or when Dependabot PRs are piling up.
---

# Land the Dependabot PRs

Dependabot (`.github/dependabot.yml`) opens weekly PRs for three ecosystems:
**gomod** (minor/patch batched into one `go-minor-patch` group PR; majors
individual), **github-actions**, and **docker** (directories `/` and
`/contrib/glama`: the `@sha256` digest pin of the distroless base image in
`Dockerfile` and `contrib/glama/Dockerfile`, #436). They pass through the same
required checks as any PR (`build`/`govulncheck`/`check`). This skill is the
review judgment in between: confirm the bump is safe for THIS repo, then land
them one at a time.

## STEP 1 — Inventory

```
gh pr list --author "app/dependabot" --json number,title,headRefName,statusCheckRollup
```

**Authenticity check**: the author must be exactly `app/dependabot` — a PR
merely titled like a bump but from another author is a red flag, not a
dependency update; stop and tell the user.

Order: land CI-green PRs first; a red one gets diagnosed, not forced (STEP 4).

## STEP 2 — Review each PR (this is the actual review, don't skip it)

For every PR, in this order:

1. **Diff scope** — `gh pr diff <n>`: a gomod PR may touch ONLY
   `go.mod`/`go.sum` (and vendored files if we ever vendor); an actions PR may
   touch ONLY `uses:` lines/hashes under `.github/workflows/`; a docker PR may
   touch ONLY the `@sha256:` digest of the `FROM` lines in `Dockerfile` and
   `contrib/glama/Dockerfile` — same image and tag
   (`gcr.io/distroless/static-debian12:nonroot`), new digest. Anything else
   (code, configs, scripts, a changed image or tag, a `FROM` that loses its
   digest) → do not merge; escalate to the user.
2. **What changed upstream** — the PR body carries release notes/changelog/
   commits. For a **major** bump, actually read them for breaking changes and
   check against OUR usage:
   - actions: `grep -rn "<action-name>" .github/workflows/` — renamed/removed
     inputs, changed defaults, node-runtime requirements, new permissions.
     (Example class: `actions/checkout` v5→v7, `docker/login-action` v3→v4 —
     majors were input-compatible for our usage, but that is checked, not
     assumed.)
   - gomod: `grep -rn "<module-path>" --include="*.go"` for the APIs we import;
     read the module's release notes for behavior changes in those.
   - docker: there are no release notes — the review is confirming the new
     digest is the current **multi-arch index** (not a single-platform
     manifest) of `gcr.io/distroless/static-debian12:nonroot`, via
     `docker buildx imagetools inspect gcr.io/distroless/static-debian12:nonroot`
     or the registry manifest API; the digest must match in both Dockerfiles.
3. **Security-sensitive deps get extra eyes** — bumps touching crypto, ssh,
   OAuth/JWT, or the MCP SDK affect the product's security surface: skim the
   upstream diff for the parts we depend on, and prefer `make verify` locally
   on the PR branch (`gh pr checkout <n>`), not just CI.

For the batched minor/patch gomod group, review the list as a whole; the
required checks plus a scan of the module list is proportionate.

## STEP 3 — Land, one at a time

```
gh pr merge <n> --squash --auto --delete-branch
```

- One at a time: after each merge Dependabot rebases the remaining PRs itself
  (or comment `@dependabot rebase` to force it). Don't edit Dependabot branches
  by hand — use `@dependabot rebase` / `@dependabot recreate`.
- If the auto-mode guardrail denies the merge, collect the reviewed PR numbers
  and ask the user to authorize them in one go.
- No changelog entry for routine bumps — dependency updates surface in the
  release notes via the git log cross-check in /release. A major bump that
  changes behavior users can see DOES get an `[Unreleased]` bullet.

## STEP 4 — A red Dependabot PR

- `govulncheck` red on ALL PRs at once → that's a stdlib CVE, not this bump:
  run /cve-fix first, then `@dependabot rebase` and re-check.
- Red only on this PR → the bump likely breaks us: reproduce locally on the PR
  branch, decide fix-forward (rare; that becomes an /issue) vs. reject. To
  reject: comment `@dependabot ignore this major version` (or
  `this minor version` / `this dependency`) so it stops reopening, close the
  PR, and tell the user what was ignored and why — ignoring a security update
  is the user's call, never yours.

## Guardrails

- Never merge with red required checks; never `--admin`.
- Never merge a "dependency PR" whose diff exceeds its manifest scope or whose
  author isn't `app/dependabot`.
- Version pins/hashes only move forward; never downgrade to dodge a failure.
- Ignoring or deferring a security-relevant bump requires the user's explicit
  decision.
