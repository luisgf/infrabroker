---
name: issue
description: Work a GitHub issue of infrabroker end-to-end — branch first, implement with tests, changelog entry under [Unreleased], make verify, then a PR that closes the issue on merge (auto-merge). Use when the user asks to work on, implement, fix or ship a specific issue, pick up the next issue from the backlog, or continue issue work.
---

# Work a GitHub issue → auto-merged PR

Take ONE issue from `luisgf/infrabroker` to a merged PR that closes it, with the
work recorded in the changelog. The live backlog IS the GitHub issue list (the
user's decision — no pending-work files in the repo or in memory).

## Prerequisites

- `gh auth status` OK, `origin` = `luisgf/infrabroker`.
- Start from a clean, synced `main`: `git checkout main && git pull --ff-only origin main`.
- The verify gate needs the docs venv and Go tooling; on this machine use
  `export PATH="$PWD/.venv/bin:$(go env GOPATH)/bin:$PATH"` and **`/usr/bin/make`**
  (plain `make` is a broken zsh autoload stub). See the /release skill for the
  full list of this machine's shell gotchas.

## STEP 1 — Pick & understand the issue

- Given `#N`, read ALL of it: `gh issue view N --comments` (the thread often
  refines or overrides the opening post; the LAST decisions win).
- No number given? `gh issue list --state open` (the `audit-bot` ones belong to
  the /audit loop), propose the most valuable unblocked one with a one-line
  rationale, and confirm before starting.
- **Do not assume product/security decisions.** If the issue leaves open a
  choice with real trade-offs (validation model, RBAC scope, crypto/custody,
  anything the owner must decide), ask FIRST — binary options with trade-offs,
  not implementation details.
- Architecture-shaping work (multiple packages touched, new component or
  surface): plan first and validate the design with the user before writing
  code — this is the user's standing preference.

## STEP 2 — Branch BEFORE editing (recurring slip — first command, always)

```
git checkout -b <type>/<slug>     # feat/…, fix/…, docs/…, chore/… per repo history
```

Editing on a fresh checkout of `main` and branching afterwards has burned this
repo twice; `main` is push-protected so the mistake surfaces late. Branch is the
FIRST step of every issue, before any file changes.

## STEP 3 — Implement

- Minimal, correct change scoped to the issue — no drive-bys (spin a new issue
  for anything unrelated you find).
- Tests lock in the behavior: security- and logic-relevant changes ALWAYS get
  one. Follow `docs/CODING_STYLE.md` and the surrounding code's idiom.
- NEVER weaken a security control, relax a validation, or delete/skip a test to
  make something pass.

## STEP 4 — Changelog (the work must be recorded)

Add a bullet to `docs/CHANGELOG.md` under `## [Unreleased]` at the top — create
that section if it does not exist (it won't right after a release; /release
folds it into each version's section when cutting):

```
## [Unreleased]

### Added | ### Changed | ### Fixed | ### Internal
- **<feature/fix name>** — user-facing, honest description of the impact,
  matching the voice of the released entries below.
```

Pick the subsection by nature of the change, not by commit type. Purely internal
work still gets a line under `### Internal` — /release decides what surfaces.

## STEP 5 — Verify (green before any commit)

```
export PATH="$PWD/.venv/bin:$(go env GOPATH)/bin:$PATH"
/usr/bin/make verify
```

gofmt + vet + build + race tests (+ govulncheck when on PATH) + the docs gate.
If it regenerated `docs/reference/`, COMMIT those files with the change. Fix
forward; never commit a red tree.

## STEP 6 — PR with `Closes #N`, then auto-merge

- ONE logical commit, Conventional Commits matching repo history
  (`feat:`/`fix:`/`docs:`/`chore:`). **No `Co-Authored-By` / "Generated with" /
  any assistant-attribution trailer** (standing user rule).
- Push and open the PR:

  ```
  git push -u origin <branch>
  gh pr create --base main --title "<type>: <summary>" --body "…

  Closes #N"
  ```

- **Issue-linking keywords — GitHub ignores negation.** ANY
  `close|closes|closed|fix|fixes|fixed|resolve|resolves|resolved #N` in the PR
  body or commits closes issue N on merge, even inside "does **not** close #N"
  (this bit us: a Phase-0 PR closed its parent). Rules:
  - The PR fully resolves the issue → `Closes #N`.
  - Partial/phased work → `Part of #N` or `tracked in #N`, NEVER a closing
    keyword next to that `#N`.
- Enable auto-merge (the user's standing mechanism — repo has
  `allow_auto_merge`, branch protection requires `build`/`govulncheck`/`check`):

  ```
  gh pr merge <n> --squash --auto --delete-branch
  ```

  If the harness's auto-mode guardrail denies the agent merging its own PR,
  STOP and ask the user to authorize it (e.g. "merge #NN") or to run the
  command — never work around the denial (no `--admin`, no direct pushes to
  `main`).

## STEP 7 — Confirm & report

- Checks green, PR `MERGED`, branch deleted.
- `Closes #N` → the issue must now be CLOSED; `Part of #N` → it must still be
  OPEN (reopen and neutralize the wording if a keyword slipped through).
- `git checkout main && git pull --ff-only origin main`; leave the tree clean.
- Report: what changed, what was verified (the actual gate output, not "should
  pass"), PR and issue links.

## Guardrails (hard rules)

- One issue per PR; no unrelated changes riding along.
- Never commit secrets, keys, real configs (`signer.json`, `config.json`,
  `broker-ctl.json`, `*.env`), `plans/` (local-only), `dist*/` artifacts, or
  `.claude/settings.local.json`.
- A red required check blocks the merge — that is the protection working; fix
  forward instead of bypassing.
- If mid-implementation the issue turns out to need a human product/security
  decision, stop and ask; don't guess and ship.
