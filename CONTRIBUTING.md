# Contributing — ssh-broker

Development workflow, versioning, and the mandatory pre-commit checklist. For Go
style rules see [CODING_STYLE.md](CODING_STYLE.md).

---

## Branches

- Every **new feature** is developed on its own branch (`feature/<name>`) or fix
  (`fix/<name>`); documentation-only work on `docs/<name>`.
- A branch is merged into `main` only once the work is considered valid.
- Minor maintenance commits (docs, config) may go directly to `main`.
- Tags `vX.Y.Z` are created **only on `main`**, never on development branches.

---

## Versioning — `X.Y.Z`

| Component | When it increments | Reset on increment |
|---|---|---|
| `X` (major) | Architecture change or backward-incompatible break | `Y=0`, `Z=0` |
| `Y` (minor) | Automatically when a branch is merged into `main` | `Z=0` |
| `Z` (build) | Each commit on `main` | — |

Initial version: `v1.0.0`.

### Procedure: commit on `main` (docs, config, hotfix)

```bash
git describe --tags --abbrev=0        # e.g. v1.12.0
# update the living docs (see checklist below)
git commit -m "description of the change"
git tag v1.12.1                       # Z+1
```

### Procedure: merge a feature branch → `main`

```bash
git merge --no-ff feature/my-feature  # Y+1, Z=0
# update the living docs
git add CHANGELOG.md README.md ...
git commit -m "chore: merge feature/my-feature → v1.13.0"
git tag v1.13.0
```

End commit messages with the project's `Co-Authored-By` trailer when applicable.

**Embedded version.** The binaries report their version from `internal/version`,
injected at build time from `git describe --tags` by the `Makefile` (`make
build` / `make install`). Tagging is therefore the single source of truth — no
constant to bump by hand. A plain `go build` falls back to a `dev-<commit>`
string from the Go build info.

---

## Mandatory pre-commit checklist (living docs)

**Before any commit that changes code, configuration, or behavior**, update the
living documentation. A commit without these updates asserts that nothing
externally visible changed (internal refactor only).

1. **`CHANGELOG.md`** — add an entry at the **top**:
   ```markdown
   ## [vX.Y.Z] - YYYY-MM-DD
   ### Added / Changed / Fixed / Security / Removed
   - …
   ```
2. **`README.md`** — reflect any change to the public interface, configuration,
   new options, security sections, or pending-work status.
3. **`API.md`** — if an HTTP endpoint was added, removed, renamed, or its
   request/response schema changed. Applies to all services: signer
   (`/v1/sign`, `/v1/hosts`, `/v1/reload`), control plane, broker HTTP
   (`/v1/ssh_run`), and MCP HTTP (including MCP tool signatures).
4. **`USAGE.md`** — if an MCP tool was added, removed, renamed, or its
   parameters/return values/restrictions changed.

When a change touches design rationale, runbook steps, or the security posture,
also update [ARCHITECTURE.md](ARCHITECTURE.md), [OPERATIONS.md](OPERATIONS.md),
or [THREAT_MODEL.md](THREAT_MODEL.md) respectively.

A purely internal change (variable rename, refactor with no external effect) may
skip the above **with an explicit justification in the commit message**.

---

## Language

All source code and **new** documentation must be in **English** — including
legacy code. Do not mix languages within a single function or doc block; when
editing a legacy function with Spanish comments, translate them in the same
commit.

| Artifact | Language |
|---|---|
| Commit messages, Go comments, CLI strings, error messages | English |
| `CHANGELOG.md`, `README.md`, `API.md`, `USAGE.md`, and the `*.md` design/ops/security docs | English |
| `HANDOFF.md` | Spanish (internal session-handoff document) |

---

## Plan of work for each commit

Quick checklist (from [CODING_STYLE.md](CODING_STYLE.md)):

```
[ ] gofmt -l . → no output
[ ] go vet ./... → no output
[ ] go test -race ./... → all pass
[ ] No function body > 80 lines
[ ] New I/O functions take ctx context.Context as the first param
[ ] No _ = json.NewEncoder(w).Encode(...) in handlers (use the writeJSON helper)
[ ] New Test functions call t.Parallel() (if applicable)
[ ] Imports in three groups: stdlib / third-party / internal
[ ] fmt.Errorf uses %w when wrapping an existing error
[ ] Living docs updated (see checklist above)
```
