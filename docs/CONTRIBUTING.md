# Contributing — infrabroker

Development workflow, versioning, and the mandatory pre-commit checklist. For Go
style rules see [CODING_STYLE.md](CODING_STYLE.md).

---

## Branches

- **All work goes through a pull request.** `main` is a protected branch:
  nothing is pushed to it directly — not features, not docs, not config — and
  the `build`, `govulncheck` and `check` workflow jobs are required status
  checks, so a red gate blocks the merge.
- Branch first, then edit: `feature/<name>`, `fix/<name>` (or `fix/audit-<N>`
  for audit findings), `docs/<name>`. Squash-merge the PR (auto-merge is the
  standing mechanism for issue and audit fixes: `gh pr merge <n> --squash
  --auto --delete-branch`); a PR that fixes an issue ends its description with
  `Closes #<N>`.
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/)
  matching the repo history (`feat:` / `fix:` / `docs:` / `chore:`, with an
  optional scope such as `fix(signer):`), in English. **Never add an
  assistant-attribution trailer** — no `Co-Authored-By`, no "Generated with".
- Tags `vX.Y.Z` are created **only on `main`**, only by the release procedure
  below — never on development branches and never per commit.

---

## Versioning — semver by content

Versions are not tied to the number of commits or merges. Work accumulates on
`main` under the `## [Unreleased]` section of `CHANGELOG.md`, and a release is
cut when there is something worth shipping; the bump level is decided by what
that section (and `git log <last-tag>..HEAD`) contains:

| Component | When it increments | Reset on increment |
|---|---|---|
| `X` (major) | A breaking change (a `!` commit type, or a documented incompatible change) | `Y=0`, `Z=0` |
| `Y` (minor) | Any new user-facing feature (`feat:`) — a new command, tool, route, or config surface | `Z=0` |
| `Z` (patch) | Only fixes / docs / chore / internal cleanup, no new surface | — |

Many merges can land between two tags (a patch tag routinely follows dozens of
merged PRs); the version is stamped into the tag, the ghcr image and the MCP
Registry entry, so it is chosen once, at release time.

### Procedure: cut a release

The full checklist is the release skill,
[`.agents/skills/release/SKILL.md`](https://github.com/luisgf/infrabroker/blob/main/.agents/skills/release/SKILL.md);
in outline:

1. On a clean, synced `main`, determine `vX.Y.Z` from `[Unreleased]` and the
   git log since the last tag (state the reasoning).
2. Prepare the release commit on a `release/vX.Y.Z-changelog` branch: rename
   `## [Unreleased]` to `## [vX.Y.Z] - YYYY-MM-DD` (cross-checked against the
   git log), bump `server.json` (`version` and the OCI `identifier`), update
   `docs/HANDOFF.md`. `make verify` must be green.
3. Open the release PR (`chore: prepare vX.Y.Z release (changelog, server.json,
   handoff)`). **Release PRs are not auto-merged** — a human reviews and merges.
4. After the merge: an **annotated** tag on the merged commit,
   `git tag -a vX.Y.Z -m "..."` then `git push origin vX.Y.Z`. The tag push is
   the publish: `release.yml` builds the GitHub release, the multi-arch ghcr
   images and the MCP Registry entry — nothing is run locally.

**Embedded version.** The binaries report their version from `internal/version`,
injected at build time from `git describe --tags` by the `Makefile` (`make
build` / `make install`). Tagging is therefore the single source of truth — no
constant to bump by hand. A plain `go build` falls back to a `dev-<commit>`
string from the Go build info.

---

## Documentation: published, and guarded against drift

The docs live in `docs/` (this folder) and are published to **GitHub Pages**; the
Markdown in the repo is the single source of truth, reviewed in the same PR as the
code. Two layers keep them honest:

- **Generated reference** — `docs/reference/{endpoints,mcp-tools,config,cli}.md` is
  produced from the code by `tools/docgen` (the actual routes, MCP tool schemas,
  config structs, and CLI). **Do not edit these by hand.** Run `make docs-gen` and
  commit the result; CI fails if the committed files differ from a fresh generation.
- **Strict build** — `mkdocs build --strict` fails on a broken internal link or a
  renamed anchor, and the example configs are validated against the Go structs.

Run **`make verify`** before pushing — it runs the whole mechanical gate locally
(gofmt, vet, build, race tests, and this docs gate; the site build needs
`pip install --require-hashes -r requirements-docs.txt` once — the file is a
hashed pip-compile lock of `requirements-docs.in`). `make docs-check` runs the docs
gate alone; `make docs-serve` previews the site.

These are not advisory: the `build`, `govulncheck` and `check` workflow jobs are
**required status checks** on the protected `main` branch, so a red gate blocks
the merge. (`gh pr merge --admin` exists as an explicit emergency bypass — do
not use it to skip a failing gate.)

### Mandatory pre-commit checklist (living docs)

**Before any commit that changes code, configuration, or behavior**, update the
living documentation. A commit without these updates asserts that nothing
externally visible changed (internal refactor only).

1. **`make docs-gen`** if you changed an HTTP route, an MCP tool schema, a config
   struct, or the `broker-ctl` CLI — then commit the regenerated `docs/reference/`.
2. **`CHANGELOG.md`** — add a bullet under the `## [Unreleased]` section at the
   **top** (create it if the last release folded it away); the version heading
   is written only by the release procedure:
   ```markdown
   ## [Unreleased]

   ### Security / Added / Fixed / Documentation / Internal
   - **Short title (#N)** — what changed and why it matters.
   ```
3. **`README.md`** — reflect any change to the public interface, configuration,
   new options, security sections, or pending-work status.
4. **`API.md`** — the per-endpoint **prose** (request/response bodies, auth, error
   codes). The route inventory itself is generated; this is the human explanation.
5. **`USAGE.md`** — if an MCP tool's usage guidance changed (the tool schema is
   generated; this is the how-to for the model/operator).

When a change touches design rationale, runbook steps, or the security posture,
also update [ARCHITECTURE.md](ARCHITECTURE.md), [OPERATIONS.md](OPERATIONS.md),
or [THREAT_MODEL.md](THREAT_MODEL.md) respectively. Finally, `make docs-check` must
pass.

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

Quick checklist (from [CODING_STYLE.md](CODING_STYLE.md)); `make verify` runs
the mechanical ones — fmt, vet, build, race tests, docs gate — in one shot:

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
