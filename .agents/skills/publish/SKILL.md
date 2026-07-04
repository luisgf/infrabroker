---
name: publish
description: Cut and publish a new infrabroker release end-to-end — semver bump, CHANGELOG, server.json + HANDOFF, make verify, release PR, annotated tag, and the CI-driven GitHub release + multi-arch ghcr image + MCP Registry publish. Use when the user asks to publish, cut/ship/tag a release, bump the version and release, or make a new version.
---

# Publish an infrabroker release

The deterministic mechanics live in the repo: `.github/workflows/release.yml`
(triggered by a `v*.*.*` tag) runs goreleaser and the `mcp-registry` job, and
`make verify` is the local gate. This skill is the judgment layer around them:
pick the right version, prepare the release commit, drive it through review, tag
it, and confirm every published surface came out right.

**The publish pipeline, end to end:**

1. Prepare a release commit — `docs/CHANGELOG.md`, `server.json`, `docs/HANDOFF.md`.
2. `make verify` green.
3. Branch → PR → **human review + merge to `main`**.
4. Annotated tag `vX.Y.Z` on the merged commit → `git push origin vX.Y.Z`.
5. `release.yml` fires (you do NOT run goreleaser or mcp-publisher locally):
   - job **`release`** → goreleaser: GitHub release, 4 per-platform archives +
     `checksums.txt`, the installer tarball (`infrabroker-vX.Y.Z.tar.gz` +
     `installer.sha256`), and multi-arch images to `ghcr.io/luisgf/infrabroker`
     (`X.Y.Z` + `latest`).
   - job **`mcp-registry`** (`needs: release`) → GitHub OIDC → `publisher publish`
     → `server.json` to the MCP Registry.
6. Verify all three surfaces (GitHub release, ghcr, MCP Registry).

Steps 1–4 are yours; step 5 is CI; step 6 is confirmation. Two steps are human
gates you must not bypass: the **PR merge** and the **tag push**.

## Prerequisites (verify once; abort with a clear message if missing)

- `gh auth status` OK, `origin` = `luisgf/infrabroker`.
- On `main`, clean tree, synced: `git checkout main && git pull --ff-only origin main`.
  Never cut a release off a feature branch or a dirty tree.
- Docs toolchain for `make verify`: a venv with `pip install -r requirements-docs.txt`
  (provides `mkdocs`), and `govulncheck` on `PATH` (`go install
  golang.org/x/vuln/cmd/govulncheck@latest`). A missing `mkdocs` is an ENVIRONMENT
  error to fix, not a reason to skip the gate.
- `mcp-publisher` for `mcp-publisher validate server.json` (Homebrew:
  `brew install mcp-publisher`). Optional but do it — the live registry schema
  rots.

### This machine's shell gotchas (zsh; they recur every session)

- `make`, `diff`, and some others are broken autoload stubs
  (`function definition file not found`). Use the absolute binary: **`/usr/bin/make`**,
  `/usr/bin/diff`.
- `cp`/`mv` are aliased to `-i` (interactive) → they hang on a prompt in
  background/non-interactive runs. Use `command cp -f` / `command mv -f`, or just
  Edit/Write the file.
- `noclobber` is on: `>` over an existing file fails ("file exists"). Use `>|`,
  or Write/Edit.
- For the gate, put the venv and Go bin on PATH first:
  `export PATH="$PWD/.venv/bin:$(go env GOPATH)/bin:$PATH"` then `/usr/bin/make verify`.

See `memory/project-operations.md` (branch protection, required checks) and
`memory/project-ssh-broker.md` (versioning) for the durable context.

## STEP 1 — Determine the version (semver; state your reasoning)

```
git describe --tags --abbrev=0            # last released tag, e.g. v1.38.0
git log --oneline <last-tag>..HEAD        # what shipped since
```

- **MAJOR** (`X`+1): a breaking change (a `!` commit type, or a documented
  incompatible change).
- **MINOR** (`Y`+1): any new user-facing feature (`feat:`) — a new command, tool,
  route, or config surface.
- **PATCH** (`Z`+1): only fixes / docs / chore / internal cleanup, no new surface.

Announce the computed version and *why* (cite the commits that drive the level).
If the bump level is genuinely ambiguous, ask the user before proceeding — the
version is stamped into the tag, the image, the registry, and is not cleanly
reversible.

## STEP 2 — Prepare the release files

- **`docs/CHANGELOG.md`** — prepend a new section at the top (above the previous
  version), dated with the real current date:

  ```
  ## [vX.Y.Z] - YYYY-MM-DD

  <one-line theme of the release>

  ### Added / ### Changed / ### Fixed / ### Internal
  - user-facing, honest bullets; describe impact, don't over-claim.
  ```

  Summarize the `git log` since the last tag. Match the existing entries' voice.

- **`server.json`** — bump BOTH:
  - `"version": "X.Y.Z"`
  - the OCI `"identifier": "ghcr.io/luisgf/infrabroker:X.Y.Z"` — **no `v` prefix**
    (parity with the image tag goreleaser derives from `{{ .Version }}`).

  Then validate: `mcp-publisher validate server.json` → must print
  `✅ server.json is valid`. The `description` must stay **≤100 chars** and
  `$schema` must be the current registry schema (a deprecated schema URL is a
  real failure).

- **`docs/HANDOFF.md`** — update the "última actualización" header line to the new
  version and add a concise `vX.Y.Z` bullet at the top of "Estado reciente".

## STEP 3 — Verify (must be green before tagging)

```
export PATH="$PWD/.venv/bin:$(go env GOPATH)/bin:$PATH"
/usr/bin/make verify
```

gofmt + vet + build + `go test -race ./...` + govulncheck + docs drift gate +
strict mkdocs. If `docgen` regenerated `docs/reference/`, COMMIT those files with
the release commit (the gate only DETECTS drift). Fix forward — never tag a red
tree.

## STEP 4 — Branch, PR, merge (human gate)

Follow the repo convention (`git log` shows `release/vX.Y.Z-changelog` branches):

```
git checkout -b release/vX.Y.Z-changelog
git commit -F - <<'EOF'
chore: prepare vX.Y.Z release (changelog, server.json, handoff)

<why this level; what shipped>
EOF
git push -u origin release/vX.Y.Z-changelog
gh pr create --base main --title "chore: vX.Y.Z release (changelog + version bump)" --body "..."
```

One logical commit. **Never add a `Co-Authored-By` / "Generated with" /
assistant-attribution trailer.** Wait for the required checks — **`build`,
`check`, `govulncheck`** — to pass; `deploy`/`wiki-mirror` show `skipping` on a
PR, which is expected. Never `gh pr merge --admin` past a red gate.

**MERGE IS A HUMAN GATE.** The auto-mode guardrail blocks the agent from merging
a PR it authored this session without explicit human review (two-party review).
Ask the user to review and merge, or to explicitly authorize the merge (e.g.
"merge #NN") — then `gh pr merge <NN> --merge --delete-branch`. Do NOT work
around it (no manual `git push`/`git merge` to `main`).

## STEP 5 — Tag & publish (human-authorized, irreversible)

After the PR is merged:

```
git checkout main && git pull --ff-only origin main
grep -E '"version"|identifier' server.json     # confirm X.Y.Z landed on main
# confirm the auto-publish job is present AND wired to run after the image exists:
grep -qE '^\s*mcp-registry:' .github/workflows/release.yml && \
  grep -q 'needs: release' .github/workflows/release.yml && echo "mcp-registry job OK"
git tag -a vX.Y.Z -m "vX.Y.Z — <summary>"      # annotated tag on the merged commit
git push origin vX.Y.Z                          # <-- THE PUBLISH
```

**The tag push is the irreversible publish** — it creates a public GitHub release
and pushes public ghcr images. Do it only with explicit user authorization.

Do NOT run `goreleaser`, push images, or run `mcp-publisher publish` yourself —
`release.yml` owns all of it on the tag push. The `mcp-registry` job authenticates
with GitHub OIDC and only runs after the image exists (`needs: release`), because
the registry validates OCI ownership by pulling the image and reading its
`io.modelcontextprotocol.server.name` label (which must equal `server.json`'s
`name`).

## STEP 6 — Watch the release run and verify the surfaces

```
gh run list --workflow=release.yml --limit 3          # find the run for the tag
gh run view <run-id> --json conclusion,jobs --jq '.conclusion, (.jobs[]|"\(.name): \(.status)/\(.conclusion)")'
```

Both jobs must be `success` — the goreleaser `release` job AND the `mcp-registry`
job (don't stop at "the GitHub release exists"). Then confirm each surface:

```
gh release view vX.Y.Z --json assets --jq '[.assets[].name]'
# expect: checksums.txt, infrabroker-vX.Y.Z.tar.gz, 4x infrabroker_X.Y.Z_{os}_{arch}.tar.gz, installer.sha256

curl -s "https://registry.modelcontextprotocol.io/v0/servers?search=infrabroker" | \
  python3 -c "import sys,json; [print(s['server']['name'], s['server']['version'], s['_meta']['io.modelcontextprotocol.registry/official']['status']) for s in json.load(sys.stdin)['servers']]"
# expect a row: io.github.luisgf/infrabroker  X.Y.Z  active
```

If `mcp-registry` fails *after* `release` succeeded, the GitHub release and image
are already published — re-run just that job (fixing OIDC/CLI as needed). The
registry rejects a duplicate version, so never re-publish an already-published
version.

## Guardrails (hard rules)

- The **PR merge** and the **tag push** are human gates — get explicit
  authorization; never circumvent them.
- Never `--admin`-bypass a red required check; a red gate is protection working.
- Never publish secrets/keys/real configs (`config.json`, `signer.json`,
  `broker-ctl.json`, `control-plane.json`, `*.env`, `pki/`, `dist/`).
- Semver honestly — don't inflate or deflate the bump to avoid a decision.
- No assistant-attribution trailers on commits or tags.
- `server.json`'s OCI identifier must reference the version being published; the
  image only exists after the tag's `release` job runs (hence `mcp-registry` is
  `needs: release`) — never point it at an unpublished tag.
- Leave `main` synced to the tagged commit and the tree clean when done.
