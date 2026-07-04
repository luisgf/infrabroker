---
name: deploy
description: Deploy infrabroker to production (or upgrade an existing install) using make dist + deploy/install.sh, with preflight policy checks, operator choice of CA custody (Azure Key Vault vs local PEM), and post-deploy health verification. Use when the user asks to deploy, release, install as a service, or upgrade infrabroker on a host.
---

# Deploy infrabroker to production

The deterministic mechanics live in the repo — `make dist`, `deploy/install.sh`,
the systemd units in `deploy/systemd/` and the checklist in `deploy/README.md`.
This skill adds the judgment layer: what to verify before, what to ask the
operator, and how to confirm the deployment is healthy after.

## 0. Scope the deployment

Ask (or infer from the request) before doing anything:

- **Which services on which host?** `signer` (CA custody — ideally its own
  host), `control-plane` (approvals), `mcp-http` (remote MCP frontend). The
  stdio `mcp-broker` is launched by the MCP client and is never deployed as a
  service.
- **Fresh install or upgrade?** An upgrade replaces binaries + units and keeps
  `/etc/infrabroker/*.json`; a fresh install seeds configs from the examples
  that MUST be edited before starting.
- **Local or remote target?** The installer runs as root ON the target host.
  For a remote target: `make dist`, copy the tarball with scp, then run the
  installer over ssh.

## 1. CA custody — the operator chooses

This is an explicit decision the user must make; never default silently.
Set in `signer.json` → `ca_keys` (`"_default"` = global; per-group keys
override). Backends supported by the code (`internal/ca/loader.go`):

- **`akv` (Azure Key Vault) — recommended for production.** The private key
  never leaves the vault. Needs `vault_url` + `key_name`. Auth via
  `DefaultAzureCredential`: managed identity needs nothing; a service
  principal needs `AZURE_TENANT_ID`/`AZURE_CLIENT_ID`/`AZURE_CLIENT_SECRET`
  in `/etc/infrabroker/signer.env` (0600 root, loaded by the unit).
  **Constraint:** AKV has no Ed25519 — the CA will be RSA or EC, and the
  managed hosts' `TrustedUserCAKeys` must carry that public key
  (`az keyvault key download` + `ssh-keygen -i -m PKCS8`).
- **`pem` (local file) — lab/dev only.** The signer logs a warning at startup.
  If the user picks this for production, warn once about the threat model
  (key readable on disk) and respect their choice.

If the user hasn't stated a preference, ask which backend to use, presenting
exactly this trade-off.

## 1b. Kubernetes target (only if `kubernetes.clusters` is configured)

The per-cluster minter credential (`token_file`) is the signer's **only
standing cluster credential** — treat it like the CA key:

- Lives under the signer's state dir (e.g.
  `/var/lib/infrabroker/signer/pki/<cluster>-minter.token`), `0600`, owned by
  `infrabroker-signer`. Never under the shared `/etc/infrabroker/pki` root.
- Its RBAC in the cluster must be minimal: `create` on
  `serviceaccounts/token` for the bound SAs only. If the user hands you a
  broader credential, flag it before deploying.
- Cluster names must stay disjoint from host names (the signer refuses
  otherwise); every cluster is default-deny until it has ≥1 allow rule and an
  `sa_bindings` entry.

## 2. Preflight (before touching the target)

Run from the repo:

- `make verify` passes (gofmt, vet, build, race tests, and the full docs gate
  including the example-config validation).
- `make version` — confirm the tag you are about to ship; a `-dirty` suffix
  means uncommitted changes: stop and ask.
- Review the real config that will run for production posture (the signer
  config is `/var/lib/infrabroker/signer/signer.json` — service-owned so the
  durable policy API can rewrite it; control-plane/mcp-http configs are under
  `/etc/infrabroker/`):
  - `callers` contains `"_default": {"allowed_groups": []}` — default-deny.
    Its absence is the #1 fail-open misconfiguration; flag it.
  - `reload_callers` lists the admin CN. Without it there is no HTTP reload,
    no policy mutation API, and the post-deploy E2E check
    (`host list --remote`) gets 403 — only local SIGHUP remains.
  - `sign_rate_limit_per_min` set (> 0).
  - `monitor_listen` bound to localhost/private interface, never public.
  - `state_db` set in `signer.json` and `control-plane.json`
    (`/var/lib/infrabroker/<svc>/state.db`) so grants/waivers and pending
    approvals survive restarts. Its absence is not an error, but changes the
    restart trade-offs in step 4 — say so.
  - `redact` block present in the three configs (secrets in commands masked in
    audit logs, recordings, notifications).
  - Cert/key paths are ABSOLUTE and point into the service's OWN pki subdir
    (`/etc/infrabroker/pki/<svc>/...`); a relative `audit_log` is fine (lands
    in `/var/lib/infrabroker/<svc>/`).
  - Every host with `"jump"` shares a group with its bastion.
  - `/etc/infrabroker/broker-ctl.json` (client parameters) points `signer.url`
    at the real signer and cert/key/ca at the real PKI, with a cert whose CN
    is in `reload_callers` — this is what makes every later `broker-ctl`
    step in this skill work flag-less.
- **Upgrade only:** snapshot the live policy BEFORE touching anything —
  `broker-ctl host list --remote > /tmp/policy-before.txt` — and diff it
  against the same command after the upgrade. An unexpected delta means the
  config file that shipped does not match what was really running (e.g.
  un-persisted mutations or a stale file). If `state_db` is configured, back
  up each `state.db` **with its `-wal`/`-shm` sidecars** before replacing
  binaries.

## 3. Install

```bash
make dist                                   # dist/infrabroker-<version>.tar.gz
# remote target:
scp dist/infrabroker-<v>.tar.gz host:  &&  ssh host 'tar xzf infrabroker-<v>.tar.gz'
sudo ./deploy/install.sh [--services "..."]
```

Idempotent; never overwrites an existing real config. On a fresh install, edit
the seeded configs (`/var/lib/infrabroker/signer/signer.json` for the signer,
`/etc/infrabroker/*.json` for the rest) and place the mTLS PKI before starting:
each service's cert+key in ITS subdir `/etc/infrabroker/pki/<svc>/`
(`0640 root:infrabroker-<svc>`), the shared `mtls_ca.crt` at the `pki/` root,
admin CLI material in `pki/admin/` (root-only). Services run as per-service
users (`infrabroker-<svc>`) — privilege separation, see `deploy/README.md`.
That includes the seeded `/etc/infrabroker/broker-ctl.json`: point its `signer` /
`control_plane` sections at the installed PKI so the admin CLI needs no
flags (precedence: flag > `BROKER_CTL_*` env > file > default).

**Upgrade from ≤ v1.34 (single-user layout):** the installer converges users,
state-dir and config ownership automatically, and WARNS about private keys
still flat under `pki/` — those must be moved into the per-service subdirs and
the config paths updated before restarting (see `deploy/README.md` §Upgrades).

## 4. Start / apply

- **Order matters:** signer first, then control-plane / mcp-http
  (`systemctl enable --now infrabroker-signer`, then the rest).
- **Upgrade of an already-running install:** decide reload vs restart.
  Policy-only changes (hosts, callers, command policies, CA keys) →
  `systemctl reload infrabroker-signer` (SIGHUP) or `broker-ctl reload`
  (flag-less via the client config; works from another machine), no
  downtime. New binaries, `listen`, TLS material or `audit_log` → restart.
  Warn before restarting, scaled to whether `state_db` is configured:
  **with** it, runtime grants/waivers and pending approvals survive and only
  the behaviour baseline (re-learns) and live MCP sessions are lost;
  **without** it, a control-plane restart also drops pending approvals and a
  signer restart drops runtime grants/waivers.

## 5. Verify

- `systemctl status` on each installed unit; `journalctl -u <unit> -n 20`
  clean of errors. With `pem` custody a CA warning line is expected.
- **Privilege separation holds** — each unit runs as ITS user, and the
  isolation is real, not assumed:

  ```bash
  systemctl show -p User infrabroker-signer infrabroker-control-plane infrabroker-mcp-http
  # expect infrabroker-signer / infrabroker-control-plane / infrabroker-mcp-http
  runuser -u infrabroker-mcp-http -- cat /var/lib/infrabroker/signer/signer.json
  # MUST fail (Permission denied) — if it reads, the layout regressed to shared
  ```
- `curl -s http://127.0.0.1:9160/healthz` (signer monitor) and the
  control-plane equivalent (`:9170` by default).
- End-to-end — proves mTLS, `reload_callers` authorization and full policy
  load in one shot (plain `broker-ctl host list` reads the local file and
  proves nothing):

  ```bash
  broker-ctl host list --remote
  ```

  URL and certs come from `/etc/infrabroker/broker-ctl.json` (seeded by the
  installer; flags/`BROKER_CTL_SIGNER_*` override). The client cert CN must
  be in the signer's `reload_callers`. Expect the full table (principal, TTL,
  groups, policy) reflecting the live in-memory state. On an upgrade, diff it
  against the pre-upgrade snapshot from step 2. This read also lands a
  `policy-read` entry in `/var/lib/infrabroker/signer/signer_audit.log` —
  check it is there: it proves the audit pipeline in the same pass.
- RBAC default-deny check, separately — the admin read above bypasses group
  filtering, so it cannot prove it. With a cert whose CN is NOT in `callers`:

  ```bash
  curl -s --cert other.crt --key other.key --cacert mtls_ca.crt \
    https://<signer>:9443/v1/hosts
  ```

  Expect `{}` when `callers._default` is default-deny.
- **Kubernetes target only:** `broker-ctl cluster list --remote` returns the
  configured clusters (proves the signer loaded them and the mTLS path); the
  minter `token_file` is `0600 infrabroker-signer` and NOT readable by the
  other service users.
- `signer --version` matches the tag shipped in step 2.

Report what was deployed (services, host, version, custody backend) and any
checklist deviations the operator accepted.
