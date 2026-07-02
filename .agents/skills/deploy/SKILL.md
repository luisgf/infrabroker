---
name: deploy
description: Deploy ssh-broker to production (or upgrade an existing install) using make dist + deploy/install.sh, with preflight policy checks, operator choice of CA custody (Azure Key Vault vs local PEM), and post-deploy health verification. Use when the user asks to deploy, release, install as a service, or upgrade ssh-broker on a host.
---

# Deploy ssh-broker to production

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
  `/etc/ssh-broker/*.json`; a fresh install seeds configs from the examples
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
  in `/etc/ssh-broker/signer.env` (0600 root, loaded by the unit).
  **Constraint:** AKV has no Ed25519 — the CA will be RSA or EC, and the
  managed hosts' `TrustedUserCAKeys` must carry that public key
  (`az keyvault key download` + `ssh-keygen -i -m PKCS8`).
- **`pem` (local file) — lab/dev only.** The signer logs a warning at startup.
  If the user picks this for production, warn once about the threat model
  (key readable on disk) and respect their choice.

If the user hasn't stated a preference, ask which backend to use, presenting
exactly this trade-off.

## 2. Preflight (before touching the target)

Run from the repo:

- `make test` and `make docs-check` pass (docs-check also validates the
  example configs against the structs).
- `make version` — confirm the tag you are about to ship; a `-dirty` suffix
  means uncommitted changes: stop and ask.
- Review the real config that will run (existing `/etc/ssh-broker/*.json` on
  upgrade, or the edited seed on fresh install) for production posture:
  - `callers` contains `"_default": {"allowed_groups": []}` — default-deny.
    Its absence is the #1 fail-open misconfiguration; flag it.
  - `sign_rate_limit_per_min` set (> 0).
  - `monitor_listen` bound to localhost/private interface, never public.
  - Cert/key paths are ABSOLUTE (`/etc/ssh-broker/pki/...`); a relative
    `audit_log` is fine (lands in `/var/lib/ssh-broker/<svc>/`).
  - Every host with `"jump"` shares a group with its bastion.

## 3. Install

```bash
make dist                                   # dist/ssh-broker-<version>.tar.gz
# remote target:
scp dist/ssh-broker-<v>.tar.gz host:  &&  ssh host 'tar xzf ssh-broker-<v>.tar.gz'
sudo ./deploy/install.sh [--services "..."]
```

Idempotent; never overwrites an existing real config. On a fresh install,
edit `/etc/ssh-broker/*.json` and place the mTLS PKI before starting.

## 4. Start / apply

- **Order matters:** signer first, then control-plane / mcp-http
  (`systemctl enable --now ssh-broker-signer`, then the rest).
- **Upgrade of an already-running install:** decide reload vs restart.
  Policy-only changes (hosts, callers, command policies, CA keys) →
  `systemctl reload ssh-broker-signer` (SIGHUP), no downtime. New binaries,
  `listen`, TLS material or `audit_log` → restart. Warn before restarting:
  control-plane restart drops pending approvals and the behaviour baseline;
  mcp-http restart drops live MCP sessions.

## 5. Verify

- `systemctl status` on each installed unit; `journalctl -u <unit> -n 20`
  clean of errors. With `pem` custody a CA warning line is expected.
- `curl -s http://127.0.0.1:9160/healthz` (signer monitor) and the
  control-plane equivalent (`:9170` by default).
- End-to-end — proves mTLS, `reload_callers` authorization and full policy
  load in one shot (plain `broker-ctl host list` reads the local file and
  proves nothing):

  ```bash
  broker-ctl host list --remote
  ```

  URL and certs come from `/etc/ssh-broker/broker-ctl.json` (seeded by the
  installer; flags/`BROKER_CTL_SIGNER_*` override). The client cert CN must
  be in the signer's `reload_callers`. Expect the full table (principal, TTL,
  groups, policy) reflecting the live in-memory state.
- RBAC default-deny check, separately — the admin read above bypasses group
  filtering, so it cannot prove it. With a cert whose CN is NOT in `callers`:

  ```bash
  curl -s --cert other.crt --key other.key --cacert mtls_ca.crt \
    https://<signer>:9443/v1/hosts
  ```

  Expect `{}` when `callers._default` is default-deny.
- `signer --version` matches the tag shipped in step 2.

Report what was deployed (services, host, version, custody backend) and any
checklist deviations the operator accepted.
