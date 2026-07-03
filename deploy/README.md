# Production deployment

Artifacts to run ssh-broker as system services. For day-2 operations
(adding hosts, hot reload, PKI, monitoring) see `docs/OPERATIONS.md`; for
what to harden and why, `docs/THREAT_MODEL.md`.

## Contents

| File | Purpose |
|---|---|
| `systemd/ssh-broker-signer.service` | Signing service — CA custody + issuance policy |
| `systemd/ssh-broker-control-plane.service` | Approvals + behaviour guardrails |
| `systemd/ssh-broker-mcp-http.service` | Remote MCP frontend (Streamable HTTP + OIDC) |
| `install.sh` | Idempotent installer (run as root on the target host) |
| `sshd_config.snippet` | Configuration for the *managed* hosts' sshd |

The local stdio frontend (`cmd/mcp-broker`) needs no unit: the MCP client
launches it on connect.

## Quick start

```bash
# On a build machine
make dist                                  # → dist/ssh-broker-<version>.tar.gz

# On the target host
tar xzf ssh-broker-<version>.tar.gz && cd ssh-broker-<version>
sudo ./deploy/install.sh                   # everything; or --services "signer"
```

The installer creates **one system user per service**, installs binaries to
`/usr/local/bin`, configs to `/etc/ssh-broker/` (never overwriting an
existing one) and the units to `/etc/systemd/system`. It does **not** start
anything: a fresh config still points at example values.

## Privilege separation — one user per service

Each service runs as its own system user: `ssh-broker-signer`,
`ssh-broker-control-plane`, `ssh-broker-mcp-http`. The shared `ssh-broker`
group exists **only** to traverse `/etc/ssh-broker` and read the shared mTLS
CA certificate; everything sensitive carries the per-service user/group.

Why: the broker frontends are the exposed surface. Under a single shared user,
a compromised mcp-http process could **read** the signer's config (the whole
policy), its `state.db` (grants), its audit seed, the k8s minter token, the
local CA key under `pem` custody — and every other service's mTLS key, i.e.
impersonate the signer. With per-service users none of that is readable; the
systemd sandbox (`ProtectSystem=strict` + per-unit `StateDirectory`) already
contained writes. Running the signer on a **separate host** remains the
stronger posture (see `THREAT_MODEL.md`); this hardens the colocated layout.

## Reference layout

```
/usr/local/bin/{signer,control-plane,mcp-broker-http,broker-ctl}
/etc/ssh-broker/control-plane.json      root:ssh-broker-control-plane 0640
/etc/ssh-broker/config.json             root:ssh-broker-mcp-http 0640
/etc/ssh-broker/broker-ctl.json         root:ssh-broker 0640 (admin CLI params)
/etc/ssh-broker/pki/mtls_ca.crt         root:ssh-broker 0640 (shared, public)
/etc/ssh-broker/pki/<svc>/              root:ssh-broker-<svc> 0750, keys 0640
/etc/ssh-broker/pki/admin/              root 0700 (broker-ctl admin cert+key)
/etc/ssh-broker/signer.env              optional AZURE_* creds (0600 root)
/var/lib/ssh-broker/signer/signer.json  ssh-broker-signer 0640
/var/lib/ssh-broker/<svc>/              state + audit logs (ssh-broker-<svc>)
```

The **signer config lives under `/var/lib/ssh-broker/signer/`**, owned by the
service, not under `/etc` — the durable policy-mutation API (`broker-ctl policy
add/remove`) rewrites it in place, which the read-only `/etc` tree would block.
The other services' configs stay root-owned in `/etc` with the per-service
group (they can carry secrets — OIDC client, webhook tokens — so no service
reads another's). Each private key goes in its service's `pki/<svc>/`
subdirectory: a key dropped there is protected by the directory ownership
alone. The admin CLI material in `pki/admin/` is root-only — no service can
impersonate the admin.

Configs must use **absolute** paths for certs/keys; a relative `audit_log`
resolves under `/var/lib/ssh-broker/<svc>/` (the unit's WorkingDirectory),
which is where audit logs belong.

## Choosing CA custody

The CA custody backend is **the operator's choice**, made in `signer.json`
under `ca_keys` (globally with the reserved `_default` key, and optionally
per group):

| | `"akv"` — Azure Key Vault | `"pem"` — local file |
|---|---|---|
| Private key exposure | Never leaves the vault; broker/signer compromise cannot exfiltrate it | On disk; readable by the signer process |
| Key types | RSA 2048/3072/4096, EC P-256/P-384/P-521 (no Ed25519) | Any OpenSSH type, incl. Ed25519 |
| Credentials | `DefaultAzureCredential`: managed identity (recommended, zero config) or service principal via `/etc/ssh-broker/signer.env` | — |
| Intended use | **Production** | Lab/dev (the signer logs a warning) |

```jsonc
// signer.json — production (AKV)
"ca_keys": {
  "_default": { "type": "akv", "vault_url": "https://my-vault.vault.azure.net", "key_name": "ssh-ca" }
}

// signer.json — lab (PEM)
"ca_keys": {
  "_default": { "type": "pem", "path": "/etc/ssh-broker/pki/ssh_ca" }
}
```

With AKV, the managed hosts still need the CA **public** key in OpenSSH
format for `TrustedUserCAKeys`:

```bash
az keyvault key download --vault-name my-vault -n ssh-ca -f ca.pem
ssh-keygen -i -m PKCS8 -f ca.pem > /etc/ssh/ca_prod.pub
```

Service-principal credentials go in `/etc/ssh-broker/signer.env`
(`0600 root:root`, loaded by the unit's `EnvironmentFile=`):

```
AZURE_TENANT_ID=...
AZURE_CLIENT_ID=...
AZURE_CLIENT_SECRET=...
```

## Production checklist

- [ ] `signer.json` `callers` has `"_default": {"allowed_groups": []}` — default-deny for unknown broker CNs.
- [ ] `sign_rate_limit_per_min` set (size to the busiest legitimate broker).
- [ ] CA custody is `akv` (or another KMS); `pem` only in a lab.
- [ ] mTLS PKI split per service: each key in `/etc/ssh-broker/pki/<svc>/`
  (`0640 root:ssh-broker-<svc>`), admin CLI material in `pki/admin/` (root-only),
  only the shared CA **cert** at the `pki/` root. No private key readable by
  more than its own service.
- [ ] `monitor_listen` bound to localhost or a private scrape interface — never public.
- [ ] Signer ideally on a separate host from the broker (see THREAT_MODEL.md).
- [ ] Single instance per service (live sessions and the behaviour baseline are in-memory).
- [ ] `state_db` set in `signer.json` (`/var/lib/ssh-broker/signer/state.db`) and
  `control-plane.json` (`/var/lib/ssh-broker/control-plane/state.db`) so runtime
  grants/waivers and pending approvals survive restarts. Back up the `.db` with
  its `-wal`/`-shm` sidecars.
- [ ] `redact` block enabled in the three configs (secrets in commands are
  masked in audit logs, recordings, and approval notifications).
- [ ] Managed hosts configured per `sshd_config.snippet` (TrustedUserCAKeys, principals, sudoers).

## Order and verification

```bash
sudo systemctl enable --now ssh-broker-signer        # always first
sudo systemctl enable --now ssh-broker-control-plane # if installed
sudo systemctl enable --now ssh-broker-mcp-http      # if installed

curl -s http://127.0.0.1:9160/healthz                # signer liveness (monitor_listen)

# End-to-end: mTLS + reload_callers authz + full policy load in one shot.
# Uses /etc/ssh-broker/broker-ctl.json (seeded by the installer) for URL and
# certs; the client cert CN must be in the signer's reload_callers.
broker-ctl host list --remote

# RBAC default-deny check (separate: the admin read above bypasses group
# filtering). An unknown CN must get {} when callers._default is default-deny:
curl -s --cert other.crt --key other.key --cacert mtls_ca.crt \
     https://<signer>:9443/v1/hosts

journalctl -u ssh-broker-signer -f                   # logs go to the journal
```

Policy changes (`hosts`, `callers`, `command_policies`, CA keys) do **not**
need a restart: `sudo systemctl reload ssh-broker-signer` (SIGHUP), or
`broker-ctl reload`, or `auto_reload_seconds`. Only `listen`, TLS material
and `audit_log` require a restart.

## Upgrades

```bash
sudo ./deploy/install.sh          # replaces binaries + units, keeps configs
sudo systemctl restart ssh-broker-signer ssh-broker-control-plane ssh-broker-mcp-http
signer --version                  # verify the embedded version
```

**Upgrading from a single-user install (≤ v1.34)**: the installer creates the
per-service users, re-owns the state directories and configs, and installs the
new units automatically. What it can **not** do is guess which mTLS key belongs
to which service — it warns about private keys still sitting flat under
`pki/` (readable by every service, the exposure this layout removes). Move
each one and update the config paths before restarting:

```bash
sudo mv /etc/ssh-broker/pki/signer.key /etc/ssh-broker/pki/signer.crt /etc/ssh-broker/pki/signer/
sudo chown root:ssh-broker-signer /etc/ssh-broker/pki/signer/*
# ... same for control-plane/ and mcp-http/; broker-ctl material → pki/admin/
```

Then restart the units (§Upgrades). Only **after** the services are running as
their new per-service users can the legacy shared account be retired — while
the old units are still up they hold it open and `userdel` refuses:

```bash
sudo userdel ssh-broker            # optional; fails if any process still uses it
```

With `state_db` configured, runtime grants/waivers (signer) and pending or
approved-but-uncollected approvals (control plane) survive a restart. What is
still lost by design: the behaviour baseline (re-learns quickly) and live MCP
sessions on mcp-http (TCP connections cannot be resurrected). Plan accordingly.
