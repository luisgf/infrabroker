# Production deployment

Artifacts to run infrabroker as system services. For day-2 operations
(adding hosts, hot reload, PKI, monitoring) see `docs/OPERATIONS.md`; for
what to harden and why, `docs/THREAT_MODEL.md`.

## Contents

| File | Purpose |
|---|---|
| `systemd/infrabroker-signer.service` | Signing service — CA custody + issuance policy |
| `systemd/infrabroker-control-plane.service` | Approvals + behaviour guardrails |
| `systemd/infrabroker-mcp-http.service` | Remote MCP frontend (Streamable HTTP + OIDC) |
| `install.sh` | Idempotent installer (run as root on the target host) |
| `sshd_config.snippet` | Configuration for the *managed* hosts' sshd |

The local stdio frontend (`cmd/mcp-broker`) needs no unit: the MCP client
launches it on connect.

## Quick start

```bash
# On a build machine
make dist                                  # → dist/infrabroker-<version>.tar.gz

# On the target host
tar xzf infrabroker-<version>.tar.gz && cd infrabroker-<version>
sudo ./deploy/install.sh                   # everything; or --services "signer"
```

The installer creates **one system user per service**, installs binaries to
`/usr/local/bin`, configs to `/etc/infrabroker/` (never overwriting an
existing one) and the units to `/etc/systemd/system`. It does **not** start
anything: a fresh config still points at example values.

## Privilege separation — one user per service

Each service runs as its own system user: `infrabroker-signer`,
`infrabroker-control-plane`, `infrabroker-mcp-http`. The shared `infrabroker`
group exists **only** to traverse `/etc/infrabroker` and read the shared mTLS
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
/etc/infrabroker/control-plane.json      root:infrabroker-control-plane 0640
/etc/infrabroker/config.json             root:infrabroker-mcp-http 0640
/etc/infrabroker/broker-ctl.json         root:infrabroker 0640 (admin CLI params)
/etc/infrabroker/pki/mtls_ca.crt         root:infrabroker 0640 (shared, public)
/etc/infrabroker/pki/<svc>/              root:infrabroker-<svc> 0750, keys 0640
/etc/infrabroker/pki/admin/              root 0700 (broker-ctl admin cert+key)
/etc/infrabroker/signer.env              optional AZURE_* creds (0600 root)
/var/lib/infrabroker/signer/signer.json  infrabroker-signer 0640
/var/lib/infrabroker/<svc>/              state + audit logs (infrabroker-<svc>)
```

The **signer config lives under `/var/lib/infrabroker/signer/`**, owned by the
service, not under `/etc` — the durable policy-mutation API (`broker-ctl policy
add/remove`) rewrites it in place, which the read-only `/etc` tree would block.
The other services' configs stay root-owned in `/etc` with the per-service
group (they can carry secrets — OIDC client, webhook tokens — so no service
reads another's). Each private key goes in its service's `pki/<svc>/`
subdirectory: a key dropped there is protected by the directory ownership
alone. The admin CLI material in `pki/admin/` is root-only — no service can
impersonate the admin.

Configs must use **absolute** paths for certs/keys; a relative `audit_log`
resolves under `/var/lib/infrabroker/<svc>/` (the unit's WorkingDirectory),
which is where audit logs belong.

## Choosing CA custody

The CA custody backend is **the operator's choice**, made in `signer.json`
under `ca_keys` (globally with the reserved `_default` key, and optionally
per group):

| | `"akv"` — Azure Key Vault | `"pem"` — local file |
|---|---|---|
| Private key exposure | Never leaves the vault; broker/signer compromise cannot exfiltrate it | On disk; readable by the signer process |
| Key types | RSA 2048/3072/4096, EC P-256/P-384/P-521 (no Ed25519) | Any OpenSSH type, incl. Ed25519 |
| Credentials | `DefaultAzureCredential`: managed identity (recommended, zero config) or service principal via `/etc/infrabroker/signer.env` | — |
| Intended use | **Production** | Lab/dev (the signer logs a warning) |

```jsonc
// signer.json — production (AKV)
"ca_keys": {
  "_default": { "type": "akv", "vault_url": "https://my-vault.vault.azure.net", "key_name": "ssh-ca" }
}

// signer.json — lab (PEM)
"ca_keys": {
  "_default": { "type": "pem", "path": "/etc/infrabroker/pki/ssh_ca" }
}
```

With AKV, the managed hosts still need the CA **public** key in OpenSSH
format for `TrustedUserCAKeys`:

```bash
az keyvault key download --vault-name my-vault -n ssh-ca -f ca.pem
ssh-keygen -i -m PKCS8 -f ca.pem > /etc/ssh/ca_prod.pub
```

Service-principal credentials go in `/etc/infrabroker/signer.env`
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
- [ ] mTLS PKI split per service: each key in `/etc/infrabroker/pki/<svc>/`
  (`0640 root:infrabroker-<svc>`), admin CLI material in `pki/admin/` (root-only),
  only the shared CA **cert** at the `pki/` root. No private key readable by
  more than its own service.
- [ ] `monitor_listen` bound to localhost or a private scrape interface — never public.
- [ ] Signer ideally on a separate host from the broker (see THREAT_MODEL.md).
- [ ] Single instance per service (live sessions and the behaviour baseline are in-memory).
- [ ] `state_db` set in `signer.json` (`/var/lib/infrabroker/signer/state.db`) and
  `control-plane.json` (`/var/lib/infrabroker/control-plane/state.db`) so runtime
  grants/waivers and pending approvals survive restarts. Back up the `.db` with
  its `-wal`/`-shm` sidecars.
- [ ] `redact` block enabled in the three configs (secrets in commands are
  masked in audit logs, recordings, and approval notifications).
- [ ] Managed hosts configured per `sshd_config.snippet` (TrustedUserCAKeys, principals, sudoers).

## Order and verification

```bash
sudo systemctl enable --now infrabroker-signer        # always first
sudo systemctl enable --now infrabroker-control-plane # if installed
sudo systemctl enable --now infrabroker-mcp-http      # if installed

curl -s http://127.0.0.1:9160/healthz                # signer liveness (monitor_listen)

# End-to-end: mTLS + reload_callers authz + full policy load in one shot.
# Uses /etc/infrabroker/broker-ctl.json (seeded by the installer) for URL and
# certs; the client cert CN must be in the signer's reload_callers.
broker-ctl host list --remote

# RBAC default-deny check (separate: the admin read above bypasses group
# filtering). An unknown CN must get {} when callers._default is default-deny:
curl -s --cert other.crt --key other.key --cacert mtls_ca.crt \
     https://<signer>:9443/v1/hosts

journalctl -u infrabroker-signer -f                   # logs go to the journal
```

Policy changes (`hosts`, `callers`, `command_policies`, CA keys) do **not**
need a restart: `sudo systemctl reload infrabroker-signer` (SIGHUP), or
`broker-ctl reload`, or `auto_reload_seconds`. Only `listen`, TLS material
and `audit_log` require a restart.

## Upgrades

```bash
sudo ./deploy/install.sh          # replaces binaries + units, keeps configs
sudo systemctl restart infrabroker-signer infrabroker-control-plane infrabroker-mcp-http
signer --version                  # verify the embedded version
```

**Upgrading from ssh-broker (pre-rename, ≤ v1.35)**: the project was renamed
from `ssh-broker` to `infrabroker`; the installer does **not** migrate the old
users, paths or units — running it on top of an old install would create a
parallel tree and the two unit sets would fight over the same ports. Rename in
place first (`usermod -l`/`groupmod -n` keep the UIDs/GIDs, so file ownership
follows):

```bash
sudo systemctl disable --now ssh-broker-signer ssh-broker-control-plane ssh-broker-mcp-http
for svc in signer control-plane mcp-http; do
  sudo usermod  -l "infrabroker-${svc}" "ssh-broker-${svc}"
  sudo usermod  -d /var/lib/infrabroker "infrabroker-${svc}"
  sudo groupmod -n "infrabroker-${svc}" "ssh-broker-${svc}"
done
sudo groupmod -n infrabroker ssh-broker           # the shared traversal group
sudo mv /etc/ssh-broker /etc/infrabroker
sudo mv /var/lib/ssh-broker /var/lib/infrabroker
sudo rm -f /etc/systemd/system/ssh-broker-*.service && sudo systemctl daemon-reload
# configs keep absolute paths — rewrite them before starting anything:
sudo sed -i 's|/etc/ssh-broker|/etc/infrabroker|g; s|/var/lib/ssh-broker|/var/lib/infrabroker|g' /etc/infrabroker/*.json
sudo ./deploy/install.sh          # lays down the new units and heals ownership
```

Verify with `grep -r ssh-broker /etc/infrabroker /etc/systemd/system` (no
hits expected), then start and health-check the services (§Order and
verification). The sshd side of the managed hosts is untouched: certificates,
CA keys and `TrustedUserCAKeys` do not change with the rename.

**Upgrading from a single-user install (≤ v1.34)**: do the pre-rename
migration above first if the install predates the rename. Then: the installer creates the
per-service users, re-owns the state directories and configs, and installs the
new units automatically. What it can **not** do is guess which mTLS key belongs
to which service — it warns about private keys still sitting flat under
`pki/` (readable by every service, the exposure this layout removes). Move
each one and update the config paths before restarting:

```bash
sudo mv /etc/infrabroker/pki/signer.key /etc/infrabroker/pki/signer.crt /etc/infrabroker/pki/signer/
sudo chown root:infrabroker-signer /etc/infrabroker/pki/signer/*
# ... same for control-plane/ and mcp-http/; broker-ctl material → pki/admin/
```

Then restart the units (§Upgrades). Only **after** the services are running as
their new per-service users can the legacy shared account be retired — while
the old units are still up they hold it open and `userdel` refuses:

```bash
sudo userdel ssh-broker             # optional; fails if any process still uses it
```

With `state_db` configured, runtime grants/waivers (signer) and pending or
approved-but-uncollected approvals (control plane) survive a restart. What is
still lost by design: the behaviour baseline (re-learns quickly) and live MCP
sessions on mcp-http (TCP connections cannot be resurrected). Plan accordingly.
