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

The installer creates the `ssh-broker` system user, installs binaries to
`/usr/local/bin`, configs to `/etc/ssh-broker/` (never overwriting an
existing one) and the units to `/etc/systemd/system`. It does **not** start
anything: a fresh config still points at example values.

## Reference layout

```
/usr/local/bin/{signer,control-plane,mcp-broker-http,broker-ctl}
/etc/ssh-broker/{control-plane.json,config.json,broker-ctl.json}  root:ssh-broker 0640
/etc/ssh-broker/pki/                                              mTLS certs/keys
/etc/ssh-broker/signer.env                                        optional AZURE_* creds (0600 root)
/var/lib/ssh-broker/signer/signer.json                           ssh-broker:ssh-broker 0640
/var/lib/ssh-broker/<svc>/                                        audit logs (StateDirectory)
```

The **signer config lives under `/var/lib/ssh-broker/signer/`**, owned by the
service, not under `/etc` — the durable policy-mutation API (`broker-ctl policy
add/remove`) rewrites it in place, which the read-only `/etc` tree would block.
The PKI and the other services' configs stay root-owned in `/etc`; the services
only read them.

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
- [ ] mTLS PKI in `/etc/ssh-broker/pki`, keys `0640 root:ssh-broker`.
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

With `state_db` configured, runtime grants/waivers (signer) and pending or
approved-but-uncollected approvals (control plane) survive a restart. What is
still lost by design: the behaviour baseline (re-learns quickly) and live MCP
sessions on mcp-http (TCP connections cannot be resurrected). Plan accordingly.
