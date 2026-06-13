# Operations — ssh-broker

Operational runbook: building, running, adding hosts, hot-reload, PKI, and
reference configs. For the design rationale see [ARCHITECTURE.md](ARCHITECTURE.md);
for the security posture see [THREAT_MODEL.md](THREAT_MODEL.md).

---

## Table of contents

1. [Starting the system](#1-starting-the-system)
2. [Adding a host](#2-adding-a-host)
3. [Hot reload](#3-hot-reload)
4. [broker-ctl](#4-broker-ctl)
5. [Local PKI](#5-local-pki)
6. [Reference config files](#6-reference-config-files)

---

## 1. Starting the system

```bash
cd /path/to/ssh-broker

# 1. Start the signer (must be running before the broker starts)
./signer.sh start        # background, PID in signer.pid, log in signer.log
./signer.sh status
./signer.sh log          # tail -f signer.log
./signer.sh stop
./signer.sh restart

# 2. The MCP (mcp-broker) is started by the MCP client (e.g. OpenCode / Claude
#    Code) on connect. It requires the signer to be running: if it cannot
#    GET /v1/hosts, the broker fails to start.

# 3. Rebuild after changes (make embeds the git-tag version into the binaries)
make install                 # all binaries → ~/bin
make signer                  # or just one
```

Compiled binaries: `~/bin/mcp-broker` · `~/bin/mcp-broker-http` · `~/bin/signer`
· `~/bin/broker-ctl`. `make install` injects the version from `git describe
--tags`; a plain `go build ./cmd/...` still works but reports a `dev-<commit>`
version. Run `make version` to see what would be embedded.

**Order matters:** always start the signer before opening the MCP client. With
multiple broker replicas, note that session/approval/behavior state is in-memory
per process (single-instance only — see THREAT_MODEL.md).

---

## 2. Adding a host

`signer.json` is the **single source of truth**. Edit it (or use `broker-ctl
host add`) and reload the signer; the broker picks up the change in ≤
`hosts_refresh_seconds` without a restart.

```json
"hosts": {
  "web01": {
    "addr":             "10.0.0.21:22",
    "user":             "deploy",
    "host_key":         "ssh-ed25519 AAAA...",
    "principal":        "host:web01",
    "source_address":   "",
    "max_ttl_seconds":  120,
    "allow_as_bastion": false,

    "groups": ["prod-web"],            // RBAC: groups this host belongs to

    "allow_sudo": true,
    "allowed_sudo_users": ["root", "deploy"],
    "allow_pty": true
  }
},
"callers": {
  "broker-1": { "allowed_groups": ["prod-web"] }   // CN → allowed groups
}
```

> **Bastions:** if the host uses `"jump": "bastion"`, the bastion must share the
> host's groups, or the broker cannot resolve the jump chain.

> **Backward compatible:** a CN absent from `callers` has no group restriction
> and sees every host.

Obtain the `host_key`:

```bash
ssh-keyscan -t ed25519 <ip-or-hostname>
# copy only the "ssh-ed25519 AAAA..." part (without the hostname prefix)
```

### Remote host configuration

In the target's `/etc/ssh/sshd_config`:

```
TrustedUserCAKeys /etc/ssh/ssh_broker_ca.pub   # copy pki/ssh_ca.pub
AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
LogLevel VERBOSE
AllowTcpForwarding no   # yes on bastions
X11Forwarding no
PermitTunnel no
# PermitTTY yes          # default; uncomment only if it was disabled
```

Create `/etc/ssh/auth_principals/<user>` with the host's `principal` (e.g.
`host:web01`). For elevation, add the sudoers entry described in
[ARCHITECTURE.md § Privilege elevation](ARCHITECTURE.md#privilege-elevation-sudo-nopasswd).
See also `deploy/sshd_config.snippet`.

---

## 3. Hot reload

The signer re-reads `signer.json` without restarting, atomically replacing the
**hosts policy**, `max_ttl_seconds`, `reload_callers`, and the CA key(s). If the
new config is invalid, the previous state is preserved. `listen`, TLS, and
`audit_log` require a full restart.

```bash
broker-ctl reload          # SIGHUP if local, else POST /v1/reload (mTLS)
# alternatives:
kill -HUP "$(cat signer.pid)"
./signer.sh restart
```

- **`POST /v1/reload`** (mTLS): only CNs in `reload_callers` may invoke it
  (others → 403). Empty `reload_callers` disables the HTTP endpoint.
- **`SIGHUP`**: local reload, bypasses the allowlist.

The broker does **not** need a reload: it refreshes `/v1/hosts` every
`hosts_refresh_seconds`.

---

## 4. broker-ctl

```bash
# Build
go build -o ~/bin/broker-ctl ./cmd/broker-ctl
```

### Hosts

```bash
# Add host (with automatic ssh-keyscan)
broker-ctl host add --name web01 --addr 10.0.0.1:22 --user deploy --scan \
  --sudo --pty --groups prod-web --callers broker-1

# Add host with a manual key
broker-ctl host add --name web01 --addr 10.0.0.1:22 --user deploy \
  --host-key "ssh-ed25519 AAAA..." --ttl 120

# Add host with a command policy (allowlist)
broker-ctl host add --name web01 --addr 10.0.0.1:22 --user deploy --scan \
  --policy-mode allowlist --allow "^uptime$,^df -h" --shell-parse

# Update an existing host preserving its command_policy
broker-ctl host add --name web01 --addr 10.0.0.1:22 --user deploy --scan --force
# (no --policy-mode/--allow/--deny flags → CommandPolicy copied from existing entry)

# Update an existing host replacing its command_policy
broker-ctl host add --name web01 --addr 10.0.0.1:22 --user deploy --scan --force \
  --policy-mode denylist --deny "rm -rf"

# List hosts (columns: JUMP, SRC_ADDR, SUDO_USERS, CALLERS, POLICY)
broker-ctl host list

# Remove host
broker-ctl host remove web01
```

**`host add` flags:**

| Flag | Required | Default | Description |
|---|---|---|---|
| `--name` | ✓ | — | Logical host name |
| `--addr` | ✓ | — | `host:port` of the SSH server |
| `--user` | ✓ | — | Remote SSH account |
| `--host-key` | ✓* | — | Host key (authorized_keys). `-` = read stdin |
| `--scan` | ✓* | — | Fetch the key with `ssh-keyscan` (alternative to `--host-key`) |
| `--principal` | | `host:<name>` | SSH principal in the cert |
| `--ttl` | | `120` | `max_ttl_seconds` |
| `--jump` | | — | Name of the preceding bastion |
| `--source-address` | | — | Bastion egress IP/CIDR |
| `--sudo` | | false | `allow_sudo=true` |
| `--sudo-users` | | — | `allowed_sudo_users` (comma-separated) |
| `--pty` | | false | `allow_pty=true` |
| `--groups` | | — | RBAC groups (comma-separated) |
| `--callers` | | — | CNs allowed on this host (comma-separated) |
| `--bastion` | | false | `allow_as_bastion=true` |
| `--force` | | false | Update if it exists, preserving every field whose flag you don't pass (see note) |
| `--policy-mode` | | — | `allowlist` \| `denylist` \| `off` |
| `--allow` | | — | Allowlist patterns (RE2 regex, comma-separated) |
| `--deny` | | — | Denylist patterns (RE2 regex, comma-separated) |
| `--require-approval` | | — | Require-approval patterns (RE2 regex, comma-separated) |
| `--shell-parse` | | false | Parse commands as POSIX sh before evaluating the policy |

\* Either `--host-key` or `--scan` is required, but not both. `--scan` honours
the port in `--addr` (and IPv6 literals).

> **Partial update with `--force` (v1.12.6):** a `--force` update starts from
> the existing entry and overrides **only** the fields whose flags you pass; any
> field you omit (sudo, groups, callers, TTL, `command_policy`, …) keeps its
> current value. So `host add --name web01 --addr newip:22 --user deploy --scan
> --force` changes just the address and leaves sudoers/groups/policy intact. A
> flag set explicitly to empty (`--groups ""`, `--sudo=false`) still clears its
> field. (`--addr`, `--user`, and `--host-key`/`--scan` are always required and
> thus always written.)

### CA keys

```bash
broker-ctl ca-keys add --name _default --type pem --path pki/ssh_ca
broker-ctl ca-keys add --name prod-web --type akv \
  --vault-url https://myvault.vault.azure.net/ --key-name ssh-ca-web
broker-ctl ca-keys list
broker-ctl ca-keys remove prod-web
```

### Callers (group RBAC table)

```bash
broker-ctl callers add --name broker-1 --groups prod-web,staging
broker-ctl callers add --name broker-1 --groups prod-web --force   # update
broker-ctl callers list
broker-ctl callers remove broker-1
```

### Reload

```bash
broker-ctl reload
broker-ctl --config /path/to/signer.json host list   # alternative config
```

### Approvals (mTLS to the control plane, approver cert)

```bash
broker-ctl approval list
broker-ctl approval allow <id>
broker-ctl approval deny  <id>
```

### Audit

```bash
# Follow the broker log live (shows the last 20 lines first)
broker-ctl audit tail --log audit.log
broker-ctl audit tail --log audit.log -n 50

# Follow the signer log (certificate issuances)
broker-ctl audit tail --log signer_audit.log

# Filter (host, caller, outcome, date; combinable)
broker-ctl audit show --log audit.log --host web01
broker-ctl audit show --log audit.log --outcome denied
broker-ctl audit show --log signer_audit.log --outcome issued --since 2026-06-05
broker-ctl audit show --log audit.log --host db01 --outcome denied --limit 20

# JSON for jq pipelines
broker-ctl audit show --log audit.log --outcome denied --json | jq .
broker-ctl audit show --log audit.log --json | jq 'select(.serial==1042)'

# Verify the hash chain
broker-ctl audit verify --log audit.log
broker-ctl audit verify --log signer_audit.log

# Verify chain + Ed25519 signatures
broker-ctl audit verify --log audit.log        --key pki/audit.seed
broker-ctl audit verify --log signer_audit.log --key pki/signer_audit.seed
```

See [USAGE.md § 7](USAGE.md#7-reviewing-audit-logs) for the full audit-review
guide (jq recipes, field reference, chain-integrity details).

---

## 5. Local PKI

Generated locally — **never commit `pki/` to git** (it holds private keys).

| File | Description | Rotate when |
|---|---|---|
| `pki/ssh_ca` | SSH CA private key (Ed25519) | CA rotation |
| `pki/ssh_ca.pub` | SSH CA public key | — (copy to hosts as `TrustedUserCAKeys`) |
| `pki/mtls_ca.{key,crt}` | TLS CA (self-signed, 10y) for broker↔signer mTLS | 2036 |
| `pki/signer.{key,crt}` | Signer server cert (SAN: 127.0.0.1, localhost) | 2036 |
| `pki/broker.{key,crt}` | Broker client cert (CN=broker-1) | 2036 |
| `pki/audit.seed` | Ed25519 seed for the broker log | do not rotate (breaks the chain) |
| `pki/signer_audit.seed` | Ed25519 seed for the signer log | do not rotate (breaks the chain) |

> Production CA custody belongs in an HSM/KMS/Secure Enclave. The seam is ready:
> `ca.LoadCAFromPEM` returns an `ssh.Signer`; replace it with
> `ssh.NewSignerFromSigner(kmsClient)` (AKV already supported — see
> ARCHITECTURE.md § Multi-CA).

### Rotating keys and certificates

The system issues *ephemeral* SSH credentials, but its own control-plane PKI is
long-lived and must be rotated deliberately. There is no automation for this yet
— follow these procedures.

**SSH CA key (`pki/ssh_ca`).** Hosts pin it via `TrustedUserCAKeys`, so rotation
needs a transition window where both the old and new CA are trusted:

1. Generate the new CA key and add it to `signer.json` as a **per-group** CA
   (`ca_keys`, see ARCHITECTURE.md § Multi-CA) or stage it alongside the current
   `ca_key`.
2. Distribute the new public key to every managed host, appending it to the
   `TrustedUserCAKeys` file (a host may trust multiple CA keys — keep both lines
   during the transition). Reload `sshd` (`systemctl reload sshd`).
3. Switch issuance to the new CA (point the host group at the new `ca_keys`
   entry, or replace `ca_key`) and `broker-ctl reload` the signer.
4. Once all live certificates signed by the old CA have expired (≤ `max_ttl`,
   i.e. minutes), remove the old public key from every host's
   `TrustedUserCAKeys` and reload `sshd`.

Multi-CA (v1.11.0) makes step 1–3 per host group, so you can rotate one group at
a time instead of the whole fleet.

**mTLS PKI (`pki/mtls_ca`, `signer.crt`, `broker.crt`, control-plane cert).**
These are self-signed with a 10-year validity, which is itself a long-lived
credential. To rotate the issuing `mtls_ca` (the higher-impact case):

1. Generate a new `mtls_ca` and issue new server/client certs from it.
2. During transition, configure each service's `client_ca` to trust **both** the
   old and new CA (concatenate the two CA PEMs into the file referenced by
   `client_ca`). Restart the services (TLS config is not hot-reloaded).
3. Roll out the new client certs (`broker.crt`, control-plane cert) and server
   certs (`signer.crt`).
4. Remove the old CA from the `client_ca` bundles and restart.

To rotate only a leaf cert (e.g. a compromised `broker.crt`) without changing the
CA: issue a new cert from the existing `mtls_ca`, deploy it, and — because there
is no CRL on the mTLS path — rely on the broker CN allowlists (`callers`,
`allowed_callers`, `reload_callers`, `trusted_forwarders`) to deny the old CN if
it must be revoked before expiry.

> **Audit seeds are not certificates and must not be rotated** — replacing
> `pki/*.seed` breaks the hash/signature chain of existing logs (see the table
> above). Archive the seed with the log if you ever retire a log file.

---

## 6. Reference config files

| File | Purpose |
|---|---|
| `config.json` | Active broker config (remote mode) |
| `config.example.json` | Reference with local + remote modes; `allow_sudo`/`allow_pty`/`command_policy`/`approval_wait_seconds` |
| `signer.json` | Active signer config (single source of truth for hosts) |
| `signer.example.json` | Reference with per-host `allow_sudo`/`allowed_sudo_users`/`allow_pty`/`groups`/`command_policy` + `callers` + `trusted_forwarders` |
| `control-plane.example.json` | Control plane reference: `signer` block, `approval` (notifier/callers/timeout), `behavior`, `trusted_forwarders`, mTLS |
| `deploy/sshd_config.snippet` | `sshd_config` fragment + NOPASSWD sudoers for managed hosts |

### Common operational notes

1. **The signer must be running** before the broker / MCP client starts.
2. **`hosts_refresh_seconds: 30`** is a development value. In production raise it
   to 300 (5 min) or more.
3. To use **elevation** on a real host: set `allow_sudo: true` in `signer.json`,
   reload the signer, and configure NOPASSWD sudoers on the host. Verify with
   `ssh_execute(server, "id", sudo=true)`.
4. To use **PTY**: set `allow_pty: true` and reload. Use `ssh_execute(..., pty=true)`
   (one-shot) or `ssh_session_open(server, mode="pty")` (interactive).
5. To use **group RBAC (broker mTLS)**: add `"groups"` per host and a `callers`
   section. Issue a new CN signed by `pki/mtls_ca.crt` for each restricted broker
   and add it to `callers`. Include any bastion in the same groups.
6. To use the **HTTP+OAuth frontend** (`cmd/mcp-broker-http`): configure the
   `oauth` block and `resource_url` in `config.json`. Provide `server_cert`/
   `server_key` (no `client_ca` — auth is the bearer token). For per-user RBAC
   add `"groups_claim": "groups"` and the `groups` field on the relevant hosts.
7. **Physical broker/signer separation** (different machines) requires a new SAN
   on the signer cert with the real IP/hostname, and updating `config.json` with
   that URL.
