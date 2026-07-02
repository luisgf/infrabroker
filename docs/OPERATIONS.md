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
7. [Monitoring](#7-monitoring)
8. [Production deployment](#8-production-deployment)

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
· `~/bin/broker-ctl` · `~/bin/broker` · `~/bin/control-plane`. `make install` injects the version from `git describe
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
> and sees every host — unless the table has a reserved `"_default"` entry,
> which absent CNs then inherit. Recommended for production:
> `"_default": { "allowed_groups": [] }` makes the table **default-deny**, so
> forgetting to list a new broker CN fails closed instead of open.

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
`hosts_refresh_seconds` for its cached server list. New `ssh_execute` and
`ssh_session_open` calls refresh `/v1/hosts` immediately before building SSH
hops and fail closed if the signer/control-plane cannot provide the current host
view.

Command-policy and target/bastion authorization changes are evaluated by the
signer on every new certificate and on every `ssh_session_exec` preflight.
Existing `mode=exec` sessions therefore start enforcing a new policy on their
next command. Existing `mode=shell` / `mode=pty` sessions are rejected on their
next command once a policy becomes active, because their stateful command stream
cannot be verified per command.
If a host's physical SSH route changes (`addr`, `user`, `host_key`, or `jump`),
already-open sessions are rejected on their next command and must be reopened so
they authenticate to the new route.

---

## 4. broker-ctl

```bash
# Build
go build -o ~/bin/broker-ctl ./cmd/broker-ctl
```

**Global options (before the subcommand):**

```bash
broker-ctl [--config <signer.json>] [--client-config <broker-ctl.json>] <command> [args]
broker-ctl --version [--verbose]     # print the build version
```

`--config` is a **global** option and must precede the subcommand
(`broker-ctl --config /etc/signer.json host list`), consistent with the other
binaries. It defaults to `./signer.json`.

> **Breaking change (v1.15.0):** `--config` no longer works *after* the
> subcommand. Replace `broker-ctl host list --config f` with
> `broker-ctl --config f host list`.

### Client configuration (remote commands)

The remote commands (`reload`, `policy add/remove/grant/grants/revoke`,
`approval list/allow/deny`, `host list --remote`) need a URL and an mTLS
identity. Instead of repeating `--url/--cert/--key/--ca` on every call, put
them in a **client parameters file** (this is client-side config — the service
policy stays in `signer.json`):

```json
{
  "signer":        { "url": "127.0.0.1:9443", "cert": "pki/broker.crt", "key": "pki/broker.key", "ca": "pki/mtls_ca.crt" },
  "control_plane": { "url": "127.0.0.1:7443", "cert": "pki/broker-admin.crt", "key": "pki/broker-admin.key", "ca": "pki/mtls_ca.crt" }
}
```

Search order: `--client-config` → `$BROKER_CTL_CONFIG` →
`~/.config/broker-ctl/config.json` → `/etc/ssh-broker/broker-ctl.json`
(the production installer seeds the last one). The current working directory is
**not** searched — an implicit `./broker-ctl.json` could let a planted file
redirect the CLI's mTLS endpoint and CA trust anchor, so a project-local file
must be named explicitly with `--client-config`. Per-parameter precedence:
**explicit flag > env var > file > built-in default**. Environment variables:
`BROKER_CTL_SIGNER_{URL,CERT,KEY,CA}` for the signer section,
`BROKER_CTL_CP_{URL,CERT,KEY,CA}` for the control plane. See
`broker-ctl.example.json`.

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

# Add host with command-policy audit mode to collect a baseline before enforcing
broker-ctl host add --name web02 --addr 10.0.0.2:22 --user deploy --scan \
  --policy-mode allowlist --policy-enforcement audit \
  --allow "^uptime$,^df -h,^journalctl "

# Update an existing host preserving its command_policy
broker-ctl host add --name web01 --addr 10.0.0.1:22 --user deploy --scan --force
# (no --policy-* / --allow / --deny flags → CommandPolicy copied from existing entry)

# Update an existing host replacing its command_policy
broker-ctl host add --name web01 --addr 10.0.0.1:22 --user deploy --scan --force \
  --policy-mode denylist --deny "rm -rf"

# List hosts (columns: JUMP, SRC_ADDR, SUDO_USERS, CALLERS, POLICY)
broker-ctl host list

# List the LIVE policy from a running signer over mTLS (GET /v1/policy/hosts;
# the client cert CN must be in reload_callers). Same columns as the local
# view, but reflecting the in-memory state after hot-reloads and grants —
# also the recommended post-deploy end-to-end check.
broker-ctl host list --remote

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
| `--file-transfer` | | false | `allow_file_transfer=true` (`ssh_put_file` / `ssh_get_file`) |
| `--callers` | | — | CNs allowed on this host (comma-separated) |
| `--bastion` | | false | `allow_as_bastion=true` |
| `--force` | | false | Update if it exists, preserving every field whose flag you don't pass (see note) |
| `--policy-mode` | | — | `allowlist` \| `denylist` \| `off` |
| `--policy-enforcement` | | — (empty = `enforce`) | `enforce` \| `audit`; audit allows commands but emits would-deny / would-require-approval warnings |
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
>
> **Command-policy sub-flags are also merged field-granularly (v1.13.0):**
> passing e.g. only `--require-approval` updates that list and keeps the existing
> `--policy-mode`/`--policy-enforcement`/`--allow`/`--deny`/`--shell-parse`.
> Previously any single policy sub-flag rebuilt the whole `command_policy` from
> flag defaults, silently downgrading the host to `mode:off` (firewall disabled,
> sessions re-enabled).

> **Baseline workflow:** start a candidate firewall with
> `--policy-enforcement audit`, let real `ssh_execute` and `ssh_session_exec`
> traffic run, then inspect warnings in `broker-ctl audit show` and mine
> suggestions with `broker-ctl policy recommend`. Switch to
> `--policy-enforcement enforce` only after reviewing the proposed allow/deny
> rules.

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
broker-ctl callers add --name _default --groups ""   # default-deny unlisted CNs
broker-ctl callers list
broker-ctl callers remove broker-1
```

An explicitly-empty `--groups ""` writes `allowed_groups: []` (deny every
host); combined with the reserved name `_default` it applies to every CN not
explicitly listed, turning the table default-deny.

### Reload

```bash
broker-ctl reload
broker-ctl --config /path/to/signer.json reload   # alternative config (global flag)
```

### Command policy: explain, recommend, mutate (v1.17.0)

```bash
# Explain a host's composed (group + inline) command policy, evaluate a command offline
broker-ctl policy explain   --host web01 --command 'systemctl restart nginx'

# Mine an audit log for advisory suggestions (read-only — changes nothing)
broker-ctl policy recommend --audit signer_audit.log --min-count 5
#   [PROMOTE]  web01  ^systemctl restart nginx$   47x, 47 human-approved
#   [DEAD]     web01  ^journalctl                  0 matches in window -> review/remove

# Durable change via the validated mutation API (mTLS; CN must be in reload_callers).
# Validated before persist, written atomically, applied in-memory, audited:
broker-ctl policy add    --host web01 --allow '^systemctl status [a-z0-9_.-]+$'
broker-ctl policy remove --host web01 --allow '^journalctl '
```

### Runtime grants: temporary, expiring widening (v1.18.0)

A **grant** widens an allowlist host **for a while** without editing `signer.json` —
it lives in memory and **expires on its own**. Operator-only (mTLS, CN in
`reload_callers`), audited, and **widen-only**: a grant only adds `allow` patterns,
applies only on a host that is **already allowlist-active**, and can never override a
baseline `deny`. Cap the maximum TTL with `max_grant_ttl_seconds` in `signer.json`.

```bash
# Incident: web01 (allowlist) denies 'systemctl restart nginx'. Grant it for 2 hours.
broker-ctl policy grant  --host web01 --allow '^systemctl restart nginx$' --ttl 2h
# → granted on web01: allow "^systemctl restart nginx$" for 2h0m0s (id 42d1..., expires ...Z)

# Verify without running anything (dry-run flips denied -> allowed):
broker-ctl policy explain --host web01 --command 'systemctl restart nginx'   # static view
#   …and from the agent side, ssh_execute --dry_run now reports ALLOWED.

# Scope a grant to one broker CN or one end user (default = host-wide):
broker-ctl policy grant  --host web01 --allow '^systemctl restart nginx$' --ttl 2h --caller broker-1
broker-ctl policy grant  --host web01 --allow '^systemctl restart nginx$' --ttl 2h --end-user alice

# List active grants; revoke early (otherwise it just expires):
broker-ctl policy grants
# ID                         HOST       EXPIRES (UTC)          SCOPE              RULES
# 42d1eabd7c73b474c85e75a7   web01      2026-06-19T14:00:00Z   any                allow[^systemctl restart nginx$]
broker-ctl policy revoke 42d1eabd7c73b474c85e75a7
```

Notes: a grant on a **non-allowlist** host is refused (`409` — it would be a no-op
and would invert the host to default-deny); grants **survive a config reload** but are
**dropped on a signer restart** (fail-safe — the baseline is more restrictive); every
create/revoke is in the signed audit log (`grant-created` / `grant-revoked`).

### Approvals (mTLS to the control plane, approver cert)

```bash
broker-ctl approval list
broker-ctl approval allow <id>
broker-ctl approval deny  <id>

# Approve-and-learn (v1.18.0): also waive RE-approval for this exact command for a
# while, so it runs without prompting again until the waiver expires for the same
# broker/end-user subject. The signer mints an approval waiver scoped to the
# original broker CN and end user (honoured only because the control plane is a
# trusted_forwarder); it shows up in 'policy grants' and is revocable like any grant.
broker-ctl approval allow <id> --learn --ttl 2h
broker-ctl policy grants            # the waiver appears as waive-approval[^cmd$]
broker-ctl policy revoke <grant-id> # end it early (otherwise it just expires)
```

A waiver only un-gates an **already-allowed** command (it never widens allow/deny),
so it is safe even on a default-allow host that carries a `require_approval` rule. The
waiver is scoped to the approved caller/end-user and elevation, and the TTL is clamped
to `max_grant_ttl_seconds` if that cap is set. Every mint is audited
(`approval-waiver-created`, linked to the originating approval id).

> **Browser UI:** the control plane also serves an approval UI at
> `https://<control-plane>/ui/approvals` (list) and `/ui/approvals/{id}`
> (detail with Approve / Deny and the approve-and-learn TTL). Auth is the
> browser's mTLS client certificate — import an approver cert (CN in
> `approval.callers`) into the browser. Point `approval_url_template` at
> `https://<control-plane>/ui/approvals/{id}` so Teams/webhook notification
> links land on the request page.

`approval.timeout_seconds` in `control-plane.example.json` controls both halves of
the approval lifecycle: a pending request must be decided before that TTL elapses
from creation, and an approved request must be collected by the broker before the
same TTL elapses from the decision. Approved requests are consumed once.

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

# Verify the WHOLE chain across rotated segments (<log> plus <log>.<timestamp>),
# checking cross-file linkage so a dropped or truncated segment is detected.
# Single-file verify accepts the first prev_hash as an unchecked seed; --all does not.
broker-ctl audit verify --log audit.log --all --key pki/audit.seed
```

See [USAGE.md § 7](USAGE.md#7-reviewing-audit-logs) for the full audit-review
guide (jq recipes, field reference, chain-integrity details).

### Version

Every binary reports its build version. Short by default (script-friendly),
detailed with `--verbose`:

```bash
broker-ctl --version            # e.g. v1.15.0
broker-ctl --version --verbose  # version + Go toolchain + os/arch + VCS revision
broker-ctl version              # equivalent subcommand form
broker-ctl version --verbose

signer --version                # same flags on every binary
broker --version --verbose
```

The version is injected from the git tag at build time (`make build`); a plain
`go build` falls back to the module version or the VCS revision recorded by the
Go toolchain, so it is never a stale hard-coded string.

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
| `control-plane.example.json` | Control plane reference: `signer` block, `sign_callers` (broker/approver role separation), `approval` (notifier/callers/timeout), `behavior`, `trusted_forwarders`, mTLS |
| `broker-ctl.example.json` | Client parameters for the remote `broker-ctl` commands (`signer` / `control_plane` URL + mTLS cert/key/ca); see §4 |
| `deploy/sshd_config.snippet` | `sshd_config` fragment + NOPASSWD sudoers for managed hosts |

### Common operational notes

1. **The signer must be running** before the broker / MCP client starts.
2. **`hosts_refresh_seconds`** is optional and defaults to 300 (5 min) when
   absent or `0` — already production-appropriate. It is not set in the shipped
   example configs. Lower it (e.g. `30`) only in development to pick up
   host-list changes from the signer faster.
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
8. **Broker/approver role separation (control plane):** the signing path
   (`/v1/sign`, `/v1/hosts`, `/v1/sign/result`) is restricted to brokers. List the
   broker CNs in `sign_callers`; with no list, a CN in `approval.callers` is denied
   the sign path (an approver is not a broker). This stops an approver certificate,
   signed by the same `client_ca`, from originating signing requests.
9. **Config is strictly validated at load:** an unknown or misspelled key
   (e.g. `sign_caller` instead of `sign_callers`) is rejected at startup/reload
   rather than silently ignored, so a typo cannot quietly leave a setting open.
   `_*` comment keys and the reserved `_default` group are still accepted.

---

## 7. Monitoring

Every service accepts an optional `monitor_listen` config key (empty or absent
= disabled) that starts a **separate plain-HTTP listener** with two endpoints:

| Endpoint | Purpose |
|---|---|
| `/healthz` | Liveness: `200 ok` while the process is serving. Use it for load-balancer/systemd/container health checks. |
| `/metrics` | Metrics in the Prometheus text exposition format. |

The broker config key covers all three broker frontends (`broker`,
`mcp-broker`, `mcp-broker-http`); the signer and control plane have their own
key in `signer.json` / `control-plane.json`.

> **Security:** the listener has **no authentication and no TLS**. Bind it to
> `127.0.0.1` or a private scrape interface, never a public address. It is
> deliberately a separate listener so the mTLS/OAuth service ports stay clean.

### Metrics

| Metric | Service | Meaning |
|---|---|---|
| `signer_sign_requests_total{outcome}` | signer | `POST /v1/sign` requests by audit outcome (`issued`, `denied`, `approval-required`, `dry_run_*`, …) plus `rate-limited`, which is counted here but deliberately **not** audited. |
| `controlplane_events_total{outcome}` | control plane | Audit events by outcome (`forwarded`, `denied`, `anomaly`, `rate-limited`, `approval-*`, `error`). |
| `controlplane_approvals_pending` | control plane | Approval requests currently awaiting a human decision (gauge, read at scrape time). |
| `broker_events_total{outcome}` | broker frontends | Audit events by outcome (`executed`, `denied`, `session_open`, `session_exec`, `session_close`, `error`, …). |
| `broker_sessions_active` | broker frontends | Persistent SSH sessions currently open (gauge). |
| `audit_append_failures_total` | all | Audit-log `Append` errors. **Alert on any increase**: the operation continues by design (threat-model gap #9), so this counter is the only machine-readable signal that the audit trail has a gap. |

Example scrape check:

```bash
curl -s http://127.0.0.1:9160/healthz
curl -s http://127.0.0.1:9160/metrics | grep signer_sign_requests_total
```

---

## 8. Production deployment

The manual flow above (signer.sh + `make install` to `~/bin`) is the lab
setup. For production, `deploy/` in the repository ships hardened systemd
units for the three daemons (`signer`, `control-plane`, `mcp-broker-http`),
an idempotent installer and a release target:

```bash
make dist                        # dist/ssh-broker-<version>.tar.gz
# on the target host, as root:
./deploy/install.sh              # user, dirs, binaries, units, seed configs
systemctl enable --now ssh-broker-signer   # always the signer first
```

Reference layout: binaries in `/usr/local/bin`, configs in
`/etc/ssh-broker/` (never overwritten on upgrade), mTLS PKI in
`/etc/ssh-broker/pki/`, audit logs in `/var/lib/ssh-broker/<svc>/`.
Policy hot-reload maps to `systemctl reload ssh-broker-signer` (SIGHUP).
The installer also seeds `/etc/ssh-broker/broker-ctl.json` (client parameters,
see §4) so `broker-ctl host list --remote` works flag-less as the post-deploy
end-to-end check.

**CA custody is the operator's choice**, made in `signer.json` → `ca_keys`:
`"akv"` (Azure Key Vault — the private key never leaves the vault;
recommended for production; RSA/EC only) or `"pem"` (local file — lab/dev,
the signer logs a warning). Credentials for AKV come from
`DefaultAzureCredential` (managed identity, or a service principal via the
unit's optional `EnvironmentFile=/etc/ssh-broker/signer.env`).

The full checklist — custody trade-offs, default-deny `callers`, rate
limits, upgrade caveats (in-memory approvals/sessions) — lives in
`deploy/README.md` in the repository.
