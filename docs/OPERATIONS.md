# Operations — infrabroker

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
cd /path/to/infrabroker

# 0. First-time setup: generate the local PKI + the custody-separated two-service
#    config (signer.json holds the SSH CA + policy; config.json is the remote-mode
#    broker). Pure-Go, no ssh-keygen/openssl. Re-run with --force to regenerate.
#    (This is a local PEM CA — lab/dev custody; see §8 for separated/HSM custody.)
#    Add --import-ssh-config to import hosts from ~/.ssh/config (ssh -G + known_hosts
#    / keyscan), and --register-mcp to run `claude mcp add` for you.
infrabroker init         # writes pki/, signer.json, config.json in the current dir

# 1. Start the signer (must be running before the broker starts)
./signer.sh start        # background, PID in signer.pid, log in signer.log
./signer.sh status
./signer.sh log          # tail -f signer.log
./signer.sh stop
./signer.sh restart

# 2. The MCP stdio server (`infrabroker serve-mcp`, or the legacy `mcp-broker`
#    wrapper) is started by the MCP client (e.g. OpenCode / Claude Code) on
#    connect. It requires the signer to be running: if it cannot GET /v1/hosts,
#    the broker fails to start.

# 3. Rebuild after changes (make embeds the git-tag version into the binaries)
make install                 # all binaries → ~/bin
make signer                  # or just one
```

Compiled binaries: `~/bin/infrabroker` (the unified broker frontend) · `~/bin/signer`
· `~/bin/broker-ctl` · `~/bin/control-plane`, plus the **deprecated** compat
wrappers `~/bin/{broker, mcp-broker, mcp-broker-http}` (each just runs the matching
`infrabroker serve-*`). `make install` injects the version from `git describe
--tags`; a plain `go build ./cmd/...` still works but reports a `dev-<commit>`
version. Run `make version` to see what would be embedded.

**Order matters:** always start the signer before opening the MCP client. With
multiple broker replicas, note that session/approval/behavior state is in-memory
per process (single-instance only — see THREAT_MODEL.md).

**What survives a restart:** with `state_db` set (signer and control plane),
runtime grants/waivers and pending or approved-but-uncollected approvals are
persisted (SQLite, write-through) and restored at startup. Live SSH sessions
and the behaviour baseline are intentionally not persisted: a TCP connection
cannot be resurrected, and the baseline re-learns. Without `state_db`,
restarts drop grants/waivers/approvals as before (fail-safe). Back up the
`.db` together with its `-wal`/`-shm` sidecar files.

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

> **Default-deny (v2.0.0):** once `callers` is non-empty it is authoritative — a
> CN absent from it sees and signs **no** host, so forgetting to list a new broker
> CN fails closed. To grant unlisted CNs a baseline instead, add a reserved
> `"_default": { "allowed_groups": [...] }` entry with groups. Omitting `callers`
> entirely leaves every caller unrestricted (single-broker deployments only).

Obtain the `host_key`:

```bash
ssh-keyscan -t ed25519 <ip-or-hostname>
# copy only the "ssh-ed25519 AAAA..." part (without the hostname prefix)
```

### Remote host configuration

In the target's `/etc/ssh/sshd_config`:

```
TrustedUserCAKeys /etc/ssh/infrabroker_ca.pub   # copy pki/ssh_ca.pub
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

### 2.1 Adding a Kubernetes cluster (optional)

The signer can also broker Kubernetes access (credential-broker; see
[ARCHITECTURE.md § Kubernetes target](ARCHITECTURE.md#kubernetes-target-v1340)).
Clusters live under `kubernetes.clusters` in `signer.json`, are **default-deny**,
and are hot-reloadable like hosts. Setup has two sides — in the cluster and in
`signer.json`.

**In the cluster:** create a least-privilege *minter* ServiceAccount whose only
RBAC is minting bound tokens for the agent SAs, and one or more agent SAs with
the Roles the agent actually needs (layer B):

```yaml
# The minter: its ENTIRE RBAC is `create` on serviceaccounts/token for the
# agent SAs. A signer compromise yields token-minting for those SAs, nothing more.
apiVersion: v1
kind: ServiceAccount
metadata: { name: infrabroker-minter, namespace: agents }
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: { name: infrabroker-minter, namespace: agents }
rules:
  - apiGroups: [""]
    resources: ["serviceaccounts/token"]
    resourceNames: ["broker-platform", "broker-readonly"]  # the agent SAs
    verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: { name: infrabroker-minter, namespace: agents }
roleRef: { apiGroup: rbac.authorization.k8s.io, kind: Role, name: infrabroker-minter }
subjects: [{ kind: ServiceAccount, name: infrabroker-minter, namespace: agents }]
---
# An agent SA (layer B). Give it exactly the cluster RBAC the agent may use;
# the broker's action policy (layer A) can only narrow this, never widen it.
apiVersion: v1
kind: ServiceAccount
metadata: { name: broker-platform, namespace: agents }
# ...bind it to Roles/ClusterRoles for the resources your rules allow.
```

Mint the minter's own token and store it where `token_file` points; the signer
re-reads it per mint, so you can rotate it out-of-band. It is a **standing
cluster credential** — write it `0600` owned by the signer's service user
(`infrabroker-signer` in the production layout, §8) and never under the
group-readable `/etc/infrabroker/pki` root:

```bash
umask 077
kubectl -n agents create token infrabroker-minter --duration=8760h \
  > /var/lib/infrabroker/signer/pki/prod-k8s-minter.token
kubectl config view --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' \
  | base64 -d > /var/lib/infrabroker/signer/pki/prod-k8s-ca.crt
chown infrabroker-signer:infrabroker-signer /var/lib/infrabroker/signer/pki/prod-k8s-minter.token
chmod 0600 /var/lib/infrabroker/signer/pki/prod-k8s-minter.token
```

**In `signer.json`:** add the cluster under `kubernetes.clusters` (see
`signer.example.json` for a fully-commented block). Cluster names must be
**disjoint** from host names. Verify end-to-end after a reload:

```bash
broker-ctl cluster list --remote      # the caller-scoped cluster view (mTLS)
```

---

## 3. Hot reload

The signer re-reads `signer.json` without restarting, atomically replacing the
**hosts policy**, the **Kubernetes clusters**, `max_ttl_seconds`,
`reload_callers`, and the CA key(s). If the new config is invalid (including a
bad cluster rule or an unreadable `ca_cert`/`token_file`), the previous state is
preserved. `listen`, TLS, and `audit_log` require a full restart.

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

The relative `pki/*` paths above are the **lab** layout. In the production
per-service install (§8) the admin CLI material is root-only under
`/etc/infrabroker/pki/admin/`, and the seeded `/etc/infrabroker/broker-ctl.json`
points both sections at `pki/admin/admin.{crt,key}` with the shared
`pki/mtls_ca.crt` — no service user can read it and impersonate the admin.

Search order: `--client-config` → `$BROKER_CTL_CONFIG` →
`~/.config/broker-ctl/config.json` → `/etc/infrabroker/broker-ctl.json`
(the production installer seeds the last one). The current working directory is
**not** searched — an implicit `./broker-ctl.json` could let a planted file
redirect the CLI's mTLS endpoint and CA trust anchor, so a project-local file
must be named explicitly with `--client-config`. Per-parameter precedence:
**explicit flag > env var > file > built-in default**. Environment variables:
`BROKER_CTL_SIGNER_{URL,CERT,KEY,CA}` for the signer section,
`BROKER_CTL_CP_{URL,CERT,KEY,CA}` for the control plane. See
`broker-ctl.example.json`. When a config file omits `cert`/`key`/`ca`, the
built-in `./pki/*` default is resolved relative to that file's directory (not
the current working directory), so a partial file cannot pull the mTLS trust
material from wherever `broker-ctl` happens to run.

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
# ssh-agent — CA key in a YubiKey PIV slot / SoftHSM / TPM (loaded with
# `ssh-add -s <pkcs11.so>`); the only hardware-custody option that supports Ed25519:
broker-ctl ca-keys add --name _default --type agent \
  --public-key-path pki/ssh_ca.pub          # --socket defaults to $SSH_AUTH_SOCK
broker-ctl ca-keys list
broker-ctl ca-keys remove prod-web
```

The **agent** backend keeps the CA private key in a running ssh-agent (no cgo in
the signer, no cloud). `public_key_path` pins which agent key is the CA; the
signer confirms it is present at startup (fail-closed) and re-dials the agent for
each signature. Caveats: the signer's systemd unit needs the agent socket
(`SSH_AUTH_SOCK` in the environment, socket readable by the service user); and a
touch-required policy (`sk-*`, PIV touch) breaks unattended per-operation signing
— use a presence-optional slot for a service CA.

### Callers (group RBAC table)

```bash
broker-ctl callers add --name broker-1 --groups prod-web,staging
broker-ctl callers add --name broker-1 --groups prod-web --force   # update
broker-ctl callers add --name _default --groups platform   # grant unlisted CNs a baseline
broker-ctl callers list
broker-ctl callers remove broker-1
```

A non-empty `callers` table is already default-deny, so unlisted CNs need no
`_default` entry to be denied. Add `_default` with groups only to *grant* every
unlisted CN a baseline; an explicitly-empty `--groups ""` writes
`allowed_groups: []` (the same deny you get by omitting `_default`).

**In-conversation approval opt-in (`self_approve`, #118).** A caller entry may
carry `"self_approve": true`, which lets that broker CN approve its **own**
`require_approval` commands — the signer otherwise honours `approved` only from
the control plane. It deliberately **waives four-eyes** for that CN and is meant
for a single-operator stdio broker where the same human requests and approves
in the MCP client. Pair it with `approval_via_elicitation: true` on that broker's
config (the broker asks the human via elicitation; on approval it re-signs with
`approved`). In **single-binary** mode the broker is the signer, so
`approval_via_elicitation` alone enables it. Leave both off (the default) to keep
four-eyes and approve through `broker-ctl` / the web UI / the Slack bridge. Each
self-approval is audited `self_approved`.

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
and would invert the host to default-deny); grants **survive a config reload**, and
with `state_db` set they also **survive a signer restart** (without it they are
dropped — fail-safe, the baseline is more restrictive); every create/revoke is in
the signed audit log (`grant-created` / `grant-revoked`).

### Freezing a subject: the kill switch (#117)

A **freeze** immediately cuts a subject off: it gets **no new certificate**
(`/v1/sign`) and **no connectivity** (`/v1/hosts`), its runtime grants and
approve-and-learn waivers are revoked, and every broker force-closes its live
sessions on its next revocation poll (`revocation_poll_seconds`, default 10s —
this is the kill latency for an established session, including one running a
command). Operator-only (mTLS, CN in `reload_callers`), audited (`frozen` /
`unfrozen`; the broker records `session_killed`). A subject is one of:
`--caller <CN>`, `--end-user <u>`, `--session-id <id>`, `--serial <n>`.

```bash
# Incident: broker-1 looks compromised. Freeze it — no new access, sessions killed.
broker-ctl freeze --caller broker-1 --reason incident-4821
# → frozen caller=broker-1 (grants revoked: 2)

# Freeze one end user, or one specific live session / certificate:
broker-ctl freeze --end-user alice --reason offboarding
broker-ctl freeze --serial 12345

# Kill a single runaway session by id (sugar for freeze --session-id):
broker-ctl session kill 7f3c...

# List what is frozen; release when the incident is over:
broker-ctl revocations
# KIND         VALUE          FROZEN AT (UTC)       BY      REASON
# caller       broker-1       2026-07-09T06:00:00Z  admin   incident-4821
broker-ctl unfreeze --caller broker-1
```

> **Requires `state_db`.** Freezes are persisted **fail-closed**: with `state_db`
> set they survive a signer restart, and the signer **refuses to start** if it
> cannot load the freeze set (a lost freeze would fail *open*). **Without**
> `state_db` a freeze is volatile (lost on restart), so since v2.0.0
> `broker-ctl freeze` is **refused** unless you pass `--volatile` to accept a
> memory-only freeze — set `state_db` in production.

> **Avoid self-lockout.** Do not freeze the `caller` CN your own tooling or the
> control plane uses, or you cut off the path you administer through. Freezes are
> keyed on the mTLS CN, so a broker sharing a CN with an approver/forwarder is
> affected too. Prefer freezing a narrower subject (`end_user`, `session_id`,
> `serial`) when possible.

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

### Approve from chat: the approval bridge (Slack)

`cmd/approval-bridge` posts pending approvals to a chat platform with **Allow /
Deny buttons** and relays the decision back — approvers act without leaving chat
or opening the web UI. It is **outbound-only** (polls the control plane's mTLS
`GET /v1/approvals`, connects out to the platform), so nothing with approval
authority becomes internet-facing, and it decides with its **own approver CN**,
leaving the control plane's consumed-once guard unchanged. Because it decides
with the bridge CN, the control plane's four-eyes guard can't see the human who
clicked; configure `--identity-map` (below) to have the bridge enforce four-eyes
for the platform path itself.

**Slack (Socket Mode):**

1. Create a Slack app; enable **Socket Mode** and generate an **app-level token**
   (`xapp-…`, scope `connections:write`).
2. Add bot scope `chat:write`, install to the workspace, take the **bot token**
   (`xoxb-…`), and invite the bot to the approvals channel.
3. Give the bridge an **approver mTLS cert** whose CN is in the control plane's
   `approval.callers` — a dedicated CN, distinct from any broker.
4. Run it (tokens via env, never flags):

```bash
SLACK_BOT_TOKEN=xoxb-… SLACK_APP_TOKEN=xapp-… \
  approval-bridge --cp-url 127.0.0.1:7443 \
    --cert pki/approver.crt --key pki/approver.key --ca pki/mtls_ca.crt \
    --slack-channel C0123456789 \
    --identity-map pki/slack-identities.json   # optional; enables four-eyes (below)
```

5. **(Recommended) Enforce four-eyes with `--identity-map`.** Point it at a JSON
   object mapping each **Slack user id** to the **end-user identity** (the OIDC
   identity that appears as `end_user` on the request) it belongs to:

   ```json
   { "U0123ABC": "alice@corp.com", "U0456DEF": "bob@corp.com" }
   ```

   With the map set, the bridge **refuses an Approve whose clicker maps to the
   request's originating end user** (`BRIDGE_IDENTITY_MAP` is the env equivalent).
   The guard fails **open**: a click by an unmapped user, or on a request with no
   `end_user`, is relayed as before — so the map is a strict, opt-in improvement,
   not a lockout. Without it the bridge behaves as it always has (the documented
   residual). Keep the map in sync with your directory; a stale entry only means a
   self-approval it no longer recognises slips through, never a false denial of a
   legitimate approver.

**Teams:** an in-card Allow/Deny button is a **deferred** adapter — Teams needs a
Bot Framework bot with a *public inbound* endpoint (it can't present a client
cert and Incoming Webhooks don't support `Action.Submit`), which reintroduces the
friction Slack's outbound-only Socket Mode avoids. Meanwhile **Teams approval
works today**: set `notifier: "teams"` and point `approval_url_template` at
`https://<control-plane>/ui/approvals/{id}` — the card's "View request" link
lands the approver on the mTLS web UI to decide.

> **Trust note.** The bridge decides with one approver CN, so "who may approve"
> moves partly to **chat channel membership**, and approver attribution in the
> audit is **bridge-asserted** (bridge CN + platform user id) — see
> [THREAT_MODEL](THREAT_MODEL.md). `--identity-map` restores **four-eyes** (an
> originator can't approve their own request in chat) but not cryptographic
> attribution. For a single operator, the in-conversation elicitation approval
> (above) avoids the bridge; for per-human attribution, approve via `broker-ctl`
> or the web UI (per-human mTLS certs).

### Action budgets: rate limits + behavior guardrails

Beyond *what* an agent may run (the command policy) and *whether* a human must
approve it, infrabroker bounds *how much* an agent may do — a budget over its
actions per window, so a hijacked or runaway agent is throttled and its
deviations surface. Two independent, opt-in layers:

**Signer — per-CN sign budget.** `sign_rate_limit_per_min` in `signer.json` caps
`POST /v1/sign` requests per authenticated broker CN (token bucket: burst up to
the cap, then continuous refill). Excess gets `429` + `Retry-After`; these
rejections are deliberately **not** audited, so the tamper-evident log cannot
become a flooding amplifier. Off by default — set it in production.

**Control plane — per-subject behavior budget.** The `behavior` block budgets and
watches each agent's activity. The subject is the broker CN, or `<CN>:<end_user>`
when that CN is a `trusted_forwarder`.

```json
// control-plane.json
"behavior": {
  "mode": "enforce",               // off | observe | enforce
  "rate_limit_per_min": 60,        // per-subject operation budget (1-min sliding window)
  "max_distinct_per_subject": 128, // bound on tracked hosts / command fingerprints
  "subject_ttl_minutes": 60,       // evict a subject idle this long
  "max_subjects": 4096             // cap tracked subjects (LRU eviction)
}
```

- `observe` audits deviations (`anomaly`) but never blocks — run it first to
  learn a baseline, then switch to `enforce`.
- `enforce` **denies** a subject over `rate_limit_per_min` with `429` (blocked
  attempts are still counted, so a flood cannot evade the cap), and **escalates
  to human approval** on a deviation from the agent's pattern: the subject's
  first request sets the baseline, and a *subsequent* host it has not used or a
  *novel* command (first-token fingerprint) is flagged — so the human is asked on
  the **first deviation**, not after N. A novel value is learned only once its
  approval is granted, so a repeated unapproved anomaly stays anomalous. Novelty
  tracking is bounded: past `max_distinct_per_subject` it degrades to "seen"
  rather than emitting unbounded escalations.

The contrast with network-layer tools is the point: a mesh/VPN budgets what an
agent can *reach*, and an LLM gateway (e.g. NetBird's Agent Network) budgets what
it *spends* on model calls; infrabroker budgets the **actions themselves** — how
many operations, and any drift from the agent's established pattern — because
every action is individually inspected and signed. Budgets over actions are only
possible at the layer that sees each action.

> **Future — per-operation-class caps (build with demand).** A natural extension
> is budgeting per *class* of operation (sudo executions, mutating Kubernetes
> verbs, file transfers) rather than uniformly. Design, if it is built: it lives
> in the control plane's `BehaviorConfig` (the signer stays stateless per the
> threat model), in-memory like the current tracker (restart resets the
> baseline), exhaustion **denies with `429`** and never auto-escalates (an
> exhausted budget is not an anomaly, and flooding the approval queue would be an
> amplification vector), and is audited edge-triggered. File-transfer
> classification needs a new wire field, so it bundles with the next protocol
> revision. Not built yet — open an issue if you need it.

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

#### Exporting the audit log to WORM / SIEM

The audit trail is a local append-only JSONL file — one Ed25519-signed,
hash-chained entry per line — plus `/metrics`. To retain it off-host in immutable
(WORM) storage and/or feed a SIEM, run a standard log shipper as a **sidecar**
that tails the file. infrabroker deliberately does **not** push logs itself, so a
slow or unreachable SIEM can never block an action: the local file stays the
fail-closed source of truth, and the shipper only reads it.

Two distinct goals, best served by two sinks:

- **WORM archive (authoritative).** Ship to **S3 Object Lock** (or GCS retention)
  so a host compromise cannot delete or rewrite already-exported records. Combined
  with the per-entry signatures and hash chain, the archive is both
  **tamper-proof** (Object Lock) and **tamper-evident** (the chain): pull a copy
  back and run `broker-ctl audit verify --all --key <seed>` to prove it is intact
  and complete.
- **SIEM (search / alerting).** Ship to **syslog / Loki / a generic HTTP sink**
  for dashboards and alerts on `outcome=denied`, `anomaly=…`, `approved_by=…`.
  Best-effort operational visibility, not the authoritative copy.

What to ship, and how:

- **Include the rotated segments.** Rotation renames the file to
  `<log>.<YYYYMMDDTHHMMSSZ>` (with a `.<n>` suffix on same-second collisions), so
  glob `audit.log*` to follow the live file and every segment. Exclude the
  audit-repair quarantine file `<log>.corrupt-*` — it is quarantined, not part of
  the chain.
- **Ship each line verbatim and in order.** Do not parse-and-re-encode the JSON or
  reorder lines: each line carries its own signature and links to the previous via
  `prev_hash`, so byte-exact lines in sequence are what `audit verify` checks.
- **Secrets are already redacted** before an entry is signed, so no secret
  material leaves the host (see the `redact` config).

A ready-to-adapt **Vector** reference for the S3-Object-Lock + syslog/Loki pattern
is in `deploy/vector.example.toml` — validate it with `vector validate` first. The
same sidecar pattern works with any shipper (Fluent Bit, Filebeat, Promtail,
rsyslog).

#### Recovering a torn audit log (signer won't boot)

The signer is **fail-closed** on audit-log corruption. If a crash or power loss
tears the *final* record mid-write (a truncated, unparseable trailing line), the
signer refuses to start — you will see a fatal
`audit: restoring audit chain: parsing last log entry: …` — rather than silently
continuing over a gap. On a tamper-evident, hash-chained log a truncated tail is
indistinguishable from a truncation attack, so recovery is a deliberate operator
action, never automatic:

```bash
# 1. Inspect what would be dropped (dry-run — makes NO changes):
broker-ctl audit repair --log /var/lib/infrabroker/signer/signer_audit.log

# 2. (optional) confirm the kept prefix's signatures are intact first:
broker-ctl audit repair --log signer_audit.log --key pki/signer_audit.seed

# 3. Apply: quarantine the torn bytes to <log>.corrupt-<timestamp> and truncate
#    the log to the last well-formed record so the signer can boot. The hash
#    chain continues from there; keep the quarantine file for forensics.
broker-ctl audit repair --log signer_audit.log --apply
```

`repair` only ever removes a contiguous corrupt *suffix*. If it finds a malformed
record *before* a well-formed one (mid-file corruption, which does not block
startup because the signer reads the last line), it refuses and points you to
`audit verify` to investigate.

#### Actions failing with "audit unavailable" (fail-closed audit)

Since v2.0.0 the signer and broker are **fail-closed on audit writes** by default
(`audit_fail_mode: "closed"`): if the audit log cannot be written, the signer
issues no certificate and the broker withholds the result, both returning
`500 "audit unavailable"`. This is the honest availability trade — a full or
unwritable audit disk stops actions until it is resolved. When operations start
failing with that error:

```bash
# 1. Confirm it is the audit sink: the metric jumps and the process log carries
#    "audit unavailable, denying action" / "…withholding result".
curl -s http://127.0.0.1:9160/metrics | grep -E 'audit_(append_failures|blocked)_total'

# 2. The usual cause is a full or read-only filesystem under the audit path.
df -h /var/lib/infrabroker/signer   # and .../broker
journalctl -u infrabroker-signer -n 50

# 3. Free space / fix permissions / rotate off old segments, then actions resume
#    automatically (no restart needed — the next Append self-heals).
```

Break-glass: if you must keep operating while fixing the disk, set
`audit_fail_mode: "open"` and **restart** the service (this setting is read at
startup, not hot-reloaded) — actions then proceed with only a logged warning and
the trail has a gap for that window. Revert to `closed` and restart once healthy.
Usually unnecessary: once the disk is fixed the next `Append` self-heals and
actions resume with no config change.

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
infrabroker --version --verbose
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
10. **Remote mode warns about ignored local-mode fields:** unlike a typo, a
    *known* field the active mode ignores still passes strict validation. When the
    `signer` block is set (remote mode), a `ca_key`/`ca_keys`, `command_policies`,
    or any per-host policy field (`command_policy`, `allow_sudo`, `principal`, …)
    is dead weight — the host inventory and policy come from the signer. The
    broker logs one aggregated startup warning naming them, so a present-but-
    inactive policy is never mistaken for an enforced one (the same error class
    as the `_default` firewall gap, #82).
11. **Configs accept JSONC** (#183): every config file (`config.json`,
    `signer.json`, `control-plane.json`, `broker-ctl.json`) may carry `//` and
    `/* */` comments and trailing commas — now the canonical way to annotate a
    config. Plain JSON keeps loading unchanged, and the legacy `_*` comment keys
    keep working (deprecated in favour of real comments). Malformed JSONC fails
    closed like any other parse error, on startup and on every reload path.

### Per-agent identity: OAuth2 client_credentials

The HTTP frontend authenticates every request with an OIDC bearer token and keys
audit + per-user RBAC on the token's identity. Give **each AI agent its own IdP
identity** the way a human gets one — an OAuth2 **client_credentials service
account**, one client per agent. Its actions are then attributed to it, its RBAC
groups gate which hosts it reaches, and revoking access is disabling the client
in the IdP. No infrabroker change is needed — the verifier is claim-agnostic (the
`ClientCredentials` cases in `internal/oauth/verifier_test.go`); it is IdP
configuration. Three non-obvious bits (Keycloak; reproducible lab
`lab/run_oauth_lab.sh`):

- **`"user_claim": "azp"`** in the frontend `oauth` block. In a Keycloak
  client_credentials token `sub` is the service-account **UUID**; `azp` carries
  the client id — the stable, human-meaningful identity you want in the audit log
  and RBAC.
- **An audience mapper** on the client emitting your `audience` (e.g.
  `infrabroker`). Keycloak's default `aud` is `account`, which the verifier
  rejects.
- **A group-membership mapper** on the service account so the token carries the
  `groups` claim. With `groups_claim` configured the verifier is fail-closed: a
  token without it is rejected (it would otherwise bypass per-user RBAC).

```json
"oauth": {
  "issuer":       "https://keycloak.example/realms/infrabroker",
  "audience":     "infrabroker",
  "user_claim":   "azp",
  "groups_claim": "groups"
}
```

The agent obtains a token with the standard grant and sends it as the MCP bearer;
keep the client secret in the agent's secret store, never in prompts or tool logs:

```bash
curl -s https://keycloak.example/realms/infrabroker/protocol/openid-connect/token \
  -d grant_type=client_credentials -d client_id=agent-ci-runner -d client_secret=<secret>
```

This is the layer network tools cede: a mesh or LLM gateway can give an agent an
identity to *reach* endpoints or meter its spend; here that identity is bound to
**what the agent may execute**, and to every signed audit line.

---

## 7. Monitoring

Every service accepts an optional `monitor_listen` config key (empty or absent
= disabled) that starts a **separate plain-HTTP listener** with two endpoints:

| Endpoint | Purpose |
|---|---|
| `/healthz` | Liveness: `200 ok` while the process is serving. Use it for load-balancer/systemd/container health checks. |
| `/metrics` | Metrics in the Prometheus text exposition format. |

The broker config key covers all three broker transports (`infrabroker
serve-http` / `serve-mcp` / `serve-mcp-http`, and their legacy `broker` /
`mcp-broker` / `mcp-broker-http` wrappers); the signer and control plane have
their own key in `signer.json` / `control-plane.json`.

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
| `broker_revocation_poll_errors_total` | broker frontends (remote mode) | Failed signer freeze-set fetches by the kill-switch revocation poll (#117/#126). **Alert on any increase**: while it climbs the broker is not force-closing sessions of newly-frozen subjects — the kill switch is degraded even though new-cert issuance stays blocked signer-side. |
| `broker_revocation_poll_last_success_timestamp_seconds` | broker frontends (remote mode) | Unix time of the last successful revocation-poll fetch (gauge). **Alert when `time() - ` this exceeds a few `revocation_poll_seconds` intervals**: it catches a stopped or persistently-erroring poll that would otherwise silently disable the live-session kill switch. |
| `audit_append_failures_total` | all | Audit-log `Append` errors. **Alert on any increase**: the machine-readable signal that the audit sink is failing. With `audit_fail_mode: "closed"` (the default) the audited action is then denied (see `audit_blocked_total`); with `"open"` it proceeds and the trail has a gap. |
| `audit_blocked_total` | signer, broker | Actions denied because the audit log could not be written and the service is fail-closed (`audit_fail_mode: "closed"`). **Alert on any increase**: operations are being refused with `500 "audit unavailable"` — check the audit filesystem (threat-model gap #9). |

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
make dist                        # dist/infrabroker-<version>.tar.gz
# on the target host, as root:
./deploy/install.sh              # per-service users, dirs, binaries, units, seed configs
systemctl enable --now infrabroker-signer   # always the signer first
```

Reference layout: binaries in `/usr/local/bin`, the control-plane / mcp-http
configs and the mTLS PKI in `/etc/infrabroker/` (root-owned, never overwritten
on upgrade), audit logs in `/var/lib/infrabroker/<svc>/`. The **signer config
lives in `/var/lib/infrabroker/signer/signer.json`** (service-owned): the durable
policy-mutation API rewrites it in place, so it cannot sit in the read-only
`/etc` tree. Policy hot-reload maps to `systemctl reload infrabroker-signer`
(SIGHUP).

**Privilege separation (v1.35.0+):** each daemon runs as its own system user
(`infrabroker-signer`, `infrabroker-control-plane`, `infrabroker-mcp-http`); the
shared `infrabroker` group only grants traversal of `/etc/infrabroker` and read
of the shared mTLS CA cert. Each service's mTLS key lives in its own
`/etc/infrabroker/pki/<svc>/` (`0750 root:infrabroker-<svc>`), the admin CLI
material in `pki/admin/` (root-only), and only the CA **cert** sits at the
`pki/` root. A compromised broker frontend therefore cannot read the signer's
CA key, policy, state, or another service's key. See `deploy/README.md` for the
full layout and the upgrade steps from a single-user install.
The installer also seeds `/etc/infrabroker/broker-ctl.json` (client parameters,
see §4) so `broker-ctl host list --remote` works flag-less as the post-deploy
end-to-end check.

**CA custody is the operator's choice**, made in `signer.json` → `ca_keys`:
`"akv"` (Azure Key Vault — the private key never leaves the vault;
recommended for production; RSA/EC only) or `"pem"` (local file — lab/dev,
the signer logs a warning). Credentials for AKV come from
`DefaultAzureCredential` (managed identity, or a service principal via the
unit's optional `EnvironmentFile=/etc/infrabroker/signer.env`).

The full checklist — custody trade-offs, default-deny `callers`, rate
limits, upgrade caveats (in-memory approvals/sessions) — lives in
`deploy/README.md` in the repository.
