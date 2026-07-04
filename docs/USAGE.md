# Usage Guide — infrabroker MCP Tools

This document covers practical usage of the seven MCP tools exposed by
`cmd/mcp-broker` (stdio) and `cmd/mcp-broker-http` (HTTP+OAuth2/OIDC).

Keep this file up to date whenever a tool is added, removed, renamed, or its
parameters or behaviour change.

---

## Table of Contents

1. [Before you start](#1-before-you-start)
2. [ssh\_execute — one-shot command](#2-ssh_execute--one-shot-command)
3. [ssh\_session\_open / exec / close — persistent session](#3-ssh_session_open--exec--close--persistent-session)
4. [Common patterns](#4-common-patterns)
5. [Error handling](#5-error-handling)
6. [Quick reference](#6-quick-reference)
7. [Reviewing audit logs](#7-reviewing-audit-logs)
8. [Session recording](#8-session-recording)
9. [ssh\_put\_file / ssh\_get\_file — file transfer](#9-ssh_put_file--ssh_get_file--file-transfer)

---

## 1. Before you start

**Always call `ssh_list_servers` first.** It returns the hosts accessible to
you, together with the capabilities that determine which parameters are valid
for each host. In the HTTP+OAuth frontend the list is already filtered by your
RBAC groups — a host you cannot sign for is not listed.

```
tool: ssh_list_servers
params: (none)
```

Example response:

```
web01 (sudo=true pty=true file_transfer=true)
db01  (sudo=false pty=false file_transfer=false)
bastion (sudo=false pty=false file_transfer=false)
app02 (sudo=true pty=true file_transfer=false via=bastion)
```

What the fields mean:

| Field | Value | What it implies |
|---|---|---|
| `allow_sudo` | `true` | You may use `sudo=true` in execute/session calls. |
| `allow_sudo` | `false` | Do **not** pass `sudo=true`. The signer will reject it. Do not retry. |
| `allow_pty` | `true` | You may use `pty=true` (execute) or `mode=pty` (session). |
| `allow_pty` | `false` | Do **not** request a PTY. Do not retry. |
| `allow_file_transfer` | `true` | You may use `ssh_put_file` / `ssh_get_file` (see [§9](#9-ssh_put_file--ssh_get_file--file-transfer)). |
| `allow_file_transfer` | `false` | Do **not** attempt file transfers. The signer will reject them. Do not retry. |
| `jump` | `"bastion"` | The host is reached via a ProxyJump hop through `bastion`. Transparent — no extra action needed. |

**Operator note — host groups, CA keys and broker-ctl (v1.11.1):** each host in `signer.json` belongs to one or more `groups`. Those groups determine both RBAC visibility (which broker CN can reach the host) and, if the operator has configured `ca_keys`, which CA key signs its certificates. From the model's perspective this is transparent — the tools and their parameters are unchanged. Operators manage hosts, CA keys, callers, and command policy via `broker-ctl`; see [OPERATIONS.md §4](OPERATIONS.md#4-broker-ctl). Per-host command policy (allowlist, denylist, require-approval) is configured with `broker-ctl host add --policy-mode` flags and takes effect after the next `broker-ctl reload`.

---

## 2. ssh_execute — one-shot command

Use `ssh_execute` when you need to run **one command** (or several independent
commands) on a host. Each call issues a fresh ephemeral certificate scoped to
exactly that command (`force-command` in the cert). The connection is opened,
the command runs, and the connection is discarded.

### 2.1 Basic execution

```
tool: ssh_execute
params:
  server:  "web01"
  command: "uptime"
```

Response:

```
 12:03:47 up 42 days,  3:21,  1 user,  load average: 0.12, 0.08, 0.05

[exit=0 serial=1042]
```

`exit=0` means success. `serial` is only useful for audit log correlation — the
model should not reason over it.

### 2.2 Capturing both stdout and stderr

```
tool: ssh_execute
params:
  server:  "web01"
  command: "ls /nonexistent"
```

Response:

```

[stderr]
ls: cannot access '/nonexistent': No such file or directory

[exit=2 serial=1043]
```

`exit_code != 0` is a **remote command failure**, not a tool error. Handle it
the same way you would a process that exits with a non-zero status.

### 2.3 With sudo (root)

Requires `allow_sudo=true` on the host (check `ssh_list_servers` first).

```
tool: ssh_execute
params:
  server:  "web01"
  command: "systemctl restart nginx"
  sudo:    true
```

The signer bakes `sudo -n -- /bin/sh -c 'systemctl restart nginx'` into the
cert's `force-command`. `sshd` enforces it; the broker cannot modify it.

### 2.4 With sudo to a specific user

```
tool: ssh_execute
params:
  server:    "web01"
  command:   "id"
  sudo:      true
  sudo_user: "deploy"
```

`sudo_user` must be in the host's `allowed_sudo_users` list. Empty `sudo_user`
defaults to `root`.

### 2.5 With PTY

Use `pty=true` only when the command explicitly requires a terminal (checks
`isatty()`, uses terminal control sequences, etc.). Requires `allow_pty=true`.

```
tool: ssh_execute
params:
  server:  "web01"
  command: "top -b -n 1"
  pty:     true
```

**Important:** with `pty=true`, stdout and stderr are merged in the PTY stream.
The `stderr` field in the response will be empty.

### 2.6 Overriding the certificate TTL

By default the broker requests the maximum TTL allowed by the host policy. Pass
`ttl_seconds` to request a shorter window.

```
tool: ssh_execute
params:
  server:      "web01"
  command:     "date"
  ttl_seconds: 30
```

### 2.7 Dry-run — preview without executing

Pass `dry_run=true` to check whether a command **would** be allowed by the host's
command policy (and whether it would require human approval) **without connecting
or running anything**. Nothing executes; no `stdout` is produced.

```
tool: ssh_execute
params:
  server:  "web01"
  command: "systemctl restart nginx"
  dry_run: true
```

Response (allowed, but approval-gated):

```
[dry-run] ALLOWED (requires human approval before executing)
rule: require_approval:^systemctl restart
force-command: systemctl restart nginx
ttl: 120s
```

Response (denied by command policy):

```
[dry-run] DENIED: command not allowed on "web01" by command_policy (allowlist:no-match)
```

Response (allowed because the host is in command-policy audit mode):

```
[dry-run] ALLOWED
rule: allowlist:no-match
warning: command_policy audit: would deny (allowlist:no-match)
force-command: rm -rf /tmp/example
ttl: 120s
```

Use dry-run to decide whether to proceed before committing an action. A host may
restrict commands via an **allowlist** or **denylist** (see the
[AI-action firewall](ARCHITECTURE.md#ai-action-firewall) in ARCHITECTURE.md).
When a policy uses `enforcement: "audit"`, the command is allowed but the
response and audit log carry `would_deny` / `would_require_approval` warnings.
Use this only to collect a baseline before switching to `enforce`.

### 2.8 Commands that require human approval

Some commands are configured to require **human approval** before they run
(`require_approval` in the host policy). When you call `ssh_execute` for such a
command, the tool **blocks** while a human is asked to approve out-of-band:

```
tool: ssh_execute
params:
  server:  "web01"
  command: "systemctl restart nginx"
```

- If approved, the call returns normally (stdout / exit code) once the human
  approves — this may take seconds to minutes.
- If denied or it times out, the call returns an error explaining the command was
  not approved. **Do not retry automatically**; surface the outcome to the user.

You can check ahead of time whether a command needs approval with
`dry_run: true` (the response says "requires human approval"). This lets you
warn the user that the action will pause for approval before you run it.

**Approve-and-learn.** When a human approves, they may also *learn* the decision
(`broker-ctl approval allow <id> --learn --ttl 2h`). After that, the **same command
on that host, from the same broker/end-user identity, runs without prompting again**
until the waiver expires — so a follow-up `ssh_execute` (or a `dry_run`) of that exact
command returns immediately instead of blocking. This is decided entirely by the
human/operator; from your side nothing changes except that a previously-gated command
may stop pausing for a while. When the waiver expires the approval gate returns
automatically.

**Note:** approval can also be triggered *dynamically* by behavioral guardrails —
e.g. the first time you touch a new host, or run an unusual command, the
deployment may require a human to approve it even if the command itself isn't on
the approval list. Additionally, a burst of commands may be rate-limited (the call
returns a "rate limit" error); if that happens, slow down and inform the user
rather than retrying in a tight loop.

The operator's notification channel (how the approval request reaches the human)
is configured server-side — options include a process log, a generic webhook, or
a Microsoft Teams card (`notifier: "teams"` in `control-plane.json`). This does
not affect how the tool behaves from the model's perspective.

---

## 3. ssh_session_open / exec / close — persistent session

Use sessions when you need:

- **Stateful execution** — `cd` to a directory and run subsequent commands
  there, or set environment variables that persist across calls.
- **Reduced latency** — the SSH connection is established once and reused.
- **Interactive programs** — editors, pagers, or programs that require a real
  TTY (`mode=pty`).

> Always close a session when done with `ssh_session_close`. Open sessions hold
> an SSH connection until they are closed or reaped. The reaper closes a session
> after `session_idle_seconds` of inactivity or `session_max_seconds` of total
> lifetime — **not** when the certificate TTL elapses: OpenSSH validates the
> certificate only at authentication, so an already-established connection
> survives certificate expiry. Set `session_max_seconds` to the maximum exposure
> window you are willing to accept.

### 3.1 mode=exec (default) — isolated commands, shared connection

Each `ssh_session_exec` call runs in a separate SSH channel. State (working
directory, variables) does **not** persist between calls. Use this when you want
connection reuse without state leakage.

The broker preflights every `ssh_session_exec` against the current signer policy
before sending it to SSH. This applies to sessions that were already open before
a signer reload: target and bastion access, end-user groups, sudo, sudo_user and
PTY are revalidated on the next call. The broker also checks whether the host's
physical SSH route (`addr`, `user`, `host_key`, or `jump`) changed since the
session was opened; if it did, the next command is rejected and you must open a
new session.
If a `command_policy` is added to the host, `mode=exec` commands are checked,
and `mode=shell` / `mode=pty` commands are rejected because stateful streams are
not independently verifiable. In `enforcement: "enforce"` a denied or
approval-gated command is not executed; in `enforcement: "audit"` it executes
and returns a warning.

```
tool: ssh_session_open
params:
  server: "web01"
  mode:   "exec"
```

Response: `session_id=abc123 serial=1050`

```
tool: ssh_session_exec
params:
  session_id: "abc123"
  command:    "hostname"
```

Response: `web01\n[exit=0 serial=1050]`

Audit-mode response example:

```
web01
[warning] command_policy audit: would deny (allowlist:no-match)
[exit=0 serial=1050]
```

```
tool: ssh_session_close
params:
  session_id: "abc123"
```

Response: `closed`

### 3.2 mode=shell — stateful shell

A single `/bin/sh` process is started. `cd`, variable assignments, and
environment changes persist across `ssh_session_exec` calls.

Hosts with a `command_policy` reject `mode=shell`; use `mode=exec` for
preflighted repeated commands, or `ssh_execute` for the strongest one-shot
`force-command` guarantee.

```
tool: ssh_session_open
params:
  server: "web01"
  mode:   "shell"
```

Response: `session_id=def456 serial=1060`

```
tool: ssh_session_exec
params:
  session_id: "def456"
  command:    "cd /var/log && pwd"
```

Response: `/var/log\n[exit=0 serial=1061]`

```
tool: ssh_session_exec
params:
  session_id: "def456"
  command:    "ls -lh nginx/"
```

Response (still in `/var/log`):

```
total 48M
-rw-r--r-- 1 root root  12M Jun  5 11:00 access.log
-rw-r--r-- 1 root root 256K Jun  5 11:00 error.log

[exit=0 serial=1062]
```

```
tool: ssh_session_close
params:
  session_id: "def456"
```

### 3.3 mode=pty — interactive shell with PTY

Opens a shell with a pseudo-terminal. Use for programs that call `isatty()`,
check `$TERM`, or produce terminal-formatted output. Requires `allow_pty=true`.
Hosts with a `command_policy` reject `mode=pty`.

stdout and stderr are **merged** in the PTY stream.

```
tool: ssh_session_open
params:
  server: "web01"
  mode:   "pty"
```

Response: `session_id=ghi789 serial=1070`

```
tool: ssh_session_exec
params:
  session_id: "ghi789"
  command:    "journalctl -u nginx --no-pager -n 20"
```

```
tool: ssh_session_close
params:
  session_id: "ghi789"
```

### 3.4 Session with sudo (root escalation)

Requires `allow_sudo=true` (check `ssh_list_servers`).

**mode=shell or mode=pty with sudo:** the entire shell process is launched as
`sudo -n -- /bin/sh`. Every command in the session runs elevated.

```
tool: ssh_session_open
params:
  server: "web01"
  mode:   "shell"
  sudo:   true
```

```
tool: ssh_session_exec
params:
  session_id: "<id>"
  command:    "cat /etc/shadow | head -3"
```

**mode=exec with sudo:** each command is individually prefixed with the sudo
prefix returned by the signer (`elevation_prefix`).

```
tool: ssh_session_open
params:
  server: "web01"
  mode:   "exec"
  sudo:   true
```

### 3.5 Session with sudo to a specific user

```
tool: ssh_session_open
params:
  server:    "web01"
  mode:      "shell"
  sudo:      true
  sudo_user: "appuser"
```

---

## 4. Common patterns

### 4.1 Check service status across multiple hosts

```
# For each host in the list:
tool: ssh_execute
params:
  server:  "web01"
  command: "systemctl is-active nginx"

tool: ssh_execute
params:
  server:  "app02"
  command: "systemctl is-active myapp"
```

### 4.2 Deploy a config change and restart a service

```
tool: ssh_session_open
params:
  server: "web01"
  mode:   "shell"
  sudo:   true

tool: ssh_session_exec
params:
  session_id: "<id>"
  command:    "cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak"

tool: ssh_session_exec
params:
  session_id: "<id>"
  command:    "printf 'server { listen 80; ... }' > /etc/nginx/conf.d/app.conf"

tool: ssh_session_exec
params:
  session_id: "<id>"
  command:    "nginx -t && systemctl reload nginx"

tool: ssh_session_close
params:
  session_id: "<id>"
```

### 4.3 Investigate a failing service

```
tool: ssh_session_open
params:
  server: "web01"
  mode:   "shell"
  sudo:   true

tool: ssh_session_exec
params:
  session_id: "<id>"
  command:    "systemctl status myapp --no-pager"

tool: ssh_session_exec
params:
  session_id: "<id>"
  command:    "journalctl -u myapp --no-pager -n 50"

tool: ssh_session_exec
params:
  session_id: "<id>"
  command:    "ss -tlnp | grep :8080"

tool: ssh_session_close
params:
  session_id: "<id>"
```

### 4.4 Disk usage check

```
tool: ssh_execute
params:
  server:  "web01"
  command: "df -h && du -sh /var/log/* 2>/dev/null | sort -rh | head -10"
```

### 4.5 Host reachable via bastion (ProxyJump)

No special parameters needed. The broker resolves the hop chain automatically.
`ssh_list_servers` will show `jump=bastion` on the host entry.

```
tool: ssh_execute
params:
  server:  "app02"
  command: "uptime"
```

The broker signs two certificates (one for the bastion, one for `app02`) and
tunnels through automatically.

---

## 5. Error handling

### 5.1 Remote command failure vs tool error

`exit_code != 0` means the **remote command** failed. It is not a tool error.
Treat it as you would any process that exits non-zero.

```
# exit_code=1 from grep when no match found — not an error:
tool: ssh_execute
params:
  server:  "web01"
  command: "grep 'pattern' /var/log/app.log"
# Response: [exit=1 serial=...] → no match, not a failure worth alerting on
```

A **tool error** (`IsError: true` in the MCP response) means the broker itself
could not complete the request — e.g., the host is unknown, the signer rejected
the intent, or the SSH connection failed. These are actual errors that need
attention.

### 5.2 sudo rejected

If `allow_sudo=false` on a host and you pass `sudo=true`, the signer returns 403
and the tool returns an error. **Do not retry with sudo.** Inform the user that
the host does not permit privilege escalation.

```
# ssh_list_servers shows: db01 (sudo=false pty=false)
# Attempting sudo on db01 → tool error:
#   host "db01" does not allow elevation (allow_sudo=false)
# Correct response: inform the user, do not retry
```

### 5.3 PTY rejected

Same rule: if `allow_pty=false`, do not pass `pty=true` or `mode=pty`. Do not
retry.

### 5.4 Session expired or closed

If `ssh_session_exec` returns an error for a session ID that was previously
valid, the session was most likely closed by the reaper — after
`session_idle_seconds` of inactivity or `session_max_seconds` of total lifetime.
Open a new session.

### 5.5 Newlines in commands

Commands must not contain `\n` or `\r`:

- **`ssh_execute` (one-shot):** the signer rejects them — a newline would smuggle
  extra command lines past the host's command policy. Compose with `;` or `&&`
  instead.
- **`ssh_session_exec` in `shell`/`pty` sessions:** the broker rejects them, since
  a newline would inject additional commands into the persistent shell.
- **`ssh_session_exec` in `exec` sessions:** the command runs in an isolated
  channel, so the broker does not reject newlines by itself. If the current
  signer policy evaluates commands, the signer rejects newlines during preflight
  for the same command-policy reason as one-shot. Use multiple
  `ssh_session_exec` calls instead.

```
# Wrong — will be rejected:
command: "echo foo\necho bar"

# Correct:
tool: ssh_session_exec  command: "echo foo"
tool: ssh_session_exec  command: "echo bar"
```

---

## 6. Quick reference

### Tool selection

| Scenario | Tool |
|---|---|
| Single independent command | `ssh_execute` |
| Multiple commands, no shared state needed | `ssh_execute` (repeated) |
| Multiple commands with `cd` or env state | `ssh_session_open` (`mode=shell`) + `ssh_session_exec` |
| Program that requires a TTY | `ssh_execute` (`pty=true`) or `ssh_session_open` (`mode=pty`) |
| Lowest latency for many commands | `ssh_session_open` (`mode=exec`) + `ssh_session_exec` |
| Write a file (config, script) | `ssh_put_file` (requires `allow_file_transfer=true`) |
| Read a file (log, config) | `ssh_get_file` (requires `allow_file_transfer=true`) |

### Parameter constraints

| Parameter | Constraint |
|---|---|
| `sudo=true` | Only when `allow_sudo=true` (from `ssh_list_servers`). Never retry if `false`. |
| `sudo_user` | Must be in `allowed_sudo_users` for the host. Empty = `root`. |
| `pty=true` / `mode=pty` | Only when `allow_pty=true`. Never retry if `false`. |
| `command` | Must not contain `\n` or `\r` for one-shot `ssh_execute` and `shell`/`pty` session exec; use `;` or `&&`. Every session command is preflighted against the current signer policy: target and bastion access, end-user groups, sudo, sudo_user, PTY, and the physical host route are revalidated; when a host has `command_policy`, `mode=exec` must satisfy the allowlist/denylist and `shell`/`pty` commands are rejected. |
| `ttl_seconds` | Optional. Omit to use the host policy maximum. |
| `dry_run=true` | `ssh_execute` only. Simulates policy (allow/deny + approval) without executing. Nothing runs. |
| `ssh_put_file` / `ssh_get_file` | Only when `allow_file_transfer=true` (from `ssh_list_servers`). Never retry if `false`. Content capped by `file_transfer_max_bytes` (default 512 KiB). See [§9](#9-ssh_put_file--ssh_get_file--file-transfer). |

### Recommended workflow

```
1. ssh_list_servers          → discover hosts and their capabilities
2. ssh_execute               → for simple, independent commands
   — or —
   ssh_session_open          → for stateful / multi-step work
   ssh_session_exec (×N)
   ssh_session_close         → always close when done
```

---

## 7. Reviewing audit logs

Both the broker and the signer write append-only, Ed25519-signed, SHA-256-chained
audit logs. Every entry carries a `serial` (issued by the signer) and a `seq`
(monotonic per log), allowing precise correlation across the three audit sources
(signer, broker, sshd).

Default log paths (from the active config):

| Service | Log file | Signing seed |
|---|---|---|
| Broker | `audit.log` | `pki/audit.seed` |
| Signer | `signer_audit.log` | `pki/signer_audit.seed` |

### 7.1 Live tail

Follow the broker log as commands execute:

```bash
broker-ctl audit tail --log audit.log
broker-ctl audit tail --log audit.log -n 50   # show last 50 lines before following
```

Follow the signer log (certificate issuances):

```bash
broker-ctl audit tail --log signer_audit.log
```

Output columns: `TIME · SEQ · CALLER · HOST · OUTCOME · SERIAL · DETAIL`

### 7.2 Searching and filtering

Filter by host (substring match):

```bash
broker-ctl audit show --log audit.log --host web01
```

Filter by outcome:

```bash
# Broker outcomes: executed, denied, error, session_open, session_exec,
#                  session_close, dry_run_allowed, dry_run_denied,
#                  file_put, file_get
broker-ctl audit show --log audit.log --outcome denied

# Signer outcomes: issued, denied, approval-required, dry_run_allowed,
#                  dry_run_denied, reloaded, reload-denied, reload-failed
broker-ctl audit show --log signer_audit.log --outcome issued
```

Filter by caller:

```bash
broker-ctl audit show --log audit.log --caller mcp-stdio
```

Filter by time window:

```bash
broker-ctl audit show --log audit.log --since 2026-06-05
broker-ctl audit show --log audit.log --since 2026-06-05T12:00:00Z
```

Combine filters and limit output:

```bash
broker-ctl audit show --log audit.log --host db01 --outcome denied --limit 20
```

### 7.3 jq pipelines

Raw JSON output (`--json`) pipes directly into `jq`:

```bash
# All denied entries as pretty JSON:
broker-ctl audit show --log audit.log --outcome denied --json | jq .

# Extract serial numbers from denied signer entries:
broker-ctl audit show --log signer_audit.log --outcome denied --json \
  | jq -r .serial

# Correlate broker and signer by serial — find the cert that matches execution 1042:
broker-ctl audit show --log audit.log        --json | jq 'select(.serial==1042)'
broker-ctl audit show --log signer_audit.log --json | jq 'select(.serial==1042)'

# Count executions per host in the last hour:
broker-ctl audit show --log audit.log \
  --since "$(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --outcome executed --json \
  | jq -r .host | sort | uniq -c | sort -rn

# Show all sudo (elevated) entries:
broker-ctl audit show --log audit.log --json \
  | jq 'select(.elevation != null and .elevation != "")'

# Show all PTY sessions:
broker-ctl audit show --log audit.log --json | jq 'select(.pty == true)'
```

### 7.4 Verifying chain integrity

Verify hash chain only (no key needed):

```bash
broker-ctl audit verify --log audit.log
# OK: 1234 entries, chain intact (pass --key to also verify signatures)

broker-ctl audit verify --log signer_audit.log
```

Verify hash chain **and** Ed25519 signatures:

```bash
broker-ctl audit verify --log audit.log        --key pki/audit.seed
broker-ctl audit verify --log signer_audit.log --key pki/signer_audit.seed
# OK: 1234 entries, chain intact, all signatures valid
```

If tampering is detected, `verify` exits with code 1 and prints the affected
sequence number(s):

```
ERROR: seq 42 — prev_hash mismatch
  expected: 3a7f...
  got:      000...
FAIL: 1234 entries checked, 1 error(s) found
```

### 7.5 Audit entry fields reference

| Field | Type | Description |
|---|---|---|
| `time` | RFC3339 | Timestamp (UTC) |
| `seq` | uint64 | Monotonic counter within this log file |
| `caller` | string | Broker CN (mTLS) or OIDC `sub` (HTTP) |
| `host` | string | Logical host name (broker) or FQDN/addr (signer) |
| `user` | string | Remote SSH account |
| `principal` | string | SSH certificate principal |
| `command` | string | Command executed (one-shot) or session mode |
| `ttl` | string | Certificate TTL granted |
| `serial` | uint64 | Certificate serial — correlates broker ↔ signer ↔ sshd |
| `session_id` | string | Session id — 24-char random hex token (session events only) |
| `outcome` | string | See table in §7.2 |
| `exit_code` | int | Remote exit code (execution events) |
| `err` | string | Error detail (on failure) |
| `elevation` | string | `sudo:root` or `sudo:<user>` if escalated |
| `pty` | bool | `true` if PTY was requested |
| `prev_hash` | string | SHA-256 hex of the previous raw JSON line |
| `sig` | string | Base64 Ed25519 signature over the entry (with `sig=""`) |

## 8. Session recording

When `session_recording_dir` is set in `config.json`, the broker records
`shell` and `pty` sessions to **ASCIIcast v2** files (`.cast`). Each file
captures stdin (what the agent typed), stdout, and stderr with millisecond
timestamps.

### Enabling recording

```json
{
  "session_recording_dir": "/var/log/infrabroker/recordings"
}
```

The directory must exist and be writable by the broker process. File permissions
are set to `0600` (owner-read only).

### File naming

One file per session: `<session_id>.cast`

```
/var/log/infrabroker/recordings/
  a3f1b2c4d5e60718293a4b5c.cast
  b7c8d9e0f1a2b3c4.cast
```

The `session_id` matches the `session_id` field in the broker's audit log.
Use the audit log as an index to find recordings by agent, host, or time:

```bash
# Find all sessions opened by alice on web01 today
broker-ctl audit show --log audit.log --outcome session_open \
  --host web01 --caller alice --since 2026-06-09 --json \
  | jq -r '.session_id'

# List the corresponding recording files
broker-ctl audit show --log audit.log --outcome session_open --json \
  | jq -r '.session_id' \
  | xargs -I{} ls /var/log/infrabroker/recordings/{}.cast 2>/dev/null
```

### Recording file format

The file is **ASCIIcast v2** JSONL — one JSON line per event:

```
{"version":2,"width":220,"height":40,"timestamp":1749470400,
 "title":"session a3f1b2c4d5e60718293a4b5c — alice@web01",
 "env":{"TERM":"xterm-256color"},
 "ssh_broker":{"session_id":"a3f1b2c4d5e60718293a4b5c","caller":"alice","host":"web01",
               "serial":1042,"started_at":"2026-06-09T14:00:01Z"}}
[0.000, "i", "df -h /\n"]
[0.012, "o", "Filesystem      Size  Used Avail Use% Mounted on\n"]
[0.013, "o", "/dev/sda1        50G   18G   30G  38% /\n"]
[1.244, "i", "uptime\n"]
[1.251, "o", " 14:00:02 up 3 days,  2:00\n"]
```

| Field | Description |
|---|---|
| Header line | Session metadata: session_id, caller, host, serial, timestamps |
| `[delta, "i", data]` | Input (command typed by the agent) |
| `[delta, "o", data]` | Output (stdout, or merged PTY output) |
| `[delta, "e", data]` | Stderr (non-PTY sessions only) |
| `delta` | Seconds since session start (float, millisecond precision) |

The `ssh_broker` extension field in the header is a private extension within the
ASCIIcast v2 spec (extra fields are allowed). Standard tools ignore it.

### Playback

Any tool that supports ASCIIcast v2 can replay the recording:

```bash
# Install asciinema if not present
pip install asciinema   # or: brew install asciinema

# Play a session recording
asciinema play /var/log/infrabroker/recordings/a3f1b2c4d5e60718293a4b5c.cast

# Print the recording as plain text (no timing)
asciinema cat /var/log/infrabroker/recordings/a3f1b2c4d5e60718293a4b5c.cast

# Stream new events as they are written (live tail)
tail -f /var/log/infrabroker/recordings/a3f1b2c4d5e60718293a4b5c.cast \
  | asciinema cat /dev/stdin
```

### Scope

Only `shell` and `pty` sessions are recorded. One-shot `ssh_execute` commands
and `exec`-mode sessions are not recorded (those are fully captured in the audit
log including stdout/stderr content via `ssh_execute` responses).

### Storage management

Recording files are not rotated automatically. Use standard tools to manage
retention:

```bash
# Delete recordings older than 90 days
find /var/log/infrabroker/recordings -name "*.cast" -mtime +90 -delete
```

---

## 9. ssh_put_file / ssh_get_file — file transfer

Write and read files on a host without heredoc tricks. Both tools use the same
ephemeral-certificate machinery as `ssh_execute`: each transfer is a one-shot
command (`cat > path` for writes, a bounded read for downloads) locked into the
certificate's `force-command`, with the content streamed over stdin/stdout.

**Requires `allow_file_transfer=true` on the host** (check `ssh_list_servers`
first). If it is `false`, the signer rejects the transfer — do **not** retry;
inform the user. Transfers run as the host's configured SSH user (no sudo):
the path must be readable/writable by that user.

### 9.1 Write a file

```
tool: ssh_put_file
params:
  server:  "web01"
  path:    "/etc/myapp/config.yaml"
  content: "listen: :8080\nworkers: 4\n"
  mode:    "0644"
```

Response:

```
wrote 28 bytes to /etc/myapp/config.yaml (sha256=9f86d0…) [serial=1044]
```

- The destination is created or **overwritten**. Read it first if you need to
  preserve content.
- `mode` is optional (octal, e.g. `0644`, `0755`); without it the file keeps
  the remote user's default umask.
- For binary data pass `content_base64: true` and base64-encode `content`.
- Content is capped by the broker's `file_transfer_max_bytes`
  (default 512 KiB).

### 9.2 Read a file

```
tool: ssh_get_file
params:
  server: "web01"
  path:   "/var/log/myapp/error.log"
```

- Text files come back as-is in `content`; binary files come back
  base64-encoded with `base64: true` in the result.
- A file larger than `max_bytes` (default: the broker cap) is an **error**,
  not a truncation — lower your expectations or fetch a slice with
  `ssh_execute` (`tail -c`, `sed -n`).

### 9.3 Policy and audit interaction

- On hosts with a `command_policy`, the generated transfer command
  (`cat > 'path'` / `head -c N < 'path'`) is evaluated like any one-shot: an
  allowlist host denies transfers unless a pattern allows them, and a
  `shell_parse` policy in enforce mode rejects the stream redirects these
  commands use (deliberately conservative).
- Every transfer writes two correlated audit entries (same `serial`): the
  regular `executed` entry with the transfer command, and a `file_put` /
  `file_get` entry carrying `path=… bytes=… sha256=…` for content integrity.

## 10. Kubernetes tools (`k8s_*`)

These tools appear **only** when the broker is configured with at least one
Kubernetes cluster; an SSH-only deployment does not expose them. Like SSH, the
model never sees a cluster credential: for an authorised action the signer mints
a short-lived bound ServiceAccount token, the broker makes the one API call, and
the token is discarded.

Every cluster is **default-deny**: an action runs only if the cluster policy has
an `allow` (or `require_approval`) rule matching its `verb`, `resource`,
`namespace`, and `name`. If a tool returns "not allowed", **do not retry** —
tell the user the cluster policy forbids it.

### 10.1 List the reachable clusters

```
tool: k8s_list_clusters
```

Always call this first to learn the cluster names (filtered to the user's RBAC
groups).

### 10.2 Read: get, list, logs

```
tool: k8s_get
params: { cluster: "prod-k8s", resource: "pods", namespace: "prod", name: "web-1" }

tool: k8s_list
params: { cluster: "prod-k8s", resource: "deployments", namespace: "prod", label_selector: "app=web" }

tool: k8s_logs
params: { cluster: "prod-k8s", namespace: "prod", pod: "web-1", container: "app", tail_lines: 100 }
```

- Omit `group` for core resources (pods, services, configmaps, nodes…); the
  broker fills it in from the cluster's resource table. Omit `namespace` only
  for cluster-scoped resources (nodes, namespaces, persistentvolumes) or to
  `k8s_list` across all namespaces the ServiceAccount can read.
- `k8s_get`/`k8s_list`/`k8s_logs` return the API server's JSON (or plain-text
  logs) in `output`.

### 10.3 Mutate: apply, delete

```
tool: k8s_apply
params:
  cluster:  "prod-k8s"
  resource: "deployments"
  namespace: "staging"
  name:     "api"
  manifest: '{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"api","namespace":"staging"},"spec":{...}}'

tool: k8s_delete
params: { cluster: "prod-k8s", resource: "pods", namespace: "prod", name: "web-1" }
```

- `k8s_apply` is a **server-side apply** (create-or-update); the manifest's
  `apiVersion`/`kind`/`metadata.name`/`metadata.namespace` must match the
  arguments.
- Mutating actions are frequently `require_approval`: the tool then blocks until
  a human approves (or the request times out). This is the same approval flow as
  SSH — the approver sees the canonical action (e.g. `delete pods prod/web-1`).

### 10.4 Dry-run

Every k8s tool accepts `dry_run: true` to preview the **broker policy** decision
(allowed / denied / requires approval) without calling the API server. Use it
before a mutating action to check whether it will be allowed or gated.
