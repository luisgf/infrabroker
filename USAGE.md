# Usage Guide — ssh-broker MCP Tools

This document covers practical usage of the five MCP tools exposed by
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

---

## 1. Before you start

**Always call `ssh_list_servers` first.** It returns every host the broker
knows about, together with the capabilities that determine which parameters are
valid for that host.

```
tool: ssh_list_servers
params: (none)
```

Example response:

```
web01 (sudo=true pty=true)
db01  (sudo=false pty=false)
bastion (sudo=false pty=false)
app02 (sudo=true pty=true via=bastion)
```

What the fields mean:

| Field | Value | What it implies |
|---|---|---|
| `allow_sudo` | `true` | You may use `sudo=true` in execute/session calls. |
| `allow_sudo` | `false` | Do **not** pass `sudo=true`. The signer will reject it. Do not retry. |
| `allow_pty` | `true` | You may use `pty=true` (execute) or `mode=pty` (session). |
| `allow_pty` | `false` | Do **not** request a PTY. Do not retry. |
| `jump` | `"bastion"` | The host is reached via a ProxyJump hop through `bastion`. Transparent — no extra action needed. |

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
[dry-run] PERMITIDO (requiere aprobación humana antes de ejecutar)
regla: require_approval:^systemctl restart
force-command: systemctl restart nginx
ttl: 120s
```

Response (denied by command policy):

```
[dry-run] DENEGADO: comando no permitido en "web01" por command_policy (allowlist:no-match)
```

Use dry-run to decide whether to proceed before committing an action. A host may
restrict commands via an **allowlist** or **denylist** (see the README
"AI-action firewall" section). Hosts with a command policy **do not allow
sessions** — use `ssh_execute` on them.

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
`dry_run: true` (the response says "requiere aprobación humana"). This lets you
warn the user that the action will pause for approval before you run it.

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
> an SSH connection and consume resources until the certificate TTL expires.

### 3.1 mode=exec (default) — isolated commands, shared connection

Each `ssh_session_exec` call runs in a separate SSH channel. State (working
directory, variables) does **not** persist between calls. Use this when you want
connection reuse without state leakage.

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

Response: `web01\n[exit=0 serial=1051]`

```
tool: ssh_session_close
params:
  session_id: "abc123"
```

Response: `cerrada`

### 3.2 mode=shell — stateful shell

A single `/bin/sh` process is started. `cd`, variable assignments, and
environment changes persist across `ssh_session_exec` calls.

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
  command:    "cat > /etc/nginx/conf.d/app.conf << 'EOF'\nserver { listen 80; ... }\nEOF"

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
# Attempting sudo on db01 → tool error: "host no autorizado" or policy denial
# Correct response: inform the user, do not retry
```

### 5.3 PTY rejected

Same rule: if `allow_pty=false`, do not pass `pty=true` or `mode=pty`. Do not
retry.

### 5.4 Session expired or closed

If `ssh_session_exec` returns an error for a session ID that was previously
valid, the session has likely expired (TTL elapsed) or was closed by the reaper.
Open a new session.

### 5.5 Newlines in commands

Commands passed to `ssh_session_exec` must not contain `\n` or `\r`. The broker
rejects them to prevent command injection. Use multiple `ssh_session_exec` calls
or shell quoting instead.

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

### Parameter constraints

| Parameter | Constraint |
|---|---|
| `sudo=true` | Only when `allow_sudo=true` (from `ssh_list_servers`). Never retry if `false`. |
| `sudo_user` | Must be in `allowed_sudo_users` for the host. Empty = `root`. |
| `pty=true` / `mode=pty` | Only when `allow_pty=true`. Never retry if `false`. |
| `command` | Must not contain `\n` or `\r` (session exec). On hosts with a command policy, must satisfy the allowlist/denylist. |
| `ttl_seconds` | Optional. Omit to use the host policy maximum. |
| `dry_run=true` | `ssh_execute` only. Simulates policy (allow/deny + approval) without executing. Nothing runs. |

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
# Broker outcomes: executed, denied, error, session_open, session_exec, session_close
broker-ctl audit show --log audit.log --outcome denied

# Signer outcomes: issued, denied, reloaded, reload-denied, reload-failed
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
| `session_id` | string | Session UUID (session events only) |
| `outcome` | string | See table in §7.2 |
| `exit_code` | int | Remote exit code (execution events) |
| `err` | string | Error detail (on failure) |
| `elevation` | string | `sudo:root` or `sudo:<user>` if escalated |
| `pty` | bool | `true` if PTY was requested |
| `prev_hash` | string | SHA-256 hex of the previous raw JSON line |
| `sig` | string | Base64 Ed25519 signature over the entry (with `sig=""`) |
