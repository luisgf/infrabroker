# Quickstart — first `ssh_execute` in under 10 minutes (local mode)

The fastest path from `git clone` to your AI agent running its first policy-gated
command on a host **you already reach over SSH** — one binary, one config file,
no signer service and no mTLS PKI.

This is **local (single-binary) mode**: `infrabroker serve-mcp` signs ephemeral
SSH certificates in-process with a local CA. It is the on-ramp, **not** the
production recommendation — a local PEM CA is lab/dev custody (the broker prints
a warning to say so). When you want separated CA custody, human approvals, and
RBAC, [graduate to remote mode](#when-to-move-to-remote-mode).

Prerequisites: Go (to build), one Linux host you can already `ssh` into, and an
MCP client (Claude Code / Claude Desktop / OpenCode).

---

## 1. Build the broker

```bash
git clone https://github.com/luisgf/infrabroker && cd infrabroker
go build -o infrabroker ./cmd/infrabroker    # or: make build
```

## 2. Create the local CA and the audit key

```bash
mkdir -p ~/.infrabroker && cd ~/.infrabroker
ssh-keygen -t ed25519 -f ssh_ca -N "" -C infrabroker-ca   # → ssh_ca (private) + ssh_ca.pub
head -c 32 /dev/urandom > audit.key                       # 32-byte Ed25519 audit seed
```

Keep `ssh_ca` and `audit.key` private (`chmod 600`). `ssh_ca.pub` is the CA the
hosts will trust.

## 3. Enrol the target host (one paste per host)

On the **target host's** `sshd`, trust your CA and authorise the certificate
principal for the login account. As root on the host:

```bash
# a) install the CA public key you generated in step 2
sudo install -m 0644 /path/to/ssh_ca.pub /etc/ssh/infrabroker_ca.pub

# b) trust it, and map the cert principal to the login user
sudo tee -a /etc/ssh/sshd_config >/dev/null <<'EOF'

TrustedUserCAKeys /etc/ssh/infrabroker_ca.pub
AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
EOF

# c) allow the "infrabroker" principal to log in as the user you'll use (here: deploy)
sudo mkdir -p /etc/ssh/auth_principals
echo infrabroker | sudo tee /etc/ssh/auth_principals/deploy

sudo systemctl reload ssh    # or: sudo systemctl reload sshd
```

(The `principal` and `user` here must match your `config.json` below.
`deploy/sshd_config.snippet` documents the host side in full.)

## 4. Write the minimal config

Copy [`config.minimal.example.json`](https://github.com/luisgf/infrabroker/blob/main/config.minimal.example.json)
to `~/.infrabroker/config.json` and edit the one host block. Pin the host key so
a man-in-the-middle cannot impersonate the server:

```bash
ssh-keyscan -t ed25519 myhost.example.com     # copy the output line into "host_key"
```

```jsonc
{
  "audit_log": "/Users/you/.infrabroker/audit.log",
  "audit_key": "/Users/you/.infrabroker/audit.key",
  "ca_key":    "/Users/you/.infrabroker/ssh_ca",
  "hosts": {
    "myhost": {
      "addr": "myhost.example.com:22",
      "user": "deploy",
      "host_key": "myhost.example.com ssh-ed25519 AAAA…from-ssh-keyscan…",
      "principal": "infrabroker",
      "command_policy": {
        "mode": "allowlist",
        "allow": ["^uptime$", "^df -h$", "^systemctl status [a-zA-Z0-9._-]+$"]
      }
    }
  }
}
```

The `command_policy` allowlist is the **AI-action firewall**: only these
commands can run, visible from the first request. Anything else is denied by the
signer, not the shell.

## 5. Register the broker with your MCP client

```jsonc
// Claude Code / Claude Desktop — ~/.claude.json
"infrabroker": {
  "type": "stdio",
  "command": "/Users/you/infrabroker/infrabroker",
  "args": ["serve-mcp", "-config", "/Users/you/.infrabroker/config.json"]
}
```

Restart the client. On startup the broker logs
`mcp-broker (stdio) ready; 1 hosts configured` (and a one-line **PEM CA lab-use**
warning — expected in local mode).

## 6. Run your first command

Ask the agent to use the tools:

- **`ssh_list_servers`** → shows `myhost` and its capabilities.
- **`ssh_execute(server="myhost", command="uptime")`** → runs it and returns
  stdout / stderr / exit_code.
- **`ssh_execute(server="myhost", command="rm -rf /", dry_run=true)`** →
  returns a decision with `reason_code: "allowlist_no_match"` (denied) **without
  connecting** — proof the firewall gates before anything runs.

Every issuance and execution is recorded in the signed, hash-chained audit log:

```bash
broker-ctl audit tail   --log ~/.infrabroker/audit.log
broker-ctl audit verify --log ~/.infrabroker/audit.log --key ~/.infrabroker/audit.key
```

---

## When to move to remote mode

Local mode keeps the CA **in the broker process** — fine for a lab or a personal
setup, but the broker both decides and signs, and the PEM key sits on disk (the
startup warning is deliberate). Move to **remote mode** when you want any of:

- **Separated custody** — a standalone [`cmd/signer`](OPERATIONS.md) holds the CA
  (Azure Key Vault or ssh-agent/hardware) and the policy; the broker never sees
  the key. See the CA-custody choice in `deploy/README.md`.
- **Human approvals & RBAC** — the control plane gates sensitive commands behind
  four-eyes approval and restricts each broker CN to its groups.
- **Recording, kill switch, multi-agent** — endpoint session recording and the
  freeze/revocation controls described in [ARCHITECTURE.md](ARCHITECTURE.md) and
  [THREAT_MODEL.md](THREAT_MODEL.md).

The full setup — signer, PKI bootstrap, and the production checklist (which
`broker-ctl doctor --security` automates) — is in [OPERATIONS.md](OPERATIONS.md)
and `deploy/README.md`. Tool usage for the model is in [USAGE.md](USAGE.md).
