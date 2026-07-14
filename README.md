# infrabroker

[![CI](https://github.com/luisgf/infrabroker/actions/workflows/go.yml/badge.svg)](https://github.com/luisgf/infrabroker/actions/workflows/go.yml)
[![Release](https://img.shields.io/github/v/release/luisgf/infrabroker)](https://github.com/luisgf/infrabroker/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/luisgf/infrabroker)](https://goreportcard.com/report/github.com/luisgf/infrabroker)
[![License: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-blue)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-luisgf.github.io%2Finfrabroker-informational)](https://luisgf.github.io/infrabroker/)

**Infrastructure access broker for AI agents — SSH & Kubernetes. The model
never touches a credential.** *(formerly `ssh-broker`)*

The agent requests an *action* — run a command on a host, query or change a
cluster. infrabroker checks it against policy, executes it with a credential
minted for that single operation — an **ephemeral, scope-limited SSH
certificate** from its own CA, or a **short-lived bound ServiceAccount token**
— and returns **only the output**. Keys, certificates and tokens live in the
broker's memory and are discarded after the call: nothing enters the model's
context, so a prompt-injected agent has nothing to exfiltrate.

One binary — `infrabroker` — exposes the same engine (`internal/broker`) and tool
surface (`internal/mcpserver`) over three transports, chosen by subcommand. (The
legacy per-transport binaries `broker` / `mcp-broker` / `mcp-broker-http` remain as
thin **deprecated wrappers** over these subcommands, so existing configs keep
working.)

- **MCP stdio (local, recommended for personal use)** — `infrabroker serve-mcp`.
  Tools: `ssh_execute`, `ssh_session_open` / `ssh_session_exec` / `ssh_session_close`,
  `ssh_list_servers`, `ssh_put_file` / `ssh_get_file`; with clusters configured,
  also `k8s_get` / `k8s_list` / `k8s_logs` / `k8s_apply` / `k8s_delete` /
  `k8s_list_clusters`. No transport auth — isolation comes from the process
  being launched by the user (as the MCP spec recommends for stdio).
- **MCP HTTP + OAuth2/OIDC (remote, multi-user)** — `infrabroker serve-mcp-http`,
  Streamable HTTP. Same tools, but each client authenticates with an **OIDC
  bearer token** validated locally against the issuer's JWKS; the user identity
  (and groups, for per-user RBAC) is propagated to the signer.
- **HTTP + mTLS** — `infrabroker serve-http`, `POST /v1/ssh_run` (one-shot), for
  network agents authenticated with a client certificate.

## Documentation

This README is a landing page. The detail lives in focused, single-source docs:

| Document | Contents |
|---|---|
| [QUICKSTART.md](docs/QUICKSTART.md) | First `ssh_execute` in under 10 minutes — single-binary local mode, no signer/PKI |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Diagram, request flow, design decisions, sudo elevation, sessions, multi-CA |
| [THREAT_MODEL.md](docs/THREAT_MODEL.md) | Actors, trust boundaries, security controls, and explicit non-goals/gaps |
| [OPERATIONS.md](docs/OPERATIONS.md) | Runbook: startup, adding hosts, hot-reload, `broker-ctl`, PKI rotation, configs |
| [MESH.md](docs/MESH.md) | Running infrabroker over a NetBird / Tailscale mesh — the session layer on top of the overlay path |
| [API.md](docs/API.md) | HTTP endpoint reference for all services |
| [USAGE.md](docs/USAGE.md) | Guide to the MCP tools (SSH + Kubernetes), dry-run, and audit review (for the model / operator) |
| [SECURITY.md](docs/SECURITY.md) | Vulnerability disclosure policy |
| [CONTRIBUTING.md](docs/CONTRIBUTING.md) · [CODING_STYLE.md](docs/CODING_STYLE.md) | Workflow, versioning, Go style |

## Why infrabroker

- **Anti-exfiltration (prompt injection):** the ephemeral key/cert/token live
  only in the broker's memory; they never enter the model's context.
- **Kubernetes without kubeconfigs:** the signer mints a short-lived **bound
  ServiceAccount token** (TokenRequest API) per operation; every cluster is
  **default-deny** with per-verb/resource/namespace policy and the same
  dry-run, approval and audit path as SSH.
- **Anti-reuse:** each cert carries a TTL of minutes, `source-address` (broker or
  bastion IP), and — for one-shot — a `force-command`. Useless outside its
  host/time/IP.
- **Controlled escalation:** `allow_sudo` / `allowed_sudo_users` live in the
  signer; a compromised broker cannot escalate where policy forbids it.
- **CA compromise bounded:** one CA per host group (`ca_keys`), each key
  optionally in Azure Key Vault — the private key never leaves the HSM.
- **Audit / non-repudiation:** append-only, Ed25519-chained log correlated by
  `serial` across signer, broker, and `sshd`.

The full threat model — including what the system deliberately does **not**
defend — is in [THREAT_MODEL.md](docs/THREAT_MODEL.md).

## How it works

```
AI model ──tool call──> broker ──mTLS──> [control-plane] ──mTLS──> signer
   (no credential)      (ephemeral key      (approval +          (CA key +
                         in RAM, never        guardrails,          policy + RBAC,
                         on disk)             no CA key)           signs the cert)
                            │
                            └── SSH with the ephemeral cert ──> bastion ──> target host
                                                                 └─ stdout/stderr/exit_code ─> model
```

The broker sends an *intent* (`{host, role, purpose, command?, sudo?, pty?,
pubkey, …}`); the signer derives every certificate constraint from policy and
returns the signed cert. The ephemeral private key is generated in the broker
and never leaves it. See [ARCHITECTURE.md](docs/ARCHITECTURE.md) for the request flow,
the design decisions, and the per-hop ProxyJump certificate diagrams.

## Feature overview

| Capability | One-liner | More |
|---|---|---|
| **Ephemeral certificates** | Ed25519 pair in RAM per operation; minutes-long, scoped cert. No reusable secret. | [ARCHITECTURE](docs/ARCHITECTURE.md) |
| **External signer** | A separate `cmd/signer` holds the CA key and policy; the broker never does. | [ARCHITECTURE](docs/ARCHITECTURE.md) |
| **Multi-CA + HSM** | One CA key per host group via `ca_keys`; local PEM or Azure Key Vault. | [ARCHITECTURE](docs/ARCHITECTURE.md#multi-ca--azure-key-vault-v1110) |
| **AI-action firewall** | Per-host or **composable-by-group** command policy (allow/deny/`require_approval`), POSIX-sh AST parsing, dry-run. Authoritative for one-shot. | [ARCHITECTURE](docs/ARCHITECTURE.md#ai-action-firewall) · [USAGE](docs/USAGE.md) |
| **Human-in-the-loop approval** | Optional control plane gates `require_approval` commands behind out-of-band approval; the signer enforces it. | [ARCHITECTURE](docs/ARCHITECTURE.md#human-in-the-loop--control-plane) · [API](docs/API.md#control-plane-api) |
| **Action budgets** (behaviour guardrails) | Budget *how much* an agent can do: per-CN sign-rate cap plus per-subject rate limit and novelty escalation (a subsequent new host / novel command → approval); observe or enforce. Network tools budget what an agent can *reach* or *spend*; this budgets the actions themselves. | [OPERATIONS](docs/OPERATIONS.md#action-budgets-rate-limits--behavior-guardrails) · [ARCHITECTURE](docs/ARCHITECTURE.md#human-in-the-loop--control-plane) |
| **RBAC** | Broker-CN groups (mTLS) + per-end-user OIDC groups; fail-closed. | [ARCHITECTURE](docs/ARCHITECTURE.md#rbac) |
| **sudo / PTY** | Policy-gated elevation (`sudo -n`) and PTY allocation, per host. | [ARCHITECTURE](docs/ARCHITECTURE.md#privilege-elevation-sudo-nopasswd) |
| **Kubernetes broker** | `k8s_*` tools with per-operation bound SA tokens, default-deny verb/resource/namespace policy, dry-run. | [USAGE §10](docs/USAGE.md#10-kubernetes-tools-k8s_) |
| **Session recording** | `shell`/`pty` sessions to ASCIIcast v2 (`.cast`), indexed by `session_id`. | [USAGE §8](docs/USAGE.md#8-session-recording) |
| **Chained audit** | Append-only, Ed25519-signed, SHA-256-chained; correlated by `serial`. | [USAGE §7](docs/USAGE.md#7-reviewing-audit-logs) · [API](docs/API.md#audit-log-correlation) |
| **Hot reload** | `signer.json` re-read (and validated) without restart, via `POST /v1/reload` or SIGHUP. | [OPERATIONS §3](docs/OPERATIONS.md#3-hot-reload) |

## Comparison with existing solutions

Several tools address SSH access control or AI-agent credential security, but
none cover the full combination that infrabroker targets in a lightweight,
self-hosted package.

| Feature | **infrabroker** | Teleport | Vault + SSH engine | StrongDM | ssh-mcp |
|---|---|---|---|---|---|
| Ephemeral cert in memory (no disk) | ✅ | ✅ | ✅ | ❌ | ❌ |
| Separate broker / signing service | ✅ | ✅ | Partial | ❌ | ❌ |
| MCP-native (AI agents) | ✅ | ✅ (2025) | ✅ (2025) | ❌ | ✅ |
| OAuth2/OIDC on MCP transport | ✅ | ✅ | ✅ | ❌ | ❌ |
| Per-command policy + dry-run (AI-action firewall) | ✅ | ❌ | ❌ | ❌ | ❌ |
| Human-in-the-loop approval for AI commands | ✅ | ❌ | ❌ | ❌ | ❌ |
| Per-agent behavioral guardrails (anomaly/rate) | ✅ | ❌ | ❌ | ❌ | ❌ |
| Session recording (ASCIIcast v2, stdin+stdout+stderr) | ✅ | ✅ | ❌ | Partial | ❌ |
| Cryptographically chained audit log | ✅ | ❌ | ❌ | Partial | ❌ |
| Single-binary / simple self-hosted | ✅ | ❌ | ❌ | ❌ | ✅ |
| HSM/KMS for CA key | ✅ (AKV) | ✅ | ✅ | — | — |

**[Teleport](https://goteleport.com/)** is the closest commercial equivalent —
short-lived SSH certs, RBAC, and since 2025 *Secure MCP*; its Jan-2026 *Agentic
Identity Framework* targets the same threat model. The difference is operational
weight: Teleport needs a dedicated control-plane cluster, recording proxy, and
web UI — orders of magnitude heavier than a Go binary + signer.

**[HashiCorp Vault SSH secrets engine](https://developer.hashicorp.com/vault/docs/secrets/ssh)**
is an SSH CA with full HSM/KMS support and (2025) its own MCP server, but it
provides only the *signing* piece — you still build the execution layer
(`engine.go`, `session.go`, the MCP tools) yourself.

**[StrongDM](https://www.strongdm.com/)** hides credentials but stores
long-lived secrets rather than generating ephemeral certs in memory, making it
weaker against exfiltration. **[Smallstep SSH CA](https://smallstep.com/)** is a
lightweight OIDC-integrated SSH CA (close to `cmd/signer`) with no execution
broker or MCP layer. **[ssh-mcp](https://github.com/tufantunc/ssh-mcp)** exposes
SSH to LLMs over MCP but uses a **static SSH key** — the exact vulnerability this
broker prevents. **[CyberArk PAM](https://docs.cyberark.com/)** offers
comparable JIT cert access but is a closed enterprise platform for human
operators, not AI workloads.

**Where it fits:** MCP-native AI-agent access + in-memory ephemeral certs +
separate signer + ASCIIcast recording + chained audit, as a small set of Go
binaries without a cluster. Enterprise features (web UI, multi-region HA) are on
the roadmap (see [HANDOFF.md](docs/HANDOFF.md)).

## Install

- **Prebuilt binaries** — each [release](https://github.com/luisgf/infrabroker/releases)
  ships `infrabroker_<ver>_{linux,darwin}_{amd64,arm64}.tar.gz` with all binaries,
  plus the installer tarball (`infrabroker-v<ver>.tar.gz`) that
  `deploy/install.sh` consumes for the systemd production path.
- **go install** — `go install github.com/luisgf/infrabroker/cmd/infrabroker@latest`
  (pure Go, no CGO; same for the other `cmd/` binaries).
- **Container** — `ghcr.io/luisgf/infrabroker` (docker or podman, multi-arch;
  entrypoint is the stdio MCP frontend). See [CONTAINERS.md](docs/CONTAINERS.md),
  including a compose demo that runs the full stack against a toy host:
  `cd examples/compose && docker compose up --build -d` (or `make demo`).
- **From source** — the Quickstart below.

Register with Claude Code in one line — native binary or container:

```bash
claude mcp add infrabroker -- ~/bin/infrabroker serve-mcp -config /secure/path/config.json
claude mcp add infrabroker -- docker run -i --rm -v /secure/path:/config \
  ghcr.io/luisgf/infrabroker -config /config/config.json
```

## Quickstart

**Fastest path (local, single binary):** [QUICKSTART.md](docs/QUICKSTART.md) takes
you from `git clone` to your first `ssh_execute` in under 10 minutes with one
binary and one `config.json` — no signer service, no PKI. The steps below set up
the full **remote** stack (a separated signer); the containerised demo is under
[Install](#install).

```bash
# 1. Build (make injects the version from the git tag into every binary)
make install                 # → ~/bin/{infrabroker,signer,broker,broker-ctl,mcp-broker,...}
# or a single binary:        make signer
# (plain `go build ./cmd/...` also works; it reports a dev-<commit> version)

# 2. Generate the local PKI + the two-service config (signer.json + config.json)
infrabroker init             # writes pki/, signer.json, config.json; --force to redo
# add --import-ssh-config to import hosts from ~/.ssh/config, --register-mcp to
# run `claude mcp add` for you

# 3. Start the signing service (must be running before the broker)
./signer.sh start

# 4. Add a host and reload
broker-ctl host add --name web01 --addr web01.example.com:22 --user deploy --scan \
  --groups prod-web --sudo
broker-ctl reload

# (--config is a global flag, before the subcommand; every binary takes --version)
broker-ctl --config /secure/path/signer.json host list
broker-ctl --version            # short; add --verbose for build details
```

Register the stdio MCP with your client:

```jsonc
// Claude Code — ~/.claude.json
"infrabroker": { "type": "stdio", "command": "/Users/<you>/bin/infrabroker",
                "args": ["serve-mcp", "-config", "/secure/path/config.json"] }

// OpenCode — ~/.config/opencode/opencode.json  (note: type "local", command is an array)
"infrabroker": { "type": "local",
                "command": ["/home/<you>/bin/infrabroker", "serve-mcp", "-config", "/secure/path/config.json"],
                "enabled": true }
```

Full setup — local vs external signing mode, the remote OAuth frontend, host
fields, sudoers, PKI, and `broker-ctl` — is in [OPERATIONS.md](docs/OPERATIONS.md).
Tool usage for the model is in [USAGE.md](docs/USAGE.md).

## API

Full reference: [API.md](docs/API.md).

| Service | Endpoint | Auth | Description |
|---|---|---|---|
| Signer | `POST /v1/sign` | mTLS | Request an ephemeral SSH certificate |
| Signer | `GET /v1/hosts` | mTLS | List accessible hosts (filtered by caller groups) |
| Signer | `POST /v1/reload` | mTLS | Hot-reload `signer.json` without restart |
| Control plane | `POST /v1/sign`, `/v1/approvals/{id}`, … | mTLS | Forwarding + human approval |
| Broker HTTP | `POST /v1/ssh_run` | mTLS | Execute a one-shot SSH command |
| MCP HTTP | `/.well-known/oauth-protected-resource` | None | OAuth2 discovery (RFC 9728) |
| MCP HTTP | Streamable HTTP | OIDC Bearer | MCP tools |

## Security

The security posture — trust boundaries, the layered controls (RBAC, command
policy, approval gate, guardrails, source-address/TTL pinning, chained audit),
and the **explicit non-goals** (`mode=exec` sessions are broker-preflighted but
not host-enforced, no KRL, secrets logged verbatim, …) — is documented in
[THREAT_MODEL.md](docs/THREAT_MODEL.md).

To report a vulnerability, see [SECURITY.md](docs/SECURITY.md). CI enforces `gofmt`,
`go vet`, `go test -race`, and `govulncheck` on every push and PR.

## Testing

```bash
make test                      # go test -race ./...  (cert build, policy/RBAC/sudo/PTY, hops, …)
bash lab/run_signer_lab.sh     # external signer: broker without ca_key + policy + denial
bash lab/run_mcp_lab.sh        # bastion + target (ProxyJump) MCP scenario
bash lab/run_lab.sh            # HTTP/mTLS frontend
```

## License

Copyright (C) 2026 Luis González Fernández.

This program is free software: you can redistribute it and/or modify it under the
terms of the **GNU General Public License v3.0** as published by the Free Software
Foundation. It is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY. See [LICENSE](LICENSE) for the full text.
