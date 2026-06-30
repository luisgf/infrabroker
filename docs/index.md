# ssh-broker

SSH access broker with an **ephemeral CA** for AI agents. The model **never receives a
credential**: it requests a command to run on a host, and the broker signs an ephemeral,
scope-limited SSH certificate, opens the SSH connection itself, and returns **only the
command output**.

This site is the published reference. The Markdown lives in the
[repository](https://github.com/luisgf/ssh-broker) under `docs/` and is the single source of
truth — it is reviewed in the same pull request as the code, and the
[generated reference](reference/endpoints.md) is rebuilt from the code on every build so it
cannot drift.

## Start here

| If you want to… | Read |
|---|---|
| Understand the design and request flow | [Architecture](ARCHITECTURE.md) |
| Know what is and isn't defended | [Threat model](THREAT_MODEL.md) |
| Run it — startup, hosts, hot-reload, PKI | [Operations](OPERATIONS.md) |
| Call the HTTP services | [API reference](API.md) |
| Use the MCP tools (as the model/operator) | [Tool usage](USAGE.md) |
| Report a vulnerability | [Security](SECURITY.md) |
| Contribute | [Contributing](CONTRIBUTING.md) · [Coding style](CODING_STYLE.md) |

## Generated reference (from code)

These pages are produced by `tools/docgen` from the actual routes, tool schemas, and config
structs, and are diff-checked in CI:

- [HTTP endpoints](reference/endpoints.md) — every route across the services
- [MCP tools](reference/mcp-tools.md) — tool names and input/output schemas
- [Config reference](reference/config.md) — every config field and policy vocabulary
- [broker-ctl CLI](reference/cli.md) — command and flag reference

## The three frontends

- **MCP stdio** (`cmd/mcp-broker`) — local, recommended for personal use; isolation from the
  process being launched by the user.
- **MCP HTTP + OAuth2/OIDC** (`cmd/mcp-broker-http`) — remote, multi-user; each client
  authenticates with an OIDC bearer token; the user identity (and groups) propagate to the signer.
- **HTTP + mTLS** (`cmd/broker`, `POST /v1/ssh_run`) — one-shot, for network agents with a
  client certificate.
