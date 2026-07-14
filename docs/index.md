# infrabroker

Infrastructure access broker for AI agents — **SSH & Kubernetes**. The model
**never receives a credential**: it requests an action, and the broker executes
it with a credential minted for that single operation — an ephemeral,
scope-limited SSH certificate from its own CA, or a short-lived bound
ServiceAccount token — and returns **only the output**. *(formerly `ssh-broker`)*

This site is the published reference. The Markdown lives in the
[repository](https://github.com/luisgf/infrabroker) under `docs/` and is the single source of
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

One `infrabroker` binary, transport chosen by subcommand (the legacy `broker` /
`mcp-broker` / `mcp-broker-http` binaries remain as deprecated wrappers):

- **MCP stdio** (`infrabroker serve-mcp`) — local, recommended for personal use; isolation from the
  process being launched by the user.
- **MCP HTTP + OAuth2/OIDC** (`infrabroker serve-mcp-http`) — remote, multi-user; each client
  authenticates with an OIDC bearer token; the user identity (and groups) propagate to the signer.
- **HTTP + mTLS** (`infrabroker serve-http`, `POST /v1/ssh_run`) — one-shot, for network agents with a
  client certificate.
