# Glama introspection image

[Glama](https://glama.ai/mcp/servers) scores an MCP server by building a
Dockerfile, starting the container and issuing an MCP introspection request
(`initialize` + `tools/list`). infrabroker's real entrypoint cannot start bare —
it needs a signer/PKI (remote mode) or a full local config with a CA key.

`Dockerfile` here starts `mcp-broker` in a **zero-host local mode** with
throwaway credentials generated **at build time** (never committed, never
reused): an SSH CA that signs certificates for zero hosts, and an audit seed for
a throwaway log. It exposes the exact tool surface and can do nothing else —
there is no host to reach and no signer. It is **only** for Glama introspection;
to actually run the broker use `ghcr.io/luisgf/infrabroker` (see
[docs/CONTAINERS.md](../../docs/CONTAINERS.md)).

Build and verify locally (context is the repo root):

```sh
docker build -f contrib/glama/Dockerfile -t infrabroker-introspect .

printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
  | docker run --rm -i infrabroker-introspect
```

The second response lists the tools (`ssh_execute`, `ssh_session_open` /
`ssh_session_exec` / `ssh_session_close`, `ssh_list_servers`, `ssh_put_file` /
`ssh_get_file`), which is what Glama's check needs.
