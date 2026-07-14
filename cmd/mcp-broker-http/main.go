// Command mcp-broker-http is a thin, DEPRECATED compatibility wrapper for
// `infrabroker serve-mcp-http` — the broker as a remote MCP server over HTTP
// (Streamable HTTP) protected with OAuth2/OIDC. Prefer the unified `infrabroker`
// binary; this name is kept so existing systemd units and deploy scripts keep
// working unchanged. Same flags, same behaviour.
package main

import (
	"os"

	"github.com/luisgf/infrabroker/internal/brokermain"
)

func main() { brokermain.RunMCPHTTP(os.Args[1:]) }
