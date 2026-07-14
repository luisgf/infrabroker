// Command mcp-broker is a thin, DEPRECATED compatibility wrapper for
// `infrabroker serve-mcp` — the broker as an MCP server over stdio. Prefer the
// unified `infrabroker` binary; this name is kept so existing MCP-client configs
// (and the container ENTRYPOINT the MCP registry pulls) keep working unchanged.
// Same flags, same behaviour.
package main

import (
	"os"

	"github.com/luisgf/infrabroker/internal/brokermain"
)

func main() { brokermain.RunMCP(os.Args[1:]) }
