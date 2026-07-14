package brokermain

import (
	"context"
	"log"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/luisgf/infrabroker/internal/broker"
	"github.com/luisgf/infrabroker/internal/mcpserver"
	"github.com/luisgf/infrabroker/internal/monitor"
)

// stdioCaller identifies the origin in the audit log. Over stdio the caller is
// the local client process that launched the broker (no mTLS or OAuth); isolation
// is provided by the fact that the process is started by the user/MCP client
// itself. No groups: the signer does not apply per-user RBAC for local requests.
func stdioCaller(context.Context) broker.Caller {
	return broker.Caller{ID: "mcp-stdio"}
}

// RunMCP serves the broker as an MCP server over stdio — the `serve-mcp`
// transport (legacy binary `mcp-broker`). The model invokes ssh_execute and
// receives only the output: for each call an ephemeral, scoped SSH certificate is
// signed, the command executed, and the result audited; the model never sees a
// key or a certificate.
func RunMCP(args []string) {
	cfgPath, done := parseCommonFlags("mcp-broker", args)
	if done {
		return
	}
	eng, cfg := Boot("mcp-broker", cfgPath)
	defer eng.Close()

	srv := mcpserver.New(eng, stdioCaller, cfg.ApprovalViaElicitation)

	// A stdio process has no main listener to gate on, so it is ready for the
	// /readyz probe (if a monitor listener is configured) once the engine is up.
	monitor.SetReady(true)
	log.Printf("mcp-broker (stdio) ready; %d hosts configured", len(eng.Servers()))
	if err := srv.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatalf("MCP server: %v", err)
	}
}
