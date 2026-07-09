// Command mcp-broker exposes the broker as an MCP server over stdio. The model
// invokes ssh_execute(server, command) and receives only the output: for each
// call an ephemeral, scoped SSH certificate is signed, the command is executed,
// and the result is audited. The model never sees a key or a certificate.
//
// Launch from the MCP client, e.g. in ~/.claude.json:
//
//	"infrabroker": { "type": "stdio", "command": "/path/to/mcp-broker",
//	                "args": ["-config", "/path/to/config.json"] }
//
// To expose the broker over the network with OAuth2/OIDC authentication, see
// cmd/mcp-broker-http.
package main

import (
	"context"
	"flag"
	"log"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/luisgf/infrabroker/internal/broker"
	"github.com/luisgf/infrabroker/internal/mcpserver"
	"github.com/luisgf/infrabroker/internal/monitor"
	"github.com/luisgf/infrabroker/internal/version"
)

// stdioCaller identifies the origin in the audit log. Over stdio the caller is
// the local client process that launched the broker (no mTLS or OAuth); isolation
// is provided by the fact that the process is started by the user/MCP client
// itself. No groups: the signer does not apply per-user RBAC for local requests.
func stdioCaller(context.Context) broker.Caller {
	return broker.Caller{ID: "mcp-stdio"}
}

func main() {
	cfgPath := flag.String("config", "config.json", "path to JSON configuration file")
	showVersion := flag.Bool("version", false, "print version and exit")
	verbose := flag.Bool("verbose", false, "with --version, print detailed build info")
	flag.Parse()

	if *showVersion {
		version.Print(*verbose)
		return
	}

	cfg, err := broker.LoadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	eng, err := broker.NewEngine(cfg)
	if err != nil {
		log.Fatalf("initialising broker: %v", err)
	}
	defer eng.Close()

	// Optional monitoring listener (/healthz, /metrics); lives with the process.
	go monitor.Serve(context.Background(), cfg.MonitorListen, "mcp-broker")

	srv := mcpserver.New(eng, stdioCaller, cfg.ApprovalViaElicitation)

	log.Printf("mcp-broker (stdio) ready; %d hosts configured", len(eng.Servers()))
	if err := srv.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatalf("MCP server: %v", err)
	}
}
