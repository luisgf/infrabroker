// Command infrabroker is the unified broker frontend: one binary with the
// transport chosen by a subcommand.
//
//	infrabroker serve-http      [-config config.json]   # HTTP + mTLS, POST /v1/ssh_run
//	infrabroker serve-mcp       [-config config.json]   # MCP over stdio (local)
//	infrabroker serve-mcp-http  [-config config.json]   # MCP over HTTP + OAuth2/OIDC
//	infrabroker version [--verbose]
//
// The legacy per-transport binaries (broker, mcp-broker, mcp-broker-http) remain
// as thin deprecated wrappers over these same subcommands. The signer,
// control-plane and approval-bridge stay separate binaries (they are trust
// boundaries, not transports).
package main

import (
	"fmt"
	"os"

	"github.com/luisgf/infrabroker/internal/brokermain"
	"github.com/luisgf/infrabroker/internal/version"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve-http":
		brokermain.RunHTTP(os.Args[2:])
	case "serve-mcp":
		brokermain.RunMCP(os.Args[2:])
	case "serve-mcp-http":
		brokermain.RunMCPHTTP(os.Args[2:])
	case "version", "--version", "-version":
		version.Print(hasVerbose(os.Args[2:]))
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "infrabroker: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func hasVerbose(args []string) bool {
	for _, a := range args {
		if a == "--verbose" || a == "-verbose" {
			return true
		}
	}
	return false
}

func usage() {
	fmt.Fprint(os.Stderr, `infrabroker — unified broker frontend

Usage:
  infrabroker serve-http      [-config config.json]   HTTP + mTLS (POST /v1/ssh_run)
  infrabroker serve-mcp       [-config config.json]   MCP over stdio (local)
  infrabroker serve-mcp-http  [-config config.json]   MCP over HTTP + OAuth2/OIDC
  infrabroker version [--verbose]

Each subcommand also accepts -version/-verbose. The legacy binaries broker,
mcp-broker and mcp-broker-http are deprecated wrappers over these subcommands.
`)
}
