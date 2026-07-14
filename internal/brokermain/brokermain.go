// Package brokermain holds the wiring shared by infrabroker's three broker
// frontends — the HTTP+mTLS one-shot API (serve-http), the stdio MCP server
// (serve-mcp), and the OAuth-protected HTTP MCP server (serve-mcp-http). Each is
// only a transport over the same broker.Engine + internal/mcpserver, so the boot
// preamble lives here once. cmd/infrabroker dispatches the subcommands; the legacy
// cmd/broker, cmd/mcp-broker and cmd/mcp-broker-http binaries are thin (deprecated)
// wrappers over the same Run* functions, preserving their names and CLI.
package brokermain

import (
	"context"
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/luisgf/infrabroker/internal/broker"
	"github.com/luisgf/infrabroker/internal/httpserve"
	"github.com/luisgf/infrabroker/internal/monitor"
	"github.com/luisgf/infrabroker/internal/version"
)

// parseCommonFlags parses the -config/-version/-verbose set that every frontend
// shares. done is true when --version was handled and the caller must return
// without serving. name labels the flag set in usage/error output.
func parseCommonFlags(name string, args []string) (cfgPath string, done bool) {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	cfg := fs.String("config", "config.json", "path to the JSON/JSONC configuration file")
	showVersion := fs.Bool("version", false, "print version and exit")
	verbose := fs.Bool("verbose", false, "with --version, print detailed build info")
	_ = fs.Parse(args)
	if *showVersion {
		version.Print(*verbose)
		return "", true
	}
	return *cfg, false
}

// Boot performs the wiring shared by every transport: load the config, build the
// engine, and start the optional monitoring listener. The caller MUST defer
// eng.Close(). name is the audit/metric label ("broker" / "mcp-broker" /
// "mcp-broker-http"), kept identical to the pre-merge binaries so logs and
// metrics are unchanged.
func Boot(name, cfgPath string) (*broker.Engine, *broker.Config) {
	cfg, err := broker.LoadConfig(cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	eng, err := broker.NewEngine(cfg)
	if err != nil {
		log.Fatalf("initialising broker: %v", err)
	}
	// Optional monitoring listener (/healthz, /metrics); lives with the process.
	go monitor.Serve(context.Background(), cfg.MonitorListen, name)
	return eng, cfg
}

// serveHTTP runs an HTTPS listener with the timeouts shared by the two HTTP
// frontends. WriteTimeout is deliberately unset: the response is written only
// after the remote command completes (up to the SSH exec timeout) or, for the MCP
// SSE stream, for as long as the stream stays open. Slowloris/hung connections are
// bounded by ReadTimeout + IdleTimeout instead.
func serveHTTP(cfg *broker.Config, tlsCfg *tls.Config, handler http.Handler, name string) {
	httpSrv := &http.Server{
		Addr:        cfg.Listen,
		Handler:     handler,
		TLSConfig:   tlsCfg,
		ReadTimeout: 15 * time.Second,
		IdleTimeout: 120 * time.Second,
	}
	httpserve.RunTLS(httpSrv, name, 10*time.Second)
}
