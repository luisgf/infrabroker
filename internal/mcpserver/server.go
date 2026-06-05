package mcpserver

import (
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/luisgf/ssh-broker/internal/broker"
)

// Version es la versión anunciada por el servidor MCP a sus clientes.
const Version = "1.4.1"

// New construye un *mcp.Server con las tools del broker registradas. callerFn
// determina la identidad del llamante por petición (fija en stdio, derivada del
// token OIDC en HTTP).
func New(eng *broker.Engine, callerFn CallerFunc) *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{
		Name:    "ssh-broker",
		Title:   "SSH Broker (CA efímera)",
		Version: Version,
	}, nil)
	Register(srv, eng, callerFn)
	return srv
}
