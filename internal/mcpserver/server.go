package mcpserver

import (
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/luisgf/infrabroker/internal/broker"
	"github.com/luisgf/infrabroker/internal/version"
)

// New builds a *mcp.Server with the broker tools registered. callerFn
// determines the caller identity per request (fixed in stdio, derived from the
// OIDC token in HTTP). elicitApprovals turns a require_approval command into an
// in-conversation elicitation (#118) instead of a denial — the interactive
// stdio frontend passes it; HTTP passes false.
func New(eng *broker.Engine, callerFn CallerFunc, elicitApprovals bool) *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{
		Name:    "infrabroker",
		Title:   "infrabroker (SSH & Kubernetes, ephemeral credentials)",
		Version: version.String(),
	}, nil)
	Register(srv, eng, callerFn, elicitApprovals)
	// Register the Kubernetes tool family only when the broker actually sees a
	// cluster, so an SSH-only deployment does not offer k8s_* tools to the model.
	if HasK8sClusters(eng) {
		RegisterK8s(srv, eng, callerFn)
	}
	return srv
}
