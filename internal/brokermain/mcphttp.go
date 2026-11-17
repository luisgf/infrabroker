package brokermain

import (
	"context"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"

	mtls "github.com/luisgf/infrabroker/internal/auth" // alias: avoids collision with go-sdk/auth
	"github.com/luisgf/infrabroker/internal/broker"
	"github.com/luisgf/infrabroker/internal/mcpserver"
	"github.com/luisgf/infrabroker/internal/oauth"
)

// prmPath is the path for the Protected Resource Metadata document (RFC 9728).
const prmPath = "/.well-known/oauth-protected-resource"

// maxMCPBody bounds the MCP request body before the SDK's streamable handler
// reads it. That handler does an unbounded io.ReadAll(req.Body); without this an
// authenticated client could POST a multi-gigabyte body and exhaust process
// memory (the per-field validateInput cap of 64 KiB only runs after the whole
// body is already buffered, and ReadTimeout does not help a fast uploader who
// delivers GBs within the window). 1 MiB is far above any legitimate request —
// the largest tool field is broker.MaxInputLen (64 KiB) plus the JSON-RPC
// envelope — while keeping the peer servers' fail-closed posture.
const maxMCPBody = 1 << 20 // 1 MiB

// mcpSessionIdleTimeout closes an MCP session (Mcp-Session-Id) that has received
// no HTTP request for this long; the SDK's zero default never closes one, so
// abandoned sessions would accumulate until the broker restarts (#807). The
// session holds no authorisation state — every tool call is authorised with its
// own request's token (httpCaller) — so this is resource hygiene, not a
// security bound, and a constant rather than a config knob. The SDK pauses the
// timer while a POST is in flight (a long tool call is never reaped); an open
// standalone GET stream does not count as activity. A reaped session answers
// 404 and the client must re-initialise; live SSH sessions are owned by the
// caller ID, not by the MCP session, so they survive that.
const mcpSessionIdleTimeout = 30 * time.Minute

// RunMCPHTTP serves the broker as a remote MCP server over HTTP (Streamable HTTP)
// protected with OAuth2/OIDC — the `serve-mcp-http` transport (legacy binary
// `mcp-broker-http`). Each client authenticates with a bearer token, validated
// locally against the issuer's JWKS; the user identity feeds the audit log and
// per-user RBAC in the signer. The ephemeral SSH credential never leaves the
// process; the model only receives the command output.
func RunMCPHTTP(args []string) {
	cfgPath, done := parseCommonFlags("mcp-broker-http", args)
	if done {
		return
	}
	eng, cfg := Boot("mcp-broker-http", cfgPath)
	defer eng.Close()

	if cfg.OAuth == nil {
		log.Fatalf("config: missing \"oauth\" block (required by the HTTP frontend)")
	}
	if cfg.ResourceURL == "" {
		log.Fatalf("config: missing \"resource_url\" (canonical URL of this MCP server)")
	}

	mux, err := newMux(context.Background(), eng, cfg)
	if err != nil {
		log.Fatalf("%v", err)
	}

	tlsCfg, err := mtls.ServerTLSConfigNoClientAuth(cfg.ServerCert, cfg.ServerKey)
	if err != nil {
		log.Fatalf("tls: %v", err)
	}
	log.Printf("mcp-broker-http (OAuth2/OIDC) on %s; issuer=%s; %d hosts", cfg.Listen, cfg.OAuth.Issuer, len(eng.Servers()))
	serveHTTP(cfg, tlsCfg, mux, "mcp-broker-http")
}

// newMux builds the HTTP handler for the frontend: the MCP endpoint protected
// by OIDC bearer token and the Protected Resource Metadata document (RFC 9728).
// Separated from RunMCPHTTP so it can be tested end-to-end without opening TLS
// sockets.
func newMux(ctx context.Context, eng *broker.Engine, cfg *broker.Config) (*http.ServeMux, error) {
	verifier, err := oauth.NewVerifier(ctx, oauth.Config{
		Issuer:         cfg.OAuth.Issuer,
		Audience:       cfg.OAuth.Audience,
		RequiredScopes: cfg.OAuth.RequiredScopes,
		UserClaim:      cfg.OAuth.UserClaim,
		GroupsClaim:    cfg.OAuth.GroupsClaim,
		ContextClaim:   cfg.OAuth.ContextClaim,
		MaxTokenAge:    time.Duration(cfg.OAuth.MaxTokenAgeSeconds) * time.Second,
		ClockSkew:      time.Duration(cfg.OAuth.ClockSkewSeconds) * time.Second,
	})
	if err != nil {
		return nil, err
	}

	srv := mcpserver.New(eng, httpCaller, false)
	mcpHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv },
		&mcp.StreamableHTTPOptions{SessionTimeout: mcpSessionIdleTimeout})

	resourceMetadataURL := strings.TrimRight(cfg.ResourceURL, "/") + prmPath
	protected := auth.RequireBearerToken(verifier.Verify, &auth.RequireBearerTokenOptions{
		ResourceMetadataURL: resourceMetadataURL,
		Scopes:              cfg.OAuth.RequiredScopes,
	})(capBody(mcpHandler, maxMCPBody))

	prm := auth.ProtectedResourceMetadataHandler(&oauthex.ProtectedResourceMetadata{
		Resource:               cfg.ResourceURL,
		AuthorizationServers:   []string{cfg.OAuth.Issuer},
		ScopesSupported:        cfg.OAuth.RequiredScopes,
		BearerMethodsSupported: []string{"header"},
		ResourceName:           "infrabroker (MCP)",
	})

	mux := http.NewServeMux()
	mux.Handle(prmPath, prm)
	mux.Handle("/", protected)
	return mux, nil
}

// capBody wraps h so the request body is bounded to max bytes before h reads
// it. http.MaxBytesReader makes the wrapped handler's read fail at the limit
// (HTTP 413) instead of buffering an unbounded body in memory.
func capBody(h http.Handler, max int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, max)
		h.ServeHTTP(w, r)
	})
}

// httpCaller derives the caller identity from the bearer token the middleware
// validated for THIS request, which the SDK hands the tool handler as
// req.Extra.TokenInfo. UserID feeds the audit log; groups (when present in the
// token) activate per-user RBAC in the signer.
//
// It deliberately ignores the handler context: on the stateful streamable
// handler that context derives from the request that created the MCP session
// (initialize), so auth.TokenInfoFromContext(ctx) would return the FIRST token
// of the session and keep its groups, context and raw token for the session's
// whole life — a refreshed token with fewer groups would not take effect
// (#807). A request without a TokenInfo yields the empty caller, as a context
// without a token did before; there is no fallback to the session's token. The
// case is unreachable in practice: RequireBearerToken rejects a request without
// a valid bearer before the SDK sees it.
func httpCaller(_ context.Context, req *mcp.CallToolRequest) broker.Caller {
	if req == nil || req.Extra == nil || req.Extra.TokenInfo == nil {
		return broker.Caller{}
	}
	ti := req.Extra.TokenInfo
	c := broker.Caller{ID: ti.UserID}
	if ti.Extra != nil {
		if g, ok := ti.Extra[oauth.ExtraGroupsKey].([]string); ok {
			c.Groups = g
		}
		// Carry the raw bearer so the engine can forward it to the signer for
		// signer-side re-validation of the end user (#143). In-process only.
		if rt, ok := ti.Extra[oauth.ExtraRawTokenKey].(string); ok {
			c.RawToken = rt
		}
		// Attribution context from the token (oauth.context_claim), e.g. the
		// sandbox_id of an ASP workload token; it reaches the cert KeyID and the
		// audit record, never a decision.
		if cx, ok := ti.Extra[oauth.ExtraContextKey].(string); ok {
			c.Context = cx
		}
	}
	return c
}
