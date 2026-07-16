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
// the largest tool field is mcpserver.maxInputLen (64 KiB) plus the JSON-RPC
// envelope — while keeping the peer servers' fail-closed posture.
const maxMCPBody = 1 << 20 // 1 MiB

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
		MaxTokenAge:    time.Duration(cfg.OAuth.MaxTokenAgeSeconds) * time.Second,
		ClockSkew:      time.Duration(cfg.OAuth.ClockSkewSeconds) * time.Second,
	})
	if err != nil {
		return nil, err
	}

	srv := mcpserver.New(eng, httpCaller, false)
	mcpHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil)

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

// httpCaller derives the caller identity from the bearer token validated by the
// middleware. UserID feeds the audit log; groups (when present in the token)
// activate per-user RBAC in the signer.
func httpCaller(ctx context.Context) broker.Caller {
	ti := auth.TokenInfoFromContext(ctx)
	if ti == nil {
		return broker.Caller{}
	}
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
	}
	return c
}
