// Command mcp-broker-http expone el broker como servidor MCP remoto sobre HTTP
// (Streamable HTTP) protegido con OAuth2/OIDC, según la especificación de
// autorización del MCP. Cada cliente se autentica con un bearer token; el broker
// lo valida localmente contra el JWKS del issuer (sin round-trip por petición) y
// usa la identidad del usuario para auditoría y para el RBAC por usuario del
// signer.
//
// A diferencia de cmd/mcp-broker (stdio, local), este frontend está pensado para
// despliegues multiusuario por red. La credencial SSH efímera nunca sale del
// proceso; el modelo solo recibe la salida del comando.
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"

	mtls "github.com/luisgf/ssh-broker/internal/auth" // alias: evita colisión con go-sdk/auth
	"github.com/luisgf/ssh-broker/internal/broker"
	"github.com/luisgf/ssh-broker/internal/mcpserver"
	"github.com/luisgf/ssh-broker/internal/oauth"
)

// prmPath es la ruta del documento Protected Resource Metadata (RFC 9728).
const prmPath = "/.well-known/oauth-protected-resource"

func main() {
	cfgPath := flag.String("config", "config.json", "ruta al fichero de configuración JSON")
	flag.Parse()

	cfg, err := broker.LoadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if cfg.OAuth == nil {
		log.Fatalf("config: falta el bloque \"oauth\" (requerido por el frontend HTTP)")
	}
	if cfg.ResourceURL == "" {
		log.Fatalf("config: falta \"resource_url\" (URL canónica de este servidor MCP)")
	}

	eng, err := broker.NewEngine(cfg)
	if err != nil {
		log.Fatalf("inicializar broker: %v", err)
	}
	defer eng.Close()

	mux, err := newMux(context.Background(), eng, cfg)
	if err != nil {
		log.Fatalf("%v", err)
	}

	tlsCfg, err := mtls.ServerTLSConfigNoClientAuth(cfg.ServerCert, cfg.ServerKey)
	if err != nil {
		log.Fatalf("tls: %v", err)
	}
	// A1: timeouts para evitar agotamiento de conexiones (slowloris).
	// WriteTimeout deliberadamente no establecido: los streams SSE del MCP pueden
	// estar abiertos mientras dure la respuesta de un comando SSH.
	httpSrv := &http.Server{
		Addr:        cfg.Listen,
		Handler:     mux,
		TLSConfig:   tlsCfg,
		ReadTimeout: 15 * time.Second,
		IdleTimeout: 120 * time.Second,
	}
	log.Printf("mcp-broker-http (OAuth2/OIDC) en %s; issuer=%s; %d hosts", cfg.Listen, cfg.OAuth.Issuer, len(eng.Servers()))
	log.Fatal(httpSrv.ListenAndServeTLS("", ""))
}

// newMux construye el handler HTTP del frontend: el endpoint MCP protegido por
// bearer token OIDC y el documento Protected Resource Metadata (RFC 9728). Se
// separa de main para poder probarlo end-to-end sin abrir sockets TLS.
func newMux(ctx context.Context, eng *broker.Engine, cfg *broker.Config) (*http.ServeMux, error) {
	verifier, err := oauth.NewVerifier(ctx, oauth.Config{
		Issuer:         cfg.OAuth.Issuer,
		Audience:       cfg.OAuth.Audience,
		RequiredScopes: cfg.OAuth.RequiredScopes,
		UserClaim:      cfg.OAuth.UserClaim,
		GroupsClaim:    cfg.OAuth.GroupsClaim,
		MaxTokenAge:    time.Duration(cfg.OAuth.MaxTokenAgeSeconds) * time.Second,
	})
	if err != nil {
		return nil, err
	}

	srv := mcpserver.New(eng, httpCaller)
	mcpHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil)

	resourceMetadataURL := strings.TrimRight(cfg.ResourceURL, "/") + prmPath
	protected := auth.RequireBearerToken(verifier.Verify, &auth.RequireBearerTokenOptions{
		ResourceMetadataURL: resourceMetadataURL,
		Scopes:              cfg.OAuth.RequiredScopes,
	})(mcpHandler)

	prm := auth.ProtectedResourceMetadataHandler(&oauthex.ProtectedResourceMetadata{
		Resource:               cfg.ResourceURL,
		AuthorizationServers:   []string{cfg.OAuth.Issuer},
		ScopesSupported:        cfg.OAuth.RequiredScopes,
		BearerMethodsSupported: []string{"header"},
		ResourceName:           "SSH Broker (MCP)",
	})

	mux := http.NewServeMux()
	mux.Handle(prmPath, prm)
	mux.Handle("/", protected)
	return mux, nil
}

// httpCaller deriva la identidad del llamante del token bearer validado por el
// middleware. UserID alimenta la auditoría; los grupos (si el token los porta)
// activan el RBAC por usuario en el signer.
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
	}
	return c
}
