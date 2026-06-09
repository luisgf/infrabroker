package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"golang.org/x/crypto/ssh"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/luisgf/ssh-broker/internal/broker"
)

// --- Fake OIDC IdP (discovery + JWKS) signing with a test RSA key. ---

type fakeIdP struct {
	srv    *httptest.Server
	signer jose.Signer
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithHeader("kid", "test").WithType("JWT"),
	)
	if err != nil {
		t.Fatal(err)
	}
	idp := &fakeIdP{signer: signer}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 idp.srv.URL,
			"jwks_uri":               idp.srv.URL + "/jwks",
			"authorization_endpoint": idp.srv.URL + "/auth",
			"token_endpoint":         idp.srv.URL + "/token",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: &key.PublicKey, KeyID: "test", Algorithm: "RS256", Use: "sig",
		}}})
	})
	idp.srv = httptest.NewServer(mux)
	t.Cleanup(idp.srv.Close)
	return idp
}

func (idp *fakeIdP) token(t *testing.T, sub string) string {
	t.Helper()
	payload, _ := json.Marshal(map[string]any{
		"iss":   idp.srv.URL,
		"aud":   "ssh-broker",
		"sub":   sub,
		"scope": "mcp:tools",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
	})
	jws, err := idp.signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// --- Broker engine in local mode with a test host (no actual connection:
// the test only calls ssh_list_servers, which does not open SSH). ---

func testEngine(t *testing.T, issuer string) (*broker.Engine, *broker.Config) {
	t.Helper()
	dir := t.TempDir()

	// CA key (ed25519) in OpenSSH PEM format.
	_, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	blk, err := ssh.MarshalPrivateKey(caPriv, "ca-test")
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(dir, "ca")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(blk), 0o600); err != nil {
		t.Fatal(err)
	}

	seed := make([]byte, 32)
	_, _ = rand.Read(seed)
	seedPath := filepath.Join(dir, "audit.seed")
	if err := os.WriteFile(seedPath, seed, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &broker.Config{
		CAKey:         caPath,
		AuditLog:      filepath.Join(dir, "audit.log"),
		AuditKey:      seedPath,
		SourceAddress: "127.0.0.1",
		MaxTTLSeconds: 120,
		ResourceURL:   "https://broker.test",
		OAuth: &broker.OAuthConfig{
			Issuer:         issuer,
			Audience:       "ssh-broker",
			RequiredScopes: []string{"mcp:tools"},
			UserClaim:      "sub",
		},
		Hosts: map[string]broker.HostConfig{
			"web01": {Addr: "10.0.0.21:22", User: "deploy", Principal: "host:web01",
				HostKey: "ssh-ed25519 AAAAC3Nz", AllowSudo: true},
		},
	}
	eng, err := broker.NewEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { eng.Close() })
	return eng, cfg
}

// bearerTransport injects an Authorization: Bearer header into every request.
type bearerTransport struct {
	token string
	base  http.RoundTripper
}

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if b.token != "" {
		r = r.Clone(r.Context())
		r.Header.Set("Authorization", "Bearer "+b.token)
	}
	return b.base.RoundTrip(r)
}

func dialMCP(t *testing.T, endpoint, token string) (*mcp.ClientSession, error) {
	t.Helper()
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	httpClient := &http.Client{Transport: bearerTransport{token: token, base: http.DefaultTransport}}
	return client.Connect(context.Background(),
		&mcp.StreamableClientTransport{Endpoint: endpoint, HTTPClient: httpClient},
		nil)
}

func TestHTTPFrontendAuth(t *testing.T) {
	idp := newFakeIdP(t)
	eng, cfg := testEngine(t, idp.srv.URL)

	mux, err := newMux(context.Background(), eng, cfg)
	if err != nil {
		t.Fatalf("newMux: %v", err)
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	t.Run("valid token lists servers", func(t *testing.T) {
		sess, err := dialMCP(t, srv.URL, idp.token(t, "alice"))
		if err != nil {
			t.Fatalf("connect with valid token: %v", err)
		}
		defer sess.Close()

		res, err := sess.CallTool(context.Background(), &mcp.CallToolParams{Name: "ssh_list_servers"})
		if err != nil {
			t.Fatalf("ssh_list_servers: %v", err)
		}
		if res.IsError {
			t.Fatalf("ssh_list_servers returned error: %+v", res.Content)
		}
		txt := textContent(res)
		if want := "web01"; !contains(txt, want) {
			t.Errorf("output does not contain %q: %q", want, txt)
		}
	})

	t.Run("no token is rejected", func(t *testing.T) {
		if _, err := dialMCP(t, srv.URL, ""); err == nil {
			t.Fatal("connection without token should fail (401)")
		}
	})
}

func TestProtectedResourceMetadata(t *testing.T) {
	idp := newFakeIdP(t)
	eng, cfg := testEngine(t, idp.srv.URL)
	mux, err := newMux(context.Background(), eng, cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + prmPath)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PRM status = %d", resp.StatusCode)
	}
	var prm struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&prm); err != nil {
		t.Fatal(err)
	}
	if prm.Resource != "https://broker.test" {
		t.Errorf("resource = %q", prm.Resource)
	}
	if len(prm.AuthorizationServers) != 1 || prm.AuthorizationServers[0] != idp.srv.URL {
		t.Errorf("authorization_servers = %v", prm.AuthorizationServers)
	}
}

func textContent(res *mcp.CallToolResult) string {
	var s string
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			s += tc.Text
		}
	}
	return s
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
