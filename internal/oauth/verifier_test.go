package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// oidcTestServer runs a minimal OIDC provider (discovery + JWKS) signing with
// a test RSA key, sufficient to exercise the Verifier offline.
type oidcTestServer struct {
	srv    *httptest.Server
	key    *rsa.PrivateKey
	signer jose.Signer
}

func newOIDCTestServer(t *testing.T) *oidcTestServer {
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

	ts := &oidcTestServer{key: key, signer: signer}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 ts.srv.URL,
			"jwks_uri":               ts.srv.URL + "/jwks",
			"authorization_endpoint": ts.srv.URL + "/auth",
			"token_endpoint":         ts.srv.URL + "/token",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: &key.PublicKey, KeyID: "test", Algorithm: "RS256", Use: "sig",
		}}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	})
	ts.srv = httptest.NewServer(mux)
	t.Cleanup(ts.srv.Close)
	return ts
}

// sign serialises claims as a JWT signed by the server key.
func (ts *oidcTestServer) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := ts.signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func (ts *oidcTestServer) newVerifier(t *testing.T, cfg Config) *Verifier {
	t.Helper()
	if cfg.Issuer == "" {
		cfg.Issuer = ts.srv.URL
	}
	v, err := NewVerifier(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}

func baseClaims(ts *oidcTestServer) map[string]any {
	return map[string]any{
		"iss": ts.srv.URL,
		"aud": "ssh-broker",
		"sub": "alice",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
}

func TestVerifyValid(t *testing.T) {
	ts := newOIDCTestServer(t)
	v := ts.newVerifier(t, Config{Audience: "ssh-broker", GroupsClaim: "groups"})

	claims := baseClaims(ts)
	claims["scope"] = "mcp:tools openid"
	claims["groups"] = []string{"prod", "ops"}
	tok := ts.sign(t, claims)

	ti, err := v.Verify(context.Background(), tok, nil)
	if err != nil {
		t.Fatalf("token válido rechazado: %v", err)
	}
	if ti.UserID != "alice" {
		t.Errorf("UserID = %q, quiero alice", ti.UserID)
	}
	if len(ti.Scopes) != 2 || ti.Scopes[0] != "mcp:tools" {
		t.Errorf("Scopes = %v", ti.Scopes)
	}
	g, _ := ti.Extra[ExtraGroupsKey].([]string)
	if len(g) != 2 || g[0] != "prod" {
		t.Errorf("groups = %v", g)
	}
}

func TestVerifyWrongAudience(t *testing.T) {
	ts := newOIDCTestServer(t)
	v := ts.newVerifier(t, Config{Audience: "ssh-broker"})

	claims := baseClaims(ts)
	claims["aud"] = "otra-api"
	tok := ts.sign(t, claims)

	if _, err := v.Verify(context.Background(), tok, nil); err == nil {
		t.Fatal("aud incorrecto debería rechazarse")
	}
}

func TestVerifyExpired(t *testing.T) {
	ts := newOIDCTestServer(t)
	v := ts.newVerifier(t, Config{Audience: "ssh-broker"})

	claims := baseClaims(ts)
	claims["exp"] = time.Now().Add(-time.Minute).Unix()
	tok := ts.sign(t, claims)

	if _, err := v.Verify(context.Background(), tok, nil); err == nil {
		t.Fatal("token expirado debería rechazarse")
	}
}

func TestVerifyBadSignature(t *testing.T) {
	ts := newOIDCTestServer(t)
	v := ts.newVerifier(t, Config{Audience: "ssh-broker"})

	// Sign with a different key from the one published in the JWKS.
	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	otherSigner, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: otherKey},
		(&jose.SignerOptions{}).WithHeader("kid", "test").WithType("JWT"),
	)
	payload, _ := json.Marshal(baseClaims(ts))
	jws, _ := otherSigner.Sign(payload)
	tok, _ := jws.CompactSerialize()

	if _, err := v.Verify(context.Background(), tok, nil); err == nil {
		t.Fatal("invalid signature should be rejected")
	}
}

func TestVerifyMissingUserClaim(t *testing.T) {
	ts := newOIDCTestServer(t)
	v := ts.newVerifier(t, Config{Audience: "ssh-broker", UserClaim: "preferred_username"})

	// Token does not carry preferred_username → no usable identity.
	tok := ts.sign(t, baseClaims(ts))

	if _, err := v.Verify(context.Background(), tok, nil); err == nil {
		t.Fatal("missing user claim should be rejected")
	}
}
