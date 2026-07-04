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
		"aud": "infrabroker",
		"sub": "alice",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
}

func TestVerifyValid(t *testing.T) {
	ts := newOIDCTestServer(t)
	v := ts.newVerifier(t, Config{Audience: "infrabroker", GroupsClaim: "groups"})

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
	v := ts.newVerifier(t, Config{Audience: "infrabroker"})

	claims := baseClaims(ts)
	claims["aud"] = "otra-api"
	tok := ts.sign(t, claims)

	if _, err := v.Verify(context.Background(), tok, nil); err == nil {
		t.Fatal("aud incorrecto debería rechazarse")
	}
}

func TestVerifyExpired(t *testing.T) {
	ts := newOIDCTestServer(t)
	v := ts.newVerifier(t, Config{Audience: "infrabroker"})

	claims := baseClaims(ts)
	claims["exp"] = time.Now().Add(-time.Minute).Unix()
	tok := ts.sign(t, claims)

	if _, err := v.Verify(context.Background(), tok, nil); err == nil {
		t.Fatal("token expirado debería rechazarse")
	}
}

func TestVerifyBadSignature(t *testing.T) {
	ts := newOIDCTestServer(t)
	v := ts.newVerifier(t, Config{Audience: "infrabroker"})

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
	v := ts.newVerifier(t, Config{Audience: "infrabroker", UserClaim: "preferred_username"})

	// Token does not carry preferred_username → no usable identity.
	tok := ts.sign(t, baseClaims(ts))

	if _, err := v.Verify(context.Background(), tok, nil); err == nil {
		t.Fatal("missing user claim should be rejected")
	}
}

func TestVerifyMissingGroupsClaimRejected(t *testing.T) {
	ts := newOIDCTestServer(t)
	v := ts.newVerifier(t, Config{Audience: "infrabroker", GroupsClaim: "groups"})

	// Token without the configured groups claim: fail-closed, otherwise the
	// signer's per-user RBAC would be silently bypassed (nil = unrestricted).
	tok := ts.sign(t, baseClaims(ts))

	if _, err := v.Verify(context.Background(), tok, nil); err == nil {
		t.Fatal("token without groups claim should be rejected when groups_claim is configured")
	}
}

func TestVerifyEmptyGroupsClaimPropagated(t *testing.T) {
	ts := newOIDCTestServer(t)
	v := ts.newVerifier(t, Config{Audience: "infrabroker", GroupsClaim: "groups"})

	// An explicitly empty groups list is valid: it is propagated as-is and the
	// signer denies every host for the user (deny-all, not unrestricted).
	claims := baseClaims(ts)
	claims["groups"] = []string{}
	tok := ts.sign(t, claims)

	ti, err := v.Verify(context.Background(), tok, nil)
	if err != nil {
		t.Fatalf("token with empty groups list rejected: %v", err)
	}
	g, ok := ti.Extra[ExtraGroupsKey].([]string)
	if !ok || g == nil || len(g) != 0 {
		t.Errorf("groups = %v (ok=%v), want non-nil empty slice", g, ok)
	}
}

func TestVerifyMissingIATRejectedWithMaxAge(t *testing.T) {
	ts := newOIDCTestServer(t)
	v := ts.newVerifier(t, Config{Audience: "infrabroker", MaxTokenAge: time.Hour})

	// Token without iat: its age cannot be established, so with MaxTokenAge in
	// force it must be rejected (fail-closed), not exempted from the check.
	claims := baseClaims(ts)
	delete(claims, "iat")
	tok := ts.sign(t, claims)

	if _, err := v.Verify(context.Background(), tok, nil); err == nil {
		t.Fatal("token without iat should be rejected when MaxTokenAge is enforced")
	}
}

func TestVerifyTokenAge(t *testing.T) {
	ts := newOIDCTestServer(t)
	v := ts.newVerifier(t, Config{Audience: "infrabroker", MaxTokenAge: time.Hour})

	// Fresh token accepted.
	if _, err := v.Verify(context.Background(), ts.sign(t, baseClaims(ts)), nil); err != nil {
		t.Fatalf("fresh token rejected: %v", err)
	}

	// Token older than MaxTokenAge rejected (still within exp).
	claims := baseClaims(ts)
	claims["iat"] = time.Now().Add(-2 * time.Hour).Unix()
	if _, err := v.Verify(context.Background(), ts.sign(t, claims), nil); err == nil {
		t.Fatal("token older than MaxTokenAge should be rejected")
	}
}

func TestVerifyNotYetValid(t *testing.T) {
	ts := newOIDCTestServer(t)
	v := ts.newVerifier(t, Config{Audience: "infrabroker"})

	// nbf well into the future: go-oidc does not check nbf, so this package must.
	claims := baseClaims(ts)
	claims["nbf"] = time.Now().Add(time.Hour).Unix()
	if _, err := v.Verify(context.Background(), ts.sign(t, claims), nil); err == nil {
		t.Fatal("token with a future nbf should be rejected")
	}
}

func TestVerifyNbfWithinSkewAccepted(t *testing.T) {
	ts := newOIDCTestServer(t)
	v := ts.newVerifier(t, Config{Audience: "infrabroker"}) // default 1-minute skew

	// nbf just barely in the future: absorbed by the clock-skew tolerance.
	claims := baseClaims(ts)
	claims["nbf"] = time.Now().Add(20 * time.Second).Unix()
	if _, err := v.Verify(context.Background(), ts.sign(t, claims), nil); err != nil {
		t.Fatalf("nbf within the skew tolerance should be accepted: %v", err)
	}
}

func TestVerifyFutureIATRejected(t *testing.T) {
	ts := newOIDCTestServer(t)
	v := ts.newVerifier(t, Config{Audience: "infrabroker", MaxTokenAge: time.Hour})

	// iat far in the future would read as a negative age and slip under the
	// max-age bound; it must be rejected as issued-in-the-future.
	claims := baseClaims(ts)
	claims["iat"] = time.Now().Add(time.Hour).Unix()
	if _, err := v.Verify(context.Background(), ts.sign(t, claims), nil); err == nil {
		t.Fatal("token with an iat in the future should be rejected")
	}
}
