package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/modelcontextprotocol/go-sdk/auth"
)

// oidcTestServer runs a minimal OIDC provider (discovery + JWKS) signing with
// a test RSA key, sufficient to exercise the Verifier offline.
type oidcTestServer struct {
	srv    *httptest.Server
	key    *rsa.PrivateKey
	signer jose.Signer
	// jwksHits counts GETs on the JWKS endpoint (#448: the refresh throttle).
	jwksHits atomic.Int64
	// jwksHook, when set, runs before the JWKS response; returning true means
	// the hook handled (or swallowed) the request (#583: a hung IdP).
	jwksHook func(w http.ResponseWriter, r *http.Request) bool
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
		ts.jwksHits.Add(1)
		if ts.jwksHook != nil && ts.jwksHook(w, r) {
			return
		}
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
	return signWith(t, ts.signer, claims)
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

// TestVerifyRetainsRawToken pins #143: Verify stashes the raw bearer under
// ExtraRawTokenKey so the HTTP frontend can forward it to the signer for
// signer-side re-validation of the end-user identity.
func TestVerifyRetainsRawToken(t *testing.T) {
	ts := newOIDCTestServer(t)
	v := ts.newVerifier(t, Config{Audience: "infrabroker"})
	tok := ts.sign(t, baseClaims(ts))

	ti, err := v.Verify(context.Background(), tok, nil)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	got, _ := ti.Extra[ExtraRawTokenKey].(string)
	if got != tok {
		t.Errorf("raw token not retained under ExtraRawTokenKey: got %q, want the presented token", got)
	}
}

// TestVerifyEndUser pins #143: the helper derives the identity and groups from
// the verified JWT, preserving the nil-vs-empty groups contract the signer
// relies on (nil = no groups claim configured; non-nil empty = deny every host).
func TestVerifyEndUser(t *testing.T) {
	ts := newOIDCTestServer(t)

	// Groups claim configured and present → derived.
	v := ts.newVerifier(t, Config{Audience: "infrabroker", GroupsClaim: "groups"})
	claims := baseClaims(ts)
	claims["groups"] = []string{"ops"}
	id, err := v.VerifyEndUser(context.Background(), ts.sign(t, claims))
	if err != nil {
		t.Fatalf("VerifyEndUser: %v", err)
	}
	if id.UserID != "alice" {
		t.Errorf("id = %q, want alice", id.UserID)
	}
	if len(id.Groups) != 1 || id.Groups[0] != "ops" {
		t.Errorf("groups = %v, want [ops]", id.Groups)
	}

	// Groups claim configured but empty → non-nil empty slice (deny-all).
	empty := baseClaims(ts)
	empty["groups"] = []string{}
	id2, err := v.VerifyEndUser(context.Background(), ts.sign(t, empty))
	if err != nil {
		t.Fatalf("VerifyEndUser empty groups: %v", err)
	}
	if id2.Groups == nil {
		t.Error("an empty groups claim must yield a non-nil empty slice (deny-all), not nil")
	}
	if len(id2.Groups) != 0 {
		t.Errorf("groups2 = %v, want empty", id2.Groups)
	}

	// No groups claim configured → nil groups (per-user RBAC not derived).
	vNoGroups := ts.newVerifier(t, Config{Audience: "infrabroker"})
	id3, err := vNoGroups.VerifyEndUser(context.Background(), ts.sign(t, baseClaims(ts)))
	if err != nil {
		t.Fatalf("VerifyEndUser no groups claim: %v", err)
	}
	if id3.Groups != nil {
		t.Errorf("no groups claim configured must yield nil groups, got %v", id3.Groups)
	}

	// Invalid token → error.
	if _, err := v.VerifyEndUser(context.Background(), "not-a-jwt"); err == nil {
		t.Error("an invalid token must be rejected")
	}
}

// TestContextClaim pins the attribution context (docs/SANDBOX.md): with a
// context_claim configured, a string claim is carried under ExtraContextKey and
// returned by VerifyEndUser; a missing or non-string claim is NOT an error (it
// is attribution, never authorisation), and without a context_claim nothing is
// derived even when the token carries the claim.
func TestContextClaim(t *testing.T) {
	ts := newOIDCTestServer(t)
	v := ts.newVerifier(t, Config{Audience: "infrabroker", UserClaim: "user_sub", ContextClaim: "sandbox_id"})

	// An ASP-shaped workload token: sub is the sandbox, user_sub the human owner.
	claims := baseClaims(ts)
	claims["sub"] = "sandbox/abc123"
	claims["user_sub"] = "alice"
	claims["sandbox_id"] = "abc123"
	ti, err := v.Verify(context.Background(), ts.sign(t, claims), nil)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if ti.UserID != "alice" {
		t.Errorf("UserID = %q, want the user_sub 'alice'", ti.UserID)
	}
	if got, _ := ti.Extra[ExtraContextKey].(string); got != "abc123" {
		t.Errorf("context = %q, want abc123", got)
	}
	id, err := v.VerifyEndUser(context.Background(), ts.sign(t, claims))
	if err != nil {
		t.Fatalf("VerifyEndUser: %v", err)
	}
	if id.UserID != "alice" || id.Context != "abc123" {
		t.Errorf("VerifyEndUser = %+v, want alice/abc123", id)
	}

	// Claim absent: accepted, no context.
	absent := baseClaims(ts)
	absent["user_sub"] = "alice"
	ti, err = v.Verify(context.Background(), ts.sign(t, absent), nil)
	if err != nil {
		t.Fatalf("a token without the context claim must be accepted: %v", err)
	}
	if _, ok := ti.Extra[ExtraContextKey]; ok {
		t.Error("no context must be stored when the claim is absent")
	}

	// Claim present but not a string: ignored, not an error.
	bad := baseClaims(ts)
	bad["user_sub"] = "alice"
	bad["sandbox_id"] = 42
	ti, err = v.Verify(context.Background(), ts.sign(t, bad), nil)
	if err != nil {
		t.Fatalf("a non-string context claim must be ignored, not rejected: %v", err)
	}
	if _, ok := ti.Extra[ExtraContextKey]; ok {
		t.Error("a non-string context claim must not be stored")
	}

	// No context_claim configured: the claim in the token is not derived.
	off := ts.newVerifier(t, Config{Audience: "infrabroker", UserClaim: "user_sub"})
	id, err = off.VerifyEndUser(context.Background(), ts.sign(t, claims))
	if err != nil {
		t.Fatalf("VerifyEndUser: %v", err)
	}
	if id.Context != "" {
		t.Errorf("context derived without a context_claim configured: %q", id.Context)
	}
}

// TestVerifyEndUserRequiredScopes pins #143: unlike the HTTP frontend (whose
// go-sdk middleware checks scopes), the signer path has no middleware, so
// VerifyEndUser must enforce required_scopes itself — otherwise end_user_oidc's
// required_scopes would be a silent no-op weaker than the frontend's check.
func TestVerifyEndUserRequiredScopes(t *testing.T) {
	ts := newOIDCTestServer(t)
	v := ts.newVerifier(t, Config{Audience: "infrabroker", RequiredScopes: []string{"mcp:access"}})

	ok := baseClaims(ts)
	ok["scope"] = "openid mcp:access"
	if _, err := v.VerifyEndUser(context.Background(), ts.sign(t, ok)); err != nil {
		t.Fatalf("token carrying the required scope rejected: %v", err)
	}

	no := baseClaims(ts)
	no["scope"] = "openid"
	if _, err := v.VerifyEndUser(context.Background(), ts.sign(t, no)); err == nil {
		t.Error("a token missing the required scope must be rejected on the signer path")
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

// TestVerifyClientCredentialsIdentity is the "one identity per agent" case
// (#121): a Keycloak client_credentials token puts the service-account UUID in
// `sub` and the client id in `azp`. With user_claim=azp the agent's identity is
// the stable, human-meaningful client id — not the opaque UUID — so audit and
// per-agent RBAC key on the agent, exactly like a human end user.
func TestVerifyClientCredentialsIdentity(t *testing.T) {
	ts := newOIDCTestServer(t)
	v := ts.newVerifier(t, Config{Audience: "infrabroker", GroupsClaim: "groups", UserClaim: "azp"})

	claims := baseClaims(ts)
	claims["sub"] = "b1f2c3d4-5678-90ab-cdef-service-account" // Keycloak: sub = SA UUID
	claims["azp"] = "agent-ci-runner"                         // the client id
	claims["groups"] = []string{"ci"}
	claims["scope"] = "mcp:tools"
	tok := ts.sign(t, claims)

	ti, err := v.Verify(context.Background(), tok, nil)
	if err != nil {
		t.Fatalf("client_credentials token rejected: %v", err)
	}
	if ti.UserID != "agent-ci-runner" {
		t.Errorf("UserID = %q, want the client id agent-ci-runner (not the sub UUID)", ti.UserID)
	}
	g, _ := ti.Extra[ExtraGroupsKey].([]string)
	if len(g) != 1 || g[0] != "ci" {
		t.Errorf("groups = %v, want [ci]", g)
	}
}

// TestVerifyClientCredentialsDefaultSubIsUUID shows why user_claim=azp is
// needed: with the default (sub) the identity is the opaque service-account
// UUID, useless for audit/RBAC.
func TestVerifyClientCredentialsDefaultSubIsUUID(t *testing.T) {
	ts := newOIDCTestServer(t)
	v := ts.newVerifier(t, Config{Audience: "infrabroker", GroupsClaim: "groups"}) // default user_claim=sub

	claims := baseClaims(ts)
	claims["sub"] = "b1f2c3d4-5678-90ab-cdef-service-account"
	claims["azp"] = "agent-ci-runner"
	claims["groups"] = []string{"ci"}
	tok := ts.sign(t, claims)

	ti, err := v.Verify(context.Background(), tok, nil)
	if err != nil {
		t.Fatalf("token rejected: %v", err)
	}
	if ti.UserID != "b1f2c3d4-5678-90ab-cdef-service-account" {
		t.Errorf("UserID = %q, want the sub UUID — motivating user_claim=azp", ti.UserID)
	}
}

// TestVerifyClientCredentialsMissingGroupsRejected is why the lab configures a
// group-membership mapper on the service account: without it the token has no
// groups claim, per-user RBAC is fail-closed, and the token is rejected.
func TestVerifyClientCredentialsMissingGroupsRejected(t *testing.T) {
	ts := newOIDCTestServer(t)
	v := ts.newVerifier(t, Config{Audience: "infrabroker", GroupsClaim: "groups", UserClaim: "azp"})

	claims := baseClaims(ts)
	claims["azp"] = "agent-ci-runner"
	// No "groups" claim (no group-membership mapper on the service account).
	tok := ts.sign(t, claims)

	if _, err := v.Verify(context.Background(), tok, nil); err == nil {
		t.Fatal("a client_credentials token without the groups mapper must be rejected (fail-closed)")
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

// forgedSigner signs with a key the IdP never published but under the IdP's
// real kid, so go-oidc's cached key fails to verify and it asks the remote
// JWKS for new keys — the amplification path of #448.
func forgedSigner(t *testing.T) jose.Signer {
	t.Helper()
	rogue, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: rogue},
		(&jose.SignerOptions{}).WithHeader("kid", "test").WithType("JWT"),
	)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func signWith(t *testing.T, s jose.Signer, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := s.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// TestJWKSRefreshThrottled pins #448: sequential bearers that fail signature
// verification (forged under the IdP's real kid) must not each cost one JWKS
// fetch to the IdP. The outbound refreshes are bounded by the throttle, a
// legitimate token keeps verifying against the cached key while the throttle
// is exhausted, and once the window elapses a refresh is allowed again (key
// rotation is delayed, not broken).
func TestJWKSRefreshThrottled(t *testing.T) {
	ts := newOIDCTestServer(t)
	v := ts.newVerifier(t, Config{Audience: "infrabroker"})
	forged := forgedSigner(t)

	for i := 0; i < 50; i++ {
		_, err := v.Verify(context.Background(), signWith(t, forged, baseClaims(ts)), nil)
		if err == nil {
			t.Fatalf("forged token %d accepted", i)
		}
		if !errors.Is(err, auth.ErrInvalidToken) {
			t.Fatalf("forged token %d: err = %v, want auth.ErrInvalidToken", i, err)
		}
	}
	hits := ts.jwksHits.Load()
	if hits > jwksRefreshBurst {
		t.Fatalf("50 forged tokens drove %d JWKS fetches, want <= %d", hits, jwksRefreshBurst)
	}
	if hits == 0 {
		t.Fatal("no JWKS fetch at all: the test did not exercise the refresh path")
	}

	// Throttle exhausted: a legitimate token still verifies locally against
	// the cached key, with no outbound fetch.
	if _, err := v.Verify(context.Background(), ts.sign(t, baseClaims(ts)), nil); err != nil {
		t.Fatalf("valid token rejected while the refresh throttle is exhausted: %v", err)
	}
	if got := ts.jwksHits.Load(); got != hits {
		t.Fatalf("valid token caused a JWKS fetch (%d -> %d)", hits, got)
	}

	// Once one refresh interval has elapsed, exactly one more refresh is
	// allowed (then the bucket is empty again).
	v.jwks.mu.Lock()
	v.jwks.now = func() time.Time { return time.Now().Add(jwksRefreshInterval + time.Second) }
	v.jwks.mu.Unlock()
	for i := 0; i < 5; i++ {
		if _, err := v.Verify(context.Background(), signWith(t, forged, baseClaims(ts)), nil); err == nil {
			t.Fatal("forged token accepted after the window")
		}
	}
	if got := ts.jwksHits.Load(); got != hits+1 {
		t.Fatalf("after the refresh window: %d JWKS fetches, want exactly %d", got, hits+1)
	}
	if _, err := v.Verify(context.Background(), ts.sign(t, baseClaims(ts)), nil); err != nil {
		t.Fatalf("valid token rejected after the window: %v", err)
	}
}

// TestIdPTimeoutBoundsJWKSRefresh pins #583: go-oidc keeps the HTTP client
// installed by NewVerifier for every later JWKS refresh and serialises
// refreshes behind one inflight fetch, so an IdP that accepts the connection
// and never answers must not pin that fetch (and every post-rotation Verify)
// forever. With the client timeout in place, a Verify that needs a refresh
// returns auth.ErrInvalidToken within the bound, and the key set recovers once
// the IdP answers again.
func TestIdPTimeoutBoundsJWKSRefresh(t *testing.T) {
	saved := idpHTTPTimeout
	idpHTTPTimeout = 300 * time.Millisecond
	t.Cleanup(func() { idpHTTPTimeout = saved })

	ts := newOIDCTestServer(t)
	// After discovery (served normally), the JWKS endpoint hangs until the
	// client gives up or the test ends.
	var hang atomic.Bool
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	ts.jwksHook = func(w http.ResponseWriter, r *http.Request) bool {
		if !hang.Load() {
			return false
		}
		select {
		case <-r.Context().Done():
		case <-release:
		}
		return true
	}
	v := ts.newVerifier(t, Config{Audience: "infrabroker"})
	hang.Store(true)

	// First Verify: no cached key yet, so it must fetch the JWKS -> hangs ->
	// must be cut by the timeout, not block the caller.
	start := time.Now()
	_, err := v.Verify(context.Background(), ts.sign(t, baseClaims(ts)), nil)
	elapsed := time.Since(start)
	if !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("Verify against a hung IdP: err = %v, want auth.ErrInvalidToken", err)
	}
	if elapsed > 5*idpHTTPTimeout {
		t.Fatalf("Verify took %v against a hung IdP; the %v client timeout did not bound it", elapsed, idpHTTPTimeout)
	}
	// The inflight fetch was released by the timeout: once the IdP answers
	// again, the next refresh completes and the token verifies (nothing is
	// pinned until restart).
	hang.Store(false)
	if _, err := v.Verify(context.Background(), ts.sign(t, baseClaims(ts)), nil); err != nil {
		t.Fatalf("Verify after the IdP recovered: %v", err)
	}
}

// TestIdPTimeoutBoundsDiscovery pins the startup half of #583: a hung
// discovery endpoint fails NewVerifier within the bound instead of hanging the
// frontend's startup forever.
func TestIdPTimeoutBoundsDiscovery(t *testing.T) {
	saved := idpHTTPTimeout
	idpHTTPTimeout = 300 * time.Millisecond
	t.Cleanup(func() { idpHTTPTimeout = saved })

	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(srv.Close)

	start := time.Now()
	_, err := NewVerifier(context.Background(), Config{Issuer: srv.URL, Audience: "infrabroker"})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("NewVerifier against a hung discovery endpoint succeeded")
	}
	if elapsed > 5*idpHTTPTimeout {
		t.Fatalf("NewVerifier took %v against a hung IdP; the %v client timeout did not bound it", elapsed, idpHTTPTimeout)
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
