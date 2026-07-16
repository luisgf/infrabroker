package main

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

	"github.com/luisgf/infrabroker/internal/oauth"
	"github.com/luisgf/infrabroker/internal/signer"
)

// oidcTB is a minimal OIDC provider (discovery + JWKS) for signer tests,
// mirroring internal/oauth's test harness so the signer can build a real
// *oauth.Verifier offline and mint tokens for signer-side re-validation (#143).
type oidcTB struct {
	srv    *httptest.Server
	signer jose.Signer
}

func newOIDCTB(t *testing.T) *oidcTB {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jsigner, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithHeader("kid", "test").WithType("JWT"),
	)
	if err != nil {
		t.Fatal(err)
	}
	o := &oidcTB{signer: jsigner}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 o.srv.URL,
			"jwks_uri":               o.srv.URL + "/jwks",
			"authorization_endpoint": o.srv.URL + "/auth",
			"token_endpoint":         o.srv.URL + "/token",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: &key.PublicKey, KeyID: "test", Algorithm: "RS256", Use: "sig",
		}}})
	})
	o.srv = httptest.NewServer(mux)
	t.Cleanup(o.srv.Close)
	return o
}

// token mints a JWT for sub, optionally carrying a groups claim (nil = omit it).
func (o *oidcTB) token(t *testing.T, sub string, groups []string) string {
	t.Helper()
	claims := map[string]any{
		"iss": o.srv.URL,
		"aud": "infrabroker",
		"sub": sub,
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
	if groups != nil {
		claims["groups"] = groups
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := o.signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func (o *oidcTB) verifier(t *testing.T, groupsClaim string) *oauth.Verifier {
	t.Helper()
	v, err := oauth.NewVerifier(context.Background(), oauth.Config{
		Issuer: o.srv.URL, Audience: "infrabroker", GroupsClaim: groupsClaim,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}

// TestRederiveEndUser exercises the signer-side re-validation logic directly
// (#143): a gated caller's end_user/groups are derived from the verified JWT and
// overwrite the broker-asserted values; a non-gated caller is untouched; and a
// gated caller fails closed when it cannot be verified.
func TestRederiveEndUser(t *testing.T) {
	o := newOIDCTB(t)
	v := o.verifier(t, "groups")
	gated := signer.CallerTable{"http-broker": {AllowedGroups: []string{"ops"}, RequireVerifiedEndUser: true}}

	t.Run("not gated is a no-op", func(t *testing.T) {
		srv := &server{callers: gated, endUserVerifier: v}
		req := &signer.WireRequest{
			EndUser: "asserted", EndUserGroups: []string{"whatever"},
			BearerToken: o.token(t, "alice", []string{"ops"}),
		}
		if err := srv.rederiveEndUser(context.Background(), gated, "unlisted-broker", req); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if req.EndUser != "asserted" {
			t.Errorf("EndUser mutated for a non-gated caller: %q", req.EndUser)
		}
	})

	t.Run("gated overwrites with the verified identity", func(t *testing.T) {
		srv := &server{callers: gated, endUserVerifier: v}
		req := &signer.WireRequest{
			EndUser: "forged-admin", EndUserGroups: []string{"forged-group"},
			BearerToken: o.token(t, "alice", []string{"ops"}),
		}
		if err := srv.rederiveEndUser(context.Background(), gated, "http-broker", req); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if req.EndUser != "alice" {
			t.Errorf("EndUser = %q, want the verified sub 'alice'", req.EndUser)
		}
		if len(req.EndUserGroups) != 1 || req.EndUserGroups[0] != "ops" {
			t.Errorf("EndUserGroups = %v, want the verified [ops]", req.EndUserGroups)
		}
	})

	t.Run("gated without a verifier fails closed", func(t *testing.T) {
		srv := &server{callers: gated, endUserVerifier: nil}
		req := &signer.WireRequest{EndUser: "x", BearerToken: o.token(t, "alice", []string{"ops"})}
		if err := srv.rederiveEndUser(context.Background(), gated, "http-broker", req); err == nil {
			t.Error("a gated caller with no verifier configured must be denied")
		}
	})

	t.Run("gated without a token fails closed", func(t *testing.T) {
		srv := &server{callers: gated, endUserVerifier: v}
		req := &signer.WireRequest{EndUser: "x"}
		if err := srv.rederiveEndUser(context.Background(), gated, "http-broker", req); err == nil {
			t.Error("a gated caller with no forwarded token must be denied")
		}
	})

	t.Run("gated with an invalid token fails closed", func(t *testing.T) {
		srv := &server{callers: gated, endUserVerifier: v}
		req := &signer.WireRequest{EndUser: "x", BearerToken: "not-a-jwt"}
		if err := srv.rederiveEndUser(context.Background(), gated, "http-broker", req); err == nil {
			t.Error("a gated caller with an invalid token must be denied")
		}
	})

	// #143 (review): an asymmetric config — the frontend asserts groups but the
	// signer has no groups_claim to re-verify them — must fail closed, not
	// silently discard the restriction and widen access to the caller CN's whole
	// allowlist.
	t.Run("gated without groups_claim denies an asserted group restriction", func(t *testing.T) {
		vNoGroups := o.verifier(t, "")
		srv := &server{callers: gated, endUserVerifier: vNoGroups}
		req := &signer.WireRequest{EndUser: "x", EndUserGroups: []string{"prod"}, BearerToken: o.token(t, "alice", nil)}
		if err := srv.rederiveEndUser(context.Background(), gated, "http-broker", req); err == nil {
			t.Error("must deny: the signer cannot re-verify asserted groups without a groups_claim")
		}
	})

	// Attribution-only (the frontend asserts no groups) is unaffected: nil in, nil
	// derived, nothing discarded — the verified identity still overwrites end_user.
	t.Run("gated without groups_claim allows attribution-only", func(t *testing.T) {
		vNoGroups := o.verifier(t, "")
		srv := &server{callers: gated, endUserVerifier: vNoGroups}
		req := &signer.WireRequest{EndUser: "forged", BearerToken: o.token(t, "alice", nil)}
		if err := srv.rederiveEndUser(context.Background(), gated, "http-broker", req); err != nil {
			t.Fatalf("attribution-only (no asserted groups) must be allowed: %v", err)
		}
		if req.EndUser != "alice" {
			t.Errorf("EndUser = %q, want the verified 'alice'", req.EndUser)
		}
		if req.EndUserGroups != nil {
			t.Errorf("EndUserGroups = %v, want nil (no per-user narrowing)", req.EndUserGroups)
		}
	})
}

// TestHandleSignReValidatesEndUser proves handleSign wires re-validation in
// (#143): a compromised broker's forged end_user is overwritten by the verified
// identity before the Intent reaches the signer, and a gated caller that
// forwards no token is denied (fail-closed) before any issuance.
func TestHandleSignReValidatesEndUser(t *testing.T) {
	o := newOIDCTB(t)
	v := o.verifier(t, "groups")
	callers := signer.CallerTable{"http-broker": {AllowedGroups: []string{"ops"}, RequireVerifiedEndUser: true}}
	hosts := signer.PolicyTable{"web": {Addr: "10.0.0.1:22", User: "deploy", Principal: "host:web", Groups: []string{"ops"}}}

	newSrv := func(capture *captureLocalSigner) *server {
		return &server{
			local: capture, hosts: hosts, callers: callers,
			audit: testAudit(t), freezes: signer.NewFreezeStore(),
			endUserVerifier: v, auditFailClosed: true,
		}
	}

	// A forged end_user is overwritten by the verified identity in the Intent.
	capture := &captureLocalSigner{}
	rec := httptest.NewRecorder()
	newSrv(capture).handleSign(rec, signRequestAs(t, "http-broker", signer.WireRequest{
		Host: "web", Role: signer.RoleTarget, Purpose: signer.PurposeOneshot,
		Command: "uptime", DryRun: true,
		EndUser: "forged-admin", BearerToken: o.token(t, "alice", []string{"ops"}),
	}))
	if rec.Code != http.StatusOK {
		t.Fatalf("dry-run status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if capture.got.EndUser != "alice" {
		t.Errorf("Intent.EndUser = %q, want the verified 'alice' — a compromised broker's forged end_user must not survive", capture.got.EndUser)
	}

	// A gated caller that forwards no token is denied before any issuance.
	capture2 := &captureLocalSigner{}
	rec2 := httptest.NewRecorder()
	newSrv(capture2).handleSign(rec2, signRequestAs(t, "http-broker", signer.WireRequest{
		Host: "web", Role: signer.RoleTarget, Purpose: signer.PurposeOneshot,
		Command: "uptime", DryRun: true, EndUser: "someone",
	}))
	if rec2.Code != http.StatusForbidden {
		t.Errorf("gated caller with no token → status %d, want 403 (body %s)", rec2.Code, rec2.Body.String())
	}
	if capture2.got.EndUser != "" {
		t.Error("SignIntent must not be reached when end-user verification fails closed")
	}
}
