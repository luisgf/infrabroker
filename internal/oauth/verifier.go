// Package oauth implements bearer OIDC token validation for the HTTP MCP
// frontend (cmd/mcp-broker-http). It delegates to github.com/coreos/go-oidc,
// which discovers the issuer, downloads and caches the JWKS (with key
// rotation), and validates the JWT signature, iss, aud, exp and nbf locally —
// no round-trip per request. go-oidc enforces nbf only with a hardcoded
// 5-minute leeway, so this package re-checks nbf under the operator-configured
// (typically stricter) clock-skew tolerance, and additionally enforces the iat
// age bound.
package oauth

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/modelcontextprotocol/go-sdk/auth"
)

// Config configures the OIDC verifier.
type Config struct {
	Issuer         string   // OIDC provider URL (auto-discovery)
	Audience       string   // expected value of the aud claim (this resource server)
	RequiredScopes []string // required scopes (checked by the SDK middleware)
	UserClaim      string   // identity claim; default "sub"
	// GroupsClaim is the groups/roles claim to propagate for per-user RBAC.
	// Optional; but when set, validation is fail-closed: a token WITHOUT the
	// claim is rejected. Accepting it would silently disable the per-user
	// filter in the signer (nil groups = unrestricted), e.g. on a claim-name
	// typo or an IdP that stops emitting the claim.
	GroupsClaim string
	// MaxTokenAge is the maximum acceptable age of the token since issuance
	// (iat claim). 0 = no limit. Limiting to 1–2 hours reduces the replay risk
	// of leaked tokens within their exp window (M3). Fail-closed: when set,
	// tokens without a numeric iat claim are rejected (their age cannot be
	// established).
	MaxTokenAge time.Duration
	// ClockSkew is the tolerance applied to the time-based claims (nbf, and the
	// iat lower/upper bounds) to absorb small clock differences between the IdP
	// and this host. 0 selects defaultClockSkew; a negative value disables the
	// tolerance. Without it, a token issued a second into the future (or whose
	// nbf has not quite arrived) would be rejected with a spurious 401.
	ClockSkew time.Duration
}

// defaultClockSkew is the tolerance used when Config.ClockSkew is 0.
const defaultClockSkew = 1 * time.Minute

// Verifier validates tokens and extracts the user identity and groups.
type Verifier struct {
	verifier    *oidc.IDTokenVerifier
	userClaim   string
	groupsClaim string
	maxTokenAge time.Duration // M3: 0 = no limit
	clockSkew   time.Duration // tolerance for nbf/iat (<0 = none)
	// requiredScopes is enforced by VerifyEndUser (the signer path), NOT by
	// Verify: the HTTP frontend delegates scope checks to the go-sdk middleware
	// (auth.RequireBearerToken), but the signer has no such middleware, so
	// end_user_oidc.required_scopes would be inert there without this (#143).
	requiredScopes []string
}

// ExtraGroupsKey is the key under which Verify stores the user's groups in
// TokenInfo.Extra, so the frontend can propagate them to the signer.
const ExtraGroupsKey = "groups"

// ExtraRawTokenKey is the key under which Verify stores the raw bearer token in
// TokenInfo.Extra, so the HTTP frontend can forward it to the signer for
// signer-side re-validation of the end-user identity (#143). In-process only;
// the value is a secret and must never be logged or persisted.
const ExtraRawTokenKey = "raw_token"

// NewVerifier discovers the issuer and constructs the verifier. JWKS management
// (download, cache, and rotation) is handled by go-oidc.
func NewVerifier(ctx context.Context, cfg Config) (*Verifier, error) {
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("oauth: issuer is required")
	}
	if cfg.Audience == "" {
		return nil, fmt.Errorf("oauth: audience is required")
	}
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oauth: OIDC discovery: %w", err)
	}
	userClaim := cfg.UserClaim
	if userClaim == "" {
		userClaim = "sub"
	}
	skew := cfg.ClockSkew
	if skew == 0 {
		skew = defaultClockSkew
	}
	if skew < 0 {
		skew = 0
	}
	return &Verifier{
		verifier:       provider.Verifier(&oidc.Config{ClientID: cfg.Audience}),
		userClaim:      userClaim,
		groupsClaim:    cfg.GroupsClaim,
		maxTokenAge:    cfg.MaxTokenAge,
		clockSkew:      skew,
		requiredScopes: cfg.RequiredScopes,
	}, nil
}

// Verify implements auth.TokenVerifier: validates the token and returns its
// TokenInfo. Validation errors are wrapped in auth.ErrInvalidToken so the
// middleware responds with 401.
func (v *Verifier) Verify(ctx context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
	idToken, err := v.verifier.Verify(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", auth.ErrInvalidToken, err)
	}

	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("%w: unreadable claims: %v", auth.ErrInvalidToken, err)
	}

	ti := &auth.TokenInfo{
		Scopes:     scopesFromClaims(claims),
		Expiration: idToken.Expiry,
		UserID:     stringClaim(claims, v.userClaim),
	}
	if ti.UserID == "" {
		// Without a usable identity we cannot audit or apply RBAC.
		return nil, fmt.Errorf("%w: user claim %q absent", auth.ErrInvalidToken, v.userClaim)
	}
	now := time.Now()
	// nbf (not before): go-oidc already rejects a token whose nbf is in the
	// future, but only with a hardcoded 5-minute leeway. Re-check it here under
	// the operator-configured clockSkew (default 1 minute), which is typically
	// tighter, so a token valid only from a future instant is rejected sooner.
	if nbfRaw, ok := claims["nbf"].(float64); ok {
		notBefore := time.Unix(int64(nbfRaw), 0)
		if now.Add(v.clockSkew).Before(notBefore) {
			return nil, fmt.Errorf("%w: token not valid yet (nbf=%v)",
				auth.ErrInvalidToken, notBefore.UTC().Format(time.RFC3339))
		}
	}
	// M3: verify token age (iat) to limit the replay risk. Fail-closed: with an
	// age limit in force, a token whose age cannot be established (missing or
	// non-numeric iat) is rejected rather than silently exempted.
	if v.maxTokenAge > 0 {
		iatRaw, ok := claims["iat"].(float64)
		if !ok {
			return nil, fmt.Errorf("%w: iat claim absent or not numeric (required when max token age is enforced)",
				auth.ErrInvalidToken)
		}
		issuedAt := time.Unix(int64(iatRaw), 0)
		// Reject tokens issued in the future beyond the skew (clock problem or a
		// forged iat), which would otherwise read as a negative age and slip
		// under the max-age bound.
		if issuedAt.After(now.Add(v.clockSkew)) {
			return nil, fmt.Errorf("%w: token issued in the future (iat=%v)",
				auth.ErrInvalidToken, issuedAt.UTC().Format(time.RFC3339))
		}
		age := now.Sub(issuedAt)
		if age > v.maxTokenAge+v.clockSkew {
			return nil, fmt.Errorf("%w: token too old (age=%v, max=%v)",
				auth.ErrInvalidToken, age.Truncate(time.Second), v.maxTokenAge)
		}
	}
	// Groups: with a groups claim configured, per-user RBAC is in force, so a
	// token without the claim is rejected (fail-closed) instead of silently
	// bypassing the signer's per-user filter. An empty list is propagated
	// as-is (the signer then denies every host for that user).
	if v.groupsClaim != "" {
		groups := stringSliceClaim(claims, v.groupsClaim)
		if groups == nil {
			return nil, fmt.Errorf("%w: groups claim %q absent", auth.ErrInvalidToken, v.groupsClaim)
		}
		ti.Extra = map[string]any{ExtraGroupsKey: groups}
	}
	// Retain the raw token so the HTTP frontend can forward it to the signer for
	// signer-side re-validation of the end-user identity (#143). In-process only:
	// it is never logged or persisted from here, and TokenInfo lives only in the
	// request context.
	if ti.Extra == nil {
		ti.Extra = map[string]any{}
	}
	ti.Extra[ExtraRawTokenKey] = token
	return ti, nil
}

// VerifyEndUser validates the token and returns the end-user identity and the
// groups derived from it, for signer-side re-validation (#143). It keeps the
// go-sdk auth.TokenInfo type out of callers that only need the derived identity
// (the signer). groups is nil when no groups claim is configured (per-user RBAC
// is not derived from the token); a non-nil empty slice when the claim is
// present but empty (deny every host), preserving the nil-vs-empty contract the
// signer relies on.
func (v *Verifier) VerifyEndUser(ctx context.Context, token string) (userID string, groups []string, err error) {
	ti, err := v.Verify(ctx, token, nil)
	if err != nil {
		return "", nil, err
	}
	// Enforce required scopes here: Verify only populates ti.Scopes, and the
	// go-sdk middleware that checks them wraps the HTTP frontend only. Without
	// this, end_user_oidc.required_scopes would be a silent no-op on the signer,
	// making its re-validation weaker than the frontend's original check (#143).
	for _, want := range v.requiredScopes {
		if !slices.Contains(ti.Scopes, want) {
			return "", nil, fmt.Errorf("token missing required scope %q", want)
		}
	}
	if ti.Extra != nil {
		if g, ok := ti.Extra[ExtraGroupsKey].([]string); ok {
			groups = g
		}
	}
	return ti.UserID, groups, nil
}

// scopesFromClaims extracts scopes from the "scope" claim (space-separated
// string, OAuth2 format) or "scp" (list, used by some providers).
func scopesFromClaims(claims map[string]any) []string {
	if s, ok := claims["scope"].(string); ok && s != "" {
		return strings.Fields(s)
	}
	return stringSliceClaim(claims, "scp")
}

func stringClaim(claims map[string]any, name string) string {
	if v, ok := claims[name].(string); ok {
		return v
	}
	return ""
}

// stringSliceClaim returns claim name as []string. Accepts both a JSON array
// and a single string. Returns nil if the claim does not exist.
func stringSliceClaim(claims map[string]any, name string) []string {
	switch v := claims[name].(type) {
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	default:
		return nil
	}
}
