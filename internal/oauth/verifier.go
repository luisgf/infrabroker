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
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
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
	// ContextClaim names an optional claim whose string value travels with the
	// end-user identity as attribution context — the certificate KeyID (ctx=)
	// and the audit record (end_user_context) — so an action can be correlated
	// with the caller's execution context in another system, e.g. the
	// sandbox_id claim of an ASP workload token (docs/SANDBOX.md). It is
	// attribution only, never authorisation: a token without the claim, or with
	// a non-string value, is accepted and carries no context. Empty = off.
	ContextClaim string
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

// JWKS refresh throttle (#448). go-oidc's RemoteKeySet re-fetches the JWKS
// whenever a token does not verify against the cached keys — including a
// forged token that reuses the IdP's real kid — and only coalesces concurrent
// fetches, so every sequential unverifiable bearer would otherwise cost one
// HTTPS round trip to the IdP. The HTTP frontend mounts the bearer check
// before any rate limit, so an unauthenticated client could drive that rate.
// The throttle is a token bucket on outbound JWKS fetches: jwksRefreshBurst
// fetches are always available, then one more per jwksRefreshInterval. While
// exhausted, a token signed by an already-cached key still verifies locally
// (the cache is consulted first); only tokens that NEED a refresh fail, with
// auth.ErrInvalidToken, until a refresh token refills. A real key rotation is
// therefore delayed by at most jwksRefreshInterval under a flood.
const (
	jwksRefreshInterval = 10 * time.Second
	jwksRefreshBurst    = 5
)

// idpHTTPTimeout bounds every HTTP request go-oidc makes to the IdP: the
// discovery GET in NewVerifier and each later JWKS refresh (#583). go-oidc
// keeps the client installed by NewVerifier for the lifetime of the key set and
// ignores the per-call context for refreshes, and its RemoteKeySet coalesces
// concurrent refreshes behind ONE inflight fetch that is only cleared when the
// fetch returns. Without a timeout (http.DefaultTransport sets none on the
// response header), an IdP that accepts the TCP+TLS handshake and never answers
// would pin that inflight fetch forever: every token needing a refresh (a new
// kid after rotation) would hang, and no refresh could ever complete until the
// process restarted. A var so tests can shorten it.
var idpHTTPTimeout = 15 * time.Second

// errJWKSRefreshThrottled is what the throttled transport returns in place of
// an outbound fetch; go-oidc surfaces it as a verification failure.
var errJWKSRefreshThrottled = errors.New("oauth: JWKS refresh throttled (too many unverifiable tokens)")

// jwksThrottle is the http.RoundTripper behind the go-oidc HTTP client. Every
// request go-oidc makes through it (the one-off discovery GET at startup and
// each JWKS refresh) consumes one bucket token; a request that finds the
// bucket empty fails locally without touching the network.
type jwksThrottle struct {
	next http.RoundTripper

	mu     sync.Mutex
	tokens float64
	last   time.Time
	now    func() time.Time // test seam, read under mu
}

func newJWKSThrottle(next http.RoundTripper) *jwksThrottle {
	t := &jwksThrottle{next: next, tokens: jwksRefreshBurst, now: time.Now}
	t.last = t.now()
	return t
}

// allow consumes one token when available (continuous refill of one token
// per jwksRefreshInterval up to jwksRefreshBurst).
func (t *jwksThrottle) allow() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	t.tokens += now.Sub(t.last).Seconds() / jwksRefreshInterval.Seconds()
	if t.tokens > jwksRefreshBurst {
		t.tokens = jwksRefreshBurst
	}
	t.last = now
	if t.tokens < 1 {
		return false
	}
	t.tokens--
	return true
}

// RoundTrip implements http.RoundTripper.
func (t *jwksThrottle) RoundTrip(req *http.Request) (*http.Response, error) {
	if !t.allow() {
		return nil, errJWKSRefreshThrottled
	}
	return t.next.RoundTrip(req)
}

// Verifier validates tokens and extracts the user identity and groups.
type Verifier struct {
	verifier     *oidc.IDTokenVerifier
	jwks         *jwksThrottle // bounds outbound JWKS refreshes (#448)
	userClaim    string
	groupsClaim  string
	contextClaim string        // attribution context claim; "" = off
	maxTokenAge  time.Duration // M3: 0 = no limit
	clockSkew    time.Duration // tolerance for nbf/iat (<0 = none)
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

// ExtraContextKey is the key under which Verify stores the value of the
// configured ContextClaim in TokenInfo.Extra (absent when the claim is not
// configured or the token does not carry it as a string).
const ExtraContextKey = "context"

// EndUserIdentity is what the signer derives from a verified end-user token
// (#143): the identity, the RBAC groups under the nil-vs-empty contract, and
// the attribution context ("" when no ContextClaim is configured or present).
type EndUserIdentity struct {
	UserID  string
	Groups  []string
	Context string
}

// NewVerifier discovers the issuer and constructs the verifier. JWKS management
// (download, cache, and rotation) is handled by go-oidc.
func NewVerifier(ctx context.Context, cfg Config) (*Verifier, error) {
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("oauth: issuer is required")
	}
	if cfg.Audience == "" {
		return nil, fmt.Errorf("oauth: audience is required")
	}
	// go-oidc takes its HTTP client from the context and keeps it for the
	// lifetime of the key set (cancellation is ignored), so the throttled
	// transport installed here bounds every later JWKS refresh (#448) and the
	// client timeout bounds how long any discovery or refresh request may
	// hang on an unresponsive IdP (#583).
	throttle := newJWKSThrottle(http.DefaultTransport)
	ctx = oidc.ClientContext(ctx, &http.Client{Transport: throttle, Timeout: idpHTTPTimeout})
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
		jwks:           throttle,
		userClaim:      userClaim,
		groupsClaim:    cfg.GroupsClaim,
		contextClaim:   cfg.ContextClaim,
		maxTokenAge:    cfg.MaxTokenAge,
		clockSkew:      skew,
		requiredScopes: cfg.RequiredScopes,
	}, nil
}

// ContextClaim reports the configured attribution-context claim name ("" when
// none), so a consumer can tell "the token carried no context" from "this
// verifier never derives one".
func (v *Verifier) ContextClaim() string { return v.contextClaim }

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
	// Attribution context (e.g. an ASP sandbox_id): carried when present, never
	// required — it labels the action, it does not authorise it.
	if v.contextClaim != "" {
		if c := stringClaim(claims, v.contextClaim); c != "" {
			ti.Extra[ExtraContextKey] = c
		}
	}
	return ti, nil
}

// VerifyEndUser validates the token and returns the end-user identity, the
// groups and the attribution context derived from it, for signer-side
// re-validation (#143). It keeps the go-sdk auth.TokenInfo type out of callers
// that only need the derived identity (the signer). Groups is nil when no groups
// claim is configured (per-user RBAC is not derived from the token); a non-nil
// empty slice when the claim is present but empty (deny every host), preserving
// the nil-vs-empty contract the signer relies on. Context is "" when no
// ContextClaim is configured or the token does not carry it.
func (v *Verifier) VerifyEndUser(ctx context.Context, token string) (EndUserIdentity, error) {
	ti, err := v.Verify(ctx, token, nil)
	if err != nil {
		return EndUserIdentity{}, err
	}
	// Enforce required scopes here: Verify only populates ti.Scopes, and the
	// go-sdk middleware that checks them wraps the HTTP frontend only. Without
	// this, end_user_oidc.required_scopes would be a silent no-op on the signer,
	// making its re-validation weaker than the frontend's original check (#143).
	for _, want := range v.requiredScopes {
		if !slices.Contains(ti.Scopes, want) {
			return EndUserIdentity{}, fmt.Errorf("token missing required scope %q", want)
		}
	}
	id := EndUserIdentity{UserID: ti.UserID}
	if ti.Extra != nil {
		if g, ok := ti.Extra[ExtraGroupsKey].([]string); ok {
			id.Groups = g
		}
		if c, ok := ti.Extra[ExtraContextKey].(string); ok {
			id.Context = c
		}
	}
	return id, nil
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
