// Package oauth implementa la validación de tokens bearer OIDC para el frontend
// MCP sobre HTTP (cmd/mcp-broker-http). Delega en github.com/coreos/go-oidc, que
// descubre el issuer, descarga y cachea el JWKS (con rotación de claves) y valida
// firma, iss, aud y exp del JWT localmente, sin round-trip por petición.
package oauth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/modelcontextprotocol/go-sdk/auth"
)

// Config configura el verificador OIDC.
type Config struct {
	Issuer         string        // URL del proveedor OIDC (descubrimiento automático)
	Audience       string        // valor esperado del claim aud (este resource server)
	RequiredScopes []string      // scopes exigidos (los comprueba el middleware del SDK)
	UserClaim      string        // claim de identidad; default "sub"
	GroupsClaim    string        // claim de grupos/roles a propagar; opcional
	// MaxTokenAge es la antigüedad máxima aceptable del token desde su emisión
	// (claim iat). 0 = sin límite. Limitar a 1–2 horas reduce el riesgo de
	// replay de tokens filtrados dentro de su ventana exp (M3).
	MaxTokenAge time.Duration
}

// Verifier valida tokens y extrae la identidad y los grupos del usuario.
type Verifier struct {
	verifier    *oidc.IDTokenVerifier
	userClaim   string
	groupsClaim string
	maxTokenAge time.Duration // M3: 0 = sin límite
}

// ExtraGroupsKey es la clave bajo la que Verify guarda los grupos del usuario en
// TokenInfo.Extra, para que el frontend los propague al signer.
const ExtraGroupsKey = "groups"

// NewVerifier descubre el issuer y construye el verificador. La gestión del JWKS
// (descarga, cache y rotación) corre a cargo de go-oidc.
func NewVerifier(ctx context.Context, cfg Config) (*Verifier, error) {
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("oauth: issuer obligatorio")
	}
	if cfg.Audience == "" {
		return nil, fmt.Errorf("oauth: audience obligatorio")
	}
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oauth: descubrimiento OIDC: %w", err)
	}
	userClaim := cfg.UserClaim
	if userClaim == "" {
		userClaim = "sub"
	}
	return &Verifier{
		verifier:    provider.Verifier(&oidc.Config{ClientID: cfg.Audience}),
		userClaim:   userClaim,
		groupsClaim: cfg.GroupsClaim,
		maxTokenAge: cfg.MaxTokenAge,
	}, nil
}

// Verify implementa auth.TokenVerifier: valida el token y devuelve su TokenInfo.
// Los errores de validación se envuelven en auth.ErrInvalidToken para que el
// middleware responda 401.
func (v *Verifier) Verify(ctx context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
	idToken, err := v.verifier.Verify(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", auth.ErrInvalidToken, err)
	}

	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("%w: claims ilegibles: %v", auth.ErrInvalidToken, err)
	}

	ti := &auth.TokenInfo{
		Scopes:     scopesFromClaims(claims),
		Expiration: idToken.Expiry,
		UserID:     stringClaim(claims, v.userClaim),
	}
	if ti.UserID == "" {
		// Sin identidad utilizable no podemos auditar ni aplicar RBAC.
		return nil, fmt.Errorf("%w: claim de usuario %q ausente", auth.ErrInvalidToken, v.userClaim)
	}
	// M3: verificar antigüedad del token (iat) para limitar el riesgo de replay.
	if v.maxTokenAge > 0 {
		if iatRaw, ok := claims["iat"].(float64); ok {
			issuedAt := time.Unix(int64(iatRaw), 0)
			age := time.Since(issuedAt)
			if age > v.maxTokenAge {
				return nil, fmt.Errorf("%w: token demasiado antiguo (edad=%v, máximo=%v)",
					auth.ErrInvalidToken, age.Truncate(time.Second), v.maxTokenAge)
			}
		}
	}
	if v.groupsClaim != "" {
		if groups := stringSliceClaim(claims, v.groupsClaim); groups != nil {
			ti.Extra = map[string]any{ExtraGroupsKey: groups}
		}
	}
	return ti, nil
}

// scopesFromClaims extrae los scopes del claim "scope" (string separado por
// espacios, formato OAuth2) o "scp" (lista, usado por algunos proveedores).
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

// stringSliceClaim devuelve el claim name como []string. Acepta tanto un array
// JSON como un único string. Devuelve nil si el claim no existe.
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
