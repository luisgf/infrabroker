package signer

import (
	"fmt"
	"regexp"
	"sync"
)

// Modos de CommandPolicy.
const (
	CmdPolicyOff       = "off"       // sin restricción de comando (también el valor vacío)
	CmdPolicyAllowlist = "allowlist" // el comando DEBE casar alguna regex de Allow
	CmdPolicyDenylist  = "denylist"  // el comando NO debe casar ninguna regex de Deny
)

// CommandPolicy restringe qué comandos pueden ejecutarse en un host. Es la base
// del "AI-action firewall": el signer la aplica de forma autoritativa para
// one-shot (el force-command horneado en el cert por la clave de CA es inevadible).
//
// Las reglas son expresiones regulares (RE2: tiempo lineal, sin backtracking
// catastrófico). Provienen de la config del operador (signer.json), de confianza.
//
// Debe ser copiable por valor (vive dentro de HostPolicy, que se copia en mapas):
// por eso la caché de regex compiladas es a nivel de paquete, no un campo.
type CommandPolicy struct {
	// Mode: "off" (o vacío) | "allowlist" | "denylist". Controla allow/deny.
	Mode string `json:"mode,omitempty"`
	// Allow: en modo allowlist, el comando debe casar al menos una.
	Allow []string `json:"allow,omitempty"`
	// Deny: en modo denylist, el comando no debe casar ninguna.
	Deny []string `json:"deny,omitempty"`
	// RequireApproval: comandos que casen requieren aprobación humana out-of-band.
	// Se evalúa con independencia del modo (lo orquesta el control plane).
	RequireApproval []string `json:"require_approval,omitempty"`
}

// Active indica si la política impone restricción de ejecución (allow/deny).
// Las reglas de require_approval por sí solas no cuentan como restricción de
// ejecución, pero sí impiden el uso de sesiones (ver Restricts).
func (cp CommandPolicy) Active() bool {
	return cp.Mode == CmdPolicyAllowlist || cp.Mode == CmdPolicyDenylist
}

// Restricts indica si el host tiene alguna regla de comando (allow/deny o
// aprobación). Si la tiene, las sesiones no son verificables (el comando no llega
// al firmante al firmar) y deben rechazarse.
func (cp CommandPolicy) Restricts() bool {
	return cp.Active() || len(cp.RequireApproval) > 0
}

// Decide evalúa command contra la política.
//   - allowed=false  → denegación autoritativa (el cert no debe emitirse).
//   - needsApproval  → el comando requiere aprobación humana.
//   - rule           → patrón/etiqueta que motivó la decisión (para auditoría).
//
// Devuelve error solo ante una regex inválida o un modo desconocido (fallo de
// configuración), no ante una denegación de política.
func (cp CommandPolicy) Decide(command string) (allowed bool, needsApproval bool, rule string, err error) {
	// require_approval se evalúa siempre, sea cual sea el modo.
	for _, p := range cp.RequireApproval {
		re, e := cachedRegex(p)
		if e != nil {
			return false, false, "", fmt.Errorf("regex require_approval inválida %q: %w", p, e)
		}
		if re.MatchString(command) {
			needsApproval = true
			rule = "require_approval:" + p
			break
		}
	}

	switch cp.Mode {
	case "", CmdPolicyOff:
		return true, needsApproval, rule, nil
	case CmdPolicyAllowlist:
		for _, p := range cp.Allow {
			re, e := cachedRegex(p)
			if e != nil {
				return false, false, "", fmt.Errorf("regex allow inválida %q: %w", p, e)
			}
			if re.MatchString(command) {
				if rule == "" {
					rule = "allow:" + p
				}
				return true, needsApproval, rule, nil
			}
		}
		return false, needsApproval, "allowlist:no-match", nil
	case CmdPolicyDenylist:
		for _, p := range cp.Deny {
			re, e := cachedRegex(p)
			if e != nil {
				return false, false, "", fmt.Errorf("regex deny inválida %q: %w", p, e)
			}
			if re.MatchString(command) {
				return false, needsApproval, "deny:" + p, nil
			}
		}
		return true, needsApproval, rule, nil
	default:
		return false, false, "", fmt.Errorf("modo de command_policy desconocido: %q", cp.Mode)
	}
}

// regexCache memoriza las regex compiladas por patrón (compartido entre signer y
// control plane). Las claves son patrones de confianza (config del operador).
var regexCache sync.Map // string → *regexp.Regexp | error

func cachedRegex(pattern string) (*regexp.Regexp, error) {
	if v, ok := regexCache.Load(pattern); ok {
		switch t := v.(type) {
		case *regexp.Regexp:
			return t, nil
		case error:
			return nil, t
		}
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		regexCache.Store(pattern, err)
		return nil, err
	}
	regexCache.Store(pattern, re)
	return re, nil
}
