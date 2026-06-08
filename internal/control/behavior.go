package control

import (
	"strings"
	"sync"
	"time"
)

// Modos de los guardrails de comportamiento.
const (
	BehaviorOff     = "off"     // desactivado (también el valor vacío)
	BehaviorObserve = "observe" // solo audita anomalías; no bloquea
	BehaviorEnforce = "enforce" // anomalías escalan a aprobación; rate excedido se deniega
)

// BehaviorConfig configura los guardrails de comportamiento por agente.
type BehaviorConfig struct {
	// Mode: "off"|"observe"|"enforce".
	Mode string `json:"mode,omitempty"`
	// RateLimitPerMin: máximo de peticiones por sujeto y minuto (0 = sin límite).
	RateLimitPerMin int `json:"rate_limit_per_min,omitempty"`
}

// BehaviorTracker detecta desviaciones del comportamiento normal de cada agente:
// picos de tasa, hosts nunca usados antes y comandos fuera del histórico. Es
// estadístico/basado en reglas (sin ML). El estado vive en memoria (se calienta
// en runtime); reiniciar el control plane reinicia la línea base.
type BehaviorTracker struct {
	mu       sync.Mutex
	cfg      BehaviorConfig
	subjects map[string]*subjectState
}

type subjectState struct {
	events []time.Time         // ventana deslizante de tiempos de petición (para tasa)
	hosts  map[string]struct{} // hosts vistos
	cmds   map[string]struct{} // fingerprints de comando vistos (primer token)
}

// NewBehaviorTracker crea un tracker con la configuración dada.
func NewBehaviorTracker(cfg BehaviorConfig) *BehaviorTracker {
	return &BehaviorTracker{cfg: cfg, subjects: make(map[string]*subjectState)}
}

// Enabled indica si los guardrails están activos (observe o enforce).
func (t *BehaviorTracker) Enabled() bool {
	return t.cfg.Mode == BehaviorObserve || t.cfg.Mode == BehaviorEnforce
}

// Enforcing indica si el modo es enforce (bloquea/escala en vez de solo auditar).
func (t *BehaviorTracker) Enforcing() bool { return t.cfg.Mode == BehaviorEnforce }

// Check registra una petición del sujeto (broker o usuario final) y devuelve las
// anomalías detectadas y si se ha superado el límite de tasa. La primera petición
// de un sujeto establece la línea base: no se marcan new-host/new-command (solo en
// peticiones posteriores con host/comando novedosos).
func (t *BehaviorTracker) Check(subject, host, command string) (anomalies []string, exceeded bool) {
	if !t.Enabled() {
		return nil, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	st, seen := t.subjects[subject]
	if !seen {
		st = &subjectState{hosts: map[string]struct{}{}, cmds: map[string]struct{}{}}
		t.subjects[subject] = st
	}
	now := time.Now()

	// Límite de tasa (ventana deslizante de 1 minuto). Se cuentan también los
	// intentos bloqueados para que no se pueda burlar el límite.
	if t.cfg.RateLimitPerMin > 0 {
		cutoff := now.Add(-time.Minute)
		kept := st.events[:0]
		for _, e := range st.events {
			if e.After(cutoff) {
				kept = append(kept, e)
			}
		}
		st.events = append(kept, now)
		if len(st.events) > t.cfg.RateLimitPerMin {
			exceeded = true
			anomalies = append(anomalies, "rate-exceeded")
		}
	}

	// Host/comando novedosos: solo tras establecer la línea base (sujeto ya visto).
	fp := firstToken(command)
	if seen {
		if _, ok := st.hosts[host]; !ok {
			anomalies = append(anomalies, "new-host:"+host)
		}
		if fp != "" {
			if _, ok := st.cmds[fp]; !ok {
				anomalies = append(anomalies, "new-command:"+fp)
			}
		}
	}
	st.hosts[host] = struct{}{}
	if fp != "" {
		st.cmds[fp] = struct{}{}
	}
	return anomalies, exceeded
}

// firstToken devuelve el primer token (el programa) de un comando, como
// fingerprint. P. ej. "systemctl restart nginx" → "systemctl".
func firstToken(command string) string {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}
