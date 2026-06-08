package control

import (
	"testing"
)

func containsPrefix(ss []string, prefix string) bool {
	for _, s := range ss {
		if len(s) >= len(prefix) && s[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

func TestBehaviorDisabled(t *testing.T) {
	tr := NewBehaviorTracker(BehaviorConfig{Mode: BehaviorOff})
	if tr.Enabled() {
		t.Error("off no debe estar habilitado")
	}
	an, ex := tr.Check("s", "h", "cmd")
	if an != nil || ex {
		t.Error("off no debe detectar nada")
	}
}

func TestBehaviorBaselineNoAnomalyFirstRequest(t *testing.T) {
	tr := NewBehaviorTracker(BehaviorConfig{Mode: BehaviorObserve})
	an, _ := tr.Check("alice", "web01", "uptime")
	if len(an) != 0 {
		t.Errorf("la primera petición establece línea base, sin anomalías: %v", an)
	}
}

func TestBehaviorNewHostAndCommand(t *testing.T) {
	tr := NewBehaviorTracker(BehaviorConfig{Mode: BehaviorObserve})
	tr.Check("alice", "web01", "uptime") // línea base
	an, _ := tr.Check("alice", "db01", "psql")
	if !containsPrefix(an, "new-host:") {
		t.Errorf("debe detectar host nuevo: %v", an)
	}
	if !containsPrefix(an, "new-command:") {
		t.Errorf("debe detectar comando nuevo: %v", an)
	}
	// Repetir el mismo host/comando ya no es anomalía.
	an2, _ := tr.Check("alice", "db01", "psql -l")
	if containsPrefix(an2, "new-host:") {
		t.Errorf("host ya visto no debe ser anomalía: %v", an2)
	}
	// "psql" ya visto como fingerprint (primer token).
	if containsPrefix(an2, "new-command:") {
		t.Errorf("comando con fingerprint ya visto no debe ser anomalía: %v", an2)
	}
}

func TestBehaviorPerSubjectIsolation(t *testing.T) {
	tr := NewBehaviorTracker(BehaviorConfig{Mode: BehaviorObserve})
	tr.Check("alice", "web01", "uptime")
	// bob es un sujeto distinto: su primera petición es línea base, sin anomalía.
	an, _ := tr.Check("bob", "web01", "uptime")
	if len(an) != 0 {
		t.Errorf("otro sujeto parte de cero: %v", an)
	}
}

func TestBehaviorRateLimit(t *testing.T) {
	tr := NewBehaviorTracker(BehaviorConfig{Mode: BehaviorEnforce, RateLimitPerMin: 3})
	var lastExceeded bool
	for i := 0; i < 4; i++ {
		_, ex := tr.Check("alice", "web01", "uptime")
		lastExceeded = ex
	}
	if !lastExceeded {
		t.Error("la 4ª petición debe superar el límite de 3/min")
	}
}

func TestBehaviorModeFlags(t *testing.T) {
	obs := NewBehaviorTracker(BehaviorConfig{Mode: BehaviorObserve})
	if !obs.Enabled() || obs.Enforcing() {
		t.Error("observe: enabled, no enforcing")
	}
	enf := NewBehaviorTracker(BehaviorConfig{Mode: BehaviorEnforce})
	if !enf.Enabled() || !enf.Enforcing() {
		t.Error("enforce: enabled y enforcing")
	}
}

func TestFirstToken(t *testing.T) {
	cases := map[string]string{
		"systemctl restart nginx": "systemctl",
		"  uptime  ":              "uptime",
		"":                        "",
		"ls -la /tmp":             "ls",
	}
	for in, want := range cases {
		if got := firstToken(in); got != want {
			t.Errorf("firstToken(%q) = %q, quiero %q", in, got, want)
		}
	}
}
