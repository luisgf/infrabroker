package control

import (
	"fmt"
	"testing"
	"time"
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
	t.Parallel()
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
	t.Parallel()
	tr := NewBehaviorTracker(BehaviorConfig{Mode: BehaviorObserve})
	an, _ := tr.Check("alice", "web01", "uptime")
	if len(an) != 0 {
		t.Errorf("la primera petición establece línea base, sin anomalías: %v", an)
	}
}

func TestBehaviorNewHostAndCommand(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
	tr := NewBehaviorTracker(BehaviorConfig{Mode: BehaviorObserve})
	tr.Check("alice", "web01", "uptime")
	// bob es un sujeto distinto: su primera petición es línea base, sin anomalía.
	an, _ := tr.Check("bob", "web01", "uptime")
	if len(an) != 0 {
		t.Errorf("otro sujeto parte de cero: %v", an)
	}
}

func TestBehaviorRateLimit(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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

// TestBehaviorSubjectTableCapped verifies the subject table never exceeds
// MaxSubjects: a flood of distinct subjects evicts the least-recently-seen one
// instead of growing without bound.
func TestBehaviorSubjectTableCapped(t *testing.T) {
	t.Parallel()
	tr := NewBehaviorTracker(BehaviorConfig{Mode: BehaviorObserve, MaxSubjects: 3})
	for i := 0; i < 100; i++ {
		tr.Check(fmt.Sprintf("subject-%d", i), "web01", "uptime")
	}
	tr.mu.Lock()
	n := len(tr.subjects)
	tr.mu.Unlock()
	if n > 3 {
		t.Errorf("subject table = %d entries, want <= 3 (cap enforced)", n)
	}
}

// TestBehaviorEvictsIdleSubjects verifies idle subjects past the TTL are pruned
// when a new subject arrives at capacity.
func TestBehaviorEvictsIdleSubjects(t *testing.T) {
	t.Parallel()
	tr := NewBehaviorTracker(BehaviorConfig{Mode: BehaviorObserve, MaxSubjects: 2, SubjectTTLMinutes: 1})
	tr.Check("old", "web01", "uptime")
	// Backdate "old" past the TTL.
	tr.mu.Lock()
	tr.subjects["old"].lastSeen = time.Now().Add(-2 * time.Minute)
	tr.mu.Unlock()
	// Fill to cap, then add a third: eviction must run and drop the idle "old".
	tr.Check("b", "web01", "uptime")
	tr.Check("c", "web01", "uptime")
	tr.mu.Lock()
	_, oldStillThere := tr.subjects["old"]
	n := len(tr.subjects)
	tr.mu.Unlock()
	if oldStillThere {
		t.Error("idle subject past TTL should have been evicted")
	}
	if n > 2 {
		t.Errorf("subject table = %d entries, want <= 2", n)
	}
}

// TestBehaviorPerSubjectCardinalityCap verifies a subject's host set cannot grow
// past the cap, and that once full, novelty for that dimension degrades to
// "seen" (no flag) instead of growing the map.
func TestBehaviorPerSubjectCardinalityCap(t *testing.T) {
	t.Parallel()
	tr := NewBehaviorTracker(BehaviorConfig{Mode: BehaviorObserve, MaxDistinctPerSubject: 2})
	tr.Check("alice", "h0", "uptime") // baseline
	tr.Check("alice", "h1", "uptime") // fills hosts set to {h0,h1} (cap 2)
	// hosts set is now full; a genuinely-new host must not be flagged nor stored.
	an, _ := tr.Check("alice", "h2", "uptime")
	if containsPrefix(an, "new-host:") {
		t.Errorf("host novelty must degrade to 'seen' once the set is full: %v", an)
	}
	tr.mu.Lock()
	n := len(tr.subjects["alice"].hosts)
	tr.mu.Unlock()
	if n > 2 {
		t.Errorf("hosts set = %d entries, want <= 2 (cap enforced)", n)
	}
}
