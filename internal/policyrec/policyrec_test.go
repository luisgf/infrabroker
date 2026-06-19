package policyrec

import (
	"testing"
	"time"

	"github.com/luisgf/ssh-broker/internal/audit"
	"github.com/luisgf/ssh-broker/internal/signer"
)

func testPolicy(t *testing.T) signer.PolicyTable {
	t.Helper()
	hosts := signer.PolicyTable{
		"web01": {Principal: "host:web01", CommandPolicy: signer.CommandPolicy{
			Mode: signer.CmdPolicyAllowlist, Allow: []string{"^uptime$", "^journalctl "},
		}},
		"db01": {Principal: "host:db01"}, // no command policy (unrestricted)
	}
	compiled, err := signer.CompileHostPolicies(hosts, nil, nil)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return compiled
}

func entry(host, cmd, outcome, caller string, ts time.Time) audit.Entry {
	return audit.Entry{Host: host, Command: cmd, Outcome: outcome, Caller: caller, Time: ts}
}

func find(t *testing.T, sugs []Suggestion, typ SuggestionType, host, pattern string) *Suggestion {
	t.Helper()
	for i := range sugs {
		s := &sugs[i]
		if s.Type == typ && s.Host == host && s.Pattern == pattern {
			return s
		}
	}
	return nil
}

func TestRecommendBuckets(t *testing.T) {
	t.Parallel()
	compiled := testPolicy(t)
	now := time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC)
	var es []audit.Entry
	// uptime: allowed (uses ^uptime$ -> not dead)
	es = append(es, entry("web01", "uptime", "executed", "a", now))
	es = append(es, entry("web01", "uptime", "executed", "b", now))
	// systemctl restart nginx: human-approved 5x but not in allowlist -> PROMOTE
	for i := 0; i < 5; i++ {
		es = append(es, entry("web01", "systemctl restart nginx", "approval-granted", "a", now))
	}
	// rm -rf: denied 2x -> FRICTION
	es = append(es, entry("web01", "rm -rf /tmp/x", "denied", "a", now))
	es = append(es, entry("web01", "rm -rf /tmp/x", "denied", "b", now))
	// db01 unrestricted: no suggestion
	es = append(es, entry("db01", "ls -la", "executed", "a", now))

	sugs := Recommend(es, compiled, Options{})

	if p := find(t, sugs, Promote, "web01", "^systemctl restart nginx$"); p == nil {
		t.Fatalf("missing promote suggestion; got %+v", sugs)
	} else if p.Count != 5 || p.Approved != 5 || p.Callers != 1 {
		t.Errorf("promote evidence wrong: count=%d approved=%d callers=%d", p.Count, p.Approved, p.Callers)
	}
	if f := find(t, sugs, Friction, "web01", "rm -rf /tmp/x"); f == nil || f.Count != 2 {
		t.Errorf("friction suggestion wrong: %+v", f)
	}
	if d := find(t, sugs, DeadRule, "web01", "^journalctl "); d == nil {
		t.Error("^journalctl never matched -> should be flagged dead")
	}
	if d := find(t, sugs, DeadRule, "web01", "^uptime$"); d != nil {
		t.Error("^uptime$ matched real commands -> must NOT be flagged dead")
	}
	for _, s := range sugs {
		if s.Host == "db01" {
			t.Errorf("unrestricted host should yield no suggestions: %+v", s)
		}
	}
}

func TestRecommendMinCountAndHostFilter(t *testing.T) {
	t.Parallel()
	compiled := testPolicy(t)
	now := time.Now().UTC()
	es := []audit.Entry{
		entry("web01", "systemctl restart nginx", "executed", "a", now), // count 1
		entry("db01", "whoami", "executed", "a", now),
	}
	// min-count 2 suppresses the single-occurrence promote
	if sugs := Recommend(es, compiled, Options{MinCount: 2}); find(t, sugs, Promote, "web01", "^systemctl restart nginx$") != nil {
		t.Error("min-count=2 should suppress a 1-occurrence promote")
	}
	// host filter: restrict to db01 -> no web01 dead-rule suggestions leak
	for _, s := range Recommend(es, compiled, Options{Host: "db01"}) {
		if s.Host != "db01" {
			t.Errorf("host filter leaked: %+v", s)
		}
	}
}

func TestRecommendSinceFilter(t *testing.T) {
	t.Parallel()
	compiled := testPolicy(t)
	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	recent := time.Date(2026, 6, 19, 0, 0, 0, 0, time.UTC)
	es := []audit.Entry{
		entry("web01", "systemctl restart nginx", "executed", "a", old),
		entry("web01", "systemctl restart nginx", "executed", "a", recent),
	}
	sugs := Recommend(es, compiled, Options{Since: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)})
	if p := find(t, sugs, Promote, "web01", "^systemctl restart nginx$"); p == nil || p.Count != 1 {
		t.Errorf("since filter should keep only the recent entry: %+v", p)
	}
}
