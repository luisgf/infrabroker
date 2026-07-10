package confcheck

import "testing"

type sample struct {
	Name    string              `json:"name"`
	Callers []string            `json:"sign_callers"`
	Keys    map[string]string   `json:"ca_keys"`
	Groups  map[string][]string `json:"group_command_policies"`
}

func TestStrict(t *testing.T) {
	t.Parallel()

	// Comments stripped, the reserved "_default" map key preserved, known fields loaded.
	good := []byte(`{
		"_comment": "documentation",
		"name": "cp",
		"sign_callers": ["broker-1"],
		"ca_keys": {"_default": "k1", "prod": "k2"},
		"group_command_policies": {"_default": ["base"], "prod": ["ro"]}
	}`)
	var s sample
	if err := Strict(good, &s); err != nil {
		t.Fatalf("a valid config with comments + _default must load: %v", err)
	}
	if s.Callers == nil || len(s.Callers) != 1 {
		t.Errorf("sign_callers must be loaded: %v", s.Callers)
	}
	if s.Keys["_default"] != "k1" || len(s.Keys) != 2 {
		t.Errorf("the reserved _default map key must survive: %v", s.Keys)
	}
	if len(s.Groups["_default"]) != 1 {
		t.Errorf("_default group policies must survive: %v", s.Groups)
	}

	// A typo in a security control fails closed instead of being silently ignored.
	var s2 sample
	if err := Strict([]byte(`{"sign_caller": ["broker-1"]}`), &s2); err == nil {
		t.Error("a typo'd field (sign_caller) must be rejected at load")
	}

	// Regression: a MAP key that legitimately begins with "_" (e.g. a broker CN
	// "_ci" listed in callers) is real configuration and must NOT be stripped like
	// a comment — dropping it would make that CN fall back to default-open.
	var s3 struct {
		Callers map[string][]string `json:"callers"`
	}
	if err := Strict([]byte(`{"callers": {"_ci": ["prod"], "web-1": ["prod"]}}`), &s3); err != nil {
		t.Fatalf("a config with a _-prefixed caller CN must load: %v", err)
	}
	if _, ok := s3.Callers["_ci"]; !ok || len(s3.Callers) != 2 {
		t.Errorf("a _-prefixed map key must be preserved, not stripped: %v", s3.Callers)
	}

	// A typo nested INSIDE a _-prefixed map entry must still be caught: stripping
	// only comment keys means such entries reach the strict validation pass.
	var s4 struct {
		Hosts map[string]struct {
			Groups []string `json:"groups"`
		} `json:"hosts"`
	}
	if err := Strict([]byte(`{"hosts": {"_x": {"groops": ["a"]}}}`), &s4); err == nil {
		t.Error("a typo (groops) nested in a _-prefixed host entry must be rejected")
	}
	// A comment key keeps being stripped (so it never trips the strict pass).
	if err := Strict([]byte(`{"_hosts_comment": "doc", "hosts": {"web": {"groups": ["a"]}}}`), &s4); err != nil {
		t.Errorf("a _*_comment key must still be stripped: %v", err)
	}

	// An ad-hoc scalar "_note" inside an object is an inline comment and must be
	// stripped (not rejected as an unknown field) — the project uses this pattern.
	var s5 struct {
		Hosts map[string]struct {
			Principal string `json:"principal"`
		} `json:"hosts"`
	}
	if err := Strict([]byte(`{"hosts": {"db01": {"principal": "host:db01", "_note": "keep me"}}}`), &s5); err != nil {
		t.Errorf("an inline scalar _note must be treated as a comment: %v", err)
	}
}

func TestStrictAcceptsJSONC(t *testing.T) {
	t.Parallel()

	// // and /* */ comments plus a trailing comma load like plain JSON, and a
	// legacy _comment key keeps working alongside a real // comment.
	jsonc := []byte(`{
		// the canonical comment style now
		"_comment": "legacy comment key still accepted",
		"name": "cp",            // trailing line comment
		"sign_callers": ["a"],   /* block comment */
		"ca_keys": {"_default": "k"},
	}`)
	var s sample
	if err := Strict(jsonc, &s); err != nil {
		t.Fatalf("JSONC (comments + trailing comma) must load: %v", err)
	}
	if s.Name != "cp" || len(s.Callers) != 1 || s.Keys["_default"] != "k" {
		t.Errorf("JSONC values must decode correctly: %+v", s)
	}

	// A typo is still caught even with comments present (fail-closed unchanged).
	if err := Strict([]byte(`{ // note
		"sign_caller": ["a"] }`), &sample{}); err == nil {
		t.Error("a typo'd field must still be rejected through the JSONC path")
	}

	// Plain JSON is unchanged (idempotent standardize).
	std, err := Standardize([]byte(`{"name":"x"}`))
	if err != nil || string(std) != `{"name":"x"}` {
		t.Errorf("plain JSON must pass through unchanged: %q %v", std, err)
	}

	// Malformed input fails closed with a parse error.
	if _, err := Standardize([]byte(`{"name": }`)); err == nil {
		t.Error("malformed JSONC must fail closed")
	}
}
