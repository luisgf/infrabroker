package confcheck

import (
	"strings"
	"testing"
)

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

func TestStandardizeRejectsDuplicateKeys(t *testing.T) {
	t.Parallel()

	// encoding/json silently keeps the last value for a repeated key while hujson's
	// Patch resolver targets the first; a duplicate key must fail closed so the two
	// parsers can never disagree on a security config.
	dupes := map[string]string{
		"top-level":                   `{"name": "a", "name": "b"}`,
		"nested security key":         `{"hosts": {"web": {"principal": "host:web", "principal": "host:evil"}}}`,
		"duplicate command_policy":    `{"hosts": {"web": {"command_policy": {"mode": "allowlist", "allow": []}, "command_policy": {"mode": "allowlist", "allow": ["^rm -rf /$"]}}}}`,
		"inside an array element":     `{"hosts": {"web": {"principals": [{"p": 1, "p": 2}]}}}`,
		"duplicate with a // comment": "{\n // note\n \"a\": 1,\n \"a\": 2\n}",
	}
	for name, cfg := range dupes {
		if _, err := Standardize([]byte(cfg)); err == nil {
			t.Errorf("%s: a duplicate key must be rejected: %s", name, cfg)
		}
	}

	// No false positives: the reserved "_default" data key appearing in two
	// DIFFERENT objects is not a duplicate, and comment keys alongside real keys
	// load fine.
	ok := []string{
		`{"ca_keys": {"_default": "k1", "prod": "k2"}, "group_command_policies": {"_default": ["base"]}}`,
		`{"_comment": "doc", "hosts": {"web": {"groups": ["a"]}, "db": {"groups": ["b"]}}}`,
	}
	for _, cfg := range ok {
		if _, err := Standardize([]byte(cfg)); err != nil {
			t.Errorf("a duplicate-free config must pass: %s: %v", cfg, err)
		}
	}
}

func TestStandardizeRejectsCaseVariantDuplicateKeys(t *testing.T) {
	t.Parallel()

	// encoding/json matches keys case-insensitively (last wins) and
	// DisallowUnknownFields accepts the variant spelling, while a hujson Patch
	// resolves the exact-name member: a case-variant duplicate reproduces the
	// #216 silent divergence, so it must fail closed too (#661).
	dupes := map[string]string{
		"top-level":       `{"sign_callers": ["broker-a"], "Sign_Callers": ["broker-b"]}`,
		"top-level rev":   `{"Sign_Callers": ["broker-b"], "sign_callers": ["broker-a"]}`,
		"nested object":   `{"hosts": {"web": {"principal": "host:web", "Principal": "host:evil"}}}`,
		"inside an array": `{"hosts": {"web": {"principals": [{"p": 1, "P": 2}]}}}`,
	}
	for name, cfg := range dupes {
		_, err := Standardize([]byte(cfg))
		if err == nil {
			t.Errorf("%s: a case-variant duplicate key must be rejected: %s", name, cfg)
			continue
		}
		if !strings.Contains(err.Error(), "case-insensitive match") {
			t.Errorf("%s: error should name the case-insensitive match, got %v", name, err)
		}
	}

	var s sample
	if err := Strict([]byte(`{"sign_callers": ["broker-a"], "Sign_Callers": ["broker-b"]}`), &s); err == nil {
		t.Error("Strict must reject a case-variant duplicate sign_callers key")
	}
	if _, err := Patch([]byte(`{"sign_callers": ["broker-a"], "Sign_Callers": ["broker-b"]}`),
		[]byte(`[{"op":"replace","path":"/sign_callers","value":["x"]}]`)); err == nil {
		t.Error("Patch must refuse to edit a config with a case-variant duplicate key")
	}

	// Distinct names that merely share a prefix are not duplicates.
	if _, err := Standardize([]byte(`{"sign_callers": [], "sign_callers_extra": []}`)); err != nil {
		t.Errorf("distinct keys must pass: %v", err)
	}
}

func TestStrictRejectsDuplicateKeys(t *testing.T) {
	t.Parallel()
	// A duplicated security control must fail closed at the typed load, not be
	// silently resolved last-wins.
	var s sample
	if err := Strict([]byte(`{"sign_callers": ["a"], "sign_callers": ["a", "b"]}`), &s); err == nil {
		t.Error("Strict must reject a duplicated sign_callers key")
	}
}

func TestPatchRejectsDuplicateKeys(t *testing.T) {
	t.Parallel()
	// The finding scenario: a host with two command_policy objects. hujson would
	// patch the FIRST while the loader enforces the LAST — so refuse the edit
	// entirely rather than report success against the wrong occurrence.
	orig := []byte(`{
  "hosts": {
    "web": {
      "command_policy": { "mode": "allowlist", "allow": [] },
      "command_policy": { "mode": "allowlist", "allow": ["^rm -rf /$"] }
    }
  }
}`)
	patch := []byte(`[{"op":"remove","path":"/hosts/web/command_policy/allow/0"}]`)
	if _, err := Patch(orig, patch); err == nil {
		t.Error("Patch must refuse to edit a config with a duplicate key")
	}
}

// TestPatchRejectsCaseVariantDuplicateItCreates locks in #749: the input is
// clean (one spelling), the patch adds the canonical spelling beside it, and
// the result would be refused by every loader — so Patch must refuse it.
func TestPatchRejectsCaseVariantDuplicateItCreates(t *testing.T) {
	t.Parallel()
	orig := []byte(`{
  "hosts": {
    "web01": { "addr": "10.0.0.1:22", "Host_Key": "ssh-ed25519 AAAA" }
  }
}`)
	patch := []byte(`[{"op":"add","path":"/hosts/web01/host_key","value":"ssh-ed25519 BBBB"}]`)
	_, err := Patch(orig, patch)
	if err == nil {
		t.Fatal("Patch must refuse an add that creates a case-variant duplicate")
	}
	if !strings.Contains(err.Error(), `duplicate key "host_key"`) || !strings.Contains(err.Error(), "/hosts/web01") {
		t.Errorf("error must name the duplicate and its location: %v", err)
	}
	// A top-level section spelled differently is the same defect one level up.
	orig = []byte(`{ "Hosts": { "web01": { "addr": "10.0.0.1:22" } } }`)
	patch = []byte(`[{"op":"add","path":"/hosts","value":{"web02":{"addr":"10.0.0.2:22"}}}]`)
	if _, err := Patch(orig, patch); err == nil || !strings.Contains(err.Error(), `duplicate key "hosts"`) {
		t.Errorf("Patch must refuse adding a section beside its case variant, got %v", err)
	}
	// The same add on the canonical spelling still works.
	orig = []byte(`{ "hosts": { "web01": { "addr": "10.0.0.1:22", "host_key": "ssh-ed25519 AAAA" } } }`)
	patch = []byte(`[{"op":"add","path":"/hosts/web01/host_key","value":"ssh-ed25519 BBBB"}]`)
	out, err := Patch(orig, patch)
	if err != nil {
		t.Fatalf("replace in place must succeed: %v", err)
	}
	if !strings.Contains(string(out), "BBBB") || strings.Contains(string(out), "AAAA") {
		t.Errorf("expected an in-place replace, got %s", out)
	}
}

func TestPatchPreservesComments(t *testing.T) {
	t.Parallel()
	orig := []byte(`{
  // keep this top comment
  "hosts": {
    "web": {
      "principal": "host:web", // inline note kept
      "command_policy": { "mode": "allowlist", "allow": ["^uptime$"] }
    }
  }
}`)
	// Append a pattern to a nested array — the editAllow scenario.
	patch := []byte(`[{"op":"add","path":"/hosts/web/command_policy/allow/-","value":"^df -h$"}]`)
	out, err := Patch(orig, patch)
	if err != nil {
		t.Fatalf("Patch: %v", err)
	}
	s := string(out)
	if !strings.Contains(s, "// keep this top comment") || !strings.Contains(s, "// inline note kept") {
		t.Errorf("operator comments must survive the patch:\n%s", s)
	}
	if !strings.Contains(s, "^df -h$") {
		t.Errorf("the patched-in value must be present:\n%s", s)
	}
	// The result must still load through the strict loader.
	var cfg struct {
		Hosts map[string]struct {
			Principal     string `json:"principal"`
			CommandPolicy struct {
				Mode  string   `json:"mode"`
				Allow []string `json:"allow"`
			} `json:"command_policy"`
		} `json:"hosts"`
	}
	if err := Strict(out, &cfg); err != nil {
		t.Fatalf("patched config must still load: %v", err)
	}
	if got := cfg.Hosts["web"].CommandPolicy.Allow; len(got) != 2 || got[1] != "^df -h$" {
		t.Errorf("allow must have the appended pattern: %v", got)
	}

	// HasComments distinguishes JSONC from plain JSON.
	if !HasComments(orig) || HasComments([]byte(`{"a":1}`)) {
		t.Error("HasComments must be true for // comments and false for plain JSON")
	}
}

// TestPatchFormatsOnlyInsertedValues is the #561 guard: a patch lays out only
// what it inserts, in the file's own indentation; every untouched line stays
// byte-for-byte (no document-wide re-indent to tabs, no value alignment, no
// expansion of a one-line sibling), and a per-key edit keeps the entry's key
// order and the comments inside it.
func TestPatchFormatsOnlyInsertedValues(t *testing.T) {
	t.Parallel()
	orig := []byte(`{
  "hosts": {
    "web01": {
      "addr": "10.0.0.1:22", // the addr
      // sealed on purpose
      "sealed_exec": true,
      "user": "deploy"
    },
    "db01": {"addr": "10.0.0.2:22", "user": "pg", "host_key": "ssh-ed25519 AAAA", "principal": "host:db01"}
  }
}`)
	patch := []byte(`[
  {"op":"add","path":"/hosts/web01/addr","value":"10.0.0.9:22"},
  {"op":"add","path":"/hosts/web01/groups","value":["a","b"]},
  {"op":"add","path":"/hosts/new","value":{"addr":"x:22","command_policy":{"mode":"allowlist","allow":["^a$"]}}}
]`)
	out, err := Patch(orig, patch)
	if err != nil {
		t.Fatalf("Patch: %v", err)
	}
	want := `{
  "hosts": {
    "web01": {
      "addr": "10.0.0.9:22", // the addr
      // sealed on purpose
      "sealed_exec": true,
      "user": "deploy",
      "groups": ["a", "b"]
    },
    "db01": {"addr": "10.0.0.2:22", "user": "pg", "host_key": "ssh-ed25519 AAAA", "principal": "host:db01"},
    "new": {
      "addr":           "x:22",
      "command_policy": {"mode": "allowlist", "allow": ["^a$"]}
    }
  }
}`
	if string(out) != want {
		t.Errorf("patched config:\n%s\nwant:\n%s", out, want)
	}
	var cfg struct {
		Hosts map[string]map[string]any `json:"hosts"`
	}
	if err := Strict(out, &cfg); err != nil {
		t.Fatalf("patched config must still load: %v", err)
	}

	// The first member of an empty section in a multi-line file is expanded at
	// its depth; an inline parent stays inline; a single-line document stays
	// single-line.
	cases := []struct{ name, orig, patch, want string }{
		{"empty section", "{\n\t\"hosts\": {},\n\t\"callers\": {\"a\": {\"allowed_groups\": [\"x\"]}}\n}",
			`[{"op":"add","path":"/hosts/web01","value":{"addr":"x:22"}},{"op":"add","path":"/callers/a/allowed_groups","value":["y"]}]`,
			"{\n\t\"hosts\": {\n\t\t\"web01\": {\"addr\": \"x:22\"}\n\t},\n\t\"callers\": {\"a\": {\"allowed_groups\": [\"y\"]}}\n}"},
		{"array append", "{\n  \"cp\": { \"allow\": [\"^uptime$\"] }\n}",
			`[{"op":"add","path":"/cp/allow/-","value":"^df -h$"}]`,
			"{\n  \"cp\": { \"allow\": [\"^uptime$\", \"^df -h$\"] }\n}"},
		{"single line", `{"ca_key":"/etc/ca.key","hosts":{}}`,
			`[{"op":"add","path":"/hosts/web01","value":{"addr":"x:22"}},{"op":"add","path":"/ca_keys","value":{"_default":{"type":"pem"}}}]`,
			`{"ca_key":"/etc/ca.key","hosts":{"web01": {"addr": "x:22"}}, "ca_keys": {"_default": {"type": "pem"}}}`},
	}
	for _, c := range cases {
		out, err := Patch([]byte(c.orig), []byte(c.patch))
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if string(out) != c.want {
			t.Errorf("%s:\n%s\nwant:\n%s", c.name, out, c.want)
		}
	}
}
