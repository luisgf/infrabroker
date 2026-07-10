package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luisgf/infrabroker/internal/confcheck"
	"github.com/luisgf/infrabroker/internal/signer"
)

// TestAtomicWritePreservesModeNoLitter is the #220 guard: the rewrite keeps the
// config's existing (narrow) permissions rather than adopting a stale/planted
// temp's mode, and leaves no temp file behind (a fresh O_EXCL temp, not a fixed
// path+".tmp").
func TestAtomicWritePreservesModeNoLitter(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "signer.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	fi0, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	want := fi0.Mode().Perm()

	if err := atomicWrite(path, []byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); string(got) != `{"a":1}` {
		t.Errorf("content = %q, want {\"a\":1}", got)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != want {
		t.Errorf("permissions changed from %o to %o (must not widen)", want, fi.Mode().Perm())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || entries[0].Name() != "signer.json" {
		t.Errorf("expected only signer.json (no temp litter), got %v", entries)
	}
}

const policyFixture = `{
  "_comment": "top-level note",
  "reload_callers": ["admin"],
  "hosts": {
    "web01": { "principal": "host:web01", "command_policy": {"mode":"allowlist","allow":["^uptime$"]} },
    "db01":  { "principal": "host:db01", "_note": "keep me verbatim" }
  }
}`

func allowOf(t *testing.T, b []byte, host string) signer.CommandPolicy {
	t.Helper()
	b, err := confcheck.Standardize(b) // the edited config may carry // comments
	if err != nil {
		t.Fatalf("standardize: %v", err)
	}
	var top, hosts map[string]json.RawMessage
	if err := json.Unmarshal(b, &top); err != nil {
		t.Fatalf("reparse top: %v", err)
	}
	if err := json.Unmarshal(top["hosts"], &hosts); err != nil {
		t.Fatalf("reparse hosts: %v", err)
	}
	var hp signer.HostPolicy
	if err := json.Unmarshal(hosts[host], &hp); err != nil {
		t.Fatalf("reparse host: %v", err)
	}
	return hp.CommandPolicy
}

func TestEditAllowAddAndPreserve(t *testing.T) {
	t.Parallel()
	b, err := editAllow([]byte(policyFixture), "web01", "^free( .*)?$", true)
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	cp := allowOf(t, b, "web01")
	if cp.Mode != signer.CmdPolicyAllowlist || len(cp.Allow) != 2 || cp.Allow[1] != "^free( .*)?$" {
		t.Fatalf("allow not appended correctly: %+v", cp)
	}
	// Preservation: top-level comment and the OTHER host (with its comment) survive.
	var top map[string]json.RawMessage
	json.Unmarshal(b, &top)
	if _, ok := top["_comment"]; !ok {
		t.Error("top-level _comment was dropped")
	}
	var hosts map[string]json.RawMessage
	json.Unmarshal(top["hosts"], &hosts)
	if !bytes.Contains(hosts["db01"], []byte("keep me verbatim")) {
		t.Error("an untouched host's comment was dropped")
	}
}

func TestEditAllowOnHostWithoutPolicySetsAllowlist(t *testing.T) {
	t.Parallel()
	b, err := editAllow([]byte(policyFixture), "db01", "^uptime$", true)
	if err != nil {
		t.Fatal(err)
	}
	if cp := allowOf(t, b, "db01"); cp.Mode != signer.CmdPolicyAllowlist || len(cp.Allow) != 1 {
		t.Fatalf("first allow rule should turn the host into an allowlist: %+v", cp)
	}
}

func TestEditAllowRemove(t *testing.T) {
	t.Parallel()
	b, err := editAllow([]byte(policyFixture), "web01", "^uptime$", false)
	if err != nil {
		t.Fatal(err)
	}
	if cp := allowOf(t, b, "web01"); len(cp.Allow) != 0 {
		t.Fatalf("pattern should be removed: %+v", cp)
	}
}

func TestEditAllowErrors(t *testing.T) {
	t.Parallel()
	if _, err := editAllow([]byte(policyFixture), "ghost", "^x$", true); !errors.Is(err, errHostNotFound) {
		t.Errorf("unknown host -> errHostNotFound, got %v", err)
	}
	if _, err := editAllow([]byte(policyFixture), "web01", "^uptime$", true); !errors.Is(err, errNoChange) {
		t.Errorf("duplicate add -> errNoChange, got %v", err)
	}
	if _, err := editAllow([]byte(policyFixture), "web01", "^nope$", false); !errors.Is(err, errNoChange) {
		t.Errorf("removing absent pattern -> errNoChange, got %v", err)
	}
}

// TestEditAllowRejectsDuplicateKey is the #216 guard: a host with two
// command_policy objects must NOT be edited. The loader enforces the LAST
// occurrence (encoding/json last-wins) while the format-preserving patch targets
// the FIRST (hujson first-match), so an edit here would report success against a
// shadowed occurrence and leave the effective rule untouched. The mutation path
// must refuse it instead.
func TestEditAllowRejectsDuplicateKey(t *testing.T) {
	t.Parallel()
	dup := `{
  "hosts": {
    "web01": {
      "command_policy": {"mode":"allowlist","allow":[]},
      "command_policy": {"mode":"allowlist","allow":["^rm -rf /$"]}
    }
  }
}`
	if _, err := editAllow([]byte(dup), "web01", "^rm -rf /$", false); err == nil {
		t.Error("editAllow must refuse a config with a duplicated command_policy key")
	}
}

// TestEditAllowPreservesLineComments is the #183 round-trip: a signer.json that
// carries // comments has an allow rule added through the policy-mutation edit,
// and the comments survive on disk alongside the new rule.
func TestEditAllowPreservesLineComments(t *testing.T) {
	t.Parallel()
	jsonc := `{
  // operator note: production web tier
  "reload_callers": ["admin"],
  "hosts": {
    "web01": {
      "principal": "host:web01", // pinned principal
      "command_policy": { "mode": "allowlist", "allow": ["^uptime$"] }
    }
  }
}`
	b, err := editAllow([]byte(jsonc), "web01", "^df -h$", true)
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	s := string(b)
	if !strings.Contains(s, "// operator note: production web tier") || !strings.Contains(s, "// pinned principal") {
		t.Errorf("operator // comments must survive the edit:\n%s", s)
	}
	if cp := allowOf(t, b, "web01"); len(cp.Allow) != 2 || cp.Allow[1] != "^df -h$" {
		t.Errorf("the new rule must be present: %+v", cp)
	}
}
