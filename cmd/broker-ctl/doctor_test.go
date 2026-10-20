package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luisgf/infrabroker/internal/monitor"
)

// TestListenIsPublic keeps the doctor-facing contract of the address classifier
// (now monitor.ListenIsPublic, shared with the startup warning, #449).
func TestListenIsPublic(t *testing.T) {
	t.Parallel()
	cases := []struct {
		addr string
		want bool
	}{
		{"", true},                  // empty host after split failure → treated as bare host "" → public
		{":9160", true},             // all interfaces
		{"0.0.0.0:9160", true},      // unspecified
		{"[::]:9160", true},         // unspecified v6
		{"127.0.0.1:9160", false},   // loopback
		{"[::1]:9160", false},       // loopback v6
		{"localhost:9160", false},   // hostname loopback
		{"10.0.0.5:9160", false},    // RFC1918 private
		{"192.168.1.9:9160", false}, // private
		{"172.16.4.4:9160", false},  // private
		{"8.8.8.8:9160", true},      // global
		{"203.0.113.7:9160", true},  // global
	}
	for _, c := range cases {
		if got := monitor.ListenIsPublic(c.addr); got != c.want {
			t.Errorf("monitor.ListenIsPublic(%q) = %v, want %v", c.addr, got, c.want)
		}
	}
}

// writeTmp writes content to a temp file and returns its path.
func writeTmp(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

// findByCheck returns the finding whose check contains sub, or a zero finding.
func findByCheck(f []doctorFinding, sub string) doctorFinding {
	for _, x := range f {
		if strings.Contains(x.check, sub) {
			return x
		}
	}
	return doctorFinding{}
}

func TestCheckSignerConfig(t *testing.T) {
	t.Parallel()

	// A hardened signer config: default-deny, rate limit, KMS custody, state_db,
	// redact, private monitor. No FAIL, no WARN.
	good := writeTmp(t, "signer.json", `{
		"callers": {"broker-1": {"allowed_groups": ["web"]}, "_default": {"allowed_groups": []}},
		"sign_rate_limit_per_min": 120,
		"ca_keys": {"_default": {"type": "akv", "vault_url": "x", "key_name": "y"}},
		"state_db": "/var/lib/x/state.db",
		"redact": {},
		"monitor_listen": "127.0.0.1:9160"
	}`)
	f := checkSignerConfig(good)
	for _, x := range f {
		if x.level == docFAIL || x.level == docWARN {
			t.Errorf("hardened config produced %s on %q (fix: %s)", x.level, x.check, x.fix)
		}
	}

	// An open lab config: pem custody, public monitor, no rate limit/state_db/
	// redact. callers without _default is now default-deny (v2.0.0), so it PASSes.
	bad := writeTmp(t, "bad.json", `{
		"callers": {"broker-1": {"allowed_groups": ["web"]}},
		"ca_key": "pki/ssh_ca",
		"monitor_listen": "0.0.0.0:9160"
	}`)
	fb := checkSignerConfig(bad)
	if got := findByCheck(fb, "default-deny"); got.level != docPASS {
		t.Errorf("callers without _default is now default-deny, must PASS, got %q", got.level)
	}
	if got := findByCheck(fb, "CA custody"); got.level != docFAIL {
		t.Errorf("pem custody must FAIL, got %q", got.level)
	}
	if got := findByCheck(fb, "monitor_listen"); got.level != docFAIL {
		t.Errorf("public monitor must FAIL, got %q", got.level)
	}
	if got := findByCheck(fb, "rate_limit"); got.level != docWARN {
		t.Errorf("missing rate limit must WARN, got %q", got.level)
	}

	// No callers block at all → unrestricted, must WARN.
	none := writeTmp(t, "none.json", `{"ca_key": "pki/ssh_ca"}`)
	if got := findByCheck(checkSignerConfig(none), "callers RBAC configured"); got.level != docWARN {
		t.Errorf("no callers block must WARN, got %q", got.level)
	}

	// An explicit _default that grants groups widens access → WARN.
	widen := writeTmp(t, "widen.json", `{
		"callers": {"_default": {"allowed_groups": ["web"]}},
		"ca_key": "pki/ssh_ca"
	}`)
	if got := findByCheck(checkSignerConfig(widen), "default-deny"); got.level != docWARN {
		t.Errorf("_default granting groups must WARN, got %q", got.level)
	}
}

// TestRedactFindingEfficacy is the #223 guard: a redact block that disables the
// built-in defaults and defines no patterns is a no-op redactor and must WARN,
// not PASS on mere presence. Defaults on, or patterns present, PASS.
func TestRedactFindingEfficacy(t *testing.T) {
	t.Parallel()

	// disable_defaults with no patterns → zero rules → WARN.
	noop := writeTmp(t, "noop.json", `{
		"ca_keys": {"_default": {"type": "akv", "vault_url": "x", "key_name": "y"}},
		"redact": {"disable_defaults": true}
	}`)
	if got := findByCheck(checkSignerConfig(noop), "redact"); got.level != docWARN {
		t.Errorf("a no-op redactor (disable_defaults, no patterns) must WARN, got %q", got.level)
	}

	// disable_defaults BUT with a pattern → effective → PASS.
	custom := writeTmp(t, "custom.json", `{
		"ca_keys": {"_default": {"type": "akv", "vault_url": "x", "key_name": "y"}},
		"redact": {"disable_defaults": true, "patterns": [{"regex": "token=\\S+"}]}
	}`)
	if got := findByCheck(checkSignerConfig(custom), "redact"); got.level != docPASS {
		t.Errorf("disable_defaults with a pattern is effective, must PASS, got %q", got.level)
	}

	// Empty block (built-in defaults on) → PASS.
	defaults := writeTmp(t, "defaults.json", `{
		"ca_keys": {"_default": {"type": "akv", "vault_url": "x", "key_name": "y"}},
		"redact": {}
	}`)
	if got := findByCheck(checkSignerConfig(defaults), "redact"); got.level != docPASS {
		t.Errorf("an empty redact block keeps the built-ins, must PASS, got %q", got.level)
	}
}

// TestCheckSignerConfigCAKeysNoDefault pins #240: a ca_keys config with no
// _default (and no legacy ca_key) has no resolvable default CA — the signer
// refuses to start (LoadGroupCAs) — so the preflight must WARN, not PASS.
func TestCheckSignerConfigCAKeysNoDefault(t *testing.T) {
	t.Parallel()
	noDefault := writeTmp(t, "nodefault.json", `{
		"ca_keys": {"groupA": {"type": "akv", "vault_url": "x", "key_name": "y"}}
	}`)
	if got := findByCheck(checkSignerConfig(noDefault), "CA custody"); got.level != docWARN {
		t.Errorf("ca_keys without a _default must WARN (no resolvable default CA), got %q", got.level)
	}
}

// TestCheckSignerConfigCAKeysUnknownType pins #442: internal/ca LoadCA has no
// default type, so a ca_keys entry with an empty or misspelled `type` makes
// LoadGroupCAs fail and the signer refuses to start — the preflight must FAIL
// (naming the group) instead of PASSing "CA custody not local PEM" for what is
// usually a PEM key with the `type` line forgotten.
func TestCheckSignerConfigCAKeysUnknownType(t *testing.T) {
	t.Parallel()

	// _default is a local key file with no type at all.
	noType := writeTmp(t, "notype.json", `{
		"ca_keys": {"_default": {"path": "pki/ssh_ca"}}
	}`)
	got := findByCheck(checkSignerConfig(noType), "CA custody")
	if got.level != docFAIL {
		t.Errorf("ca_keys._default without a type must FAIL (signer refuses to start), got %q", got.level)
	}
	if !strings.Contains(got.check, "refuses to start") {
		t.Errorf("the FAIL must say the signer refuses to start: %q", got.check)
	}
	if !strings.Contains(got.fix, "_default") {
		t.Errorf("the FAIL must name the offending group: %q", got.fix)
	}

	// _default is fine but a per-group entry has a misspelled type.
	misspelled := writeTmp(t, "misspelled.json", `{
		"ca_keys": {
			"_default": {"type": "akv", "vault_url": "x", "key_name": "y"},
			"edge": {"type": "agnet", "public_key_path": "pki/ca.pub"}
		}
	}`)
	got = findByCheck(checkSignerConfig(misspelled), "CA custody")
	if got.level != docFAIL {
		t.Errorf("a misspelled per-group type must FAIL, got %q", got.level)
	}
	if !strings.Contains(got.fix, "edge") || !strings.Contains(got.fix, "agnet") {
		t.Errorf("the FAIL must name the group and the bad type: %q", got.fix)
	}
	if strings.Contains(got.fix, "_default") {
		t.Errorf("a valid group must not be named as offending: %q", got.fix)
	}

	// A pem group alongside an unknown one: both are reported in one FAIL.
	both := writeTmp(t, "both.json", `{
		"ca_keys": {
			"_default": {"path": "pki/ssh_ca"},
			"legacy": {"type": "pem", "path": "pki/legacy_ca"}
		}
	}`)
	got = findByCheck(checkSignerConfig(both), "CA custody")
	if got.level != docFAIL || !strings.Contains(got.fix, "_default") || !strings.Contains(got.fix, "legacy") {
		t.Errorf("unknown + pem groups must FAIL naming both: %q / %q", got.level, got.fix)
	}
}

// TestCheckSignerConfigCAKeysPerGroupPem is the #218 guard: internal/ca loads
// every ca_keys group, so a per-group local `pem` override must FAIL even when
// _default uses a hardware/KMS backend — otherwise the preflight green-lights a
// lab-only CA custody in production.
func TestCheckSignerConfigCAKeysPerGroupPem(t *testing.T) {
	t.Parallel()

	// _default is akv (secure) but a "legacy" group is a local pem key on disk.
	mixed := writeTmp(t, "mixed.json", `{
		"callers": {"broker-1": {"allowed_groups": ["web"]}},
		"ca_keys": {
			"_default": {"type": "akv", "vault_url": "x", "key_name": "y"},
			"legacy": {"type": "pem", "path": "pki/legacy_ca"}
		},
		"monitor_listen": "127.0.0.1:9160"
	}`)
	got := findByCheck(checkSignerConfig(mixed), "CA custody")
	if got.level != docFAIL {
		t.Errorf("a per-group pem override must FAIL, got %q", got.level)
	}
	if !strings.Contains(got.fix, "legacy") {
		t.Errorf("the FAIL must name the offending group: %q", got.fix)
	}

	// Every group on a non-pem backend → PASS.
	secure := writeTmp(t, "secure.json", `{
		"ca_keys": {
			"_default": {"type": "akv", "vault_url": "x", "key_name": "y"},
			"ed25519": {"type": "agent", "public_key_path": "pki/ca.pub"}
		}
	}`)
	if got := findByCheck(checkSignerConfig(secure), "CA custody"); got.level != docPASS {
		t.Errorf("all-KMS/agent custody must PASS, got %q", got.level)
	}
}

// TestDoctorAuditFailModeAndBrokerCustody is the #562 guard: `audit_fail_mode:
// open` FAILs on all three services (it reverts the v2.0.0 fail-closed flip),
// and a broker in local mode (no `signer` block) holding a local PEM CA FAILs
// the custody control that only the signer config used to get; a remote-mode
// broker PASSes custody as separated.
func TestDoctorAuditFailModeAndBrokerCustody(t *testing.T) {
	t.Parallel()

	signer := writeTmp(t, "signer.json", `{
		"callers": {"broker-1": {"allowed_groups": ["web"]}},
		"ca_keys": {"_default": {"type": "akv", "vault_url": "x", "key_name": "y"}},
		"audit_fail_mode": "open"
	}`)
	if got := findByCheck(checkSignerConfig(signer), "audit_fail_mode"); got.level != docFAIL {
		t.Errorf("signer audit_fail_mode open must FAIL, got %q", got.level)
	}

	broker := writeTmp(t, "config.json", `{
		"ca_key": "pki/ssh_ca",
		"audit_fail_mode": "open"
	}`)
	fb := checkBrokerConfig(broker)
	if got := findByCheck(fb, "audit_fail_mode"); got.level != docFAIL {
		t.Errorf("broker audit_fail_mode open must FAIL, got %q", got.level)
	}
	if got := findByCheck(fb, "CA custody"); got.level != docFAIL || !strings.Contains(got.fix, "ca_key (legacy)") {
		t.Errorf("local-mode broker with a pem ca_key must FAIL custody, got %q (%s)", got.level, got.fix)
	}

	cp := writeTmp(t, "control-plane.json", `{"audit_fail_mode": "open"}`)
	if got := findByCheck(checkControlPlaneConfig(cp), "audit_fail_mode"); got.level != docFAIL {
		t.Errorf("control-plane audit_fail_mode open must FAIL, got %q", got.level)
	}

	// Remote mode: the signer block means the broker holds no CA key, so the
	// stale ca_keys it carries are not its custody (the broker ignores them).
	remote := writeTmp(t, "remote.json", `{
		"signer": {"url": "https://signer:9443"},
		"ca_keys": {"_default": {"type": "pem", "path": "/old/ca"}},
		"audit_fail_mode": "closed"
	}`)
	fr := checkBrokerConfig(remote)
	if got := findByCheck(fr, "CA custody"); got.level != docPASS || !strings.Contains(got.check, "remote mode") {
		t.Errorf("remote-mode broker must PASS custody as separated, got %q %q", got.level, got.check)
	}
	if got := findByCheck(fr, "audit_fail_mode"); got.level != docPASS {
		t.Errorf("audit_fail_mode closed must PASS, got %q", got.level)
	}
	// Local mode with KMS custody and the default (absent) fail mode is clean.
	local := writeTmp(t, "local.json", `{
		"ca_keys": {"_default": {"type": "agent", "public_key_path": "/ca.pub"}}
	}`)
	for _, x := range checkBrokerConfig(local) {
		if x.level == docFAIL {
			t.Errorf("local-mode broker with agent custody produced FAIL on %q", x.check)
		}
	}
	// An invalid value is a startup error: FAIL, not PASS.
	if got := auditFailModeFinding("lenient", "x.json"); got.level != docFAIL {
		t.Errorf("invalid audit_fail_mode must FAIL, got %q", got.level)
	}
}

func TestCheckControlPlaneConfig(t *testing.T) {
	t.Parallel()

	// Approvers present but no sign_callers → no explicit allowlist. WARN, not
	// FAIL: the control plane already denies an approver CN the sign path when
	// sign_callers is empty (isSignCaller), so the finding must not claim an
	// approver could sign (#563).
	loose := writeTmp(t, "cp.json", `{
		"approval": {"callers": ["broker-admin"]},
		"sign_callers": []
	}`)
	got := findByCheck(checkControlPlaneConfig(loose), "sign_callers")
	if got.level != docWARN {
		t.Errorf("approvers without sign_callers must WARN, got %q", got.level)
	}
	if !strings.Contains(got.fix, "already denied") || strings.Contains(got.fix, "could originate") {
		t.Errorf("the WARN must say approvers are already denied, not that one could sign: %s", got.fix)
	}

	// Approvers present with an explicit sign_callers allowlist → PASS.
	safe := writeTmp(t, "cp2.json", `{
		"approval": {"callers": ["broker-admin"]},
		"sign_callers": ["broker-1"],
		"state_db": "/var/lib/x/cp.db",
		"redact": {},
		"monitor_listen": "127.0.0.1:9170"
	}`)
	fs := checkControlPlaneConfig(safe)
	if got := findByCheck(fs, "sign_callers"); got.level != docPASS {
		t.Errorf("approvers with sign_callers must PASS, got %q", got.level)
	}
	for _, x := range fs {
		if x.level == docFAIL {
			t.Errorf("hardened control-plane produced FAIL on %q", x.check)
		}
	}
}

// TestCheckControlPlaneConfigSignCallersOverlap: an approver CN inside
// sign_callers defeats the role separation (isSignCaller applies the approver
// exclusion only to an empty list) → FAIL; disjoint lists → PASS (#640).
func TestCheckControlPlaneConfigSignCallersOverlap(t *testing.T) {
	t.Parallel()

	overlap := writeTmp(t, "cp-overlap.json", `{
		"approval": {"callers": ["approver-1", "shared"]},
		"sign_callers": ["broker-1", "shared"]
	}`)
	got := findByCheck(checkControlPlaneConfig(overlap), "sign_callers")
	if got.level != docFAIL || !strings.Contains(got.check, "overlap") {
		t.Fatalf("overlap must FAIL, got %q %q", got.level, got.check)
	}
	if !strings.Contains(got.fix, "shared") || strings.Contains(got.fix, "broker-1") {
		t.Errorf("fix must name only the overlapping CN: %s", got.fix)
	}

	disjoint := writeTmp(t, "cp-disjoint.json", `{
		"approval": {"callers": ["approver-1"]},
		"sign_callers": ["broker-1"]
	}`)
	got = findByCheck(checkControlPlaneConfig(disjoint), "sign_callers")
	if got.level != docPASS {
		t.Errorf("disjoint lists must PASS, got %q %q", got.level, got.check)
	}
}

// TestCheckSignerConfigReloadCallersOverlap: a broker CN (a callers key) in
// reload_callers can rewrite its own policy → WARN; disjoint → no finding (#640).
func TestCheckSignerConfigReloadCallersOverlap(t *testing.T) {
	t.Parallel()

	overlap := writeTmp(t, "signer-overlap.json", `{
		"callers": {"broker-local": {"allowed_groups": ["lab"]}, "broker-2": {"allowed_groups": ["lab"]}},
		"reload_callers": ["admin", "broker-local"]
	}`)
	got := findByCheck(checkSignerConfig(overlap), "reload_callers")
	if got.level != docWARN {
		t.Fatalf("overlap must WARN, got %q %q", got.level, got.check)
	}
	if !strings.Contains(got.fix, "broker-local") || strings.Contains(got.fix, "broker-2") {
		t.Errorf("fix must name only the overlapping CN: %s", got.fix)
	}

	disjoint := writeTmp(t, "signer-disjoint.json", `{
		"callers": {"broker-1": {"allowed_groups": ["lab"]}},
		"reload_callers": ["admin"]
	}`)
	if got := findByCheck(checkSignerConfig(disjoint), "reload_callers"); got.check != "" {
		t.Errorf("disjoint lists must produce no reload_callers finding, got %q %q", got.level, got.check)
	}
}
