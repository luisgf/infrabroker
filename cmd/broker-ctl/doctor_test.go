package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
		if got := listenIsPublic(c.addr); got != c.want {
			t.Errorf("listenIsPublic(%q) = %v, want %v", c.addr, got, c.want)
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

	// An open lab config: callers without _default, pem custody, public monitor,
	// no rate limit/state_db/redact.
	bad := writeTmp(t, "bad.json", `{
		"callers": {"broker-1": {"allowed_groups": ["web"]}},
		"ca_key": "pki/ssh_ca",
		"monitor_listen": "0.0.0.0:9160"
	}`)
	fb := checkSignerConfig(bad)
	if got := findByCheck(fb, "_default"); got.level != docFAIL {
		t.Errorf("callers without _default must FAIL, got %q", got.level)
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
}

func TestCheckControlPlaneConfig(t *testing.T) {
	t.Parallel()

	// Approvers present but no sign_callers → an approver could sign. FAIL.
	danger := writeTmp(t, "cp.json", `{
		"approval": {"callers": ["broker-admin"]},
		"sign_callers": []
	}`)
	if got := findByCheck(checkControlPlaneConfig(danger), "sign_callers"); got.level != docFAIL {
		t.Errorf("approvers without sign_callers must FAIL, got %q", got.level)
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
