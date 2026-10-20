package initcmd

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiscoverSSHHosts(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config")
	content := `# a comment line
Host web01 web02
    HostName 10.0.0.1
    User deploy
Host *.example.com
    User ops
Host bastion
    HostName bastion.example.com
Host *
    ForwardAgent no
`
	if err := os.WriteFile(cfg, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := discoverSSHHosts(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Patterns (*.example.com, *) are skipped; multi-alias lines are expanded.
	want := []string{"web01", "web02", "bastion"}
	if !equalStrings(got, want) {
		t.Errorf("discoverSSHHosts = %v, want %v", got, want)
	}
}

func TestDiscoverSSHHostsMissingFileIsEmpty(t *testing.T) {
	got, err := discoverSSHHosts(filepath.Join(t.TempDir(), "no-such-config"))
	if err != nil {
		t.Fatalf("missing ssh config must not error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("missing ssh config yields %v, want none", got)
	}
}

func TestSanitizeName(t *testing.T) {
	cases := map[string]string{
		"web01":    "web01",
		"Web-01":   "web-01",
		"app.prod": "app.prod",
		"a b/c":    "a-b-c",
		"HOST_1":   "host_1",
	}
	for in, want := range cases {
		if got := sanitizeName(in); got != want {
			t.Errorf("sanitizeName(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestHostAddrIPv6 pins #446: `ssh -G` prints a bare IPv6 literal as the
// hostname, and hostname + ":" + port gave "::1:22", which the broker dials
// verbatim ("too many colons"). The addr must be bracketed.
func TestHostAddrIPv6(t *testing.T) {
	cases := map[[2]string]string{
		{"::1", "22"}:                   "[::1]:22",
		{"2001:db8::10", "2222"}:        "[2001:db8::10]:2222",
		{"10.0.0.1", "22"}:              "10.0.0.1:22",
		{"bastion.example.com", "2200"}: "bastion.example.com:2200",
	}
	for in, want := range cases {
		if got := hostAddr(in[0], in[1]); got != want {
			t.Errorf("hostAddr(%q, %q) = %q, want %q", in[0], in[1], got, want)
		}
	}
}

// TestHostKeyTOFUNotice pins #446: a key that falls back to ssh-keyscan is
// pinned trust-on-first-use, so the operator gets a one-line notice naming the
// host; a key taken from known_hosts prints nothing.
func TestHostKeyTOFUNotice(t *testing.T) {
	const scanned = "ssh-ed25519 AAAAscanned"
	const known = "ssh-ed25519 AAAAknown"
	noEntry := func(host, port string) string { return "" }
	scan := func(host, port string) (string, error) { return scanned, nil }

	// known_hosts empty → keyscan result + notice (alias, bracketed addr).
	var out strings.Builder
	hk, err := hostKeyWith(noEntry, scan, &out, "v6box", "::1", "22", "")
	if err != nil || hk != scanned {
		t.Fatalf("hostKeyWith = %q, %v; want the scanned key", hk, err)
	}
	notice := out.String()
	if strings.Count(notice, "\n") != 1 {
		t.Errorf("want exactly one notice line, got %q", notice)
	}
	for _, want := range []string{`"v6box"`, "[::1]:22", "ssh-keyscan", "trust-on-first-use"} {
		if !strings.Contains(notice, want) {
			t.Errorf("notice %q must mention %q", notice, want)
		}
	}

	// known_hosts hit → that key, no notice, keyscan never consulted.
	out.Reset()
	hit := func(host, port string) string {
		if host == "alias.internal" && port == "22" {
			return known
		}
		return ""
	}
	noScan := func(host, port string) (string, error) {
		t.Errorf("keyscan must not run when known_hosts has the key")
		return "", nil
	}
	hk, err = hostKeyWith(hit, noScan, &out, "web01", "10.0.0.1", "22", "alias.internal")
	if err != nil || hk != known {
		t.Fatalf("hostKeyWith = %q, %v; want the known_hosts key", hk, err)
	}
	if out.String() != "" {
		t.Errorf("a known_hosts key must print no notice, got %q", out.String())
	}

	// keyscan failure → error, no notice.
	out.Reset()
	failScan := func(host, port string) (string, error) { return "", errors.New("no route") }
	if _, err := hostKeyWith(noEntry, failScan, &out, "down", "10.0.0.2", "22", ""); err == nil {
		t.Error("a failed keyscan must surface its error")
	}
	if out.String() != "" {
		t.Errorf("a failed keyscan must print no TOFU notice, got %q", out.String())
	}
}

func TestMCPAddArgs(t *testing.T) {
	got := mcpAddArgs("/usr/local/bin/infrabroker", "/etc/infrabroker/config.json")
	want := []string{"mcp", "add", "infrabroker", "--", "/usr/local/bin/infrabroker", "serve-mcp", "-config", "/etc/infrabroker/config.json"}
	if !equalStrings(got, want) {
		t.Errorf("mcpAddArgs = %v, want %v", got, want)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
