package initcmd

import (
	"os"
	"path/filepath"
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
