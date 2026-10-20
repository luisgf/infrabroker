package initcmd

import (
	"errors"
	"io"
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

// TestDiscoverSSHHostsFollowsInclude pins #565: hosts defined in files pulled
// in via `Include` (relative to the config's dir, globs, `Keyword=arg` form,
// nested) are discovered; a loop terminates; a non-matching glob is ignored.
func TestDiscoverSSHHostsFollowsInclude(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, content string) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("config", `Host top
    HostName 10.0.0.1
Include conf.d/*.conf
Include=nested.conf
Include no-such-dir/*.conf
Host *
    ForwardAgent no
`)
	write("conf.d/10-a.conf", "Host inc-a\n    HostName 10.0.0.2\n")
	write("conf.d/20-b.conf", "Host inc-b inc-*\n    HostName 10.0.0.3\n")
	write("conf.d/ignored.txt", "Host not-included\n")
	// nested.conf includes itself and config again: must terminate.
	write("nested.conf", "Include nested.conf\nInclude config\nHost deep\n    HostName 10.0.0.4\n")

	got, err := discoverSSHHosts(filepath.Join(dir, "config"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"top", "inc-a", "inc-b", "deep"}
	if !equalStrings(got, want) {
		t.Errorf("discoverSSHHosts = %v, want %v", got, want)
	}
}

func readFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestParseSSHG pins #565: `ssh -G` output yields the direct-dial fields plus
// any ProxyJump/ProxyCommand (`none` counts as unset).
func TestParseSSHG(t *testing.T) {
	direct := parseSSHG(readFixture(t, "ssh-G-direct.txt"))
	if direct.hostname != "10.0.0.1" || direct.user != "deploy" || direct.port != "22" || direct.keyAlias != "web01.internal" {
		t.Errorf("direct = %+v", direct)
	}
	if via := direct.proxyVia(); via != "" {
		t.Errorf("direct host reports proxy %q", via)
	}

	pj := parseSSHG(readFixture(t, "ssh-G-proxyjump.txt"))
	if pj.hostname != "10.0.0.5" || pj.port != "2222" || pj.proxyJump != "bastion" || pj.proxyCommand != "" {
		t.Errorf("proxyjump = %+v", pj)
	}
	if via := pj.proxyVia(); via != "ProxyJump bastion" {
		t.Errorf("proxyVia = %q", via)
	}

	pc := parseSSHG(readFixture(t, "ssh-G-proxycommand.txt"))
	if pc.hostname != "10.0.0.6" || pc.proxyJump != "" || !strings.HasPrefix(pc.proxyCommand, "nc -X connect") {
		t.Errorf("proxycommand = %+v", pc)
	}
	if via := pc.proxyVia(); !strings.HasPrefix(via, "ProxyCommand nc") {
		t.Errorf("proxyVia = %q", via)
	}

	none := parseSSHG(readFixture(t, "ssh-G-proxy-none.txt"))
	if none.hostname != "b.example.com" || none.proxyVia() != "" {
		t.Errorf("`none` must count as unset: %+v", none)
	}
}

// TestImportSkipsProxiedHosts pins #565: a host reached via ProxyJump or
// ProxyCommand is not written as a direct-dial target (the signer dials addr
// directly and the import would fail at first use); it is skipped with a note,
// and when its bastion is itself imported the note names the jump mapping.
func TestImportSkipsProxiedHosts(t *testing.T) {
	fixtures := map[string]string{
		"web01":   readFixture(t, "ssh-G-direct.txt"),
		"app":     readFixture(t, "ssh-G-proxyjump.txt"),
		"pc":      readFixture(t, "ssh-G-proxycommand.txt"),
		"bastion": readFixture(t, "ssh-G-proxy-none.txt"),
	}
	canon := func(alias string) sshHostInfo { return parseSSHG(fixtures[alias]) }
	var keyed []string
	key := func(w io.Writer, alias, hostname, port, keyAlias string) (string, error) {
		keyed = append(keyed, alias)
		return "ssh-ed25519 AAAA" + alias, nil
	}
	var out strings.Builder
	hosts := importHostsWith(&out, []string{"web01", "app", "pc", "bastion"}, canon, key)

	var names []string
	for _, h := range hosts {
		names = append(names, h.name)
	}
	if want := []string{"web01", "bastion"}; !equalStrings(names, want) {
		t.Errorf("imported %v, want %v", names, want)
	}
	if want := []string{"web01", "bastion"}; !equalStrings(keyed, want) {
		t.Errorf("host keys looked up for %v, want %v (no key lookup for a skipped host)", keyed, want)
	}
	if hosts[0].addr != "10.0.0.1:22" || hosts[0].hostKey != "ssh-ed25519 AAAAweb01" {
		t.Errorf("web01 = %+v", hosts[0])
	}

	notes := out.String()
	if strings.Count(notes, "\n") != 2 {
		t.Errorf("want exactly two skip lines, got %q", notes)
	}
	for _, want := range []string{
		`skipped "app" (10.0.0.5): reached via ProxyJump bastion — not importable as a direct target`,
		`"jump": "bastion"`, `"allow_as_bastion": true`,
		`skipped "pc" (10.0.0.6): reached via ProxyCommand nc -X connect`,
	} {
		if !strings.Contains(notes, want) {
			t.Errorf("notes %q must contain %q", notes, want)
		}
	}
	// A ProxyJump whose bastion is NOT imported gets the plain note only.
	out.Reset()
	importHostsWith(&out, []string{"app"}, canon, key)
	if n := out.String(); !strings.Contains(n, "not importable as a direct target") || strings.Contains(n, "allow_as_bastion") {
		t.Errorf("unimported bastion must yield the plain skip note, got %q", n)
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
