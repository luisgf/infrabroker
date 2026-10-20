package initcmd

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// importSSHConfigHosts reads ~/.ssh/config (following Include), canonicalises
// each concrete Host alias with `ssh -G`, and acquires each host key (from
// known_hosts, falling back to an ssh-keyscan TOFU). Best-effort: an alias that
// cannot be resolved or whose key cannot be found is skipped with a note on
// stderr. A host reached via ProxyJump/ProxyCommand is skipped too (#565): the
// signer dials `addr` directly, so importing the final HostName would succeed
// silently (known_hosts keys that name) and fail at first use. Returns the
// importable hosts.
func importSSHConfigHosts() []starterHost {
	cfg := sshConfigPath()
	aliases, err := discoverSSHHosts(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "infrabroker init: reading %s: %v\n", cfg, err)
		return nil
	}
	return importHostsWith(os.Stderr, aliases, sshCanonicalize, hostKey)
}

// importHostsWith is importSSHConfigHosts with the `ssh -G` resolution and the
// host-key lookup injected (tests run without ssh, ~/.ssh or the network).
func importHostsWith(w io.Writer, aliases []string, canon func(alias string) sshHostInfo, key func(w io.Writer, alias, hostname, port, keyAlias string) (string, error)) []starterHost {
	known := map[string]bool{}
	for _, alias := range aliases {
		known[alias] = true
	}
	var hosts []starterHost
	seen := map[string]bool{}
	for _, alias := range aliases {
		info := canon(alias)
		if info.hostname == "" {
			fmt.Fprintf(w, "  skipped %q: ssh -G could not resolve it\n", alias)
			continue
		}
		if via := info.proxyVia(); via != "" {
			fmt.Fprintf(w, "  skipped %q (%s): reached via %s — not importable as a direct target", alias, info.hostname, via)
			if jump := info.proxyJump; jump != "" && known[jump] {
				// The bastion is itself imported, so the operator can route the
				// host through it by hand: `jump` on this host and
				// `allow_as_bastion` on the bastion. init does not write that
				// pair itself: the starter `_default` command policy applies to
				// every host and the signer refuses a host that is both
				// command-restricted and a bastion (CompileHostPolicies), so the
				// generated signer.json would not load.
				b := sanitizeName(jump)
				fmt.Fprintf(w, " (its bastion %q is imported as %q: set \"jump\": %q on this host and \"allow_as_bastion\": true on %q — allow_as_bastion and the starter _default command policy are mutually exclusive, so first attach the starter policy to a group %q is not in)", jump, b, b, b, b)
			}
			fmt.Fprintln(w)
			continue
		}
		hk, err := key(w, alias, info.hostname, info.port, info.keyAlias)
		if err != nil {
			fmt.Fprintf(w, "  skipped %q (%s): no host key — %v\n", alias, info.hostname, err)
			continue
		}
		name := sanitizeName(alias)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		hosts = append(hosts, starterHost{name: name, addr: hostAddr(info.hostname, info.port), user: info.user, hostKey: hk})
	}
	return hosts
}

func sshConfigPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".ssh", "config")
}

// maxIncludeDepth bounds Include nesting (OpenSSH itself stops at 16).
const maxIncludeDepth = 16

// discoverSSHHosts returns the concrete (non-pattern) Host aliases in an ssh
// config file, following `Include` directives (globs, `~/` and paths relative
// to the config's directory — OpenSSH resolves a relative Include against
// ~/.ssh for the user config). Patterns (*, ?, !) and the catch-all `Host *`
// are skipped — they are not connectable targets. A missing file (or an
// Include that matches nothing) yields no hosts (not an error).
func discoverSSHHosts(path string) ([]string, error) {
	return discoverSSHHostsIn(path, filepath.Dir(path), map[string]bool{}, 0)
}

func discoverSSHHostsIn(path, baseDir string, visited map[string]bool, depth int) ([]string, error) {
	if depth > maxIncludeDepth {
		return nil, nil
	}
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	if visited[path] {
		return nil, nil
	}
	visited[path] = true

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var hosts []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// ssh_config accepts `Keyword arg`, `Keyword=arg` and `Keyword = arg`.
		if i := strings.IndexByte(line, '='); i >= 0 && !strings.ContainsAny(line[:i], " \t") {
			line = line[:i] + " " + line[i+1:]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if fields[1] == "=" {
			fields = append(fields[:1], fields[2:]...)
			if len(fields) < 2 {
				continue
			}
		}
		switch strings.ToLower(fields[0]) {
		case "host":
			for _, alias := range fields[1:] {
				if strings.ContainsAny(alias, "*?!") {
					continue
				}
				hosts = append(hosts, alias)
			}
		case "include":
			for _, pattern := range fields[1:] {
				for _, inc := range expandInclude(pattern, baseDir) {
					sub, err := discoverSSHHostsIn(inc, baseDir, visited, depth+1)
					if err != nil {
						return nil, fmt.Errorf("include %s: %w", inc, err)
					}
					hosts = append(hosts, sub...)
				}
			}
		}
	}
	return hosts, sc.Err()
}

// expandInclude resolves one Include operand to the files it names: `~/`
// expands to the home dir, a relative path is taken against baseDir, and globs
// are expanded (filepath.Glob returns matches sorted, so discovery is stable).
// A malformed or non-matching pattern yields nothing.
func expandInclude(pattern, baseDir string) []string {
	if strings.HasPrefix(pattern, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil
		}
		pattern = filepath.Join(home, pattern[2:])
	} else if !filepath.IsAbs(pattern) {
		pattern = filepath.Join(baseDir, pattern)
	}
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil
	}
	return matches
}

// sshHostInfo is what init needs from `ssh -G alias`.
type sshHostInfo struct {
	hostname, user, port, keyAlias string
	// proxyJump / proxyCommand are set when the alias is reached through a
	// bastion or a proxy process (`none` counts as unset). Such a host is not
	// dialable at hostname:port by the signer/broker.
	proxyJump, proxyCommand string
}

// proxyVia names the indirection ("ProxyJump bastion" / "ProxyCommand ...")
// or returns "" when the host is a direct target.
func (i sshHostInfo) proxyVia() string {
	switch {
	case i.proxyJump != "":
		return "ProxyJump " + i.proxyJump
	case i.proxyCommand != "":
		return "ProxyCommand " + i.proxyCommand
	}
	return ""
}

// sshCanonicalize runs `ssh -G alias` and extracts hostname, user, port, the
// hostkeyalias (empty unless configured) and any ProxyJump/ProxyCommand.
// Returns an empty hostname on failure.
func sshCanonicalize(alias string) sshHostInfo {
	out, err := exec.Command("ssh", "-G", alias).Output()
	if err != nil {
		return sshHostInfo{}
	}
	return parseSSHG(string(out))
}

// parseSSHG extracts the fields init uses from `ssh -G` output. OpenSSH prints
// proxyjump/proxycommand only when set (older releases print `none`).
func parseSSHG(out string) sshHostInfo {
	info := sshHostInfo{port: "22"}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), " ")
		if !ok {
			continue
		}
		switch strings.ToLower(k) {
		case "hostname":
			info.hostname = v
		case "user":
			info.user = v
		case "port":
			info.port = v
		case "hostkeyalias":
			info.keyAlias = v
		case "proxyjump":
			if v != "none" {
				info.proxyJump = v
			}
		case "proxycommand":
			if v != "none" {
				info.proxyCommand = v
			}
		}
	}
	return info
}

// hostAddr builds the signer.json `addr` for a host. net.JoinHostPort brackets
// an IPv6 literal (`ssh -G` prints a bare `::1`), so the broker can dial it;
// `hostname + ":" + port` produced "::1:22" ("too many colons" at first use).
func hostAddr(hostname, port string) string {
	return net.JoinHostPort(hostname, port)
}

// hostKey resolves a host key: known_hosts first (via ssh-keygen -F, which handles
// hashed entries and [host]:port), then an ssh-keyscan TOFU fallback. Returns the
// two-field "ssh-ed25519 AAAA..." form the host_key field stores. A key taken
// from ssh-keyscan is unauthenticated (trust-on-first-use), so a one-line notice
// naming the host goes to w — the operator must be able to tell pinned-from-
// known_hosts hosts from TOFU'd ones.
func hostKey(w io.Writer, alias, hostname, port, keyAlias string) (string, error) {
	return hostKeyWith(knownHostsKey, keyscan, w, alias, hostname, port, keyAlias)
}

// hostKeyWith is hostKey with the known_hosts lookup and the keyscan injected
// (tests run without ~/.ssh or the network).
func hostKeyWith(lookup func(host, port string) string, scan func(host, port string) (string, error), w io.Writer, alias, hostname, port, keyAlias string) (string, error) {
	target := hostname
	if keyAlias != "" {
		target = keyAlias
	}
	if hk := lookup(target, port); hk != "" {
		return hk, nil
	}
	hk, err := scan(hostname, port)
	if err != nil {
		return "", err
	}
	fmt.Fprintf(w, "  note: %q (%s): no known_hosts entry — host key pinned from ssh-keyscan (trust-on-first-use; verify its fingerprint before relying on it)\n", alias, hostAddr(hostname, port))
	return hk, nil
}

// knownHostsKey queries ~/.ssh/known_hosts for host's key via ssh-keygen -F,
// preferring an ed25519 key. Returns "" if not found.
func knownHostsKey(host, port string) string {
	target := host
	if port != "" && port != "22" {
		target = "[" + host + "]:" + port
	}
	home, _ := os.UserHomeDir()
	out, err := exec.Command("ssh-keygen", "-F", target, "-f", filepath.Join(home, ".ssh", "known_hosts")).Output()
	if err != nil {
		return ""
	}
	var first string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}
		key := strings.Join(parts[1:], " ")
		if strings.HasPrefix(parts[1], "ssh-ed25519") {
			return key
		}
		if first == "" {
			first = key
		}
	}
	return first
}

// sanitizeName maps an ssh alias to a signer host name (lowercase, [a-z0-9._-]).
func sanitizeName(alias string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(alias) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	return b.String()
}
