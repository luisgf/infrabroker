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

// importSSHConfigHosts reads ~/.ssh/config, canonicalises each concrete Host alias
// with `ssh -G`, and acquires each host key (from known_hosts, falling back to an
// ssh-keyscan TOFU). Best-effort: an alias that cannot be resolved or whose key
// cannot be found is skipped with a note on stderr. Returns the importable hosts.
func importSSHConfigHosts() []starterHost {
	cfg := sshConfigPath()
	aliases, err := discoverSSHHosts(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "infrabroker init: reading %s: %v\n", cfg, err)
		return nil
	}
	var hosts []starterHost
	seen := map[string]bool{}
	for _, alias := range aliases {
		hostname, user, port, keyAlias := sshCanonicalize(alias)
		if hostname == "" {
			fmt.Fprintf(os.Stderr, "  skipped %q: ssh -G could not resolve it\n", alias)
			continue
		}
		hk, err := hostKey(os.Stderr, alias, hostname, port, keyAlias)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  skipped %q (%s): no host key — %v\n", alias, hostname, err)
			continue
		}
		name := sanitizeName(alias)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		hosts = append(hosts, starterHost{name: name, addr: hostAddr(hostname, port), user: user, hostKey: hk})
	}
	return hosts
}

func sshConfigPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".ssh", "config")
}

// discoverSSHHosts returns the concrete (non-pattern) Host aliases in an ssh
// config file. Patterns (*, ?, !) and the catch-all `Host *` are skipped — they
// are not connectable targets. A missing file yields no hosts (not an error).
func discoverSSHHosts(path string) ([]string, error) {
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
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.EqualFold(fields[0], "Host") {
			continue
		}
		for _, alias := range fields[1:] {
			if strings.ContainsAny(alias, "*?!") {
				continue
			}
			hosts = append(hosts, alias)
		}
	}
	return hosts, sc.Err()
}

// sshCanonicalize runs `ssh -G alias` and extracts hostname, user, port and the
// hostkeyalias (empty unless configured). Returns an empty hostname on failure.
func sshCanonicalize(alias string) (hostname, user, port, keyAlias string) {
	out, err := exec.Command("ssh", "-G", alias).Output()
	if err != nil {
		return "", "", "", ""
	}
	port = "22"
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), " ")
		if !ok {
			continue
		}
		switch strings.ToLower(k) {
		case "hostname":
			hostname = v
		case "user":
			user = v
		case "port":
			port = v
		case "hostkeyalias":
			keyAlias = v
		}
	}
	return hostname, user, port, keyAlias
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
