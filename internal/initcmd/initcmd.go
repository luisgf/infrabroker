// Package initcmd implements `infrabroker init`: one command that generates a
// local PKI and writes a custody-separated two-service config (a signer that
// holds the SSH CA + a broker in remote mode), installs a default-deny starter
// policy, and prints the per-host sshd enrolment snippet — the fast path from
// zero to a policy-gated agent. Two opt-in flags extend it: --import-ssh-config
// bulk-imports hosts from ~/.ssh/config, and --register-mcp registers the stdio
// MCP with Claude Code. Remote host enrolment is NOT automated: it stays a
// printed sshd snippet the operator runs on each managed host.
package initcmd

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
)

// Run executes `infrabroker init` with args (everything after the subcommand).
// It exits the process (fatalf) on any error.
func Run(args []string) {
	fs := flag.NewFlagSet("infrabroker init", flag.ExitOnError)
	dir := fs.String("dir", ".", "directory to write the PKI and configs into")
	force := fs.Bool("force", false, "overwrite an existing PKI/config in --dir")
	importSSH := fs.Bool("import-ssh-config", false, "import hosts from ~/.ssh/config (ssh -G + known_hosts / keyscan)")
	register := fs.Bool("register-mcp", false, "register the stdio MCP with Claude Code (runs `claude mcp add`)")
	_ = fs.Parse(args)

	hosts, err := generate(*dir, *force, *importSSH)
	if err != nil {
		fatalf("%v", err)
	}
	printNextSteps(*dir, filepath.Join(*dir, "pki"), hosts)

	if *register {
		cfgAbs, _ := filepath.Abs(filepath.Join(*dir, "config.json"))
		if err := registerMCP(selfPath(), cfgAbs); err != nil {
			fmt.Fprintf(os.Stderr, "\ncould not auto-register the MCP (%v); run it manually:\n  claude mcp add infrabroker -- %s serve-mcp -config %s\n", err, selfPath(), cfgAbs)
		} else {
			fmt.Print("\nRegistered the stdio MCP with Claude Code (server name: infrabroker).\n")
		}
	}
}

// generate does the file-producing work of init and returns the hosts written.
// Split from Run — which handles flags, MCP registration and printing — so it is
// testable without exiting the process. Returns an error (not fatalf) so
// idempotency and failure paths can be asserted.
func generate(root string, force, importSSH bool) ([]starterHost, error) {
	// Resolve to an absolute root: the generated configs embed absolute PKI/audit
	// paths so they load regardless of the process CWD (the broker config is
	// launched by the MCP client from its own dir — see buildBrokerJSON, #271).
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolving --dir %q: %w", root, err)
	}
	pkiDir := filepath.Join(absRoot, "pki")

	// Idempotency: never silently clobber an existing setup.
	if !force {
		for _, p := range []string{filepath.Join(absRoot, "signer.json"), filepath.Join(absRoot, "config.json"), filepath.Join(pkiDir, "ssh_ca")} {
			if _, err := os.Stat(p); err == nil {
				return nil, fmt.Errorf("refusing to overwrite existing %s (pass --force to regenerate the PKI and configs)", p)
			}
		}
	}
	if err := os.MkdirAll(pkiDir, 0o700); err != nil {
		return nil, fmt.Errorf("creating %s: %w", pkiDir, err)
	}
	if err := generatePKI(pkiDir); err != nil {
		return nil, fmt.Errorf("generating PKI: %w", err)
	}

	hosts := collectHosts(importSSH)
	if err := writeJSONConfig(filepath.Join(absRoot, "signer.json"), buildSignerJSON(hosts, absRoot)); err != nil {
		return nil, fmt.Errorf("writing signer.json: %w", err)
	}
	if err := writeJSONConfig(filepath.Join(absRoot, "config.json"), buildBrokerJSON(absRoot)); err != nil {
		return nil, fmt.Errorf("writing config.json: %w", err)
	}
	return hosts, nil
}

// collectHosts chooses the hosts to write: the imported ~/.ssh/config hosts when
// --import-ssh-config is set (falling back to the localhost starter if the import
// finds nothing), otherwise the best-effort localhost starter alone.
func collectHosts(importSSH bool) []starterHost {
	if importSSH {
		if h := importSSHConfigHosts(); len(h) > 0 {
			return h
		}
	}
	if h := detectLocalhostHost(); h != nil {
		return []starterHost{*h}
	}
	return nil
}

// detectLocalhostHost best-effort keyscans the local sshd for a functional
// starter host. Returns nil (→ empty host list + guidance) if there is no local
// sshd or ssh-keyscan is unavailable — init never fails on this.
func detectLocalhostHost() *starterHost {
	hk, err := keyscan("127.0.0.1", "22")
	if err != nil {
		return nil
	}
	return &starterHost{name: "localhost", addr: "127.0.0.1:22", user: currentUser(), hostKey: hk}
}

// keyscan mirrors broker-ctl's sshKeyscan (cmd/broker-ctl/main.go): fetch the
// host's ed25519 key and strip the leading hostname, yielding the two-field
// "ssh-ed25519 AAAA..." form the host_key field stores.
func keyscan(host, port string) (string, error) {
	out, err := exec.Command("ssh-keyscan", "-p", port, "-t", "ed25519", host).Output()
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if parts := strings.Fields(line); len(parts) >= 3 {
			return strings.Join(parts[1:], " "), nil
		}
	}
	return "", fmt.Errorf("ssh-keyscan returned no ed25519 key for %s", host)
}

func currentUser() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return "deploy"
}

func printNextSteps(root, pkiDir string, hosts []starterHost) {
	abs := func(p string) string {
		if a, err := filepath.Abs(p); err == nil {
			return a
		}
		return p
	}
	fmt.Printf(`infrabroker init: wrote the local PKI and two-service config into %s

  pki/          SSH CA, mTLS pair, audit seeds  (lab/dev custody — keys are 0600)
  signer.json   the signer: holds the SSH CA key + policy
  config.json   the broker: remote mode, holds NO CA key

Start the two services (run from %s):
  signer      -config signer.json
  infrabroker serve-mcp -config config.json          # or serve-http / serve-mcp-http

Register the stdio MCP with Claude Code (or re-run init with --register-mcp):
  claude mcp add infrabroker -- %s serve-mcp -config %s

`, root, root, abs(selfPath()), abs(filepath.Join(root, "config.json")))

	if len(hosts) > 0 {
		var names []string
		for _, h := range hosts {
			names = append(names, fmt.Sprintf("%s (%s@%s)", h.name, h.user, h.addr))
		}
		caPub, _ := os.ReadFile(filepath.Join(pkiDir, "ssh_ca.pub"))
		fmt.Printf("%d host(s) added — review signer.json, then enrol each host's sshd. The\n"+
			"default-deny policy allows only `uptime` until you widen it (broker-ctl policy grant).\n  %s\n\n",
			len(hosts), strings.Join(names, "\n  "))
		fmt.Print(enrollSnippet(caPub, hosts[0].user, "host:"+hosts[0].name))
		if len(hosts) > 1 {
			fmt.Print("\n(Same TrustedUserCAKeys on every host; for each, add its `host:<name>` principal\nto /etc/ssh/auth_principals/<its login user>.)\n")
		}
	} else {
		fmt.Print(`No hosts were added. Import from ~/.ssh/config (infrabroker init --force --import-ssh-config),
or add one:  broker-ctl host add --name web01 --addr web01.example.com:22 --user deploy --scan --groups local
then enrol its sshd (see docs/OPERATIONS.md § Remote host configuration).

`)
	}

	fmt.Print("Note: this is a local PEM CA (lab/dev custody); the signer logs a \"lab use only\"\nwarning. For separated/HSM custody see docs/OPERATIONS.md.\n")
}

// selfPath returns the path to the running infrabroker binary, for the printed
// `claude mcp add` line; falls back to the plain name.
func selfPath() string {
	if p, err := os.Executable(); err == nil {
		return p
	}
	return "infrabroker"
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "infrabroker init: "+format+"\n", args...)
	os.Exit(1)
}
