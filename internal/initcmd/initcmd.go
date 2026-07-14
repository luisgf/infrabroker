// Package initcmd implements `infrabroker init`: one command that generates a
// local PKI and writes a custody-separated two-service config (a signer that
// holds the SSH CA + a broker in remote mode), installs a default-deny starter
// policy, and prints the per-host sshd enrolment snippet — the fast path from
// zero to a policy-gated agent. It does NOT do remote enrolment (that stays a
// printed snippet), bulk ~/.ssh/config import, or MCP auto-registration.
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
	_ = fs.Parse(args)

	host, err := generate(*dir, *force)
	if err != nil {
		fatalf("%v", err)
	}
	printNextSteps(*dir, filepath.Join(*dir, "pki"), host)
}

// generate does the file-producing work of init and returns the starter host (or
// nil). Split from Run — which handles flags and prints — so it is testable
// without exiting the process. Returns an error (not fatalf) so idempotency and
// failure paths can be asserted.
func generate(root string, force bool) (*starterHost, error) {
	pkiDir := filepath.Join(root, "pki")

	// Idempotency: never silently clobber an existing setup.
	if !force {
		for _, p := range []string{filepath.Join(root, "signer.json"), filepath.Join(root, "config.json"), filepath.Join(pkiDir, "ssh_ca")} {
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

	host := detectLocalhostHost()
	if err := writeJSONConfig(filepath.Join(root, "signer.json"), buildSignerJSON(host)); err != nil {
		return nil, fmt.Errorf("writing signer.json: %w", err)
	}
	if err := writeJSONConfig(filepath.Join(root, "config.json"), buildBrokerJSON()); err != nil {
		return nil, fmt.Errorf("writing config.json: %w", err)
	}
	return host, nil
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

func printNextSteps(root, pkiDir string, host *starterHost) {
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

Register the stdio MCP with Claude Code:
  claude mcp add infrabroker -- %s serve-mcp -config %s

`, root, root, abs(selfPath()), abs(filepath.Join(root, "config.json")))

	if host != nil {
		caPub, _ := os.ReadFile(filepath.Join(pkiDir, "ssh_ca.pub"))
		fmt.Printf(`A starter host %q (%s@%s) was added. The default-deny policy allows only
`+"`uptime`"+` until you widen it — e.g. broker-ctl policy grant --host %s --allow '^systemctl status '.

Enrol its sshd so it trusts the CA:

%s`, host.name, host.user, host.addr, host.name, enrollSnippet(caPub, host.user, "host:"+host.name))
	} else {
		fmt.Print(`No local sshd was reachable, so no starter host was added. Add your first host:
  broker-ctl host add --name web01 --addr web01.example.com:22 --user deploy --scan --groups local
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
