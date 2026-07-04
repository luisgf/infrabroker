// broker-ctl manages the signer configuration (signer.json), triggers reloads,
// and allows reviewing audit logs.
//
// --config is a global option and must precede the subcommand:
//
//	broker-ctl [--config f] host add    [flags]     # Add or update a host
//	broker-ctl [--config f] host list               # List configured hosts
//	broker-ctl [--config f] host remove <name>      # Remove a host
//	broker-ctl [--config f] ca-keys add  [flags]    # Add or update a CA key entry
//	broker-ctl [--config f] ca-keys list            # List CA key entries
//	broker-ctl [--config f] ca-keys remove <name>   # Remove a CA key entry
//	broker-ctl [--config f] callers add  [flags]    # Add or update a caller entry
//	broker-ctl [--config f] callers list            # List caller entries
//	broker-ctl [--config f] callers remove <cn>     # Remove a caller entry
//	broker-ctl [--config f] reload      [flags]     # Reload signer
//	broker-ctl audit tail   --log <f> [-n N]        # Follow log in real time
//	broker-ctl audit show   --log <f> [filters]     # Search/filter entries
//	broker-ctl audit verify --log <f> [--key seed]  # Verify chain integrity
//	broker-ctl --version [--verbose]                # Print the build version
package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/luisgf/infrabroker/internal/audit"
	"github.com/luisgf/infrabroker/internal/version"
)

// configPath is the path to signer.json. It is a global option, parsed before
// the subcommand (broker-ctl --config f <command> ...). Unlike the rest of the
// CLI, subcommands no longer accept their own --config: a single, leading flag
// keeps broker-ctl consistent with the other binaries (signer, broker, ...),
// which all take --config at the top level.
var configPath = "./signer.json"

func main() {
	cfg, args, showVersion, verbose, err := parseGlobalFlags(os.Args[1:])
	if err != nil {
		usageTop()
		os.Exit(2)
	}
	configPath = cfg

	if showVersion {
		version.Print(verbose)
		return
	}

	if len(args) == 0 {
		usageTop()
		os.Exit(1)
	}
	switch args[0] {
	case "host":
		cmdHost(args[1:])
	case "ca-keys":
		cmdCAKeys(args[1:])
	case "callers":
		cmdCallers(args[1:])
	case "reload":
		cmdReload(args[1:])
	case "approval":
		cmdApproval(args[1:])
	case "audit":
		cmdAudit(args[1:])
	case "policy":
		cmdPolicy(args[1:])
	case "cluster":
		cmdCluster(args[1:])
	case "version":
		cmdVersion(args[1:])
	case "help":
		usageTop()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %q\n", args[0])
		usageTop()
		os.Exit(1)
	}
}

// parseGlobalFlags parses the leading global flags (--config, --version,
// --verbose) up to the subcommand. Go's flag package stops at the first non-flag
// argument, so any flags belonging to the subcommand (e.g. audit show --log) are
// returned untouched in rest for that subcommand's own FlagSet to parse. It uses
// ContinueOnError so it is unit-testable; main() turns a parse error into the
// top-level usage and a non-zero exit.
func parseGlobalFlags(args []string) (cfg string, rest []string, showVersion, verbose bool, err error) {
	fs := flag.NewFlagSet("broker-ctl", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	c := fs.String("config", "./signer.json", "path to signer.json")
	cc := fs.String("client-config", "", "path to the broker-ctl client parameters file (default search: $BROKER_CTL_CONFIG, ~/.config/broker-ctl/config.json, /etc/infrabroker/broker-ctl.json; the CWD is not searched)")
	sv := fs.Bool("version", false, "print version and exit")
	vb := fs.Bool("verbose", false, "with --version, print detailed build info")
	if perr := fs.Parse(args); perr != nil {
		return "", nil, false, false, perr
	}
	clientConfigPath = *cc
	return *c, fs.Args(), *sv, *vb, nil
}

// cmdVersion implements `broker-ctl version [--verbose]`, the subcommand twin of
// the global --version flag (short by default, detailed with --verbose).
func cmdVersion(args []string) {
	fs := flag.NewFlagSet("version", flag.ExitOnError)
	verbose := fs.Bool("verbose", false, "print detailed build info")
	must(fs.Parse(args))
	version.Print(*verbose)
}

func usageTop() {
	fmt.Fprintln(os.Stderr, `broker-ctl — infrabroker configuration management

Usage:
  broker-ctl [--config f] [--client-config f] <command> [args]

Commands:
  broker-ctl host add      [flags]                          Add or update a host
  broker-ctl host list     [--remote]                       List configured hosts (--remote: live from the signer, mTLS)
  broker-ctl host remove   <name>                           Remove a host
  broker-ctl ca-keys add   --name <n> [flags]               Add or update a CA key entry
  broker-ctl ca-keys list                                   List configured CA keys
  broker-ctl ca-keys remove <name>                          Remove a CA key entry
  broker-ctl callers add   --name <cn> [flags]              Add or update a caller
  broker-ctl callers list                                   List configured callers
  broker-ctl callers remove <cn>                            Remove a caller
  broker-ctl reload        [flags]                          Reload the signer
  broker-ctl approval list  [flags]                         List approval requests
  broker-ctl approval allow <id> [--learn --ttl 2h]         Approve a request (--learn waives re-approval for the TTL)
  broker-ctl approval deny  <id> [flags]                    Deny a request
  broker-ctl audit tail    --log <f> [-n N]                 Follow audit log in real time
  broker-ctl audit show    --log <f> [filters]              Search and filter log entries
  broker-ctl audit verify  --log <f> [--key seed]           Verify chain integrity
  broker-ctl policy explain --host <n> [--command c]        Show a host's composed command policy
  broker-ctl policy recommend --audit <f> [filters]         Suggest policy changes from the audit log
  broker-ctl policy add     --host <n> --allow <regex>      Add a command-policy allow rule (signer API, mTLS)
  broker-ctl policy remove  --host <n> --allow <regex>      Remove a command-policy allow rule
  broker-ctl policy grant   --host <n> --allow <regex> [--ttl 2h]  Create a runtime, expiring grant (signer API, mTLS)
  broker-ctl policy grants  [--json]                        List active runtime grants
  broker-ctl policy revoke  <grant-id>                      Revoke a runtime grant
  broker-ctl cluster list  --remote                         List Kubernetes clusters live from the signer (mTLS)
  broker-ctl version       [--verbose]                      Print the build version

Global options:
  --config         Path to signer.json (default: ./signer.json), before the subcommand
  --client-config  Path to the client parameters file for the remote commands
  --version        Print the build version and exit (--verbose for details)

Client parameters (remote commands: reload, policy add/remove/grant/grants/revoke,
approval, host list --remote):
  Per-parameter precedence: flag > env var > client config file > default.
  File search order: --client-config, $BROKER_CTL_CONFIG,
  ~/.config/broker-ctl/config.json, /etc/infrabroker/broker-ctl.json (the current
  working directory is not searched; use --client-config for a local file).
  Sections "signer" and "control_plane", each with url/cert/key/ca (see broker-ctl.example.json).
  Env vars: BROKER_CTL_SIGNER_{URL,CERT,KEY,CA}, BROKER_CTL_CP_{URL,CERT,KEY,CA}.`)
}

// ── host ──────────────────────────────────────────────────────────────────────

func cmdHost(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: broker-ctl host {add|list|remove} [args]")
		os.Exit(1)
	}
	switch args[0] {
	case "add":
		cmdHostAdd(args[1:])
	case "list":
		cmdHostList(args[1:])
	case "remove", "rm", "del":
		cmdHostRemove(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown host subcommand: %q\n", args[0])
		os.Exit(1)
	}
}

func cmdHostAdd(args []string) {
	fs := flag.NewFlagSet("host add", flag.ExitOnError)
	name := fs.String("name", "", "logical host name (required)")
	addr := fs.String("addr", "", "host:port of the SSH server (required)")
	user := fs.String("user", "", "remote SSH account (required)")
	hostKey := fs.String("host-key", "", "host key in authorized_keys format (or '-' to read from stdin)")
	scan := fs.Bool("scan", false, "fetch host key automatically with ssh-keyscan")
	principal := fs.String("principal", "", "SSH principal in the cert (default: host:<name>)")
	ttl := fs.Int("ttl", 120, "max_ttl_seconds")
	jump := fs.String("jump", "", "logical name of the preceding bastion")
	srcAddr := fs.String("source-address", "", "bastion egress IP/CIDR")
	sudo := fs.Bool("sudo", false, "allow_sudo=true")
	sudoUsers := fs.String("sudo-users", "", "allowed_sudo_users comma-separated")
	pty := fs.Bool("pty", false, "allow_pty=true")
	fileTransfer := fs.Bool("file-transfer", false, "allow_file_transfer=true (ssh_put_file / ssh_get_file)")
	groups := fs.String("groups", "", "RBAC groups comma-separated")
	callers := fs.String("callers", "", "allowed CNs comma-separated (per-host restriction)")
	bastion := fs.Bool("bastion", false, "allow_as_bastion=true")
	force := fs.Bool("force", false, "overwrite if already exists")
	pMode := fs.String("policy-mode", "", "command policy mode: allowlist|denylist|off")
	pEnforcement := fs.String("policy-enforcement", "", "command policy enforcement: enforce|audit")
	pAllow := fs.String("allow", "", "allowlist patterns, comma-separated regex")
	pDeny := fs.String("deny", "", "denylist patterns, comma-separated regex")
	pApprove := fs.String("require-approval", "", "require-approval patterns, comma-separated regex")
	pShell := fs.Bool("shell-parse", false, "parse commands as POSIX sh before policy evaluation")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: broker-ctl host add --name <n> --addr <h:p> --user <u> {--host-key <k>|--scan} [flags]")
		fs.PrintDefaults()
	}
	must(fs.Parse(args))

	if *name == "" || *addr == "" || *user == "" {
		fs.Usage()
		os.Exit(1)
	}
	if !*scan && *hostKey == "" {
		fmt.Fprintln(os.Stderr, "error: --host-key or --scan is required")
		fs.Usage()
		os.Exit(1)
	}
	if *scan && *hostKey != "" {
		fmt.Fprintln(os.Stderr, "error: --host-key and --scan are mutually exclusive")
		os.Exit(1)
	}

	hk, err := acquireHostKey(*scan, *hostKey, *addr)
	if err != nil {
		fatalf("host key: %v", err)
	}
	if *principal == "" {
		*principal = "host:" + *name
	}

	hp := hostEntry{
		Addr:          *addr,
		User:          *user,
		HostKey:       hk,
		Principal:     *principal,
		MaxTTLSeconds: *ttl,
	}
	if *jump != "" {
		hp.Jump = *jump
	}
	if *srcAddr != "" {
		hp.SourceAddress = *srcAddr
	}
	if *bastion {
		hp.AllowAsBastion = true
	}
	if *sudo {
		hp.AllowSudo = true
	}
	if *sudoUsers != "" {
		hp.AllowedSudoUsers = splitComma(*sudoUsers)
	}
	if *pty {
		hp.AllowPTY = true
	}
	if *fileTransfer {
		hp.AllowFileTransfer = true
	}
	if *groups != "" {
		hp.Groups = splitComma(*groups)
	}
	if *callers != "" {
		hp.AllowedCallers = splitComma(*callers)
	}

	// Record which flags were explicitly set: a --force update must only
	// override the fields the user actually passed (see mergeUnsetHostFields).
	setFlags := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { setFlags[f.Name] = true })
	policySet := setFlags["policy-mode"] || setFlags["policy-enforcement"] || setFlags["allow"] || setFlags["deny"] ||
		setFlags["require-approval"] || setFlags["shell-parse"]

	raw, err := loadRaw(configPath)
	if err != nil {
		fatalf("reading config: %v", err)
	}
	hosts, err := extractHosts(raw)
	if err != nil {
		fatalf("parsing hosts: %v", err)
	}

	// Check existence before modifying; on --force start from the existing
	// entry and override only the explicitly set flags.
	action := "added"
	hostExisted := false
	var existingPolicy json.RawMessage
	if existing, exists := hosts[*name]; exists {
		if !*force {
			fatalf("host %q already exists (use --force to overwrite)", *name)
		}
		action = "updated"
		hostExisted = true
		existingPolicy = existing.CommandPolicy
		mergeUnsetHostFields(&hp, existing, setFlags)
		if !policySet {
			hp.CommandPolicy = existing.CommandPolicy
		}
	}
	if policySet {
		var cp json.RawMessage
		var cerr error
		if hostExisted {
			// Field-granular merge: a --force update must override only the policy
			// sub-fields whose flags were set, not rebuild the whole policy from
			// defaults — otherwise omitting --policy-mode silently downgrades the
			// host to mode=off (firewall disabled, sessions re-enabled).
			cp, cerr = mergeCommandPolicyJSON(existingPolicy, setFlags, *pMode, *pEnforcement, *pAllow, *pDeny, *pApprove, *pShell)
		} else {
			cp, cerr = buildCommandPolicyJSON(*pMode, *pEnforcement, *pAllow, *pDeny, *pApprove, *pShell)
		}
		if cerr != nil {
			fatalf("command policy: %v", cerr)
		}
		hp.CommandPolicy = cp
	}

	hosts[*name] = hp
	if err := writeHosts(configPath, raw, hosts); err != nil {
		fatalf("writing config: %v", err)
	}
	fmt.Printf("host %q %s (addr=%s, user=%s, principal=%s)\n", *name, action, hp.Addr, hp.User, hp.Principal)
}

// mergeUnsetHostFields copies from existing every field whose flag the user
// did not explicitly set, so a --force update only overrides the requested
// fields instead of silently resetting the rest to flag defaults. Flags set
// to an explicit empty value (e.g. --groups "") still override, because
// flag.Visit fires for them. addr, user and host-key/scan are required flags,
// so they are always explicitly set and never merged from existing.
func mergeUnsetHostFields(hp *hostEntry, existing hostEntry, set map[string]bool) {
	if !set["principal"] {
		hp.Principal = existing.Principal
	}
	if !set["ttl"] {
		hp.MaxTTLSeconds = existing.MaxTTLSeconds
	}
	if !set["jump"] {
		hp.Jump = existing.Jump
	}
	if !set["source-address"] {
		hp.SourceAddress = existing.SourceAddress
	}
	if !set["bastion"] {
		hp.AllowAsBastion = existing.AllowAsBastion
	}
	if !set["sudo"] {
		hp.AllowSudo = existing.AllowSudo
	}
	if !set["sudo-users"] {
		hp.AllowedSudoUsers = existing.AllowedSudoUsers
	}
	if !set["pty"] {
		hp.AllowPTY = existing.AllowPTY
	}
	if !set["file-transfer"] {
		hp.AllowFileTransfer = existing.AllowFileTransfer
	}
	if !set["groups"] {
		hp.Groups = existing.Groups
	}
	if !set["callers"] {
		hp.AllowedCallers = existing.AllowedCallers
	}
}

// acquireHostKey resolves the host key from --host-key / stdin / ssh-keyscan.
func acquireHostKey(scan bool, hostKeyFlag, addr string) (string, error) {
	if scan {
		host, port, err := splitHostPortDefault(addr)
		if err != nil {
			return "", fmt.Errorf("parsing addr %q: %w", addr, err)
		}
		return sshKeyscan(host, port)
	}
	if hostKeyFlag == "-" {
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(os.Stdin); err != nil {
			return "", fmt.Errorf("reading stdin: %w", err)
		}
		return strings.TrimSpace(buf.String()), nil
	}
	return hostKeyFlag, nil
}

// commandPolicyJSON is the wire shape of a host command_policy, shared by the
// build (new host) and merge (--force update) paths.
type commandPolicyJSON struct {
	Mode            string   `json:"mode,omitempty"`
	Enforcement     string   `json:"enforcement,omitempty"`
	Allow           []string `json:"allow,omitempty"`
	Deny            []string `json:"deny,omitempty"`
	RequireApproval []string `json:"require_approval,omitempty"`
	ShellParse      bool     `json:"shell_parse,omitempty"`
}

// buildCommandPolicyJSON marshals command-policy flag values into a RawMessage.
func buildCommandPolicyJSON(mode, enforcement, allow, deny, requireApproval string, shellParse bool) (json.RawMessage, error) {
	p := commandPolicyJSON{
		Mode:            mode,
		Enforcement:     enforcement,
		Allow:           splitComma(allow),
		Deny:            splitComma(deny),
		RequireApproval: splitComma(requireApproval),
		ShellParse:      shellParse,
	}
	b, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// mergeCommandPolicyJSON applies the command-policy flags onto the existing
// policy, overriding only the sub-fields whose flags the operator explicitly
// set. This makes a --force command_policy update field-granular like every
// other host field, so a partial change (e.g. appending a require_approval
// pattern, or flipping --shell-parse) cannot silently erase the allow/deny
// rules and turn a firewalled host fully permissive.
func mergeCommandPolicyJSON(existing json.RawMessage, set map[string]bool, mode, enforcement, allow, deny, requireApproval string, shellParse bool) (json.RawMessage, error) {
	var p commandPolicyJSON
	if len(existing) > 0 {
		if err := json.Unmarshal(existing, &p); err != nil {
			return nil, fmt.Errorf("parsing existing command_policy: %w", err)
		}
	}
	if set["policy-mode"] {
		p.Mode = mode
	}
	if set["policy-enforcement"] {
		p.Enforcement = enforcement
	}
	if set["allow"] {
		p.Allow = splitComma(allow)
	}
	if set["deny"] {
		p.Deny = splitComma(deny)
	}
	if set["require-approval"] {
		p.RequireApproval = splitComma(requireApproval)
	}
	if set["shell-parse"] {
		p.ShellParse = shellParse
	}
	b, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// commandPolicyLabel returns a short human-readable summary of a command_policy
// JSON blob (e.g. "allowlist(2)", "denylist(1)", "approval(1)", "off", "—").
func commandPolicyLabel(raw json.RawMessage) string {
	if len(raw) == 0 {
		return "—"
	}
	var p struct {
		Mode            string   `json:"mode"`
		Enforcement     string   `json:"enforcement"`
		Allow           []string `json:"allow"`
		Deny            []string `json:"deny"`
		RequireApproval []string `json:"require_approval"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return "?"
	}
	var label string
	switch p.Mode {
	case "allowlist":
		label = fmt.Sprintf("allowlist(%d)", len(p.Allow))
	case "denylist":
		label = fmt.Sprintf("denylist(%d)", len(p.Deny))
	case "off":
		if len(p.RequireApproval) > 0 {
			label = fmt.Sprintf("off+approval(%d)", len(p.RequireApproval))
		} else {
			label = "off"
		}
	default: // "" or unknown
		if len(p.RequireApproval) > 0 {
			label = fmt.Sprintf("approval(%d)", len(p.RequireApproval))
		} else {
			label = "—"
		}
	}
	if p.Enforcement == "audit" && label != "—" {
		label += " audit"
	}
	return label
}

func cmdHostList(args []string) {
	fs := flag.NewFlagSet("host list", flag.ExitOnError)
	remote := fs.Bool("remote", false, "read the live policy from the signer over mTLS instead of the local config file")
	urlFlag, cert, key, ca := signerFlags(fs)
	must(fs.Parse(args))

	var hosts map[string]hostEntry
	if *remote {
		resolveSignerTarget(fs)
		client, base := policyHTTP(*urlFlag, *cert, *key, *ca)
		var err error
		hosts, err = fetchRemoteHosts(client, base)
		if err != nil {
			fatalf("%v", err)
		}
	} else {
		raw, err := loadRaw(configPath)
		if err != nil {
			fatalf("reading config: %v", err)
		}
		hosts, err = extractHosts(raw)
		if err != nil {
			fatalf("parsing hosts: %v", err)
		}
	}
	renderHostTable(os.Stdout, hosts)
}

// fetchRemoteHosts retrieves the full host-policy table from the signer's
// GET /v1/policy/hosts. The response uses the same schema as the signer.json
// "hosts" table, so it decodes straight into hostEntry and both modes render
// identically. A non-200 is a hard failure — deliberately no fallback to the
// reduced GET /v1/hosts view, whose blank PRINCIPAL/TTL/CALLERS/POLICY columns
// would read as "no policy configured".
func fetchRemoteHosts(client *http.Client, base string) (map[string]hostEntry, error) {
	resp, err := client.Get(base + "/v1/policy/hosts")
	if err != nil {
		return nil, fmt.Errorf("GET %s/v1/policy/hosts: %w", base, err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("signer rejected the request (HTTP %d): %s\nhint: the client cert CN must be in the signer's reload_callers (GET /v1/hosts is the caller-scoped connectivity view)",
			resp.StatusCode, strings.TrimSpace(string(rb)))
	}
	var hosts map[string]hostEntry
	if err := json.Unmarshal(rb, &hosts); err != nil {
		return nil, fmt.Errorf("decoding host policy: %w", err)
	}
	return hosts, nil
}

// renderHostTable prints the host-policy table; shared by the local and
// remote modes of `host list` so both render the exact same columns.
func renderHostTable(out io.Writer, hosts map[string]hostEntry) {
	if len(hosts) == 0 {
		fmt.Fprintln(out, "(no hosts configured)")
		return
	}

	names := make([]string, 0, len(hosts))
	for n := range hosts {
		names = append(names, n)
	}
	sort.Strings(names)

	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tADDR\tUSER\tPRINCIPAL\tTTL\tJUMP\tSRC_ADDR\tSUDO\tSUDO_USERS\tPTY\tFT\tBASTION\tGROUPS\tCALLERS\tPOLICY")
	for _, n := range names {
		h := hosts[n]
		jump := dash(h.Jump)
		srcAddr := dash(h.SourceAddress)
		sudoUsers := dashJoin(h.AllowedSudoUsers)
		grps := dashJoin(h.Groups)
		callers := dashJoin(h.AllowedCallers)
		policy := commandPolicyLabel(h.CommandPolicy)
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			n, h.Addr, h.User, h.Principal,
			strconv.Itoa(h.MaxTTLSeconds)+"s",
			jump, srcAddr,
			boolStr(h.AllowSudo), sudoUsers,
			boolStr(h.AllowPTY), boolStr(h.AllowFileTransfer), boolStr(h.AllowAsBastion),
			grps, callers, policy)
	}
	w.Flush()
}

func cmdHostRemove(args []string) {
	fs := flag.NewFlagSet("host remove", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: broker-ctl [--config f] host remove <name>")
	}
	must(fs.Parse(args))

	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(1)
	}
	name := fs.Arg(0)

	raw, err := loadRaw(configPath)
	if err != nil {
		fatalf("reading config: %v", err)
	}
	hosts, err := extractHosts(raw)
	if err != nil {
		fatalf("parsing hosts: %v", err)
	}
	if _, exists := hosts[name]; !exists {
		fatalf("host %q not found", name)
	}

	delete(hosts, name)
	if err := writeHosts(configPath, raw, hosts); err != nil {
		fatalf("writing config: %v", err)
	}
	fmt.Printf("host %q removed\n", name)
}

// ── ca-keys ───────────────────────────────────────────────────────────────────

// caKeyEntry models only the ca.CAKeyConfig fields that broker-ctl can set via
// flags; it is used to build new entries and to render the list view. Entries
// are stored as raw JSON (see extractCAKeys) so the fields not modeled here
// (key_version, tenant_id, client_id, client_secret_env) are never stripped
// from entries broker-ctl does not touch.
type caKeyEntry struct {
	Type     string `json:"type"`
	Path     string `json:"path,omitempty"`
	VaultURL string `json:"vault_url,omitempty"`
	KeyName  string `json:"key_name,omitempty"`
}

func cmdCAKeys(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: broker-ctl ca-keys {add|list|remove} [args]")
		os.Exit(1)
	}
	switch args[0] {
	case "add":
		cmdCAKeysAdd(args[1:])
	case "list":
		cmdCAKeysList(args[1:])
	case "remove", "rm":
		cmdCAKeysRemove(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown ca-keys subcommand: %q\n", args[0])
		os.Exit(1)
	}
}

func cmdCAKeysAdd(args []string) {
	fs := flag.NewFlagSet("ca-keys add", flag.ExitOnError)
	name := fs.String("name", "", "entry name: _default or a group name (required)")
	keyType := fs.String("type", "", "backend type: pem|akv (required)")
	path := fs.String("path", "", "PEM file path (type=pem)")
	vaultURL := fs.String("vault-url", "", "AKV vault URL (type=akv)")
	keyName := fs.String("key-name", "", "AKV key name (type=akv)")
	force := fs.Bool("force", false, "overwrite if already exists")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage:\n  broker-ctl ca-keys add --name <n> --type pem --path <f>\n  broker-ctl ca-keys add --name <n> --type akv --vault-url <u> --key-name <k>")
		fs.PrintDefaults()
	}
	must(fs.Parse(args))

	if *name == "" || *keyType == "" {
		fs.Usage()
		os.Exit(1)
	}
	switch *keyType {
	case "pem":
		if *path == "" {
			fatalf("--path is required for type=pem")
		}
	case "akv":
		if *vaultURL == "" || *keyName == "" {
			fatalf("--vault-url and --key-name are required for type=akv")
		}
	default:
		fatalf("unsupported type %q: use pem or akv", *keyType)
	}

	// The new entry contains exactly the fields provided via flags (omitempty
	// drops the rest); existing entries are left untouched as raw JSON.
	entryJSON, err := json.Marshal(caKeyEntry{Type: *keyType, Path: *path, VaultURL: *vaultURL, KeyName: *keyName})
	if err != nil {
		fatalf("serialising entry: %v", err)
	}

	raw, err := loadRaw(configPath)
	if err != nil {
		fatalf("reading config: %v", err)
	}
	keys, err := extractCAKeys(raw)
	if err != nil {
		fatalf("parsing ca_keys: %v", err)
	}

	action := "added"
	if _, exists := keys[*name]; exists {
		if !*force {
			fatalf("ca-key %q already exists (use --force to overwrite)", *name)
		}
		action = "updated"
	}
	keys[*name] = entryJSON
	if err := writeCAKeys(configPath, raw, keys); err != nil {
		fatalf("writing config: %v", err)
	}
	fmt.Printf("ca-key %q %s (type=%s)\n", *name, action, *keyType)
}

func cmdCAKeysList(args []string) {
	fs := flag.NewFlagSet("ca-keys list", flag.ExitOnError)
	must(fs.Parse(args))

	raw, err := loadRaw(configPath)
	if err != nil {
		fatalf("reading config: %v", err)
	}
	keys, err := extractCAKeys(raw)
	if err != nil {
		fatalf("parsing ca_keys: %v", err)
	}

	if len(keys) == 0 {
		fmt.Println("(no ca-keys configured)")
		return
	}

	names := make([]string, 0, len(keys))
	for n := range keys {
		names = append(names, n)
	}
	sort.Strings(names)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tTYPE\tDETAIL")
	for _, n := range names {
		var k caKeyEntry
		if err := json.Unmarshal(keys[n], &k); err != nil {
			fatalf("parsing ca_keys entry %q: %v", n, err)
		}
		detail := k.Path
		if k.Type == "akv" {
			detail = k.VaultURL + " (key: " + k.KeyName + ")"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n", n, k.Type, detail)
	}
	w.Flush()
}

func cmdCAKeysRemove(args []string) {
	fs := flag.NewFlagSet("ca-keys remove", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: broker-ctl [--config f] ca-keys remove <name>")
	}
	must(fs.Parse(args))

	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(1)
	}
	name := fs.Arg(0)

	raw, err := loadRaw(configPath)
	if err != nil {
		fatalf("reading config: %v", err)
	}
	keys, err := extractCAKeys(raw)
	if err != nil {
		fatalf("parsing ca_keys: %v", err)
	}
	if _, exists := keys[name]; !exists {
		fatalf("ca-key %q not found", name)
	}

	delete(keys, name)
	if err := writeCAKeys(configPath, raw, keys); err != nil {
		fatalf("writing config: %v", err)
	}
	fmt.Printf("ca-key %q removed\n", name)
}

// extractCAKeys extracts the "ca_keys" map from the raw map, keeping each
// entry as raw JSON. Only the entry being added or removed is ever decoded or
// encoded, so all other entries round-trip untouched — the same
// preserve-unknown-fields approach loadRaw applies to the top-level config.
func extractCAKeys(raw map[string]json.RawMessage) (map[string]json.RawMessage, error) {
	keysRaw, ok := raw["ca_keys"]
	if !ok {
		return map[string]json.RawMessage{}, nil
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(keysRaw, &keys); err != nil {
		return nil, err
	}
	if keys == nil {
		keys = map[string]json.RawMessage{}
	}
	return keys, nil
}

// writeCAKeys serialises ca_keys back into the raw map and writes the file.
func writeCAKeys(path string, raw map[string]json.RawMessage, keys map[string]json.RawMessage) error {
	keysJSON, err := json.MarshalIndent(keys, "  ", "  ")
	if err != nil {
		return err
	}
	raw["ca_keys"] = keysJSON
	return writeRaw(path, raw)
}

// ── callers ───────────────────────────────────────────────────────────────────

// callerEntry is the JSON representation of a caller in the callers map.
// AllowedGroups has no omitempty so an empty list serialises as [] (not omitted),
// matching signer.CallerPolicy behaviour.
type callerEntry struct {
	AllowedGroups []string `json:"allowed_groups"`
}

func cmdCallers(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: broker-ctl callers {add|list|remove} [args]")
		os.Exit(1)
	}
	switch args[0] {
	case "add":
		cmdCallersAdd(args[1:])
	case "list":
		cmdCallersList(args[1:])
	case "remove", "rm":
		cmdCallersRemove(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown callers subcommand: %q\n", args[0])
		os.Exit(1)
	}
}

func cmdCallersAdd(args []string) {
	fs := flag.NewFlagSet("callers add", flag.ExitOnError)
	name := fs.String("name", "", "mTLS cert CN (required)")
	groups := fs.String("groups", "", "allowed_groups comma-separated (required)")
	force := fs.Bool("force", false, "overwrite if already exists")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: broker-ctl [--config f] callers add --name <cn> --groups <g1,g2>")
		fmt.Fprintln(os.Stderr, "An explicitly-empty --groups \"\" denies every host to the CN; with")
		fmt.Fprintln(os.Stderr, "--name _default it makes the callers table default-deny for unlisted CNs.")
		fs.PrintDefaults()
	}
	must(fs.Parse(args))

	// An explicitly-passed empty --groups is a deny-all policy (meaningful for
	// any CN, and the only way to express the "_default" deny-all entry); an
	// omitted --groups is still a usage error.
	groupsSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "groups" {
			groupsSet = true
		}
	})
	if *name == "" || !groupsSet {
		fs.Usage()
		os.Exit(1)
	}
	entry := callerEntry{AllowedGroups: splitComma(*groups)}
	if entry.AllowedGroups == nil {
		entry.AllowedGroups = []string{} // marshal as [] rather than null
	}

	raw, err := loadRaw(configPath)
	if err != nil {
		fatalf("reading config: %v", err)
	}
	callers, err := extractCallers(raw)
	if err != nil {
		fatalf("parsing callers: %v", err)
	}

	action := "added"
	if _, exists := callers[*name]; exists {
		if !*force {
			fatalf("caller %q already exists (use --force to overwrite)", *name)
		}
		action = "updated"
	}
	callers[*name] = entry
	if err := writeCallers(configPath, raw, callers); err != nil {
		fatalf("writing config: %v", err)
	}
	fmt.Printf("caller %q %s (groups=%s)\n", *name, action, *groups)
}

func cmdCallersList(args []string) {
	fs := flag.NewFlagSet("callers list", flag.ExitOnError)
	must(fs.Parse(args))

	raw, err := loadRaw(configPath)
	if err != nil {
		fatalf("reading config: %v", err)
	}
	callers, err := extractCallers(raw)
	if err != nil {
		fatalf("parsing callers: %v", err)
	}

	if len(callers) == 0 {
		fmt.Println("(no callers configured)")
		return
	}

	names := make([]string, 0, len(callers))
	for n := range callers {
		names = append(names, n)
	}
	sort.Strings(names)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tALLOWED_GROUPS")
	for _, n := range names {
		c := callers[n]
		grps := dashJoin(c.AllowedGroups)
		fmt.Fprintf(w, "%s\t%s\n", n, grps)
	}
	w.Flush()
}

func cmdCallersRemove(args []string) {
	fs := flag.NewFlagSet("callers remove", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: broker-ctl [--config f] callers remove <cn>")
	}
	must(fs.Parse(args))

	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(1)
	}
	name := fs.Arg(0)

	raw, err := loadRaw(configPath)
	if err != nil {
		fatalf("reading config: %v", err)
	}
	callers, err := extractCallers(raw)
	if err != nil {
		fatalf("parsing callers: %v", err)
	}
	if _, exists := callers[name]; !exists {
		fatalf("caller %q not found", name)
	}

	delete(callers, name)
	if err := writeCallers(configPath, raw, callers); err != nil {
		fatalf("writing config: %v", err)
	}
	fmt.Printf("caller %q removed\n", name)
}

// extractCallers extracts and parses the "callers" key from the raw map.
func extractCallers(raw map[string]json.RawMessage) (map[string]callerEntry, error) {
	callersRaw, ok := raw["callers"]
	if !ok {
		return map[string]callerEntry{}, nil
	}
	var callers map[string]callerEntry
	if err := json.Unmarshal(callersRaw, &callers); err != nil {
		return nil, err
	}
	if callers == nil {
		callers = map[string]callerEntry{}
	}
	return callers, nil
}

// writeCallers serialises callers back into the raw map and writes the file.
func writeCallers(path string, raw map[string]json.RawMessage, callers map[string]callerEntry) error {
	callersJSON, err := json.MarshalIndent(callers, "  ", "  ")
	if err != nil {
		return err
	}
	raw["callers"] = callersJSON
	return writeRaw(path, raw)
}

// ── reload ────────────────────────────────────────────────────────────────────

func cmdReload(args []string) {
	fs := flag.NewFlagSet("reload", flag.ExitOnError)
	pidFile := fs.String("pid-file", "./signer.pid", "path to signer PID file")
	urlFlag, cert, key, ca := signerFlags(fs)
	must(fs.Parse(args))

	// Try local SIGHUP first, but only when we can confirm the PID really is the
	// signer (not a recycled PID belonging to another process). Otherwise fall
	// through to the authenticated HTTP reload.
	if pid, err := readPID(*pidFile); err == nil {
		if isSignerProcess(pid) {
			if err := syscall.Kill(pid, syscall.SIGHUP); err != nil {
				fatalf("SIGHUP to PID %d: %v", pid, err)
			}
			fmt.Printf("SIGHUP sent to signer (PID %d)\n", pid)
			return
		}
		if isAlive(pid) {
			fmt.Fprintf(os.Stderr, "note: PID %d from %s does not look like the signer; using HTTP reload\n", pid, *pidFile)
		}
	}

	// Fallback: POST /v1/reload via mTLS.
	resolveSignerTarget(fs)
	client, base := policyHTTP(*urlFlag, *cert, *key, *ca)
	url := base + "/v1/reload"
	resp, err := client.Post(url, "application/json", nil)
	if err != nil {
		fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()

	var result struct {
		Status string `json:"status"`
		Hosts  int    `json:"hosts"`
		Error  string `json:"error,omitempty"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		fatalf("parse response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		fatalf("signer rejected reload (HTTP %d): %s", resp.StatusCode, result.Error)
	}
	fmt.Printf("signer reloaded via HTTP (hosts: %d)\n", result.Hosts)
}

// ── approval (control plane) ──────────────────────────────────────────────────

func cmdApproval(args []string) {
	if len(args) < 1 {
		fatalf("usage: broker-ctl approval <list|allow|deny> [id] [flags]")
	}
	switch args[0] {
	case "list":
		cmdApprovalList(args[1:])
	case "allow", "approve":
		cmdApprovalDecide(args[1:], true)
	case "deny", "reject":
		cmdApprovalDecide(args[1:], false)
	default:
		fatalf("unknown approval subcommand: %q (list|allow|deny)", args[0])
	}
}

// approvalFlags registers common mTLS flags for the control plane.
func approvalFlags(fs *flag.FlagSet) (url, cert, key, ca *string) {
	url = fs.String("url", "127.0.0.1:7443", "host:port of the control plane")
	cert = fs.String("cert", "./pki/broker-admin.crt", "mTLS client cert (approver)")
	key = fs.String("key", "./pki/broker-admin.key", "mTLS client key")
	ca = fs.String("ca", "./pki/mtls_ca.crt", "mTLS CA")
	return
}

func approvalClient(cert, key, ca string) *http.Client {
	tlsCfg, err := buildTLSConfig(cert, key, ca)
	if err != nil {
		fatalf("TLS: %v", err)
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}}
}

func cmdApprovalList(args []string) {
	fs := flag.NewFlagSet("approval list", flag.ExitOnError)
	url, cert, key, ca := approvalFlags(fs)
	asJSON := fs.Bool("json", false, "raw JSON output")
	must(fs.Parse(args))
	resolveControlPlaneTarget(fs)

	client := approvalClient(*cert, *key, *ca)
	resp, err := client.Get("https://" + *url + "/v1/approvals")
	if err != nil {
		fatalf("GET /v1/approvals: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		fatalf("control plane returned %d: %s", resp.StatusCode, bytes.TrimSpace(body))
	}
	if *asJSON {
		fmt.Println(string(body))
		return
	}
	var items []struct {
		ID        string `json:"id"`
		Caller    string `json:"caller"`
		EndUser   string `json:"end_user"`
		Host      string `json:"host"`
		Command   string `json:"command"`
		Sudo      bool   `json:"sudo"`
		SudoUser  string `json:"sudo_user"`
		Rule      string `json:"rule"`
		Status    string `json:"status"`
		CreatedAt string `json:"created_at"`
	}
	if err := json.Unmarshal(body, &items); err != nil {
		fatalf("parse response: %v", err)
	}
	if len(items) == 0 {
		fmt.Println("(no pending requests)")
		return
	}
	for _, it := range items {
		user := it.EndUser
		if user == "" {
			user = "-"
		}
		// Show the elevation the certificate would carry: a human must see that a
		// benign-looking command would run as root before approving it.
		elev := "none"
		if it.Sudo {
			su := it.SudoUser
			if su == "" {
				su = "root"
			}
			elev = "sudo:" + su
		}
		fmt.Printf("%s  [%s]  caller=%s user=%s host=%s elevation=%s\n    cmd=%q rule=%s\n",
			it.ID, it.Status, it.Caller, user, it.Host, elev, it.Command, it.Rule)
	}
}

func cmdApprovalDecide(args []string, approve bool) {
	fs := flag.NewFlagSet("approval decide", flag.ExitOnError)
	url, cert, key, ca := approvalFlags(fs)
	// Approve-and-learn (allow only): mint a TTL'd approval waiver so the same
	// command runs without re-approval until it expires.
	var learn *bool
	var learnTTL *time.Duration
	if approve {
		learn = fs.Bool("learn", false, "also waive re-approval for this exact command for --ttl (approve-and-learn)")
		learnTTL = fs.Duration("ttl", time.Hour, "with --learn: how long the waiver lasts, e.g. 2h, 30m")
	}
	must(fs.Parse(args))
	if fs.NArg() < 1 {
		fatalf("missing request id")
	}
	id := fs.Arg(0)
	resolveControlPlaneTarget(fs)

	body := map[string]any{"approve": approve}
	if approve && *learn {
		if *learnTTL <= 0 {
			fatalf("--ttl must be > 0 with --learn")
		}
		body["learn"] = true
		body["ttl_seconds"] = int(learnTTL.Seconds())
	}
	payload, _ := json.Marshal(body)

	client := approvalClient(*cert, *key, *ca)
	resp, err := client.Post("https://"+*url+"/v1/approvals/"+id, "application/json", bytes.NewReader(payload))
	if err != nil {
		fatalf("POST /v1/approvals/%s: %v", id, err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		fatalf("control plane rejected decision (HTTP %d): %s", resp.StatusCode, bytes.TrimSpace(rb))
	}
	verb := "denied"
	if approve {
		verb = "approved"
		if *learn {
			verb = fmt.Sprintf("approved + learned (no re-approval for %s)", *learnTTL)
		}
	}
	fmt.Printf("request %s %s\n", id, verb)
}

// ── JSON helpers ──────────────────────────────────────────────────────────────

// hostEntry is the JSON representation of a host in signer.json.
// CommandPolicy uses json.RawMessage so that any command_policy object is
// preserved verbatim through add/update round-trips, without broker-ctl
// needing to understand its internal structure.
type hostEntry struct {
	Addr              string          `json:"addr"`
	User              string          `json:"user"`
	HostKey           string          `json:"host_key"`
	Jump              string          `json:"jump,omitempty"`
	Principal         string          `json:"principal"`
	SourceAddress     string          `json:"source_address,omitempty"`
	MaxTTLSeconds     int             `json:"max_ttl_seconds,omitempty"`
	AllowAsBastion    bool            `json:"allow_as_bastion,omitempty"`
	AllowedCallers    []string        `json:"allowed_callers,omitempty"`
	AllowSudo         bool            `json:"allow_sudo,omitempty"`
	AllowedSudoUsers  []string        `json:"allowed_sudo_users,omitempty"`
	AllowPTY          bool            `json:"allow_pty,omitempty"`
	AllowFileTransfer bool            `json:"allow_file_transfer,omitempty"`
	Groups            []string        `json:"groups,omitempty"`
	CommandPolicy     json.RawMessage `json:"command_policy,omitempty"`
}

// loadRaw reads signer.json as a RawMessage map to preserve unknown fields.
func loadRaw(path string) (map[string]json.RawMessage, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	return raw, nil
}

// extractHosts extracts and parses the "hosts" key from the raw map.
func extractHosts(raw map[string]json.RawMessage) (map[string]hostEntry, error) {
	hostsRaw, ok := raw["hosts"]
	if !ok {
		return map[string]hostEntry{}, nil
	}
	var hosts map[string]hostEntry
	if err := json.Unmarshal(hostsRaw, &hosts); err != nil {
		return nil, err
	}
	if hosts == nil {
		hosts = map[string]hostEntry{}
	}
	return hosts, nil
}

// writeHosts serialises hosts back into the raw map and writes the file.
func writeHosts(path string, raw map[string]json.RawMessage, hosts map[string]hostEntry) error {
	hostsJSON, err := json.MarshalIndent(hosts, "  ", "  ")
	if err != nil {
		return err
	}
	raw["hosts"] = hostsJSON
	return writeRaw(path, raw)
}

// writeRaw marshals raw as indented JSON and writes it atomically to path.
func writeRaw(path string, raw map[string]json.RawMessage) error {
	out, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(out, '\n'), 0640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// readSignerURL extracts the "listen" field from signer.json to build the HTTP URL.
func readSignerURL(configPath string) (string, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return "", err
	}
	var cfg struct {
		Listen string `json:"listen"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return "", err
	}
	if cfg.Listen == "" {
		return "", errors.New("'listen' field empty in signer.json")
	}
	// If listen is ":9443" (no host), use 127.0.0.1.
	if strings.HasPrefix(cfg.Listen, ":") {
		return "127.0.0.1" + cfg.Listen, nil
	}
	return cfg.Listen, nil
}

// ── TLS / PID helpers ─────────────────────────────────────────────────────────

func buildTLSConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("loading client cert: %w", err)
	}
	caData, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("reading CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caData) {
		return nil, errors.New("invalid CA PEM")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
	}, nil
}

func readPID(pidFile string) (int, error) {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("invalid PID in %s: %w", pidFile, err)
	}
	return pid, nil
}

func isAlive(pid int) bool {
	return syscall.Kill(pid, 0) == nil
}

// isSignerProcess reports whether pid is alive AND its command line looks like
// the signer. A bare liveness check (kill(pid,0)) is not enough: if the signer
// died and the OS recycled its PID for an unrelated process of the same user, a
// blind SIGHUP would hit that bystander. When identity cannot be confirmed we
// return false so the caller falls back to the authenticated HTTP reload, which
// targets the signer by URL and cannot hit the wrong process.
func isSignerProcess(pid int) bool {
	if !isAlive(pid) {
		return false
	}
	out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "command=").Output()
	if err != nil {
		return false
	}
	return commandLooksLikeSigner(string(out))
}

// commandLooksLikeSigner matches argv[0] against the signer binary name. The
// signer is conventionally built as "signer" (see signer.sh). Use an exact
// basename match so an unrelated command such as "cosigner" or "not-signer"
// cannot receive a local reload signal just because a recycled PID contains that
// substring.
func commandLooksLikeSigner(cmdline string) bool {
	fields := strings.Fields(cmdline)
	if len(fields) == 0 {
		return false
	}
	return strings.EqualFold(filepath.Base(fields[0]), "signer")
}

// splitHostPortDefault splits addr into host and port, defaulting to port 22
// when addr carries no port. Bracketed IPv6 literals ("[::1]:2222", "[::1]")
// and bare IPv6 literals ("2001:db8::1") are handled correctly.
func splitHostPortDefault(addr string) (host, port string, err error) {
	host, port, err = net.SplitHostPort(addr)
	if err == nil {
		if port == "" { // trailing colon, e.g. "web01:"
			port = "22"
		}
		return host, port, nil
	}
	// "missing port": bare hostname or "[v6]". "too many colons": bare IPv6
	// literal. In both cases the whole addr is the host; default the port.
	var aerr *net.AddrError
	if errors.As(err, &aerr) &&
		(strings.Contains(aerr.Err, "missing port") || strings.Contains(aerr.Err, "too many colons")) {
		host = strings.TrimSuffix(strings.TrimPrefix(addr, "["), "]")
		return host, "22", nil
	}
	return "", "", err
}

// sshKeyscan runs ssh-keyscan against host:port and extracts the first
// ed25519 line.
func sshKeyscan(host, port string) (string, error) {
	out, err := exec.Command("ssh-keyscan", "-p", port, "-t", "ed25519", host).Output()
	if err != nil {
		return "", fmt.Errorf("ssh-keyscan failed: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Format: "hostname ssh-ed25519 AAAA..."  Strip the hostname prefix.
		parts := strings.Fields(line)
		if len(parts) >= 3 {
			return strings.Join(parts[1:], " "), nil
		}
	}
	return "", fmt.Errorf("ssh-keyscan returned no ed25519 key for %s", host)
}

// ── misc ──────────────────────────────────────────────────────────────────────

func splitComma(s string) []string {
	var result []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			result = append(result, p)
		}
	}
	return result
}

func boolStr(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// dash returns s if non-empty, otherwise "—".
func dash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// dashJoin joins a slice with commas, returning "—" for an empty slice.
func dashJoin(ss []string) string {
	if len(ss) == 0 {
		return "—"
	}
	return strings.Join(ss, ",")
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}

func must(err error) {
	if err != nil {
		fatalf("%v", err)
	}
}

// ── audit ─────────────────────────────────────────────────────────────────────
//
// This file uses internal/audit.Entry directly (cmd/ may import internal
// packages of the same module). Ed25519 verification re-marshals the entry
// with Sig="" exactly like the producer (audit.Log.Append), so producer and
// verifier can never drift: a mirror struct missing a signed field would make
// every entry carrying that field fail --key verification.

func cmdAudit(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: broker-ctl audit {tail|show|verify} [flags]")
		os.Exit(1)
	}
	switch args[0] {
	case "tail":
		cmdAuditTail(args[1:])
	case "show":
		cmdAuditShow(args[1:])
	case "verify":
		cmdAuditVerify(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown audit subcommand: %q\n", args[0])
		os.Exit(1)
	}
}

func cmdAuditTail(args []string) {
	fs := flag.NewFlagSet("audit tail", flag.ExitOnError)
	logPath := fs.String("log", "", "path to audit log file (required)")
	n := fs.Int("n", 20, "number of recent entries to show before following")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: broker-ctl audit tail --log <path> [-n N]")
		fs.PrintDefaults()
	}
	must(fs.Parse(args))
	if *logPath == "" {
		fs.Usage()
		os.Exit(1)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	printAuditHeader(w)

	lines, offset, err := lastNLines(*logPath, *n)
	if err != nil && !os.IsNotExist(err) {
		fatalf("open log: %v", err)
	}
	for _, line := range lines {
		printAuditLine(w, line)
	}
	w.Flush()

	// Stream new entries as they are written.
	followFile(*logPath, offset, func(line []byte) {
		printAuditLine(w, line)
		w.Flush()
	})
}

func cmdAuditShow(args []string) {
	fs := flag.NewFlagSet("audit show", flag.ExitOnError)
	logPath := fs.String("log", "", "path to audit log file (required)")
	host := fs.String("host", "", "filter by host (substring match)")
	caller := fs.String("caller", "", "filter by caller (substring match)")
	outcome := fs.String("outcome", "", "filter by exact outcome (e.g. executed, denied, issued)")
	serial := fs.Uint64("serial", 0, "filter by exact serial number (0 = no filter)")
	since := fs.String("since", "", "show entries after this time (RFC3339 or YYYY-MM-DD)")
	limit := fs.Int("limit", 0, "max entries to return (0 = no limit)")
	asJSON := fs.Bool("json", false, "output as raw JSON lines (compatible with jq)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: broker-ctl audit show --log <path> [filters] [--json]")
		fs.PrintDefaults()
	}
	must(fs.Parse(args))
	if *logPath == "" {
		fs.Usage()
		os.Exit(1)
	}

	var sinceTime time.Time
	if *since != "" {
		var err error
		sinceTime, err = parseAuditTime(*since)
		if err != nil {
			fatalf("invalid --since value %q: %v", *since, err)
		}
	}

	f, err := os.Open(*logPath)
	if err != nil {
		fatalf("open log: %v", err)
	}
	defer f.Close()

	var tw *tabwriter.Writer
	if !*asJSON {
		tw = tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		printAuditHeader(tw)
	}

	count := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 256*1024), 256*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e audit.Entry
		if err := json.Unmarshal(line, &e); err != nil {
			continue // skip malformed lines silently
		}

		// Apply filters (all ANDed).
		if *host != "" && !strings.Contains(e.Host, *host) {
			continue
		}
		if *caller != "" && !strings.Contains(e.Caller, *caller) {
			continue
		}
		if *outcome != "" && e.Outcome != *outcome {
			continue
		}
		if *serial != 0 && e.Serial != *serial {
			continue
		}
		if !sinceTime.IsZero() && e.Time.Before(sinceTime) {
			continue
		}

		if *asJSON {
			os.Stdout.Write(line)
			os.Stdout.Write([]byte{'\n'})
		} else {
			printAuditRow(tw, e)
		}
		count++
		if *limit > 0 && count >= *limit {
			break
		}
	}
	if err := sc.Err(); err != nil {
		fatalf("read error: %v", err)
	}
	if !*asJSON {
		tw.Flush()
		if count == 0 {
			fmt.Fprintln(os.Stderr, "(no matching entries)")
		}
	}
}

func cmdAuditVerify(args []string) {
	fs := flag.NewFlagSet("audit verify", flag.ExitOnError)
	logPath := fs.String("log", "", "path to audit log file (required)")
	keyPath := fs.String("key", "", "path to audit seed file for Ed25519 signature verification (optional)")
	all := fs.Bool("all", false, "verify the whole chain across rotated segments (<log> plus <log>.<timestamp> files), checking cross-file linkage so a dropped/truncated segment is detected")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: broker-ctl audit verify --log <path> [--key seed-path] [--all]")
		fs.PrintDefaults()
	}
	must(fs.Parse(args))
	if *logPath == "" {
		fs.Usage()
		os.Exit(1)
	}

	// Derive public key from seed if provided.
	var pubKey ed25519.PublicKey
	if *keyPath != "" {
		seed, err := os.ReadFile(*keyPath)
		if err != nil {
			fatalf("read key: %v", err)
		}
		if len(seed) < ed25519.SeedSize {
			fatalf("seed file too short (need %d bytes, got %d)", ed25519.SeedSize, len(seed))
		}
		privKey := ed25519.NewKeyFromSeed(seed[:ed25519.SeedSize])
		pubKey = privKey.Public().(ed25519.PublicKey)
	}

	reportf := func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, "ERROR: "+format+"\n", args...)
	}

	var total, errs int
	if *all {
		total, errs = verifyAuditSegments(*logPath, pubKey, reportf)
	} else {
		f, err := os.Open(*logPath)
		if err != nil {
			fatalf("open log: %v", err)
		}
		defer f.Close()
		total, errs = verifyAuditChain(f, pubKey, reportf)
	}

	scope := "chain intact"
	if *all {
		scope = "chain intact across all rotated segments"
	}
	if errs == 0 {
		if pubKey != nil {
			fmt.Printf("OK: %d entries, %s, all signatures valid\n", total, scope)
		} else {
			fmt.Printf("OK: %d entries, %s (pass --key to also verify signatures)\n", total, scope)
		}
	} else {
		fmt.Fprintf(os.Stderr, "FAIL: %d entries checked, %d error(s) found\n", total, errs)
		os.Exit(1)
	}
}

// discoverAuditSegments returns the rotated segments of logPath (matching
// "<logPath>.*", sorted oldest→newest — the timestamp suffix 20060102T150405Z
// sorts chronologically) followed by the active file. Active rotation in
// internal/audit.maybeRotate names rotated files this way.
func discoverAuditSegments(logPath string) ([]string, error) {
	matches, err := filepath.Glob(logPath + ".*")
	if err != nil {
		return nil, err
	}
	sort.Strings(matches)
	files := matches
	if _, err := os.Stat(logPath); err == nil {
		files = append(files, logPath)
	}
	return files, nil
}

// verifyAuditSegments verifies the complete audit chain across rotated segments.
// Each segment is checked internally with verifyAuditChain, and consecutive
// segments are cross-linked: segment[N]'s first prev_hash must equal SHA-256 of
// segment[N-1]'s last line, and the earliest segment must begin at genesis
// (prev_hash=""). This makes dropping/truncating/reordering a whole rotated
// segment detectable — the guarantee THREAT_MODEL.md states for rotation, which
// single-file verification cannot deliver (it accepts the first prev_hash as an
// unchecked seed).
func verifyAuditSegments(logPath string, pubKey ed25519.PublicKey, reportf func(string, ...any)) (total, errs int) {
	segments, err := discoverAuditSegments(logPath)
	if err != nil {
		reportf("discovering audit segments: %v", err)
		return 0, 1
	}
	if len(segments) == 0 {
		reportf("no audit segments found for %q", logPath)
		return 0, 1
	}
	prevLast := ""
	for i, seg := range segments {
		f, err := os.Open(seg)
		if err != nil {
			reportf("%s: open: %v", seg, err)
			errs++
			continue
		}
		t, e := verifyAuditChain(f, pubKey, func(format string, args ...any) {
			reportf(seg+": "+format, args...)
		})
		f.Close()
		total += t
		errs += e

		firstPrev, lastHash, berr := auditFileBounds(seg)
		if berr != nil {
			reportf("%s: %v", seg, berr)
			errs++
			continue
		}
		switch {
		case i == 0 && firstPrev != "":
			reportf("%s: earliest segment does not start at genesis (prev_hash=%s); an earlier segment is missing or was pruned", seg, firstPrev)
			errs++
		case i > 0 && firstPrev != prevLast:
			reportf("%s: first prev_hash does not link to the previous segment\n  expected: %s\n  got:      %s\n  (a rotated segment was dropped, truncated, replaced, or reordered)", seg, prevLast, firstPrev)
			errs++
		}
		prevLast = lastHash
	}
	return total, errs
}

// auditFileBounds returns the prev_hash of the first entry and the SHA-256 of
// the last raw line of an audit segment, used to verify cross-segment linkage.
func auditFileBounds(path string) (firstPrevHash, lastHash string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 256*1024), 256*1024)
	first := true
	for sc.Scan() {
		b := sc.Bytes()
		if len(b) == 0 {
			continue
		}
		line := make([]byte, len(b))
		copy(line, b)
		if first {
			var e audit.Entry
			if err := json.Unmarshal(line, &e); err != nil {
				return "", "", fmt.Errorf("parsing first entry: %w", err)
			}
			firstPrevHash = e.PrevHash
			first = false
		}
		sum := sha256.Sum256(line)
		lastHash = hex.EncodeToString(sum[:])
	}
	if err := sc.Err(); err != nil {
		return "", "", fmt.Errorf("scanning: %w", err)
	}
	if first {
		return "", "", fmt.Errorf("empty segment")
	}
	return firstPrevHash, lastHash, nil
}

// verifyAuditChain checks sequence monotonicity, the prev_hash chain and,
// when pubKey is non-nil, the Ed25519 signature of every entry read from r.
// The first line's prev_hash is treated as the chain seed: after log rotation
// the first entry of a file carries the hash of the last entry of the previous
// file, so any seed value is accepted and continuity is verified from there.
// Each problem is reported through reportf; returns (entries read, errors).
func verifyAuditChain(r io.Reader, pubKey ed25519.PublicKey, reportf func(format string, args ...any)) (total, errs int) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 256*1024), 256*1024)

	var prevHash string
	var prevSeq uint64
	first := true

	for sc.Scan() {
		rawLine := sc.Bytes()
		if len(rawLine) == 0 {
			continue
		}
		// Copy before next Scan() invalidates the buffer.
		line := make([]byte, len(rawLine))
		copy(line, rawLine)

		var e audit.Entry
		if err := json.Unmarshal(line, &e); err != nil {
			reportf("malformed JSON: %v", err)
			errs++
			continue
		}
		total++

		// 1. Sequence monotonicity.
		if !first && e.Seq != prevSeq+1 {
			reportf("seq %d — expected %d (gap or reorder)", e.Seq, prevSeq+1)
			errs++
		}

		// 2. Hash chain: prev_hash of entry N must equal SHA-256 of raw line N-1.
		if !first && e.PrevHash != prevHash {
			reportf("seq %d — prev_hash mismatch\n  expected: %s\n  got:      %s",
				e.Seq, prevHash, e.PrevHash)
			errs++
		}

		// 3. Ed25519 signature (optional).
		if pubKey != nil {
			errs += verifyEntrySig(e, pubKey, reportf)
		}

		sum := sha256.Sum256(line)
		prevHash = hex.EncodeToString(sum[:])
		prevSeq = e.Seq
		first = false
	}
	if err := sc.Err(); err != nil {
		reportf("read error: %v", err)
		errs++
	}
	return total, errs
}

// verifyEntrySig checks the Ed25519 signature of a single entry. The canonical
// payload is the entry re-marshaled with Sig="" — exactly what the producer
// signs in audit.Log.Append. Returns the number of errors reported (0 or 1).
func verifyEntrySig(e audit.Entry, pubKey ed25519.PublicKey, reportf func(format string, args ...any)) int {
	sigBytes, err := base64.StdEncoding.DecodeString(e.Sig)
	if err != nil {
		reportf("seq %d — invalid sig encoding: %v", e.Seq, err)
		return 1
	}
	e.Sig = ""
	payload, err := json.Marshal(e)
	if err != nil {
		reportf("seq %d — marshal for sig check: %v", e.Seq, err)
		return 1
	}
	if !ed25519.Verify(pubKey, payload, sigBytes) {
		reportf("seq %d — signature invalid", e.Seq)
		return 1
	}
	return 0
}

// printAuditHeader writes the column header for the audit table.
func printAuditHeader(w *tabwriter.Writer) {
	fmt.Fprintln(w, "TIME\tSEQ\tCALLER\tHOST\tOUTCOME\tSERIAL\tDETAIL")
}

// printAuditLine parses a raw JSON line and appends one table row.
func printAuditLine(w *tabwriter.Writer, line []byte) {
	var e audit.Entry
	if err := json.Unmarshal(line, &e); err != nil {
		return
	}
	printAuditRow(w, e)
}

// printAuditRow formats a single audit entry as a tab-delimited row.
func printAuditRow(w *tabwriter.Writer, e audit.Entry) {
	t := e.Time.UTC().Format("2006-01-02T15:04:05Z")
	fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\t%d\t%s\n",
		t, e.Seq, e.Caller, e.Host, e.Outcome, e.Serial, auditDetail(e))
}

// auditDetail builds the DETAIL column: command + [sudo:X] [pty] [rule: ...]
// [dry-run] [approved-by: ...] [anomaly: ...] [err: ...].
func auditDetail(e audit.Entry) string {
	var b strings.Builder
	b.WriteString(e.Command)
	if e.Elevation != "" {
		fmt.Fprintf(&b, " [%s]", e.Elevation)
	}
	if e.PTY {
		b.WriteString(" [pty]")
	}
	if e.PolicyRule != "" {
		fmt.Fprintf(&b, " [rule: %s]", e.PolicyRule)
	}
	if e.DryRun {
		b.WriteString(" [dry-run]")
	}
	if e.ApprovedBy != "" {
		fmt.Fprintf(&b, " [approved-by: %s]", e.ApprovedBy)
	}
	if e.Anomaly != "" {
		fmt.Fprintf(&b, " [anomaly: %s]", e.Anomaly)
	}
	if e.Warning != "" {
		fmt.Fprintf(&b, " [warning: %s]", e.Warning)
	}
	if e.Err != "" {
		fmt.Fprintf(&b, " [err: %s]", e.Err)
	}
	return b.String()
}

// lastNLines reads the last n non-empty lines of path and returns them together
// with the file's current byte offset (used as the start position for followFile).
func lastNLines(path string, n int) ([][]byte, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 256*1024), 256*1024)
	var ring [][]byte
	for sc.Scan() {
		b := sc.Bytes()
		if len(b) == 0 {
			continue
		}
		line := make([]byte, len(b))
		copy(line, b)
		ring = append(ring, line)
		if len(ring) > n {
			ring = ring[1:]
		}
	}
	if err := sc.Err(); err != nil {
		return nil, 0, err
	}
	size, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return ring, 0, nil
	}
	return ring, size, nil
}

// followFile polls path every 500 ms and calls fn for each new complete line.
// If the file shrinks (log rotation), it restarts from the beginning of the
// new file.
func followFile(path string, offset int64, fn func([]byte)) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for range ticker.C {
		fi, err := os.Stat(path)
		if err != nil {
			continue
		}
		if fi.Size() < offset {
			offset = 0 // rotation: restart from top
		}
		if fi.Size() == offset {
			continue // no new data
		}
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			f.Close()
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 256*1024), 256*1024)
		for sc.Scan() {
			b := sc.Bytes()
			offset += int64(len(b)) + 1 // +1 for the stripped newline
			if len(b) == 0 {
				continue
			}
			line := make([]byte, len(b))
			copy(line, b)
			fn(line)
		}
		f.Close()
	}
}

// parseAuditTime accepts RFC3339 ("2006-01-02T15:04:05Z") or date-only
// ("2006-01-02", interpreted as midnight UTC).
func parseAuditTime(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("expected RFC3339 (e.g. 2026-06-05T12:00:00Z) or YYYY-MM-DD")
}
