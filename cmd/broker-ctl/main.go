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
//	broker-ctl audit repair --log <f> [--apply]     # Recover a torn final record so the signer can boot
//	broker-ctl --version [--verbose]                # Print the build version
package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
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
	"reflect"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/luisgf/infrabroker/internal/audit"
	"github.com/luisgf/infrabroker/internal/auth"
	"github.com/luisgf/infrabroker/internal/confcheck"
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
	case "freeze":
		cmdFreeze(args[1:])
	case "unfreeze":
		cmdUnfreeze(args[1:])
	case "revocations":
		cmdRevocations(args[1:])
	case "session":
		cmdSession(args[1:])
	case "envelope":
		cmdEnvelope(args[1:])
	case "doctor":
		cmdDoctor(args[1:])
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
  broker-ctl audit verify  --log <f> [--key seed] [--all]   Verify chain integrity (--all: across rotated segments)
  broker-ctl audit repair  --log <f> [--apply --key seed]   Quarantine a torn final record so the signer can boot
  broker-ctl policy explain --host <n> [--command c]        Show a host's composed command policy
  broker-ctl policy recommend --audit <log> (--key <seed>|--unverified) [--host h] [--since t] [--min-count n] [--json]  Suggest policy changes from the audit log
  broker-ctl policy add     --host <n> --allow <regex>      Add a command-policy allow rule (signer API, mTLS)
  broker-ctl policy remove  --host <n> --allow <regex>      Remove a command-policy allow rule
  broker-ctl policy grant   --host <n> --allow <regex> [--ttl 2h] [--caller cn] [--end-user u]  Create a runtime, expiring grant (signer API, mTLS)
  broker-ctl policy grants  [--json]                        List active runtime grants
  broker-ctl policy revoke  <grant-id>                      Revoke a runtime grant
  broker-ctl cluster list  --remote                         List Kubernetes clusters live from the signer (mTLS)
  broker-ctl freeze        (--caller cn|--end-user u|--session-id id|--serial n) [--reason r] [--volatile]  Freeze a subject: no new certs, kill its live sessions (mTLS)
  broker-ctl unfreeze      (--caller cn|--end-user u|--session-id id|--serial n)  Release a frozen subject (mTLS)
  broker-ctl revocations   [--json]                         List currently frozen subjects (mTLS)
  broker-ctl session kill  <session-id> [--reason r] [--volatile]  Force-close a live session (freezes its session_id, mTLS)
  broker-ctl envelope pubkey --seed <f>                     Print the sealed-exec envelope public key for a seed (offline; for rotation)
  broker-ctl doctor --security [--signer f --broker f --control-plane f]  Offline production-hardening preflight over the config files (no keys/network)
  broker-ctl version       [--verbose]                      Print the build version

Global options:
  --config         Path to signer.json (default: ./signer.json), before the subcommand
  --client-config  Path to the client parameters file for the remote commands
  --version        Print the build version and exit (--verbose for details)

Client parameters (remote commands: reload, policy add/remove/grant/grants/revoke,
approval list/allow/deny, host list --remote, cluster list, freeze, unfreeze,
revocations, session kill):
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
	// codingstyle:long-function: one CLI command — flag parsing, validation and
	// the config mutation are a single cohesive unit.
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
	pShell := fs.Bool("shell-parse", false, "parse commands as POSIX sh before policy evaluation (signer default: on; pass --shell-parse=false to author a raw-string opt-out)")
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
	var existingRaw json.RawMessage
	if existing, exists := hosts[*name]; exists {
		if !*force {
			fatalf("host %q already exists (use --force to overwrite)", *name)
		}
		action = "updated"
		hostExisted = true
		existingPolicy = existing.CommandPolicy
		if existingRaw, err = extractRawHost(raw, *name); err != nil {
			fatalf("parsing host %q: %v", *name, err)
		}
		mergeUnsetHostFields(&hp, existing, setFlags)
		if !policySet {
			hp.CommandPolicy = existing.CommandPolicy
		}
	}
	if policySet {
		var cp json.RawMessage
		var cerr error
		// nil unless --shell-parse was explicitly passed, so authoring a host
		// without the flag inherits the signer's parse-on default rather than
		// pinning shell_parse (and --shell-parse=false authors an explicit opt-out).
		var shellArg *bool
		if setFlags["shell-parse"] {
			shellArg = pShell
		}
		if hostExisted {
			// Field-granular merge: a --force update must override only the policy
			// sub-fields whose flags were set, not rebuild the whole policy from
			// defaults — otherwise omitting --policy-mode silently downgrades the
			// host to mode=off (firewall disabled, sessions re-enabled).
			cp, cerr = mergeCommandPolicyJSON(existingPolicy, setFlags, *pMode, *pEnforcement, *pAllow, *pDeny, *pApprove, shellArg)
		} else {
			cp, cerr = buildCommandPolicyJSON(*pMode, *pEnforcement, *pAllow, *pDeny, *pApprove, shellArg)
		}
		if cerr != nil {
			fatalf("command policy: %v", cerr)
		}
		hp.CommandPolicy = cp
	}

	// A --force update is written as per-key ops on /hosts/<name>/<key> for the
	// modeled keys that change (hostEntryDelta): every HostPolicy key broker-ctl
	// has no flag for (sealed_exec, or a key added after this binary was built)
	// survives instead of being silently dropped by the hostEntry round-trip
	// (#438), and because the entry object itself is never replaced, its key
	// order and the // comments inside it survive too (#561).
	if hostExisted && !isJSONNull(existingRaw) {
		set, remove, derr := hostEntryDelta(existingRaw, hp)
		if derr != nil {
			fatalf("merging host %q: %v", *name, derr)
		}
		if err := patchConfigEntryKeys(configPath, "hosts", *name, set, remove); err != nil {
			fatalf("writing config: %v", err)
		}
	} else if err := patchConfigEntry(configPath, "hosts", *name, hp, false); err != nil {
		fatalf("writing config: %v", err)
	}
	fmt.Printf("host %q %s (addr=%s, user=%s, principal=%s)\n", *name, action, hp.Addr, hp.User, hp.Principal)
}

// isJSONNull reports whether raw is the JSON literal null (a `"name": null`
// entry has no object to patch per key; it is replaced whole).
func isJSONNull(raw json.RawMessage) bool {
	return string(bytes.TrimSpace(raw)) == "null"
}

// hostEntryKeys is the set of signer.json host keys that hostEntry models (its
// json tag names), derived by reflection so it cannot drift from the struct.
var hostEntryKeys = jsonTagNames(reflect.TypeOf(hostEntry{}))

// jsonTagNames returns the json key of every exported, non-ignored field of t.
func jsonTagNames(t reflect.Type) map[string]bool {
	keys := map[string]bool{}
	for i := 0; i < t.NumField(); i++ {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		if name == "" || name == "-" {
			continue
		}
		keys[name] = true
	}
	return keys
}

// hostEntryDelta computes the per-key edit a --force update writes, from the
// existing entry's raw JSON and hp: set holds every modeled key (hostEntryKeys)
// whose value differs from the existing one, remove every modeled key hp omits
// (a bool flag explicitly cleared, a list flag set to "") that the entry still
// carries. hp already carries the field-granular merge of mergeUnsetHostFields
// / mergeCommandPolicyJSON, so the modeled keys keep their flag semantics;
// unmodeled keys (sealed_exec, future HostPolicy fields) are never part of the
// delta (#438), and an unchanged key — e.g. a command_policy no policy flag
// touched — is left alone, so the comments inside it survive as well (#561).
func hostEntryDelta(existingRaw json.RawMessage, hp hostEntry) (set map[string]json.RawMessage, remove []string, err error) {
	existing := map[string]json.RawMessage{}
	if len(existingRaw) > 0 {
		if err := json.Unmarshal(existingRaw, &existing); err != nil {
			return nil, nil, fmt.Errorf("existing entry: %w", err)
		}
	}
	b, err := json.Marshal(hp)
	if err != nil {
		return nil, nil, err
	}
	var modeled map[string]json.RawMessage
	if err := json.Unmarshal(b, &modeled); err != nil {
		return nil, nil, err
	}
	set = map[string]json.RawMessage{}
	for key := range hostEntryKeys {
		nv, have := modeled[key]
		ov, had := existing[key]
		switch {
		case have && (!had || !jsonEqual(ov, nv)):
			set[key] = nv
		case !have && had:
			remove = append(remove, key)
		}
	}
	sort.Strings(remove)
	return set, remove, nil
}

// jsonEqual reports whether a and b are the same JSON value modulo whitespace.
func jsonEqual(a, b json.RawMessage) bool {
	var ca, cb bytes.Buffer
	if json.Compact(&ca, a) != nil || json.Compact(&cb, b) != nil {
		return false
	}
	return bytes.Equal(ca.Bytes(), cb.Bytes())
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
	// ShellParse is a three-state pointer mirroring signer.CommandPolicy: nil
	// (key omitted) means the signer's default — parsing ON — while an explicit
	// false authors a raw-string opt-out. A plain bool with omitempty could not
	// emit the explicit false.
	ShellParse *bool `json:"shell_parse,omitempty"`
}

// buildCommandPolicyJSON marshals command-policy flag values into a RawMessage.
// shellParse is nil when --shell-parse was not passed, so a new host inherits the
// signer's parse-on default instead of pinning shell_parse.
func buildCommandPolicyJSON(mode, enforcement, allow, deny, requireApproval string, shellParse *bool) (json.RawMessage, error) {
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
func mergeCommandPolicyJSON(existing json.RawMessage, set map[string]bool, mode, enforcement, allow, deny, requireApproval string, shellParse *bool) (json.RawMessage, error) {
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
	// This helper returns a tailored error+hint rather than fatalf, so it stays
	// off the shared doJSON path — but the read is bounded the same way (#212).
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, maxRespBytes))
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

	if err := patchConfigEntry(configPath, "hosts", name, nil, true); err != nil {
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
	Type          string `json:"type"`
	Path          string `json:"path,omitempty"`
	Socket        string `json:"socket,omitempty"`
	PublicKeyPath string `json:"public_key_path,omitempty"`
	VaultURL      string `json:"vault_url,omitempty"`
	KeyName       string `json:"key_name,omitempty"`
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
	keyType := fs.String("type", "", "backend type: pem|akv|agent (required)")
	path := fs.String("path", "", "PEM file path (type=pem)")
	socket := fs.String("socket", "", "ssh-agent socket (type=agent; empty = $SSH_AUTH_SOCK)")
	pubKeyPath := fs.String("public-key-path", "", "CA public key file pinning the agent key (type=agent)")
	vaultURL := fs.String("vault-url", "", "AKV vault URL (type=akv)")
	keyName := fs.String("key-name", "", "AKV key name (type=akv)")
	force := fs.Bool("force", false, "overwrite if already exists")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage:\n  broker-ctl ca-keys add --name <n> --type pem --path <f>\n  broker-ctl ca-keys add --name <n> --type akv --vault-url <u> --key-name <k>\n  broker-ctl ca-keys add --name <n> --type agent --public-key-path <f> [--socket <s>]")
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
	case "agent":
		if *pubKeyPath == "" {
			fatalf("--public-key-path is required for type=agent")
		}
	default:
		fatalf("unsupported type %q: use pem, akv, or agent", *keyType)
	}

	entry := caKeyEntry{
		Type: *keyType, Path: *path, Socket: *socket, PublicKeyPath: *pubKeyPath,
		VaultURL: *vaultURL, KeyName: *keyName,
	}
	action, dropped, err := caKeysAdd(configPath, *name, entry, *force)
	if err != nil {
		fatalf("%v", err)
	}
	fmt.Printf("ca-key %q %s (type=%s)\n", *name, action, *keyType)
	if len(dropped) > 0 {
		fmt.Printf("  type changed from %s: dropped %s\n", dropped[0], strings.Join(dropped[1:], ", "))
	}
}

// caKeysAdd writes ca_keys[name] = entry into the config at path and reports
// "added" or "updated". A pre-existing entry is an error unless force is set;
// with force the flagged keys are overlaid onto the existing raw object
// (overlayCAKeyEntry, #560) so the ca.CAKeyConfig fields broker-ctl has no
// flag for (key_version, tenant_id, client_id, client_secret_env) survive a
// same-type update. On a type change the old backend's keys are removed and
// returned as dropped (dropped[0] is the old type, the rest the key names).
func caKeysAdd(path, name string, entry caKeyEntry, force bool) (action string, dropped []string, err error) {
	// A new entry contains exactly the fields provided via flags (omitempty
	// drops the rest); existing entries are left untouched as raw JSON.
	entryJSON, err := json.Marshal(entry)
	if err != nil {
		return "", nil, fmt.Errorf("serialising entry: %w", err)
	}

	raw, err := loadRaw(path)
	if err != nil {
		return "", nil, fmt.Errorf("reading config: %w", err)
	}
	keys, err := extractCAKeys(raw)
	if err != nil {
		return "", nil, fmt.Errorf("parsing ca_keys: %w", err)
	}

	action = "added"
	var value any = entryJSON
	if existing, exists := keys[name]; exists {
		if !force {
			return "", nil, fmt.Errorf("ca-key %q already exists (use --force to overwrite)", name)
		}
		action = "updated"
		merged, d, merr := overlayCAKeyEntry(existing, entry)
		if merr != nil {
			return "", nil, fmt.Errorf("merging ca-key %q: %w", name, merr)
		}
		value, dropped = merged, d
	}
	if err := patchConfigEntry(path, "ca_keys", name, value, false); err != nil {
		return "", nil, fmt.Errorf("writing config: %w", err)
	}
	return action, dropped, nil
}

// caKeyBackendKeys lists, per backend type, every ca.CAKeyConfig key that
// belongs to that backend — modeled by caKeyEntry or not. It drives the
// explicit drop on a --force type change (#560).
var caKeyBackendKeys = map[string][]string{
	"pem":   {"path"},
	"agent": {"socket", "public_key_path"},
	"akv":   {"vault_url", "key_name", "key_version", "tenant_id", "client_id", "client_secret_env"},
}

// overlayCAKeyEntry builds the ca_keys object written by a --force update,
// mirroring overlayHostEntry (#438): the existing entry's raw JSON with the
// keys the flags set (type and the non-empty flagged fields) replaced by e's
// values and every other key kept verbatim, so an AKV entry's pinned
// key_version and service-principal override (tenant_id, client_id,
// client_secret_env) survive a key_name change instead of silently reverting
// to "latest" and DefaultAzureCredential (a different identity). When the type
// changes, the OLD backend's keys are removed explicitly and reported as
// dropped (dropped[0] is the old type, then the removed key names) so the
// operator sees what the update discarded.
func overlayCAKeyEntry(existingRaw json.RawMessage, e caKeyEntry) (map[string]json.RawMessage, []string, error) {
	merged := map[string]json.RawMessage{}
	if len(existingRaw) > 0 {
		if err := json.Unmarshal(existingRaw, &merged); err != nil {
			return nil, nil, fmt.Errorf("existing entry: %w", err)
		}
		if merged == nil { // JSON null
			merged = map[string]json.RawMessage{}
		}
	}
	var oldType string
	if t, ok := merged["type"]; ok {
		_ = json.Unmarshal(t, &oldType) // an unparsable type is treated as "no backend"
	}
	var dropped []string
	if oldType != e.Type {
		for _, k := range caKeyBackendKeys[oldType] {
			if _, ok := merged[k]; ok {
				delete(merged, k)
				dropped = append(dropped, k)
			}
		}
		if len(dropped) > 0 {
			dropped = append([]string{oldType}, dropped...)
		}
	}
	b, err := json.Marshal(e)
	if err != nil {
		return nil, nil, err
	}
	var flagged map[string]json.RawMessage // omitempty: only type + the flags that were set
	if err := json.Unmarshal(b, &flagged); err != nil {
		return nil, nil, err
	}
	for k, v := range flagged {
		merged[k] = v
	}
	return merged, dropped, nil
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

	if err := patchConfigEntry(configPath, "ca_keys", name, nil, true); err != nil {
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

// ── callers ───────────────────────────────────────────────────────────────────

// callerEntry is the JSON representation of a caller in the callers map.
// AllowedGroups has no omitempty so an empty list serialises as [] (not omitted),
// matching signer.CallerPolicy behaviour. The two security flags mirror
// signer.CallerPolicy so `callers list` can show them; they are never written
// by broker-ctl (an operator sets them by hand in signer.json) and `callers add
// --force` preserves them — and any other key — by writing only
// allowed_groups, as a per-key patch (#439, #561).
type callerEntry struct {
	AllowedGroups          []string `json:"allowed_groups"`
	SelfApprove            bool     `json:"self_approve,omitempty"`
	RequireVerifiedEndUser bool     `json:"require_verified_end_user,omitempty"`
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
	action, err := callersAdd(configPath, *name, splitComma(*groups), *force)
	if err != nil {
		fatalf("%v", err)
	}
	fmt.Printf("caller %q %s (groups=%s)\n", *name, action, *groups)
}

// callersAdd writes callers[name].allowed_groups = groups into the config at
// path and reports "added" or "updated". A pre-existing entry is an error
// unless force is set; with force ONLY allowed_groups is written, as a per-key
// patch on /callers/<cn>/allowed_groups — the rest of the object
// (self_approve, require_verified_end_user and any key this broker-ctl does
// not know yet) is never touched, nor are the entry's key order and the
// comments inside it (#439, #561). Before #439 the whole object was replaced
// by {allowed_groups}, so a routine group change silently switched off
// signer-side OIDC re-validation (THREAT_MODEL gap #2) and four-eyes waivers
// for that CN.
func callersAdd(path, name string, groups []string, force bool) (string, error) {
	if groups == nil {
		groups = []string{} // marshal as [] rather than null
	}

	raw, err := loadRaw(path)
	if err != nil {
		return "", fmt.Errorf("reading config: %w", err)
	}
	var callers map[string]json.RawMessage // raw: the entry is patched, not re-marshaled
	if c, ok := raw["callers"]; ok {
		if err := json.Unmarshal(c, &callers); err != nil {
			return "", fmt.Errorf("parsing callers: %w", err)
		}
	}

	if existing, exists := callers[name]; exists {
		if !force {
			return "", fmt.Errorf("caller %q already exists (use --force to overwrite)", name)
		}
		if !isJSONNull(existing) {
			gb, err := json.Marshal(groups)
			if err != nil {
				return "", err
			}
			if err := patchConfigEntryKeys(path, "callers", name, map[string]json.RawMessage{"allowed_groups": gb}, nil); err != nil {
				return "", fmt.Errorf("writing config: %w", err)
			}
			return "updated", nil
		}
		// A literal null entry has no object to patch per key: replace it.
		if err := patchConfigEntry(path, "callers", name, callerEntry{AllowedGroups: groups}, false); err != nil {
			return "", fmt.Errorf("writing config: %w", err)
		}
		return "updated", nil
	}
	if err := patchConfigEntry(path, "callers", name, callerEntry{AllowedGroups: groups}, false); err != nil {
		return "", fmt.Errorf("writing config: %w", err)
	}
	return "added", nil
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
	renderCallerTable(os.Stdout, callers)
}

// renderCallerTable prints the callers table. The two security flags are
// shown next to the groups (#439): self_approve waives four-eyes for the CN
// and require_verified_end_user turns on signer-side OIDC re-validation, so an
// operator must be able to see them — and notice their absence — from the CLI.
func renderCallerTable(out io.Writer, callers map[string]callerEntry) {
	names := make([]string, 0, len(callers))
	for n := range callers {
		names = append(names, n)
	}
	sort.Strings(names)

	yesDash := func(b bool) string {
		if b {
			return "yes"
		}
		return "-"
	}
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tALLOWED_GROUPS\tSELF_APPROVE\tREQUIRE_VERIFIED_END_USER")
	for _, n := range names {
		c := callers[n]
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", n, dashJoin(c.AllowedGroups), yesDash(c.SelfApprove), yesDash(c.RequireVerifiedEndUser))
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

	if err := patchConfigEntry(configPath, "callers", name, nil, true); err != nil {
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

// ── reload ────────────────────────────────────────────────────────────────────

// sighupHint is printed after a SIGHUP reload: the signal is one-way, so a
// config the signer rejects ("keeping previous config") is reported only in
// its log and audit trail, never to the CLI (#564).
const sighupHint = "note: SIGHUP is one-way — a rejected config is kept out silently here. Confirm with `journalctl -u infrabroker-signer` (or the signer log) or `broker-ctl audit show --outcome reload-failed`."

func cmdReload(args []string) {
	fs := flag.NewFlagSet("reload", flag.ExitOnError)
	pidFile := fs.String("pid-file", "./signer.pid", "path to signer PID file")
	urlFlag, cert, key, ca := signerFlags(fs)
	must(fs.Parse(args))

	// Prefer the authenticated HTTP reload: the signer answers it, so a config
	// it rejects ("hosts: invalid regex", previous policy kept) reaches the
	// operator (#441). SIGHUP is one-way — the signer logs and audits the
	// failure but nothing comes back — so it is only the fallback when no
	// signer URL resolves or the HTTP path is unavailable (#564).
	resolveSignerTarget(fs)
	url := *urlFlag
	if url == "" {
		url, _ = readSignerURL(configPath) // "" when no local signer.json either
	}
	var httpErr error
	if url != "" {
		hosts, err := reloadOverHTTP(url, *cert, *key, *ca)
		if err == nil {
			fmt.Printf("signer reloaded via HTTP (hosts: %d)\n", hosts)
			return
		}
		if isReloadVerdict(err) {
			// The signer's own answer on the new config: never mask it with a
			// blind SIGHUP that would fail the same way, silently.
			fatalf("%v", err)
		}
		httpErr = err
	}

	// Fallback: local SIGHUP, only when we can confirm the PID really is the
	// signer (not a recycled PID belonging to another process).
	pid, perr := readPID(*pidFile)
	switch {
	case perr != nil && httpErr != nil:
		fatalf("HTTP reload unavailable (%v) and no local signer PID (%v)", httpErr, perr)
	case perr != nil:
		fatalf("no signer URL (pass --url, set BROKER_CTL_SIGNER_URL, add it to broker-ctl.json, or point --config at signer.json) and no local signer PID (%v)", perr)
	case !isSignerProcess(pid):
		why := "not alive"
		if isAlive(pid) {
			why = "does not look like the signer"
		}
		if httpErr != nil {
			fatalf("HTTP reload unavailable (%v) and PID %d from %s %s", httpErr, pid, *pidFile, why)
		}
		fatalf("no signer URL resolves and PID %d from %s %s", pid, *pidFile, why)
	}
	if httpErr != nil {
		fmt.Fprintf(os.Stderr, "note: HTTP reload unavailable (%v); falling back to SIGHUP\n", httpErr)
	}
	if err := syscall.Kill(pid, syscall.SIGHUP); err != nil {
		fatalf("SIGHUP to PID %d: %v", pid, err)
	}
	fmt.Printf("SIGHUP sent to signer (PID %d)\n", pid)
	fmt.Println(sighupHint)
}

// reloadOverHTTP POSTs /v1/reload on the signer at url over mTLS and returns
// the reloaded host count. Every failure is an error; isReloadVerdict tells the
// signer's own answer on the config apart from an unavailable HTTP path.
func reloadOverHTTP(url, cert, key, ca string) (int, error) {
	tlsCfg, err := auth.ClientTLSConfig(cert, key, ca)
	if err != nil {
		return 0, fmt.Errorf("TLS: %w", err)
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}}
	return reloadHTTP(client, "https://"+url+"/v1/reload")
}

// reloadError is a non-200 answer to POST /v1/reload: the status and the
// signer's text/plain reason.
type reloadError struct {
	status int
	body   string
}

func (e *reloadError) Error() string {
	return fmt.Sprintf("signer rejected reload (HTTP %d): %s", e.status, e.body)
}

// isReloadVerdict reports whether err is the signer's verdict on the NEW config
// (HTTP 500 from handleReload: the reload ran and failed, previous config
// kept). Anything else — no URL, missing mTLS material, transport, 401/403 —
// only means the HTTP path is unavailable, and a confirmed local signer may
// still be reloaded with SIGHUP.
func isReloadVerdict(err error) bool {
	var re *reloadError
	return errors.As(err, &re) && re.status == http.StatusInternalServerError
}

// reloadHTTP POSTs /v1/reload and returns the reloaded host count. The signer
// answers a rejected reload (401/403, or 500 with the config error) via
// http.Error — text/plain, never JSON — so the status is checked BEFORE the body
// is decoded and the raw body is surfaced; decoding first turned "hosts:
// invalid regex" into "parse response: invalid character ..." (#441). The read
// is bounded like doJSON's.
func reloadHTTP(client *http.Client, url string) (int, error) {
	resp, err := client.Post(url, "application/json", nil)
	if err != nil {
		return 0, fmt.Errorf("POST %s: %w", url, err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, maxRespBytes))
	if resp.StatusCode != http.StatusOK {
		return 0, &reloadError{resp.StatusCode, strings.TrimSpace(string(rb))}
	}
	var result struct {
		Status string `json:"status"`
		Hosts  int    `json:"hosts"`
	}
	if err := json.Unmarshal(rb, &result); err != nil {
		return 0, fmt.Errorf("parse response: %w", err)
	}
	return result.Hosts, nil
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
	tlsCfg, err := auth.ClientTLSConfig(cert, key, ca)
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
	body := doJSON(client, http.MethodGet, "https://"+*url+"/v1/approvals", nil, nil)
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
	client := approvalClient(*cert, *key, *ca)
	doJSON(client, http.MethodPost, "https://"+*url+"/v1/approvals/"+id, body, nil)
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
// needing to understand its internal structure. It deliberately models only
// the keys broker-ctl has flags for: a --force update patches only these, per
// key, in the existing raw entry (hostEntryDelta), so keys it does not model
// (e.g. sealed_exec) are preserved rather than dropped.
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
	if err := confcheck.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	return raw, nil
}

// extractRawHost returns the verbatim JSON object of hosts[name], or nil when
// the host (or the hosts section) is absent. It is the raw counterpart of
// extractHosts, used by the --force overlay to keep keys hostEntry does not
// model.
func extractRawHost(raw map[string]json.RawMessage, name string) (json.RawMessage, error) {
	hostsRaw, ok := raw["hosts"]
	if !ok {
		return nil, nil
	}
	var hosts map[string]json.RawMessage
	if err := json.Unmarshal(hostsRaw, &hosts); err != nil {
		return nil, err
	}
	return hosts[name], nil
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

// patchConfigEntry rewrites the config at path so section[name] = value (or
// removes it when remove is true), PRESERVING the file's // comments, key order
// and formatting via a format-preserving JSON Patch (confcheck.Patch, #183),
// written atomically. It is the comment-preserving replacement for the old
// extract→mutate→re-marshal round trip. When the section object is absent it is
// created with the single entry.
func patchConfigEntry(path, section, name string, value any, remove bool) error {
	orig, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var ops []map[string]any
	if remove {
		ops = []map[string]any{{"op": "remove", "path": "/" + section + "/" + jsonPtrEscape(name)}}
	} else {
		std, err := confcheck.Standardize(orig)
		if err != nil {
			return err
		}
		var top map[string]json.RawMessage
		if err := json.Unmarshal(std, &top); err != nil {
			return err
		}
		if _, ok := top[section]; ok {
			ops = []map[string]any{{"op": "add", "path": "/" + section + "/" + jsonPtrEscape(name), "value": value}}
		} else {
			ops = []map[string]any{{"op": "add", "path": "/" + section, "value": map[string]any{name: value}}}
		}
	}
	patch, err := json.Marshal(ops)
	if err != nil {
		return err
	}
	nb, err := confcheck.Patch(orig, patch)
	if err != nil {
		return err
	}
	return writeConfigAtomic(path, nb)
}

// patchConfigEntryKeys rewrites the existing section[name] object in place with
// per-key JSON-Patch ops — add (replace in place, or append when new) for every
// key in set, remove for every key in remove — instead of replacing the whole
// object, so the entry's position, key order and the // comments inside it
// survive a --force update (#561). Keys are patched in sorted order so the
// rewrite is deterministic; an empty delta leaves the file untouched.
func patchConfigEntryKeys(path, section, name string, set map[string]json.RawMessage, remove []string) error {
	base := "/" + section + "/" + jsonPtrEscape(name) + "/"
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var ops []map[string]any
	for _, k := range keys {
		ops = append(ops, map[string]any{"op": "add", "path": base + jsonPtrEscape(k), "value": set[k]})
	}
	for _, k := range remove {
		ops = append(ops, map[string]any{"op": "remove", "path": base + jsonPtrEscape(k)})
	}
	if len(ops) == 0 {
		return nil
	}
	orig, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	patch, err := json.Marshal(ops)
	if err != nil {
		return err
	}
	nb, err := confcheck.Patch(orig, patch)
	if err != nil {
		return err
	}
	return writeConfigAtomic(path, nb)
}

// jsonPtrEscape escapes a JSON Pointer reference token (RFC 6901): "~"→"~0",
// "/"→"~1", so an arbitrary host/key/caller name is a valid pointer segment.
func jsonPtrEscape(s string) string {
	s = strings.ReplaceAll(s, "~", "~0")
	s = strings.ReplaceAll(s, "/", "~1")
	return s
}

// writeConfigAtomic writes b to path via a fresh temp file + rename, preserving
// the existing file's permissions (0640 for a new file) and its owner/group
// (#559). The temp is created exclusively with a random name (never a fixed
// path+".tmp"), so a stale or planted <config>.tmp cannot have its wider mode
// adopted; the mode is set explicitly and the file and its directory are
// fsync'd for crash durability.
//
// Ownership: the temp belongs to the running euid/egid, so a root-run edit of
// the service-owned signer.json (infrabroker-signer:infrabroker-signer 0640 in
// a 0750 dir, the documented production layout) would otherwise install a
// root:root file the signer cannot read — reload keeps the old policy and the
// next restart refuses to start. When the existing file's uid/gid differ from
// ours the temp is chown'd back before the rename. A different group is best
// effort (a non-root owner may no longer be a member; the owner still reads
// the file); a different OWNER that cannot be restored (non-root) is refused
// instead of silently re-owned.
func writeConfigAtomic(path string, b []byte) error {
	mode := os.FileMode(0o640)
	uid, gid := -1, -1 // -1: keep the temp's (our) id
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			if int(st.Uid) != os.Geteuid() {
				uid = int(st.Uid)
			}
			if int(st.Gid) != os.Getegid() {
				gid = int(st.Gid)
			}
		}
	}
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }() // no-op once the rename succeeds
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return err
	}
	if uid != -1 || gid != -1 {
		if err := f.Chown(uid, gid); err != nil {
			if uid != -1 {
				_ = f.Close()
				return fmt.Errorf("%s is owned by uid %d and the rewrite cannot preserve that owner (run as root or as that user; the service would lose access to its config): %w", path, uid, err)
			}
			if !errors.Is(err, syscall.EPERM) {
				_ = f.Close()
				return fmt.Errorf("preserve group %d of %s: %w", gid, path, err)
			}
			// group-only EPERM (non-root, no longer a member): keep our egid.
		}
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil { // best-effort: make the rename durable
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
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
	if err := confcheck.Unmarshal(data, &cfg); err != nil {
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

// ── PID helpers ───────────────────────────────────────────────────────────────

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
// Chain and signature verification lives in internal/audit (Verify, VerifyEntry,
// VerifySegments, FileBounds, TrailingCorruption): the package that produces
// entries also verifies them, so canonicalization and the prev_hash chain are
// defined exactly once and cannot drift. The audit subcommands below are thin
// wrappers that add CLI UX (flags, output, exit codes) over those functions.

func cmdAudit(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: broker-ctl audit {tail|show|verify|repair} [flags]")
		os.Exit(1)
	}
	switch args[0] {
	case "tail":
		cmdAuditTail(args[1:])
	case "show":
		cmdAuditShow(args[1:])
	case "verify":
		cmdAuditVerify(args[1:])
	case "repair":
		cmdAuditRepair(args[1:])
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
	// codingstyle:long-function: one CLI command — flag parsing plus a single
	// filtering-and-printing loop over the log.
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
		total, errs = audit.VerifySegments(*logPath, pubKey, reportf)
	} else {
		f, err := os.Open(*logPath)
		if err != nil {
			fatalf("open log: %v", err)
		}
		defer f.Close()
		total, errs = audit.Verify(f, pubKey, reportf)
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

// cmdAuditRepair is the explicit operator recovery path for a log whose FINAL
// record was torn by a crash. The signer stays fail-closed by design (a
// truncated trailing record is indistinguishable from a truncation attack, so
// Open refuses to boot); this command lets an operator deliberately quarantine
// the corrupt bytes and truncate the log to the last well-formed record, so the
// hash chain continues cleanly and the signer can start. It is a no-op unless
// --apply is passed.
func cmdAuditRepair(args []string) {
	// codingstyle:long-function: one CLI recovery command — the detect → preview
	// → apply flow is cohesive and reads worse split across helpers.
	fs := flag.NewFlagSet("audit repair", flag.ExitOnError)
	logPath := fs.String("log", "", "path to audit log file (required)")
	keyPath := fs.String("key", "", "audit seed file: also verify the kept prefix's Ed25519 signatures before repairing (optional)")
	apply := fs.Bool("apply", false, "quarantine the corrupt tail and truncate the log (default: dry-run, no changes)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: broker-ctl audit repair --log <path> [--apply] [--key seed-path]")
		fmt.Fprintln(os.Stderr, "\nRecover a log whose final record was torn by a crash. A truncated, unparseable")
		fmt.Fprintln(os.Stderr, "trailing record makes the signer refuse to boot (fail-closed by design). This is")
		fmt.Fprintln(os.Stderr, "the explicit recovery path: it quarantines the corrupt trailing bytes to")
		fmt.Fprintln(os.Stderr, "<log>.corrupt-<timestamp> and truncates the log to the last well-formed record,")
		fmt.Fprintln(os.Stderr, "preserving the hash chain. Runs as a dry-run unless --apply is given.")
		fs.PrintDefaults()
	}
	must(fs.Parse(args))
	if *logPath == "" {
		fs.Usage()
		os.Exit(1)
	}

	data, err := os.ReadFile(*logPath)
	if err != nil {
		fatalf("read log: %v", err)
	}
	cleanEnd, lastGoodSeq, goodCount, corruptTail, middle := audit.TrailingCorruption(data)

	if middle {
		fmt.Fprintf(os.Stderr, "FAIL: %s has a malformed record BEFORE a well-formed one (not a torn tail).\n", *logPath)
		fmt.Fprintln(os.Stderr, "  The signer will still boot (the last record is intact), so no repair is applied.")
		fmt.Fprintln(os.Stderr, "  Run 'broker-ctl audit verify' to locate the integrity break and investigate manually.")
		os.Exit(1)
	}
	if len(corruptTail) == 0 {
		fmt.Printf("OK: %s ends on a well-formed record (%d records); nothing to repair.\n", *logPath, goodCount)
		return
	}

	// Optionally assure the operator that the prefix being kept is itself intact.
	if *keyPath != "" {
		seed, err := os.ReadFile(*keyPath)
		if err != nil {
			fatalf("read key: %v", err)
		}
		if len(seed) < ed25519.SeedSize {
			fatalf("seed file too short (need %d bytes, got %d)", ed25519.SeedSize, len(seed))
		}
		pub := ed25519.NewKeyFromSeed(seed[:ed25519.SeedSize]).Public().(ed25519.PublicKey)
		if _, errs := audit.Verify(bytes.NewReader(data[:cleanEnd]), pub, func(format string, a ...any) {
			fmt.Fprintf(os.Stderr, "  prefix integrity: "+format+"\n", a...)
		}); errs > 0 {
			fatalf("the well-formed prefix itself fails verification (%d error(s)); refusing to repair — investigate manually", errs)
		}
	}

	preview := corruptTail
	if len(preview) > 120 {
		preview = preview[:120]
	}
	fmt.Printf("Torn final record detected in %s:\n", *logPath)
	fmt.Printf("  well-formed records kept: %d (last seq %d, ending at byte %d)\n", goodCount, lastGoodSeq, cleanEnd)
	fmt.Printf("  corrupt trailing bytes:   %d\n", len(corruptTail))
	fmt.Printf("  preview:                  %q\n", preview)

	if !*apply {
		fmt.Println("\nDry run — no changes written. Re-run with --apply to quarantine the corrupt tail")
		fmt.Println("and truncate the log so the signer can boot (the chain continues from the last")
		fmt.Println("well-formed record).")
		return
	}

	quarantine := fmt.Sprintf("%s.corrupt-%s", *logPath, time.Now().UTC().Format("20060102T150405Z"))
	if err := os.WriteFile(quarantine, corruptTail, 0o600); err != nil {
		fatalf("writing quarantine file: %v", err)
	}
	if err := os.Truncate(*logPath, int64(cleanEnd)); err != nil {
		fatalf("truncating log (corrupt bytes preserved in %s): %v", quarantine, err)
	}
	fmt.Printf("\nRepaired: quarantined %d byte(s) to %s and truncated %s to %d byte(s).\n", len(corruptTail), quarantine, *logPath, cleanEnd)
	fmt.Printf("The signer can now boot; the chain continues from seq %d. Keep the quarantine file\n", lastGoodSeq)
	fmt.Println("for forensics — it holds the torn record dropped from the trail.")
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
	if e.EndUserContext != "" {
		fmt.Fprintf(&b, " [ctx: %s]", e.EndUserContext)
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
