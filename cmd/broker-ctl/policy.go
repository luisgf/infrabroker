package main

import (
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/luisgf/infrabroker/internal/audit"
	"github.com/luisgf/infrabroker/internal/auth"
	"github.com/luisgf/infrabroker/internal/confcheck"
	"github.com/luisgf/infrabroker/internal/policyrec"
	"github.com/luisgf/infrabroker/internal/signer"
)

// policyConfig is the subset of a signer.json / local config.json needed to
// explain command-policy composition. It unmarshals from either config shape
// (the relevant JSON tags — hosts.groups, hosts.command_policy — are shared).
type policyConfig struct {
	Hosts                signer.PolicyTable              `json:"hosts"`
	CommandPolicies      map[string]signer.CommandPolicy `json:"command_policies"`
	GroupCommandPolicies map[string][]string             `json:"group_command_policies"`
}

func cmdPolicy(args []string) {
	if len(args) == 0 {
		policyUsage()
		os.Exit(1)
	}
	switch args[0] {
	case "explain":
		cmdPolicyExplain(args[1:])
	case "recommend":
		cmdPolicyRecommend(args[1:])
	case "add":
		cmdPolicyMutate(args[1:], true)
	case "remove":
		cmdPolicyMutate(args[1:], false)
	case "grant":
		cmdPolicyGrant(args[1:])
	case "grants":
		cmdPolicyGrants(args[1:])
	case "revoke":
		cmdPolicyRevoke(args[1:])
	default:
		policyUsage()
		os.Exit(1)
	}
}

func policyUsage() {
	fmt.Fprintln(os.Stderr, "Usage:\n"+
		"  broker-ctl [--config f] policy explain   --host <name> [--command <cmd>]\n"+
		"  broker-ctl [--config f] policy recommend --audit <log> (--key <audit seed>|--unverified) [--host h] [--since t] [--min-count n] [--json]\n"+
		"  broker-ctl [--config f] policy add       --host <name> --allow <regex>   (signer mutation API, mTLS)\n"+
		"  broker-ctl [--config f] policy remove    --host <name> --allow <regex>\n"+
		"  broker-ctl [--config f] policy grant     --host <name> --allow <regex> [--ttl 2h] [--caller cn] [--end-user u]   (runtime grant, mTLS)\n"+
		"  broker-ctl [--config f] policy grants    [--json]                       (list active grants, mTLS)\n"+
		"  broker-ctl [--config f] policy revoke    <grant-id>                     (mTLS)")
}

// policyHTTP builds an mTLS client and the signer base URL ("https://host:port"),
// shared by the signer-facing remote commands. An empty url falls back to the
// listen field of the signer config (--config): with --url (or the client
// config file / BROKER_CTL_SIGNER_URL) no local signer.json is needed at all.
func policyHTTP(url, cert, key, ca string) (*http.Client, string) {
	if url == "" {
		s, err := readSignerURL(configPath)
		if err != nil {
			fatalf("no signer URL: %v (pass --url, set BROKER_CTL_SIGNER_URL, or add it to broker-ctl.json)", err)
		}
		url = s
	}
	tlsCfg, err := auth.ClientTLSConfig(cert, key, ca)
	if err != nil {
		fatalf("TLS: %v", err)
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}}
	return client, "https://" + url
}

// cmdPolicyGrant creates a runtime, widen-only grant on the signer over mTLS: a
// time-boxed allow rule on an allowlist host that expires on its own. The client
// cert CN must be in the signer's reload_callers, and the host must be
// allowlist-active (the signer refuses the grant otherwise).
func cmdPolicyGrant(args []string) {
	fs := flag.NewFlagSet("policy grant", flag.ExitOnError)
	host := fs.String("host", "", "target host (required; must be allowlist-active)")
	allow := fs.String("allow", "", "allow regex to grant (required)")
	ttl := fs.Duration("ttl", time.Hour, "grant lifetime, e.g. 2h, 30m, 90s")
	scopeCaller := fs.String("caller", "", "optional: limit the grant to this broker CN")
	scopeUser := fs.String("end-user", "", "optional: limit the grant to this end user")
	urlFlag, cert, key, ca := signerFlags(fs)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: broker-ctl [--config f] policy grant --host <name> --allow <regex> [--ttl 2h] [--caller cn] [--end-user u]")
		fs.PrintDefaults()
	}
	must(fs.Parse(args))
	if *host == "" || *allow == "" || *ttl <= 0 {
		fs.Usage()
		os.Exit(1)
	}
	resolveSignerTarget(fs)

	client, base := policyHTTP(*urlFlag, *cert, *key, *ca)
	endpoint := base + "/v1/policy/hosts/" + url.PathEscape(*host) + "/grants"
	var result struct {
		ID        string `json:"id"`
		ExpiresAt string `json:"expires_at"`
	}
	doJSON(client, http.MethodPost, endpoint, map[string]any{
		"allow": []string{*allow}, "ttl_seconds": int(ttl.Seconds()),
		"caller": *scopeCaller, "end_user": *scopeUser,
	}, &result)
	fmt.Printf("granted on %s: allow %q for %s (id %s, expires %s)\n",
		*host, *allow, *ttl, result.ID, result.ExpiresAt)
}

// cmdPolicyGrants lists the signer's active runtime grants over mTLS.
func cmdPolicyGrants(args []string) {
	fs := flag.NewFlagSet("policy grants", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "output as JSON")
	urlFlag, cert, key, ca := signerFlags(fs)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: broker-ctl [--config f] policy grants [--json]")
		fs.PrintDefaults()
	}
	must(fs.Parse(args))
	resolveSignerTarget(fs)

	client, base := policyHTTP(*urlFlag, *cert, *key, *ca)
	rb := doJSON(client, http.MethodGet, base+"/v1/policy/grants", nil, nil)
	if *asJSON {
		os.Stdout.Write(rb)
		if len(rb) > 0 && rb[len(rb)-1] != '\n' {
			fmt.Println()
		}
		return
	}
	var grants []signer.Grant
	if err := json.Unmarshal(rb, &grants); err != nil {
		fatalf("decode grants: %v", err)
	}
	if len(grants) == 0 {
		fmt.Println("(no active grants)")
		return
	}
	fmt.Printf("%-26s %-10s %-22s %-16s %s\n", "ID", "HOST", "EXPIRES (UTC)", "SCOPE", "RULES")
	for _, g := range grants {
		fmt.Printf("%-26s %-10s %-22s %-16s %s\n",
			g.ID, g.Host, g.ExpiresAt.UTC().Format(time.RFC3339), grantScope(g), grantRules(g))
	}
}

// grantRules renders a grant's allow / waive-approval patterns with a kind tag,
// so a list shows both widen-only grants and approve-and-learn waivers.
func grantRules(g signer.Grant) string {
	var parts []string
	if len(g.Allow) > 0 {
		parts = append(parts, "allow["+strings.Join(g.Allow, " | ")+"]")
	}
	if len(g.WaiveApproval) > 0 {
		parts = append(parts, "waive-approval["+strings.Join(g.WaiveApproval, " | ")+"]")
	}
	return strings.Join(parts, " ")
}

// grantScope renders a grant's caller/end-user scope, or "any" for host-wide.
func grantScope(g signer.Grant) string {
	var parts []string
	if g.Caller != "" {
		parts = append(parts, "caller="+g.Caller)
	}
	if g.EndUser != "" {
		parts = append(parts, "user="+g.EndUser)
	}
	if len(parts) == 0 {
		return "any"
	}
	return strings.Join(parts, ",")
}

// cmdPolicyRevoke revokes a grant by id over mTLS.
func cmdPolicyRevoke(args []string) {
	fs := flag.NewFlagSet("policy revoke", flag.ExitOnError)
	urlFlag, cert, key, ca := signerFlags(fs)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: broker-ctl [--config f] policy revoke <grant-id>")
		fs.PrintDefaults()
	}
	must(fs.Parse(args))
	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(1)
	}
	id := fs.Arg(0)
	resolveSignerTarget(fs)

	client, base := policyHTTP(*urlFlag, *cert, *key, *ca)
	endpoint := base + "/v1/policy/grants/" + url.PathEscape(id)
	doJSON(client, http.MethodDelete, endpoint, nil, nil)
	fmt.Printf("revoked grant %s\n", id)
}

// cmdPolicyMutate calls the signer's POST/DELETE /v1/policy/hosts/{host}/allow to
// add or remove a command-policy allow rule over mTLS. The client cert CN must be
// in the signer's reload_callers; the signer validates and applies the change
// atomically (in-memory + on disk). The signer URL is read from the global config.
func cmdPolicyMutate(args []string, add bool) {
	op, past := "add", "added"
	if !add {
		op, past = "remove", "removed"
	}
	fs := flag.NewFlagSet("policy "+op, flag.ExitOnError)
	host := fs.String("host", "", "target host (required)")
	allow := fs.String("allow", "", "allow regex to "+op+" (required)")
	urlFlag, cert, key, ca := signerFlags(fs)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: broker-ctl [--config f] policy %s --host <name> --allow <regex>\n", op)
		fs.PrintDefaults()
	}
	must(fs.Parse(args))
	if *host == "" || *allow == "" {
		fs.Usage()
		os.Exit(1)
	}
	resolveSignerTarget(fs)

	client, base := policyHTTP(*urlFlag, *cert, *key, *ca)
	endpoint := base + "/v1/policy/hosts/" + url.PathEscape(*host) + "/allow"

	method := http.MethodPost
	if !add {
		method = http.MethodDelete
	}
	var result struct {
		Hosts int `json:"hosts"`
	}
	doJSON(client, method, endpoint, map[string]string{"pattern": *allow}, &result)
	fmt.Printf("allow %q %s on %s (hosts: %d)\n", *allow, past, *host, result.Hosts)
}

// cmdPolicyRecommend mines an audit log and prints advisory command-policy
// suggestions (promote / dead-rule / friction). Read-only: it never changes
// policy. The config (for the current rules) comes from the global --config.
//
// The log is verified before it is mined (#454): with --key (the signer's
// audit_key seed, as for `audit verify`) every entry's Ed25519 signature and
// the prev_hash chain are checked and any line that fails is dropped and
// counted, so a "N× human-approved" promote cannot be fabricated by whoever can
// write the file. --unverified mines without signatures (chain checks only) and
// must be asked for explicitly.
func cmdPolicyRecommend(args []string) {
	fs := flag.NewFlagSet("policy recommend", flag.ExitOnError)
	auditLog := fs.String("audit", "", "path to an audit log to mine (required)")
	keyPath := fs.String("key", "", "path to the audit seed file (the service's audit_key): verifies every entry's signature and the hash chain before mining; required unless --unverified")
	unverified := fs.Bool("unverified", false, "mine without verifying signatures (chain checks only) — anyone who can write the log can then fabricate the counts")
	host := fs.String("host", "", "restrict to one host")
	since := fs.String("since", "", "ignore entries before this time (RFC3339 or YYYY-MM-DD)")
	minCount := fs.Int("min-count", 1, "suppress suggestions with fewer occurrences")
	asJSON := fs.Bool("json", false, "output as JSON")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: broker-ctl [--config f] policy recommend --audit <log> (--key <audit seed>|--unverified) [--host h] [--since t] [--min-count n] [--json]")
		fs.PrintDefaults()
	}
	must(fs.Parse(args))
	if *auditLog == "" {
		fs.Usage()
		os.Exit(1)
	}
	if *keyPath == "" && !*unverified {
		fmt.Fprintln(os.Stderr, "error: pass --key <audit seed> to verify the log's signatures before mining it, or --unverified to mine it as-is")
		fs.Usage()
		os.Exit(1)
	}
	var pub ed25519.PublicKey
	if *keyPath != "" {
		pub = auditPubFromSeed(*keyPath)
	}

	var sinceT time.Time
	if *since != "" {
		var err error
		if sinceT, err = parseAuditTime(*since); err != nil {
			fatalf("invalid --since: %v", err)
		}
	}

	var cfg policyConfig
	b, err := os.ReadFile(configPath)
	if err != nil {
		fatalf("read config: %v", err)
	}
	if err := confcheck.Unmarshal(b, &cfg); err != nil {
		fatalf("parse config: %v", err)
	}
	compiled, err := signer.CompileHostPolicies(cfg.Hosts, cfg.CommandPolicies, cfg.GroupCommandPolicies)
	if err != nil {
		fatalf("invalid policy config: %v", err)
	}

	entries, skipped := loadAuditEntries(*auditLog, pub, os.Stderr)
	if pub == nil {
		fmt.Fprintf(os.Stderr, "WARN: signatures not verified (--unverified): anyone who can write %s can fabricate the counts below\n", *auditLog)
	}
	sugs := policyrec.Recommend(entries, compiled, policyrec.Options{
		Host: *host, Since: sinceT, MinCount: *minCount,
	})

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(sugs); err != nil {
			fatalf("encode: %v", err)
		}
		return
	}
	printRecommendations(*auditLog, len(entries), skipped, pub != nil, sugs)
}

// auditPubFromSeed derives the audit public key from a seed file, with the same
// contract as `broker-ctl audit verify --key`: the first ed25519.SeedSize bytes.
func auditPubFromSeed(path string) ed25519.PublicKey {
	seed, err := os.ReadFile(path)
	if err != nil {
		fatalf("read key: %v", err)
	}
	if len(seed) < ed25519.SeedSize {
		fatalf("seed file too short (need %d bytes, got %d)", ed25519.SeedSize, len(seed))
	}
	return ed25519.NewKeyFromSeed(seed[:ed25519.SeedSize]).Public().(ed25519.PublicKey)
}

// loadAuditEntries reads an NDJSON audit log through the audit-verify path
// (internal/audit.VerifyEntries: sequence, prev_hash chain and — with pub — the
// Ed25519 signature of every line) and returns only the entries that passed
// every check, plus the number of lines dropped. Each problem is written to
// warn as it is found and a summary line follows when anything was skipped, so
// a mined log of unknown provenance can never silently feed the analysis (#454).
func loadAuditEntries(path string, pub ed25519.PublicKey, warn io.Writer) (entries []audit.Entry, skipped int) {
	f, err := os.Open(path)
	if err != nil {
		fatalf("open audit log: %v", err)
	}
	defer f.Close()
	entries, skipped, _ = audit.VerifyEntries(f, pub, func(format string, args ...any) {
		fmt.Fprintf(warn, "WARN: %s: "+format+"\n", append([]any{path}, args...)...)
	})
	if skipped > 0 {
		fmt.Fprintf(warn, "WARN: %d line(s) of %s skipped (malformed, out of chain or invalid signature) — not mined; run `broker-ctl audit verify --log %s --key <seed>` to investigate\n", skipped, path, path)
	}
	return entries, skipped
}

func printRecommendations(logPath string, n, skipped int, verified bool, sugs []policyrec.Suggestion) {
	kind := "unverified"
	if verified {
		kind = "verified"
	}
	fmt.Printf("Policy recommendations (from %s, %d %s entries, %d skipped)\n", logPath, n, kind, skipped)
	if len(sugs) == 0 {
		fmt.Println("  (no suggestions)")
		return
	}
	for _, s := range sugs {
		// Patterns and samples are mined from recorded commands: an agent
		// controls those bytes, and a newline inside one would print as a
		// suggestion of its own (#748). escapeText keeps each on one line.
		host, pattern := escapeText(s.Host), escapeText(s.Pattern)
		switch s.Type {
		case policyrec.Promote:
			fmt.Printf("\n  [PROMOTE]  %s   %s\n", host, pattern)
			fmt.Printf("     %d× · %d callers · %d human-approved · last %s\n",
				s.Count, s.Callers, s.Approved, s.LastSeen.UTC().Format("2006-01-02"))
			if len(s.Samples) > 0 {
				fmt.Printf("     e.g. %s\n", escapeText(s.Samples[0]))
			}
			fmt.Printf("     → add to the allowlist of %s if intended\n", host)
		case policyrec.Friction:
			fmt.Printf("\n  [FRICTION] %s   denied %d× : %s\n", host, s.Count, pattern)
		case policyrec.DeadRule:
			fmt.Printf("\n  [DEAD]     %s   %s   (0 matches in window → review/remove)\n", host, pattern)
		}
	}
	fmt.Println("\nAdvisory only — nothing was changed. Review before applying.")
}

// cmdPolicyExplain prints a host's effective (composed) command policy and,
// optionally, evaluates a command offline against it — no signing, no network.
// The config file (a signer.json or a local config.json) comes from the global
// --config option, parsed before the subcommand.
func cmdPolicyExplain(args []string) {
	fs := flag.NewFlagSet("policy explain", flag.ExitOnError)
	host := fs.String("host", "", "host name to explain (required)")
	command := fs.String("command", "", "optional command to evaluate against the composed policy")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: broker-ctl [--config f] policy explain --host <name> [--command <cmd>]")
		fs.PrintDefaults()
	}
	must(fs.Parse(args))
	if *host == "" {
		fs.Usage()
		os.Exit(1)
	}

	var cfg policyConfig
	b, err := os.ReadFile(configPath)
	if err != nil {
		fatalf("read config: %v", err)
	}
	if err := confcheck.Unmarshal(b, &cfg); err != nil {
		fatalf("parse config: %v", err)
	}
	hp, ok := cfg.Hosts[*host]
	if !ok {
		fatalf("host %q not found in %s", *host, configPath)
	}
	// Compile to validate the config and populate the effective PolicySet — the
	// same step the signer/broker run at load, so a bad regex or an unknown
	// policy reference surfaces here too.
	compiled, err := signer.CompileHostPolicies(cfg.Hosts, cfg.CommandPolicies, cfg.GroupCommandPolicies)
	if err != nil {
		fatalf("invalid policy config: %v", err)
	}
	eff := compiled[*host].Policies

	fmt.Printf("Host:   %s\nGroups: %s\n", *host, dashJoin(hp.Groups))
	fmt.Println("Effective command policies (composed; union of allows, deny wins):")
	for _, line := range policyContributors(hp, cfg) {
		fmt.Printf("  - %s\n", line)
	}
	if len(eff) == 0 {
		fmt.Println("  (none — no command restriction; every command is allowed)")
	}
	fmt.Printf("Sessions: %s\n", sessionStatus(eff))

	if *command != "" {
		printDecision(eff, *command)
	}
}

// policyContributors resolves the ordered, deduplicated policies contributing to
// the host (mirrors signer.composePolicies) with their source group and a label.
func policyContributors(hp signer.HostPolicy, cfg policyConfig) []string {
	var out []string
	seen := map[string]bool{}
	add := func(group string, names []string) {
		for _, n := range names {
			if seen[n] {
				continue
			}
			cp, ok := cfg.CommandPolicies[n]
			if !ok {
				continue
			}
			seen[n] = true
			out = append(out, fmt.Sprintf("%-16s [%s] %s", n, group, policyLabel(cp)))
		}
	}
	add("_default", cfg.GroupCommandPolicies["_default"])
	for _, g := range hp.Groups {
		add(g, cfg.GroupCommandPolicies[g])
	}
	if hp.CommandPolicy.Restricts() {
		out = append(out, fmt.Sprintf("%-16s [%s] %s", "<inline>", "host", policyLabel(hp.CommandPolicy)))
	}
	return out
}

// policyLabel renders a one-line summary of a single command policy.
func policyLabel(cp signer.CommandPolicy) string {
	var parts []string
	switch cp.Mode {
	case signer.CmdPolicyAllowlist:
		parts = append(parts, fmt.Sprintf("allowlist(allow:%d)", len(cp.Allow)))
	case signer.CmdPolicyDenylist:
		parts = append(parts, fmt.Sprintf("denylist(deny:%d)", len(cp.Deny)))
	}
	if len(cp.RequireApproval) > 0 {
		parts = append(parts, fmt.Sprintf("approval:%d", len(cp.RequireApproval)))
	}
	if cp.ShellParse != nil && !*cp.ShellParse {
		// Parsing is on by default; only the explicit opt-out is worth surfacing.
		parts = append(parts, "shell_parse:off")
	}
	if cp.Enforcement == signer.CmdPolicyAudit {
		parts = append(parts, "audit")
	}
	if len(parts) == 0 {
		return "off"
	}
	return strings.Join(parts, " ")
}

func sessionStatus(eff signer.PolicySet) string {
	if eff.Restricts() {
		return "exec preflighted; shell/pty rejected (command policy active)"
	}
	return "allowed"
}

func printDecision(eff signer.PolicySet, command string) {
	allowed, approval, rule, err := eff.Decide(command)
	auditMode := eff.Enforcement() == signer.CmdPolicyAudit
	fmt.Printf("\nCommand: %s\n", command)
	switch {
	case err != nil:
		if auditMode {
			fmt.Printf("Decision: ALLOWED with audit warning (would error: %v)\n", err)
		} else {
			fmt.Printf("Decision: ERROR (%v)\n", err)
		}
	case !allowed:
		if auditMode {
			fmt.Printf("Decision: ALLOWED with audit warning (would deny; rule: %s)\n", rule)
		} else {
			fmt.Printf("Decision: DENIED  (rule: %s)\n", rule)
		}
	case approval:
		if auditMode {
			fmt.Printf("Decision: ALLOWED with audit warning (would require approval; rule: %s)\n", rule)
		} else {
			fmt.Printf("Decision: ALLOWED, requires approval  (rule: %s)\n", rule)
		}
	default:
		fmt.Printf("Decision: ALLOWED  (rule: %s)\n", dash(rule))
	}
}
