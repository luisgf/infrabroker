package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/luisgf/ssh-broker/internal/audit"
	"github.com/luisgf/ssh-broker/internal/policyrec"
	"github.com/luisgf/ssh-broker/internal/signer"
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
		"  broker-ctl [--config f] policy recommend --audit <log> [--host h] [--since t] [--min-count n] [--json]\n"+
		"  broker-ctl [--config f] policy add       --host <name> --allow <regex>   (signer mutation API, mTLS)\n"+
		"  broker-ctl [--config f] policy remove    --host <name> --allow <regex>\n"+
		"  broker-ctl [--config f] policy grant     --host <name> --allow <regex> [--ttl 2h] [--caller cn] [--end-user u]   (runtime grant, mTLS)\n"+
		"  broker-ctl [--config f] policy grants    [--json]                       (list active grants, mTLS)\n"+
		"  broker-ctl [--config f] policy revoke    <grant-id>                     (mTLS)")
}

// policyHTTP builds an mTLS client and the signer base URL ("https://host:port")
// from the global --config, shared by the grant commands.
func policyHTTP(cert, key, ca string) (*http.Client, string) {
	signerURL, err := readSignerURL(configPath)
	if err != nil {
		fatalf("reading signer URL from config: %v", err)
	}
	tlsCfg, err := buildTLSConfig(cert, key, ca)
	if err != nil {
		fatalf("TLS: %v", err)
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}}
	return client, "https://" + signerURL
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
	cert := fs.String("cert", "./pki/broker.crt", "mTLS client cert")
	key := fs.String("key", "./pki/broker.key", "mTLS client key")
	ca := fs.String("ca", "./pki/mtls_ca.crt", "mTLS CA")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: broker-ctl [--config f] policy grant --host <name> --allow <regex> [--ttl 2h] [--caller cn] [--end-user u]")
		fs.PrintDefaults()
	}
	must(fs.Parse(args))
	if *host == "" || *allow == "" || *ttl <= 0 {
		fs.Usage()
		os.Exit(1)
	}

	client, base := policyHTTP(*cert, *key, *ca)
	endpoint := base + "/v1/policy/hosts/" + url.PathEscape(*host) + "/grants"
	body, _ := json.Marshal(map[string]any{
		"allow": []string{*allow}, "ttl_seconds": int(ttl.Seconds()),
		"caller": *scopeCaller, "end_user": *scopeUser,
	})
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		fatalf("request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		fatalf("POST %s: %v", endpoint, err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		fatalf("signer rejected the grant (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(rb)))
	}
	var result struct {
		ID        string `json:"id"`
		ExpiresAt string `json:"expires_at"`
	}
	_ = json.Unmarshal(rb, &result)
	fmt.Printf("granted on %s: allow %q for %s (id %s, expires %s)\n",
		*host, *allow, *ttl, result.ID, result.ExpiresAt)
}

// cmdPolicyGrants lists the signer's active runtime grants over mTLS.
func cmdPolicyGrants(args []string) {
	fs := flag.NewFlagSet("policy grants", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "output as JSON")
	cert := fs.String("cert", "./pki/broker.crt", "mTLS client cert")
	key := fs.String("key", "./pki/broker.key", "mTLS client key")
	ca := fs.String("ca", "./pki/mtls_ca.crt", "mTLS CA")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: broker-ctl [--config f] policy grants [--json]")
		fs.PrintDefaults()
	}
	must(fs.Parse(args))

	client, base := policyHTTP(*cert, *key, *ca)
	resp, err := client.Get(base + "/v1/policy/grants")
	if err != nil {
		fatalf("GET %s/v1/policy/grants: %v", base, err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		fatalf("signer rejected the request (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(rb)))
	}
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
	cert := fs.String("cert", "./pki/broker.crt", "mTLS client cert")
	key := fs.String("key", "./pki/broker.key", "mTLS client key")
	ca := fs.String("ca", "./pki/mtls_ca.crt", "mTLS CA")
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

	client, base := policyHTTP(*cert, *key, *ca)
	endpoint := base + "/v1/policy/grants/" + url.PathEscape(id)
	req, err := http.NewRequest(http.MethodDelete, endpoint, nil)
	if err != nil {
		fatalf("request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		fatalf("DELETE %s: %v", endpoint, err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		fatalf("signer rejected the revoke (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(rb)))
	}
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
	cert := fs.String("cert", "./pki/broker.crt", "mTLS client cert")
	key := fs.String("key", "./pki/broker.key", "mTLS client key")
	ca := fs.String("ca", "./pki/mtls_ca.crt", "mTLS CA")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: broker-ctl [--config f] policy %s --host <name> --allow <regex>\n", op)
		fs.PrintDefaults()
	}
	must(fs.Parse(args))
	if *host == "" || *allow == "" {
		fs.Usage()
		os.Exit(1)
	}

	signerURL, err := readSignerURL(configPath)
	if err != nil {
		fatalf("reading signer URL from config: %v", err)
	}
	endpoint := "https://" + signerURL + "/v1/policy/hosts/" + url.PathEscape(*host) + "/allow"
	tlsCfg, err := buildTLSConfig(*cert, *key, *ca)
	if err != nil {
		fatalf("TLS: %v", err)
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}}

	method := http.MethodPost
	if !add {
		method = http.MethodDelete
	}
	body, _ := json.Marshal(map[string]string{"pattern": *allow})
	req, err := http.NewRequest(method, endpoint, bytes.NewReader(body))
	if err != nil {
		fatalf("request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		fatalf("%s %s: %v", method, endpoint, err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		fatalf("signer rejected the change (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(rb)))
	}
	var result struct {
		Hosts int `json:"hosts"`
	}
	_ = json.Unmarshal(rb, &result)
	fmt.Printf("allow %q %s on %s (hosts: %d)\n", *allow, past, *host, result.Hosts)
}

// cmdPolicyRecommend mines an audit log and prints advisory command-policy
// suggestions (promote / dead-rule / friction). Read-only: it never changes
// policy. The config (for the current rules) comes from the global --config.
func cmdPolicyRecommend(args []string) {
	fs := flag.NewFlagSet("policy recommend", flag.ExitOnError)
	auditLog := fs.String("audit", "", "path to an audit log to mine (required)")
	host := fs.String("host", "", "restrict to one host")
	since := fs.String("since", "", "ignore entries before this time (RFC3339 or YYYY-MM-DD)")
	minCount := fs.Int("min-count", 1, "suppress suggestions with fewer occurrences")
	asJSON := fs.Bool("json", false, "output as JSON")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: broker-ctl [--config f] policy recommend --audit <log> [--host h] [--since t] [--min-count n] [--json]")
		fs.PrintDefaults()
	}
	must(fs.Parse(args))
	if *auditLog == "" {
		fs.Usage()
		os.Exit(1)
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
	if err := json.Unmarshal(b, &cfg); err != nil {
		fatalf("parse config: %v", err)
	}
	compiled, err := signer.CompileHostPolicies(cfg.Hosts, cfg.CommandPolicies, cfg.GroupCommandPolicies)
	if err != nil {
		fatalf("invalid policy config: %v", err)
	}

	entries := loadAuditEntries(*auditLog)
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
	printRecommendations(*auditLog, len(entries), sugs)
}

// loadAuditEntries reads an NDJSON audit log into entries (malformed lines are
// skipped). The integrity chain is not verified here — a follow-up should reuse
// the audit-verify path before mining a log of unknown provenance.
func loadAuditEntries(path string) []audit.Entry {
	f, err := os.Open(path)
	if err != nil {
		fatalf("open audit log: %v", err)
	}
	defer f.Close()
	var out []audit.Entry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 256*1024), 256*1024)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var e audit.Entry
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			out = append(out, e)
		}
	}
	if err := sc.Err(); err != nil {
		fatalf("read audit log: %v", err)
	}
	return out
}

func printRecommendations(logPath string, n int, sugs []policyrec.Suggestion) {
	fmt.Printf("Policy recommendations (from %s, %d entries)\n", logPath, n)
	if len(sugs) == 0 {
		fmt.Println("  (no suggestions)")
		return
	}
	for _, s := range sugs {
		switch s.Type {
		case policyrec.Promote:
			fmt.Printf("\n  [PROMOTE]  %s   %s\n", s.Host, s.Pattern)
			fmt.Printf("     %d× · %d callers · %d human-approved · last %s\n",
				s.Count, s.Callers, s.Approved, s.LastSeen.UTC().Format("2006-01-02"))
			if len(s.Samples) > 0 {
				fmt.Printf("     e.g. %s\n", s.Samples[0])
			}
			fmt.Printf("     → add to the allowlist of %s if intended\n", s.Host)
		case policyrec.Friction:
			fmt.Printf("\n  [FRICTION] %s   denied %d× : %s\n", s.Host, s.Count, s.Pattern)
		case policyrec.DeadRule:
			fmt.Printf("\n  [DEAD]     %s   %s   (0 matches in window → review/remove)\n", s.Host, s.Pattern)
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
	if err := json.Unmarshal(b, &cfg); err != nil {
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
	if cp.ShellParse {
		parts = append(parts, "shell_parse")
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
