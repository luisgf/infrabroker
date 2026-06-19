package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

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
	if len(args) == 0 || args[0] != "explain" {
		fmt.Fprintln(os.Stderr, "Usage: broker-ctl [--config f] policy explain --host <name> [--command <cmd>]")
		os.Exit(1)
	}
	cmdPolicyExplain(args[1:])
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
	if len(parts) == 0 {
		return "off"
	}
	return strings.Join(parts, " ")
}

func sessionStatus(eff signer.PolicySet) string {
	if eff.Restricts() {
		return "rejected (command policy active — use one-shot ssh_execute)"
	}
	return "allowed"
}

func printDecision(eff signer.PolicySet, command string) {
	allowed, approval, rule, err := eff.Decide(command)
	fmt.Printf("\nCommand: %s\n", command)
	switch {
	case err != nil:
		fmt.Printf("Decision: ERROR (%v)\n", err)
	case !allowed:
		fmt.Printf("Decision: DENIED  (rule: %s)\n", rule)
	case approval:
		fmt.Printf("Decision: ALLOWED, requires approval  (rule: %s)\n", rule)
	default:
		fmt.Printf("Decision: ALLOWED  (rule: %s)\n", dash(rule))
	}
}
