package main

// broker-ctl doctor --security is an offline production-hardening preflight. It
// reads the local config files — no keys, no network — and checks them against
// the deploy/README.md production checklist, printing PASS / WARN / FAIL with a
// one-line fix for each finding. Exit code 1 if any FAIL. The partial structs
// below decode only the checked fields; unknown keys (and `_comment` keys) are
// ignored, so the check never fails on the rest of a real config.

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/luisgf/infrabroker/internal/confcheck"
)

const (
	docPASS = "PASS"
	docWARN = "WARN"
	docFAIL = "FAIL"
)

// doctorFinding is one checklist result. fix is the one-line remediation (empty
// for PASS).
type doctorFinding struct {
	level string
	check string
	fix   string
}

type doctorCAKey struct {
	Type string `json:"type"`
}

type doctorCaller struct {
	AllowedGroups []string `json:"allowed_groups"`
}

type doctorSigner struct {
	Callers             map[string]json.RawMessage `json:"callers"`
	SignRateLimitPerMin int                        `json:"sign_rate_limit_per_min"`
	CAKey               string                     `json:"ca_key"`
	CAKeys              map[string]doctorCAKey     `json:"ca_keys"`
	StateDB             string                     `json:"state_db"`
	MonitorListen       string                     `json:"monitor_listen"`
	Redact              *json.RawMessage           `json:"redact"`
}

type doctorBroker struct {
	Signer        *json.RawMessage `json:"signer"`
	Redact        *json.RawMessage `json:"redact"`
	MonitorListen string           `json:"monitor_listen"`
}

type doctorApproval struct {
	Callers []string `json:"callers"`
}

type doctorControlPlane struct {
	SignCallers   []string         `json:"sign_callers"`
	Approval      *doctorApproval  `json:"approval"`
	StateDB       string           `json:"state_db"`
	MonitorListen string           `json:"monitor_listen"`
	Redact        *json.RawMessage `json:"redact"`
}

func cmdDoctor(args []string) {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	security := fs.Bool("security", false, "run the security / production-hardening preflight")
	signerPath := fs.String("signer", "", "path to signer.json")
	brokerPath := fs.String("broker", "", "path to the broker config.json")
	cpPath := fs.String("control-plane", "", "path to control-plane.json")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: broker-ctl doctor --security [--signer f] [--broker f] [--control-plane f]")
		fmt.Fprintln(os.Stderr, "\nOffline production-hardening preflight against the config files (no keys, no network).")
		fmt.Fprintln(os.Stderr, "Exit code 1 if any check FAILs.")
		fs.PrintDefaults()
	}
	must(fs.Parse(args))
	if !*security {
		fs.Usage()
		os.Exit(2)
	}
	if *signerPath == "" && *brokerPath == "" && *cpPath == "" {
		fatalf("provide at least one of --signer, --broker, --control-plane")
	}

	var findings []doctorFinding
	if *signerPath != "" {
		findings = append(findings, checkSignerConfig(*signerPath)...)
	}
	if *brokerPath != "" {
		findings = append(findings, checkBrokerConfig(*brokerPath)...)
	}
	if *cpPath != "" {
		findings = append(findings, checkControlPlaneConfig(*cpPath)...)
	}
	if printDoctorFindings(findings) > 0 {
		os.Exit(1)
	}
}

// loadDoctorJSON reads path and decodes only the fields present in v, ignoring
// unknown keys. Comments are the legacy `_comment` string keys, which are just
// ignored object members — no stripping needed.
func loadDoctorJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return confcheck.Unmarshal(b, v)
}

func checkSignerConfig(path string) []doctorFinding {
	var sc doctorSigner
	if err := loadDoctorJSON(path, &sc); err != nil {
		return []doctorFinding{{docFAIL, "signer.json readable/parseable", fmt.Sprintf("could not read %s: %v", path, err)}}
	}
	var f []doctorFinding
	add := func(level, check, fix string) { f = append(f, doctorFinding{level, check, fix}) }

	// callers RBAC: since v2.0.0 a non-empty `callers` table is default-deny for
	// unlisted broker CNs (they inherit `_default`, or the zero policy = no hosts).
	// The only remaining misconfiguration is no `callers` at all (unrestricted),
	// or an explicit `_default` that GRANTS groups to every unlisted CN.
	if len(sc.Callers) == 0 {
		add(docWARN, "callers RBAC configured", "no `callers` block — every authenticated broker CN can request/sign ALL hosts. Add a `callers` table (non-empty is default-deny: unlisted CNs get no hosts) to scope brokers to host groups.")
	} else if raw, ok := sc.Callers["_default"]; !ok {
		add(docPASS, "callers RBAC default-deny", "")
	} else {
		var d doctorCaller
		_ = json.Unmarshal(raw, &d)
		if len(d.AllowedGroups) == 0 {
			add(docPASS, "callers RBAC default-deny", "")
		} else {
			add(docWARN, "callers RBAC default-deny", fmt.Sprintf("`_default` grants groups %v to every unlisted CN — that widens access beyond the default-deny you get by omitting `_default`. Remove it or set `allowed_groups` to [] unless intentional.", d.AllowedGroups))
		}
	}

	// CA custody.
	caType := ""
	if d, ok := sc.CAKeys["_default"]; ok {
		caType = d.Type
	} else if sc.CAKey != "" {
		caType = "pem" // legacy ca_key is a local PEM path
	}
	switch caType {
	case "":
		add(docWARN, "CA custody configured", "no `ca_key`/`ca_keys` — the signer has no CA to sign with.")
	case "pem":
		add(docFAIL, "CA custody not local PEM", "CA custody is `pem` (a local key file). Use `akv` (Azure Key Vault) or `agent` (ssh-agent/hardware) in production; `pem` is lab-only.")
	default:
		add(docPASS, "CA custody not local PEM", "")
	}

	f = append(f,
		rateLimitFinding(sc.SignRateLimitPerMin),
		stateDBFinding(sc.StateDB, "signer"),
		redactFinding(sc.Redact != nil, "signer.json"),
		monitorFinding(sc.MonitorListen, "signer"),
	)
	return f
}

func checkBrokerConfig(path string) []doctorFinding {
	var bc doctorBroker
	if err := loadDoctorJSON(path, &bc); err != nil {
		return []doctorFinding{{docFAIL, "config.json readable/parseable", fmt.Sprintf("could not read %s: %v", path, err)}}
	}
	return []doctorFinding{
		redactFinding(bc.Redact != nil, "config.json"),
		monitorFinding(bc.MonitorListen, "broker"),
	}
}

func checkControlPlaneConfig(path string) []doctorFinding {
	var cp doctorControlPlane
	if err := loadDoctorJSON(path, &cp); err != nil {
		return []doctorFinding{{docFAIL, "control-plane.json readable/parseable", fmt.Sprintf("could not read %s: %v", path, err)}}
	}
	approvers := 0
	if cp.Approval != nil {
		approvers = len(cp.Approval.Callers)
	}
	var f []doctorFinding
	switch {
	case approvers > 0 && len(cp.SignCallers) == 0:
		f = append(f, doctorFinding{docFAIL, "sign_callers restricts the signing path", "`approval.callers` is set but `sign_callers` is empty — an approver certificate (signed by the same client_ca) could originate signing requests. List the broker CNs in `sign_callers`."})
	case approvers > 0:
		f = append(f, doctorFinding{docPASS, "sign_callers restricts the signing path", ""})
	default:
		f = append(f, doctorFinding{docPASS, "broker/approver separation (no approvers configured)", ""})
	}
	f = append(f, stateDBFinding(cp.StateDB, "control-plane"))
	f = append(f, redactFinding(cp.Redact != nil, "control-plane.json"))
	f = append(f, monitorFinding(cp.MonitorListen, "control-plane"))
	return f
}

func rateLimitFinding(perMin int) doctorFinding {
	if perMin <= 0 {
		return doctorFinding{docWARN, "sign_rate_limit_per_min set", "not set — no per-caller signing cap (gap #4). Size `sign_rate_limit_per_min` to the busiest legitimate broker's rate."}
	}
	return doctorFinding{docPASS, "sign_rate_limit_per_min set", ""}
}

func stateDBFinding(path, svc string) doctorFinding {
	if strings.TrimSpace(path) == "" {
		return doctorFinding{docWARN, svc + " state_db set", "not set — runtime grants/waivers/freezes are in-memory and lost on restart (a freeze needs it to survive, and is refused without it unless opted in as volatile). Set `state_db` to a persistent path."}
	}
	return doctorFinding{docPASS, svc + " state_db set", ""}
}

func redactFinding(present bool, file string) doctorFinding {
	if !present {
		return doctorFinding{docWARN, file + " redact enabled", "no `redact` block — secrets in commands are stored verbatim in audit logs/recordings/notifications. Add `\"redact\": {}` for the built-in patterns."}
	}
	return doctorFinding{docPASS, file + " redact enabled", ""}
}

func monitorFinding(addr, svc string) doctorFinding {
	if strings.TrimSpace(addr) == "" {
		return doctorFinding{docPASS, svc + " monitor_listen not public (disabled)", ""}
	}
	if listenIsPublic(addr) {
		return doctorFinding{docFAIL, svc + " monitor_listen not public", fmt.Sprintf("`monitor_listen` %q is public — /metrics and /healthz are unauthenticated. Bind to 127.0.0.1 or a private scrape interface.", addr)}
	}
	return doctorFinding{docPASS, svc + " monitor_listen not public", ""}
}

// listenIsPublic reports whether a listen address is reachable from outside the
// host: an unspecified bind (0.0.0.0/::/empty host) or a globally-routable IP.
// Loopback, RFC1918/ULA private, and link-local addresses are treated as safe.
func listenIsPublic(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if host == "" {
		return true // ":9160" binds every interface
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return !strings.EqualFold(host, "localhost")
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return false
	}
	return true // unspecified (0.0.0.0/::) or a specific global address
}

// printDoctorFindings prints the findings grouped by level and returns the FAIL
// count. FAILs first (with fixes), then WARNs, then a PASS count.
func printDoctorFindings(findings []doctorFinding) int {
	var fails, warns, passes int
	for _, f := range findings {
		switch f.level {
		case docFAIL:
			fails++
		case docWARN:
			warns++
		default:
			passes++
		}
	}
	for _, lvl := range []string{docFAIL, docWARN} {
		for _, f := range findings {
			if f.level == lvl {
				fmt.Printf("[%s] %s\n", f.level, f.check)
				if f.fix != "" {
					fmt.Printf("       fix: %s\n", f.fix)
				}
			}
		}
	}
	fmt.Printf("\n%d PASS, %d WARN, %d FAIL\n", passes, warns, fails)
	if fails == 0 && warns == 0 {
		fmt.Println("security preflight clean.")
	} else if fails == 0 {
		fmt.Println("no failures; review the warnings above.")
	} else {
		fmt.Println("FAILED: fix the items above before running in production.")
	}
	return fails
}
