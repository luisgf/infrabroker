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
	"os"
	"sort"
	"strings"

	"github.com/luisgf/infrabroker/internal/confcheck"
	"github.com/luisgf/infrabroker/internal/monitor"
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
	ReloadCallers       []string                   `json:"reload_callers"`
	SignRateLimitPerMin int                        `json:"sign_rate_limit_per_min"`
	CAKey               string                     `json:"ca_key"`
	CAKeys              map[string]doctorCAKey     `json:"ca_keys"`
	StateDB             string                     `json:"state_db"`
	MonitorListen       string                     `json:"monitor_listen"`
	Redact              *json.RawMessage           `json:"redact"`
	AuditFailMode       string                     `json:"audit_fail_mode"`
}

// doctorBroker mirrors broker.Config's checked fields. ca_key/ca_keys are
// LOCAL-mode custody (in-process signing); when the `signer` block is present
// the broker holds no CA key and ignores them (#562).
type doctorBroker struct {
	Signer        *json.RawMessage       `json:"signer"`
	CAKey         string                 `json:"ca_key"`
	CAKeys        map[string]doctorCAKey `json:"ca_keys"`
	Redact        *json.RawMessage       `json:"redact"`
	MonitorListen string                 `json:"monitor_listen"`
	AuditFailMode string                 `json:"audit_fail_mode"`
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
	AuditFailMode string           `json:"audit_fail_mode"`
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

	// reload_callers is the operator tier (reload, policy add/grant, freeze). A CN
	// that is also a `callers` key is a broker identity: it can rewrite its own
	// policy, create grants and unfreeze itself (#640). WARN, not FAIL: the init
	// lab layout does this on purpose (broker-local in both).
	var reloadBrokers []string
	for _, cn := range sc.ReloadCallers {
		if _, ok := sc.Callers[cn]; ok && cn != "_default" {
			reloadBrokers = append(reloadBrokers, cn)
		}
	}
	if len(reloadBrokers) > 0 {
		sort.Strings(reloadBrokers)
		add(docWARN, "reload_callers contains a broker CN", fmt.Sprintf("`reload_callers` lists %s, which is also a `callers` key — a broker-held identity can rewrite its own policy, create grants and unfreeze itself. Use a dedicated admin CN (pki/admin); the `init` lab layout does this on purpose.", strings.Join(reloadBrokers, ", ")))
	}

	f = append(f,
		caCustodyFinding(sc.CAKey, sc.CAKeys, "signer"),
		rateLimitFinding(sc.SignRateLimitPerMin),
		stateDBFinding(sc.StateDB, "signer"),
		redactFinding(sc.Redact, "signer.json"),
		monitorFinding(sc.MonitorListen, "signer"),
		auditFailModeFinding(sc.AuditFailMode, "signer.json"),
	)
	return f
}

// caCustodyFinding checks the CA custody of a service that signs in-process:
// the signer, or a broker in LOCAL mode (no `signer` block, #562). internal/ca
// loads EVERY ca_keys group, not just _default, so a local `pem` key in ANY
// group — plus the legacy single ca_key — is a production smell, not only in
// the default. Flag every pem-backed group; a non-pem _default alongside a
// per-group pem override must not read as PASS. internal/ca LoadCA has no
// default type: an empty or misspelled `type` is "unknown CA key type" and
// LoadGroupCAs fails, so the service refuses to start — a `_default` that is
// really a PEM key with the `type` line forgotten must not read as
// production-grade custody (#442, cf. #240).
func caCustodyFinding(caKey string, caKeys map[string]doctorCAKey, svc string) doctorFinding {
	var pemGroups, badGroups []string
	for name, d := range caKeys {
		switch d.Type {
		case "pem":
			pemGroups = append(pemGroups, name)
		case "akv", "agent":
		default:
			badGroups = append(badGroups, fmt.Sprintf("%s (type %q)", name, d.Type))
		}
	}
	_, hasDefault := caKeys["_default"]
	if !hasDefault && caKey != "" {
		pemGroups = append(pemGroups, "ca_key (legacy)")
	}
	sort.Strings(pemGroups)
	sort.Strings(badGroups)
	switch {
	case !hasDefault && caKey == "":
		// No resolvable default CA — either nothing configured, or ca_keys groups
		// with no `_default` and no legacy `ca_key`. LoadGroupCAs requires a
		// default, so the service refuses to start; flag it rather than PASS a
		// config that cannot boot.
		return doctorFinding{docWARN, svc + " CA custody configured", fmt.Sprintf("no default CA — set `ca_key` or `ca_keys._default` (the %s refuses to start without one).", svc)}
	case len(badGroups) > 0:
		fix := fmt.Sprintf("`ca_keys` type is missing or unknown for: %s — the %s refuses to start (supported types are `pem`, `akv`, `agent`). Set `type` to `akv` (Azure Key Vault) or `agent` (ssh-agent/hardware) in production; `pem` is lab-only.", strings.Join(badGroups, ", "), svc)
		if len(pemGroups) > 0 {
			fix += fmt.Sprintf(" Also local `pem` custody for: %s.", strings.Join(pemGroups, ", "))
		}
		return doctorFinding{docFAIL, fmt.Sprintf("%s CA custody type invalid (%s refuses to start)", svc, svc), fix}
	case len(pemGroups) > 0:
		return doctorFinding{docFAIL, svc + " CA custody not local PEM", fmt.Sprintf("CA custody is local `pem` (a key file on disk) for: %s. Use `akv` (Azure Key Vault) or `agent` (ssh-agent/hardware) in production; `pem` is lab-only.", strings.Join(pemGroups, ", "))}
	default:
		return doctorFinding{docPASS, svc + " CA custody not local PEM", ""}
	}
}

// auditFailModeFinding flags `audit_fail_mode: open`, which reverts the v2.0.0
// fail-closed default (#184/#200): with the audit log unwritable the service
// would keep executing, signing or approving unrecorded. A value
// audit.FailClosed rejects is a startup error and is flagged too (#562).
func auditFailModeFinding(mode, file string) doctorFinding {
	switch mode {
	case "", "closed":
		return doctorFinding{docPASS, file + " audit_fail_mode fail-closed", ""}
	case "open":
		return doctorFinding{docFAIL, file + " audit_fail_mode fail-closed", "`audit_fail_mode` is `open` — when the audit log cannot be written, actions proceed unrecorded (the pre-2.0 behaviour). Remove it or set `closed` so an audit-trail gap denies the action instead."}
	default:
		return doctorFinding{docFAIL, file + " audit_fail_mode fail-closed", fmt.Sprintf("`audit_fail_mode` %q is not valid (want `closed` or `open`) — the service refuses to start. Remove it (`closed` is the default).", mode)}
	}
}

func checkBrokerConfig(path string) []doctorFinding {
	var bc doctorBroker
	if err := loadDoctorJSON(path, &bc); err != nil {
		return []doctorFinding{{docFAIL, "config.json readable/parseable", fmt.Sprintf("could not read %s: %v", path, err)}}
	}
	// CA custody: a broker with a `signer` block holds no CA key (remote mode —
	// custody lives in the signer and is checked there); without one it signs
	// in-process from ca_key/ca_keys and is held to the same custody rule as
	// the signer (#562).
	custody := doctorFinding{docPASS, "broker CA custody separated (remote mode)", ""}
	if bc.Signer == nil {
		custody = caCustodyFinding(bc.CAKey, bc.CAKeys, "broker")
	}
	return []doctorFinding{
		custody,
		redactFinding(bc.Redact, "config.json"),
		monitorFinding(bc.MonitorListen, "broker"),
		auditFailModeFinding(bc.AuditFailMode, "config.json"),
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
		// Not a vulnerability: with no sign_callers list the control plane
		// already denies an approver CN the sign path (isSignCaller — role
		// separation, secure by default). What is missing is the explicit
		// allowlist, so any OTHER CN client_ca signed may sign; hygiene, not a
		// FAIL (#563).
		f = append(f, doctorFinding{docWARN, "sign_callers restricts the signing path", "`sign_callers` is empty — no explicit allowlist; approver CNs (`approval.callers`) are already denied the sign path, but any other CN signed by `client_ca` may sign. List the broker CNs in `sign_callers` to pin the signing path to them."})
	case approvers > 0:
		// A non-empty sign_callers is an exact allowlist WITHOUT the approver
		// exclusion (isSignCaller), so an approver CN listed in it may originate
		// signing requests — role separation is lost (#640).
		inApprovers := make(map[string]bool, approvers)
		for _, cn := range cp.Approval.Callers {
			inApprovers[cn] = true
		}
		var overlap []string
		for _, cn := range cp.SignCallers {
			if inApprovers[cn] {
				overlap = append(overlap, cn)
			}
		}
		if len(overlap) > 0 {
			sort.Strings(overlap)
			f = append(f, doctorFinding{docFAIL, "sign_callers and approval.callers overlap", fmt.Sprintf("%s in both `sign_callers` and `approval.callers` — an approver CN in `sign_callers` may originate signing requests, so role separation is lost; remove it from one list.", strings.Join(overlap, ", "))})
		} else {
			f = append(f, doctorFinding{docPASS, "sign_callers restricts the signing path", ""})
		}
	default:
		f = append(f, doctorFinding{docPASS, "broker/approver separation (no approvers configured)", ""})
	}
	f = append(f, stateDBFinding(cp.StateDB, "control-plane"))
	f = append(f, redactFinding(cp.Redact, "control-plane.json"))
	f = append(f, monitorFinding(cp.MonitorListen, "control-plane"))
	f = append(f, auditFailModeFinding(cp.AuditFailMode, "control-plane.json"))
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

// doctorRedact mirrors internal/redact.Config's two knobs so the preflight can
// tell an effectively-enabled redactor from a present-but-no-op one.
type doctorRedact struct {
	DisableDefaults bool              `json:"disable_defaults"`
	Patterns        []json.RawMessage `json:"patterns"`
}

func redactFinding(raw *json.RawMessage, file string) doctorFinding {
	if raw == nil {
		// #400: absent now selects the built-in default rules, so this is no
		// longer a warning — it is the secure default. Nothing to flag.
		return doctorFinding{docPASS, file + " redact enabled", ""}
	}
	// A block that disables the built-in defaults and defines no patterns yields a
	// zero-rule redactor (internal/redact.New): present but a no-op. Presence alone
	// is not efficacy.
	var rc doctorRedact
	_ = json.Unmarshal(*raw, &rc)
	if rc.DisableDefaults && len(rc.Patterns) == 0 {
		return doctorFinding{docWARN, file + " redact enabled", "`redact` sets `disable_defaults` with no `patterns` — the redactor has zero rules and secrets are stored verbatim. Drop `disable_defaults` (to keep the built-ins) or add `patterns`."}
	}
	return doctorFinding{docPASS, file + " redact enabled", ""}
}

func monitorFinding(addr, svc string) doctorFinding {
	if strings.TrimSpace(addr) == "" {
		return doctorFinding{docPASS, svc + " monitor_listen not public (disabled)", ""}
	}
	if monitor.ListenIsPublic(addr) {
		return doctorFinding{docFAIL, svc + " monitor_listen not public", fmt.Sprintf("`monitor_listen` %q is public — /metrics and /healthz are unauthenticated. Bind to 127.0.0.1 or a private scrape interface.", addr)}
	}
	return doctorFinding{docPASS, svc + " monitor_listen not public", ""}
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
