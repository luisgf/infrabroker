// Command control-plane is the Policy Enforcement Point between the broker and
// the signer. It forwards signing requests to the signer, propagating the
// broker identity (on_behalf_of), and orchestrates human approval for commands
// that the command policy flags as require_approval. It does NOT hold the CA
// key (which lives in the signer).
//
// Approval flow (async polling, to avoid holding open connections):
//  1. broker → POST /v1/sign. The control plane forwards to the signer
//     (approved=false).
//  2. If the signer returns no certificate (requires approval), the control
//     plane creates a request, notifies out-of-band, and responds 202
//     {approval_id}.
//  3. The broker polls GET /v1/sign/result/{id}.
//  4. A human approves with POST /v1/approvals/{id} (broker-ctl approval allow).
//  5. The next poll forwards to the signer with approved=true and returns the
//     cert.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/luisgf/infrabroker/internal/audit"
	"github.com/luisgf/infrabroker/internal/auth"
	"github.com/luisgf/infrabroker/internal/confcheck"
	"github.com/luisgf/infrabroker/internal/control"
	"github.com/luisgf/infrabroker/internal/httpserve"
	"github.com/luisgf/infrabroker/internal/monitor"
	"github.com/luisgf/infrabroker/internal/redact"
	"github.com/luisgf/infrabroker/internal/signer"
	"github.com/luisgf/infrabroker/internal/statedb"
	"github.com/luisgf/infrabroker/internal/version"
)

// Config is the control plane configuration.
type Config struct {
	Listen string `json:"listen"` // e.g. ":7443"

	// mTLS toward the broker: presents server_cert and requires clients signed
	// by client_ca.
	ServerCert string `json:"server_cert"`
	ServerKey  string `json:"server_key"`
	ClientCA   string `json:"client_ca"`

	// SignCallers: client cert CNs authorised to use the signing path
	// (/v1/sign, /v1/hosts, /v1/sign/result) — i.e. the brokers. This separates
	// the broker role from the approver role (approval.callers) when both are
	// signed by the same client_ca. If non-empty, only these CNs may request
	// signing. If empty/absent, any authenticated broker may — EXCEPT a CN that
	// is in approval.callers, which is an approver, not a broker, and is denied
	// the sign path (role separation, secure by default).
	SignCallers []string `json:"sign_callers,omitempty"`

	// Signer: mTLS client toward the signing service.
	Signer struct {
		URL        string `json:"url"`
		ClientCert string `json:"client_cert"`
		ClientKey  string `json:"client_key"`
		CA         string `json:"ca"`
	} `json:"signer"`

	// Approval: human-approval orchestration.
	Approval struct {
		Notifier       string   `json:"notifier"`        // ""/"log" (default) | "webhook" | "teams"
		WebhookURL     string   `json:"webhook_url"`     // required when notifier=webhook or teams
		TimeoutSeconds int      `json:"timeout_seconds"` // TTL for pending requests
		Callers        []string `json:"callers"`         // CNs authorised to approve/deny

		// Teams-specific fields (notifier=teams).
		TeamsFormat         string `json:"teams_format"`          // ""/"workflow" (default) | "adaptivecard" | "messagecard"
		ApprovalURLTemplate string `json:"approval_url_template"` // URL with "{id}" to link the request
	} `json:"approval"`

	// Behavior: behaviour guardrails (anomaly detection + rate limiting).
	Behavior control.BehaviorConfig `json:"behavior"`

	// TrustedForwarders: broker client cert CNs whose end_user claim is trusted
	// (brokers that authenticate end users, e.g. via OIDC). Mirrors the
	// signer's trusted_forwarders semantics. Behaviour guardrails key on
	// "<broker CN>:<end_user>" only for these CNs; for any other CN the
	// client-supplied end_user is ignored and the authenticated broker CN alone
	// is used, so a client cannot evade rate limits or anomaly detection by
	// rotating end_user. Empty/absent = end_user never qualifies the subject.
	TrustedForwarders []string `json:"trusted_forwarders,omitempty"`

	// Audit log for the control plane (independent of broker and signer).
	AuditLog string `json:"audit_log"`
	AuditKey string `json:"audit_key"`

	// AuditFailMode governs what happens when the control-plane audit log cannot
	// be written for an approval-critical record (the approval decision and the
	// grant that hands out a certificate/token). "" and "closed" fail closed
	// (reject the approval rather than grant it with the "who approved" record only
	// on stderr — the secure default, matching the signer #184); "open" logs the
	// error and proceeds (pre-2.0 behaviour). Best-effort records (forwarded,
	// denied, anomaly, rate-limited) are unaffected.
	AuditFailMode string `json:"audit_fail_mode,omitempty"`

	// MonitorListen: optional plain-HTTP monitoring listener serving /healthz
	// (liveness), /readyz (readiness: 503 until the main listener binds and
	// during drain) and /metrics (Prometheus text format). No authentication —
	// bind to localhost or a private scrape interface. Empty = disabled.
	MonitorListen string `json:"monitor_listen,omitempty"`

	// Redact enables secret redaction on the control plane's persistent and
	// outbound sinks: the audit log's free-text fields and the approval
	// notification payload (log/webhook/Teams). Absent = the built-in default
	// patterns (#400: redaction is on by default); the operator may disable
	// the built-ins or add their own patterns via the knobs in redact.Config.
	// The approval registry itself keeps the original command: the mTLS
	// approval UI and API show the approver exactly what will run, and the
	// approved request forwarded to the signer is untouched.
	Redact *redact.Config `json:"redact,omitempty"`

	// StateDB: optional path to the SQLite state database that persists the
	// approval registry (pending and approved-but-uncollected requests, with
	// their original wire request) across restarts (pure-Go driver; WAL mode
	// leaves state.db-wal/-shm sidecar files next to it). Empty or absent =
	// in-memory only (previous behaviour: a restart clears pending
	// approvals). If set and the database cannot be opened or migrated, the
	// service refuses to start (fail-closed). Production:
	// /var/lib/infrabroker/control-plane/state.db.
	StateDB string `json:"state_db,omitempty"`
}

type server struct {
	remote   *signer.Remote
	registry *control.Registry
	notifier control.Notifier
	behavior *control.BehaviorTracker
	audit    *audit.Log
	// auditFailClosed rejects an approval decision / grant when its audit record
	// cannot be written (audit_fail_mode=closed, the default), so the "who
	// approved" attribution is durable before a credential is handed out (#205).
	auditFailClosed bool
	redactor        *redact.Redactor // nil = redaction disabled; applied to notifier payloads
	approveCN       map[string]struct{}
	signCN          map[string]struct{} // CNs allowed on the signing path (brokers); empty = any non-approver
	forwarders      map[string]struct{} // CNs whose end_user claim is trusted (guardrail subject)
}

// isSignCaller reports whether cn may use the signing path (/v1/sign, /v1/hosts,
// /v1/sign/result). A non-empty sign_callers list is an exact allowlist. With no
// list, any CN may — except an approver CN (in approval.callers), which is not a
// broker and is denied the sign path (role separation, secure by default).
func (s *server) isSignCaller(cn string) bool {
	if len(s.signCN) > 0 {
		_, ok := s.signCN[cn]
		return ok
	}
	_, isApprover := s.approveCN[cn]
	return !isApprover
}

// signCaller authenticates the caller and checks it may use the signing path.
// Writes 401/403 and returns ok=false on failure.
func (s *server) signCaller(w http.ResponseWriter, r *http.Request) (string, bool) {
	cn, err := auth.CallerCN(r)
	if err != nil {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return "", false
	}
	if !s.isSignCaller(cn) {
		http.Error(w, "not authorised to request signing", http.StatusForbidden)
		return "", false
	}
	return cn, true
}

func main() {
	cfgPath := flag.String("config", "control-plane.json", "path to the JSON/JSONC configuration file")
	showVersion := flag.Bool("version", false, "print version and exit")
	verbose := flag.Bool("verbose", false, "with --version, print detailed build info")
	flag.Parse()

	if *showVersion {
		version.Print(*verbose)
		return
	}

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	signerTLS, err := auth.ClientTLSConfig(cfg.Signer.ClientCert, cfg.Signer.ClientKey, cfg.Signer.CA)
	if err != nil {
		log.Fatalf("signer client TLS: %v", err)
	}
	remote := signer.NewRemote(cfg.Signer.URL, signerTLS, 10*time.Second)

	seed, err := os.ReadFile(cfg.AuditKey)
	if err != nil {
		log.Fatalf("reading audit key: %v", err)
	}
	if len(seed) < ed25519.SeedSize {
		log.Fatalf("audit key too short")
	}
	auditLog, err := audit.Open(cfg.AuditLog, ed25519.NewKeyFromSeed(seed[:ed25519.SeedSize]))
	if err != nil {
		log.Fatalf("audit: %v", err)
	}
	defer auditLog.Close()
	auditFailClosed, err := audit.FailClosed(cfg.AuditFailMode)
	if err != nil {
		log.Fatalf("%v", err)
	}

	var redactor *redact.Redactor
	// #400: redaction defaults to the built-in patterns even with no `redact`
	// block; a zero-rule config (disable_defaults, no patterns) opts out.
	redactor, err = redact.New(cfg.Redact)
	if err != nil {
		log.Fatalf("redact: %v", err)
	}
	if redactor != nil {
		auditLog.SetRedactor(redactor)
	}

	var notifier control.Notifier = control.LogNotifier{}
	switch cfg.Approval.Notifier {
	case "", "log":
	case "webhook":
		if cfg.Approval.WebhookURL == "" {
			log.Fatalf("notifier=webhook requires webhook_url")
		}
		notifier = control.NewWebhookNotifier(cfg.Approval.WebhookURL)
	case "teams":
		if cfg.Approval.WebhookURL == "" {
			log.Fatalf("notifier=teams requires webhook_url")
		}
		notifier = control.NewTeamsNotifier(
			cfg.Approval.WebhookURL,
			cfg.Approval.TeamsFormat,
			cfg.Approval.ApprovalURLTemplate,
		)
	default:
		log.Fatalf("invalid approval.notifier %q", cfg.Approval.Notifier)
	}

	registry := control.NewRegistry(time.Duration(cfg.Approval.TimeoutSeconds) * time.Second)
	if cfg.StateDB != "" {
		stateDB, err := statedb.Open(cfg.StateDB, control.RegistrySchema)
		if err != nil {
			log.Fatalf("state db: %v", err)
		}
		defer stateDB.Close()
		registry, err = control.NewRegistryDB(time.Duration(cfg.Approval.TimeoutSeconds)*time.Second, stateDB)
		if err != nil {
			log.Fatalf("state db: %v", err)
		}
		log.Printf("state db: %s (%d approvals restored)", cfg.StateDB, len(registry.List()))
	}

	srv := &server{
		remote:          remote,
		registry:        registry,
		notifier:        notifier,
		behavior:        control.NewBehaviorTracker(cfg.Behavior),
		audit:           auditLog,
		auditFailClosed: auditFailClosed,
		redactor:        redactor,
		approveCN:       cnSet(cfg.Approval.Callers),
		signCN:          cnSet(cfg.SignCallers),
		forwarders:      cnSet(cfg.TrustedForwarders),
	}

	tlsCfg, err := auth.ServerTLSConfig(cfg.ServerCert, cfg.ServerKey, cfg.ClientCA)
	if err != nil {
		log.Fatalf("tls: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/sign", srv.handleSign)
	mux.HandleFunc("GET /v1/hosts", srv.handleHosts)
	mux.HandleFunc("GET /v1/clusters", srv.handleClusters)
	mux.HandleFunc("GET /v1/sign/result/{id}", srv.handleResult)
	mux.HandleFunc("GET /v1/approvals", srv.handleApprovalsList)
	mux.HandleFunc("POST /v1/approvals/{id}", srv.handleApprovalDecide)
	// Browser UI for approvers (same mTLS auth + approval.callers check as the
	// API; decisions go through POST /v1/approvals/{id} from same-origin JS).
	mux.HandleFunc("GET /ui/approvals", srv.handleUIList)
	mux.HandleFunc("GET /ui/approvals/{id}", srv.handleUIDetail)

	// Optional monitoring listener (/healthz, /metrics). Plain HTTP on its own
	// address; lives for the whole process, so no ctx wiring. The pending gauge
	// is read at scrape time from the in-memory approval registry.
	monitor.SetGaugeFunc("controlplane_approvals_pending",
		"Approval requests currently pending a human decision.", func() float64 {
			n := 0
			for _, a := range srv.registry.List() {
				if a.Status == control.StatusPending {
					n++
				}
			}
			return float64(n)
		})
	go monitor.Serve(context.Background(), cfg.MonitorListen, "control-plane")

	httpSrv := &http.Server{
		Addr:         cfg.Listen,
		Handler:      mux,
		TLSConfig:    tlsCfg,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	behaviorMode := cfg.Behavior.Mode
	if behaviorMode == "" {
		behaviorMode = control.BehaviorOff
	}
	log.Printf("control-plane (mTLS) on %s; signer=%s; approvers=%d; behavior=%s", cfg.Listen, cfg.Signer.URL, len(srv.approveCN), behaviorMode)
	httpserve.RunTLS(httpSrv, "control-plane", 10*time.Second)
}

// handleSign forwards the request to the signer on behalf of the broker. If
// the signer does not issue a certificate (requires approval), it creates a
// request and responds 202.
func (s *server) handleSign(w http.ResponseWriter, r *http.Request) {
	brokerCN, ok := s.signCaller(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	var req signer.WireRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	// Pure dry-run: pass through the decision (skips guardrails and rate limit,
	// since nothing is executed). Executable preflights, such as
	// ssh_session_exec mode=exec, still run guardrails before the signer decision.
	if req.DryRun && !req.Preflight {
		in, err := intentFrom(req, brokerCN, false)
		if err != nil {
			http.Error(w, "invalid pubkey", http.StatusBadRequest)
			return
		}
		issued, err := s.remote.SignIntent(r.Context(), in)
		if err != nil {
			s.dryRunSignError(w, brokerCN, req, err)
			return
		}
		// Carry the sealed-exec envelope: the session-exec preflight is a dry-run
		// and the envelope is its product (#573).
		writeJSON(w, http.StatusOK, signer.WireResponse{Decision: issued.Decision, Envelope: issued.Envelope})
		return
	}

	// Behaviour guardrails.
	if s.behavior.Enabled() && !s.checkBehaviorGuardrails(w, r, brokerCN, req) {
		return
	}

	if req.DryRun {
		in, err := intentFrom(req, brokerCN, false)
		if err != nil {
			http.Error(w, "invalid pubkey", http.StatusBadRequest)
			return
		}
		issued, err := s.remote.SignIntent(r.Context(), in)
		if err != nil {
			s.dryRunSignError(w, brokerCN, req, err)
			return
		}
		writeJSON(w, http.StatusOK, signer.WireResponse{Decision: issued.Decision, Envelope: issued.Envelope})
		return
	}

	in, err := intentFrom(req, brokerCN, false)
	if err != nil {
		http.Error(w, "invalid pubkey", http.StatusBadRequest)
		return
	}
	issued, err := s.remote.SignIntent(r.Context(), in)
	if err != nil {
		// A signer 5xx (outage, k8s token mint failure) is an infrastructure
		// error, not a denial: audit "error" and relay 502 so the broker keeps
		// the same classification it would get talking to the signer directly
		// (#455). Policy/authorization denials stay 403 + "denied".
		if errors.Is(err, signer.ErrSignerUnavailable) {
			s.auditE(audit.Entry{Caller: brokerCN, Host: req.Host, Command: req.Command, Outcome: "error", Err: err.Error()})
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		s.auditE(audit.Entry{Caller: brokerCN, Host: req.Host, Command: req.Command, Outcome: "denied", Err: err.Error()})
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	s.forwardSignResult(w, r, brokerCN, req, issued)
}

// dryRunSignError answers a failed dry-run/preflight signer call with the same
// split as the live path (#455, #660): a signer outage (ErrSignerUnavailable)
// is audited "error" and relayed as 502, so the broker classifies it as an
// infrastructure failure rather than a policy denial; any other rejection is
// audited "denied" and stays 403. Both records carry dry_run=true.
func (s *server) dryRunSignError(w http.ResponseWriter, brokerCN string, req signer.WireRequest, err error) {
	if errors.Is(err, signer.ErrSignerUnavailable) {
		s.auditE(audit.Entry{Caller: brokerCN, Host: req.Host, Command: req.Command, Outcome: "error", DryRun: true, TargetType: req.TargetType, Err: err.Error()})
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	s.auditE(audit.Entry{Caller: brokerCN, Host: req.Host, Command: req.Command, Outcome: "denied", DryRun: true, TargetType: req.TargetType, Err: err.Error()})
	http.Error(w, err.Error(), http.StatusForbidden)
}

// checkBehaviorGuardrails evaluates the behaviour guardrails. Returns true
// when the request may proceed, false when a response has already been sent
// (blocked/escalated).
func (s *server) checkBehaviorGuardrails(w http.ResponseWriter, r *http.Request, brokerCN string, req signer.WireRequest) bool {
	subject := s.guardrailSubject(brokerCN, req.EndUser)
	anomalies, exceeded := s.behavior.Check(subject, req.Host, req.Command)
	if !s.behavior.Enforcing() {
		// Observe mode: audit the anomaly and continue.
		if len(anomalies) > 0 || exceeded {
			s.auditE(audit.Entry{Caller: brokerCN, Host: req.Host, Command: req.Command, Outcome: "anomaly", Anomaly: strings.Join(anomalies, ",")})
		}
		return true
	}
	// Enforce mode.
	if exceeded {
		s.auditE(audit.Entry{Caller: brokerCN, Host: req.Host, Command: req.Command, Outcome: "rate-limited", Anomaly: "rate-exceeded"})
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return false
	}
	if len(anomalies) > 0 {
		// Verify the command would be allowed before bothering a human.
		din, err := intentFrom(req, brokerCN, false)
		if err != nil {
			http.Error(w, "invalid pubkey", http.StatusBadRequest)
			return false
		}
		din.DryRun = true
		d, err := s.remote.SignIntent(r.Context(), din)
		// A signer outage on the guardrail dry-run is an infrastructure error,
		// not a denial: audit "error" and relay 502 like the live path (#455,
		// #660).
		if errors.Is(err, signer.ErrSignerUnavailable) {
			s.auditE(audit.Entry{Caller: brokerCN, Host: req.Host, Command: req.Command, Outcome: "error", TargetType: req.TargetType, Anomaly: strings.Join(anomalies, ","), Err: err.Error()})
			http.Error(w, err.Error(), http.StatusBadGateway)
			return false
		}
		if err != nil || d.Decision == nil || !d.Decision.Allowed {
			s.auditE(audit.Entry{Caller: brokerCN, Host: req.Host, Command: req.Command, Outcome: "denied", Anomaly: strings.Join(anomalies, ","), Err: errString(err)})
			http.Error(w, "command not allowed", http.StatusForbidden)
			return false
		}
		s.requireApproval(w, brokerCN, req, "behavior", strings.Join(anomalies, ","))
		return false
	}
	return true
}

// guardrailSubject returns the subject that keys the behaviour guardrails. It
// is always derived from the authenticated broker CN: the client-supplied
// end_user only qualifies the subject ("<broker CN>:<end_user>") when the
// broker CN is in trusted_forwarders. End_user is an unauthenticated JSON
// field; keying on it directly would let a client evade rate limits and
// anomaly detection by rotating it (fresh subjects start a new baseline).
func (s *server) guardrailSubject(brokerCN, endUser string) string {
	if _, trusted := s.forwarders[brokerCN]; trusted && endUser != "" {
		return brokerCN + ":" + endUser
	}
	return brokerCN
}

// forwardSignResult responds to the broker with the result of a signer signing.
// Covers three states: cert issued, approval required, and unexpected error.
func (s *server) forwardSignResult(w http.ResponseWriter, _ *http.Request, brokerCN string, req signer.WireRequest, issued *signer.Issued) {
	if issued.Certificate != nil {
		s.auditE(audit.Entry{
			Caller: brokerCN, Host: req.Host, Command: req.Command, Serial: issued.Serial, Outcome: "forwarded",
			PolicyRule: decisionRule(issued.Decision), Warning: decisionWarning(issued.Decision),
		})
		writeJSON(w, http.StatusOK, signer.WireResponse{
			Certificate:     string(ssh.MarshalAuthorizedKey(issued.Certificate)),
			Serial:          issued.Serial,
			ElevationPrefix: issued.ElevationPrefix,
			Decision:        issued.Decision,
		})
		return
	}
	// Kubernetes: the signer returned a bound token instead of a certificate.
	if issued.K8sToken != "" {
		s.auditE(audit.Entry{
			Caller: brokerCN, Host: req.Host, Command: req.Command, Serial: issued.Serial,
			Outcome: "forwarded", TargetType: signer.TargetTypeK8s,
			PolicyRule: decisionRule(issued.Decision), Warning: decisionWarning(issued.Decision),
		})
		writeJSON(w, http.StatusOK, signer.WireResponse{
			K8sToken:       issued.K8sToken,
			K8sTokenExpiry: issued.K8sTokenExpiry,
			Serial:         issued.Serial,
			Decision:       issued.Decision,
		})
		return
	}
	if issued.Decision != nil && issued.Decision.RequireApproval {
		s.requireApproval(w, brokerCN, req, issued.Decision.MatchedRule, "")
		return
	}
	// Unexpected state: no credential, not dry-run, not approval.
	http.Error(w, "signer response missing credential", http.StatusBadGateway)
}

// requireApproval creates an approval request, notifies, and responds 202.
// rule documents the reason (command policy rule or "behavior"); anomaly lists
// behaviour anomalies when the escalation came from the guardrails.
func (s *server) requireApproval(w http.ResponseWriter, brokerCN string, req signer.WireRequest, rule, anomaly string) {
	// end_user is an unauthenticated, broker-supplied JSON field. Trust it — for
	// the approver's display, the notifier payload, and the forward to the
	// signer — only when the broker CN is a trusted forwarder, mirroring
	// guardrailSubject and the signer's own trusted_forwarders semantics.
	// Otherwise a malicious broker could label a dangerous command as coming
	// from a trusted admin (e.g. end_user=ciso@corp) to bias the human decision.
	// req is a local copy, so clearing it here does not affect the caller.
	// Remember that an assertion was dropped: such an approval can be approved
	// but not approved-and-learned (#451) — the signer would mint the waiver
	// with an empty end user, i.e. for every end user of that broker.
	var opts control.CreateOptions
	if _, trusted := s.forwarders[brokerCN]; !trusted {
		opts.EndUserStripped = req.EndUser != ""
		req.EndUser = ""
		req.EndUserContext = ""
	}
	a, err := s.registry.CreateWith(req, brokerCN, &signer.DecisionInfo{RequireApproval: true, MatchedRule: rule}, opts)
	if err != nil {
		http.Error(w, "could not create approval request", http.StatusInternalServerError)
		return
	}
	// Notify with a redacted copy: the notification persists in the process log
	// or leaves the host (webhook/Teams). The registry keeps the original — the
	// mTLS approval UI shows the approver the exact command.
	notifyCopy := *a
	if s.redactor != nil {
		notifyCopy = notifyCopy.WithRedactedCommand(s.redactor)
	}
	if nerr := s.notifier.Notify(notifyCopy); nerr != nil {
		log.Printf("warning: approval notification failed: %v", nerr)
	}
	s.auditE(audit.Entry{Caller: brokerCN, Host: req.Host, Command: req.Command, Outcome: "approval-required", ApprovalID: a.ID, PolicyRule: rule, Anomaly: anomaly})
	writeJSON(w, http.StatusAccepted, map[string]string{"approval_id": a.ID, "status": string(control.StatusPending)})
}

// handleResult serves the broker's polling for an approval request. When
// approved, it forwards to the signer with approved=true and returns the cert.
func (s *server) handleResult(w http.ResponseWriter, r *http.Request) {
	// codingstyle:long-function: one HTTP handler for the approval-result
	// callback (authorize poller → consume decision → respond); the ordering is
	// clearer inline than split across helpers.
	pollerCN, ok := s.signCaller(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	a, ok := s.registry.Get(id)
	if !ok {
		http.Error(w, "unknown request", http.StatusNotFound)
		return
	}
	// Only the broker that originated the request may collect its result.
	if a.Caller != pollerCN {
		http.Error(w, "not authorised", http.StatusForbidden)
		return
	}

	switch a.Status {
	case control.StatusPending:
		writeJSON(w, http.StatusAccepted, map[string]string{"status": string(a.Status)})
	case control.StatusDenied:
		s.auditE(audit.Entry{Caller: a.Caller, Host: a.Host, Command: a.Command, Outcome: "approval-denied", ApprovalID: a.ID, ApprovedBy: a.DecidedBy})
		http.Error(w, "approval denied", http.StatusForbidden)
	case control.StatusExpired:
		s.auditE(audit.Entry{Caller: a.Caller, Host: a.Host, Command: a.Command, Outcome: "approval-timeout", ApprovalID: a.ID})
		http.Error(w, "approval expired", http.StatusRequestTimeout)
	case control.StatusApproved:
		// Claim the approval while forwarding it to the signer. The claim prevents
		// concurrent double-issuance; it is only burned after the signer returns a
		// usable cert/decision, so transient signer failures can be retried.
		started, retry := s.registry.BeginConsume(id)
		if !started {
			if retry {
				writeJSON(w, http.StatusAccepted, map[string]string{"status": "issuing"})
				return
			}
			http.Error(w, "approval already used", http.StatusGone)
			return
		}
		consumeOK := false
		defer func() { s.registry.FinishConsume(id, consumeOK) }()

		req, _ := s.registry.Request(id)
		in, err := intentFrom(req, a.Caller, true)
		if err != nil {
			http.Error(w, "invalid pubkey", http.StatusBadRequest)
			return
		}
		// Approve-and-learn: carry the learn intent into the approved forward so the
		// signer mints a TTL'd waiver scoped to this caller/end-user/elevation.
		// Honoured by the signer only because the control plane is a trusted forwarder.
		if a.LearnTTL > 0 {
			in.LearnTTLSeconds = int(a.LearnTTL / time.Second)
			in.LearnApprover = a.DecidedBy
			in.LearnApprovalID = a.ID
		}
		issued, err := s.remote.SignIntent(r.Context(), in)
		if err != nil {
			// Same split as handleSign (#455): a signer 5xx or outage is an
			// infrastructure error — audit "error", answer 502, and leave the
			// approval claimable so the next poll retries. Anything else is the
			// signer refusing the approved command (policy changed, subject frozen
			// after the human said yes): audit "denied" with the approval
			// attribution and relay 403 with the signer's reason (#576).
			if errors.Is(err, signer.ErrSignerUnavailable) {
				s.auditE(audit.Entry{Caller: a.Caller, Host: a.Host, Command: a.Command, Outcome: "error", ApprovalID: a.ID, Err: errString(err)})
				http.Error(w, "signing after approval failed", http.StatusBadGateway)
				return
			}
			s.auditE(audit.Entry{Caller: a.Caller, Host: a.Host, Command: a.Command, Outcome: "denied", ApprovalID: a.ID, ApprovedBy: a.DecidedBy, Err: errString(err)})
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		if req.DryRun {
			if issued.Decision == nil {
				s.auditE(audit.Entry{Caller: a.Caller, Host: a.Host, Command: a.Command, Outcome: "error", ApprovalID: a.ID, Err: "signer response missing decision"})
				http.Error(w, "signing after approval failed", http.StatusBadGateway)
				return
			}
			consumeOK = true
			s.learnBehaviorApproval(a, req)
			if !s.auditGate(w, audit.Entry{Caller: a.Caller, Host: a.Host, Command: a.Command, Outcome: "approval-granted", ApprovalID: a.ID, ApprovedBy: a.DecidedBy}) {
				consumeOK = false // don't burn the approval when we withhold the result (#205)
				return
			}
			// An approved session-exec preflight on a sealed host yields the
			// envelope the broker must present to the shim (#573).
			writeJSON(w, http.StatusOK, signer.WireResponse{Decision: issued.Decision, Envelope: issued.Envelope})
			return
		}
		// Kubernetes approved action: the signer returns a bound token.
		if req.TargetType == signer.TargetTypeK8s {
			if issued.K8sToken == "" {
				s.auditE(audit.Entry{Caller: a.Caller, Host: a.Host, Command: a.Command, Outcome: "error", ApprovalID: a.ID, TargetType: signer.TargetTypeK8s, Err: "signer response missing token"})
				http.Error(w, "signing after approval failed", http.StatusBadGateway)
				return
			}
			consumeOK = true
			s.learnBehaviorApproval(a, req)
			if !s.auditGate(w, audit.Entry{Caller: a.Caller, Host: a.Host, Command: a.Command, Serial: issued.Serial, Outcome: "approval-granted", ApprovalID: a.ID, ApprovedBy: a.DecidedBy, TargetType: signer.TargetTypeK8s}) {
				consumeOK = false // don't burn the approval when we withhold the token (#205)
				return
			}
			writeJSON(w, http.StatusOK, signer.WireResponse{
				K8sToken: issued.K8sToken, K8sTokenExpiry: issued.K8sTokenExpiry,
				Serial: issued.Serial, Decision: issued.Decision,
			})
			return
		}
		if issued.Certificate == nil {
			s.auditE(audit.Entry{Caller: a.Caller, Host: a.Host, Command: a.Command, Outcome: "error", ApprovalID: a.ID, Err: "signer response missing certificate"})
			http.Error(w, "signing after approval failed", http.StatusBadGateway)
			return
		}
		consumeOK = true
		s.learnBehaviorApproval(a, req)
		if !s.auditGate(w, audit.Entry{Caller: a.Caller, Host: a.Host, Command: a.Command, Serial: issued.Serial, Outcome: "approval-granted", ApprovalID: a.ID, ApprovedBy: a.DecidedBy}) {
			consumeOK = false // don't burn the approval when we withhold the certificate (#205)
			return
		}
		writeJSON(w, http.StatusOK, signer.WireResponse{
			Certificate:     string(ssh.MarshalAuthorizedKey(issued.Certificate)),
			Serial:          issued.Serial,
			ElevationPrefix: issued.ElevationPrefix,
			Decision:        issued.Decision,
		})
	}
}

func (s *server) learnBehaviorApproval(a control.Approval, req signer.WireRequest) {
	if a.Rule != "behavior" || !s.behavior.Enabled() {
		return
	}
	s.behavior.Learn(s.guardrailSubject(a.Caller, req.EndUser), req.Host, req.Command)
}

// handleHosts forwards GET /v1/hosts to the signer on behalf of the broker
// (the X-On-Behalf-Of header ensures group filtering matches the original
// broker).
func (s *server) handleHosts(w http.ResponseWriter, r *http.Request) {
	brokerCN, ok := s.signCaller(w, r)
	if !ok {
		return
	}
	hosts, err := s.remote.FetchHosts(r.Context(), brokerCN)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	out := make(map[string]signer.WireHostInfo, len(hosts))
	for name, h := range hosts {
		out[name] = signer.WireHostInfo{
			Addr: h.Addr, User: h.User, HostKey: h.HostKey, Jump: h.Jump,
			// Every capability flag must be forwarded: the broker reports them in
			// ssh_list_servers and the tool descriptions tell the model to trust
			// them ("allow_file_transfer=false -> DO NOT attempt file transfers").
			// A flag dropped here reads as "not allowed" to the model, so an
			// operator-enabled capability becomes unusable behind the control plane
			// while it works with a direct signer.
			AllowSudo: h.AllowSudo, AllowPTY: h.AllowPTY, AllowFileTransfer: h.AllowFileTransfer,
			// Groups must be forwarded so the broker can apply per-user group
			// filtering in ssh_list_servers (otherwise an OIDC user with groups
			// sees zero hosts behind the control plane).
			Groups: h.Groups,
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// handleClusters forwards GET /v1/clusters to the signer on behalf of the
// broker, so the broker sees the same group-filtered cluster list it would
// see directly. Mirrors handleHosts.
func (s *server) handleClusters(w http.ResponseWriter, r *http.Request) {
	brokerCN, ok := s.signCaller(w, r)
	if !ok {
		return
	}
	clusters, err := s.remote.FetchClusters(r.Context(), brokerCN)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	out := make(map[string]signer.WireClusterInfo, len(clusters))
	for name, c := range clusters {
		out[name] = signer.WireClusterInfo{
			APIServer: c.APIServer, CACertPEM: c.CACertPEM,
			Groups: c.Groups, ExtraResources: c.ExtraResources,
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// handleApprovalsList lists pending requests (authorised approvers only).
func (s *server) handleApprovalsList(w http.ResponseWriter, r *http.Request) {
	if !s.isApprover(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, s.registry.List())
}

// handleApprovalDecide resolves a request as approved or denied.
func (s *server) handleApprovalDecide(w http.ResponseWriter, r *http.Request) {
	cn, ok := s.approver(r)
	if !ok {
		http.Error(w, "not authorised to approve", http.StatusForbidden)
		return
	}
	// CSRF hardening for the browser UI: mTLS client certs are ambient
	// credentials the browser attaches to any request to this origin, and an
	// HTML form with enctype=text/plain can smuggle a JSON-shaped body
	// cross-site. Requiring the application/json media type stops forms, and a
	// cross-origin fetch carrying it is stopped by the CORS preflight (this
	// server sends no CORS headers). broker-ctl already sends it.
	if ct := r.Header.Get("Content-Type"); ct != "application/json" && !strings.HasPrefix(ct, "application/json;") {
		http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
		return
	}
	id := r.PathValue("id")
	r.Body = http.MaxBytesReader(w, r.Body, 4*1024)
	var body struct {
		Approve bool `json:"approve"`
		// Approve-and-learn: when approving, learn=true asks the signer to mint a
		// TTL'd approval waiver for this command and approved subject/elevation so
		// it runs without re-approval until ttl_seconds elapses.
		Learn      bool `json:"learn,omitempty"`
		TTLSeconds int  `json:"ttl_seconds,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	var learnTTL time.Duration
	if body.Approve && body.Learn {
		if body.TTLSeconds <= 0 {
			http.Error(w, "learn requires ttl_seconds > 0", http.StatusBadRequest)
			return
		}
		learnTTL = time.Duration(body.TTLSeconds) * time.Second
	}
	// Self-approval guard: the originator of a request must not decide it,
	// even when its CN is in the approvers list (four-eyes principle).
	if pending, ok := s.registry.Get(id); ok && pending.Caller == cn {
		s.auditE(audit.Entry{Caller: pending.Caller, Host: pending.Host, Command: pending.Command, Outcome: "self-approval-rejected", ApprovalID: pending.ID, ApprovedBy: cn})
		http.Error(w, "self-approval not allowed: request originator cannot decide it", http.StatusForbidden)
		return
	}
	a, err := s.registry.Decide(id, body.Approve, cn, learnTTL)
	if err != nil {
		if errors.Is(err, control.ErrLearnUnattributable) {
			// The approval is still pending: a plain approve works (#451).
			s.auditE(audit.Entry{Caller: a.Caller, Host: a.Host, Command: a.Command, Outcome: "approval-learn-refused", ApprovalID: a.ID, ApprovedBy: cn, Err: "end_user stripped (broker not a trusted forwarder)"})
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	outcome := "approval-denied"
	if body.Approve {
		outcome = "approval-decision-allow"
		if learnTTL > 0 {
			outcome = "approval-decision-allow-learn"
		}
	}
	// An allow decision is approval-critical: its "who approved" attribution must
	// be durable before the pending sign request is released (#205). A deny grants
	// nothing, so it stays best-effort.
	if body.Approve {
		if !s.auditGate(w, audit.Entry{Caller: a.Caller, Host: a.Host, Command: a.Command, Outcome: outcome, ApprovalID: a.ID, ApprovedBy: cn}) {
			return
		}
	} else {
		s.auditE(audit.Entry{Caller: a.Caller, Host: a.Host, Command: a.Command, Outcome: outcome, ApprovalID: a.ID, ApprovedBy: cn})
	}
	writeJSON(w, http.StatusOK, a)
}

// approver returns the CN if it is authorised to approve; ok=false otherwise.
func (s *server) approver(r *http.Request) (string, bool) {
	cn, err := auth.CallerCN(r)
	if err != nil {
		return "", false
	}
	if _, ok := s.approveCN[cn]; !ok {
		return "", false
	}
	return cn, true
}

func (s *server) isApprover(w http.ResponseWriter, r *http.Request) bool {
	if _, ok := s.approver(r); !ok {
		http.Error(w, "not authorised", http.StatusForbidden)
		return false
	}
	return true
}

// eventsTotal counts every control-plane audit event by outcome (forwarded,
// denied, anomaly, rate-limited, approval-*, error). Fed by auditE, the single
// audit funnel.
var eventsTotal = monitor.GetCounterVec("controlplane_events_total",
	"Control-plane audit events by outcome.", "outcome")

func (s *server) auditE(e audit.Entry) {
	eventsTotal.With(e.Outcome).Inc()
	if err := s.audit.Append(e); err != nil {
		log.Printf("warning: error writing control plane audit log: %v", err)
	}
}

// auditGate appends an approval-critical record — the allow decision, and the
// grant that hands out a certificate/token — and, in fail-closed mode
// (audit_fail_mode=closed, the default), REJECTS the request when the append
// fails instead of granting it: the "who approved" attribution must be durable
// before a credential leaves the control plane (#205). It writes 503 and returns
// false on a fail-closed append error; in fail-open mode it degrades to
// log-and-continue and returns true. Mirrors the signer's fail-closed audit gate.
func (s *server) auditGate(w http.ResponseWriter, e audit.Entry) bool {
	eventsTotal.With(e.Outcome).Inc()
	if err := s.audit.Append(e); err != nil {
		if s.auditFailClosed {
			audit.RecordBlocked()
			log.Printf("warning: approval audit append failed (fail-closed), rejecting: %v", err)
			http.Error(w, "audit log unavailable", http.StatusServiceUnavailable)
			return false
		}
		log.Printf("warning: error writing control plane audit log: %v", err)
	}
	return true
}

// intentFrom converts an incoming WireRequest into an Intent for the signer,
// setting on_behalf_of (broker CN) and, optionally, approved.
func intentFrom(req signer.WireRequest, onBehalfOf string, approved bool) (signer.Intent, error) {
	in := signer.Intent{
		Host:           req.Host,
		Role:           req.Role,
		Purpose:        req.Purpose,
		SessionMode:    req.SessionMode,
		Command:        req.Command,
		RequestedTTL:   time.Duration(req.TTLSeconds) * time.Second,
		Sudo:           req.Sudo,
		SudoUser:       req.SudoUser,
		PTY:            req.PTY,
		FileTransfer:   req.FileTransfer,
		DryRun:         req.DryRun,
		Preflight:      req.Preflight,
		OnBehalfOf:     onBehalfOf,
		Approved:       approved,
		EndUser:        req.EndUser,
		EndUserGroups:  req.EndUserGroups,
		EndUserContext: req.EndUserContext,
		// Forward the end-user bearer so the signer can re-validate the identity
		// itself for gated callers (#143). Held in memory only across an approval
		// wait; see internal/control insertDB (stripped before persistence).
		RawToken: req.BearerToken,
	}
	// Kubernetes: no ephemeral public key; carry the structured action so
	// Remote.SignIntent re-serialises the k8s fields to the signer. The signer
	// re-validates the action and its canonical form.
	if req.TargetType == signer.TargetTypeK8s {
		in.TargetType = signer.TargetTypeK8s
		in.K8s = &signer.K8sAction{
			Verb:      req.K8sVerb,
			Resource:  req.K8sResource,
			Group:     req.K8sGroup,
			Namespace: req.K8sNamespace,
			Name:      req.K8sName,
		}
		return in, nil
	}
	pub, err := signer.ParsePublicKey(req.PublicKey)
	if err != nil {
		return signer.Intent{}, err
	}
	in.PublicKey = pub
	return in, nil
}

func cnSet(cns []string) map[string]struct{} {
	m := make(map[string]struct{}, len(cns))
	for _, cn := range cns {
		if cn != "" {
			m[cn] = struct{}{}
		}
	}
	return m
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("writeJSON: %v", err)
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func decisionRule(dec *signer.DecisionInfo) string {
	if dec == nil {
		return ""
	}
	return dec.MatchedRule
}

func decisionWarning(dec *signer.DecisionInfo) string {
	if dec == nil {
		return ""
	}
	return dec.Warning
}

func loadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := confcheck.Strict(b, &c); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if c.Listen == "" {
		c.Listen = ":7443"
	}
	if err := validateConfig(&c); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return &c, nil
}

func validateConfig(c *Config) error {
	switch c.Approval.Notifier {
	case "", "log", "webhook", "teams":
	default:
		return fmt.Errorf("approval.notifier: unknown value %q (must be log, webhook, or teams)", c.Approval.Notifier)
	}
	switch c.Approval.TeamsFormat {
	case "", control.TeamsFormatWorkflow, control.TeamsFormatAdaptiveCard, control.TeamsFormatMessageCard:
	default:
		return fmt.Errorf("approval.teams_format: unknown value %q (must be workflow, adaptivecard, or messagecard)", c.Approval.TeamsFormat)
	}
	switch c.Behavior.Mode {
	case "", control.BehaviorOff, control.BehaviorObserve, control.BehaviorEnforce:
	default:
		return fmt.Errorf("behavior.mode: unknown value %q (must be off, observe, or enforce)", c.Behavior.Mode)
	}
	// A webhook/Teams notifier POSTs full approval details (host, command, sudo
	// target, caller, end_user) to webhook_url. Require https so those details
	// are not sent in cleartext; allow http only to a loopback host (a local
	// relay). Emptiness is reported by the notifier setup with a clearer message.
	if (c.Approval.Notifier == "webhook" || c.Approval.Notifier == "teams") && c.Approval.WebhookURL != "" {
		u, err := url.Parse(c.Approval.WebhookURL)
		if err != nil {
			return fmt.Errorf("approval.webhook_url: %w", err)
		}
		switch u.Scheme {
		case "https":
		case "http":
			if !isLoopbackHost(u.Hostname()) {
				return fmt.Errorf("approval.webhook_url: http:// sends approval details in cleartext; use https (http allowed only for a loopback host)")
			}
		default:
			return fmt.Errorf("approval.webhook_url: scheme %q not allowed; use https", u.Scheme)
		}
	}
	return nil
}

// isLoopbackHost reports whether host (a URL hostname, no port) is the local
// loopback, for which plaintext http to a local relay is acceptable.
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
