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
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/luisgf/ssh-broker/internal/audit"
	"github.com/luisgf/ssh-broker/internal/auth"
	"github.com/luisgf/ssh-broker/internal/confcheck"
	"github.com/luisgf/ssh-broker/internal/control"
	"github.com/luisgf/ssh-broker/internal/httpserve"
	"github.com/luisgf/ssh-broker/internal/signer"
	"github.com/luisgf/ssh-broker/internal/version"
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
		Notifier       string   `json:"notifier"`        // "webhook" | "teams" | "log" (default)
		WebhookURL     string   `json:"webhook_url"`     // required when notifier=webhook or teams
		TimeoutSeconds int      `json:"timeout_seconds"` // TTL for pending requests
		Callers        []string `json:"callers"`         // CNs authorised to approve/deny

		// Teams-specific fields (notifier=teams).
		TeamsFormat         string `json:"teams_format"`          // "workflow" (default) | "messagecard"
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
}

type server struct {
	remote     *signer.Remote
	registry   *control.Registry
	notifier   control.Notifier
	behavior   *control.BehaviorTracker
	audit      *audit.Log
	approveCN  map[string]struct{}
	signCN     map[string]struct{} // CNs allowed on the signing path (brokers); empty = any non-approver
	forwarders map[string]struct{} // CNs whose end_user claim is trusted (guardrail subject)
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
	cfgPath := flag.String("config", "control-plane.json", "path to JSON configuration file")
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

	var notifier control.Notifier = control.LogNotifier{}
	switch cfg.Approval.Notifier {
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
	}

	srv := &server{
		remote:     remote,
		registry:   control.NewRegistry(time.Duration(cfg.Approval.TimeoutSeconds) * time.Second),
		notifier:   notifier,
		behavior:   control.NewBehaviorTracker(cfg.Behavior),
		audit:      auditLog,
		approveCN:  cnSet(cfg.Approval.Callers),
		signCN:     cnSet(cfg.SignCallers),
		forwarders: cnSet(cfg.TrustedForwarders),
	}

	tlsCfg, err := auth.ServerTLSConfig(cfg.ServerCert, cfg.ServerKey, cfg.ClientCA)
	if err != nil {
		log.Fatalf("tls: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/sign", srv.handleSign)
	mux.HandleFunc("GET /v1/hosts", srv.handleHosts)
	mux.HandleFunc("GET /v1/sign/result/{id}", srv.handleResult)
	mux.HandleFunc("GET /v1/approvals", srv.handleApprovalsList)
	mux.HandleFunc("POST /v1/approvals/{id}", srv.handleApprovalDecide)

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
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		writeJSON(w, http.StatusOK, signer.WireResponse{Decision: issued.Decision})
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
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		writeJSON(w, http.StatusOK, signer.WireResponse{Decision: issued.Decision})
		return
	}

	in, err := intentFrom(req, brokerCN, false)
	if err != nil {
		http.Error(w, "invalid pubkey", http.StatusBadRequest)
		return
	}
	issued, err := s.remote.SignIntent(r.Context(), in)
	if err != nil {
		s.auditE(audit.Entry{Caller: brokerCN, Host: req.Host, Command: req.Command, Outcome: "denied", Err: err.Error()})
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	s.forwardSignResult(w, r, brokerCN, req, issued)
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
	if issued.Decision != nil && issued.Decision.RequireApproval {
		s.requireApproval(w, brokerCN, req, issued.Decision.MatchedRule, "")
		return
	}
	// Unexpected state: no cert, not dry-run, not approval.
	http.Error(w, "signer response missing certificate", http.StatusBadGateway)
}

// requireApproval creates an approval request, notifies, and responds 202.
// rule documents the reason (command policy rule or "behavior"); anomaly lists
// behaviour anomalies when the escalation came from the guardrails.
func (s *server) requireApproval(w http.ResponseWriter, brokerCN string, req signer.WireRequest, rule, anomaly string) {
	a, err := s.registry.Create(req, brokerCN, &signer.DecisionInfo{RequireApproval: true, MatchedRule: rule})
	if err != nil {
		http.Error(w, "could not create approval request", http.StatusInternalServerError)
		return
	}
	if nerr := s.notifier.Notify(*a); nerr != nil {
		log.Printf("warning: approval notification failed: %v", nerr)
	}
	s.auditE(audit.Entry{Caller: brokerCN, Host: req.Host, Command: req.Command, Outcome: "approval-required", ApprovalID: a.ID, PolicyRule: rule, Anomaly: anomaly})
	writeJSON(w, http.StatusAccepted, map[string]string{"approval_id": a.ID, "status": string(control.StatusPending)})
}

// handleResult serves the broker's polling for an approval request. When
// approved, it forwards to the signer with approved=true and returns the cert.
func (s *server) handleResult(w http.ResponseWriter, r *http.Request) {
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
		// signer mints a TTL'd approval waiver. Honoured by the signer only because
		// the control plane is a trusted forwarder.
		if a.LearnTTL > 0 {
			in.LearnTTLSeconds = int(a.LearnTTL / time.Second)
			in.LearnApprover = a.DecidedBy
			in.LearnApprovalID = a.ID
		}
		issued, err := s.remote.SignIntent(r.Context(), in)
		if err != nil {
			s.auditE(audit.Entry{Caller: a.Caller, Host: a.Host, Command: a.Command, Outcome: "error", ApprovalID: a.ID, Err: errString(err)})
			http.Error(w, "signing after approval failed", http.StatusBadGateway)
			return
		}
		if req.DryRun {
			if issued.Decision == nil {
				s.auditE(audit.Entry{Caller: a.Caller, Host: a.Host, Command: a.Command, Outcome: "error", ApprovalID: a.ID, Err: "signer response missing decision"})
				http.Error(w, "signing after approval failed", http.StatusBadGateway)
				return
			}
			consumeOK = true
			s.auditE(audit.Entry{Caller: a.Caller, Host: a.Host, Command: a.Command, Outcome: "approval-granted", ApprovalID: a.ID, ApprovedBy: a.DecidedBy})
			writeJSON(w, http.StatusOK, signer.WireResponse{Decision: issued.Decision})
			return
		}
		if issued.Certificate == nil {
			s.auditE(audit.Entry{Caller: a.Caller, Host: a.Host, Command: a.Command, Outcome: "error", ApprovalID: a.ID, Err: "signer response missing certificate"})
			http.Error(w, "signing after approval failed", http.StatusBadGateway)
			return
		}
		consumeOK = true
		s.auditE(audit.Entry{Caller: a.Caller, Host: a.Host, Command: a.Command, Serial: issued.Serial, Outcome: "approval-granted", ApprovalID: a.ID, ApprovedBy: a.DecidedBy})
		writeJSON(w, http.StatusOK, signer.WireResponse{
			Certificate:     string(ssh.MarshalAuthorizedKey(issued.Certificate)),
			Serial:          issued.Serial,
			ElevationPrefix: issued.ElevationPrefix,
			Decision:        issued.Decision,
		})
	}
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
			AllowSudo: h.AllowSudo, AllowPTY: h.AllowPTY,
			// Groups must be forwarded so the broker can apply per-user group
			// filtering in ssh_list_servers (otherwise an OIDC user with groups
			// sees zero hosts behind the control plane).
			Groups: h.Groups,
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
	id := r.PathValue("id")
	r.Body = http.MaxBytesReader(w, r.Body, 4*1024)
	var body struct {
		Approve bool `json:"approve"`
		// Approve-and-learn: when approving, learn=true asks the signer to mint a
		// TTL'd approval waiver for this command so it runs without re-approval until
		// ttl_seconds elapses.
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
	s.auditE(audit.Entry{Caller: a.Caller, Host: a.Host, Command: a.Command, Outcome: outcome, ApprovalID: a.ID, ApprovedBy: cn})
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

func (s *server) auditE(e audit.Entry) {
	if err := s.audit.Append(e); err != nil {
		log.Printf("warning: error writing control plane audit log: %v", err)
	}
}

// intentFrom converts an incoming WireRequest into an Intent for the signer,
// setting on_behalf_of (broker CN) and, optionally, approved.
func intentFrom(req signer.WireRequest, onBehalfOf string, approved bool) (signer.Intent, error) {
	pub, err := signer.ParsePublicKey(req.PublicKey)
	if err != nil {
		return signer.Intent{}, err
	}
	return signer.Intent{
		Host:          req.Host,
		Role:          req.Role,
		Purpose:       req.Purpose,
		SessionMode:   req.SessionMode,
		Command:       req.Command,
		RequestedTTL:  time.Duration(req.TTLSeconds) * time.Second,
		PublicKey:     pub,
		Sudo:          req.Sudo,
		SudoUser:      req.SudoUser,
		PTY:           req.PTY,
		DryRun:        req.DryRun,
		Preflight:     req.Preflight,
		OnBehalfOf:    onBehalfOf,
		Approved:      approved,
		EndUser:       req.EndUser,
		EndUserGroups: req.EndUserGroups,
	}, nil
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
	return &c, nil
}
