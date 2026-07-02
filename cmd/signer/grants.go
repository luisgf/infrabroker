package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/luisgf/ssh-broker/internal/audit"
	"github.com/luisgf/ssh-broker/internal/auth"
	"github.com/luisgf/ssh-broker/internal/signer"
)

// grantReq is the body of POST /v1/policy/hosts/{host}/grants.
type grantReq struct {
	Allow      []string `json:"allow"`
	TTLSeconds int      `json:"ttl_seconds"`
	Caller     string   `json:"caller,omitempty"`   // optional scope: only this broker CN
	EndUser    string   `json:"end_user,omitempty"` // optional scope: only this OIDC user
}

// policyAdmin authenticates the caller and reports whether it may change policy
// (mTLS CN present in reload_callers). authd=false → unauthenticated (401);
// authz=false → authenticated but not authorised (403).
func (s *server) policyAdmin(r *http.Request) (caller string, authd, authz bool) {
	caller, err := auth.CallerCN(r)
	if err != nil {
		return "", false, false
	}
	s.mu.RLock()
	_, ok := s.reloadCN[caller]
	s.mu.RUnlock()
	return caller, true, ok
}

// handleGrantCreate adds a runtime, widen-only command-policy grant: a time-boxed
// set of allow patterns that expire on their own. Auth is mTLS + reload_callers
// (same "may change policy" tier as the mutation API). The grant is refused
// unless the host is allowlist-active — on a default-allow/denylist host it would
// be a no-op and, if applied, would invert the host to default-deny. Regexes are
// validated by GrantStore.Add. Grants live in memory only (never persisted) and
// every attempt is recorded in the signed audit log.
func (s *server) handleGrantCreate(w http.ResponseWriter, r *http.Request) {
	caller, authd, authz := s.policyAdmin(r)
	if !authd {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	host := r.PathValue("host")
	if !authz {
		s.auditGrant(caller, host, "", nil, "grant-denied", errors.New("caller not authorised"))
		http.Error(w, "not authorised to change policy", http.StatusForbidden)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	var req grantReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Allow) == 0 || req.TTLSeconds <= 0 {
		http.Error(w, `invalid request: need {"allow":["..."],"ttl_seconds":N}`, http.StatusBadRequest)
		return
	}
	ttl := time.Duration(req.TTLSeconds) * time.Second
	if s.maxGrantTTL > 0 && ttl > s.maxGrantTTL {
		err := errors.New("ttl_seconds exceeds max_grant_ttl_seconds")
		s.auditGrant(caller, host, "", req.Allow, "grant-failed", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// The host must be allowlist-active in its composed policy (else a widen-only
	// grant is meaningless and would invert the host).
	local, _, _, _ := s.snapshot()
	exists, allowlist := local.HostAllowlistActive(host)
	if !exists {
		s.auditGrant(caller, host, "", req.Allow, "grant-failed", errHostNotFound)
		http.Error(w, "unknown host", http.StatusNotFound)
		return
	}
	if !allowlist {
		err := errors.New("host is not allowlist-active: a widen-only grant is a no-op here (it would invert the host to default-deny)")
		s.auditGrant(caller, host, "", req.Allow, "grant-failed", err)
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	now := time.Now()
	id, err := s.grants.Add(signer.Grant{
		Host: host, Allow: req.Allow, Caller: req.Caller, EndUser: req.EndUser,
		Approver: caller, GrantedAt: now, ExpiresAt: now.Add(ttl),
	})
	if err != nil { // invalid regex
		s.auditGrant(caller, host, "", req.Allow, "grant-failed", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.auditGrant(caller, host, id, req.Allow, "grant-created", nil)
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": id, "host": host, "expires_at": now.Add(ttl).UTC().Format(time.RFC3339),
	})
}

// handleGrantList returns the active (non-expired) grants. Operator-only: the
// list reveals the host's current widening posture.
func (s *server) handleGrantList(w http.ResponseWriter, r *http.Request) {
	_, authd, authz := s.policyAdmin(r)
	if !authd {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	if !authz {
		http.Error(w, "not authorised to change policy", http.StatusForbidden)
		return
	}
	writeJSON(w, http.StatusOK, s.grants.List(time.Now()))
}

// handleGrantRevoke removes a grant by id (the command is denied again at once).
func (s *server) handleGrantRevoke(w http.ResponseWriter, r *http.Request) {
	caller, authd, authz := s.policyAdmin(r)
	if !authd {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	id := r.PathValue("id")
	// The id segment is percent-decoded by ServeMux, so a "%20" yields a literal
	// space; auditGrant writes "grant "+id into Command (the space-separated
	// key=value token stream). A real grant id is system-generated hex and never
	// contains whitespace, so reject it before any auditGrant — otherwise any
	// authenticated mTLS client could splice forged tokens into the signed log via
	// the pre-authz grant-denied audit path.
	if signer.HasUnsafeTokenChar(id) {
		http.Error(w, "invalid grant id", http.StatusBadRequest)
		return
	}
	if !authz {
		s.auditGrant(caller, "", id, nil, "grant-denied", errors.New("caller not authorised"))
		http.Error(w, "not authorised to change policy", http.StatusForbidden)
		return
	}
	ok, err := s.grants.Revoke(id)
	if err != nil {
		// The state-db delete failed: the grant is deliberately kept live so it
		// cannot resurrect on restart after the operator saw a success.
		s.auditGrant(caller, "", id, nil, "grant-failed", err)
		http.Error(w, "could not persist revocation, grant still active", http.StatusInternalServerError)
		return
	}
	if !ok {
		s.auditGrant(caller, "", id, nil, "grant-failed", errors.New("unknown grant"))
		http.Error(w, "unknown grant", http.StatusNotFound)
		return
	}
	s.auditGrant(caller, "", id, nil, "grant-revoked", nil)
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "id": id})
}

// maybeLearnWaiver mints a TTL'd approval waiver after an approved sign that asked
// for it (approve-and-learn). It runs only for a request from a trusted forwarder
// (the caller gate is enforced by handleSign) that actually issued a certificate
// for a require_approval command. It is best-effort: the certificate is already
// issued, so a too-long TTL is clamped to max_grant_ttl_seconds and any Add error
// is audited but never fails the sign. The waiver is scoped to the effective
// broker caller and end-user that were approved, and matches the exact command.
func (s *server) maybeLearnWaiver(caller string, req signer.WireRequest, issued *signer.Issued) {
	// A credential was issued when either an SSH certificate or a k8s bound
	// token came back; approve-and-learn applies to both targets.
	if req.LearnTTLSeconds <= 0 || req.DryRun || issued == nil || (issued.Certificate == nil && issued.K8sToken == "") {
		return
	}
	if issued.Decision == nil || !issued.Decision.RequireApproval {
		// Learn was requested but the command is not approval-gated: nothing to
		// waive. Audit the no-op so the mismatch is visible to operators.
		s.appendAudit(audit.Entry{
			Caller: caller, Host: req.Host, Command: "approval-waiver",
			Outcome: "approval-waiver-skipped", ApprovalID: req.LearnApprovalID,
			ApprovedBy: req.LearnApprover, Err: "command is not require_approval; nothing to waive",
		})
		return
	}
	ttl := time.Duration(req.LearnTTLSeconds) * time.Second
	if s.maxGrantTTL > 0 && ttl > s.maxGrantTTL {
		ttl = s.maxGrantTTL // clamp, never reject: the cert is already issued
	}
	now := time.Now()
	pattern := "^" + regexp.QuoteMeta(req.Command) + "$"
	g := signer.Grant{
		Host: req.Host, Caller: caller, EndUser: req.EndUser,
		WaiveApproval: []string{pattern},
		Sudo:          req.Sudo, SudoUser: req.SudoUser, // bind the waiver to the approved elevation
		Approver: req.LearnApprover, ApprovalID: req.LearnApprovalID,
		GrantedAt: now, ExpiresAt: now.Add(ttl),
	}
	s.grants.SupersedeWaiver(g) // refresh in place; don't accumulate duplicates
	id, err := s.grants.Add(g)
	e := audit.Entry{
		Caller: caller, Host: req.Host, Command: "approval-waiver " + id,
		Outcome: "approval-waiver-created", PolicyRule: "waive_approval:" + pattern,
		ApprovalID: req.LearnApprovalID, ApprovedBy: req.LearnApprover,
	}
	if err != nil {
		e.Command, e.Outcome, e.Err = "approval-waiver", "approval-waiver-failed", err.Error()
	}
	s.appendAudit(e)
}

// appendAudit writes an audit entry, logging a warning on failure.
func (s *server) appendAudit(e audit.Entry) {
	if aerr := s.audit.Append(e); aerr != nil {
		log.Printf("warning: error writing signer audit log: %v", aerr)
	}
}

// auditGrant records a grant operation in the signed audit log.
func (s *server) auditGrant(caller, host, id string, allow []string, outcome string, err error) {
	e := audit.Entry{Caller: caller, Host: host, Command: "grant " + id, Outcome: outcome}
	if len(allow) > 0 {
		e.PolicyRule = "allow:" + strings.Join(allow, ",")
	}
	if err != nil {
		e.Err = err.Error()
	}
	if aerr := s.audit.Append(e); aerr != nil {
		log.Printf("warning: error writing signer audit log: %v", aerr)
	}
}
