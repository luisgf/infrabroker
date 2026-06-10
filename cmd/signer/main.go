// Command signer is the external signing service: it holds the CA key and the
// policy, and issues ephemeral SSH certificates to mTLS-authenticated brokers.
// The broker never holds the CA key; it sends an intent and receives the signed
// certificate.
//
// The service core is a signer.Local exposed over HTTP+mTLS, with its own
// issuance log (audit independent of the broker).
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/luisgf/ssh-broker/internal/audit"
	"github.com/luisgf/ssh-broker/internal/auth"
	"github.com/luisgf/ssh-broker/internal/ca"
	"github.com/luisgf/ssh-broker/internal/httpserve"
	"github.com/luisgf/ssh-broker/internal/signer"
)

// Config is the signing service configuration.
type Config struct {
	Listen string `json:"listen"` // e.g. ":9443"

	// mTLS: presents server_cert and requires clients signed by client_ca.
	ServerCert string `json:"server_cert"`
	ServerKey  string `json:"server_key"`
	ClientCA   string `json:"client_ca"` // CA that signs authorised brokers

	// CA key custody.
	// ca_key: legacy path to a PEM CA key (backward compatible).
	// ca_keys: per-group CA key overrides.  The reserved key "_default"
	// overrides ca_key when present.  See CAKeyConfig for supported backends
	// ("pem" for local files, "akv" for Azure Key Vault).
	CAKey  string                    `json:"ca_key"`
	CAKeys map[string]ca.CAKeyConfig `json:"ca_keys,omitempty"`

	// Issuance audit log (independent of the broker).
	AuditLog string `json:"audit_log"`
	AuditKey string `json:"audit_key"`

	// MaxTTLSeconds: global cap when the host policy does not set one.
	MaxTTLSeconds int `json:"max_ttl_seconds"`

	// ReloadCallers: client cert CNs authorised to invoke POST /v1/reload.
	// Empty = HTTP endpoint disabled (403); SIGHUP still works locally.
	ReloadCallers []string `json:"reload_callers"`

	// TrustedForwarders: client cert CNs authorised to act on behalf of another
	// broker (on_behalf_of field / X-On-Behalf-Of header). This is the control
	// plane CN. Only these CNs may impersonate a broker for RBAC; any other CN
	// sending on_behalf_of is rejected.
	TrustedForwarders []string `json:"trusted_forwarders,omitempty"`

	// Hosts: issuance policy + connectivity per host. Single source of truth:
	// the broker fetches addr/user/host_key/jump via GET /v1/hosts.
	Hosts signer.PolicyTable `json:"hosts"`

	// Callers: group-based RBAC. Maps broker mTLS cert CN → allowed groups.
	// A CN absent from the table has no group restriction (backward compatible).
	// A CN present can only see and sign hosts whose groups field intersects
	// with its allowed_groups.
	Callers signer.CallerTable `json:"callers,omitempty"`
}

func main() {
	cfgPath := flag.String("config", "signer.json", "path to JSON configuration file")
	flag.Parse()

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	local, err := buildState(context.Background(), cfg)
	if err != nil {
		log.Fatalf("%v", err)
	}

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

	tlsCfg, err := auth.ServerTLSConfig(cfg.ServerCert, cfg.ServerKey, cfg.ClientCA)
	if err != nil {
		log.Fatalf("tls: %v", err)
	}

	srv := &server{
		local:      local,
		audit:      auditLog,
		hosts:      cfg.Hosts,
		callers:    cfg.Callers,
		reloadCN:   reloadSet(cfg.ReloadCallers),
		forwarders: reloadSet(cfg.TrustedForwarders),
		cfgPath:    *cfgPath,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sign", srv.handleSign)
	mux.HandleFunc("/v1/hosts", srv.handleHosts)
	mux.HandleFunc("/v1/reload", srv.handleReload)

	// Hot-reload via SIGHUP (in addition to the HTTP endpoint). Local to the
	// host, so it bypasses the reload_callers allowlist.
	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGHUP)
		for range ch {
			n, err := srv.reload()
			if err != nil {
				log.Printf("reload (SIGHUP): error: %v (keeping previous config)", err)
				srv.auditReload("SIGHUP", 0, "reload-failed", err)
				continue
			}
			log.Printf("reload (SIGHUP): %d hosts in policy", n)
			srv.auditReload("SIGHUP", n, "reloaded", nil)
		}
	}()

	// A1: timeouts to prevent connection exhaustion (slowloris and hung connections).
	httpSrv := &http.Server{
		Addr:         cfg.Listen,
		Handler:      mux,
		TLSConfig:    tlsCfg,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	log.Printf("signer (mTLS) on %s; %d hosts in policy", cfg.Listen, len(cfg.Hosts))
	// Graceful shutdown drains in-flight requests and lets the deferred
	// auditLog.Close() flush the chain on SIGINT/SIGTERM.
	httpserve.RunTLS(httpSrv, "signer", 10*time.Second)
}

// buildState constructs the hot-reloadable state (signer + host policy) from
// the config: loads CA key(s) and materialises the default TTL.
// Returns an error without touching anything on failure, so an invalid reload
// does not leave the signer in a broken state.
func buildState(ctx context.Context, cfg *Config) (*signer.Local, error) {
	// Validate the policy before touching anything so an invalid reload (bad
	// command_policy regex, unknown mode, dangling jump) is rejected up front
	// and the previous good state is preserved.
	if err := cfg.Hosts.Validate(); err != nil {
		return nil, fmt.Errorf("invalid host policy: %w", err)
	}
	defaultCA, groupCAs, err := ca.LoadGroupCAs(ctx, cfg.CAKey, cfg.CAKeys)
	if err != nil {
		return nil, fmt.Errorf("loading CA keys: %w", err)
	}
	defaultTTL := time.Duration(cfg.MaxTTLSeconds) * time.Second
	if defaultTTL <= 0 {
		defaultTTL = 5 * time.Minute
	}
	return signer.NewLocalWithGroupCAs(defaultCA, groupCAs, cfg.Hosts, defaultTTL), nil
}

// reloadSet converts the list of admin CNs into a set for O(1) lookup.
func reloadSet(cns []string) map[string]struct{} {
	m := make(map[string]struct{}, len(cns))
	for _, cn := range cns {
		if cn != "" {
			m[cn] = struct{}{}
		}
	}
	return m
}

type server struct {
	// mu protects hot-reloadable state.
	mu         sync.RWMutex
	local      *signer.Local
	hosts      signer.PolicyTable
	callers    signer.CallerTable
	reloadCN   map[string]struct{}
	forwarders map[string]struct{}

	// Immutable after startup.
	audit   *audit.Log
	cfgPath string
}

// snapshot returns the current state under RLock, so handlers do not read
// fields while a reload is replacing them.
func (s *server) snapshot() (*signer.Local, signer.PolicyTable, signer.CallerTable, map[string]struct{}) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.local, s.hosts, s.callers, s.forwarders
}

// resolveCaller determines the effective caller identity for RBAC. When
// onBehalfOf is non-empty, it is honoured only if mtlsCN is a trusted
// forwarder; otherwise ok=false (the request must be rejected with 403).
func resolveCaller(mtlsCN, onBehalfOf string, forwarders map[string]struct{}) (caller string, ok bool) {
	if onBehalfOf == "" {
		return mtlsCN, true
	}
	if _, trusted := forwarders[mtlsCN]; trusted {
		return onBehalfOf, true
	}
	return "", false
}

// reload re-reads the config file and, if valid, atomically replaces the
// signer, the host policy, and the reload allowlist. On failure it leaves the
// state unchanged and returns an error. Returns the number of loaded hosts.
func (s *server) reload() (int, error) {
	cfg, err := loadConfig(s.cfgPath)
	if err != nil {
		return 0, fmt.Errorf("config: %w", err)
	}
	local, err := buildState(context.Background(), cfg)
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	s.local = local
	s.hosts = cfg.Hosts
	s.callers = cfg.Callers
	s.reloadCN = reloadSet(cfg.ReloadCallers)
	s.forwarders = reloadSet(cfg.TrustedForwarders)
	s.mu.Unlock()
	return len(cfg.Hosts), nil
}

func (s *server) handleSign(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	caller, err := auth.CallerCN(r)
	if err != nil {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}

	// A2: limit the request body to prevent OOM from oversized payloads.
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024) // 64 KiB is more than enough
	var req signer.WireRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	pub, err := signer.ParsePublicKey(req.PublicKey)
	if err != nil {
		http.Error(w, "invalid pubkey", http.StatusBadRequest)
		return
	}

	local, hosts, callers, forwarders := s.snapshot()

	// approved is honoured only from a trusted forwarder (control plane); a
	// broker cannot self-approve.
	_, isForwarder := forwarders[caller]
	effectiveApproved := req.Approved && isForwarder

	// Resolve the effective caller identity: a trusted forwarder (control plane)
	// may act on behalf of the original broker via on_behalf_of.
	caller, ok := resolveCaller(caller, req.OnBehalfOf, forwarders)
	if !ok {
		http.Error(w, "on_behalf_of not allowed for this caller", http.StatusForbidden)
		return
	}

	// Verify group access before Resolve: if the caller has a group restriction,
	// the requested host must belong to one of its groups.
	if hostSet, restricted := signer.HostSetForCaller(caller, hosts, callers); restricted {
		if _, ok := hostSet[req.Host]; !ok {
			s.auditEmission(caller, req, hosts, 0, "denied", fmt.Errorf("host %q outside group for %q", req.Host, caller))
			http.Error(w, "host not authorised", http.StatusForbidden)
			return
		}
	}

	in := signer.Intent{
		Caller:        caller,
		Host:          req.Host,
		Role:          req.Role,
		Purpose:       req.Purpose,
		Command:       req.Command,
		RequestedTTL:  time.Duration(req.TTLSeconds) * time.Second,
		PublicKey:     pub,
		Sudo:          req.Sudo,
		SudoUser:      req.SudoUser,
		PTY:           req.PTY,
		DryRun:        req.DryRun,
		Approved:      effectiveApproved,
		EndUser:       req.EndUser,
		EndUserGroups: req.EndUserGroups,
	}
	issued, err := local.SignIntent(r.Context(), in)
	if err != nil {
		s.auditEmission(caller, req, hosts, 0, "denied", err)
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	s.respondSignResult(w, caller, req, hosts, issued)
}

// respondSignResult audits the signing result and writes the HTTP response.
// Covers three cases: dry-run, approval-required, and cert issued.
func (s *server) respondSignResult(w http.ResponseWriter, caller string, req signer.WireRequest, hosts signer.PolicyTable, issued *signer.Issued) {
	// Dry-run: no cert issued; only the decision is returned and audited.
	if req.DryRun {
		outcome := "dry_run_allowed"
		if issued.Decision != nil && !issued.Decision.Allowed {
			outcome = "dry_run_denied"
		}
		s.auditEmission(caller, req, hosts, 0, outcome, nil)
		writeJSON(w, http.StatusOK, signer.WireResponse{Decision: issued.Decision})
		return
	}

	// No certificate but allowed: the operation requires human approval and has
	// not been approved yet. Return the decision (empty cert) so the control
	// plane can orchestrate approval.
	if issued.Certificate == nil {
		s.auditEmission(caller, req, hosts, 0, "approval-required", nil)
		writeJSON(w, http.StatusOK, signer.WireResponse{Decision: issued.Decision})
		return
	}

	s.auditEmission(caller, req, hosts, issued.Serial, "issued", nil)
	writeJSON(w, http.StatusOK, signer.WireResponse{
		Certificate:     string(ssh.MarshalAuthorizedKey(issued.Certificate)),
		Serial:          issued.Serial,
		ElevationPrefix: issued.ElevationPrefix,
		Decision:        issued.Decision,
	})
}

// handleHosts serves GET /v1/hosts: returns the connectivity data for the
// hosts accessible to the caller. Callers with a group restriction receive
// only hosts whose groups field intersects with their allowed_groups.
// Does not expose policy data (principal, source_address, allowed_callers).
func (s *server) handleHosts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	caller, err := auth.CallerCN(r)
	if err != nil {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}

	_, hosts, callers, forwarders := s.snapshot()

	// A trusted forwarder can request the list on behalf of a broker
	// (X-On-Behalf-Of header) so that group filtering matches the broker.
	caller, ok := resolveCaller(caller, r.Header.Get(signer.HeaderOnBehalfOf), forwarders)
	if !ok {
		http.Error(w, "on_behalf_of not allowed for this caller", http.StatusForbidden)
		return
	}

	result := make(map[string]signer.WireHostInfo, len(hosts))
	for name, hp := range hosts {
		result[name] = signer.WireHostInfo{
			Addr:      hp.Addr,
			User:      hp.User,
			HostKey:   hp.HostKey,
			Jump:      hp.Jump,
			AllowSudo: hp.AllowSudo,
			AllowPTY:  hp.AllowPTY,
			Groups:    hp.Groups,
		}
	}

	// Filter by groups if the caller has a restriction.
	if hostSet, restricted := signer.HostSetForCaller(caller, hosts, callers); restricted {
		for name := range result {
			if _, ok := hostSet[name]; !ok {
				delete(result, name)
			}
		}
	}

	writeJSON(w, http.StatusOK, result)
}

// handleReload serves POST /v1/reload: re-reads the config file and hot-swaps
// the host policy, the global TTL, and the CA key. Only CNs in reload_callers
// may invoke it. If the new config is invalid, the previous state is preserved
// and 500 is returned.
func (s *server) handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	caller, err := auth.CallerCN(r)
	if err != nil {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}

	s.mu.RLock()
	_, allowed := s.reloadCN[caller]
	s.mu.RUnlock()
	if !allowed {
		s.auditReload(caller, 0, "reload-denied", fmt.Errorf("caller not authorised"))
		http.Error(w, "not authorised to reload", http.StatusForbidden)
		return
	}

	n, err := s.reload()
	if err != nil {
		s.auditReload(caller, 0, "reload-failed", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.auditReload(caller, n, "reloaded", nil)
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "hosts": n})
}

// auditReload records a reload operation in the audit log.
func (s *server) auditReload(caller string, hosts int, outcome string, err error) {
	e := audit.Entry{
		Caller:  caller,
		Command: fmt.Sprintf("reload hosts=%d", hosts),
		Outcome: outcome,
	}
	if err != nil {
		e.Err = err.Error()
	}
	// M1: log the error instead of silently discarding it.
	if aerr := s.audit.Append(e); aerr != nil {
		log.Printf("warning: error writing signer audit log: %v", aerr)
	}
}

func (s *server) auditEmission(caller string, req signer.WireRequest, hosts signer.PolicyTable, serial uint64, outcome string, err error) {
	cmd := "role=" + req.Role + " purpose=" + req.Purpose
	if req.EndUser != "" {
		cmd += " user=" + req.EndUser
	}
	if req.Sudo {
		u := req.SudoUser
		if u == "" {
			u = "root"
		}
		cmd += " elev=sudo:" + u
	}
	if req.PTY {
		cmd += " pty=1"
	}
	// Use the real address (FQDN) and policy metadata instead of the logical
	// name, which does not uniquely identify the target in the log.
	host := req.Host
	var user, principal string
	if hp, ok := hosts[req.Host]; ok {
		host = hp.Addr
		user = hp.User
		principal = hp.Principal
	}
	e := audit.Entry{
		Caller:    caller,
		Host:      host,
		User:      user,
		Principal: principal,
		Command:   cmd,
		Serial:    serial,
		Outcome:   outcome,
	}
	if err != nil {
		e.Err = err.Error()
	}
	// M1: log the error instead of silently discarding it.
	if aerr := s.audit.Append(e); aerr != nil {
		log.Printf("warning: error writing signer audit log: %v", aerr)
	}
}

// writeJSON serialises v as JSON with the given HTTP status code.
// Errors writing the response body are logged but cannot be remediated once
// headers are sent.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("writeJSON: %v", err)
	}
}

func loadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	if c.Listen == "" {
		c.Listen = ":9443"
	}
	// Materialise per-host MaxTTL from the JSON seconds value.
	for name, hp := range c.Hosts {
		if hp.MaxTTLSeconds > 0 {
			hp.MaxTTL = time.Duration(hp.MaxTTLSeconds) * time.Second
			c.Hosts[name] = hp
		}
	}
	return &c, nil
}
