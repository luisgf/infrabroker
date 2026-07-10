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
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/luisgf/infrabroker/internal/audit"
	"github.com/luisgf/infrabroker/internal/auth"
	"github.com/luisgf/infrabroker/internal/ca"
	"github.com/luisgf/infrabroker/internal/confcheck"
	"github.com/luisgf/infrabroker/internal/httpserve"
	"github.com/luisgf/infrabroker/internal/k8s"
	"github.com/luisgf/infrabroker/internal/monitor"
	"github.com/luisgf/infrabroker/internal/redact"
	"github.com/luisgf/infrabroker/internal/signer"
	"github.com/luisgf/infrabroker/internal/statedb"
	"github.com/luisgf/infrabroker/internal/version"
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

	// AuditFailMode governs what happens when the audit log cannot be written.
	// "closed" (default): the action being audited is denied — no signed audit
	// record, no certificate. "open": log the error, count the metric, and
	// proceed (the pre-2.0 behaviour). Empty = "closed".
	AuditFailMode string `json:"audit_fail_mode,omitempty"`

	// MaxTTLSeconds: global cap when the host policy does not set one.
	MaxTTLSeconds int `json:"max_ttl_seconds"`

	// AutoReloadSeconds: if > 0, the signer polls signer.json's mtime every N
	// seconds and hot-reloads on change — same validated, atomic path as SIGHUP /
	// POST /v1/reload, so a transiently-invalid in-progress save is rejected and
	// the previous good state is kept. 0 or absent = disabled (default).
	AutoReloadSeconds int `json:"auto_reload_seconds,omitempty"`

	// SignRateLimitPerMin caps POST /v1/sign requests per authenticated client
	// CN per minute (token bucket: burst up to the cap, continuous refill).
	// Keyed on the mTLS peer CN — not on_behalf_of — and enforced before body
	// parsing; excess requests get 429 with a Retry-After hint. Hot-reloadable.
	// 0 or absent = disabled (backward compatible).
	SignRateLimitPerMin int `json:"sign_rate_limit_per_min,omitempty"`

	// MonitorListen: optional plain-HTTP monitoring listener serving /healthz
	// (liveness) and /metrics (Prometheus text format). No authentication —
	// bind to localhost or a private scrape interface. Empty = disabled.
	MonitorListen string `json:"monitor_listen,omitempty"`

	// Redact enables secret redaction on the signer's audit log free-text
	// fields. Present (even empty, "redact": {}) = built-in default patterns;
	// absent = disabled (backward compatible). The signer's audit carries
	// request metadata rather than the raw command, but errors can embed user
	// text — every persistent sink applies the same invariant.
	Redact *redact.Config `json:"redact,omitempty"`

	// StateDB: optional path to the SQLite state database that persists
	// runtime grants and approve-and-learn waivers across restarts (pure-Go
	// driver, no system dependency; WAL mode leaves state.db-wal/-shm sidecar
	// files next to it). Empty or absent = in-memory only (previous
	// behaviour: grants are lost on restart, kept across reloads). If set and
	// the database cannot be opened or migrated, the signer refuses to start
	// (fail-closed). Production: /var/lib/infrabroker/signer/state.db.
	StateDB string `json:"state_db,omitempty"`

	// MaxGrantTTLSeconds: optional upper bound on a runtime grant's TTL
	// (POST /v1/policy/hosts/{host}/grants). 0 or absent = no cap.
	MaxGrantTTLSeconds int `json:"max_grant_ttl_seconds,omitempty"`

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
	// A non-empty table is authoritative and default-deny (v2.0.0): a CN absent
	// from it sees and signs NO hosts. An unlisted CN inherits a reserved
	// "_default" entry if present, else the zero policy (no groups). Add
	// "_default" with groups to grant unlisted CNs a baseline. An empty/absent
	// table configures no RBAC and leaves every caller unrestricted. A present CN
	// can only see and sign hosts whose groups field intersects allowed_groups.
	Callers signer.CallerTable `json:"callers,omitempty"`

	// CommandPolicies is a named library of command policies, attachable to
	// groups. GroupCommandPolicies maps a group name to the policy names that
	// apply to its hosts; the reserved group "_default" applies to every host.
	// A host's effective firewall is the composition of its inline command_policy
	// and the policies of all its groups (additive union; deny wins).
	CommandPolicies      map[string]signer.CommandPolicy `json:"command_policies,omitempty"`
	GroupCommandPolicies map[string][]string             `json:"group_command_policies,omitempty"`

	// Kubernetes is the optional Kubernetes target: a parallel map of clusters,
	// each with its own default-deny ActionPolicy, ServiceAccount bindings, and
	// a minter credential (token_file) whose RBAC is only `create` on
	// serviceaccounts/token. Absent = SSH-only signer (backward compatible).
	Kubernetes *K8sConfig `json:"kubernetes,omitempty"`
}

// K8sConfig groups the Kubernetes clusters under the "kubernetes" config key.
type K8sConfig struct {
	Clusters signer.ClusterTable `json:"clusters"`
}

func main() {
	cfgPath := flag.String("config", "signer.json", "path to the JSON/JSONC configuration file")
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

	// The grant store is created once and shared into every rebuilt Local, so
	// runtime grants survive config reloads. With state_db they also survive
	// restarts (write-through + reload at startup); without it they are lost
	// on restart (fail-safe: grants only widen).
	grantStore := signer.NewGrantStore()
	freezeStore := signer.NewFreezeStore()
	if cfg.StateDB != "" {
		stateDB, err := statedb.Open(cfg.StateDB, signer.StateMigrations())
		if err != nil {
			log.Fatalf("state db: %v", err)
		}
		defer stateDB.Close()
		grantStore, err = signer.NewGrantStoreDB(stateDB)
		if err != nil {
			log.Fatalf("state db: %v", err)
		}
		// Fail-closed: unlike grants, a freeze that fails to load must abort
		// startup rather than silently un-freeze a blocked subject.
		freezeStore, err = signer.NewFreezeStoreDB(stateDB)
		if err != nil {
			log.Fatalf("state db: %v", err)
		}
		log.Printf("state db: %s (%d live grants, %d freezes restored)",
			cfg.StateDB, len(grantStore.List(time.Now())), len(freezeStore.List()))
	} else {
		log.Printf("warning: state_db is not set — runtime grants, approve-and-learn waivers and freezes are volatile (lost on restart); a freeze via /v1/freeze needs allow_volatile (see: broker-ctl doctor --security)")
	}

	local, err := buildState(context.Background(), cfg, grantStore)
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

	if cfg.Redact != nil {
		redactor, rerr := redact.New(cfg.Redact)
		if rerr != nil {
			log.Fatalf("redact: %v", rerr)
		}
		if redactor != nil {
			auditLog.SetRedactor(redactor)
		}
	}

	auditFailClosed, err := audit.FailClosed(cfg.AuditFailMode)
	if err != nil {
		log.Fatalf("%v", err)
	}

	tlsCfg, err := auth.ServerTLSConfig(cfg.ServerCert, cfg.ServerKey, cfg.ClientCA)
	if err != nil {
		log.Fatalf("tls: %v", err)
	}

	srv := &server{
		local:           local,
		audit:           auditLog,
		hosts:           cfg.Hosts,
		callers:         cfg.Callers,
		reloadCN:        reloadSet(cfg.ReloadCallers),
		forwarders:      reloadSet(cfg.TrustedForwarders),
		signRateMin:     cfg.SignRateLimitPerMin,
		cfgPath:         *cfgPath,
		grants:          grantStore,
		freezes:         freezeStore,
		maxGrantTTL:     time.Duration(cfg.MaxGrantTTLSeconds) * time.Second,
		rateLimiter:     signer.NewRateLimiter(),
		auditFailClosed: auditFailClosed,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sign", srv.handleSign)
	mux.HandleFunc("/v1/hosts", srv.handleHosts)
	mux.HandleFunc("/v1/reload", srv.handleReload)
	// Validated policy mutation: add/remove a command_policy allow rule for a host
	// (auth: reload_callers). Validates + persists atomically + applies in-memory.
	mux.HandleFunc("POST /v1/policy/hosts/{host}/allow", srv.handlePolicyAllow)
	mux.HandleFunc("DELETE /v1/policy/hosts/{host}/allow", srv.handlePolicyAllow)
	// Runtime widen-only grants: time-boxed allow rules on an allowlist host that
	// expire on their own (auth: reload_callers). Held in memory; never persisted.
	mux.HandleFunc("POST /v1/policy/hosts/{host}/grants", srv.handleGrantCreate)
	mux.HandleFunc("GET /v1/policy/grants", srv.handleGrantList)
	mux.HandleFunc("DELETE /v1/policy/grants/{id}", srv.handleGrantRevoke)
	// Full host-policy read for operators (auth: reload_callers): the current
	// in-memory table, same schema as signer.json "hosts". Unlike GET /v1/hosts
	// (caller-scoped connectivity view) it exposes every internal policy field,
	// so it shares the mutation trust tier. Used by `broker-ctl host list --remote`.
	mux.HandleFunc("GET /v1/policy/hosts", srv.handlePolicyHostsRead)
	// Kubernetes cluster connectivity for the broker (group-filtered like
	// /v1/hosts). No-op when no clusters are configured.
	mux.HandleFunc("GET /v1/clusters", srv.handleClusters)

	// Kill switch (#117): freeze/unfreeze a subject (auth: reload_callers) and
	// stream the current freeze set to brokers (auth: any mTLS caller, like
	// /v1/hosts) so they can kill matching live sessions.
	mux.HandleFunc("POST /v1/freeze", srv.handleFreeze)
	mux.HandleFunc("POST /v1/unfreeze", srv.handleUnfreeze)
	mux.HandleFunc("GET /v1/revocations", srv.handleRevocations)

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

	// Optional auto-reload: poll the config file and hot-reload on change (same
	// validated/atomic path as SIGHUP). Off by default; local to the host, so it
	// bypasses the reload_callers allowlist exactly like SIGHUP does.
	if cfg.AutoReloadSeconds > 0 {
		go watchConfig(*cfgPath, time.Duration(cfg.AutoReloadSeconds)*time.Second, srv)
	}

	// Optional monitoring listener (/healthz, /metrics). Plain HTTP on its own
	// address; lives for the whole process (dies with it), so no ctx wiring.
	go monitor.Serve(context.Background(), cfg.MonitorListen, "signer")

	// Periodically drop expired runtime grants/waivers so they do not linger in
	// memory until the next list call (they are also filtered out at decision time).
	go func() {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for range t.C {
			srv.grants.Purge(time.Now())
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

// watchConfig polls path every interval and triggers a validated hot-reload when
// the file's mtime changes. Dependency-free (no fsnotify); the reload itself
// validates and atomically swaps, keeping the previous good state on any error,
// so a half-written file mid-save is rejected and re-applied on the next tick.
func watchConfig(path string, interval time.Duration, srv *server) {
	last := configModTime(path)
	t := time.NewTicker(interval)
	defer t.Stop()
	for range t.C {
		mt := configModTime(path)
		if mt.IsZero() || mt.Equal(last) {
			continue
		}
		last = mt
		n, err := srv.reload()
		if err != nil {
			log.Printf("reload (auto): error: %v (keeping previous config)", err)
			srv.auditReload("auto-reload", 0, "reload-failed", err)
			continue
		}
		log.Printf("reload (auto): %d hosts in policy", n)
		srv.auditReload("auto-reload", n, "reloaded", nil)
	}
}

func configModTime(path string) time.Time {
	fi, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	return fi.ModTime()
}

// buildState constructs the hot-reloadable state (signer + host policy) from
// the config: loads CA key(s) and materialises the default TTL.
// Returns an error without touching anything on failure, so an invalid reload
// does not leave the signer in a broken state.
// buildState compiles the policy and builds the *signer.Local. grants is the
// shared, stable GrantStore (created once in main and threaded through every
// rebuild) so runtime grants survive config reloads; pass nil for none.
func buildState(ctx context.Context, cfg *Config, grants signer.GrantProvider) (*signer.Local, error) {
	// The CA hard-rejects any certificate TTL over 15m (ca.BuildAndSign), so a
	// global max_ttl_seconds above that cap would make every issuance for a host
	// with no per-host max_ttl_seconds fail at request time. Reject it at load,
	// mirroring the per-host check in CompileHostPolicies (#45), instead of
	// surfacing a silent per-request denial.
	if cfg.MaxTTLSeconds > 900 {
		return nil, fmt.Errorf("max_ttl_seconds %d exceeds the 900s (15m) certificate cap", cfg.MaxTTLSeconds)
	}
	// Production-hardening nudge (broker-ctl doctor --security checks the full
	// deploy/README checklist). A non-empty callers table is default-deny for
	// unlisted CNs since v2.0.0, so no _default nudge is needed here.
	if cfg.SignRateLimitPerMin <= 0 {
		log.Printf("warning: sign_rate_limit_per_min is not set — no per-caller signing cap (see: broker-ctl doctor --security)")
	}
	// Compile + validate the host policies before touching anything so an invalid
	// reload (bad command_policy regex, unknown mode, dangling jump, unknown group
	// policy reference) is rejected up front and the previous good state is
	// preserved. The compiled table carries each host's effective PolicySet.
	compiled, err := signer.CompileHostPolicies(cfg.Hosts, cfg.CommandPolicies, cfg.GroupCommandPolicies)
	if err != nil {
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
	local := signer.NewLocalWithGrants(defaultCA, groupCAs, compiled, defaultTTL, grants)

	// Optional Kubernetes target: compile the clusters (validates + reads each
	// ca_cert, disjoint from host names) and build the bound-token minter.
	if cfg.Kubernetes != nil && len(cfg.Kubernetes.Clusters) > 0 {
		clusters, err := signer.CompileClusterPolicies(cfg.Kubernetes.Clusters, cfg.Hosts)
		if err != nil {
			return nil, fmt.Errorf("invalid kubernetes policy: %w", err)
		}
		minter := k8s.NewMinter(minterTargets(clusters))
		local.WithK8s(clusters, minter)
	}
	return local, nil
}

// minterTargets projects the compiled clusters into the minter's per-cluster
// token-request targets (API server, CA PEM, and the minter credential path).
func minterTargets(clusters signer.ClusterTable) map[string]k8s.MinterTarget {
	targets := make(map[string]k8s.MinterTarget, len(clusters))
	for name, cp := range clusters {
		targets[name] = k8s.MinterTarget{
			Target:    k8s.Target{APIServer: cp.APIServer, CAPEM: cp.CAPEM},
			TokenFile: cp.TokenFile,
		}
	}
	return targets
}

type localSigner interface {
	signer.Signer
	HostAllowlistActive(host string) (exists, allowlist bool)
	Clusters() signer.ClusterTable
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
	mu          sync.RWMutex
	local       localSigner
	hosts       signer.PolicyTable
	callers     signer.CallerTable
	reloadCN    map[string]struct{}
	forwarders  map[string]struct{}
	signRateMin int // per-CN /v1/sign requests per minute; 0 = disabled

	// writeMu serialises config mutations (POST/DELETE /v1/policy) so two
	// concurrent edits cannot interleave the file read-modify-write.
	writeMu sync.Mutex

	// Immutable after startup.
	audit   *audit.Log
	cfgPath string

	// auditFailClosed denies the audited action when the audit log cannot be
	// written (audit_fail_mode=closed, the default). False = fail-open (log and
	// proceed).
	auditFailClosed bool

	// grants is the shared runtime grant store (widen-only command-policy grants).
	// Created once and reused across reloads so live grants are not lost on a
	// config reload; its own mutex makes it concurrency-safe. maxGrantTTL caps a
	// grant's TTL at creation (0 = no cap).
	grants      *signer.GrantStore
	maxGrantTTL time.Duration

	// freezes is the shared kill-switch freeze store (#117): frozen subjects are
	// denied on /v1/sign and /v1/hosts and streamed to brokers via
	// /v1/revocations. Created once and reused across reloads; own mutex.
	freezes *signer.FreezeStore

	// rateLimiter holds the per-CN /v1/sign token buckets. Created once and
	// kept across reloads (its own mutex makes it concurrency-safe); the limit
	// itself lives in signRateMin so a reload applies instantly.
	rateLimiter *signer.RateLimiter
}

// signRate returns the hot-reloadable per-CN /v1/sign rate limit.
func (s *server) signRate() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.signRateMin
}

// snapshot returns the current state under RLock, so handlers do not read
// fields while a reload is replacing them.
func (s *server) snapshot() (localSigner, signer.PolicyTable, signer.CallerTable, map[string]struct{}) {
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
	local, err := buildState(context.Background(), cfg, s.grants)
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	s.local = local
	s.hosts = cfg.Hosts
	s.callers = cfg.Callers
	s.reloadCN = reloadSet(cfg.ReloadCallers)
	s.forwarders = reloadSet(cfg.TrustedForwarders)
	s.signRateMin = cfg.SignRateLimitPerMin
	s.mu.Unlock()
	return len(cfg.Hosts), nil
}

func (s *server) handleSign(w http.ResponseWriter, r *http.Request) {
	// codingstyle:long-function: the /v1/sign endpoint reads as one
	// request→authorize→sign→respond flow; the security-critical ordering is
	// clearer inline than split across helpers.
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	caller, err := auth.CallerCN(r)
	if err != nil {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}

	// Per-CN rate limit (threat-model gap #4), keyed on the authenticated mTLS
	// peer — not on_behalf_of, which arrives in the body from a single forwarder
	// peer anyway — and checked before body parsing so a flooding client costs
	// as little as possible. Deliberately NOT audited per rejection: the
	// tamper-evident log must not become the flooding amplifier.
	if limit := s.signRate(); limit > 0 && !s.rateLimiter.Allow(caller, limit) {
		signRequestsTotal.With("rate-limited").Inc()
		w.Header().Set("Retry-After", strconv.Itoa(signer.RetryAfter(limit)))
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	// A2: limit the request body to prevent OOM from oversized payloads.
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024) // 64 KiB is more than enough
	var req signer.WireRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	// Reject identity/intent fields that would splice forged tokens into the
	// signer audit record (auditEmission builds Entry.Command as a space-separated
	// key=value stream from these fields). This gate runs BEFORE any auditEmission,
	// so a malicious value cannot reach the tamper-evident log on the denial,
	// error, or issued paths — including session_mode, which authorizeIntent does
	// not whitespace-check on the one-shot issued path. Uses the same predicate as
	// authorizeIntent's KeyID gate so the two cannot drift.
	// The k8s_* fields are added here too: auditK8s builds the k8s audit record
	// as a space-separated key=value stream from these structured fields (never
	// from the free-form req.Command, which the client can craft with forged
	// tokens). Validating them here, before any auditK8s on the k8s denial
	// paths, keeps the stream unambiguous and unforgeable.
	for _, f := range []struct{ name, val string }{
		{"end_user", req.EndUser}, {"role", req.Role}, {"purpose", req.Purpose},
		{"session_mode", req.SessionMode}, {"sudo_user", req.SudoUser},
		{"k8s_verb", req.K8sVerb}, {"k8s_resource", req.K8sResource}, {"k8s_group", req.K8sGroup},
		{"k8s_namespace", req.K8sNamespace}, {"k8s_name", req.K8sName},
	} {
		if signer.HasUnsafeTokenChar(f.val) {
			http.Error(w, "invalid "+f.name+": control or whitespace characters not allowed", http.StatusBadRequest)
			return
		}
	}

	local, hosts, callers, forwarders := s.snapshot()

	// approved is honoured from a trusted forwarder (control plane), or from a
	// caller the operator opted into self-approval (#118, in-conversation
	// approvals: the same human requests and approves in the MCP client). Every
	// other broker cannot self-approve. Checked on the mTLS CN, before
	// resolveCaller, so on_behalf_of cannot borrow another CN's opt-in.
	_, isForwarder := forwarders[caller]
	selfApproves := callers.MaySelfApprove(caller)
	effectiveApproved := req.Approved && (isForwarder || selfApproves)

	// Resolve the effective caller identity: a trusted forwarder (control plane)
	// may act on behalf of the original broker via on_behalf_of.
	caller, ok := resolveCaller(caller, req.OnBehalfOf, forwarders)
	if !ok {
		http.Error(w, "on_behalf_of not allowed for this caller", http.StatusForbidden)
		return
	}
	// The resolved caller (the mTLS CN, or on_behalf_of for a trusted forwarder)
	// is written verbatim into the audit record's Caller field on the denial,
	// error and dry-run paths below — before authorizeIntent's own caller check
	// runs. Reject token-stream separators here so a whitespace-laden on_behalf_of
	// cannot plant a misleading attribution in the tamper-evident log. Validating
	// the resolved value covers both on_behalf_of and the raw CN in one place.
	if signer.HasUnsafeTokenChar(caller) {
		http.Error(w, "invalid caller identity: control or whitespace characters not allowed", http.StatusBadRequest)
		return
	}

	// Kill switch (#117): a frozen caller CN or end user gets no new certificate.
	// Checked before the ssh/k8s split so it covers one-shot, session open, and
	// every session-exec preflight — all of which reach /v1/sign. caller and
	// req.EndUser are both charset-checked above, so they are safe to audit.
	if subj, frozen := s.freezes.Frozen(caller, req.EndUser); frozen {
		signRequestsTotal.With("frozen-denied").Inc()
		if aerr := s.appendAudit(audit.Entry{
			Caller:  caller,
			Host:    req.Host,
			Outcome: "frozen_denied",
			Err:     fmt.Sprintf("frozen: %s=%s", subj.Kind, subj.Value),
		}); aerr != nil {
			writeAuditUnavailable(w)
			return
		}
		http.Error(w, "subject is frozen", http.StatusForbidden)
		return
	}

	// Kubernetes target: separate descriptor, group table, and audit shape.
	if req.TargetType == signer.TargetTypeK8s {
		s.handleSignK8s(w, r, caller, req, isForwarder, effectiveApproved, local, callers)
		return
	}

	pub, err := signer.ParsePublicKey(req.PublicKey)
	if err != nil {
		http.Error(w, "invalid pubkey", http.StatusBadRequest)
		return
	}

	// Verify group access before Resolve: if the caller has a group restriction,
	// the requested host must belong to one of its groups.
	if hostSet, restricted := signer.HostSetForCaller(caller, hosts, callers); restricted {
		if _, ok := hostSet[req.Host]; !ok {
			if aerr := s.auditEmission(caller, req, hosts, 0, "denied", nil, fmt.Errorf("host %q outside group for %q", req.Host, caller)); aerr != nil {
				writeAuditUnavailable(w)
				return
			}
			http.Error(w, "host not authorised", http.StatusForbidden)
			return
		}
	}

	in := signer.Intent{
		Caller:        caller,
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
		FileTransfer:  req.FileTransfer,
		DryRun:        req.DryRun,
		Preflight:     req.Preflight,
		Approved:      effectiveApproved,
		EndUser:       req.EndUser,
		EndUserGroups: req.EndUserGroups,
	}
	issued, err := local.SignIntent(r.Context(), in)
	if err != nil {
		if aerr := s.auditEmission(caller, req, hosts, 0, "denied", nil, err); aerr != nil {
			writeAuditUnavailable(w)
			return
		}
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	// #118: record a self-approval distinctly — four-eyes was deliberately waived
	// for this opted-in caller (the same human requested and approved in-chat).
	// Only when the command actually required approval.
	if selfApproves && !isForwarder && req.Approved && issued.Decision != nil && issued.Decision.RequireApproval {
		// Best-effort: a supplementary marker; the "issued" gate below is what
		// fails the sign if the log is unwritable.
		_ = s.appendAudit(audit.Entry{Caller: caller, Host: req.Host, Outcome: "self_approved"})
	}
	// Approve-and-learn: mint a TTL'd approval waiver after an approved sign that
	// requested it. The waiver is scoped to the effective caller/end-user/elevation.
	// Honoured only from a trusted forwarder (like Approved), so a broker can
	// neither self-approve nor self-learn.
	if isForwarder && req.LearnTTLSeconds > 0 {
		s.maybeLearnWaiver(caller, req, issued)
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
		if aerr := s.auditEmission(caller, req, hosts, 0, outcome, issued.Decision, nil); aerr != nil {
			writeAuditUnavailable(w)
			return
		}
		writeJSON(w, http.StatusOK, signer.WireResponse{Decision: issued.Decision})
		return
	}

	// No certificate but allowed: the operation requires human approval and has
	// not been approved yet. Return the decision (empty cert) so the control
	// plane can orchestrate approval.
	if issued.Certificate == nil {
		if aerr := s.auditEmission(caller, req, hosts, 0, "approval-required", issued.Decision, nil); aerr != nil {
			writeAuditUnavailable(w)
			return
		}
		writeJSON(w, http.StatusOK, signer.WireResponse{Decision: issued.Decision})
		return
	}

	// Issuance gate: if the "issued" record cannot be persisted in fail-closed
	// mode, deny — the certificate is never written to the response, so no action
	// can proceed downstream.
	if aerr := s.auditEmission(caller, req, hosts, issued.Serial, "issued", issued.Decision, nil); aerr != nil {
		writeAuditUnavailable(w)
		return
	}
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

	// Kill switch (#117): a frozen caller sees no connectivity, so it cannot even
	// discover hosts to attempt. A match means caller equals a value that was
	// charset-validated when it was frozen, so subj is safe to audit.
	if subj, frozen := s.freezes.Frozen(caller, ""); frozen {
		// Best-effort: GET /v1/hosts is a read; a broken log must not turn host
		// discovery into a 500 (only the sign path fails closed).
		_ = s.appendAudit(audit.Entry{
			Caller:  caller,
			Outcome: "frozen_denied",
			Err:     fmt.Sprintf("frozen: %s=%s", subj.Kind, subj.Value),
		})
		http.Error(w, "subject is frozen", http.StatusForbidden)
		return
	}

	result := make(map[string]signer.WireHostInfo, len(hosts))
	for name, hp := range hosts {
		result[name] = signer.WireHostInfo{
			Addr:              hp.Addr,
			User:              hp.User,
			HostKey:           hp.HostKey,
			Jump:              hp.Jump,
			AllowSudo:         hp.AllowSudo,
			AllowPTY:          hp.AllowPTY,
			AllowFileTransfer: hp.AllowFileTransfer,
			Groups:            hp.Groups,
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

	// Per-host allowed_callers filter: a broker must only see connectivity for
	// hosts it could actually obtain a certificate for. Resolve (/v1/sign)
	// enforces allowed_callers via callerAllowed; without the same filter here,
	// /v1/hosts would leak addr/user/host_key/topology of hosts the CN is
	// forbidden to use (the group filter alone is default-open for unlisted CNs).
	for name := range result {
		if hp, ok := hosts[name]; ok && !hp.AllowsCaller(caller) {
			delete(result, name)
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
	// Best-effort: the reload has already applied by the time this records it.
	_ = s.appendAudit(e)
}

// requireReloadCN authenticates a mutation request and checks the CN is in
// reload_callers. On failure it writes the response and returns ok=false. The
// route pattern already scopes the method.
func (s *server) requireReloadCN(w http.ResponseWriter, r *http.Request) (string, bool) {
	caller, err := auth.CallerCN(r)
	if err != nil {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return "", false
	}
	s.mu.RLock()
	_, allowed := s.reloadCN[caller]
	s.mu.RUnlock()
	if !allowed {
		http.Error(w, "not authorised", http.StatusForbidden)
		return "", false
	}
	return caller, true
}

// freezeRequest is the POST /v1/freeze and /v1/unfreeze body.
type freezeRequest struct {
	Kind   string `json:"kind"`
	Value  string `json:"value"`
	Reason string `json:"reason,omitempty"`
	// AllowVolatile lets a freeze be accepted even when the signer has no state_db
	// and the freeze would be lost on restart (fail-open). Off by default, so a
	// volatile freeze is refused unless the operator opts in (broker-ctl freeze
	// --volatile). Ignored on /v1/unfreeze.
	AllowVolatile bool `json:"allow_volatile,omitempty"`
}

// decodeFreezeSubject reads and validates a freeze subject from the request
// body. The value and reason are rejected if they carry control/whitespace so a
// forged token cannot splice into the audit stream (auditFreeze writes them as
// key=value tokens). Also returns whether the caller opted into a volatile
// freeze. Returns ok=false with the response already written.
func (s *server) decodeFreezeSubject(w http.ResponseWriter, r *http.Request) (subj signer.FreezeSubject, reason string, allowVolatile, ok bool) {
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	var req freezeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return signer.FreezeSubject{}, "", false, false
	}
	if !signer.ValidFreezeKind(req.Kind) {
		http.Error(w, "invalid kind (caller|end_user|session_id|serial)", http.StatusBadRequest)
		return signer.FreezeSubject{}, "", false, false
	}
	if req.Value == "" || signer.HasUnsafeTokenChar(req.Value) || signer.HasUnsafeTokenChar(req.Reason) {
		http.Error(w, "invalid value or reason: empty, control or whitespace characters not allowed", http.StatusBadRequest)
		return signer.FreezeSubject{}, "", false, false
	}
	return signer.FreezeSubject{Kind: req.Kind, Value: req.Value}, req.Reason, req.AllowVolatile, true
}

// handleFreeze serves POST /v1/freeze: freeze a subject so it gets no new
// certificate (/v1/sign) and no connectivity (/v1/hosts), and brokers kill its
// live sessions. reload_callers only. Freezing a caller/end_user also revokes
// that subject's runtime grants and approve-and-learn waivers.
func (s *server) handleFreeze(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireReloadCN(w, r)
	if !ok {
		return
	}
	subj, reason, allowVolatile, ok := s.decodeFreezeSubject(w, r)
	if !ok {
		return
	}
	// Without a state_db the freeze lives only in memory and vanishes on restart —
	// a subject the operator blocked silently regains access (fail-open). Refuse
	// unless the caller explicitly accepts that (allow_volatile / --volatile).
	if s.freezes.Volatile() && !allowVolatile {
		http.Error(w, "freeze would be volatile: the signer has no state_db, so this freeze is lost on restart. Configure state_db, or resend with allow_volatile to accept a memory-only freeze.", http.StatusConflict)
		return
	}
	// Serialise freeze mutations with the other config mutations so the freeze
	// and its grant revocation apply as one step.
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	newly, err := s.freezes.Add(subj, reason, caller, time.Now())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	revoked, gerr := s.grants.RevokeForSubject(subj.Kind, subj.Value)
	s.auditFreeze(caller, "frozen", subj, reason, revoked, gerr)
	if gerr != nil {
		http.Error(w, fmt.Sprintf("subject frozen, but revoking its grants failed: %v", gerr), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "newly_frozen": newly, "grants_revoked": revoked})
}

// handleUnfreeze serves POST /v1/unfreeze: release a previously frozen subject.
// reload_callers only.
func (s *server) handleUnfreeze(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireReloadCN(w, r)
	if !ok {
		return
	}
	subj, _, _, ok := s.decodeFreezeSubject(w, r)
	if !ok {
		return
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	existed, err := s.freezes.Remove(subj)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.auditFreeze(caller, "unfrozen", subj, "", 0, nil)
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "was_frozen": existed})
}

// handleRevocations serves GET /v1/revocations: the current freeze set, for
// brokers to poll and kill matching live sessions. Any authenticated mTLS caller
// may read it (operational data the broker needs), but provenance is admin-only:
// the free-text reason and the freezing admin's CN are dropped for ordinary
// brokers, which need only the subject (kind+value) to match sessions. Only the
// reload_callers tier — which can already freeze/unfreeze — sees the full record.
func (s *server) handleRevocations(w http.ResponseWriter, r *http.Request) {
	caller, err := auth.CallerCN(r)
	if err != nil {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	entries := s.freezes.List()
	s.mu.RLock()
	_, admin := s.reloadCN[caller]
	s.mu.RUnlock()
	if !admin {
		redacted := make([]signer.FrozenEntry, len(entries))
		for i, e := range entries {
			redacted[i] = signer.FrozenEntry{FreezeSubject: e.FreezeSubject, FrozenAt: e.FrozenAt}
		}
		entries = redacted
	}
	writeJSON(w, http.StatusOK, entries)
}

// auditFreeze records a freeze/unfreeze in the audit log. subj.Value and reason
// are charset-validated by decodeFreezeSubject, so the key=value stream stays
// unambiguous.
func (s *server) auditFreeze(caller, outcome string, subj signer.FreezeSubject, reason string, grantsRevoked int, err error) {
	cmd := fmt.Sprintf("%s kind=%s value=%s", outcome, subj.Kind, subj.Value)
	if outcome == "frozen" {
		cmd += fmt.Sprintf(" grants_revoked=%d", grantsRevoked)
	}
	if reason != "" {
		cmd += " reason=" + reason
	}
	e := audit.Entry{Caller: caller, Command: cmd, Outcome: outcome}
	if err != nil {
		e.Err = err.Error()
	}
	// Best-effort: the freeze/unfreeze has already applied by the time this runs.
	_ = s.appendAudit(e)
}

// signRequestsTotal counts /v1/sign requests by outcome. Fed by auditEmission
// (the single audit funnel) plus the rate-limit rejection, which is counted
// here but deliberately not audited.
var signRequestsTotal = monitor.GetCounterVec("signer_sign_requests_total",
	"POST /v1/sign requests by outcome.", "outcome")

// errAuditUnavailable is returned by the audit helpers when audit_fail_mode is
// "closed" (the default) and the tamper-evident log cannot be written. On the
// sign path it turns into a 500 and no certificate is issued.
var errAuditUnavailable = errors.New("audit unavailable")

// writeAuditUnavailable records the blocked action and writes the 500 an audited
// sign path returns when fail-closed mode cannot persist the outcome.
func writeAuditUnavailable(w http.ResponseWriter) {
	audit.RecordBlocked()
	http.Error(w, "audit unavailable", http.StatusInternalServerError)
}

// auditEmission is the single audit funnel for /v1/sign (SSH). It returns an
// error in fail-closed mode when the log cannot be written, so the caller denies
// the request (no cert leaves the signer) — the load-bearing gate for
// "no signed audit record, no action" across one-shot and session issuance.
func (s *server) auditEmission(caller string, req signer.WireRequest, hosts signer.PolicyTable, serial uint64, outcome string, dec *signer.DecisionInfo, err error) error {
	signRequestsTotal.With(outcome).Inc()
	cmd := "role=" + req.Role + " purpose=" + req.Purpose
	if req.SessionMode != "" {
		cmd += " session_mode=" + req.SessionMode
	}
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
	if req.FileTransfer {
		cmd += " ft=1"
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
	if dec != nil {
		e.PolicyRule = dec.MatchedRule
		e.Warning = dec.Warning
	}
	if err != nil {
		e.Err = err.Error()
	}
	return s.appendAudit(e)
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
	return parseConfig(b)
}

// parseConfig unmarshals config bytes and materialises derived fields (Listen
// default, per-host MaxTTL from seconds). Shared by loadConfig (startup/reload)
// and the policy-mutation path, which validates edited bytes before persisting.
func parseConfig(b []byte) (*Config, error) {
	var c Config
	if err := confcheck.Strict(b, &c); err != nil {
		return nil, err
	}
	if c.Listen == "" {
		c.Listen = ":9443"
	}
	for name, hp := range c.Hosts {
		if hp.MaxTTLSeconds > 0 {
			hp.MaxTTL = time.Duration(hp.MaxTTLSeconds) * time.Second
			c.Hosts[name] = hp
		}
	}
	return &c, nil
}
