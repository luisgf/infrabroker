// Package broker contains the shared core: configuration and the engine that,
// per request, signs an ephemeral SSH certificate, executes the command, and
// audits the result. Used by both the HTTP/mTLS frontend (cmd/broker) and the
// MCP server (cmd/mcp-broker), so security logic lives in a single place.
package broker

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/luisgf/ssh-broker/internal/audit"
	"github.com/luisgf/ssh-broker/internal/auth"
	"github.com/luisgf/ssh-broker/internal/ca"
	"github.com/luisgf/ssh-broker/internal/confcheck"
	"github.com/luisgf/ssh-broker/internal/monitor"
	"github.com/luisgf/ssh-broker/internal/redact"
	"github.com/luisgf/ssh-broker/internal/signer"
	sshrun "github.com/luisgf/ssh-broker/internal/ssh"
)

// Error categories returned by Execute / OpenSession so a frontend can map them
// to the right HTTP status instead of treating every failure as "denied". Use
// errors.Is to test them. Anything not wrapped in one of these is, by default,
// a policy/authorization denial (the conservative 403).
var (
	// ErrBadRequest: the request itself is malformed (e.g. empty command).
	ErrBadRequest = errors.New("bad request")
	// ErrUnknownHost: the host is not in the broker's configuration.
	ErrUnknownHost = errors.New("unknown host")
	// ErrUpstream: an infrastructure failure (SSH dial/exec, or the signing
	// service unreachable/5xx) — not the caller's authorization problem.
	ErrUpstream = errors.New("upstream failure")
)

// Config is loaded from a JSON file.
type Config struct {
	Listen string `json:"listen"` // HTTP only: e.g. ":8443"

	// TLS / mTLS for the HTTP frontend (not used by the MCP, which runs over stdio).
	ServerCert string `json:"server_cert"`
	ServerKey  string `json:"server_key"`
	ClientCA   string `json:"client_ca"`

	// CAKey — LOCAL mode ONLY (in-process signing). When the Signer block is
	// present, this field is ignored and the broker holds no CA key.
	// ca_keys: per-group CA key overrides. "_default" overrides ca_key when
	// present. See ca.CAKeyConfig for supported backends ("pem" for local files,
	// "akv" for Azure Key Vault). Local mode only; ignored when Signer is set.
	CAKey  string                    `json:"ca_key,omitempty"`
	CAKeys map[string]ca.CAKeyConfig `json:"ca_keys,omitempty"`

	// Signer, when present, externalises signing to a remote service
	// (HTTP+mTLS). The broker no longer holds the CA key or the policy.
	Signer *SignerClientConfig `json:"signer,omitempty"`

	// Audit.
	AuditLog string `json:"audit_log"`
	AuditKey string `json:"audit_key"` // Ed25519 seed (>=32 bytes)

	// SourceAddress: broker egress IP/CIDR, used in local mode.
	SourceAddress string `json:"source_address"`

	// MaxTTLSeconds caps the maximum requestable TTL.
	MaxTTLSeconds int `json:"max_ttl_seconds"`

	// HostsRefreshSeconds: host-list reload interval from the signer. Remote
	// mode only. Default: 300 (5 minutes).
	HostsRefreshSeconds int `json:"hosts_refresh_seconds"`

	// Persistent session idle-close and maximum lifetime.
	SessionIdleSeconds int `json:"session_idle_seconds"` // default 300
	SessionMaxSeconds  int `json:"session_max_seconds"`  // default 1800

	// SessionRecordingDir: directory for session recordings in ASCIIcast v2
	// format (.cast files). One file per session: <session_id>.cast.
	// Empty = recording disabled.
	SessionRecordingDir string `json:"session_recording_dir,omitempty"`

	// Redact enables secret redaction on this broker's persistent/outbound
	// sinks: the audit log's free-text fields and session recordings. Present
	// (even empty, "redact": {}) = built-in default patterns; absent = disabled
	// (backward compatible). Redaction never touches the decision path — the
	// signer and the certificate force-command always see the original command.
	Redact *redact.Config `json:"redact,omitempty"`

	// Hosts: used only in local mode (single-binary). In remote mode the host
	// list is fetched from the signer via /v1/hosts and refreshed periodically.
	Hosts map[string]HostConfig `json:"hosts,omitempty"`

	// CommandPolicies (local mode) is a named library of command policies,
	// attachable to groups. GroupCommandPolicies maps a group name to the policy
	// names that apply to its hosts; the reserved group "_default" applies to
	// every host. A host's effective firewall is the composition of its inline
	// command_policy and the policies of all its groups (additive union; deny wins).
	CommandPolicies      map[string]signer.CommandPolicy `json:"command_policies,omitempty"`
	GroupCommandPolicies map[string][]string             `json:"group_command_policies,omitempty"`

	// MonitorListen: optional plain-HTTP monitoring listener serving /healthz
	// (liveness) and /metrics (Prometheus text format), started by every
	// frontend (broker, mcp-broker, mcp-broker-http). No authentication — bind
	// to localhost or a private scrape interface. Empty = disabled.
	MonitorListen string `json:"monitor_listen,omitempty"`

	// FileTransferMaxBytes caps ssh_put_file content and ssh_get_file reads.
	// Default 524288 (512 KiB). The HTTP MCP frontend additionally bounds the
	// whole request body at 1 MiB, which base64-encoded content must fit.
	FileTransferMaxBytes int `json:"file_transfer_max_bytes,omitempty"`

	// OAuth and ResourceURL are used only by the HTTP+OAuth frontend
	// (cmd/mcp-broker-http); other frontends ignore them.
	OAuth *OAuthConfig `json:"oauth,omitempty"`
	// ResourceURL is the canonical URL of this MCP server, used in the Protected
	// Resource Metadata document (RFC 9728) and the WWW-Authenticate header.
	ResourceURL string `json:"resource_url,omitempty"`
}

// OAuthConfig configures OIDC token validation for the HTTP frontend. The
// token is validated locally against the issuer's JWKS (auto-discovery).
type OAuthConfig struct {
	// Issuer is the OIDC provider URL (e.g. https://keycloak.example/realms/x).
	Issuer string `json:"issuer"`
	// Audience is the expected value of the aud claim (this resource server).
	Audience string `json:"audience"`
	// RequiredScopes are the scopes the token must carry to be accepted.
	RequiredScopes []string `json:"required_scopes,omitempty"`
	// UserClaim is the claim used as user identity (default "sub").
	UserClaim string `json:"user_claim,omitempty"`
	// GroupsClaim is the claim that carries groups/roles to propagate to the
	// signer. Empty = groups are not propagated (no per-user RBAC).
	GroupsClaim string `json:"groups_claim,omitempty"`
	// MaxTokenAgeSeconds limits the age of the token since issuance (iat claim).
	// 0 = no limit (accepts any token within its exp). Recommended: 3600 (1h).
	// M3: reduces the replay risk of leaked tokens within their exp window.
	MaxTokenAgeSeconds int `json:"max_token_age_seconds,omitempty"`
	// ClockSkewSeconds is the tolerance applied to the nbf and iat claims to
	// absorb small clock differences between the IdP and this host. 0 selects a
	// 1-minute default; a negative value disables the tolerance.
	ClockSkewSeconds int `json:"clock_skew_seconds,omitempty"`
}

// HostConfig describes a destination in local mode.
type HostConfig struct {
	Addr      string `json:"addr"`
	User      string `json:"user"`
	Principal string `json:"principal"`
	HostKey   string `json:"host_key"`
	Jump      string `json:"jump,omitempty"`
	// SourceAddress: per-host override of the global value for THIS host's cert.
	// LOCAL mode only.
	SourceAddress string `json:"source_address,omitempty"`

	// Elevation (NOPASSWD) — local mode.
	AllowSudo        bool     `json:"allow_sudo,omitempty"`
	AllowedSudoUsers []string `json:"allowed_sudo_users,omitempty"`

	// AllowPTY — local mode.
	AllowPTY bool `json:"allow_pty,omitempty"`

	// AllowFileTransfer authorises ssh_put_file / ssh_get_file on this host —
	// local mode. Default false (secure by default). In remote mode this is
	// defined by the signer in signer.json.
	AllowFileTransfer bool `json:"allow_file_transfer,omitempty"`

	// Groups lists the RBAC groups this host belongs to. When ca_keys are
	// configured (multi-CA), the first matching group determines which CA signs
	// certificates for this host.  Also used for per-user RBAC in local mode.
	Groups []string `json:"groups,omitempty"`

	// AllowAsBastion authorises this host to be used as a ProxyJump hop
	// (permit-port-forwarding in its cert). Local mode only; default false to
	// match the remote-signer default-deny gate (ARCHITECTURE.md § routing). A
	// host referenced as another host's Jump target is enabled automatically (see
	// policyFromHosts), so existing jump chains keep working without per-host config.
	AllowAsBastion bool `json:"allow_as_bastion,omitempty"`

	// CommandPolicy — local mode (AI-action firewall). In remote mode this is
	// defined by the signer in signer.json.
	CommandPolicy signer.CommandPolicy `json:"command_policy,omitempty"`
}

// SignerClientConfig configures the client for the external signing service
// (direct signer or control plane).
type SignerClientConfig struct {
	URL        string `json:"url"`
	ClientCert string `json:"client_cert"`
	ClientKey  string `json:"client_key"`
	CA         string `json:"ca"`
	// ApprovalWaitSeconds: maximum time the broker waits for a human approval to
	// be resolved (202 response from the control plane). 0 = do not wait.
	ApprovalWaitSeconds int `json:"approval_wait_seconds,omitempty"`
}

// Caller identifies the origin of a request. ID is the audit identity
// (sub/preferred_username from OIDC in the HTTP frontend, mTLS CN, or
// "mcp-stdio"). Groups are the RBAC groups asserted by the frontend (OIDC);
// empty in stdio and mTLS. When Groups is non-empty the signer applies
// per-user authorisation.
type Caller struct {
	ID     string
	Groups []string
}

// ExecOptions holds the elevation and PTY options for an execution.
type ExecOptions struct {
	// Sudo requests privilege elevation via sudo NOPASSWD.
	Sudo bool
	// SudoUser is the target user for sudo (empty = root).
	SudoUser string
	// PTY requests a pseudo-terminal for the execution.
	PTY bool
	// DryRun simulates: resolves the policy and returns the decision without
	// connecting or executing. Allows the model to preview whether a command
	// would be permitted.
	DryRun bool

	// Stdin, when non-empty, is streamed to the remote command's standard
	// input (file uploads). One-shot only; ignored for sessions and PTY.
	Stdin []byte
	// FileTransfer marks the intent as a file transfer: the signer rejects it
	// unless the host policy has allow_file_transfer=true.
	FileTransfer bool
}

// elevationLabel builds the audit label for the elevation.
func (o ExecOptions) elevationLabel() string {
	if !o.Sudo {
		return ""
	}
	u := o.SudoUser
	if u == "" {
		u = "root"
	}
	return "sudo:" + u
}

// LoadConfig reads and parses the JSON configuration.
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := confcheck.Strict(b, &c); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if c.Listen == "" {
		c.Listen = ":8443"
	}
	return &c, nil
}

// Result is the outcome of an execution.
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Serial   uint64
	Warnings []string
	// DryRun is populated only for simulations (ExecOptions.DryRun): it contains
	// the policy decision instead of the output of an executed command.
	DryRun *signer.DecisionInfo
}

// hostFetcher retrieves the host list from the signer. Implemented by *signer.Remote.
type hostFetcher interface {
	FetchHosts(context.Context, string) (map[string]signer.HostInfo, error)
}

// Engine executes commands by signing ephemeral credentials and auditing.
type Engine struct {
	cfg      *Config
	sgn      signer.Signer
	fetcher  hostFetcher // nil in local mode
	auditLog *audit.Log
	redactor *redact.Redactor // nil = redaction disabled
	maxTTL   time.Duration
	sessions *sessionManager

	mu    sync.RWMutex
	hosts map[string]signer.HostInfo // cache refreshed periodically (remote mode)
	// In local mode hosts come from cfg.Hosts; the hosts map is not used.

	// hostKeyCache memoises parsed host keys, content-addressed by the
	// authorized_keys line. The same key string always parses to the same
	// ssh.PublicKey, so the cache stays valid across host-list refreshes and is
	// shared between local and remote modes. Cardinality is bounded by the number
	// of distinct host keys (operator config), so no eviction is needed.
	hostKeyCache sync.Map // string → ssh.PublicKey | error

	// refreshStop terminates the remote host-refresh goroutine on Close. It is
	// nil in local mode (no goroutine). Guarded by refreshStopOnce as a second
	// line of defence; Close itself is guarded by closeOnce.
	refreshStop     chan struct{}
	refreshStopOnce sync.Once

	closeOnce sync.Once
	closeErr  error
}

// localCaller is the broker's identity toward a local signer.
const localCaller = "local"

// NewEngine initialises the signer (local or remote) and the audit log.
func NewEngine(cfg *Config) (*Engine, error) {
	maxTTL := time.Duration(cfg.MaxTTLSeconds) * time.Second
	if maxTTL <= 0 {
		maxTTL = 5 * time.Minute
	}

	sgn, fetcher, err := buildSigner(context.Background(), cfg, maxTTL)
	if err != nil {
		return nil, err
	}

	seed, err := os.ReadFile(cfg.AuditKey)
	if err != nil {
		return nil, fmt.Errorf("reading audit key: %w", err)
	}
	if len(seed) < ed25519.SeedSize {
		return nil, fmt.Errorf("audit key too short")
	}
	al, err := audit.Open(cfg.AuditLog, ed25519.NewKeyFromSeed(seed[:ed25519.SeedSize]))
	if err != nil {
		return nil, err
	}

	// An invalid redact pattern is a startup error (fail-closed), not a
	// silently smaller rule set.
	var redactor *redact.Redactor
	if cfg.Redact != nil {
		redactor, err = redact.New(cfg.Redact)
		if err != nil {
			return nil, fmt.Errorf("compiling redact config: %w", err)
		}
		if redactor != nil {
			al.SetRedactor(redactor)
		}
	}

	idle := time.Duration(cfg.SessionIdleSeconds) * time.Second
	if idle <= 0 {
		idle = 5 * time.Minute
	}
	maxLife := time.Duration(cfg.SessionMaxSeconds) * time.Second
	if maxLife <= 0 {
		maxLife = 30 * time.Minute
	}

	e := &Engine{cfg: cfg, sgn: sgn, fetcher: fetcher, auditLog: al, redactor: redactor, maxTTL: maxTTL}
	e.sessions = newSessionManager(idle, maxLife, func(s *liveSession) {
		e.auditE(audit.Entry{Caller: s.caller, Host: s.host, Serial: s.serial,
			SessionID: s.id, Outcome: "session_close", Err: "reaped (idle/lifetime)"})
	})
	// Scrape-time gauge over the live session map. SetGaugeFunc replaces any
	// previous registration, so a rebuilt engine (tests, restarts of the
	// embedding frontend) simply rebinds the gauge to itself.
	monitor.SetGaugeFunc("broker_sessions_active",
		"Persistent SSH sessions currently open.", e.sessions.count)

	// Remote mode: initial host load and start the refresh goroutine.
	if fetcher != nil {
		h, err := fetcher.FetchHosts(context.Background(), "")
		if err != nil {
			al.Close()
			return nil, fmt.Errorf("initial host load from signer: %w", err)
		}
		e.hosts = h
		log.Printf("hosts loaded from signer: %d entries", len(h))

		refresh := time.Duration(cfg.HostsRefreshSeconds) * time.Second
		if refresh <= 0 {
			refresh = 5 * time.Minute
		}
		e.startHostRefresh(refresh)
	}

	return e, nil
}

// startHostRefresh starts the goroutine that periodically reloads the host
// list from the signer. The goroutine exits when e.refreshStop is closed (by
// Close), so it does not outlive the engine.
func (e *Engine) startHostRefresh(interval time.Duration) {
	e.refreshStop = make(chan struct{})
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-e.refreshStop:
				return
			case <-t.C:
				h, err := e.fetcher.FetchHosts(context.Background(), "")
				if err != nil {
					log.Printf("warning: host refresh failed: %v (keeping previous cache)", err)
					continue
				}
				e.mu.Lock()
				e.hosts = h
				e.mu.Unlock()
				log.Printf("hosts reloaded from signer: %d entries", len(h))
			}
		}
	}()
}

// buildSigner constructs a remote signer (when a Signer block is present) or a
// local one. Also returns the *Remote for FetchHosts (nil in local mode).
func buildSigner(ctx context.Context, cfg *Config, maxTTL time.Duration) (signer.Signer, hostFetcher, error) {
	if cfg.Signer != nil {
		tlsCfg, err := auth.ClientTLSConfig(cfg.Signer.ClientCert, cfg.Signer.ClientKey, cfg.Signer.CA)
		if err != nil {
			return nil, nil, fmt.Errorf("signing client TLS: %w", err)
		}
		r := signer.NewRemote(cfg.Signer.URL, tlsCfg, 0)
		if cfg.Signer.ApprovalWaitSeconds > 0 {
			r.SetApprovalWait(time.Duration(cfg.Signer.ApprovalWaitSeconds) * time.Second)
		}
		return r, r, nil
	}
	// Local mode: load CA key(s) and build the in-process signer.
	defaultCA, groupCAs, err := ca.LoadGroupCAs(ctx, cfg.CAKey, cfg.CAKeys)
	if err != nil {
		return nil, nil, fmt.Errorf("loading CA keys (local mode): %w", err)
	}
	// Compile + validate host policies, resolving each host's effective PolicySet
	// from its inline command_policy and the policies of its groups.
	compiled, err := signer.CompileHostPolicies(policyFromHosts(cfg), cfg.CommandPolicies, cfg.GroupCommandPolicies)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid host policy (local mode): %w", err)
	}
	return signer.NewLocalWithGroupCAs(defaultCA, groupCAs, compiled, maxTTL), nil, nil
}

// policyFromHosts derives the signer's PolicyTable from the broker's host
// config (single-binary mode, no external service).
func policyFromHosts(cfg *Config) signer.PolicyTable {
	// A host is usable as a bastion only if the operator marked it
	// allow_as_bastion, or if another host references it as its Jump target
	// (otherwise local-mode jump chains would break). Defaulting the rest to
	// false mirrors the remote-signer default-deny gate, so a leaf host no longer
	// gets permit-port-forwarding in its cert just because it runs in local mode.
	jumpTargets := make(map[string]bool)
	for _, hc := range cfg.Hosts {
		if hc.Jump != "" {
			jumpTargets[hc.Jump] = true
		}
	}
	pt := signer.PolicyTable{}
	for name, hc := range cfg.Hosts {
		src := cfg.SourceAddress
		if hc.SourceAddress != "" {
			src = hc.SourceAddress
		}
		pt[name] = signer.HostPolicy{
			Addr:              hc.Addr,
			User:              hc.User,
			HostKey:           hc.HostKey,
			Jump:              hc.Jump,
			Principal:         hc.Principal,
			SourceAddress:     src,
			AllowAsBastion:    hc.AllowAsBastion || jumpTargets[name],
			AllowSudo:         hc.AllowSudo,
			AllowedSudoUsers:  hc.AllowedSudoUsers,
			AllowPTY:          hc.AllowPTY,
			AllowFileTransfer: hc.AllowFileTransfer,
			Groups:            hc.Groups,
			CommandPolicy:     hc.CommandPolicy,
		}
	}
	return pt
}

// hostInfo returns connectivity data for a host regardless of mode (local or
// remote).
func (e *Engine) hostInfo(name string) (signer.HostInfo, bool) {
	if e.fetcher != nil {
		// Remote mode: cache protected by RWMutex.
		e.mu.RLock()
		h, ok := e.hosts[name]
		e.mu.RUnlock()
		return h, ok
	}
	// Local mode: read from cfg.Hosts.
	hc, ok := e.cfg.Hosts[name]
	if !ok {
		return signer.HostInfo{}, false
	}
	return signer.HostInfo{Addr: hc.Addr, User: hc.User, HostKey: hc.HostKey, Jump: hc.Jump,
		AllowSudo: hc.AllowSudo, AllowPTY: hc.AllowPTY, AllowFileTransfer: hc.AllowFileTransfer, Groups: hc.Groups}, true
}

// refreshHostsNow reloads the remote signer host view immediately. It is used
// by session-exec preflight so an already-open session is compared with the
// current host definition, not just the periodic broker cache.
func (e *Engine) refreshHostsNow(ctx context.Context) error {
	if e.fetcher == nil {
		return nil
	}
	h, err := e.fetcher.FetchHosts(ctx, "")
	if err != nil {
		return err
	}
	e.mu.Lock()
	e.hosts = h
	e.mu.Unlock()
	return nil
}

// currentConnectivitySignature returns the physical SSH chain signature for
// host after refreshing the remote host view when a signer/control-plane is in
// use. It fails closed on refresh errors.
func (e *Engine) currentConnectivitySignature(ctx context.Context, host string) (string, error) {
	if err := e.refreshHostsNow(ctx); err != nil {
		return "", err
	}
	return e.connectivitySignature(host)
}

func (e *Engine) refreshHostsForNewConnection(ctx context.Context) error {
	if err := e.refreshHostsNow(ctx); err != nil {
		return fmt.Errorf("%w: refreshing host list: %v", ErrUpstream, err)
	}
	return nil
}

// connectivitySignature captures the physical route for a logical host:
// chain order plus addr/user/host_key/jump for every hop. It intentionally does
// not include policy-only fields such as sudo/PTY/groups; those are revalidated
// by the signer preflight itself.
func (e *Engine) connectivitySignature(host string) (string, error) {
	chain, err := e.resolveChain(host)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, name := range chain {
		hi, ok := e.hostInfo(name)
		if !ok {
			return "", fmt.Errorf("unknown host in chain: %q", name)
		}
		writeSignaturePart(&b, name)
		writeSignaturePart(&b, hi.Addr)
		writeSignaturePart(&b, hi.User)
		writeSignaturePart(&b, hi.HostKey)
		writeSignaturePart(&b, hi.Jump)
		b.WriteByte('|')
	}
	return b.String(), nil
}

func writeSignaturePart(b *strings.Builder, s string) {
	fmt.Fprintf(b, "%d:%s", len(s), s)
}

// ServerInfo contains the logical name and capabilities of a host, so the
// model can choose the appropriate execution strategy.
type ServerInfo struct {
	Name              string
	AllowSudo         bool
	AllowPTY          bool
	AllowFileTransfer bool
	Jump              string // bastion name, if any
}

// ServerInfos returns the hosts visible to the caller with their capabilities
// (stable order). When the caller carries end-user groups (OIDC HTTP frontend),
// the list is filtered to hosts sharing at least one group — consistent with
// the per-user RBAC the signer applies at signing time, so the model is not
// offered hosts it cannot use. Callers without groups (stdio, mTLS) see every
// host (compatible).
func (e *Engine) ServerInfos(c Caller) []ServerInfo {
	var infos []ServerInfo
	if e.fetcher != nil {
		e.mu.RLock()
		infos = make([]ServerInfo, 0, len(e.hosts))
		for name, h := range e.hosts {
			if c.Groups != nil && !groupsIntersect(h.Groups, c.Groups) {
				continue
			}
			infos = append(infos, ServerInfo{Name: name, AllowSudo: h.AllowSudo, AllowPTY: h.AllowPTY, AllowFileTransfer: h.AllowFileTransfer, Jump: h.Jump})
		}
		e.mu.RUnlock()
	} else {
		infos = make([]ServerInfo, 0, len(e.cfg.Hosts))
		for name, hc := range e.cfg.Hosts {
			if c.Groups != nil && !groupsIntersect(hc.Groups, c.Groups) {
				continue
			}
			infos = append(infos, ServerInfo{Name: name, AllowSudo: hc.AllowSudo, AllowPTY: hc.AllowPTY, AllowFileTransfer: hc.AllowFileTransfer, Jump: hc.Jump})
		}
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].Name < infos[j].Name })
	return infos
}

// groupsIntersect reports whether the two group lists share at least one
// element. A host with no groups is never visible to a group-restricted user
// (same semantics as the signer's per-user check).
func groupsIntersect(hostGroups, userGroups []string) bool {
	for _, hg := range hostGroups {
		for _, ug := range userGroups {
			if hg == ug {
				return true
			}
		}
	}
	return false
}

// Servers returns the configured host names (stable order).
func (e *Engine) Servers() []string {
	var names []string
	if e.fetcher != nil {
		e.mu.RLock()
		names = make([]string, 0, len(e.hosts))
		for k := range e.hosts {
			names = append(names, k)
		}
		e.mu.RUnlock()
	} else {
		names = make([]string, 0, len(e.cfg.Hosts))
		for k := range e.cfg.Hosts {
			names = append(names, k)
		}
	}
	sort.Strings(names)
	return names
}

// Execute signs a scoped ephemeral cert (with force-command, and sudo when
// requested), executes command on host in a single shot (via bastion if
// configured), and audits.
func (e *Engine) Execute(ctx context.Context, c Caller, host, command string, ttlSeconds int, opts ExecOptions) (*Result, error) {
	if err := e.refreshHostsForNewConnection(ctx); err != nil {
		e.auditE(audit.Entry{Caller: c.ID, Host: host, Command: command, Outcome: "error", Err: err.Error()})
		return nil, err
	}
	if _, ok := e.hostInfo(host); !ok {
		e.auditE(audit.Entry{Caller: c.ID, Host: host, Command: command, Outcome: "denied", Err: "unknown host"})
		return nil, fmt.Errorf("%w: %q", ErrUnknownHost, host)
	}
	if command == "" {
		return nil, fmt.Errorf("%w: command is required", ErrBadRequest)
	}

	if opts.DryRun {
		return e.dryRun(ctx, c, host, command, ttlSeconds, opts)
	}

	hops, serial, dec, err := e.buildHops(ctx, c, host, e.ttlFor(ttlSeconds), signer.PurposeOneshot, command, opts)
	if err != nil {
		e.auditE(audit.Entry{Caller: c.ID, Host: host, Command: command, Outcome: "error", Err: err.Error()})
		return nil, classifySignErr(err)
	}
	warnings := decisionWarnings(dec)
	conn, err := sshrun.Dial(ctx, hops, 0)
	if err != nil {
		e.auditE(audit.Entry{Caller: c.ID, Host: host, Command: command, Serial: serial, Outcome: "error", Err: err.Error()})
		return nil, fmt.Errorf("%w: connection: %v", ErrUpstream, err)
	}
	defer conn.Close()

	execOpts := sshrun.ExecOptions{PTY: opts.PTY, Stdin: opts.Stdin}
	res, err := sshrun.ExecOnce(ctx, conn.Client, command, execOpts)
	if err != nil {
		e.auditE(audit.Entry{Caller: c.ID, Host: host, Command: command, Serial: serial, Outcome: "error", Err: err.Error()})
		return nil, fmt.Errorf("%w: execution: %v", ErrUpstream, err)
	}
	e.auditE(audit.Entry{
		Caller:     c.ID,
		Host:       host,
		Command:    command,
		Serial:     serial,
		Outcome:    "executed",
		ExitCode:   res.ExitCode,
		Elevation:  opts.elevationLabel(),
		PTY:        opts.PTY,
		PolicyRule: decisionRule(dec),
		Warning:    strings.Join(warnings, "; "),
	})
	return &Result{Stdout: res.Stdout, Stderr: res.Stderr, ExitCode: res.ExitCode, Serial: serial, Warnings: warnings}, nil
}

// classifySignErr maps an error from the signing path (buildHops → SignIntent)
// to a broker error category. A signing service that is unreachable or returns
// 5xx is an upstream failure (→ 502); any other error — a policy/authorization
// denial, in either local or remote mode — is left unwrapped and treated as a
// denial (→ 403) by the frontend.
func classifySignErr(err error) error {
	if errors.Is(err, signer.ErrSignerUnavailable) {
		return fmt.Errorf("%w: %v", ErrUpstream, err)
	}
	return err
}

// dryRun resolves the policy for the target host and returns the decision
// without connecting or executing. Only evaluates the target (command policy
// lives there); does not issue usable certificates or traverse the bastion chain.
func (e *Engine) dryRun(ctx context.Context, c Caller, host, command string, ttlSeconds int, opts ExecOptions) (*Result, error) {
	_, pub, err := ca.GenerateEphemeralKey()
	if err != nil {
		return nil, err
	}
	in := signer.Intent{
		Caller:        localCaller,
		Host:          host,
		Role:          signer.RoleTarget,
		Purpose:       signer.PurposeOneshot,
		Command:       command,
		RequestedTTL:  e.ttlFor(ttlSeconds),
		PublicKey:     pub,
		Sudo:          opts.Sudo,
		SudoUser:      opts.SudoUser,
		PTY:           opts.PTY,
		DryRun:        true,
		EndUser:       c.ID,
		EndUserGroups: c.Groups,
	}
	issued, err := e.sgn.SignIntent(ctx, in)
	if err != nil {
		e.auditE(audit.Entry{Caller: c.ID, Host: host, Command: command, Outcome: "error", DryRun: true, Err: err.Error()})
		return nil, err
	}
	dec := issued.Decision
	outcome := "dry_run_allowed"
	var rule string
	if dec != nil {
		rule = dec.MatchedRule
		if !dec.Allowed {
			outcome = "dry_run_denied"
		}
	}
	e.auditE(audit.Entry{
		Caller: c.ID, Host: host, Command: command, Outcome: outcome,
		DryRun: true, PolicyRule: rule, Elevation: opts.elevationLabel(), PTY: opts.PTY,
		Warning: decisionWarning(dec),
	})
	return &Result{DryRun: dec}, nil
}

func decisionWarnings(dec *signer.DecisionInfo) []string {
	if dec == nil || dec.Warning == "" {
		return nil
	}
	return []string{dec.Warning}
}

func decisionWarning(dec *signer.DecisionInfo) string {
	if dec == nil {
		return ""
	}
	return dec.Warning
}

func decisionRule(dec *signer.DecisionInfo) string {
	if dec == nil {
		return ""
	}
	return dec.MatchedRule
}

func (e *Engine) ttlFor(ttlSeconds int) time.Duration {
	ttl := time.Duration(ttlSeconds) * time.Second
	if ttl <= 0 || ttl > e.maxTTL {
		ttl = e.maxTTL
	}
	return ttl
}

// buildHops resolves the target→…→bastion chain and, per hop, generates an
// ephemeral key pair and requests a cert from the signer.
func (e *Engine) buildHops(ctx context.Context, c Caller, host string, ttl time.Duration, purpose, command string, opts ExecOptions) ([]sshrun.Hop, uint64, *signer.DecisionInfo, error) {
	chain, err := e.resolveChain(host)
	if err != nil {
		return nil, 0, nil, err
	}

	hops := make([]sshrun.Hop, 0, len(chain))
	var finalSerial uint64
	var targetDecision *signer.DecisionInfo
	for i, name := range chain {
		hi, ok := e.hostInfo(name)
		if !ok {
			return nil, 0, nil, fmt.Errorf("unknown host in chain: %q", name)
		}
		isTarget := i == len(chain)-1

		priv, pub, err := ca.GenerateEphemeralKey()
		if err != nil {
			return nil, 0, nil, err
		}
		in := signer.Intent{
			Caller:        localCaller,
			Host:          name,
			Role:          signer.RoleBastion,
			Purpose:       purpose,
			RequestedTTL:  ttl,
			PublicKey:     pub,
			EndUser:       c.ID,
			EndUserGroups: c.Groups,
		}
		if isTarget {
			in.Role = signer.RoleTarget
			in.Command = command
			// Elevation, PTY, and the file-transfer gate only at the target hop.
			in.Sudo = opts.Sudo
			in.SudoUser = opts.SudoUser
			in.PTY = opts.PTY
			in.FileTransfer = opts.FileTransfer
		}
		issued, err := e.sgn.SignIntent(ctx, in)
		if err != nil {
			return nil, 0, nil, fmt.Errorf("signing cert for %q: %w", name, err)
		}
		if issued.Certificate == nil {
			return nil, 0, nil, approvalError(name, issued.Decision)
		}
		hostKey, err := e.parseHostKeyCached(hi.HostKey)
		if err != nil {
			return nil, 0, nil, fmt.Errorf("host key for %q: %w", name, err)
		}
		hops = append(hops, sshrun.Hop{
			Addr: hi.Addr, User: hi.User, HostKey: hostKey,
			PrivateKey: priv, Certificate: issued.Certificate,
		})
		if isTarget {
			finalSerial = issued.Serial
			targetDecision = issued.Decision
		}
	}
	return hops, finalSerial, targetDecision, nil
}

// buildHopsWithPrefix is like buildHops but also returns the ElevationPrefix,
// the physical connectivity signature, and the policy decision issued by the
// signer for the target hop (sessions).
func (e *Engine) buildHopsWithPrefix(ctx context.Context, c Caller, host string, ttl time.Duration, purpose, sessionMode string, opts ExecOptions) ([]sshrun.Hop, uint64, string, string, *signer.DecisionInfo, error) {
	chain, err := e.resolveChain(host)
	if err != nil {
		return nil, 0, "", "", nil, err
	}

	hops := make([]sshrun.Hop, 0, len(chain))
	var finalSerial uint64
	var elevPrefix string
	var targetDecision *signer.DecisionInfo
	var connectivitySig strings.Builder
	for i, name := range chain {
		hi, ok := e.hostInfo(name)
		if !ok {
			return nil, 0, "", "", nil, fmt.Errorf("unknown host in chain: %q", name)
		}
		isTarget := i == len(chain)-1
		writeSignaturePart(&connectivitySig, name)
		writeSignaturePart(&connectivitySig, hi.Addr)
		writeSignaturePart(&connectivitySig, hi.User)
		writeSignaturePart(&connectivitySig, hi.HostKey)
		writeSignaturePart(&connectivitySig, hi.Jump)
		connectivitySig.WriteByte('|')

		priv, pub, err := ca.GenerateEphemeralKey()
		if err != nil {
			return nil, 0, "", "", nil, err
		}
		in := signer.Intent{
			Caller:        localCaller,
			Host:          name,
			Role:          signer.RoleBastion,
			Purpose:       purpose,
			RequestedTTL:  ttl,
			PublicKey:     pub,
			EndUser:       c.ID,
			EndUserGroups: c.Groups,
		}
		if isTarget {
			in.Role = signer.RoleTarget
			if purpose == signer.PurposeSession {
				in.SessionMode = sessionMode
			}
			in.Sudo = opts.Sudo
			in.SudoUser = opts.SudoUser
			in.PTY = opts.PTY
		}
		issued, err := e.sgn.SignIntent(ctx, in)
		if err != nil {
			return nil, 0, "", "", nil, fmt.Errorf("signing cert for %q: %w", name, err)
		}
		if issued.Certificate == nil {
			return nil, 0, "", "", nil, approvalError(name, issued.Decision)
		}
		hostKey, err := e.parseHostKeyCached(hi.HostKey)
		if err != nil {
			return nil, 0, "", "", nil, fmt.Errorf("host key for %q: %w", name, err)
		}
		hops = append(hops, sshrun.Hop{
			Addr: hi.Addr, User: hi.User, HostKey: hostKey,
			PrivateKey: priv, Certificate: issued.Certificate,
		})
		if isTarget {
			finalSerial = issued.Serial
			elevPrefix = issued.ElevationPrefix
			targetDecision = issued.Decision
		}
	}
	return hops, finalSerial, elevPrefix, connectivitySig.String(), targetDecision, nil
}

// approvalError builds the error shown to a broker when a cert is not issued
// because human approval is required. On the direct broker→signer path (no
// control plane) approval cannot be orchestrated, so the user is informed.
func approvalError(host string, d *signer.DecisionInfo) error {
	rule := ""
	if d != nil {
		rule = d.MatchedRule
	}
	return fmt.Errorf("command on %q requires human approval (%s); use the control plane to approve it", host, rule)
}

// resolveChain returns the host chain in dial order (outermost bastion first,
// target last), following Jump fields and detecting cycles.
func (e *Engine) resolveChain(host string) ([]string, error) {
	var chain []string
	seen := map[string]bool{}
	for cur := host; cur != ""; {
		if seen[cur] {
			return nil, fmt.Errorf("bastion cycle at %q", cur)
		}
		seen[cur] = true
		hi, ok := e.hostInfo(cur)
		if !ok {
			return nil, fmt.Errorf("unknown host in chain: %q", cur)
		}
		chain = append([]string{cur}, chain...)
		cur = hi.Jump
	}
	return chain, nil
}

// Close stops the host-refresh goroutine, closes all sessions and the audit log.
func (e *Engine) Close() error {
	e.closeOnce.Do(func() {
		if e.refreshStop != nil {
			e.refreshStopOnce.Do(func() { close(e.refreshStop) })
		}
		if e.sessions != nil {
			e.sessions.closeAll()
		}
		if e.auditLog != nil {
			e.closeErr = e.auditLog.Close()
		}
	})
	return e.closeErr
}

// eventsTotal counts every broker audit event by outcome (executed, denied,
// error, session_open, session_exec, session_close, …). Fed by auditE, the
// single audit funnel.
var eventsTotal = monitor.GetCounterVec("broker_events_total",
	"Broker audit events by outcome.", "outcome")

func (e *Engine) auditE(ent audit.Entry) {
	eventsTotal.With(ent.Outcome).Inc()
	if hi, ok := e.hostInfo(ent.Host); ok {
		if ent.User == "" {
			ent.User = hi.User
		}
	}
	// M1: log the error instead of silently discarding it.
	if err := e.auditLog.Append(ent); err != nil {
		log.Printf("warning: error writing audit log: %v", err)
	}
}

// ParseHostKey converts an authorized_keys line into an ssh.PublicKey.
func ParseHostKey(authorizedKeyLine string) (ssh.PublicKey, error) {
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKeyLine))
	if err != nil {
		return nil, fmt.Errorf("parsing host key: %w", err)
	}
	return pk, nil
}

// parseHostKeyCached parses an authorized_keys line through e.hostKeyCache so the
// wire-format parse runs once per distinct key instead of once per hop per
// request. Both successful keys and parse errors are memoised (negative caching),
// mirroring the signer's regex cache.
func (e *Engine) parseHostKeyCached(line string) (ssh.PublicKey, error) {
	if v, ok := e.hostKeyCache.Load(line); ok {
		switch t := v.(type) {
		case ssh.PublicKey:
			return t, nil
		case error:
			return nil, t
		}
	}
	pk, err := ParseHostKey(line)
	if err != nil {
		e.hostKeyCache.Store(line, err)
		return nil, err
	}
	e.hostKeyCache.Store(line, pk)
	return pk, nil
}
