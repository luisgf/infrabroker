// Package broker contains the shared core: configuration and the engine that,
// per request, signs an ephemeral SSH certificate, executes the command, and
// audits the result. Used by both the HTTP/mTLS frontend (cmd/broker) and the
// MCP server (cmd/mcp-broker), so security logic lives in a single place.
package broker

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/luisgf/infrabroker/internal/audit"
	"github.com/luisgf/infrabroker/internal/auth"
	"github.com/luisgf/infrabroker/internal/ca"
	"github.com/luisgf/infrabroker/internal/confcheck"
	"github.com/luisgf/infrabroker/internal/monitor"
	"github.com/luisgf/infrabroker/internal/redact"
	"github.com/luisgf/infrabroker/internal/signer"
	sshrun "github.com/luisgf/infrabroker/internal/ssh"
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
	// ErrAuditUnavailable: the audit log could not be written and the broker runs
	// in the default fail-closed mode (audit_fail_mode=closed), so the action's
	// result is withheld rather than returned without a durable record. Maps to a
	// 500 at the frontend.
	ErrAuditUnavailable = errors.New("audit unavailable")
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

	// AuditFailMode governs what happens when the audit log cannot be written.
	// "closed" (default): the audited action (ssh_execute, session open/exec, file
	// transfer, k8s action) is denied with "audit unavailable" — the result is
	// withheld. "open": log the error, count the metric, and return the result
	// anyway (the pre-2.0 behaviour). Empty = "closed".
	AuditFailMode string `json:"audit_fail_mode,omitempty"`

	// SourceAddress: broker egress IP/CIDR, used in local mode.
	SourceAddress string `json:"source_address"`

	// MaxTTLSeconds caps the maximum requestable TTL.
	MaxTTLSeconds int `json:"max_ttl_seconds"`

	// HostsRefreshSeconds: host-list reload interval from the signer. Remote
	// mode only. Default: 300 (5 minutes).
	HostsRefreshSeconds int `json:"hosts_refresh_seconds"`

	// RevocationPollSeconds: how often the broker polls the signer's freeze set
	// and force-closes matching live sessions (kill switch, #117). Remote mode
	// only; this is the kill latency for an established session. Default: 10.
	RevocationPollSeconds int `json:"revocation_poll_seconds"`

	// ApprovalViaElicitation lets the stdio mcp-broker ask the human to approve a
	// require_approval command IN THE MCP CLIENT (#118) instead of failing. It
	// waives four-eyes (the requesting and approving human are the same), so the
	// signer must also opt the broker's CN into self-approval (caller
	// self_approve). Off by default; only meaningful for the interactive stdio
	// frontend.
	ApprovalViaElicitation bool `json:"approval_via_elicitation,omitempty"`

	// Persistent session idle-close and maximum lifetime.
	SessionIdleSeconds int `json:"session_idle_seconds"` // default 300
	SessionMaxSeconds  int `json:"session_max_seconds"`  // default 1800

	// SessionRecordingDir: directory for session recordings in ASCIIcast v2
	// format (.cast files). One file per session: <session_id>.cast.
	// Empty = recording disabled.
	SessionRecordingDir string `json:"session_recording_dir,omitempty"`

	// SessionRecordingStrict makes recording failures fatal to the session
	// instead of best-effort: if the .cast file cannot be opened, the session
	// open fails, and if a recording event write fails the in-flight command
	// aborts and the session is broken. Use when recording is a compliance
	// control that must not fail open. Off by default (recording stays
	// best-effort). Failures are always counted by recording_write_errors_total.
	SessionRecordingStrict bool `json:"session_recording_strict,omitempty"`

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

	// Approved marks a require_approval command as approved (#118). The signer
	// honours it only from a trusted forwarder (control plane) or a caller the
	// operator opted into self-approval; the mcp-broker sets it after an
	// in-conversation elicitation the human accepted.
	Approved bool

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

// clusterFetcher retrieves the Kubernetes cluster list from the signer.
// Implemented by *signer.Remote; nil in local mode (no k8s target).
type clusterFetcher interface {
	FetchClusters(context.Context, string) (map[string]signer.ClusterInfo, error)
}

// revocationFetcher retrieves the freeze set from the signer (kill switch, #117).
// Implemented by *signer.Remote; nil in local mode (no signer to poll).
type revocationFetcher interface {
	FetchRevocations(context.Context) ([]signer.FrozenEntry, error)
}

// Engine executes commands by signing ephemeral credentials and auditing.
type Engine struct {
	cfg      *Config
	sgn      signer.Signer
	fetcher  hostFetcher // nil in local mode
	auditLog *audit.Log
	// auditFailClosed denies the audited action (withholds its result) when the
	// audit log cannot be written (audit_fail_mode=closed, the default).
	auditFailClosed bool
	redactor        *redact.Redactor // nil = redaction disabled
	maxTTL          time.Duration
	sessions        *sessionManager

	// clusterFetcher fetches the k8s cluster list; nil when no k8s target is
	// configured (local mode, or a signer with no clusters).
	clusterFetcher clusterFetcher

	// revFetcher polls the signer's freeze set (#117); nil in local mode. When
	// set, a background poll force-closes sessions matching a frozen subject.
	// ownIdentity is the broker's signer-facing identity (client-cert CN, or
	// "local"), used to match a frozen caller CN against this broker's sessions.
	revFetcher  revocationFetcher
	ownIdentity string

	// revPollLastSuccess is the unix time of the last successful revocation-poll
	// fetch, exposed as the broker_revocation_poll_last_success_timestamp_seconds
	// gauge so operators can alert when the poll goes stale — a silently-dead or
	// persistently-erroring poll stops enforcing the kill switch (#217).
	revPollLastSuccess atomic.Int64

	mu    sync.RWMutex
	hosts map[string]signer.HostInfo // cache refreshed periodically (remote mode)
	// lastHostRefresh is when hosts was last loaded from the signer (initial load,
	// background poller, or a per-connection refetch). refreshHostsForNewConnection
	// uses it to coalesce the hot-path refetch: within hostRefreshCoalesce of a
	// load the poller has already kept the table fresh, so Execute makes only the
	// authoritative /v1/sign call, not a redundant /v1/hosts round-trip too (#208).
	// Guarded by mu.
	lastHostRefresh time.Time
	// clusters is the k8s cluster connectivity cache, refreshed alongside hosts
	// (remote mode). Empty when no k8s target is configured.
	clusters map[string]signer.ClusterInfo
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

// hostCommandPolicySet reports whether a per-host command_policy block was
// actually written (any field set), as opposed to the zero value produced when
// the key is absent.
func hostCommandPolicySet(cp signer.CommandPolicy) bool {
	return cp.Mode != "" || cp.Enforcement != "" || len(cp.Allow) > 0 ||
		len(cp.Deny) > 0 || len(cp.RequireApproval) > 0 || cp.ShellParse != nil
}

// ignoredRemoteFieldsWarning returns a single aggregated warning naming the
// local-mode fields present in a remote-mode config (Signer block set) that the
// broker silently ignores — the host inventory and all policy come from the
// signer. It returns "" for local mode (Signer nil) or a clean remote config
// (nothing ignored). Only fields an operator could mistake for an active local
// control are reported (CA custody, command policies, per-host policy); the
// bare host coordinates that remote mode also ignores are not, to keep a pure
// remote config silent.
func ignoredRemoteFieldsWarning(cfg *Config) string {
	if cfg.Signer == nil {
		return ""
	}
	var top []string
	if cfg.CAKey != "" {
		top = append(top, "ca_key")
	}
	if len(cfg.CAKeys) > 0 {
		top = append(top, "ca_keys")
	}
	if len(cfg.CommandPolicies) > 0 {
		top = append(top, "command_policies")
	}
	if len(cfg.GroupCommandPolicies) > 0 {
		top = append(top, "group_command_policies")
	}
	if cfg.SourceAddress != "" {
		top = append(top, "source_address")
	}

	names := make([]string, 0, len(cfg.Hosts))
	for n := range cfg.Hosts {
		names = append(names, n)
	}
	sort.Strings(names)
	var hostNotes []string
	for _, name := range names {
		h := cfg.Hosts[name]
		var f []string
		if h.Principal != "" {
			f = append(f, "principal")
		}
		if h.SourceAddress != "" {
			f = append(f, "source_address")
		}
		if hostCommandPolicySet(h.CommandPolicy) {
			f = append(f, "command_policy")
		}
		if h.AllowSudo {
			f = append(f, "allow_sudo")
		}
		if len(h.AllowedSudoUsers) > 0 {
			f = append(f, "allowed_sudo_users")
		}
		if h.AllowPTY {
			f = append(f, "allow_pty")
		}
		if h.AllowFileTransfer {
			f = append(f, "allow_file_transfer")
		}
		if h.AllowAsBastion {
			f = append(f, "allow_as_bastion")
		}
		if len(f) > 0 {
			hostNotes = append(hostNotes, fmt.Sprintf("%s: %s", name, strings.Join(f, ", ")))
		}
	}

	if len(top) == 0 && len(hostNotes) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("remote mode (signer block set): ignoring local-mode config —")
	if len(top) > 0 {
		fmt.Fprintf(&b, " %s", strings.Join(top, ", "))
	}
	if len(hostNotes) > 0 {
		if len(top) > 0 {
			b.WriteString(";")
		}
		fmt.Fprintf(&b, " policy fields on %d host(s) (%s)", len(hostNotes), strings.Join(hostNotes, "; "))
	}
	b.WriteString(". Host inventory and policy come from the signer.")
	return b.String()
}

// NewEngine initialises the signer (local or remote) and the audit log.
func NewEngine(cfg *Config) (*Engine, error) {
	// A remote-mode config (Signer block set) that also carries local-mode fields
	// silently ignores them: the host inventory and all policy come from the
	// signer. Warn once at startup so an operator can never believe a local CA
	// key or command policy is active when it is not (the #82 error class).
	if w := ignoredRemoteFieldsWarning(cfg); w != "" {
		log.Printf("warning: %s", w)
	}

	maxTTL := time.Duration(cfg.MaxTTLSeconds) * time.Second
	if maxTTL <= 0 {
		maxTTL = 5 * time.Minute
	}

	sgn, fetcher, err := buildSigner(context.Background(), cfg, maxTTL)
	if err != nil {
		return nil, err
	}

	// The broker's signer-facing identity — its client-cert CN in remote mode,
	// or "local" — is how a frozen caller CN (#117) is matched against this
	// broker's sessions.
	ownIdentity := localCaller
	if cfg.Signer != nil {
		cn, cerr := clientCertCN(cfg.Signer.ClientCert)
		if cerr != nil {
			return nil, fmt.Errorf("reading broker identity from client cert: %w", cerr)
		}
		ownIdentity = cn
	}

	al, redactor, err := openAuditLog(cfg)
	if err != nil {
		return nil, err
	}

	auditFailClosed, err := audit.FailClosed(cfg.AuditFailMode)
	if err != nil {
		al.Close()
		return nil, err
	}

	idle := time.Duration(cfg.SessionIdleSeconds) * time.Second
	if idle <= 0 {
		idle = 5 * time.Minute
	}
	maxLife := time.Duration(cfg.SessionMaxSeconds) * time.Second
	if maxLife <= 0 {
		maxLife = 30 * time.Minute
	}

	e := &Engine{cfg: cfg, sgn: sgn, fetcher: fetcher, auditLog: al, auditFailClosed: auditFailClosed, redactor: redactor, maxTTL: maxTTL, ownIdentity: ownIdentity}
	e.sessions = newSessionManager(idle, maxLife, func(s *liveSession) {
		e.auditE(audit.Entry{Caller: s.caller, Host: s.host, Serial: s.serial,
			SessionID: s.id, Outcome: "session_close", Err: "reaped (idle/lifetime)"})
	})
	// Scrape-time gauge over the live session map. SetGaugeFunc replaces any
	// previous registration, so a rebuilt engine (tests, restarts of the
	// embedding frontend) simply rebinds the gauge to itself.
	monitor.SetGaugeFunc("broker_sessions_active",
		"Persistent SSH sessions currently open.", e.sessions.count)

	// Remote mode: initial host/cluster load, then the refresh + kill-switch polls.
	if err := e.initRemoteMode(fetcher); err != nil {
		return nil, err
	}

	return e, nil
}

// initRemoteMode performs remote-mode startup: the initial host (and optional
// cluster) load from the signer, then the background host-refresh and kill-switch
// revocation-poll goroutines. On an initial-load failure it closes the audit log
// and returns the error. A no-op in local mode (fetcher nil).
func (e *Engine) initRemoteMode(fetcher hostFetcher) error {
	if fetcher == nil {
		return nil
	}
	h, err := fetcher.FetchHosts(context.Background(), "")
	if err != nil {
		e.auditLog.Close()
		return fmt.Errorf("initial host load from signer: %w", err)
	}
	e.hosts = h
	e.lastHostRefresh = time.Now()
	log.Printf("hosts loaded from signer: %d entries", len(h))

	// Optional k8s target: load the cluster list too. A signer with no clusters
	// returns an empty map (the endpoint always exists), so a fetch error is a
	// real failure, not a missing feature.
	if cf, ok := fetcher.(clusterFetcher); ok {
		cl, err := cf.FetchClusters(context.Background(), "")
		if err != nil {
			e.auditLog.Close()
			return fmt.Errorf("initial cluster load from signer: %w", err)
		}
		e.clusterFetcher = cf
		e.clusters = cl
		if len(cl) > 0 {
			log.Printf("k8s clusters loaded from signer: %d entries", len(cl))
		}
	}

	refresh := time.Duration(e.cfg.HostsRefreshSeconds) * time.Second
	if refresh <= 0 {
		refresh = 5 * time.Minute
	}
	e.startHostRefresh(refresh)

	// Kill switch (#117): poll the freeze set and force-close matching sessions.
	// Shares refreshStop, so Close stops it too.
	if rf, ok := fetcher.(revocationFetcher); ok {
		e.revFetcher = rf
		revPoll := time.Duration(e.cfg.RevocationPollSeconds) * time.Second
		if revPoll <= 0 {
			revPoll = 10 * time.Second
		}
		e.startRevocationPoll(revPoll)
	}
	return nil
}

// openAuditLog opens the audit log with the Ed25519 seed key and installs the
// optional secret redactor. An invalid redact pattern is a startup error
// (fail-closed), not a silently smaller rule set.
func openAuditLog(cfg *Config) (*audit.Log, *redact.Redactor, error) {
	seed, err := os.ReadFile(cfg.AuditKey)
	if err != nil {
		return nil, nil, fmt.Errorf("reading audit key: %w", err)
	}
	if len(seed) < ed25519.SeedSize {
		return nil, nil, fmt.Errorf("audit key too short")
	}
	al, err := audit.Open(cfg.AuditLog, ed25519.NewKeyFromSeed(seed[:ed25519.SeedSize]))
	if err != nil {
		return nil, nil, err
	}
	var redactor *redact.Redactor
	if cfg.Redact != nil {
		redactor, err = redact.New(cfg.Redact)
		if err != nil {
			return nil, nil, fmt.Errorf("compiling redact config: %w", err)
		}
		if redactor != nil {
			al.SetRedactor(redactor)
		}
	}
	return al, redactor, nil
}

// clientCertCN reads the CommonName from a PEM-encoded client certificate — the
// broker's signer-facing identity, used to match a frozen caller CN (#117).
func clientCertCN(certFile string) (string, error) {
	pemBytes, err := os.ReadFile(certFile)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return "", fmt.Errorf("no PEM certificate block in %s", certFile)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parsing %s: %w", certFile, err)
	}
	return cert.Subject.CommonName, nil
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
				e.lastHostRefresh = time.Now()
				e.mu.Unlock()
				e.pruneHostKeyCache()
				log.Printf("hosts reloaded from signer: %d entries", len(h))
				if e.clusterFetcher != nil {
					cl, err := e.clusterFetcher.FetchClusters(context.Background(), "")
					if err != nil {
						log.Printf("warning: cluster refresh failed: %v (keeping previous cache)", err)
						continue
					}
					e.mu.Lock()
					e.clusters = cl
					e.mu.Unlock()
				}
			}
		}
	}()
}

// startRevocationPoll starts the goroutine that polls the signer's freeze set
// (#117) and force-closes matching live sessions. It shares e.refreshStop with
// the host-refresh goroutine, so Close stops both.
func (e *Engine) startRevocationPoll(interval time.Duration) {
	// Seed the freshness gauge to "alive as of startup", then expose it: operators
	// alert when now minus this timestamp exceeds a few poll intervals, which
	// catches a stopped or persistently-erroring poll that would otherwise stop
	// enforcing the kill switch with no signal on /metrics (#217). SetGaugeFunc
	// replaces any prior registration, so a rebuilt engine rebinds to itself.
	e.revPollLastSuccess.Store(time.Now().Unix())
	monitor.SetGaugeFunc("broker_revocation_poll_last_success_timestamp_seconds",
		"Unix time of the last successful broker kill-switch revocation-poll fetch.",
		func() float64 { return float64(e.revPollLastSuccess.Load()) })
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-e.refreshStop:
				return
			case <-t.C:
				e.pollRevocationsOnce()
			}
		}
	}()
}

// pollRevocationsOnce runs one revocation-poll cycle: fetch the freeze set and,
// on success, advance the freshness timestamp and force-close matching sessions.
// A fetch error increments broker_revocation_poll_errors_total (and leaves the
// freshness gauge to go stale) so a failing kill-switch poll is visible on
// /metrics, not only in the log (#217).
func (e *Engine) pollRevocationsOnce() {
	frozen, err := e.revFetcher.FetchRevocations(context.Background())
	if err != nil {
		revocationPollErrors.Inc()
		log.Printf("warning: revocation poll failed: %v (retrying next tick)", err)
		return
	}
	e.revPollLastSuccess.Store(time.Now().Unix())
	e.enforceRevocations(frozen)
}

// enforceRevocations force-closes every live session that matches a frozen
// subject and audits each kill as session_killed. Idempotent: once a session is
// killed it is gone, so subsequent polls with the same freeze set kill nothing.
func (e *Engine) enforceRevocations(frozen []signer.FrozenEntry) {
	pred := revocationPredicate(frozen, e.ownIdentity)
	if pred == nil {
		return
	}
	for _, s := range e.sessions.killMatching(pred) {
		e.auditE(audit.Entry{
			Caller: s.caller, Host: s.host, Serial: s.serial, SessionID: s.id,
			Outcome: "session_killed", Err: "frozen (kill switch)",
		})
	}
}

// revocationPredicate builds the "should this session be killed?" test from the
// freeze set. Mapping to liveSession fields: a frozen end_user matches
// liveSession.caller (the broker sends the end user as the signer's end_user);
// session_id and serial match directly; a frozen caller CN matches THIS broker's
// identity, in which case every one of its sessions is killed. Returns nil when
// nothing in the set could match a session, so the caller can skip the sweep.
func revocationPredicate(frozen []signer.FrozenEntry, ownIdentity string) func(*liveSession) bool {
	endUsers := map[string]bool{}
	sessionIDs := map[string]bool{}
	serials := map[string]bool{}
	brokerFrozen := false
	for _, f := range frozen {
		switch f.Kind {
		case signer.FreezeCaller:
			if f.Value == ownIdentity {
				brokerFrozen = true
			}
		case signer.FreezeEndUser:
			endUsers[f.Value] = true
		case signer.FreezeSessionID:
			sessionIDs[f.Value] = true
		case signer.FreezeSerial:
			serials[f.Value] = true
		}
	}
	if !brokerFrozen && len(endUsers) == 0 && len(sessionIDs) == 0 && len(serials) == 0 {
		return nil
	}
	return func(s *liveSession) bool {
		return brokerFrozen ||
			endUsers[s.caller] ||
			sessionIDs[s.id] ||
			serials[strconv.FormatUint(s.serial, 10)]
	}
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
	// Local mode: validate the config at load, mirroring cmd/signer's buildState,
	// so a single-binary misconfiguration fails at startup rather than at the first
	// sign request. CompileHostPolicies (below) already rejects dangling jumps,
	// unknown groups and per-host max_ttl_seconds over the cap; the global
	// max_ttl_seconds cap is the one buildState check the broker was missing — the
	// in-process CA hard-rejects any TTL over 15m (ca.BuildAndSign), so a higher
	// value would make every local issuance fail at request time.
	if cfg.MaxTTLSeconds > 900 {
		return nil, nil, fmt.Errorf("max_ttl_seconds %d exceeds the 900s (15m) certificate cap (local mode)", cfg.MaxTTLSeconds)
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
	e.lastHostRefresh = time.Now()
	e.mu.Unlock()
	e.pruneHostKeyCache()
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

// hostRefreshCoalesce bounds how stale the cached host view may be before a new
// connection forces a synchronous refetch. The 5-minute background poller keeps
// the table fresh and /v1/sign is the authoritative gate, so a per-request
// refetch only needs to catch a very recent host change — coalescing it removes
// the redundant second signer round-trip on the hot path (#208).
const hostRefreshCoalesce = 3 * time.Second

// refreshHostsForNewConnection refreshes the remote host view before opening a
// connection, coalescing so a burst of one-shot Execute/OpenSession calls does
// not each pay a full /v1/hosts round-trip on top of /v1/sign. It refetches only
// when the cache has not been refreshed within hostRefreshCoalesce; the
// background poller and the authoritative /v1/sign gate cover the rest. A no-op
// in local mode. Session-exec preflight keeps using refreshHostsNow, which is
// never coalesced, so a host-connectivity change is still caught promptly.
func (e *Engine) refreshHostsForNewConnection(ctx context.Context) error {
	if e.fetcher == nil {
		return nil
	}
	e.mu.RLock()
	fresh := !e.lastHostRefresh.IsZero() && time.Since(e.lastHostRefresh) < hostRefreshCoalesce
	e.mu.RUnlock()
	if fresh {
		return nil
	}
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
			if c.Groups != nil && !signer.GroupsIntersect(h.Groups, c.Groups) {
				continue
			}
			infos = append(infos, ServerInfo{Name: name, AllowSudo: h.AllowSudo, AllowPTY: h.AllowPTY, AllowFileTransfer: h.AllowFileTransfer, Jump: h.Jump})
		}
		e.mu.RUnlock()
	} else {
		infos = make([]ServerInfo, 0, len(e.cfg.Hosts))
		for name, hc := range e.cfg.Hosts {
			if c.Groups != nil && !signer.GroupsIntersect(hc.Groups, c.Groups) {
				continue
			}
			infos = append(infos, ServerInfo{Name: name, AllowSudo: hc.AllowSudo, AllowPTY: hc.AllowPTY, AllowFileTransfer: hc.AllowFileTransfer, Jump: hc.Jump})
		}
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].Name < infos[j].Name })
	return infos
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
	// Fail-closed gate: the command already ran, but withhold its output if the
	// "executed" record cannot be persisted — the agent gets ErrAuditUnavailable
	// instead of untraceable output (the remote side effect is the documented
	// residual of any post-execution audit).
	if err := e.auditE(audit.Entry{
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
	}); err != nil {
		return nil, err
	}
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
			in.Approved = opts.Approved
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
// the physical connectivity signature, the policy decision issued by the
// signer for the target hop (sessions), and the target certificate's expiry
// (NotAfter), so a retained session can be capped at the life of the very
// credential that opened it.
func (e *Engine) buildHopsWithPrefix(ctx context.Context, c Caller, host string, ttl time.Duration, purpose, sessionMode string, opts ExecOptions) ([]sshrun.Hop, uint64, string, string, *signer.DecisionInfo, time.Time, error) {
	chain, err := e.resolveChain(host)
	if err != nil {
		return nil, 0, "", "", nil, time.Time{}, err
	}

	hops := make([]sshrun.Hop, 0, len(chain))
	var finalSerial uint64
	var finalNotAfter time.Time
	var elevPrefix string
	var targetDecision *signer.DecisionInfo
	var connectivitySig strings.Builder
	for i, name := range chain {
		hi, ok := e.hostInfo(name)
		if !ok {
			return nil, 0, "", "", nil, time.Time{}, fmt.Errorf("unknown host in chain: %q", name)
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
			return nil, 0, "", "", nil, time.Time{}, err
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
			in.Approved = opts.Approved
		}
		issued, err := e.sgn.SignIntent(ctx, in)
		if err != nil {
			return nil, 0, "", "", nil, time.Time{}, fmt.Errorf("signing cert for %q: %w", name, err)
		}
		if issued.Certificate == nil {
			return nil, 0, "", "", nil, time.Time{}, approvalError(name, issued.Decision)
		}
		hostKey, err := e.parseHostKeyCached(hi.HostKey)
		if err != nil {
			return nil, 0, "", "", nil, time.Time{}, fmt.Errorf("host key for %q: %w", name, err)
		}
		hops = append(hops, sshrun.Hop{
			Addr: hi.Addr, User: hi.User, HostKey: hostKey,
			PrivateKey: priv, Certificate: issued.Certificate,
		})
		if isTarget {
			finalSerial = issued.Serial
			// ValidBefore is the authoritative expiry the signer clamped to
			// (<= max_ttl), not the broker's requested TTL. The signer always
			// sets a bounded TTL, so this is a finite time.
			finalNotAfter = time.Unix(int64(issued.Certificate.ValidBefore), 0)
			elevPrefix = issued.ElevationPrefix
			targetDecision = issued.Decision
		}
	}
	return hops, finalSerial, elevPrefix, connectivitySig.String(), targetDecision, finalNotAfter, nil
}

// ApprovalRequiredError signals that a certificate was withheld because the
// command requires human approval (#118). The mcp-broker inspects it (errors.As)
// to offer in-conversation elicitation approval; every other frontend surfaces
// it as an ordinary denial.
type ApprovalRequiredError struct {
	Host string
	Rule string
}

func (e *ApprovalRequiredError) Error() string {
	return fmt.Sprintf("command on %q requires human approval (%s); approve it in-chat (if enabled), via the control plane, or with broker-ctl", e.Host, e.Rule)
}

// approvalError builds the typed error returned when a cert is not issued
// because human approval is required.
func approvalError(host string, d *signer.DecisionInfo) error {
	rule := ""
	if d != nil {
		rule = d.MatchedRule
	}
	return &ApprovalRequiredError{Host: host, Rule: rule}
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

// revocationPollErrors counts failed signer freeze-set fetches by the broker's
// kill-switch poll (#117/#126). A stopped or persistently-erroring poll silently
// stops force-closing frozen sessions, so operators alert on this counter (and on
// the staleness of broker_revocation_poll_last_success_timestamp_seconds) rather
// than only on a log line (#217).
var revocationPollErrors = monitor.GetCounter("broker_revocation_poll_errors_total",
	"Broker kill-switch revocation-poll fetch failures.")

// auditE writes an audit entry. In the default fail-closed mode an Append
// failure returns ErrAuditUnavailable so an action-completion caller withholds
// the result — no durable record, no result handed back; in "open" mode it logs,
// counts the metric (via Append), and returns nil (the pre-2.0 behaviour).
// Best-effort callers (pre-execution denials, mid-session and cleanup records)
// ignore the returned error.
func (e *Engine) auditE(ent audit.Entry) error {
	eventsTotal.With(ent.Outcome).Inc()
	if hi, ok := e.hostInfo(ent.Host); ok {
		if ent.User == "" {
			ent.User = hi.User
		}
	}
	return e.appendAudit(ent)
}

// appendAudit writes ent and applies the fail-closed policy: in the default mode
// an Append failure records audit_blocked_total and returns ErrAuditUnavailable
// so an action-completion caller withholds the result; in "open" mode it logs
// and returns nil. auditE adds host-user enrichment + the outcome metric first;
// auditK8s counts its own metric and enriches from the cluster table, so it
// calls this directly.
func (e *Engine) appendAudit(ent audit.Entry) error {
	if err := e.auditLog.Append(ent); err != nil {
		if e.auditFailClosed {
			audit.RecordBlocked()
			log.Printf("audit unavailable, withholding result: %v", err)
			return ErrAuditUnavailable
		}
		log.Printf("warning: error writing audit log: %v", err)
	}
	return nil
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

// pruneHostKeyCache drops memoised host-key parses whose authorized_keys line is
// no longer present in any current host. hostKeyCache is content-addressed by the
// line, so without pruning a rotated host key leaves its old parse cached forever
// (slow unbounded growth with every rotation). Called after a remote host refresh,
// so e.hosts is the authoritative live set (#215).
func (e *Engine) pruneHostKeyCache() {
	live := make(map[string]struct{})
	e.mu.RLock()
	for _, hi := range e.hosts {
		if hi.HostKey != "" {
			live[hi.HostKey] = struct{}{}
		}
	}
	e.mu.RUnlock()
	e.hostKeyCache.Range(func(k, _ any) bool {
		if line, ok := k.(string); ok {
			if _, keep := live[line]; !keep {
				e.hostKeyCache.Delete(line)
			}
		}
		return true
	})
}
