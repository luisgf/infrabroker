// Package signer abstracts certificate issuance. The broker submits an intent
// and receives a signed certificate, without constructing security constraints
// itself or holding the CA key.
//
//   - Local:  signs in-process (single-binary mode, or the core of the service).
//   - Remote: delegates to the external signing service via HTTP+mTLS.
//
// Policy (host → principal/source-address/TTL/forwarding + caller authorisation)
// lives here and is enforced by both Local and the remote service.
package signer

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/luisgf/ssh-broker/internal/ca"
)

// Role distinguishes the role of a hop in the chain.
const (
	RoleTarget  = "target"
	RoleBastion = "bastion"
)

// Purpose distinguishes the intended use of the connection.
const (
	PurposeOneshot = "oneshot"
	PurposeSession = "session"
)

// reValidUser accepts only safe Unix usernames (no flags or metacharacters).
var reValidUser = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,31}$`)

// Intent is what the broker requests to sign. It contains no security
// constraints — those are derived by the signer's policy.
type Intent struct {
	Caller       string // requester identity (mTLS CN in remote mode; "local" in local mode)
	Host         string // logical host name
	Role         string // RoleTarget | RoleBastion
	Purpose      string // PurposeOneshot | PurposeSession
	Command      string // only relevant for one-shot at the target (force-command)
	RequestedTTL time.Duration
	PublicKey    ssh.PublicKey // ephemeral public key from the broker

	// Elevation (NOPASSWD).
	Sudo     bool   // requests privilege elevation
	SudoUser string // target user for sudo; "" = root

	// PTY: requests permit-pty in the certificate.
	PTY bool

	// DryRun: if true, the signer resolves the policy and returns the decision
	// (DecisionInfo) WITHOUT issuing a usable certificate. Allows the model to
	// preview whether a command would be allowed / require approval before running.
	DryRun bool

	// Approved indicates that an operation requiring human approval has already
	// been approved. The signer honours this only when it comes from a trusted
	// forwarder (the control plane); a broker cannot self-approve. This makes
	// approval unavoidable: without approved, a command with require_approval
	// is not issued.
	Approved bool

	// OnBehalfOf is the CN of the broker on whose behalf a trusted forwarder
	// (the control plane) is acting. The signer uses it as the effective Caller
	// for RBAC ONLY if the real mTLS CN is in trusted_forwarders; otherwise the
	// request is rejected. Empty on direct broker→signer requests (the mTLS CN
	// is used).
	OnBehalfOf string

	// EndUser is the identity of the end user who originated the request (e.g.
	// the sub/preferred_username from an OIDC token in the HTTP frontend). Empty
	// when the request carries no user identity (local stdio or mTLS frontend).
	// Used for traceability (KeyID/audit); does not replace Caller (the broker's
	// identity toward the signer).
	EndUser string
	// EndUserGroups are the RBAC groups asserted for the end user. If non-nil,
	// per-user authorisation is active: the requested host must belong to at
	// least one of these groups. If nil, no per-user filter is applied (compat).
	EndUserGroups []string
}

// Issued is the result of signing.
type Issued struct {
	Certificate *ssh.Certificate
	Serial      uint64
	// ElevationPrefix is the exact prefix to prepend to each command in persistent
	// sessions (e.g. "sudo -n" or "sudo -n -u deploy"). Empty when there is no
	// elevation or the purpose is one-shot (the prefix is already in ForceCommand).
	ElevationPrefix string
	// Decision summarises the policy decision. In dry-run, Certificate is nil and
	// only Decision is populated. In normal issuance it is populated for
	// traceability/audit.
	Decision *DecisionInfo
}

// DecisionInfo summarises the policy decision for dry-run and audit, without
// exposing the key or the certificate. Also used as a transport type (the
// decision field of WireResponse).
type DecisionInfo struct {
	// Allowed indicates whether the command would be authorised (false on a
	// dry-run denial).
	Allowed bool `json:"allowed"`
	// Reason explains a denial (empty if Allowed).
	Reason string `json:"reason,omitempty"`
	// RequireApproval indicates that the command requires out-of-band human approval.
	RequireApproval bool `json:"require_approval,omitempty"`
	// MatchedRule is the command_policy rule that drove the decision.
	MatchedRule string `json:"matched_rule,omitempty"`
	// ForceCommand is the force-command that would be baked into the cert (includes sudo).
	ForceCommand string `json:"force_command,omitempty"`
	// TTLSeconds is the TTL the issued cert would carry.
	TTLSeconds int `json:"ttl_seconds,omitempty"`
	// Elevation is the elevation prefix that would apply (sessions).
	Elevation string `json:"elevation,omitempty"`
}

// Decision is the result of PolicyTable.Resolve: the certificate constraints
// plus policy decision metadata.
type Decision struct {
	Constraints     ca.Constraints
	ElevationPrefix string
	// RequireApproval is surfaced by the signer but ACTED UPON by the control
	// plane (the signer has no approval machinery; it remains stateless).
	RequireApproval bool
	// MatchedRule is the command_policy rule that matched (audit/dry-run).
	MatchedRule string
}

// Signer issues a certificate from an intent.
type Signer interface {
	SignIntent(context.Context, Intent) (*Issued, error)
}

// HostPolicy is the issuance policy for a host and the source of truth for
// connectivity data. The signer is the only place where a host is declared:
// the broker obtains addr/user/host_key/jump via /v1/hosts.
type HostPolicy struct {
	// Connectivity — exposed to the broker via /v1/hosts.
	Addr    string `json:"addr"`           // host:port
	User    string `json:"user"`           // remote SSH account
	HostKey string `json:"host_key"`       // authorized_keys line for the host key
	Jump    string `json:"jump,omitempty"` // logical name of the preceding bastion

	// Issuance policy — internal, never exposed to the broker.
	Principal      string        `json:"principal"`
	SourceAddress  string        `json:"source_address,omitempty"`
	MaxTTL         time.Duration `json:"-"`
	MaxTTLSeconds  int           `json:"max_ttl_seconds,omitempty"`
	AllowAsBastion bool          `json:"allow_as_bastion,omitempty"`
	// AllowedCallers restricts which CNs may request this host. Empty = any
	// authenticated caller.
	AllowedCallers []string `json:"allowed_callers,omitempty"`

	// Elevation (sudo NOPASSWD).
	// AllowSudo enables privilege elevation for this host.
	AllowSudo bool `json:"allow_sudo,omitempty"`
	// AllowedSudoUsers lists the permitted target users (e.g. ["root","deploy"]).
	// Empty = root only. "root" is always implied when AllowSudo=true.
	AllowedSudoUsers []string `json:"allowed_sudo_users,omitempty"`

	// AllowPTY authorises the permit-pty extension in certificates for this host.
	// If false, PTY requests are rejected.
	AllowPTY bool `json:"allow_pty,omitempty"`

	// Groups lists the RBAC groups this host belongs to. A caller restricted by
	// groups can only access hosts that share at least one of its allowed_groups.
	// Empty = host belongs to no group.
	Groups []string `json:"groups,omitempty"`

	// CommandPolicy restricts which commands may run on this host (AI-action
	// firewall). Empty/off = no command restriction. When rules are present,
	// sessions are disabled (the command is not verifiable at signing time).
	CommandPolicy CommandPolicy `json:"command_policy,omitempty"`
}

// PolicyTable maps host name → policy.
type PolicyTable map[string]HostPolicy

// Resolve derives certificate constraints from the intent, applying
// authorisation and TTL caps. Returns a Decision with constraints, the
// ElevationPrefix for persistent sessions (empty for one-shot, where the
// prefix goes in ForceCommand), and decision metadata (command policy).
func (p PolicyTable) Resolve(in Intent, defaultMaxTTL time.Duration) (Decision, error) {
	hp, ok := p[in.Host]
	if !ok {
		return Decision{}, fmt.Errorf("no policy for host: %q", in.Host)
	}
	if !callerAllowed(hp.AllowedCallers, in.Caller) {
		return Decision{}, fmt.Errorf("caller %q not authorised for %q", in.Caller, in.Host)
	}
	// Per-user RBAC: if the request carries end-user groups (OIDC HTTP frontend),
	// the host must belong to at least one of them. If EndUserGroups is nil the
	// filter is not applied (requests without user identity: stdio/mTLS).
	if in.EndUserGroups != nil && !groupsIntersect(hp.Groups, in.EndUserGroups) {
		return Decision{}, fmt.Errorf("user %q not authorised for %q (groups)", in.EndUser, in.Host)
	}
	if in.Role == RoleBastion && !hp.AllowAsBastion {
		return Decision{}, fmt.Errorf("host %q is not allowed as a bastion", in.Host)
	}

	elevationPrefix, err := resolveElevation(hp, in)
	if err != nil {
		return Decision{}, err
	}

	if in.PTY && !hp.AllowPTY {
		return Decision{}, fmt.Errorf("host %q does not allow PTY (allow_pty=false)", in.Host)
	}

	requireApproval, matchedRule, err := resolveCommandPolicy(hp, in)
	if err != nil {
		return Decision{}, err
	}

	maxTTL := hp.MaxTTL
	if maxTTL <= 0 {
		maxTTL = defaultMaxTTL
	}
	ttl := in.RequestedTTL
	if ttl <= 0 || ttl > maxTTL {
		ttl = maxTTL
	}

	c := buildConstraints(hp, in, elevationPrefix, ttl)

	// force-command only for one-shot at the target.
	if in.Purpose == PurposeOneshot && in.Role == RoleTarget {
		cmd := in.Command
		if elevationPrefix != "" {
			cmd = buildElevatedCommand(elevationPrefix, in.Command)
		}
		c.ForceCommand = cmd
		// In one-shot the prefix goes in ForceCommand; it is not returned as prefix.
		elevationPrefix = ""
	}

	return Decision{
		Constraints:     c,
		ElevationPrefix: elevationPrefix,
		RequireApproval: requireApproval,
		MatchedRule:     matchedRule,
	}, nil
}

// resolveCommandPolicy evaluates the AI-action firewall for an Intent. Returns
// whether human approval is required, which rule matched, and any configuration
// error.
func resolveCommandPolicy(hp HostPolicy, in Intent) (requireApproval bool, matchedRule string, err error) {
	if in.Role != RoleTarget || !hp.CommandPolicy.Restricts() {
		return false, "", nil
	}
	// Sessions are not verifiable at signing time; reject them when command policy
	// is configured.
	if in.Purpose == PurposeSession {
		return false, "", fmt.Errorf("host %q has command_policy: sessions are not allowed (command is not verifiable at signing time)", in.Host)
	}
	allowed, needsApproval, rule, cerr := hp.CommandPolicy.Decide(in.Command)
	if cerr != nil {
		return false, "", fmt.Errorf("command_policy for %q: %w", in.Host, cerr)
	}
	if !allowed {
		return false, "", fmt.Errorf("command not allowed on %q by command_policy (%s)", in.Host, rule)
	}
	return needsApproval, rule, nil
}

// buildConstraints assembles the ca.Constraints from the host policy, the
// intent, and the resolved values (elevation prefix and effective TTL).
// ForceCommand is not set here; Resolve adds it for one-shot targets.
func buildConstraints(hp HostPolicy, in Intent, elevationPrefix string, ttl time.Duration) ca.Constraints {
	keyIDParts := []string{
		fmt.Sprintf("agent=%s", in.Caller),
		fmt.Sprintf("host=%s", in.Host),
		fmt.Sprintf("role=%s", in.Role),
		fmt.Sprintf("t=%d", time.Now().Unix()),
	}
	if in.EndUser != "" {
		keyIDParts = append(keyIDParts, fmt.Sprintf("user=%s", in.EndUser))
	}
	if elevationPrefix != "" {
		keyIDParts = append(keyIDParts, fmt.Sprintf("elev=%s", elevationPrefix))
	}
	if in.PTY {
		keyIDParts = append(keyIDParts, "pty=1")
	}
	return ca.Constraints{
		Principal:           hp.Principal,
		TTL:                 ttl,
		SourceAddress:       hp.SourceAddress,
		AllowPortForwarding: in.Role == RoleBastion,
		AllowPTY:            in.PTY,
		KeyID:               strings.Join(keyIDParts, " "),
	}
}

// resolveElevation validates the elevation request against the host policy and
// returns the sudo prefix to use (e.g. "sudo -n" or "sudo -n -u deploy").
// Returns "" when no elevation is needed.
func resolveElevation(hp HostPolicy, in Intent) (string, error) {
	if !in.Sudo {
		return "", nil
	}
	// Elevation only applies to the target hop; bastions do not need it.
	if in.Role != RoleTarget {
		return "", nil
	}
	if !hp.AllowSudo {
		return "", fmt.Errorf("host %q does not allow elevation (allow_sudo=false)", in.Host)
	}

	sudoUser := in.SudoUser
	if sudoUser == "" {
		sudoUser = "root"
	}

	// Validate the target username against a safe regex.
	if !reValidUser.MatchString(sudoUser) {
		return "", fmt.Errorf("sudo_user %q contains disallowed characters", sudoUser)
	}

	// Validate against the policy allowlist.
	if !sudoUserAllowed(hp.AllowedSudoUsers, sudoUser) {
		return "", fmt.Errorf("sudo_user %q is not in the allowed list for %q", sudoUser, in.Host)
	}

	if sudoUser == "root" {
		return "sudo -n", nil
	}
	return fmt.Sprintf("sudo -n -u %s", sudoUser), nil
}

// buildElevatedCommand wraps command with prefix safely:
// prefix + " -- /bin/sh -c " + shellQuote(command).
// The double dash separates sudo options from the argument, and /bin/sh -c
// allows pipelines, redirections, and variables (same as without elevation).
func buildElevatedCommand(prefix, command string) string {
	return fmt.Sprintf("%s -- /bin/sh -c %s", prefix, shellQuote(command))
}

// shellQuote wraps s in single quotes, escaping any internal single quotes
// (replacing ' with '\'').
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// sudoUserAllowed reports whether user is in the allowed list. Empty → root only.
func sudoUserAllowed(allowed []string, user string) bool {
	if len(allowed) == 0 {
		return user == "root"
	}
	for _, a := range allowed {
		if a == user {
			return true
		}
	}
	return false
}

// groupsIntersect reports whether hostGroups and userGroups share at least one
// group. A host with no groups is not accessible via per-user RBAC.
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

func callerAllowed(allowed []string, caller string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, a := range allowed {
		if a == caller {
			return true
		}
	}
	return false
}

// CallerPolicy defines the groups accessible to a caller identified by the CN
// of its mTLS certificate. Absent from CallerTable = no group restriction
// (backward compatible). Present with empty AllowedGroups = total denial by
// groups.
type CallerPolicy struct {
	AllowedGroups []string `json:"allowed_groups"`
}

// CallerTable maps mTLS cert CN → CallerPolicy.
type CallerTable map[string]CallerPolicy

// HostSetForCaller computes the set of hosts accessible to a caller based on
// group membership. A host is accessible if any of its Groups intersects with
// the caller's AllowedGroups. Returns (set, true) when the caller has a group
// restriction, (nil, false) when the caller is not in CallerTable (unrestricted).
func HostSetForCaller(callerCN string, policy PolicyTable, callers CallerTable) (map[string]struct{}, bool) {
	cp, ok := callers[callerCN]
	if !ok {
		return nil, false
	}
	allowed := make(map[string]struct{}, len(cp.AllowedGroups))
	for _, g := range cp.AllowedGroups {
		allowed[g] = struct{}{}
	}
	set := make(map[string]struct{})
	for hostName, hp := range policy {
		for _, g := range hp.Groups {
			if _, ok := allowed[g]; ok {
				set[hostName] = struct{}{}
				break
			}
		}
	}
	return set, true
}

// Local signs in-process: resolves policy and constructs+signs with the CA key.
// It supports a single default CA key as well as per-group CA overrides: the
// first group in a host's Groups list that has an entry in groupCAs wins;
// otherwise defaultCA is used.
type Local struct {
	defaultCA  ssh.Signer
	groupCAs   map[string]ssh.Signer // group → CA; nil = no per-group CAs
	policy     PolicyTable
	defaultTTL time.Duration
}

// NewLocal creates a local signer with a single CA key (backward compatible).
func NewLocal(caKey ssh.Signer, policy PolicyTable, defaultTTL time.Duration) *Local {
	return &Local{defaultCA: caKey, policy: policy, defaultTTL: defaultTTL}
}

// NewLocalWithGroupCAs creates a local signer with a default CA and optional
// per-group CA overrides. groupCAs maps group names to their CA signers; nil
// or empty means no per-group CAs (all hosts use defaultCA).
func NewLocalWithGroupCAs(defaultCA ssh.Signer, groupCAs map[string]ssh.Signer, policy PolicyTable, defaultTTL time.Duration) *Local {
	return &Local{defaultCA: defaultCA, groupCAs: groupCAs, policy: policy, defaultTTL: defaultTTL}
}

// caKeyFor returns the CA to use for the given host policy. The first group in
// hp.Groups that has an entry in groupCAs wins. Falls back to defaultCA when no
// group matches or groupCAs is nil.
func (l *Local) caKeyFor(hp HostPolicy) ssh.Signer {
	for _, g := range hp.Groups {
		if ca, ok := l.groupCAs[g]; ok {
			return ca
		}
	}
	return l.defaultCA
}

// SignIntent implements Signer.
//
// In dry-run no certificate is issued: the policy is resolved and the decision
// is returned. A policy denial in dry-run is a result (Allowed=false), not an
// error; only configuration failures (invalid regex) return an error.
func (l *Local) SignIntent(ctx context.Context, in Intent) (*Issued, error) {
	d, err := l.policy.Resolve(in, l.defaultTTL)
	if in.DryRun {
		if err != nil {
			return &Issued{Decision: &DecisionInfo{Allowed: false, Reason: err.Error()}}, nil
		}
		return &Issued{Decision: decisionInfo(d, true)}, nil
	}
	if err != nil {
		return nil, err
	}
	// Approval gate: if the policy requires human approval and it has not been
	// granted, no certificate is issued. The decision is returned (cert nil) so
	// the control plane can orchestrate approval. Approval is unavoidable: a
	// direct broker cannot set Approved (only trusted forwarders can).
	if d.RequireApproval && !in.Approved {
		return &Issued{Decision: decisionInfo(d, true)}, nil
	}
	// Select the CA for this host: first matching group CA wins, else default.
	// l.policy[in.Host] is safe here: Resolve already confirmed the host exists.
	caKey := l.caKeyFor(l.policy[in.Host])
	cert, serial, err := ca.BuildAndSign(ctx, caKey, in.PublicKey, d.Constraints)
	if err != nil {
		return nil, err
	}
	return &Issued{Certificate: cert, Serial: serial, ElevationPrefix: d.ElevationPrefix, Decision: decisionInfo(d, true)}, nil
}

// decisionInfo projects a Decision into a DecisionInfo (transport/audit).
func decisionInfo(d Decision, allowed bool) *DecisionInfo {
	return &DecisionInfo{
		Allowed:         allowed,
		RequireApproval: d.RequireApproval,
		MatchedRule:     d.MatchedRule,
		ForceCommand:    d.Constraints.ForceCommand,
		TTLSeconds:      int(d.Constraints.TTL / time.Second),
		Elevation:       d.ElevationPrefix,
	}
}
