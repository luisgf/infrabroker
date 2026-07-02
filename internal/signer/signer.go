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
	"slices"
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

// SessionMode distinguishes broker-managed session styles.
const (
	SessionModeExec  = "exec"
	SessionModeShell = "shell"
	SessionModePTY   = "pty"
)

// reValidUser accepts only safe Unix usernames (no flags or metacharacters).
var reValidUser = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,31}$`)

// Intent is what the broker requests to sign. It contains no security
// constraints — those are derived by the signer's policy.
type Intent struct {
	Caller string // requester identity (mTLS CN in remote mode; "local" in local mode)
	Host   string // logical host name (or cluster name when TargetType is k8s)

	// TargetType selects the target family: "" or "ssh" is an SSH host
	// (backward compatible — every pre-k8s client sends nothing); "k8s" is a
	// Kubernetes cluster, whose action travels in K8s and whose Command is the
	// action's canonical string form.
	TargetType string
	// K8s is the structured Kubernetes action (TargetType "k8s" only). Command
	// must equal K8s.Canonical(); the signer rejects any mismatch so the
	// audited/approved string is provably what runs.
	K8s *K8sAction

	Role         string // RoleTarget | RoleBastion
	Purpose      string // PurposeOneshot | PurposeSession
	SessionMode  string // for PurposeSession: exec | shell | pty
	Command      string // only relevant for one-shot at the target (force-command)
	RequestedTTL time.Duration
	PublicKey    ssh.PublicKey // ephemeral public key from the broker

	// Elevation (NOPASSWD).
	Sudo     bool   // requests privilege elevation
	SudoUser string // target user for sudo; "" = root

	// PTY: requests permit-pty in the certificate.
	PTY bool

	// FileTransfer marks the intent as a file transfer (ssh_put_file /
	// ssh_get_file): the host policy must have allow_file_transfer=true or the
	// request is rejected. The transfer command itself travels in Command.
	FileTransfer bool

	// DryRun: if true, the signer resolves the policy and returns the decision
	// (DecisionInfo) WITHOUT issuing a usable certificate. Allows the model to
	// preview whether a command would be allowed / require approval before running.
	DryRun bool

	// Preflight marks a dry-run that authorises an imminent execution, currently
	// broker-managed ssh_session_exec. The signer still issues no certificate;
	// control planes can use this signal to apply execution guardrails.
	Preflight bool

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

	// Approve-and-learn: when an approved command carries LearnTTLSeconds > 0, the
	// signer mints a TTL'd approval waiver for the approved command, elevation,
	// caller, and end-user scope. Like Approved, these are honoured ONLY from a
	// trusted forwarder (the control plane); a broker cannot self-learn.
	// LearnApprover / LearnApprovalID are audit metadata (the human approver CN and
	// the originating approval id).
	LearnTTLSeconds int
	LearnApprover   string
	LearnApprovalID string
}

// Issued is the result of signing.
type Issued struct {
	Certificate *ssh.Certificate
	Serial      uint64

	// K8sToken is the short-lived bound ServiceAccount token minted for a
	// Kubernetes intent — the k8s analogue of Certificate (exactly one of the
	// two is set on a successful issuance). K8sTokenExpiry is its expiry.
	K8sToken       string
	K8sTokenExpiry time.Time
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
	// Enforcement is the effective command_policy enforcement mode.
	Enforcement string `json:"enforcement,omitempty"`
	// Warning carries audit-mode command_policy observations.
	Warning string `json:"warning,omitempty"`
	// WouldDeny is true in audit mode when the command would have been denied.
	WouldDeny bool `json:"would_deny,omitempty"`
	// WouldRequireApproval is true in audit mode when approval would be required.
	WouldRequireApproval bool `json:"would_require_approval,omitempty"`
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
	// CommandPolicyEnforcement is "enforce" or "audit" for the effective policy.
	CommandPolicyEnforcement string
	// Warning carries audit-mode command_policy observations.
	Warning string
	// WouldDeny is true in audit mode when the command would have been denied.
	WouldDeny bool
	// WouldRequireApproval is true in audit mode when approval would be required.
	WouldRequireApproval bool
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

	// AllowFileTransfer authorises the file-transfer tools (ssh_put_file /
	// ssh_get_file) for this host. If false (the default — secure by default),
	// signing requests flagged file_transfer are rejected. The generated
	// transfer command is still subject to the host's command policy.
	AllowFileTransfer bool `json:"allow_file_transfer,omitempty"`

	// Groups lists the RBAC groups this host belongs to. A caller restricted by
	// groups can only access hosts that share at least one of its allowed_groups.
	// Empty = host belongs to no group.
	Groups []string `json:"groups,omitempty"`

	// CommandPolicy restricts which commands may run on this host (AI-action
	// firewall). Empty/off = no command restriction. Session commands are
	// preflighted against the current signer policy before each exec, so reloads
	// affect already-open sessions: target and bastion access, end-user groups,
	// sudo, sudo_user and PTY are revalidated; the broker also rejects
	// already-open sessions if the host's physical SSH route changed. mode=exec is
	// allowed, while shell/pty sessions are rejected when rules are present
	// because stateful commands are not independently verifiable.
	CommandPolicy CommandPolicy `json:"command_policy,omitempty"`

	// Policies is the host's effective command policy: its inline CommandPolicy
	// composed with the named policies of all its groups. Computed by
	// CompileHostPolicies at config load; never serialised. When nil (a table
	// built without compiling, e.g. in a unit test), evaluation falls back to the
	// inline CommandPolicy alone — see effectivePolicies.
	Policies PolicySet `json:"-"`
}

// PolicyTable maps host name → policy.
type PolicyTable map[string]HostPolicy

// Validate checks the policy table for configuration errors that would
// otherwise only surface at request time: invalid command-policy regexes,
// unknown command-policy modes, and dangling jump references. It is called at
// config load and on every reload, so an invalid signer.json keeps the previous
// good state instead of silently breaking a host on its next request.
func (p PolicyTable) Validate() error {
	_, err := CompileHostPolicies(p, nil, nil)
	return err
}

// CompileHostPolicies resolves each host's effective command PolicySet from its
// inline command_policy plus the named policies attached to its groups, and
// validates the whole configuration up front (so a bad regex or an unknown
// policy reference fails at load/reload, not at request time).
//
// library maps a policy name to a CommandPolicy. groupPolicies maps a group name
// to the policy names that apply to its hosts; the reserved group "_default"
// applies to every host (mirrors the ca_keys "_default"). The returned
// PolicyTable has each HostPolicy.Policies populated; the input is not mutated.
func CompileHostPolicies(hosts PolicyTable, library map[string]CommandPolicy, groupPolicies map[string][]string) (PolicyTable, error) {
	for name, cp := range library {
		if err := cp.Validate(); err != nil {
			return nil, fmt.Errorf("command_policies[%q]: %w", name, err)
		}
	}
	for group, names := range groupPolicies {
		for _, n := range names {
			if _, ok := library[n]; !ok {
				return nil, fmt.Errorf("group_command_policies[%q]: unknown policy %q (not in command_policies)", group, n)
			}
		}
	}

	out := make(PolicyTable, len(hosts))
	for name, hp := range hosts {
		if hp.Jump != "" {
			if _, ok := hosts[hp.Jump]; !ok {
				return nil, fmt.Errorf("host %q: jump target %q is not a defined host", name, hp.Jump)
			}
		}
		// The CA hard-rejects any certificate TTL over 15m (ca.BuildAndSign), so
		// a per-host max_ttl_seconds above that cap would make every issuance for
		// this host fail at request time. Catch it at load, like the other
		// invariants here, instead of surfacing a silent per-request denial.
		if hp.MaxTTLSeconds > 900 {
			return nil, fmt.Errorf("host %q: max_ttl_seconds %d exceeds the 900s (15m) certificate cap", name, hp.MaxTTLSeconds)
		}
		if err := hp.CommandPolicy.Validate(); err != nil {
			return nil, fmt.Errorf("host %q: %w", name, err)
		}
		hp.Policies = composePolicies(hp, library, groupPolicies)
		// A bastion certificate carries no force-command, so a host that is both a
		// bastion and command-policy-restricted would let a caller bypass the
		// firewall by requesting role=bastion. The two are mutually exclusive.
		if hp.AllowAsBastion && hp.Policies.Restricts() {
			return nil, fmt.Errorf("host %q: allow_as_bastion and command_policy are mutually exclusive (a bastion certificate carries no force-command and would bypass the command firewall)", name)
		}
		out[name] = hp
	}
	return out, nil
}

// composePolicies builds a host's effective PolicySet: the "_default" group's
// policies, then each of the host's groups' policies, then its own inline policy
// (when it restricts), deduplicated by policy name.
func composePolicies(hp HostPolicy, library map[string]CommandPolicy, groupPolicies map[string][]string) PolicySet {
	var set PolicySet
	seen := map[string]bool{}
	add := func(names []string) {
		for _, n := range names {
			if seen[n] {
				continue
			}
			if cp, ok := library[n]; ok {
				seen[n] = true
				set = append(set, cp)
			}
		}
	}
	add(groupPolicies["_default"])
	for _, g := range hp.Groups {
		add(groupPolicies[g])
	}
	if hp.CommandPolicy.Restricts() {
		set = append(set, hp.CommandPolicy)
	}
	return set
}

// effectivePolicies returns the host's composed PolicySet. It falls back to the
// inline CommandPolicy alone when Policies is nil — the case of a PolicyTable
// built without CompileHostPolicies (e.g. a unit test constructing a literal),
// so direct calls to Resolve keep enforcing the inline policy.
func (hp HostPolicy) effectivePolicies() PolicySet {
	if hp.Policies != nil {
		return hp.Policies
	}
	if hp.CommandPolicy.Restricts() {
		return PolicySet{hp.CommandPolicy}
	}
	return nil
}

// Resolve derives certificate constraints from the intent, applying
// authorisation and TTL caps. Returns a Decision with constraints, the
// ElevationPrefix for persistent sessions (empty for one-shot, where the
// prefix goes in ForceCommand), and decision metadata (command policy).
func (p PolicyTable) Resolve(in Intent, defaultMaxTTL time.Duration) (Decision, error) {
	return p.resolve(in, defaultMaxTTL, nil)
}

// resolve is Resolve with an optional runtime grant provider. grants is nil on
// every path except the signer's live decision (Local.SignIntent), so existing
// callers and tests keep the file-only behaviour.
func (p PolicyTable) resolve(in Intent, defaultMaxTTL time.Duration, grants GrantProvider) (Decision, error) {
	hp, ok := p[in.Host]
	if !ok {
		return Decision{}, fmt.Errorf("no policy for host: %q", in.Host)
	}
	if err := authorizeIntent(hp, in); err != nil {
		return Decision{}, err
	}

	elevationPrefix, err := resolveElevation(hp, in)
	if err != nil {
		return Decision{}, err
	}

	if in.PTY && !hp.AllowPTY {
		return Decision{}, fmt.Errorf("host %q does not allow PTY (allow_pty=false)", in.Host)
	}

	if in.FileTransfer && !hp.AllowFileTransfer {
		return Decision{}, fmt.Errorf("host %q does not allow file transfer (allow_file_transfer=false)", in.Host)
	}

	cp, err := resolveCommandPolicy(hp, in, grants)
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
		Constraints:              c,
		ElevationPrefix:          elevationPrefix,
		RequireApproval:          cp.RequireApproval,
		MatchedRule:              cp.MatchedRule,
		CommandPolicyEnforcement: cp.Enforcement,
		Warning:                  cp.Warning,
		WouldDeny:                cp.WouldDeny,
		WouldRequireApproval:     cp.WouldRequireApproval,
	}, nil
}

// authorizeIntent runs the authorisation and input-validation gates for an
// intent against a host policy, returning the first failing check (or nil when
// authorised). Kept separate from Resolve so the constraint-building path stays
// readable and within the function-length limit. All gates are default-deny.
func authorizeIntent(hp HostPolicy, in Intent) error {
	// Role and Purpose select which constraints apply: command policy is
	// evaluated only for RoleTarget, and the force-command is baked only for
	// PurposeOneshot at the target. Both values arrive from the wire, so an
	// unknown value would silently skip those gates and yield an unrestricted
	// certificate.
	if in.Role != RoleTarget && in.Role != RoleBastion {
		return fmt.Errorf("unknown role %q (must be %q or %q)", in.Role, RoleTarget, RoleBastion)
	}
	if in.Purpose != PurposeOneshot && in.Purpose != PurposeSession {
		return fmt.Errorf("unknown purpose %q (must be %q or %q)", in.Purpose, PurposeOneshot, PurposeSession)
	}
	// Identity fields flow verbatim into the cert KeyID, which sshd records in
	// its auth log, and the same fields form the signer audit record. Both the
	// KeyID and that record are a single line of space-separated key=value tokens
	// (agent=.. host=.. role=.. t=.. [user=..] [elev=..] [pty=1]). Reject:
	//   - control characters, so a compromised broker or trusted forwarder cannot
	//     forge or splice lines in the host's auth.log via end_user or the
	//     resolved Caller; and
	//   - whitespace (the token separator), so a value cannot splice a spurious
	//     token into that stream — e.g. end_user "alice elev=sudo:root" would
	//     otherwise forge an elevation attribute and a Caller "b host=db
	//     role=bastion" would forge host/role.
	// '=' is deliberately allowed: a bare '=' lands inside a single value
	// (user=alice=root parses as user="alice=root", not a new token), so it
	// cannot forge an attribute, and some IdPs emit base64 sub claims with '='
	// padding — rejecting it would lock out a legitimately authenticated user.
	// Role is enum-checked above, Host is looked up against the policy table, and
	// the elevation prefix / sudo user pass reValidUser, so Caller and EndUser are
	// the only free-form fields that reach the token stream.
	if HasUnsafeTokenChar(in.Caller) || HasUnsafeTokenChar(in.EndUser) {
		return fmt.Errorf("caller or end_user contains disallowed characters (control or whitespace)")
	}
	// A newline in a one-shot command smuggles extra command lines past regex
	// command policies: the force-command runs via the remote shell, which
	// executes each line, while an allowlist like "^ps" still matches
	// "ps\nrm -rf /" (RE2 anchors apply to the whole text, not per line).
	// Multi-line scripts can use ";" or "&&" instead.
	if strings.ContainsAny(in.Command, "\n\r") && (in.Purpose == PurposeOneshot || hp.effectivePolicies().Restricts()) {
		return fmt.Errorf("command must not contain newline characters (\\n or \\r)")
	}
	// A one-shot target's only command restriction is the force-command baked
	// into the certificate. An empty (or whitespace-only) command bakes no
	// force-command at all — ca.BuildAndSign emits the critical option only when
	// non-empty — yielding an unrestricted host credential that also slips past
	// denylist and require_approval evaluation, since an empty string matches no
	// rule (allowlist hosts still deny it). The broker already requires a
	// command; enforce the same invariant at the authoritative signer so a
	// malicious or buggy client cannot obtain an unconstrained certificate.
	if in.Purpose == PurposeOneshot && in.Role == RoleTarget && strings.TrimSpace(in.Command) == "" {
		return fmt.Errorf("one-shot command must not be empty")
	}
	if !callerAllowed(hp.AllowedCallers, in.Caller) {
		return fmt.Errorf("caller %q not authorised for %q", in.Caller, in.Host)
	}
	// Per-user RBAC: if the request carries end-user groups (OIDC HTTP frontend),
	// the host must belong to at least one of them. If EndUserGroups is nil the
	// filter is not applied (requests without user identity: stdio/mTLS).
	if in.EndUserGroups != nil && !groupsIntersect(hp.Groups, in.EndUserGroups) {
		return fmt.Errorf("user %q not authorised for %q (groups)", in.EndUser, in.Host)
	}
	if in.Role == RoleBastion && !hp.AllowAsBastion {
		return fmt.Errorf("host %q is not allowed as a bastion", in.Host)
	}
	// A host with a command policy is issuable only as a one-shot target: the
	// firewall is enforced via the force-command baked into the cert, and a
	// bastion-role cert carries no force-command (and grants port-forwarding),
	// so it would hand out an unrestricted credential for the host's principal
	// and bypass the firewall entirely. Reject any non-target role for such a
	// host (defends both the remote signer and the broker's local mode, where
	// PolicyTable.Validate is not run).
	if in.Role != RoleTarget && hp.effectivePolicies().Restricts() {
		return fmt.Errorf("host %q has command_policy: role %q not allowed (command-policy hosts cannot be used as bastions)", in.Host, in.Role)
	}
	return nil
}

type commandPolicyResult struct {
	RequireApproval      bool
	MatchedRule          string
	Enforcement          string
	Warning              string
	WouldDeny            bool
	WouldRequireApproval bool
}

// resolveCommandPolicy evaluates the AI-action firewall for an Intent.
func resolveCommandPolicy(hp HostPolicy, in Intent, grants GrantProvider) (commandPolicyResult, error) {
	eff := hp.effectivePolicies()
	res := commandPolicyResult{}
	// Widen-only runtime grants: inject the host's live allow-grants ONLY when the
	// baseline is already allowlist-active. On a default-allow/denylist host the
	// command is already permitted, and injecting an allowlist would invert the
	// host to default-deny (see PolicySet.decideOne) — so we suppress it there.
	if grants != nil && eff.hasAllowlist() {
		if g := grants.GrantsFor(in.Host, in, time.Now()); len(g) > 0 {
			if eff.Enforcement() == CmdPolicyAudit {
				g = slices.Clone(g)
				for i := range g {
					g[i].Enforcement = CmdPolicyAudit
				}
			}
			eff = append(slices.Clone(eff), g...)
		}
	}
	if in.Role != RoleTarget || !eff.Restricts() {
		return res, nil
	}
	res.Enforcement = eff.Enforcement()
	// Stateful sessions are not independently verifiable. Exec sessions are
	// allowed because each ssh_session_exec is preflighted through this same
	// policy path by the broker; opening the connection carries no command yet.
	if in.Purpose == PurposeSession {
		if in.SessionMode != SessionModeExec {
			return res, fmt.Errorf("host %q has command_policy: sessions require mode=%q (shell/pty are not command-verifiable)", in.Host, SessionModeExec)
		}
		if in.Command == "" {
			return res, nil
		}
	}
	allowed, needsApproval, rule, cerr := eff.Decide(in.Command)
	res.MatchedRule = rule
	if cerr != nil {
		if res.Enforcement == CmdPolicyAudit {
			res.WouldDeny = true
			res.Warning = commandPolicyWarning(res)
			return res, nil
		}
		return res, fmt.Errorf("command_policy for %q: %w", in.Host, cerr)
	}
	if !allowed {
		if res.Enforcement == CmdPolicyAudit {
			res.WouldDeny = true
			res.WouldRequireApproval = needsApproval
			res.Warning = commandPolicyWarning(res)
			return res, nil
		}
		return res, fmt.Errorf("command not allowed on %q by command_policy (%s)", in.Host, rule)
	}
	// Approve-and-learn: a live approval-waiver suppresses require_approval for this
	// (already-allowed) command. Applied here, AFTER the !allowed guard, so a waiver
	// can only un-gate an allowed command — never allow something new, never override
	// a deny. Independent of hasAllowlist (waivers carry no inversion risk). The
	// waiver also binds to the exact caller/end-user scope and elevation
	// (sudo/sudo_user) that were approved.
	if needsApproval && grants != nil && grants.WaiverMatches(in.Host, in, time.Now()) {
		res.MatchedRule = "approval-waived:" + rule
		return res, nil
	}
	if needsApproval {
		if res.Enforcement == CmdPolicyAudit {
			res.WouldRequireApproval = true
			res.Warning = commandPolicyWarning(res)
			return res, nil
		}
		res.RequireApproval = true
	}
	return res, nil
}

func commandPolicyWarning(res commandPolicyResult) string {
	action := "would allow"
	switch {
	case res.WouldDeny && res.WouldRequireApproval:
		action = "would deny and would require approval"
	case res.WouldDeny:
		action = "would deny"
	case res.WouldRequireApproval:
		action = "would require approval"
	}
	if res.MatchedRule != "" {
		return fmt.Sprintf("command_policy audit: %s (%s)", action, res.MatchedRule)
	}
	return "command_policy audit: " + action
}

// buildConstraints assembles the ca.Constraints from the host policy, the
// intent, and the resolved values (elevation prefix and effective TTL).
// ForceCommand is not set here; Resolve adds it for one-shot targets.
func buildConstraints(hp HostPolicy, in Intent, elevationPrefix string, ttl time.Duration) ca.Constraints {
	// Build the KeyID in one pass. Order and formatting are preserved exactly
	// (agent host role t [user] [elev] [pty]) because the KeyID is audited and
	// embedded in the certificate.
	var kid strings.Builder
	fmt.Fprintf(&kid, "agent=%s host=%s role=%s t=%d", in.Caller, in.Host, in.Role, time.Now().Unix())
	if in.EndUser != "" {
		fmt.Fprintf(&kid, " user=%s", in.EndUser)
	}
	if elevationPrefix != "" {
		fmt.Fprintf(&kid, " elev=%s", elevationPrefix)
	}
	if in.PTY {
		kid.WriteString(" pty=1")
	}
	return ca.Constraints{
		Principal:           hp.Principal,
		TTL:                 ttl,
		SourceAddress:       hp.SourceAddress,
		AllowPortForwarding: in.Role == RoleBastion,
		AllowPTY:            in.PTY,
		KeyID:               kid.String(),
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
// (replacing ' with '\”).
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

// AllowsCaller reports whether the given CN may request this host under the
// per-host allowed_callers list (empty list = any authenticated caller). It is
// the exported form of callerAllowed so that the HTTP handler can apply the
// same per-host filter to GET /v1/hosts that Resolve applies to /v1/sign.
func (hp HostPolicy) AllowsCaller(cn string) bool {
	return callerAllowed(hp.AllowedCallers, cn)
}

// hasControlChar reports whether s contains an ASCII control character
// (including newline and carriage return). Such characters must never reach the
// certificate KeyID or be written verbatim to a log.
func hasControlChar(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// HasUnsafeTokenChar reports whether s contains a character that is unsafe in the
// space-separated key=value token streams used by the certificate KeyID and the
// signer audit record: an ASCII control character or whitespace (space or tab).
// Such a character would let a broker-asserted value splice a forged token into
// the stream. It is the single predicate shared by the signer's authorizeIntent
// gate (KeyID sink) and the HTTP handler's input gate (audit sink), so the two
// cannot drift. '=' is deliberately allowed — a bare '=' lands inside one value
// and cannot start a new token, and some IdPs emit base64 sub claims with '='
// padding.
func HasUnsafeTokenChar(s string) bool {
	return hasControlChar(s) || strings.ContainsAny(s, " \t")
}

// CallerPolicy defines the groups accessible to a caller identified by the CN
// of its mTLS certificate. Absent from CallerTable = no group restriction
// (backward compatible), unless the table has a DefaultCallerKey entry, which
// absent CNs then inherit. Present with empty AllowedGroups = total denial by
// groups.
type CallerPolicy struct {
	AllowedGroups []string `json:"allowed_groups"`
}

// DefaultCallerKey is the reserved CallerTable key whose policy applies to any
// caller CN not explicitly listed. Without it an absent CN has no group
// restriction (backward compatible); with `"_default": {"allowed_groups": []}`
// the table becomes default-deny (threat-model gap #6). Follows the `_default`
// convention of ca_keys and group_command_policies. A certificate whose CN is
// literally "_default" matches this entry and cannot be granted its own policy.
const DefaultCallerKey = "_default"

// CallerTable maps mTLS cert CN → CallerPolicy.
type CallerTable map[string]CallerPolicy

// HostSetForCaller computes the set of hosts accessible to a caller based on
// group membership. A host is accessible if any of its Groups intersects with
// the caller's AllowedGroups. Returns (set, true) when the caller has a group
// restriction, (nil, false) when the caller is not in CallerTable and the table
// has no DefaultCallerKey entry (unrestricted).
func HostSetForCaller(callerCN string, policy PolicyTable, callers CallerTable) (map[string]struct{}, bool) {
	cp, ok := callers[callerCN]
	if !ok {
		if cp, ok = callers[DefaultCallerKey]; !ok {
			return nil, false
		}
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
	grants     GrantProvider // runtime widen-only grants; nil = none (fail-safe)

	// Kubernetes target (optional): the compiled cluster table and the bound
	// ServiceAccount token minter. nil = no k8s clusters configured.
	clusters ClusterTable
	minter   TokenMinter
}

// WithK8s attaches the compiled Kubernetes cluster table and its token minter
// to the signer. Returns l for chaining at construction.
func (l *Local) WithK8s(clusters ClusterTable, minter TokenMinter) *Local {
	l.clusters = clusters
	l.minter = minter
	return l
}

// Clusters returns the compiled cluster table (nil when no k8s target is
// configured). Read-only; used by the HTTP handlers.
func (l *Local) Clusters() ClusterTable { return l.clusters }

// NewLocal creates a local signer with a single CA key (backward compatible).
func NewLocal(caKey ssh.Signer, policy PolicyTable, defaultTTL time.Duration) *Local {
	return &Local{defaultCA: caKey, policy: policy, defaultTTL: defaultTTL}
}

// NewLocalWithGroupCAs creates a local signer with a default CA and optional
// per-group CA overrides. groupCAs maps group names to their CA signers; nil
// or empty means no per-group CAs (all hosts use defaultCA).
func NewLocalWithGroupCAs(defaultCA ssh.Signer, groupCAs map[string]ssh.Signer, policy PolicyTable, defaultTTL time.Duration) *Local {
	return NewLocalWithGrants(defaultCA, groupCAs, policy, defaultTTL, nil)
}

// NewLocalWithGrants is NewLocalWithGroupCAs plus a runtime GrantProvider. The
// signer (cmd/signer) passes its shared GrantStore so live grants can widen an
// allowlist host without a config edit; pass nil for file-only behaviour (the
// local single-binary broker does this — it has no grant endpoints).
func NewLocalWithGrants(defaultCA ssh.Signer, groupCAs map[string]ssh.Signer, policy PolicyTable, defaultTTL time.Duration, grants GrantProvider) *Local {
	return &Local{defaultCA: defaultCA, groupCAs: groupCAs, policy: policy, defaultTTL: defaultTTL, grants: grants}
}

// HostAllowlistActive reports whether host exists in the compiled policy and
// whether its effective (group-composed) command policy enforces an allowlist.
// The grant API uses it to refuse a widen-only grant on a host that is not
// allowlist-active — there a grant would be a no-op and, if injected, would
// invert the host to default-deny (see PolicySet.decideOne).
func (l *Local) HostAllowlistActive(host string) (exists, allowlist bool) {
	if hp, ok := l.policy[host]; ok {
		return true, hp.effectivePolicies().hasAllowlist()
	}
	// Clusters share the grant namespace with hosts (disjoint names, enforced
	// at load) and are allowlist-active by construction (default-deny), so
	// widen-only grants apply to them without a special case.
	if cp, ok := l.clusters[host]; ok {
		return true, cp.Policies.hasAllowlist()
	}
	return false, false
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
	if in.TargetType == TargetTypeK8s {
		return l.signK8s(ctx, in)
	}
	d, err := l.policy.resolve(in, l.defaultTTL, l.grants)
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
		Allowed:              allowed,
		RequireApproval:      d.RequireApproval,
		MatchedRule:          d.MatchedRule,
		ForceCommand:         d.Constraints.ForceCommand,
		TTLSeconds:           int(d.Constraints.TTL / time.Second),
		Elevation:            d.ElevationPrefix,
		Enforcement:          d.CommandPolicyEnforcement,
		Warning:              d.Warning,
		WouldDeny:            d.WouldDeny,
		WouldRequireApproval: d.WouldRequireApproval,
	}
}
