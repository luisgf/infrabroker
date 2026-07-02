package signer

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/luisgf/ssh-broker/internal/k8s"
)

// Target types carried by Intent/WireRequest/audit entries. The empty string
// means SSH (backward compatible: every pre-k8s client sends nothing).
const (
	TargetTypeSSH = "ssh"
	TargetTypeK8s = "k8s"
)

// K8s rule effects.
const (
	K8sEffectAllow           = "allow"
	K8sEffectDeny            = "deny"
	K8sEffectRequireApproval = "require_approval"
)

// Bound-token TTL bounds: the TokenRequest API refuses anything under 600s,
// and 900s keeps the k8s credential inside the same exposure ceiling as the
// SSH certificate cap.
const (
	k8sTokenTTLMin     = 600
	k8sTokenTTLMax     = 900
	k8sTokenTTLDefault = 600
)

// reK8sClusterName constrains cluster names: they share the audit Host field
// and the grants index with SSH host names, so they must be single clean
// tokens.
var reK8sClusterName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}$`)

// K8sRule is one structured ActionPolicy rule. At load it is compiled to an
// anchored regex over the canonical action string, so the whole dynamic-policy
// machinery (PolicySet composition, grants, approve-and-learn waivers, the
// recommender) applies to Kubernetes actions unchanged.
//
// Field entries are matched exactly after normalization; "*" means any. Empty
// Namespaces/Names mean any (including "-", the cluster-scoped/no-name
// marker). Effect require_approval implies allow: the action is permitted but
// gated behind human approval.
type K8sRule struct {
	Verbs      []string `json:"verbs"`
	Resources  []string `json:"resources"`
	Namespaces []string `json:"namespaces,omitempty"`
	Names      []string `json:"names,omitempty"`
	Effect     string   `json:"effect"` // allow | deny | require_approval
}

// SABinding maps end-user groups to the ServiceAccount whose bound token is
// minted for them. Bindings are evaluated in order; the first whose Groups
// intersect the end user's groups wins. A binding with empty Groups is the
// default and matches any caller — including callers with no end-user
// identity (stdio/mTLS frontends).
type SABinding struct {
	Groups         []string `json:"groups,omitempty"`
	Namespace      string   `json:"namespace"`
	ServiceAccount string   `json:"service_account"`
}

// ClusterPolicy is the issuance policy for one Kubernetes cluster — the k8s
// analogue of HostPolicy, kept as a parallel type on purpose: the two targets
// share the control plane, not the descriptor.
type ClusterPolicy struct {
	// Connectivity — exposed to the broker via /v1/clusters.
	APIServer string `json:"api_server"` // https://host:port
	CACert    string `json:"ca_cert"`    // path to the cluster CA bundle (PEM)

	// TokenFile is the signer's minter credential for this cluster: a
	// ServiceAccount token whose entire RBAC is `create` on
	// `serviceaccounts/token` for the bound SAs below. Never exposed.
	TokenFile string `json:"token_file"`

	// TokenTTLSeconds bounds the minted bound-token lifetime. 0 selects 600;
	// the valid range is [600, 900] (TokenRequest refuses less than 600).
	TokenTTLSeconds int `json:"token_ttl_seconds,omitempty"`

	// Groups / AllowedCallers: same RBAC semantics as HostPolicy.
	Groups         []string `json:"groups,omitempty"`
	AllowedCallers []string `json:"allowed_callers,omitempty"`

	// SABindings select the ServiceAccount (layer B: its native cluster RBAC)
	// per end-user group. At least one binding is required.
	SABindings []SABinding `json:"sa_bindings"`

	// Rules is the cluster's ActionPolicy. Unlike SSH hosts (default-allow
	// without a command_policy, for backward compatibility), a cluster is
	// DEFAULT-DENY: at least one allow/require_approval rule is required, and
	// anything unmatched is refused. There is no legacy to preserve here.
	Rules []K8sRule `json:"rules"`

	// ExtraResources extends the curated core resource table for this cluster
	// (explicit CRDs — no API discovery).
	ExtraResources []k8s.ResourceDef `json:"extra_resources,omitempty"`

	// Compiled state (CompileClusterPolicies); never serialised.
	Policies  PolicySet                  `json:"-"`
	Resources map[string]k8s.ResourceDef `json:"-"`
	CAPEM     []byte                     `json:"-"`
}

// ClusterTable maps cluster name → policy.
type ClusterTable map[string]ClusterPolicy

// AllowsCaller mirrors HostPolicy.AllowsCaller for clusters.
func (cp ClusterPolicy) AllowsCaller(cn string) bool {
	return callerAllowed(cp.AllowedCallers, cn)
}

// ClusterSetForCaller is HostSetForCaller for clusters: the set of clusters a
// caller may reach by group membership, and whether the caller is
// group-restricted at all (same default-open / _default semantics).
func ClusterSetForCaller(callerCN string, clusters ClusterTable, callers CallerTable) (map[string]struct{}, bool) {
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
	for name, c := range clusters {
		for _, g := range c.Groups {
			if _, ok := allowed[g]; ok {
				set[name] = struct{}{}
				break
			}
		}
	}
	return set, true
}

// TokenMinter mints a short-lived bound ServiceAccount token. Satisfied by
// *k8s.Minter; declared here so the signer core does not depend on the
// concrete client.
type TokenMinter interface {
	MintToken(ctx context.Context, cluster, namespace, serviceAccount string, ttl time.Duration) (string, time.Time, error)
}

// CompileClusterPolicies validates every cluster and compiles its rules into
// the PolicySet machinery. hostNames is the SSH host table: cluster and host
// names must be disjoint because grants, waivers, and the audit Host field are
// indexed by that shared name. Reads each cluster's ca_cert so a missing or
// unparsable file fails the (re)load, not a request.
func CompileClusterPolicies(clusters ClusterTable, hosts PolicyTable) (ClusterTable, error) {
	out := make(ClusterTable, len(clusters))
	for name, cp := range clusters {
		if !reK8sClusterName.MatchString(name) {
			return nil, fmt.Errorf("cluster %q: invalid name (single [a-zA-Z0-9._-] token required)", name)
		}
		if _, dup := hosts[name]; dup {
			return nil, fmt.Errorf("cluster %q: name collides with an SSH host (grants and audit are indexed by this name)", name)
		}
		compiled, err := compileCluster(name, cp)
		if err != nil {
			return nil, err
		}
		out[name] = compiled
	}
	return out, nil
}

func compileCluster(name string, cp ClusterPolicy) (ClusterPolicy, error) {
	u, err := url.Parse(cp.APIServer)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return cp, fmt.Errorf("cluster %q: api_server must be an https:// URL", name)
	}
	if cp.CACert == "" || cp.TokenFile == "" {
		return cp, fmt.Errorf("cluster %q: ca_cert and token_file are required", name)
	}
	pem, err := os.ReadFile(cp.CACert)
	if err != nil {
		return cp, fmt.Errorf("cluster %q: reading ca_cert: %w", name, err)
	}
	cp.CAPEM = pem
	if _, err := os.Stat(cp.TokenFile); err != nil {
		return cp, fmt.Errorf("cluster %q: token_file: %w", name, err)
	}
	if cp.TokenTTLSeconds == 0 {
		cp.TokenTTLSeconds = k8sTokenTTLDefault
	}
	if cp.TokenTTLSeconds < k8sTokenTTLMin || cp.TokenTTLSeconds > k8sTokenTTLMax {
		return cp, fmt.Errorf("cluster %q: token_ttl_seconds %d outside [%d, %d] (TokenRequest refuses less than %d)",
			name, cp.TokenTTLSeconds, k8sTokenTTLMin, k8sTokenTTLMax, k8sTokenTTLMin)
	}

	if len(cp.SABindings) == 0 {
		return cp, fmt.Errorf("cluster %q: at least one sa_binding is required", name)
	}
	for i, b := range cp.SABindings {
		if !reK8sNamespace.MatchString(b.Namespace) || !reK8sName.MatchString(b.ServiceAccount) {
			return cp, fmt.Errorf("cluster %q: sa_bindings[%d]: invalid namespace or service_account", name, i)
		}
	}

	cp.Resources, err = k8s.Resources(cp.ExtraResources)
	if err != nil {
		return cp, fmt.Errorf("cluster %q: %w", name, err)
	}

	policy, err := compileK8sRules(name, cp.Rules, cp.Resources)
	if err != nil {
		return cp, err
	}
	cp.Policies = PolicySet{policy}
	return cp, nil
}

// compileK8sRules materialises the structured rules as one allowlist
// CommandPolicy over the canonical action grammar.
func compileK8sRules(cluster string, rules []K8sRule, table map[string]k8s.ResourceDef) (CommandPolicy, error) {
	cp := CommandPolicy{Mode: CmdPolicyAllowlist, Enforcement: CmdPolicyEnforce}
	for i, r := range rules {
		re, err := compileK8sRule(r, table)
		if err != nil {
			return cp, fmt.Errorf("cluster %q: rules[%d]: %w", cluster, i, err)
		}
		switch r.Effect {
		case K8sEffectAllow:
			cp.Allow = append(cp.Allow, re)
		case K8sEffectDeny:
			cp.Deny = append(cp.Deny, re)
		case K8sEffectRequireApproval:
			// require_approval implies allow: the action is permitted but gated.
			cp.Allow = append(cp.Allow, re)
			cp.RequireApproval = append(cp.RequireApproval, re)
		default:
			return cp, fmt.Errorf("cluster %q: rules[%d]: unknown effect %q (allow, deny, or require_approval)", cluster, i, r.Effect)
		}
	}
	if len(cp.Allow) == 0 {
		return cp, fmt.Errorf("cluster %q: default-deny requires at least one allow or require_approval rule", cluster)
	}
	if err := cp.Validate(); err != nil { // compiles the generated regexes
		return cp, fmt.Errorf("cluster %q: %w", cluster, err)
	}
	return cp, nil
}

// compileK8sRule turns one structured rule into an anchored regex over the
// canonical "<verb> <resource[.group]> <ns>/<name>" form. Every literal is
// QuoteMeta'd; only the "*" wildcard produces a character-class pattern, so
// the generated expression can never be widened by operator input.
func compileK8sRule(r K8sRule, table map[string]k8s.ResourceDef) (string, error) {
	verbs, err := compileAlternates(r.Verbs, "verbs", `[a-z]+`, func(v string) (string, error) {
		for _, known := range K8sVerbs {
			if v == known {
				return regexp.QuoteMeta(v), nil
			}
		}
		return "", fmt.Errorf("unknown verb %q", v)
	})
	if err != nil {
		return "", err
	}
	resources, err := compileAlternates(r.Resources, "resources", `[^ ]+`, func(v string) (string, error) {
		def, err := k8s.Resolve(table, v, "")
		if err != nil {
			return "", err
		}
		tok := def.Resource
		if def.Group != "" {
			tok += "." + def.Group
		}
		return regexp.QuoteMeta(tok), nil
	})
	if err != nil {
		return "", err
	}
	namespaces, err := compileAlternates(r.Namespaces, "namespaces", `[^ /]+`, func(v string) (string, error) {
		if v != "-" && !reK8sNamespace.MatchString(v) {
			return "", fmt.Errorf("invalid namespace %q", v)
		}
		return regexp.QuoteMeta(v), nil
	})
	if err != nil {
		return "", err
	}
	names, err := compileAlternates(r.Names, "names", `[^ ]+`, func(v string) (string, error) {
		if v != "-" && !reK8sName.MatchString(v) {
			return "", fmt.Errorf("invalid name %q", v)
		}
		return regexp.QuoteMeta(v), nil
	})
	if err != nil {
		return "", err
	}
	return "^" + verbs + " " + resources + " " + namespaces + "/" + names + "$", nil
}

// compileAlternates builds the regex fragment for one rule field: an
// alternation of validated literals, or the wildcard pattern when the list is
// empty or contains "*".
func compileAlternates(values []string, field, wildcard string, lit func(string) (string, error)) (string, error) {
	if len(values) == 0 {
		return "(?:" + wildcard + ")", nil
	}
	alts := make([]string, 0, len(values))
	for _, v := range values {
		if v == "*" {
			return "(?:" + wildcard + ")", nil
		}
		l, err := lit(v)
		if err != nil {
			return "", fmt.Errorf("%s: %w", field, err)
		}
		alts = append(alts, l)
	}
	return "(?:" + strings.Join(alts, "|") + ")", nil
}

// bindingFor selects the ServiceAccount for the end user's groups: first
// group-intersecting binding wins; a binding with empty Groups is the default
// and matches anyone.
func (cp ClusterPolicy) bindingFor(endUserGroups []string) (SABinding, error) {
	for _, b := range cp.SABindings {
		if len(b.Groups) == 0 || groupsIntersect(b.Groups, endUserGroups) {
			return b, nil
		}
	}
	return SABinding{}, fmt.Errorf("no sa_binding matches the end user's groups")
}

// resolveK8s authorises a Kubernetes intent against the cluster policy and
// the runtime grants, returning the decision. It mirrors PolicyTable.resolve's
// gate order (identity charsets → caller allowlist → per-user groups → action
// policy) and reuses resolveCommandPolicy via a synthetic HostPolicy so there
// is exactly one firewall evaluator for both targets.
func (ct ClusterTable) resolveK8s(in Intent, grants GrantProvider) (Decision, commandPolicyResult, error) {
	cp, ok := ct[in.Host]
	if !ok {
		return Decision{}, commandPolicyResult{}, fmt.Errorf("no policy for cluster: %q", in.Host)
	}
	if in.K8s == nil {
		return Decision{}, commandPolicyResult{}, fmt.Errorf("k8s intent without an action")
	}
	if err := in.K8s.Validate(); err != nil {
		return Decision{}, commandPolicyResult{}, err
	}
	// The SSH-only intent knobs are meaningless for a stateless API call and
	// MUST NOT silently no-op: each one is a policy surface on hosts, so a
	// request that sets them is malformed or malicious.
	switch {
	case in.Sudo || in.SudoUser != "":
		return Decision{}, commandPolicyResult{}, fmt.Errorf("k8s intents do not support sudo")
	case in.PTY:
		return Decision{}, commandPolicyResult{}, fmt.Errorf("k8s intents do not support pty")
	case in.FileTransfer:
		return Decision{}, commandPolicyResult{}, fmt.Errorf("k8s intents do not support file transfer")
	case in.Purpose != PurposeOneshot || in.SessionMode != "":
		return Decision{}, commandPolicyResult{}, fmt.Errorf("k8s intents are one-shot only (no sessions)")
	case in.Role != RoleTarget:
		return Decision{}, commandPolicyResult{}, fmt.Errorf("k8s intents must have role %q", RoleTarget)
	}
	if HasUnsafeTokenChar(in.Caller) || HasUnsafeTokenChar(in.EndUser) {
		return Decision{}, commandPolicyResult{}, fmt.Errorf("caller or end_user contains disallowed characters (control or whitespace)")
	}
	// Normalize the resource against this cluster's table: unknown resources
	// fail, a client-supplied group must agree with the table, and an omitted
	// group is filled in — the canonical form always carries the resolved
	// group, on both sides of the wire (the broker normalizes against the same
	// table before signing).
	def, err := k8s.Resolve(cp.Resources, in.K8s.Resource, in.K8s.Group)
	if err != nil {
		return Decision{}, commandPolicyResult{}, err
	}
	action := *in.K8s
	action.Group = def.Group
	// Anti-mismatch: the policy decides on, the audit records, and the approver
	// sees in.Command — it must be exactly the normalized canonical form of the
	// structured action, or a malicious broker could show the human one action
	// and run another.
	if canonical := action.Canonical(); in.Command != canonical {
		return Decision{}, commandPolicyResult{}, fmt.Errorf("command %q does not match the canonical action %q", in.Command, canonical)
	}
	if !callerAllowed(cp.AllowedCallers, in.Caller) {
		return Decision{}, commandPolicyResult{}, fmt.Errorf("caller %q not authorised for %q", in.Caller, in.Host)
	}
	if in.EndUserGroups != nil && !groupsIntersect(cp.Groups, in.EndUserGroups) {
		return Decision{}, commandPolicyResult{}, fmt.Errorf("user %q not authorised for %q (groups)", in.EndUser, in.Host)
	}

	// One evaluator for both targets: the cluster's compiled PolicySet rides
	// through the same resolveCommandPolicy as SSH hosts (grants widen, deny
	// wins, approve-and-learn waivers un-gate — all unchanged).
	res, err := resolveCommandPolicy(HostPolicy{Policies: cp.Policies}, in, grants)
	if err != nil {
		return Decision{}, res, err
	}
	return Decision{
		RequireApproval:          res.RequireApproval,
		MatchedRule:              res.MatchedRule,
		CommandPolicyEnforcement: res.Enforcement,
	}, res, nil
}

// signK8s is the Kubernetes branch of Local.SignIntent: it authorises the
// action and, instead of building an SSH certificate, mints a short-lived
// bound ServiceAccount token for the SA selected by the end user's groups.
// The token plays the certificate's role in Issued; layer-B enforcement is
// the SA's native RBAC in the cluster.
func (l *Local) signK8s(ctx context.Context, in Intent) (*Issued, error) {
	d, _, err := l.clusters.resolveK8s(in, l.grants)
	cp := l.clusters[in.Host]
	ttl := time.Duration(cp.TokenTTLSeconds) * time.Second
	if in.DryRun {
		if err != nil {
			return &Issued{Decision: &DecisionInfo{Allowed: false, Reason: err.Error()}}, nil
		}
		di := decisionInfo(d, true)
		di.TTLSeconds = int(ttl / time.Second)
		return &Issued{Decision: di}, nil
	}
	if err != nil {
		return nil, err
	}
	// Approval gate: identical to SSH — no credential without approval, and
	// Approved is only ever set via a trusted forwarder.
	if d.RequireApproval && !in.Approved {
		return &Issued{Decision: decisionInfo(d, true)}, nil
	}
	if l.minter == nil {
		return nil, fmt.Errorf("cluster %q: no token minter configured", in.Host)
	}
	binding, err := cp.bindingFor(in.EndUserGroups)
	if err != nil {
		return nil, fmt.Errorf("cluster %q: %w", in.Host, err)
	}
	token, expiry, err := l.minter.MintToken(ctx, in.Host, binding.Namespace, binding.ServiceAccount, ttl)
	if err != nil {
		return nil, err
	}
	di := decisionInfo(d, true)
	di.TTLSeconds = int(ttl / time.Second)
	return &Issued{
		K8sToken:       token,
		K8sTokenExpiry: expiry,
		Serial:         newK8sSerial(),
		Decision:       di,
	}, nil
}

// newK8sSerial mints a random audit serial for a k8s issuance, playing the
// role of the SSH certificate serial (correlates the signer's issuance entry
// with the broker's execution entry).
func newK8sSerial() uint64 {
	var b [8]byte
	// crypto/rand.Read cannot fail on Go 1.24+ (it crashes on RNG failure).
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint64(b[:])
}
