package broker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/luisgf/infrabroker/internal/audit"
	"github.com/luisgf/infrabroker/internal/k8s"
	"github.com/luisgf/infrabroker/internal/signer"
)

// ClusterInfo is a Kubernetes cluster visible to the caller (name only; the
// broker never exposes the API server address or credentials to the model).
type ClusterInfo struct {
	Name string
}

// K8sResult is the outcome of a Kubernetes action.
type K8sResult struct {
	// Output is the API server's JSON response (get/list/delete/apply) or the
	// plain-text logs (logs).
	Output string
	// Serial correlates the broker's execution entry with the signer's
	// issuance entry (there is no certificate serial for k8s).
	Serial uint64
	// Warnings carries audit-mode policy observations, like the SSH path.
	Warnings []string
	// DryRun holds the policy decision for a dry-run (no action performed).
	DryRun *signer.DecisionInfo
}

// K8sClusters returns the clusters visible to the caller, filtered by end-user
// groups exactly like ServerInfos (so the model is never offered a cluster it
// cannot use). Empty when no k8s target is configured.
func (e *Engine) K8sClusters(c Caller) []ClusterInfo {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]ClusterInfo, 0, len(e.clusters))
	for name, ci := range e.clusters {
		if c.Groups != nil && !groupsIntersect(ci.Groups, c.Groups) {
			continue
		}
		out = append(out, ClusterInfo{Name: name})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// clusterInfo returns the cached connectivity for a cluster.
func (e *Engine) clusterInfo(name string) (signer.ClusterInfo, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	ci, ok := e.clusters[name]
	return ci, ok
}

// K8sExecuteOpts carries the optional per-verb knobs (list selectors, log
// tail) from the MCP tools.
type K8sExecuteOpts struct {
	List k8s.ListOptions
	Logs k8s.LogOptions
}

// K8sExecute authorises and runs one Kubernetes action. It follows the same
// credential-broker shape as SSH: it asks the signer to authorise the action
// and mint a short-lived bound ServiceAccount token, runs the API call with
// that token, and discards it — the agent never sees a cluster credential.
// Layer-B enforcement is the SA's native RBAC in the cluster.
//
// manifest is the k8s_apply body; it is never sent to the signer (it can carry
// a Secret) — only its sha256 is audited. dryRun previews the policy decision
// without minting a token or calling the cluster.
func (e *Engine) K8sExecute(ctx context.Context, c Caller, cluster string, action signer.K8sAction, manifest []byte, dryRun bool, opts K8sExecuteOpts) (*K8sResult, error) {
	ci, ok := e.clusterInfo(cluster)
	if !ok {
		e.auditE(audit.Entry{Caller: c.ID, Host: cluster, TargetType: signer.TargetTypeK8s,
			Outcome: "denied", Command: "target=k8s", Err: "unknown cluster"})
		return nil, fmt.Errorf("unknown cluster: %q", cluster)
	}
	if err := action.Validate(); err != nil {
		return nil, err
	}
	// Normalize the action's group against this cluster's resource table (core
	// plus extra_resources), so the canonical string the broker sends matches
	// the one the signer recomputes — the anti-mismatch invariant.
	table, err := resourceTable(ci)
	if err != nil {
		return nil, err
	}
	def, err := k8s.Resolve(table, action.Resource, action.Group)
	if err != nil {
		return nil, err
	}
	action.Group = def.Group
	// A cluster-scoped resource takes no namespace: drop any client-supplied one
	// so the canonical the broker signs, audits, and shows the approver matches
	// execution (resourcePath omits the namespace for these) and the signer's
	// recomputed canonical. Mirrors the group normalization; symmetric with
	// resolveK8s so the anti-mismatch check still agrees.
	if !def.Namespaced {
		action.Namespace = ""
	}
	canonical := action.Canonical()

	in := signer.Intent{
		Caller:        localCaller,
		Host:          cluster,
		TargetType:    signer.TargetTypeK8s,
		K8s:           &action,
		Role:          signer.RoleTarget,
		Purpose:       signer.PurposeOneshot,
		Command:       canonical,
		DryRun:        dryRun,
		EndUser:       c.ID,
		EndUserGroups: c.Groups,
	}
	issued, err := e.sgn.SignIntent(ctx, in)
	if err != nil {
		e.auditK8s(c, cluster, canonical, 0, "denied", nil, err)
		return nil, err
	}
	if dryRun {
		return &K8sResult{DryRun: issued.Decision}, nil
	}
	if issued.K8sToken == "" {
		// Approval-gated and not yet approved (or the client is not configured
		// to wait): surface it like the SSH approval path.
		return nil, approvalError(cluster, issued.Decision)
	}

	// Run the action with the ephemeral token, then let it fall out of scope.
	client, err := k8s.NewClient(k8s.Target{APIServer: ci.APIServer, CAPEM: []byte(ci.CACertPEM)}, issued.K8sToken, 30*time.Second)
	if err != nil {
		e.auditK8s(c, cluster, canonical, issued.Serial, "error", issued.Decision, err)
		return nil, err
	}
	out, runErr := runK8sAction(ctx, client, def, action, manifest, opts)
	outcome := "executed"
	if runErr != nil {
		outcome = "error"
	}
	e.auditK8s(c, cluster, canonical, issued.Serial, outcome, issued.Decision, runErr, manifest...)
	if runErr != nil {
		return nil, runErr
	}
	return &K8sResult{Output: out, Serial: issued.Serial, Warnings: decisionWarnings(issued.Decision)}, nil
}

// runK8sAction dispatches on the verb.
func runK8sAction(ctx context.Context, client *k8s.Client, def k8s.ResourceDef, a signer.K8sAction, manifest []byte, opts K8sExecuteOpts) (string, error) {
	switch a.Verb {
	case signer.K8sVerbGet:
		return client.Get(ctx, def, a.Namespace, a.Name)
	case signer.K8sVerbList:
		return client.List(ctx, def, a.Namespace, opts.List)
	case signer.K8sVerbLogs:
		return client.Logs(ctx, a.Namespace, a.Name, opts.Logs)
	case signer.K8sVerbDelete:
		return client.Delete(ctx, def, a.Namespace, a.Name)
	case signer.K8sVerbApply:
		if len(manifest) == 0 {
			return "", fmt.Errorf("k8s apply requires a manifest")
		}
		return client.Apply(ctx, def, a.Namespace, a.Name, manifest)
	default:
		return "", fmt.Errorf("unsupported k8s verb %q", a.Verb)
	}
}

// resourceTable builds the effective resource table for a cluster from its
// cached extra_resources.
func resourceTable(ci signer.ClusterInfo) (map[string]k8s.ResourceDef, error) {
	extra := make([]k8s.ResourceDef, 0, len(ci.ExtraResources))
	for _, rd := range ci.ExtraResources {
		extra = append(extra, k8s.ResourceDef{
			Resource: rd.Resource, Group: rd.Group, Version: rd.Version,
			Kind: rd.Kind, Namespaced: rd.Namespaced,
		})
	}
	return k8s.Resources(extra)
}

// auditK8s records a k8s execution entry. The canonical action is the Command;
// a k8s_apply manifest is never logged verbatim (it can carry a Secret) — its
// sha256 rides in body_sha256.
func (e *Engine) auditK8s(c Caller, cluster, canonical string, serial uint64, outcome string, dec *signer.DecisionInfo, err error, manifest ...byte) {
	e.mu.RLock()
	ci, ok := e.clusters[cluster]
	e.mu.RUnlock()
	host := cluster
	if ok {
		host = ci.APIServer
	}
	// The caller identity rides in the structured Caller field (JSON-encoded, not
	// splice-able), NOT as a " user=" token inside the space-delimited Command
	// stream: c.ID is the OIDC user-claim value and is not charset-validated here,
	// so splicing it in would let a whitespace-bearing identity forge tokens
	// (outcome=…, action=…) into a hash-chained entry — the audit token-forgery
	// class the signer already guards (cf. #67). The SSH path is symmetric: the
	// caller lives in Caller, never in the Command stream.
	cmd := "target=k8s action=" + canonical
	ent := audit.Entry{
		Caller:     c.ID,
		Host:       host,
		Command:    cmd,
		Serial:     serial,
		Outcome:    outcome,
		TargetType: signer.TargetTypeK8s,
	}
	if len(manifest) > 0 {
		sum := sha256.Sum256(manifest)
		ent.BodySHA256 = hex.EncodeToString(sum[:])
	}
	if dec != nil {
		ent.PolicyRule = dec.MatchedRule
		ent.Warning = dec.Warning
	}
	if err != nil {
		ent.Err = err.Error()
	}
	eventsTotal.With(outcome).Inc()
	if aerr := e.auditLog.Append(ent); aerr != nil {
		log.Printf("warning: error writing audit log: %v", aerr)
	}
}
