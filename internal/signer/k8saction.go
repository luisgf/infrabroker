package signer

import (
	"fmt"
	"regexp"
)

// Kubernetes verbs accepted by the broker's curated tool surface. Deliberately
// a closed set: the ActionPolicy grammar and the SA's native RBAC both reason
// about these five verbs only ("apply" covers create+update via server-side
// apply).
const (
	K8sVerbGet    = "get"
	K8sVerbList   = "list"
	K8sVerbLogs   = "logs"
	K8sVerbApply  = "apply"
	K8sVerbDelete = "delete"
)

// K8sVerbs is the closed verb set in a fixed order (docs, validation).
var K8sVerbs = []string{K8sVerbGet, K8sVerbList, K8sVerbLogs, K8sVerbApply, K8sVerbDelete}

// Charset gates for the canonical action string. The canonical form is a
// space-separated token stream ("<verb> <resource[.group]> <ns>/<name>"), so
// every component must be provably free of spaces and slashes BEFORE the
// string is built — the string is constructed from validated fields, never
// parsed, which is what makes it injection-free (unlike shell commands).
var (
	// reK8sResource: lowercase RFC 1123 label (plural resource names).
	reK8sResource = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
	// reK8sGroup: lowercase RFC 1123 subdomain (API group, e.g. networking.k8s.io).
	reK8sGroup = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$`)
	// reK8sNamespace: RFC 1123 label.
	reK8sNamespace = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
	// reK8sName: RFC 1123 subdomain (object names).
	reK8sName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$`)
)

// K8sAction is the structured Kubernetes action the broker requests. It is the
// k8s analogue of the shell Command: the policy decides on its canonical
// string form, and the signer recomputes that form from these fields and
// rejects any mismatch, so what the approver sees is what runs.
type K8sAction struct {
	Verb      string // one of K8sVerbs
	Resource  string // lowercase plural, e.g. "pods", "deployments"
	Group     string // API group; "" = core (normalized against the cluster's resource table)
	Namespace string // "" for cluster-scoped resources or cluster-wide list
	Name      string // "" only for list
}

// Validate checks the closed verb set, the per-component charsets, and the
// per-verb field requirements. It is intentionally table-independent — whether
// the resource exists (and whether it is namespaced) is checked against the
// cluster's resource table during normalization.
func (a K8sAction) Validate() error {
	switch a.Verb {
	case K8sVerbGet, K8sVerbList, K8sVerbLogs, K8sVerbApply, K8sVerbDelete:
	default:
		return fmt.Errorf("unknown k8s verb %q (must be one of get, list, logs, apply, delete)", a.Verb)
	}
	if !reK8sResource.MatchString(a.Resource) {
		return fmt.Errorf("invalid k8s resource %q (lowercase RFC 1123 label)", a.Resource)
	}
	if a.Group != "" && !reK8sGroup.MatchString(a.Group) {
		return fmt.Errorf("invalid k8s api group %q", a.Group)
	}
	if a.Namespace != "" && !reK8sNamespace.MatchString(a.Namespace) {
		return fmt.Errorf("invalid k8s namespace %q", a.Namespace)
	}
	if a.Name != "" && !reK8sName.MatchString(a.Name) {
		return fmt.Errorf("invalid k8s object name %q", a.Name)
	}
	switch a.Verb {
	case K8sVerbList:
		if a.Name != "" {
			return fmt.Errorf("k8s list takes no object name (got %q)", a.Name)
		}
	case K8sVerbLogs:
		if a.Namespace == "" {
			return fmt.Errorf("k8s logs requires a namespace")
		}
		fallthrough
	default: // get, logs, apply, delete
		if a.Name == "" {
			return fmt.Errorf("k8s %s requires an object name", a.Verb)
		}
	}
	return nil
}

// Canonical returns the action's canonical string form:
//
//	<verb> <resource[.group]> <namespace>/<name>
//
// with "-" standing in for an empty namespace (cluster-scoped) and an empty
// name (list). Examples:
//
//	get pods prod/web-1
//	list deployments.apps prod/-
//	list nodes -/-
//	apply deployments.apps prod/api
//
// The string is BUILT from fields that passed Validate (no spaces, no
// slashes), never parsed, so it is unambiguous by construction. It feeds
// PolicySet.Decide, the audit Command field, the approval flow, and the
// grants/waivers machinery — all of which are grammar-neutral string matchers.
func (a K8sAction) Canonical() string {
	res := a.Resource
	if a.Group != "" {
		res += "." + a.Group
	}
	ns := a.Namespace
	if ns == "" {
		ns = "-"
	}
	name := a.Name
	if name == "" {
		name = "-"
	}
	return a.Verb + " " + res + " " + ns + "/" + name
}
