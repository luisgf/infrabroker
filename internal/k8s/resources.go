// Package k8s is the Kubernetes data-plane client: a deliberately small,
// dependency-free REST layer (net/http against the API server) plus the
// TokenRequest minter. It carries NO policy — authorization lives in the
// signer (layer A: the cluster's ActionPolicy) and in the cluster itself
// (layer B: the ServiceAccount's native RBAC).
//
// There is no client-go and no API discovery: the resources the broker can
// address are a curated core table plus explicit per-cluster extra_resources.
// Fail-closed and auditable beats dynamic.
package k8s

import (
	"fmt"
	"regexp"
)

// reLabel (RFC 1123 label) and reSubdomain (RFC 1123 subdomain) are the charsets
// for Kubernetes identifiers. Both exclude spaces and '/'. Validating a resource
// table entry against them keeps the identifiers that later flow into the
// signer's canonical action string "<verb> <resource[.group]> <ns>/<name>" free
// of the separators that string is split on (mirrors the equivalent charset the
// signer's action grammar enforces on client-supplied fields).
var (
	reLabel     = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
	reSubdomain = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$`)
)

// validLabel reports whether s is a lowercase RFC 1123 label (resource plural
// names) — no dots, spaces, or slashes.
func validLabel(s string) bool { return reLabel.MatchString(s) }

// validSubdomain reports whether s is a lowercase RFC 1123 subdomain (API
// groups) — dots allowed, no spaces or slashes.
func validSubdomain(s string) bool { return reSubdomain.MatchString(s) }

// ResourceDef describes one addressable resource type: how it maps to a REST
// path and to a manifest kind.
type ResourceDef struct {
	// Resource is the lowercase plural name used in tool calls, policy rules,
	// and REST paths (e.g. "deployments").
	Resource string `json:"resource"`
	// Group is the API group; empty = core ("" → /api/v1, else /apis/<group>).
	Group string `json:"group,omitempty"`
	// Version is the served API version (e.g. "v1").
	Version string `json:"version"`
	// Kind is the manifest kind (e.g. "Deployment") — descriptive metadata for
	// the resource entry; required so an extra_resources declaration is
	// self-documenting.
	Kind string `json:"kind"`
	// Namespaced marks namespace-scoped resources.
	Namespaced bool `json:"namespaced"`
}

// coreResources is the curated table of well-known resource types. Anything
// else must be declared per cluster via extra_resources — an explicit,
// reviewable operator decision instead of API discovery.
var coreResources = []ResourceDef{
	{Resource: "pods", Group: "", Version: "v1", Kind: "Pod", Namespaced: true},
	{Resource: "services", Group: "", Version: "v1", Kind: "Service", Namespaced: true},
	{Resource: "configmaps", Group: "", Version: "v1", Kind: "ConfigMap", Namespaced: true},
	{Resource: "secrets", Group: "", Version: "v1", Kind: "Secret", Namespaced: true},
	{Resource: "serviceaccounts", Group: "", Version: "v1", Kind: "ServiceAccount", Namespaced: true},
	{Resource: "namespaces", Group: "", Version: "v1", Kind: "Namespace", Namespaced: false},
	{Resource: "nodes", Group: "", Version: "v1", Kind: "Node", Namespaced: false},
	{Resource: "events", Group: "", Version: "v1", Kind: "Event", Namespaced: true},
	{Resource: "persistentvolumeclaims", Group: "", Version: "v1", Kind: "PersistentVolumeClaim", Namespaced: true},
	{Resource: "persistentvolumes", Group: "", Version: "v1", Kind: "PersistentVolume", Namespaced: false},
	{Resource: "deployments", Group: "apps", Version: "v1", Kind: "Deployment", Namespaced: true},
	{Resource: "statefulsets", Group: "apps", Version: "v1", Kind: "StatefulSet", Namespaced: true},
	{Resource: "daemonsets", Group: "apps", Version: "v1", Kind: "DaemonSet", Namespaced: true},
	{Resource: "replicasets", Group: "apps", Version: "v1", Kind: "ReplicaSet", Namespaced: true},
	{Resource: "jobs", Group: "batch", Version: "v1", Kind: "Job", Namespaced: true},
	{Resource: "cronjobs", Group: "batch", Version: "v1", Kind: "CronJob", Namespaced: true},
	{Resource: "ingresses", Group: "networking.k8s.io", Version: "v1", Kind: "Ingress", Namespaced: true},
}

// Resources returns the effective resource table: the curated core plus the
// cluster's extra definitions. An extra entry whose Resource collides with a
// core entry (or another extra) is a configuration error — resolution must be
// unambiguous because the bare resource name is the policy vocabulary.
func Resources(extra []ResourceDef) (map[string]ResourceDef, error) {
	table := make(map[string]ResourceDef, len(coreResources)+len(extra))
	for _, r := range coreResources {
		table[r.Resource] = r
	}
	for _, r := range extra {
		if r.Resource == "" || r.Version == "" || r.Kind == "" {
			return nil, fmt.Errorf("extra_resources: resource, version, and kind are required (got %+v)", r)
		}
		// Charset-validate the identifiers that flow into the signer's canonical
		// action string. Without this an operator's extra_resources entry could
		// inject a space or '/' into Resource/Group and break the canonical's
		// "provably space/slash-free" anti-mismatch guarantee (#281).
		if !validLabel(r.Resource) {
			return nil, fmt.Errorf("extra_resources: resource %q is not a valid RFC 1123 label (lowercase alphanumeric and '-')", r.Resource)
		}
		if r.Group != "" && !validSubdomain(r.Group) {
			return nil, fmt.Errorf("extra_resources: group %q is not a valid RFC 1123 subdomain", r.Group)
		}
		if prev, ok := table[r.Resource]; ok {
			return nil, fmt.Errorf("extra_resources: %q collides with %s/%s", r.Resource, prev.Group, prev.Resource)
		}
		table[r.Resource] = r
	}
	return table, nil
}

// Resolve looks a resource up in the table by its bare name and, when the
// caller supplied a group, verifies it matches the table's normalization.
// Unknown resources are a hard error ("add it to extra_resources"), never a
// passthrough.
func Resolve(table map[string]ResourceDef, resource, group string) (ResourceDef, error) {
	def, ok := table[resource]
	if !ok {
		return ResourceDef{}, fmt.Errorf("unknown k8s resource %q: not in the core table nor this cluster's extra_resources", resource)
	}
	if group != "" && group != def.Group {
		return ResourceDef{}, fmt.Errorf("k8s resource %q belongs to group %q, not %q", resource, def.Group, group)
	}
	return def, nil
}
