package signer

import (
	"strings"
	"testing"
)

func TestK8sActionCanonical(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		a    K8sAction
		want string
	}{
		{"get core namespaced", K8sAction{Verb: "get", Resource: "pods", Namespace: "prod", Name: "web-1"}, "get pods prod/web-1"},
		{"list grouped", K8sAction{Verb: "list", Resource: "deployments", Group: "apps", Namespace: "prod"}, "list deployments.apps prod/-"},
		{"list cluster-scoped", K8sAction{Verb: "list", Resource: "nodes"}, "list nodes -/-"},
		{"apply", K8sAction{Verb: "apply", Resource: "deployments", Group: "apps", Namespace: "prod", Name: "api"}, "apply deployments.apps prod/api"},
		{"logs", K8sAction{Verb: "logs", Resource: "pods", Namespace: "kube-system", Name: "coredns-abc"}, "logs pods kube-system/coredns-abc"},
		{"delete dotted name", K8sAction{Verb: "delete", Resource: "ingresses", Group: "networking.k8s.io", Namespace: "prod", Name: "web.example.com"}, "delete ingresses.networking.k8s.io prod/web.example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.a.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
			if got := tc.a.Canonical(); got != tc.want {
				t.Errorf("Canonical() = %q, want %q", got, tc.want)
			}
			// The canonical form must always be exactly three space-separated
			// tokens: the policy regexes and the audit token stream depend on it.
			if parts := strings.Split(tc.a.Canonical(), " "); len(parts) != 3 {
				t.Errorf("canonical %q must have exactly 3 tokens", tc.a.Canonical())
			}
		})
	}
}

func TestK8sActionValidateRejects(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		a    K8sAction
	}{
		{"unknown verb", K8sAction{Verb: "exec", Resource: "pods", Namespace: "p", Name: "x"}},
		{"empty verb", K8sAction{Resource: "pods", Namespace: "p", Name: "x"}},
		{"uppercase resource", K8sAction{Verb: "get", Resource: "Pods", Namespace: "p", Name: "x"}},
		{"resource with space", K8sAction{Verb: "get", Resource: "po ds", Namespace: "p", Name: "x"}},
		{"resource with slash", K8sAction{Verb: "get", Resource: "pods/exec", Namespace: "p", Name: "x"}},
		{"namespace with slash", K8sAction{Verb: "get", Resource: "pods", Namespace: "a/b", Name: "x"}},
		{"name with space", K8sAction{Verb: "get", Resource: "pods", Namespace: "p", Name: "a b"}},
		{"name with control char", K8sAction{Verb: "get", Resource: "pods", Namespace: "p", Name: "a\nb"}},
		{"group with space", K8sAction{Verb: "get", Resource: "pods", Group: "a b", Namespace: "p", Name: "x"}},
		{"get without name", K8sAction{Verb: "get", Resource: "pods", Namespace: "p"}},
		{"delete without name", K8sAction{Verb: "delete", Resource: "pods", Namespace: "p"}},
		{"apply without name", K8sAction{Verb: "apply", Resource: "configmaps", Namespace: "p"}},
		{"list with name", K8sAction{Verb: "list", Resource: "pods", Namespace: "p", Name: "x"}},
		{"logs without namespace", K8sAction{Verb: "logs", Resource: "pods", Name: "x"}},
		{"logs without name", K8sAction{Verb: "logs", Resource: "pods", Namespace: "p"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.a.Validate(); err == nil {
				t.Errorf("Validate must reject %+v", tc.a)
			}
		})
	}
}

// TestK8sActionCanonicalInjectionFree pins the anti-mismatch property: two
// different valid actions can never share a canonical form, because no
// component may contain the separators (space, slash between ns and name is
// disambiguated by charset: namespaces cannot contain dots... they CAN — names
// can contain dots but not slashes; the ns/name split is on the single "/").
func TestK8sActionCanonicalInjectionFree(t *testing.T) {
	t.Parallel()
	a := K8sAction{Verb: "get", Resource: "pods", Namespace: "prod", Name: "web-1"}
	b := K8sAction{Verb: "get", Resource: "pods", Namespace: "prod", Name: "web-2"}
	if a.Canonical() == b.Canonical() {
		t.Fatal("distinct actions must have distinct canonical forms")
	}
	// A crafted name cannot smuggle a namespace separator or a policy token:
	// Validate rejects every character that could collide the encoding.
	evil := K8sAction{Verb: "get", Resource: "pods", Namespace: "prod", Name: "x/../admin"}
	if err := evil.Validate(); err == nil {
		t.Fatal("slash in name must be rejected")
	}
}
