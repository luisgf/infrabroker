package broker

import (
	"context"
	"strings"
	"testing"

	"github.com/luisgf/infrabroker/internal/signer"
)

// TestK8sExecuteDryRunAudits pins #204: a k8s dry-run must leave an audit trail
// (dry_run_allowed / dry_run_denied), like the SSH dry-run path. Without it an
// agent could enumerate the whole k8s ActionPolicy surface silently.
func TestK8sExecuteDryRunAudits(t *testing.T) {
	sgn := &fakeK8sSigner{allow: map[string]bool{"get pods prod/web-1": true}}
	e, _ := newK8sEngine(t, sgn)
	caller := Caller{ID: "alice", Groups: []string{"platform"}}

	// Allowed dry-run: returns the decision, no token minted, no cluster call.
	res, err := e.K8sExecute(context.Background(), caller, "prod-k8s",
		signer.K8sAction{Verb: "get", Resource: "pods", Namespace: "prod", Name: "web-1"},
		nil, true /* dryRun */, K8sExecuteOpts{})
	if err != nil {
		t.Fatalf("allowed dry-run: %v", err)
	}
	if res.DryRun == nil || !res.DryRun.Allowed {
		t.Fatalf("expected an allowed dry-run decision, got %+v", res.DryRun)
	}

	// Denied dry-run: a resource the policy does not allow still returns a
	// decision (not an error) and must be audited too.
	res, err = e.K8sExecute(context.Background(), caller, "prod-k8s",
		signer.K8sAction{Verb: "get", Resource: "pods", Namespace: "prod", Name: "web-2"},
		nil, true, K8sExecuteOpts{})
	if err != nil {
		t.Fatalf("denied dry-run should return a decision, not an error: %v", err)
	}
	if res.DryRun == nil || res.DryRun.Allowed {
		t.Fatalf("expected a denied dry-run decision, got %+v", res.DryRun)
	}

	var sawAllowed, sawDenied bool
	for _, l := range readAuditLog(t, e) {
		if strings.Contains(l, "dry_run_allowed") {
			sawAllowed = true
		}
		if strings.Contains(l, "dry_run_denied") {
			sawDenied = true
		}
	}
	if !sawAllowed {
		t.Error("allowed k8s dry-run was not audited (dry_run_allowed missing)")
	}
	if !sawDenied {
		t.Error("denied k8s dry-run was not audited (dry_run_denied missing)")
	}
}
