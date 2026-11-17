package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luisgf/infrabroker/internal/audit"
	"github.com/luisgf/infrabroker/internal/signer"
)

// TestHandleSignK8sSelfApprovedMarker pins #802: a self_approve caller that
// approves its own require_approval k8s action gets the supplementary
// "self_approved" marker after the committed "issued" record (as on the SSH
// branch, #118), so the waived four-eyes is distinguishable from a real
// approval. No marker for an action that needed no approval, nor for a
// trusted-forwarder approval.
func TestHandleSignK8sSelfApprovedMarker(t *testing.T) {
	t.Parallel()
	del := signer.WireRequest{TargetType: signer.TargetTypeK8s, Host: "prod-k8s",
		Role: signer.RoleTarget, Purpose: signer.PurposeOneshot,
		K8sVerb: "delete", K8sResource: "pods", K8sNamespace: "prod", K8sName: "web-1",
		Command: "delete pods prod/web-1", Approved: true}
	get := del
	get.K8sVerb, get.Command = "get", "get pods prod/web-1"
	rules := []signer.K8sRule{
		{Verbs: []string{"delete"}, Resources: []string{"pods"}, Effect: "require_approval"},
		{Verbs: []string{"get"}, Resources: []string{"pods"}, Effect: "allow"},
	}
	run := func(t *testing.T, req signer.WireRequest, forwarder bool) []audit.Entry {
		t.Helper()
		srv, auditPath := realK8sServer(t, rules)
		ct := srv.local.Clusters()
		cp := ct["prod-k8s"]
		cp.Groups = []string{"platform"}
		ct["prod-k8s"] = cp
		srv.callers = signer.CallerTable{"broker-1": {AllowedGroups: []string{"platform"}, SelfApprove: true}}
		if forwarder {
			srv.forwarders = map[string]struct{}{"broker-1": {}}
		}
		rec := httptest.NewRecorder()
		srv.handleSign(rec, signRequestAs(t, "broker-1", req))
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "k8s_token") {
			t.Fatalf("want an issued token, got %d: %s", rec.Code, rec.Body.String())
		}
		return readAuditEntries(t, auditPath)
	}

	t.Run("self-approved require_approval", func(t *testing.T) {
		t.Parallel()
		es := run(t, del, false)
		if len(es) != 2 || es[0].Outcome != "issued" || es[1].Outcome != "self_approved" {
			t.Fatalf("want issued then self_approved, got %+v", es)
		}
		m := es[1]
		if m.Caller != "broker-1" || m.TargetType != signer.TargetTypeK8s || m.Host != es[0].Host || m.Command != "" {
			t.Errorf("marker = %+v, want caller broker-1, k8s target type, issued host, no free-form command", m)
		}
	})
	t.Run("no approval needed", func(t *testing.T) {
		t.Parallel()
		es := run(t, get, false)
		if len(es) != 1 || es[0].Outcome != "issued" {
			t.Fatalf("want only issued, got %+v", es)
		}
	})
	t.Run("forwarder approval", func(t *testing.T) {
		t.Parallel()
		es := run(t, del, true)
		if len(es) != 1 || es[0].Outcome != "issued" {
			t.Fatalf("want only issued, got %+v", es)
		}
	})
}
