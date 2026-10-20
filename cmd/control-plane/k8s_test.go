package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/luisgf/infrabroker/internal/audit"
	"github.com/luisgf/infrabroker/internal/signer"
)

// stubK8sSigner is a signer that returns a bound token for allowed k8s
// actions, and gates "delete" behind approval. It mirrors the SSH stub.
func stubK8sSigner(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req signer.WireRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		needsApproval := req.K8sVerb == "delete"
		if req.DryRun {
			_ = json.NewEncoder(w).Encode(signer.WireResponse{Decision: &signer.DecisionInfo{Allowed: true, RequireApproval: needsApproval}})
			return
		}
		if needsApproval && !req.Approved {
			_ = json.NewEncoder(w).Encode(signer.WireResponse{Decision: &signer.DecisionInfo{Allowed: true, RequireApproval: true, MatchedRule: "require_approval:delete"}})
			return
		}
		_ = json.NewEncoder(w).Encode(signer.WireResponse{K8sToken: "bound-" + req.K8sVerb, Serial: 9})
	}))
}

func k8sSignReq(t *testing.T, cn, verb, resource, namespace, name string) *http.Request {
	t.Helper()
	canonical := verb + " " + resource + " " + namespace + "/" + name
	return req(t, "POST", "/v1/sign", cn, signer.WireRequest{
		TargetType: signer.TargetTypeK8s, Host: "lab-k8s", Role: signer.RoleTarget, Purpose: signer.PurposeOneshot,
		Command: canonical, K8sVerb: verb, K8sResource: resource, K8sNamespace: namespace, K8sName: name,
	})
}

// TestControlPlaneForwardsK8sToken: an allowed k8s action returns the bound
// token straight through (no certificate path).
func TestControlPlaneForwardsK8sToken(t *testing.T) {
	sig := stubK8sSigner(t)
	defer sig.Close()
	s := testServer(t, sig.URL)

	w := httptest.NewRecorder()
	s.handleSign(w, k8sSignReq(t, "broker-1", "get", "pods", "prod", "web-1"))
	if w.Code != http.StatusOK {
		t.Fatalf("allowed k8s action must return 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp signer.WireResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.K8sToken != "bound-get" || resp.Certificate != "" {
		t.Errorf("expected a bound token, got %+v", resp)
	}
}

// TestControlPlaneK8sApprovalFlow: a delete is gated, the approver sees the
// canonical action, and the approved poll returns the bound token.
func TestControlPlaneK8sApprovalFlow(t *testing.T) {
	sig := stubK8sSigner(t)
	defer sig.Close()
	s := testServer(t, sig.URL)

	w := httptest.NewRecorder()
	s.handleSign(w, k8sSignReq(t, "broker-1", "delete", "pods", "prod", "web-1"))
	if w.Code != http.StatusAccepted {
		t.Fatalf("delete must be gated (202), got %d: %s", w.Code, w.Body.String())
	}
	var acc map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &acc); err != nil {
		t.Fatal(err)
	}
	id := acc["approval_id"]

	// The approver sees the canonical action in the registry.
	a, ok := s.registry.Get(id)
	if !ok || a.Command != "delete pods prod/web-1" {
		t.Fatalf("approver must see the canonical action: %+v", a)
	}

	// Approve, then poll: the bound token comes back.
	if _, err := s.registry.Decide(id, true, "broker-admin", 0); err != nil {
		t.Fatal(err)
	}
	pw := httptest.NewRecorder()
	pr := req(t, "GET", "/v1/sign/result/"+id, "broker-1", nil)
	pr.SetPathValue("id", id)
	s.handleResult(pw, pr)
	if pw.Code != http.StatusOK {
		t.Fatalf("approved poll must return 200, got %d: %s", pw.Code, pw.Body.String())
	}
	var resp signer.WireResponse
	if err := json.Unmarshal(pw.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.K8sToken != "bound-delete" {
		t.Errorf("approved k8s poll must return the bound token, got %+v", resp)
	}
}

// TestControlPlaneForwardsClusters: GET /v1/clusters is forwarded to the
// signer with the broker CN in X-On-Behalf-Of.
func TestControlPlaneForwardsClusters(t *testing.T) {
	var gotOBO string
	sig := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotOBO = r.Header.Get(signer.HeaderOnBehalfOf)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]signer.WireClusterInfo{
			"lab-k8s": {APIServer: "https://10.0.0.5:6443", CACertPEM: "pem", Groups: []string{"platform"}},
		})
	}))
	defer sig.Close()
	s := testServer(t, sig.URL)

	w := httptest.NewRecorder()
	s.handleClusters(w, req(t, "GET", "/v1/clusters", "broker-1", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("clusters forward must return 200, got %d", w.Code)
	}
	if gotOBO != "broker-1" {
		t.Errorf("on-behalf-of must carry the broker CN, got %q", gotOBO)
	}
	if !strings.Contains(w.Body.String(), "lab-k8s") {
		t.Errorf("cluster list must be forwarded: %s", w.Body.String())
	}
}

// auditEntries reads every record of the audit log at path.
func auditEntries(t *testing.T, path string) []audit.Entry {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []audit.Entry
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
		var e audit.Entry
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatalf("parse audit line %q: %v", line, err)
		}
		out = append(out, e)
	}
	return out
}

// TestControlPlaneK8sAuditRecordsCarryTargetType: every control-plane record
// of a k8s request — approval-required, the allow and deny decisions, the
// approval-denied poll, approval-granted — carries target_type=k8s, and the
// approval itself exposes it, so cluster approvals are distinguishable from
// SSH ones (#664).
func TestControlPlaneK8sAuditRecordsCarryTargetType(t *testing.T) {
	sig := stubK8sSigner(t)
	defer sig.Close()
	s, auditPath := testServerWithAudit(t, sig.URL)

	gate := func() string {
		w := httptest.NewRecorder()
		s.handleSign(w, k8sSignReq(t, "broker-1", "delete", "pods", "prod", "web-1"))
		if w.Code != http.StatusAccepted {
			t.Fatalf("delete must be gated (202), got %d: %s", w.Code, w.Body.String())
		}
		var acc map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &acc); err != nil {
			t.Fatal(err)
		}
		return acc["approval_id"]
	}
	decide := func(id string, approve bool) {
		w := httptest.NewRecorder()
		dr := req(t, "POST", "/v1/approvals/"+id, "broker-admin", map[string]bool{"approve": approve})
		dr.SetPathValue("id", id)
		s.handleApprovalDecide(w, dr)
		if w.Code != http.StatusOK {
			t.Fatalf("decision must return 200, got %d: %s", w.Code, w.Body.String())
		}
	}
	poll := func(id string) {
		w := httptest.NewRecorder()
		pr := req(t, "GET", "/v1/sign/result/"+id, "broker-1", nil)
		pr.SetPathValue("id", id)
		s.handleResult(w, pr)
	}

	approved := gate()
	if a, _ := s.registry.Get(approved); a.TargetType != signer.TargetTypeK8s {
		t.Errorf("approval TargetType = %q, want k8s", a.TargetType)
	}
	decide(approved, true)
	poll(approved)
	denied := gate()
	decide(denied, false)
	poll(denied)

	seen := map[string]bool{}
	for _, e := range auditEntries(t, auditPath) {
		seen[e.Outcome] = true
		if e.TargetType != signer.TargetTypeK8s {
			t.Errorf("record %q must carry target_type=k8s, got %q", e.Outcome, e.TargetType)
		}
	}
	for _, want := range []string{"approval-required", "approval-decision-allow", "approval-granted", "approval-denied"} {
		if !seen[want] {
			t.Errorf("expected a %q record, got outcomes %v", want, seen)
		}
	}
}
