package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
