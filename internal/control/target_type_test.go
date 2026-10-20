package control

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luisgf/infrabroker/internal/signer"
)

func k8sWireReq() signer.WireRequest {
	return signer.WireRequest{
		TargetType: signer.TargetTypeK8s, Host: "prod-aks", Role: signer.RoleTarget, Purpose: signer.PurposeOneshot,
		Command: "delete pods prod/web-1", K8sVerb: "delete", K8sResource: "pods", K8sNamespace: "prod", K8sName: "web-1",
	}
}

// TestApprovalCarriesTargetType: an approval records the request's target
// family ("k8s", or "" for SSH whether target_type was absent or "ssh"),
// exposes it as target_type in its JSON (GET /v1/approvals, the webhook
// payload), and restores it from the persisted request after a restart
// without a schema change (#664).
func TestApprovalCarriesTargetType(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "state.db")
	r1, err := NewRegistryDB(time.Minute, openRegistryDB(t, path))
	if err != nil {
		t.Fatalf("NewRegistryDB: %v", err)
	}
	k8s, err := r1.Create(k8sWireReq(), "broker-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	sshReq := testWireReq("reboot")
	sshReq.TargetType = signer.TargetTypeSSH
	ssh, err := r1.Create(sshReq, "broker-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if k8s.TargetType != signer.TargetTypeK8s || ssh.TargetType != "" {
		t.Fatalf("TargetType = %q / %q, want k8s / \"\"", k8s.TargetType, ssh.TargetType)
	}
	js, _ := json.Marshal(k8s)
	if !strings.Contains(string(js), `"target_type":"k8s"`) {
		t.Errorf("approval JSON must carry target_type, got %s", js)
	}
	if js, _ := json.Marshal(ssh); strings.Contains(string(js), "target_type") {
		t.Errorf("an SSH approval must omit target_type, got %s", js)
	}

	r2, err := NewRegistryDB(time.Minute, openRegistryDB(t, path))
	if err != nil {
		t.Fatalf("NewRegistryDB after restart: %v", err)
	}
	if got, ok := r2.Get(k8s.ID); !ok || got.TargetType != signer.TargetTypeK8s {
		t.Errorf("restored k8s approval TargetType = %q (found %v), want k8s", got.TargetType, ok)
	}
	if got, ok := r2.Get(ssh.ID); !ok || got.TargetType != "" {
		t.Errorf("restored SSH approval TargetType = %q (found %v), want \"\"", got.TargetType, ok)
	}
}

// TestTeamsFactsLabelCluster: the Teams facts label a k8s request's target
// "Cluster", an SSH one "Host" (#664).
func TestTeamsFactsLabelCluster(t *testing.T) {
	n := NewTeamsNotifier("https://example.invalid/hook", TeamsFormatWorkflow, "")
	label := func(a Approval) string {
		for _, f := range n.approvalFacts(a) {
			if f["value"] == a.Host {
				return f["name"].(string)
			}
		}
		t.Fatalf("no fact carries the target %q", a.Host)
		return ""
	}
	a := sampleApproval()
	if got := label(a); got != "Host" {
		t.Errorf("SSH target label = %q, want Host", got)
	}
	a.TargetType = signer.TargetTypeK8s
	a.Host = "prod-aks"
	if got := label(a); got != "Cluster" {
		t.Errorf("k8s target label = %q, want Cluster", got)
	}
}
