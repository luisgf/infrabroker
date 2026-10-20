package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/luisgf/infrabroker/internal/control"
	"github.com/luisgf/infrabroker/internal/signer"
)

// stubSignerStatus answers every request with the given status and body.
func stubSignerStatus(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, body, status)
	}))
}

// dryRunCases covers the pure dry-run branch and the executable preflight
// branch (which runs the guardrails first) of handleSign (#660).
var dryRunCases = []struct {
	name      string
	preflight bool
}{
	{name: "dry_run", preflight: false},
	{name: "preflight", preflight: true},
}

// TestControlPlaneDryRunSignerOutageIs502Error: a signer 5xx on a dry-run or
// preflight is an infrastructure error — 502 + an audited "error" record with
// dry_run=true — exactly like the live path, not a 403 policy denial (#660).
func TestControlPlaneDryRunSignerOutageIs502Error(t *testing.T) {
	for _, tc := range dryRunCases {
		t.Run(tc.name, func(t *testing.T) {
			sig := stubSignerStatus(t, http.StatusInternalServerError, "ca backend down")
			defer sig.Close()
			s, auditPath := testServerWithAudit(t, sig.URL)

			wr := wireReq(t, "uptime")
			wr.DryRun, wr.Preflight = true, tc.preflight
			w := httptest.NewRecorder()
			s.handleSign(w, signReq(t, "broker-1", wr))
			if w.Code != http.StatusBadGateway {
				t.Fatalf("signer 5xx on a dry-run must be 502, got %d: %s", w.Code, w.Body.String())
			}
			e := lastAuditEntry(t, auditPath)
			if e.Outcome != "error" || !e.DryRun {
				t.Errorf("audit = outcome %q dry_run %v, want error/true", e.Outcome, e.DryRun)
			}
			if e.Caller != "broker-1" || e.Host != "web01" || e.Command != "uptime" {
				t.Errorf("audit record lost the request identity: %+v", e)
			}
			if !strings.Contains(e.Err, "ca backend down") {
				t.Errorf("audit err must carry the signer's reason, got %q", e.Err)
			}
		})
	}
}

// TestControlPlaneDryRunSignerDenialIs403Denied: a signer 4xx on a dry-run or
// preflight stays a policy denial — 403 — and is now audited "denied" with
// dry_run=true (it used to leave no record at all) (#660).
func TestControlPlaneDryRunSignerDenialIs403Denied(t *testing.T) {
	for _, tc := range dryRunCases {
		t.Run(tc.name, func(t *testing.T) {
			sig := stubSignerStatus(t, http.StatusForbidden, "frozen: caller broker-1 is frozen")
			defer sig.Close()
			s, auditPath := testServerWithAudit(t, sig.URL)

			wr := wireReq(t, "uptime")
			wr.DryRun, wr.Preflight = true, tc.preflight
			w := httptest.NewRecorder()
			s.handleSign(w, signReq(t, "broker-1", wr))
			if w.Code != http.StatusForbidden {
				t.Fatalf("signer denial on a dry-run must be 403, got %d: %s", w.Code, w.Body.String())
			}
			e := lastAuditEntry(t, auditPath)
			if e.Outcome != "denied" || !e.DryRun {
				t.Errorf("audit = outcome %q dry_run %v, want denied/true", e.Outcome, e.DryRun)
			}
			if !strings.Contains(e.Err, "frozen") {
				t.Errorf("audit err must carry the signer's reason, got %q", e.Err)
			}
		})
	}
}

// TestControlPlaneDryRunK8sOutageCarriesTargetType: the dry-run outage record
// of a cluster request carries target_type=k8s (#660).
func TestControlPlaneDryRunK8sOutageCarriesTargetType(t *testing.T) {
	sig := stubSignerStatus(t, http.StatusBadGateway, "mint failed")
	defer sig.Close()
	s, auditPath := testServerWithAudit(t, sig.URL)

	wr := signer.WireRequest{
		Host: "prod-aks", Role: signer.RoleTarget, Purpose: signer.PurposeOneshot,
		TargetType: signer.TargetTypeK8s, K8sVerb: "get", K8sResource: "pods", K8sNamespace: "default",
		Command: "get pods -n default", DryRun: true,
	}
	w := httptest.NewRecorder()
	s.handleSign(w, signReq(t, "broker-1", wr))
	if w.Code != http.StatusBadGateway {
		t.Fatalf("signer 5xx on a k8s dry-run must be 502, got %d: %s", w.Code, w.Body.String())
	}
	if e := lastAuditEntry(t, auditPath); e.Outcome != "error" || !e.DryRun || e.TargetType != signer.TargetTypeK8s {
		t.Errorf("audit = outcome %q dry_run %v target_type %q, want error/true/k8s", e.Outcome, e.DryRun, e.TargetType)
	}
}

// TestControlPlaneGuardrailDryRunOutageIs502Error: in enforce mode an anomaly
// triggers a dry-run before escalating to a human; a signer outage on that
// dry-run is 502 + "error", not "command not allowed" (#660).
func TestControlPlaneGuardrailDryRunOutageIs502Error(t *testing.T) {
	sig := stubSigner(t)
	defer sig.Close()
	s, auditPath := testServerWithAudit(t, sig.URL)
	s.behavior = control.NewBehaviorTracker(control.BehaviorConfig{Mode: control.BehaviorEnforce})

	// Baseline against a healthy signer.
	w := httptest.NewRecorder()
	s.handleSign(w, signReq(t, "broker-1", wireReq(t, "uptime")))
	if w.Code != http.StatusOK {
		t.Fatalf("baseline must issue (200), got %d: %s", w.Code, w.Body.String())
	}

	// The signer goes down; a new host is an anomaly → guardrail dry-run.
	down := stubSignerStatus(t, http.StatusServiceUnavailable, "signer restarting")
	defer down.Close()
	s.remote = signer.NewRemote(down.URL, nil, time.Second)
	r := wireReq(t, "uptime")
	r.Host = "db99"
	w = httptest.NewRecorder()
	s.handleSign(w, signReq(t, "broker-1", r))
	if w.Code != http.StatusBadGateway {
		t.Fatalf("signer outage on the guardrail dry-run must be 502, got %d: %s", w.Code, w.Body.String())
	}
	if e := lastAuditEntry(t, auditPath); e.Outcome != "error" || e.Anomaly == "" {
		t.Errorf("audit = outcome %q anomaly %q, want error with the anomaly", e.Outcome, e.Anomaly)
	}
}
