package broker

import (
	"context"
	"crypto/ed25519"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/luisgf/ssh-broker/internal/audit"
	"github.com/luisgf/ssh-broker/internal/signer"
)

func testEngine() *Engine {
	return &Engine{cfg: &Config{Hosts: map[string]HostConfig{
		"target":  {Addr: "t:22", Jump: "mid"},
		"mid":     {Addr: "m:22", Jump: "bastion"},
		"bastion": {Addr: "b:22"},
		"direct":  {Addr: "d:22"},
		"loopA":   {Addr: "a:22", Jump: "loopB"},
		"loopB":   {Addr: "b:22", Jump: "loopA"},
		"badjump": {Addr: "x:22", Jump: "nope"},
	}}}
}

func TestResolveChain(t *testing.T) {
	e := testEngine()
	cases := []struct {
		host string
		want []string
	}{
		{"direct", []string{"direct"}},
		{"target", []string{"bastion", "mid", "target"}}, // dial order
	}
	for _, c := range cases {
		got, err := e.resolveChain(c.host)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", c.host, err)
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: chain = %v, want %v", c.host, got, c.want)
		}
	}
}

// dryRunEngine builds a local-mode Engine with a command policy and an audit
// log in a temporary file, suitable for testing the dry-run path without
// network or CA key (no signing happens in dry-run).
func dryRunEngine(t *testing.T) *Engine {
	t.Helper()
	cfg := &Config{Hosts: map[string]HostConfig{
		"locked": {
			Addr: "h:22", User: "deploy", Principal: "host:locked",
			CommandPolicy: signer.CommandPolicy{
				Mode:            signer.CmdPolicyAllowlist,
				Allow:           []string{`^uptime$`, `^systemctl (status|restart) `},
				RequireApproval: []string{`^systemctl restart `},
			},
		},
	}}
	al, err := audit.Open(filepath.Join(t.TempDir(), "audit.log"), ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)))
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	t.Cleanup(func() { al.Close() })
	return &Engine{
		cfg:      cfg,
		sgn:      signer.NewLocal(nil, policyFromHosts(cfg), 2*time.Minute),
		auditLog: al,
		maxTTL:   2 * time.Minute,
	}
}

func TestExecuteDryRunAllowed(t *testing.T) {
	e := dryRunEngine(t)
	res, err := e.Execute(context.Background(), Caller{ID: "tester"}, "locked", "uptime", 0, ExecOptions{DryRun: true})
	if err != nil {
		t.Fatalf("dry-run must not fail: %v", err)
	}
	if res.DryRun == nil {
		t.Fatal("Result.DryRun must be populated in dry-run")
	}
	if !res.DryRun.Allowed {
		t.Errorf("uptime must be allowed: %+v", res.DryRun)
	}
	if res.DryRun.ForceCommand != "uptime" {
		t.Errorf("force-command = %q, want uptime", res.DryRun.ForceCommand)
	}
	// Dry-run does not execute: no stdout or serial.
	if res.Stdout != "" || res.Serial != 0 {
		t.Errorf("dry-run must not produce output/serial: %+v", res)
	}
}

func TestExecuteDryRunDenied(t *testing.T) {
	e := dryRunEngine(t)
	res, err := e.Execute(context.Background(), Caller{ID: "tester"}, "locked", "rm -rf /", 0, ExecOptions{DryRun: true})
	if err != nil {
		t.Fatalf("a policy denial in dry-run is a result, not an error: %v", err)
	}
	if res.DryRun == nil || res.DryRun.Allowed {
		t.Errorf("rm -rf / must be denied: %+v", res.DryRun)
	}
	if res.DryRun.Reason == "" {
		t.Error("a denial must include a reason")
	}
}

func TestExecuteDryRunRequireApproval(t *testing.T) {
	e := dryRunEngine(t)
	// systemctl restart is in the allowlist AND matches require_approval: allowed
	// but flagged as pending human approval.
	res, err := e.Execute(context.Background(), Caller{ID: "tester"}, "locked", "systemctl restart nginx", 0, ExecOptions{DryRun: true})
	if err != nil {
		t.Fatalf("dry-run must not fail: %v", err)
	}
	if res.DryRun == nil || !res.DryRun.Allowed {
		t.Fatalf("systemctl restart must be allowed: %+v", res.DryRun)
	}
	if !res.DryRun.RequireApproval {
		t.Error("Result.DryRun.RequireApproval must be true")
	}
	// systemctl status: allowed and no approval needed.
	res2, _ := e.Execute(context.Background(), Caller{ID: "tester"}, "locked", "systemctl status nginx", 0, ExecOptions{DryRun: true})
	if res2.DryRun == nil || !res2.DryRun.Allowed || res2.DryRun.RequireApproval {
		t.Errorf("systemctl status: allowed without approval, got %+v", res2.DryRun)
	}
}

func TestExecuteDryRunUnknownHost(t *testing.T) {
	e := dryRunEngine(t)
	if _, err := e.Execute(context.Background(), Caller{ID: "tester"}, "nope", "uptime", 0, ExecOptions{DryRun: true}); err == nil {
		t.Error("unknown host must fail even in dry-run")
	}
}

func TestResolveChainErrors(t *testing.T) {
	e := testEngine()
	if _, err := e.resolveChain("loopA"); err == nil {
		t.Error("expected error for bastion cycle")
	}
	if _, err := e.resolveChain("badjump"); err == nil {
		t.Error("expected error for unknown bastion")
	}
	if _, err := e.resolveChain("inexistente"); err == nil {
		t.Error("expected error for unknown host")
	}
}
