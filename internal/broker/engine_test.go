package broker

import (
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
		{"target", []string{"bastion", "mid", "target"}}, // orden de marcado
	}
	for _, c := range cases {
		got, err := e.resolveChain(c.host)
		if err != nil {
			t.Fatalf("%s: error inesperado: %v", c.host, err)
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: cadena = %v, quiero %v", c.host, got, c.want)
		}
	}
}

// dryRunEngine construye un Engine en modo local con una command policy y un log
// de auditoría en un fichero temporal, apto para probar la ruta de dry-run sin
// red ni clave de CA (en dry-run no se firma).
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
	res, err := e.Execute(Caller{ID: "tester"}, "locked", "uptime", 0, ExecOptions{DryRun: true})
	if err != nil {
		t.Fatalf("dry-run no debe fallar: %v", err)
	}
	if res.DryRun == nil {
		t.Fatal("Result.DryRun debe estar poblado en dry-run")
	}
	if !res.DryRun.Allowed {
		t.Errorf("uptime debe permitirse: %+v", res.DryRun)
	}
	if res.DryRun.ForceCommand != "uptime" {
		t.Errorf("force-command = %q, quiero uptime", res.DryRun.ForceCommand)
	}
	// Dry-run no ejecuta: no hay salida ni serial.
	if res.Stdout != "" || res.Serial != 0 {
		t.Errorf("dry-run no debe producir salida/serial: %+v", res)
	}
}

func TestExecuteDryRunDenied(t *testing.T) {
	e := dryRunEngine(t)
	res, err := e.Execute(Caller{ID: "tester"}, "locked", "rm -rf /", 0, ExecOptions{DryRun: true})
	if err != nil {
		t.Fatalf("una denegación de política en dry-run es resultado, no error: %v", err)
	}
	if res.DryRun == nil || res.DryRun.Allowed {
		t.Errorf("rm -rf / debe denegarse: %+v", res.DryRun)
	}
	if res.DryRun.Reason == "" {
		t.Error("una denegación debe incluir motivo")
	}
}

func TestExecuteDryRunRequireApproval(t *testing.T) {
	e := dryRunEngine(t)
	// systemctl restart está en la allowlist Y casa require_approval: permitido
	// pero marcado como pendiente de aprobación humana.
	res, err := e.Execute(Caller{ID: "tester"}, "locked", "systemctl restart nginx", 0, ExecOptions{DryRun: true})
	if err != nil {
		t.Fatalf("dry-run no debe fallar: %v", err)
	}
	if res.DryRun == nil || !res.DryRun.Allowed {
		t.Fatalf("systemctl restart debe permitirse: %+v", res.DryRun)
	}
	if !res.DryRun.RequireApproval {
		t.Error("Result.DryRun.RequireApproval debe ser true")
	}
	// systemctl status: permitido y sin aprobación.
	res2, _ := e.Execute(Caller{ID: "tester"}, "locked", "systemctl status nginx", 0, ExecOptions{DryRun: true})
	if res2.DryRun == nil || !res2.DryRun.Allowed || res2.DryRun.RequireApproval {
		t.Errorf("systemctl status: permitido sin aprobación, got %+v", res2.DryRun)
	}
}

func TestExecuteDryRunUnknownHost(t *testing.T) {
	e := dryRunEngine(t)
	if _, err := e.Execute(Caller{ID: "tester"}, "nope", "uptime", 0, ExecOptions{DryRun: true}); err == nil {
		t.Error("host desconocido debe fallar incluso en dry-run")
	}
}

func TestResolveChainErrors(t *testing.T) {
	e := testEngine()
	if _, err := e.resolveChain("loopA"); err == nil {
		t.Error("esperaba error por ciclo de bastión")
	}
	if _, err := e.resolveChain("badjump"); err == nil {
		t.Error("esperaba error por bastión desconocido")
	}
	if _, err := e.resolveChain("inexistente"); err == nil {
		t.Error("esperaba error por host desconocido")
	}
}
