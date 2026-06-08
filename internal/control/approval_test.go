package control

import (
	"testing"
	"time"

	"github.com/luisgf/ssh-broker/internal/signer"
)

func sampleReq() signer.WireRequest {
	return signer.WireRequest{Host: "web01", Command: "systemctl restart nginx", PublicKey: "ssh-ed25519 AAAA"}
}

func TestRegistryCreateAndApprove(t *testing.T) {
	t.Parallel()
	r := NewRegistry(time.Minute)
	a, err := r.Create(sampleReq(), "broker-1", &signer.DecisionInfo{MatchedRule: "require_approval:^systemctl restart "})
	if err != nil {
		t.Fatal(err)
	}
	if a.Status != StatusPending {
		t.Errorf("estado inicial = %s, quiero pending", a.Status)
	}
	if a.ID == "" {
		t.Error("debe asignarse un id")
	}

	got, err := r.Decide(a.ID, true, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusApproved || got.DecidedBy != "alice" {
		t.Errorf("tras aprobar: %+v", got)
	}
}

func TestRegistryDeny(t *testing.T) {
	t.Parallel()
	r := NewRegistry(time.Minute)
	a, _ := r.Create(sampleReq(), "broker-1", nil)
	got, err := r.Decide(a.ID, false, "bob")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusDenied {
		t.Errorf("estado = %s, quiero denied", got.Status)
	}
}

func TestRegistryDecideTwiceFails(t *testing.T) {
	t.Parallel()
	r := NewRegistry(time.Minute)
	a, _ := r.Create(sampleReq(), "broker-1", nil)
	if _, err := r.Decide(a.ID, true, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Decide(a.ID, true, "alice"); err == nil {
		t.Error("no debe poder decidirse dos veces")
	}
}

func TestRegistryUnknownID(t *testing.T) {
	t.Parallel()
	r := NewRegistry(time.Minute)
	if _, err := r.Decide("nope", true, "alice"); err == nil {
		t.Error("id desconocido debe fallar")
	}
	if _, ok := r.Get("nope"); ok {
		t.Error("Get de id desconocido debe ser false")
	}
}

func TestRegistryExpiry(t *testing.T) {
	t.Parallel()
	r := NewRegistry(10 * time.Millisecond)
	a, _ := r.Create(sampleReq(), "broker-1", nil)
	time.Sleep(25 * time.Millisecond)
	got, _ := r.Get(a.ID)
	if got.Status != StatusExpired {
		t.Errorf("tras TTL debe expirar, estado = %s", got.Status)
	}
	// Una solicitud expirada no puede aprobarse.
	if _, err := r.Decide(a.ID, true, "alice"); err == nil {
		t.Error("no debe poder aprobarse una solicitud expirada")
	}
}

func TestRegistryConsumeOnce(t *testing.T) {
	t.Parallel()
	r := NewRegistry(time.Minute)
	a, _ := r.Create(sampleReq(), "broker-1", nil)
	// No consumible mientras está pendiente.
	if r.Consume(a.ID) {
		t.Error("no debe consumirse una solicitud pendiente")
	}
	if _, err := r.Decide(a.ID, true, "alice"); err != nil {
		t.Fatal(err)
	}
	if !r.Consume(a.ID) {
		t.Error("debe consumirse la primera vez tras aprobar")
	}
	if r.Consume(a.ID) {
		t.Error("no debe consumirse dos veces")
	}
}

func TestRegistryRequestRoundTrip(t *testing.T) {
	t.Parallel()
	r := NewRegistry(time.Minute)
	req := sampleReq()
	a, _ := r.Create(req, "broker-1", nil)
	got, ok := r.Request(a.ID)
	if !ok {
		t.Fatal("Request debe devolver la petición almacenada")
	}
	if got.Command != req.Command || got.Host != req.Host {
		t.Errorf("petición almacenada distinta: %+v", got)
	}
}
