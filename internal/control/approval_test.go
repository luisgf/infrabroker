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

	got, err := r.Decide(a.ID, true, "alice", 0)
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
	got, err := r.Decide(a.ID, false, "bob", 0)
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
	if _, err := r.Decide(a.ID, true, "alice", 0); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Decide(a.ID, true, "alice", 0); err == nil {
		t.Error("no debe poder decidirse dos veces")
	}
}

func TestRegistryUnknownID(t *testing.T) {
	t.Parallel()
	r := NewRegistry(time.Minute)
	if _, err := r.Decide("nope", true, "alice", 0); err == nil {
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
		t.Errorf("after TTL must expire, status = %s", got.Status)
	}
	// An expired request cannot be approved.
	if _, err := r.Decide(a.ID, true, "alice", 0); err == nil {
		t.Error("an expired request must not be approvable")
	}
}

func TestRegistryApprovedRequestExpiresIfNotConsumed(t *testing.T) {
	t.Parallel()
	const ttl = 20 * time.Millisecond
	r := NewRegistry(ttl)
	a, _ := r.Create(sampleReq(), "broker-1", nil)
	if _, err := r.Decide(a.ID, true, "alice", 0); err != nil {
		t.Fatal(err)
	}

	time.Sleep(2 * ttl)

	got, ok := r.Get(a.ID)
	if !ok {
		t.Fatal("approved request should not be purged yet")
	}
	if got.Status != StatusExpired {
		t.Fatalf("approved request not consumed within TTL must expire, got %s", got.Status)
	}
	if started, retry := r.BeginConsume(a.ID); started || retry {
		t.Fatal("expired approved request must not be consumable")
	}
}

func TestRegistryConsumeOnce(t *testing.T) {
	t.Parallel()
	r := NewRegistry(time.Minute)
	a, _ := r.Create(sampleReq(), "broker-1", nil)
	// Not consumable while pending.
	if started, retry := r.BeginConsume(a.ID); started || retry {
		t.Error("a pending request must not be consumable")
	}
	if _, err := r.Decide(a.ID, true, "alice", 0); err != nil {
		t.Fatal(err)
	}
	if started, retry := r.BeginConsume(a.ID); !started || retry {
		t.Error("debe consumirse la primera vez tras aprobar")
	}
	if started, retry := r.BeginConsume(a.ID); started || !retry {
		t.Error("una aprobación en emisión debe pedir reintento, no emitir dos veces")
	}
	r.FinishConsume(a.ID, false)
	if started, retry := r.BeginConsume(a.ID); !started || retry {
		t.Error("tras un fallo de emisión debe poder reintentarse")
	}
	r.FinishConsume(a.ID, true)
	if started, retry := r.BeginConsume(a.ID); started || retry {
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

func TestRegistryPurgesOldEntries(t *testing.T) {
	t.Parallel()
	const ttl = 30 * time.Millisecond
	r := NewRegistry(ttl)

	// Three entries that reach different states: expired pending, denied,
	// and approved+consumed. All must be purged once 2×TTL has elapsed.
	expired, _ := r.Create(sampleReq(), "broker-1", nil)
	denied, _ := r.Create(sampleReq(), "broker-1", nil)
	approved, _ := r.Create(sampleReq(), "broker-1", nil)
	if _, err := r.Decide(denied.ID, false, "bob", 0); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Decide(approved.ID, true, "alice", 0); err != nil {
		t.Fatal(err)
	}
	if started, retry := r.BeginConsume(approved.ID); !started || retry {
		t.Fatal("approved entry should be consumable")
	}
	r.FinishConsume(approved.ID, true)

	time.Sleep(3 * ttl)

	// Purge runs opportunistically on List (and Create).
	if got := len(r.List()); got != 0 {
		t.Fatalf("registry should be empty after purge, has %d entries", got)
	}
	for _, id := range []string{expired.ID, denied.ID, approved.ID} {
		if _, ok := r.Get(id); ok {
			t.Errorf("entry %s should have been purged", id)
		}
	}
}

func TestRegistryRetainsRecentEntries(t *testing.T) {
	t.Parallel()
	r := NewRegistry(time.Minute)

	// A freshly decided entry must survive the purge: the broker still needs
	// to poll its result.
	a, _ := r.Create(sampleReq(), "broker-1", nil)
	if _, err := r.Decide(a.ID, true, "alice", 0); err != nil {
		t.Fatal(err)
	}
	if got := len(r.List()); got != 1 {
		t.Fatalf("recent entry purged prematurely: %d entries", got)
	}
	if _, ok := r.Get(a.ID); !ok {
		t.Error("recent decided entry must remain retrievable")
	}
}
