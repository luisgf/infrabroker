package broker

import (
	"testing"
	"time"
)

// TestPolicyFromHostsBastionGate verifies that local mode no longer marks every
// host as a bastion: only hosts referenced as another host's Jump target (or
// explicitly marked allow_as_bastion) get permit-port-forwarding, matching the
// remote-signer default-deny gate.
func TestPolicyFromHostsBastionGate(t *testing.T) {
	t.Parallel()
	cfg := &Config{Hosts: map[string]HostConfig{
		"leaf":     {Addr: "10.0.0.1:22", User: "deploy", Principal: "host:leaf"},
		"bastion":  {Addr: "10.0.0.2:22", User: "deploy", Principal: "host:bastion"},
		"target":   {Addr: "10.0.0.3:22", User: "deploy", Principal: "host:target", Jump: "bastion"},
		"explicit": {Addr: "10.0.0.4:22", User: "deploy", Principal: "host:explicit", AllowAsBastion: true},
	}}
	pt := policyFromHosts(cfg)
	if pt["leaf"].AllowAsBastion {
		t.Error("a leaf host must NOT be allow_as_bastion in local mode")
	}
	if !pt["bastion"].AllowAsBastion {
		t.Error("a host referenced as a Jump target must be allow_as_bastion")
	}
	if !pt["explicit"].AllowAsBastion {
		t.Error("an explicitly-marked host must be allow_as_bastion")
	}
	if pt["target"].AllowAsBastion {
		t.Error("a pure target (not referenced as a jump) must NOT be allow_as_bastion")
	}
}

// TestCheckoutOwnedDoesNotMutateOnForeignCaller is the regression test for the
// ordering bug where SessionExec mutated busy/lastUsed (via checkout) BEFORE the
// C1 ownership check, letting a non-owner keep another caller's session alive
// and block the reaper.
func TestCheckoutOwnedDoesNotMutateOnForeignCaller(t *testing.T) {
	t.Parallel()
	m := newTestSessionManager(t)
	s := dummySession("s1", "alice")
	old := time.Now().Add(-time.Hour)
	s.lastUsed = old
	_ = m.add(s)

	// A foreign caller gets owned=false and must NOT touch busy/lastUsed.
	got, found, owned := m.checkoutOwned("s1", "mallory")
	if !found || owned {
		t.Fatalf("foreign caller: found=%v owned=%v, want found=true owned=false", found, owned)
	}
	m.mu.Lock()
	busy, last := got.busy, got.lastUsed
	m.mu.Unlock()
	if busy != 0 {
		t.Errorf("foreign caller must not increment busy, got %d", busy)
	}
	if !last.Equal(old) {
		t.Error("foreign caller must not refresh lastUsed")
	}

	// The owner does check out and mutate.
	_, found, owned = m.checkoutOwned("s1", "alice")
	if !found || !owned {
		t.Fatalf("owner: found=%v owned=%v, want both true", found, owned)
	}
	m.mu.Lock()
	busy = got.busy
	m.mu.Unlock()
	if busy != 1 {
		t.Errorf("owner checkout must set busy=1, got %d", busy)
	}

	// Unknown id.
	if _, found, _ := m.checkoutOwned("nope", "alice"); found {
		t.Error("unknown id must return found=false")
	}
}
