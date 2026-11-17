package broker

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/luisgf/infrabroker/internal/signer"
)

// capEngine builds an Engine over a real local signer (ed25519 CA) with a
// bastion/target pair. bastionTTL/targetTTL are the hosts' max_ttl (0 = the
// signer default).
func capEngine(t *testing.T, withBastion bool, bastionTTL, targetTTL time.Duration) *Engine {
	t.Helper()
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caSigner, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &Config{Hosts: map[string]HostConfig{
		"bastion": {Addr: "b:22", User: "jump", Principal: "host:bastion", HostKey: hostKeyLine(t)},
		"target":  {Addr: "t:22", User: "deploy", Principal: "host:target", HostKey: hostKeyLine(t)},
	}}
	if withBastion {
		tg := cfg.Hosts["target"]
		tg.Jump = "bastion"
		cfg.Hosts["target"] = tg
	}
	pt := policyFromHosts(cfg)
	if bastionTTL > 0 {
		hp := pt["bastion"]
		hp.MaxTTL = bastionTTL
		pt["bastion"] = hp
	}
	if targetTTL > 0 {
		hp := pt["target"]
		hp.MaxTTL = targetTTL
		pt["target"] = hp
	}
	return &Engine{
		cfg:    cfg,
		hosts:  hostInfosFromConfig(cfg),
		sgn:    signer.NewLocal(caSigner, pt, 10*time.Minute),
		maxTTL: 10 * time.Minute,
	}
}

func hostInfosFromConfig(cfg *Config) map[string]signer.HostInfo {
	m := make(map[string]signer.HostInfo, len(cfg.Hosts))
	for n, hc := range cfg.Hosts {
		m[n] = signer.HostInfo{Addr: hc.Addr, User: hc.User, HostKey: hc.HostKey, Jump: hc.Jump}
	}
	return m
}

// The session cap must be the earliest ValidBefore across ALL hop certificates:
// a bastion with a shorter max_ttl must end the session when its own credential
// expires, not when the (longer) target certificate does (#809).
func TestBuildHopsWithPrefixCapIsEarliestHopExpiry(t *testing.T) {
	cases := []struct {
		name        string
		withBastion bool
		bastionTTL  time.Duration
		targetTTL   time.Duration
		capHop      int // index of the hop whose expiry must equal the cap
	}{
		{"short bastion caps the session", true, 60 * time.Second, 0, 0},
		{"longer bastion keeps target expiry", true, 0, 2 * time.Minute, 1},
		{"no bastion keeps target expiry", false, 0, 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := capEngine(t, tc.withBastion, tc.bastionTTL, tc.targetTTL)
			hops, _, _, _, _, notAfter, err := e.buildHopsWithPrefix(context.Background(), Caller{ID: "alice"}, "target", 10*time.Minute, signer.PurposeSession, "exec", ExecOptions{})
			if err != nil {
				t.Fatalf("buildHopsWithPrefix: %v", err)
			}
			want := time.Unix(int64(hops[tc.capHop].Certificate.ValidBefore), 0)
			if !notAfter.Equal(want) {
				t.Fatalf("cap = %v, want hop[%d] expiry %v", notAfter, tc.capHop, want)
			}
			for i, h := range hops {
				if exp := time.Unix(int64(h.Certificate.ValidBefore), 0); notAfter.After(exp) {
					t.Fatalf("cap %v outlives hop[%d] cert %v", notAfter, i, exp)
				}
			}
		})
	}
}
