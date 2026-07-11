package broker

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/luisgf/infrabroker/internal/signer"
	"golang.org/x/crypto/ssh"
)

// hostKeyLine returns a fresh valid authorized_keys line.
func hostKeyLine(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh pubkey: %v", err)
	}
	return string(ssh.MarshalAuthorizedKey(sshPub))
}

// TestPruneHostKeyCache pins #215: after a remote host refresh, memoised
// host-key parses whose line left the live host set are evicted, so a rotated
// key does not leave its old (and its negative-cached) entry behind forever.
func TestPruneHostKeyCache(t *testing.T) {
	e := &Engine{}
	keyA := hostKeyLine(t)
	keyB := hostKeyLine(t)

	// Populate the cache: two valid keys and one negative (unparsable) entry.
	if _, err := e.parseHostKeyCached(keyA); err != nil {
		t.Fatalf("parse keyA: %v", err)
	}
	if _, err := e.parseHostKeyCached(keyB); err != nil {
		t.Fatalf("parse keyB: %v", err)
	}
	if _, err := e.parseHostKeyCached("not a key"); err == nil {
		t.Fatal("expected a parse error for garbage")
	}

	// The live host set now carries only keyA (keyB's host rotated away).
	e.hosts = map[string]signer.HostInfo{"a": {HostKey: keyA}}
	e.pruneHostKeyCache()

	if _, ok := e.hostKeyCache.Load(keyA); !ok {
		t.Error("a live host key must survive pruning")
	}
	if _, ok := e.hostKeyCache.Load(keyB); ok {
		t.Error("a rotated-away host key must be evicted")
	}
	if _, ok := e.hostKeyCache.Load("not a key"); ok {
		t.Error("a stale negative-cache entry must be evicted")
	}
}
