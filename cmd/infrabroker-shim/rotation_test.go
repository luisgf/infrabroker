package main

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luisgf/infrabroker/internal/sealed"
)

// shimEnvKeys writes a pinned-key file holding every given key (one base64 line
// each — an operator's envelope.pub mid-rotation) and returns its path plus a
// fresh nonce directory.
func shimEnvKeys(t *testing.T, keys ...ed25519.PrivateKey) (pubPath, nonceDir string) {
	t.Helper()
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(sealed.PublicKeyString(k.Public().(ed25519.PublicKey)) + "\n")
	}
	dir := t.TempDir()
	pubPath = filepath.Join(dir, "envelope.pub")
	if err := os.WriteFile(pubPath, []byte(b.String()), 0o600); err != nil {
		t.Fatalf("write pinned keys: %v", err)
	}
	return pubPath, filepath.Join(dir, "nonces")
}

func rotationKey(t *testing.T, seedByte byte) ed25519.PrivateKey {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = seedByte
	}
	k, err := sealed.KeyFromSeed(seed)
	if err != nil {
		t.Fatalf("KeyFromSeed: %v", err)
	}
	return k
}

// TestAuthorizeAcceptsEitherPinnedKeyDuringRotation: while a host pins both the
// outgoing and the incoming envelope key, commands signed by EITHER run. That is
// what removes the outage from an envelope-key rotation — the signer can be
// switched over while every sealed host keeps working.
func TestAuthorizeAcceptsEitherPinnedKeyDuringRotation(t *testing.T) {
	t.Parallel()
	outgoing, incoming := rotationKey(t, 1), rotationKey(t, 2)
	pubPath, nonceDir := shimEnvKeys(t, outgoing, incoming)
	now := time.Unix(1_700_000_000, 0)

	for name, key := range map[string]ed25519.PrivateKey{
		"outgoing key": outgoing,
		"incoming key": incoming,
	} {
		wire, err := sealed.Sign(key, "web01", "uptime", sealed.DefaultTTL, now)
		if err != nil {
			t.Fatal(err)
		}
		cmd, err := authorize(pubPath, nonceDir, "web01", wire, now)
		if err != nil {
			t.Fatalf("%s: authorize: %v", name, err)
		}
		if cmd != "uptime" {
			t.Errorf("%s: command = %q, want %q", name, cmd, "uptime")
		}
	}
}

// TestAuthorizeReplayLosesRegardlessOfSigningKey: the single-use nonce bound is
// per envelope and must not be weakened by having more than one key pinned.
func TestAuthorizeReplayLosesRegardlessOfSigningKey(t *testing.T) {
	t.Parallel()
	outgoing, incoming := rotationKey(t, 1), rotationKey(t, 2)
	pubPath, nonceDir := shimEnvKeys(t, outgoing, incoming)
	now := time.Unix(1_700_000_000, 0)

	for name, key := range map[string]ed25519.PrivateKey{
		"outgoing key": outgoing,
		"incoming key": incoming,
	} {
		wire, err := sealed.Sign(key, "web01", "uptime", sealed.DefaultTTL, now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := authorize(pubPath, nonceDir, "web01", wire, now); err != nil {
			t.Fatalf("%s: first use must succeed: %v", name, err)
		}
		if _, err := authorize(pubPath, nonceDir, "web01", wire, now); err == nil {
			t.Errorf("%s: replay must be refused", name)
		}
	}
}

// TestAuthorizeRejectsUnpinnedKeyWithTwoPinned: an overlap window must not become
// "accept anything".
func TestAuthorizeRejectsUnpinnedKeyWithTwoPinned(t *testing.T) {
	t.Parallel()
	pubPath, nonceDir := shimEnvKeys(t, rotationKey(t, 1), rotationKey(t, 2))
	now := time.Unix(1_700_000_000, 0)
	wire, err := sealed.Sign(rotationKey(t, 3), "web01", "uptime", sealed.DefaultTTL, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authorize(pubPath, nonceDir, "web01", wire, now); err == nil {
		t.Fatal("an envelope signed by an unpinned key must be refused")
	}
}

// TestAuthorizeFailsClosedOnBadKeyFile: the shim must refuse rather than degrade
// when the pinned-key file is empty, comment-only, or has one good and one
// malformed line. The last case is the dangerous one: skipping the bad line would
// silently leave the host trusting only the OTHER key.
func TestAuthorizeFailsClosedOnBadKeyFile(t *testing.T) {
	t.Parallel()
	key := rotationKey(t, 1)
	good := sealed.PublicKeyString(key.Public().(ed25519.PublicKey))
	now := time.Unix(1_700_000_000, 0)
	wire, err := sealed.Sign(key, "web01", "uptime", sealed.DefaultTTL, now)
	if err != nil {
		t.Fatal(err)
	}

	for name, contents := range map[string]string{
		"empty":               "",
		"whitespace only":     " \n\t\n",
		"comments only":       "# retired 2026-08-01\n",
		"good then malformed": good + "\nnot-base64!!\n",
		"malformed then good": "not-base64!!\n" + good + "\n",
	} {
		dir := t.TempDir()
		pubPath := filepath.Join(dir, "envelope.pub")
		if err := os.WriteFile(pubPath, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
		if cmd, err := authorize(pubPath, filepath.Join(dir, "nonces"), "web01", wire, now); err == nil {
			t.Errorf("%s: must fail closed, got command %q", name, cmd)
		}
	}
}

// TestAuthorizeSingleKeyFileStillWorks: every envelope.pub already deployed holds
// one base64 line, so the multi-key parser must not break existing hosts.
func TestAuthorizeSingleKeyFileStillWorks(t *testing.T) {
	t.Parallel()
	key := rotationKey(t, 7)
	pubPath, nonceDir := shimEnvKeys(t, key)
	now := time.Unix(1_700_000_000, 0)
	wire, err := sealed.Sign(key, "web01", "id -u", sealed.DefaultTTL, now)
	if err != nil {
		t.Fatal(err)
	}
	cmd, err := authorize(pubPath, nonceDir, "web01", wire, now)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if cmd != "id -u" {
		t.Errorf("command = %q", cmd)
	}
}
