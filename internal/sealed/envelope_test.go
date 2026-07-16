package sealed

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func testKey(t *testing.T, b byte) ed25519.PrivateKey {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = b
	}
	k, err := KeyFromSeed(seed)
	if err != nil {
		t.Fatalf("KeyFromSeed: %v", err)
	}
	return k
}

func pub(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

// TestSignVerifyRoundTrip: a freshly minted envelope verifies and carries back
// exactly the host and command it authorised.
func TestSignVerifyRoundTrip(t *testing.T) {
	t.Parallel()
	k := testKey(t, 1)
	now := time.Unix(1_700_000_000, 0)

	wire, err := Sign(k, "web01", "sudo -n systemctl restart nginx", DefaultTTL, now)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if strings.ContainsAny(wire, " \n\r\t") {
		t.Errorf("the wire form travels as an SSH command and must have no whitespace: %q", wire)
	}
	e, err := Verify(pub(k), wire, "web01", now)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if e.Host != "web01" || e.Command != "sudo -n systemctl restart nginx" {
		t.Errorf("envelope = %+v", e)
	}
	if e.Nonce == "" {
		t.Error("envelope must carry a nonce")
	}
}

// TestVerifyRejectsWrongKey: only the pinned key's envelopes are honoured — the
// property the shim leans on.
func TestVerifyRejectsWrongKey(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_700_000_000, 0)
	wire, err := Sign(testKey(t, 1), "web01", "uptime", DefaultTTL, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(pub(testKey(t, 2)), wire, "web01", now); err == nil {
		t.Error("an envelope signed by another key must not verify")
	}
}

// TestVerifyRejectsTampering: mutating any signed field breaks the signature.
// This is what stops a compromised broker from editing the command the signer
// authorised.
func TestVerifyRejectsTampering(t *testing.T) {
	t.Parallel()
	k := testKey(t, 1)
	now := time.Unix(1_700_000_000, 0)
	wire, err := Sign(k, "web01", "uptime", DefaultTTL, now)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(wire)
	if err != nil {
		t.Fatal(err)
	}
	var e Envelope
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatal(err)
	}

	for name, mutate := range map[string]func(*Envelope){
		"command": func(e *Envelope) { e.Command = "rm -rf /" },
		"host":    func(e *Envelope) { e.Host = "db01" },
		"expiry":  func(e *Envelope) { e.Expiry += 3600 },
		"nonce":   func(e *Envelope) { e.Nonce = "00000000000000000000000000000000" },
	} {
		tampered := e
		mutate(&tampered)
		js, err := json.Marshal(tampered)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(pub(k), base64.RawURLEncoding.EncodeToString(js), "web01", now); err == nil {
			t.Errorf("tampering with %s must break verification", name)
		}
	}
}

// TestVerifyRejectsExpired: expiry is half of the replay bound (the shim's nonce
// cache is the other half).
func TestVerifyRejectsExpired(t *testing.T) {
	t.Parallel()
	k := testKey(t, 1)
	now := time.Unix(1_700_000_000, 0)
	wire, err := Sign(k, "web01", "uptime", DefaultTTL, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(pub(k), wire, "web01", now.Add(DefaultTTL+time.Second)); err == nil {
		t.Error("an expired envelope must not verify")
	}
	// Still valid an instant before expiry.
	if _, err := Verify(pub(k), wire, "web01", now.Add(DefaultTTL-time.Second)); err != nil {
		t.Errorf("envelope must remain valid until its expiry: %v", err)
	}
}

// TestVerifyRejectsCrossHostReplay is the regression for the cross-host replay
// hole: Host is signed, but signing it proves nothing unless the verifier
// COMPARES it. Every sealed host pins the same envelope key, so without this an
// envelope minted for a permissive host would verify — byte for byte, no
// tampering, nonce fresh — on a restrictive one, reducing the envelope to a
// fleet-wide bearer token for one command.
func TestVerifyRejectsCrossHostReplay(t *testing.T) {
	t.Parallel()
	k := testKey(t, 1)
	now := time.Unix(1_700_000_000, 0)

	wire, err := Sign(k, "dev01", "rm -rf /var/lib/data", DefaultTTL, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(pub(k), wire, "prod-db01", now); err == nil {
		t.Error("an envelope minted for dev01 must not verify on prod-db01")
	}
	// It still verifies on the host it was minted for.
	if _, err := Verify(pub(k), wire, "dev01", now); err != nil {
		t.Errorf("the envelope must verify on its own host: %v", err)
	}
}

// TestVerifyRequiresExpectedHost: an empty expected host is an error, never a
// wildcard — the host binding must be impossible to skip by omission.
func TestVerifyRequiresExpectedHost(t *testing.T) {
	t.Parallel()
	k := testKey(t, 1)
	now := time.Unix(1_700_000_000, 0)
	wire, err := Sign(k, "web01", "uptime", DefaultTTL, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(pub(k), wire, "", now); err == nil {
		t.Error("verifying with no expected host must be an error, not a wildcard match")
	}
}

// TestVerifyRejectsFarFutureExpiry bounds clock skew: Sign never issues beyond
// MaxTTL, so an expiry further ahead than that means this host's clock is behind
// the signer's. Honouring it would stretch a 30s window into minutes of replay.
func TestVerifyRejectsFarFutureExpiry(t *testing.T) {
	t.Parallel()
	k := testKey(t, 1)
	now := time.Unix(1_700_000_000, 0)
	wire, err := Sign(k, "web01", "uptime", DefaultTTL, now)
	if err != nil {
		t.Fatal(err)
	}
	// The host's clock is 15 minutes behind the signer's: the expiry looks far in
	// the future from here.
	skewed := now.Add(-15 * time.Minute)
	if _, err := Verify(pub(k), wire, "web01", skewed); err == nil {
		t.Error("an expiry more than MaxTTL in the future must be refused (clock skew)")
	}
}

// TestForceCommandBindsHost: the force-command carries the host so the shim
// learns its identity from the signer-signed certificate, and host names that
// would not survive a shell command line are refused outright.
func TestForceCommandBindsHost(t *testing.T) {
	t.Parallel()
	fc, err := sealedForceCommand(t, "web01")
	if err != nil {
		t.Fatal(err)
	}
	if fc != ShimCommand+" web01" {
		t.Errorf("force-command = %q, want %q", fc, ShimCommand+" web01")
	}
	for _, bad := range []string{"", "web 01", "web;rm -rf /", "web$(id)", "-web", "web\n01"} {
		if _, err := ForceCommand(bad); err == nil {
			t.Errorf("host name %q must be refused for sealed_exec", bad)
		}
	}
}

func sealedForceCommand(t *testing.T, host string) (string, error) {
	t.Helper()
	return ForceCommand(host)
}

func TestVerifyRejectsMalformed(t *testing.T) {
	t.Parallel()
	k := testKey(t, 1)
	now := time.Unix(1_700_000_000, 0)
	for _, wire := range []string{"", "not-base64!!", base64.RawURLEncoding.EncodeToString([]byte("{not json"))} {
		if _, err := Verify(pub(k), wire, "web01", now); err == nil {
			t.Errorf("malformed envelope %q must not verify", wire)
		}
	}
}

func TestSignRejectsBadInput(t *testing.T) {
	t.Parallel()
	k := testKey(t, 1)
	now := time.Unix(1_700_000_000, 0)
	if _, err := Sign(k, "web01", "", DefaultTTL, now); err == nil {
		t.Error("an empty command must not be signed")
	}
	if _, err := Sign(k, "", "uptime", DefaultTTL, now); err == nil {
		t.Error("an empty host must not be signed")
	}
	if _, err := Sign(k, "web01", "uptime", MaxTTL+time.Second, now); err == nil {
		t.Error("a ttl beyond MaxTTL must be refused")
	}
	if _, err := Sign(k, "web01", "uptime", 0, now); err == nil {
		t.Error("a non-positive ttl must be refused")
	}
}

func TestPublicKeyStringRoundTrip(t *testing.T) {
	t.Parallel()
	k := testKey(t, 7)
	got, err := ParsePublicKey(PublicKeyString(pub(k)))
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	if !got.Equal(pub(k)) {
		t.Error("public key must survive the base64 round trip")
	}
	// Whitespace (a trailing newline in the pinned file) is tolerated.
	if _, err := ParsePublicKey("  " + PublicKeyString(pub(k)) + "\n"); err != nil {
		t.Errorf("a pinned key file with surrounding whitespace must parse: %v", err)
	}
	if _, err := ParsePublicKey("short"); err == nil {
		t.Error("a malformed public key must be rejected")
	}
}

func TestKeyFromSeedRejectsShortSeed(t *testing.T) {
	t.Parallel()
	if _, err := KeyFromSeed(make([]byte, ed25519.SeedSize-1)); err == nil {
		t.Error("a short seed must be rejected")
	}
}
