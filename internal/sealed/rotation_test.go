package sealed

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"
)

// keyFile renders the pinned-key file contents for the given keys, the way an
// operator's /etc/infrabroker/envelope.pub looks during a rotation overlap.
func keyFile(keys ...ed25519.PrivateKey) string {
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(PublicKeyString(pub(k)) + "\n")
	}
	return b.String()
}

// TestParsePublicKeysSingleKeyIsBackwardCompatible: every envelope.pub deployed
// before rotation support existed is a single base64 line; it must keep parsing.
func TestParsePublicKeysSingleKeyIsBackwardCompatible(t *testing.T) {
	t.Parallel()
	k := testKey(t, 1)
	for _, form := range []string{
		PublicKeyString(pub(k)),         // no trailing newline
		PublicKeyString(pub(k)) + "\n",  // trailing newline
		" " + PublicKeyString(pub(k)),   // leading space
		PublicKeyString(pub(k)) + " \n", // trailing space
		"\n" + PublicKeyString(pub(k)),  // leading blank line
	} {
		keys, err := ParsePublicKeys(form)
		if err != nil {
			t.Fatalf("ParsePublicKeys(%q): %v", form, err)
		}
		if len(keys) != 1 || !keys[0].Equal(pub(k)) {
			t.Errorf("ParsePublicKeys(%q) = %d keys, want the single pinned key", form, len(keys))
		}
	}
}

// TestParsePublicKeysAcceptsCommentsAndBlanks: the file is operator-edited during
// a rotation, so it must tolerate the annotations an operator adds.
func TestParsePublicKeysAcceptsCommentsAndBlanks(t *testing.T) {
	t.Parallel()
	k1, k2 := testKey(t, 1), testKey(t, 2)
	file := "# outgoing key, retire after 2026-08-08\n" +
		PublicKeyString(pub(k1)) + "\n" +
		"\n" +
		"   # incoming key, added 2026-08-01\n" +
		PublicKeyString(pub(k2)) + "\n"
	keys, err := ParsePublicKeys(file)
	if err != nil {
		t.Fatalf("ParsePublicKeys: %v", err)
	}
	if len(keys) != 2 || !keys[0].Equal(pub(k1)) || !keys[1].Equal(pub(k2)) {
		t.Fatalf("got %d keys, want both pinned keys in file order", len(keys))
	}
}

// TestParsePublicKeysFailsClosed: the parser must reject the WHOLE file rather
// than skip a bad line. Best-effort parsing is the one dangerous variant: a
// corrupted byte in the newly appended line would silently leave the host
// trusting only the outgoing key, and the operator would then retire it.
func TestParsePublicKeysFailsClosed(t *testing.T) {
	t.Parallel()
	good := PublicKeyString(pub(testKey(t, 1)))
	short := "AAAA"
	for name, file := range map[string]string{
		"empty":               "",
		"whitespace only":     "  \n\t\n",
		"comments only":       "# nothing here\n# really\n",
		"garbage":             "not base64 at all!\n",
		"good then malformed": good + "\nnot-base64!!\n",
		"malformed then good": "not-base64!!\n" + good + "\n",
		"good then too short": good + "\n" + short + "\n",
	} {
		if keys, err := ParsePublicKeys(file); err == nil {
			t.Errorf("%s: ParsePublicKeys must fail closed, got %d keys", name, len(keys))
		}
	}
}

// TestParsePublicKeysErrorNamesTheLine: an operator editing a two-key file needs
// to know WHICH line is broken.
func TestParsePublicKeysErrorNamesTheLine(t *testing.T) {
	t.Parallel()
	good := PublicKeyString(pub(testKey(t, 1)))
	_, err := ParsePublicKeys(good + "\nnot-base64!!\n")
	if err == nil {
		t.Fatal("want an error")
	}
	if !strings.Contains(err.Error(), "line 2") {
		t.Errorf("error must name the offending line, got %q", err)
	}
}

// TestSingleKeyParserRejectsAMultiKeyFile pins the VERSION-SKEW property the
// rotation runbook depends on: ParsePublicKey — what a shim older than v3.1.0
// applies to the WHOLE file — fails on a two-key file rather than silently
// honouring the first key. Go's base64 decoder ignores newlines, so a second line
// reads as data after the first key's "=" padding and errors.
//
// The operational consequence, documented in docs/OPERATIONS.md § 2.2: appending
// the incoming key to a host still running an old shim takes that host DOWN
// (fail-closed), so every sealed host must be upgraded before step 2 of a
// rotation. If this test ever fails, that ordering requirement has changed and
// the runbook is wrong.
func TestSingleKeyParserRejectsAMultiKeyFile(t *testing.T) {
	t.Parallel()
	k1, k2 := testKey(t, 1), testKey(t, 2)
	if _, err := ParsePublicKey(keyFile(k1, k2)); err == nil {
		t.Error("the pre-rotation single-key parser must fail closed on a two-key file, " +
			"not honour the first key — the runbook's upgrade-first ordering depends on it")
	}
	// A comment line has the same effect, which is why comments are only safe
	// once every host runs a shim that parses line by line.
	if _, err := ParsePublicKey(PublicKeyString(pub(k1)) + "\n# added 2026-08-01\n"); err == nil {
		t.Error("the single-key parser must fail closed on a commented file too")
	}
	// The single-key form it DOES accept is unchanged.
	if _, err := ParsePublicKey(PublicKeyString(pub(k1)) + "\n"); err != nil {
		t.Errorf("a one-key file must still parse with the single-key parser: %v", err)
	}
}

// TestVerifyAnyAcceptsEitherPinnedKey is the rotation property itself: while a
// host pins both the outgoing and the incoming key, envelopes signed by EITHER
// run — which is what makes switching the signer a no-outage operation.
func TestVerifyAnyAcceptsEitherPinnedKey(t *testing.T) {
	t.Parallel()
	outgoing, incoming := testKey(t, 1), testKey(t, 2)
	now := time.Unix(1_700_000_000, 0)
	pinned, err := ParsePublicKeys(keyFile(outgoing, incoming))
	if err != nil {
		t.Fatal(err)
	}
	for name, signKey := range map[string]ed25519.PrivateKey{
		"outgoing key": outgoing,
		"incoming key": incoming,
	} {
		wire, err := Sign(signKey, "web01", "uptime", DefaultTTL, now)
		if err != nil {
			t.Fatal(err)
		}
		e, err := VerifyAny(pinned, wire, "web01", now)
		if err != nil {
			t.Fatalf("%s: VerifyAny: %v", name, err)
		}
		if e.Command != "uptime" {
			t.Errorf("%s: command = %q", name, e.Command)
		}
	}
}

// TestVerifyAnyRejectsUnpinnedKey: pinning two keys must not turn the check into
// "any signature will do".
func TestVerifyAnyRejectsUnpinnedKey(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_700_000_000, 0)
	pinned, err := ParsePublicKeys(keyFile(testKey(t, 1), testKey(t, 2)))
	if err != nil {
		t.Fatal(err)
	}
	wire, err := Sign(testKey(t, 3), "web01", "uptime", DefaultTTL, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAny(pinned, wire, "web01", now); err == nil {
		t.Fatal("an envelope signed by an unpinned key must be refused")
	}
}

// TestVerifyAnyRejectsEmptyAndMalformedKeySets: an empty set must fail with its
// own error rather than fall out of the loop, and a non-32-byte key must be a
// deliberate refusal — ed25519.Verify PANICS on one.
func TestVerifyAnyRejectsEmptyAndMalformedKeySets(t *testing.T) {
	t.Parallel()
	k := testKey(t, 1)
	now := time.Unix(1_700_000_000, 0)
	wire, err := Sign(k, "web01", "uptime", DefaultTTL, now)
	if err != nil {
		t.Fatal(err)
	}
	// Assert the DEDICATED error, not merely "some error": ranging over an empty
	// slice would also refuse, but only by accident — which is what invites a
	// later refactor to drop the guard. The message is the proof it is explicit.
	for name, pubs := range map[string][]ed25519.PublicKey{
		"nil":   nil,
		"empty": {},
	} {
		_, err := VerifyAny(pubs, wire, "web01", now)
		if err == nil {
			t.Fatalf("%s pinned set must be an explicit error", name)
		}
		if !strings.Contains(err.Error(), "no pinned envelope public key") {
			t.Errorf("%s pinned set must fail with its OWN error, got %q", name, err)
		}
	}
	// A short key alongside a valid one must refuse, not panic.
	mixed := []ed25519.PublicKey{pub(k), ed25519.PublicKey([]byte{1, 2, 3})}
	if _, err := VerifyAny(mixed, wire, "web01", now); err == nil {
		t.Error("a malformed pinned key must be refused")
	}
}

// TestVerifyAnyKeepsEveryPostSignatureInvariant: the multi-key loop must not
// swallow the checks that run AFTER the signature — host binding, nonce, expiry
// and the clock-skew ceiling — nor the mandatory expectedHost.
func TestVerifyAnyKeepsEveryPostSignatureInvariant(t *testing.T) {
	t.Parallel()
	k1, k2 := testKey(t, 1), testKey(t, 2)
	now := time.Unix(1_700_000_000, 0)
	pinned, err := ParsePublicKeys(keyFile(k1, k2))
	if err != nil {
		t.Fatal(err)
	}
	// Signed by the SECOND pinned key, so each rejection below is reached only
	// after the loop has already matched — proving the checks still run.
	wire, err := Sign(k2, "web01", "uptime", DefaultTTL, now)
	if err != nil {
		t.Fatal(err)
	}
	// The empty-expectedHost guard must be its OWN check, distinguishable from the
	// host comparison further down — otherwise deleting it looks harmless (the
	// comparison "web01" != "" would refuse anyway) while actually turning a
	// missing binding into a silent, ordinary mismatch.
	_, err = VerifyAny(pinned, wire, "", now)
	if err == nil {
		t.Fatal("an empty expectedHost must be an error, never a wildcard")
	}
	if !strings.Contains(err.Error(), "no expected host") {
		t.Errorf("an empty expectedHost must fail with its OWN error, got %q", err)
	}
	if _, err := VerifyAny(pinned, wire, "db01", now); err == nil {
		t.Error("cross-host replay must be refused with N pinned keys too")
	}
	if _, err := VerifyAny(pinned, wire, "web01", now.Add(DefaultTTL+time.Second)); err == nil {
		t.Error("an expired envelope must be refused with N pinned keys too")
	}
	if _, err := VerifyAny(pinned, wire, "web01", now.Add(-2*MaxTTL)); err == nil {
		t.Error("a far-future expiry (clock skew) must be refused with N pinned keys too")
	}
}

// TestVerifyAnyChecksSignatureBeforeHost pins the ORDER: e.Host is
// attacker-controlled until a pinned key has verified the bytes, so the host
// comparison must not be hoisted above the verification loop as an optimisation
// that "skips N verifications when the host does not match".
func TestVerifyAnyChecksSignatureBeforeHost(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_700_000_000, 0)
	pinned, err := ParsePublicKeys(keyFile(testKey(t, 1)))
	if err != nil {
		t.Fatal(err)
	}
	// Signed by an unpinned key AND for the wrong host: the reported failure must
	// be the signature, proving nothing downstream of it was consulted first.
	wire, err := Sign(testKey(t, 9), "other-host", "uptime", DefaultTTL, now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifyAny(pinned, wire, "web01", now)
	if err == nil {
		t.Fatal("want a refusal")
	}
	if !strings.Contains(err.Error(), "signature") {
		t.Errorf("signature must be checked before the host binding; got %q", err)
	}
}

// TestVerifyAnyErrorDoesNotNameAKey: the refusal must not tell the caller which
// pinned key was tried (the caller is the very session being refused).
func TestVerifyAnyErrorDoesNotNameAKey(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_700_000_000, 0)
	k1, k2 := testKey(t, 1), testKey(t, 2)
	pinned, err := ParsePublicKeys(keyFile(k1, k2))
	if err != nil {
		t.Fatal(err)
	}
	wire, err := Sign(testKey(t, 3), "web01", "uptime", DefaultTTL, now)
	if err != nil {
		t.Fatal(err)
	}
	_, verr := VerifyAny(pinned, wire, "web01", now)
	if verr == nil {
		t.Fatal("want a refusal")
	}
	for _, k := range []ed25519.PrivateKey{k1, k2} {
		if strings.Contains(verr.Error(), PublicKeyString(pub(k))) {
			t.Errorf("the refusal must not echo a pinned key: %q", verr)
		}
	}
}
