package audit

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

// appendAndRead writes entries to a fresh log signed with a fixed key and
// returns the file path, the public key and the stored entries.
func appendAndRead(t *testing.T, entries ...Entry) (string, ed25519.PublicKey, []Entry) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.log")
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	l, err := Open(path, priv)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if err := l.Append(e); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got []Entry
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatalf("decode: %v", err)
		}
		got = append(got, e)
	}
	return path, priv.Public().(ed25519.PublicKey), got
}

func verifyLogFile(t *testing.T, path string, pub ed25519.PublicKey) (int, int) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	return Verify(f, pub, func(format string, args ...any) { t.Logf(format, args...) })
}

// TestAppendInvalidUTF8VerifiesClean pins #842: invalid UTF-8 in a free-text
// field (an SSH error relayed from a target host) must not make the record
// fail verification.
func TestAppendInvalidUTF8VerifiesClean(t *testing.T) {
	t.Parallel()
	path, pub, got := appendAndRead(t,
		Entry{Caller: "c", Host: "h", Outcome: "error", Err: "ssh: remote said \xff\xfe bye"},
		Entry{Caller: "c", Host: "h", Outcome: "issued"},
	)
	if total, errs := verifyLogFile(t, path, pub); total != 2 || errs != 0 {
		t.Fatalf("verify: total=%d errs=%d, want 2/0", total, errs)
	}
	if want := "ssh: remote said � bye"; got[0].Err != want {
		t.Fatalf("stored Err = %q, want %q", got[0].Err, want)
	}
}

func TestAppendValidUnicodeUntouched(t *testing.T) {
	t.Parallel()
	txt := "café ünïcödé 日本語のテキスト 🚀 � légitime"
	path, pub, got := appendAndRead(t, Entry{Caller: txt, Host: txt, Command: txt, Outcome: "error", Err: txt, Warning: txt, Anomaly: txt})
	if total, errs := verifyLogFile(t, path, pub); total != 1 || errs != 0 {
		t.Fatalf("verify: total=%d errs=%d", total, errs)
	}
	e := got[0]
	for _, s := range []string{e.Caller, e.Host, e.Command, e.Err, e.Warning, e.Anomaly} {
		if s != txt {
			t.Fatalf("valid text altered: %q", s)
		}
	}
}

// TestAppendInvalidUTF8NearSizeCap: invalid bytes grow 1 -> 3 bytes, so the
// normalisation must run before the size fit or the line could exceed the cap.
func TestAppendInvalidUTF8NearSizeCap(t *testing.T) {
	t.Parallel()
	bad := strings.Repeat("\xff", maxEntryBytes-2048)
	path, pub, got := appendAndRead(t, Entry{Caller: "c", Host: "h", Outcome: "error", Err: bad, Command: bad})
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > maxEntryBytes {
		t.Fatalf("line is %d bytes, over the %d cap", len(data), maxEntryBytes)
	}
	if total, errs := verifyLogFile(t, path, pub); total != 1 || errs != 0 {
		t.Fatalf("verify: total=%d errs=%d", total, errs)
	}
	if !utf8.ValidString(got[0].Err) || !strings.Contains(got[0].Err, "�") {
		t.Fatalf("Err not normalised")
	}
}
