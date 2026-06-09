package audit

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// testKey returns a deterministic Ed25519 key (seed = 0x01 * 32).
func testKey() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 0x01
	}
	return ed25519.NewKeyFromSeed(seed)
}

// openTmp opens a Log on a new temporary file.
func openTmp(t *testing.T) (*Log, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := Open(path, testKey())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	return l, path
}

// readEntries reads all entries from the log file and returns them as
// (rawLine, Entry) pairs, preserving order.
func readEntries(t *testing.T, path string) []struct {
	raw []byte
	e   Entry
} {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("readEntries open: %v", err)
	}
	defer f.Close()

	var out []struct {
		raw []byte
		e   Entry
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 256*1024), 256*1024)
	for sc.Scan() {
		b := sc.Bytes()
		if len(b) == 0 {
			continue
		}
		line := make([]byte, len(b))
		copy(line, b)
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatalf("readEntries unmarshal: %v", err)
		}
		out = append(out, struct {
			raw []byte
			e   Entry
		}{line, e})
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("readEntries scan: %v", err)
	}
	return out
}

// ── Tests ─────────────────────────────────────────────────────────────────────

// TestAppendSeqIncrementa verifies that Seq increments by 1 starting from 1.
func TestAppendSeqIncrementa(t *testing.T) {
	t.Parallel()
	l, path := openTmp(t)
	for i := 0; i < 5; i++ {
		if err := l.Append(Entry{Outcome: "test"}); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	entries := readEntries(t, path)
	if len(entries) != 5 {
		t.Fatalf("expected 5 entries, got %d", len(entries))
	}
	for i, pair := range entries {
		wantSeq := uint64(i + 1)
		if pair.e.Seq != wantSeq {
			t.Errorf("entry %d: Seq=%d, want %d", i, pair.e.Seq, wantSeq)
		}
	}
}

// TestAppendPrevHashEncadena verifies that PrevHash of entry N equals the
// SHA-256 of raw line N-1.
func TestAppendPrevHashEncadena(t *testing.T) {
	t.Parallel()
	l, path := openTmp(t)
	for i := 0; i < 4; i++ {
		if err := l.Append(Entry{Outcome: "chain", Command: "cmd"}); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	entries := readEntries(t, path)
	if len(entries) != 4 {
		t.Fatalf("expected 4 entries, got %d", len(entries))
	}

	// First entry: PrevHash must be empty.
	if entries[0].e.PrevHash != "" {
		t.Errorf("first entry PrevHash=%q, want \"\"", entries[0].e.PrevHash)
	}

	// For each subsequent entry, PrevHash == SHA-256(previous raw line).
	for i := 1; i < len(entries); i++ {
		sum := sha256.Sum256(entries[i-1].raw)
		want := hex.EncodeToString(sum[:])
		if entries[i].e.PrevHash != want {
			t.Errorf("entry %d: PrevHash=%s, want %s", i, entries[i].e.PrevHash, want)
		}
	}
}

// TestAppendFirmaValida verifies that the Ed25519 signature of each entry is
// valid against the public key derived from the seed.
func TestAppendFirmaValida(t *testing.T) {
	t.Parallel()
	key := testKey()
	pub := key.Public().(ed25519.PublicKey)

	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := Open(path, key)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer l.Close()

	for i := 0; i < 3; i++ {
		if err := l.Append(Entry{Outcome: "sig-test", Caller: "agent"}); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}

	entries := readEntries(t, path)
	for i, pair := range entries {
		sigB64 := pair.e.Sig
		sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
		if err != nil {
			t.Fatalf("entry %d: signature is not base64: %v", i, err)
		}

		// The canonical payload is signed with Sig="".
		pair.e.Sig = ""
		payload, err := json.Marshal(pair.e)
		if err != nil {
			t.Fatalf("entry %d: marshal for verification: %v", i, err)
		}

		if !ed25519.Verify(pub, payload, sigBytes) {
			t.Errorf("entry %d: invalid Ed25519 signature", i)
		}
	}
}

// TestAppendFirmaInvalidaTrasManipulacion checks that altering an entry's
// content invalidates its signature.
func TestAppendFirmaInvalidaTrasManipulacion(t *testing.T) {
	t.Parallel()
	key := testKey()
	pub := key.Public().(ed25519.PublicKey)

	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := Open(path, key)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer l.Close()

	if err := l.Append(Entry{Outcome: "ok", Caller: "honest"}); err != nil {
		t.Fatalf("Append: %v", err)
	}

	entries := readEntries(t, path)
	e := entries[0].e
	sigBytes, _ := base64.StdEncoding.DecodeString(e.Sig)

	// Tamper with the Caller field.
	e.Caller = "attacker"
	e.Sig = ""
	payload, _ := json.Marshal(e)

	if ed25519.Verify(pub, payload, sigBytes) {
		t.Error("signature should not verify after tampering with Caller")
	}
}

// TestRestoreChainFicheroNuevo verifies that opening a log at a non-existent
// path succeeds and starts with seq=0.
func TestRestoreChainFicheroNuevo(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "nuevo.log")
	l, err := Open(path, testKey())
	if err != nil {
		t.Fatalf("Open on new file: %v", err)
	}
	defer l.Close()

	if l.seq != 0 {
		t.Errorf("initial seq=%d, want 0", l.seq)
	}
	if l.prevHash != "" {
		t.Errorf("initial prevHash=%q, want \"\"", l.prevHash)
	}
}

// TestRestoreChainFicheroVacio verifies that an empty file does not produce an
// error and the chain starts from zero.
func TestRestoreChainFicheroVacio(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "empty.log")
	// Create the empty file.
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	f.Close()

	l, err := Open(path, testKey())
	if err != nil {
		t.Fatalf("Open on empty file: %v", err)
	}
	defer l.Close()

	if l.seq != 0 || l.prevHash != "" {
		t.Errorf("seq=%d prevHash=%q, want 0/\"\"", l.seq, l.prevHash)
	}
}

// TestRestoreChainPreservaEstadoTrasReinicio opens a log, writes several
// entries, closes it, and reopens it. The second Open must restore seq and
// prevHash so the chain continues unbroken.
func TestRestoreChainPreservaEstadoTrasReinicio(t *testing.T) {
	t.Parallel()
	key := testKey()
	path := filepath.Join(t.TempDir(), "restart.log")

	// First session: write 3 entries.
	l1, err := Open(path, key)
	if err != nil {
		t.Fatalf("Open session 1: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := l1.Append(Entry{Outcome: "s1"}); err != nil {
			t.Fatalf("Append s1 %d: %v", i, err)
		}
	}
	l1.Close()

	// Second session: reopen and write 2 more entries.
	l2, err := Open(path, key)
	if err != nil {
		t.Fatalf("Open session 2: %v", err)
	}
	defer l2.Close()

	// Restored seq must be 3 (last entry in the log).
	if l2.seq != 3 {
		t.Errorf("restored seq=%d, want 3", l2.seq)
	}

	for i := 0; i < 2; i++ {
		if err := l2.Append(Entry{Outcome: "s2"}); err != nil {
			t.Fatalf("Append s2 %d: %v", i, err)
		}
	}

	// Verify the full chain (5 entries, unbroken).
	entries := readEntries(t, path)
	if len(entries) != 5 {
		t.Fatalf("expected 5 total entries, got %d", len(entries))
	}
	for i := 0; i < 5; i++ {
		if entries[i].e.Seq != uint64(i+1) {
			t.Errorf("entry %d: Seq=%d, want %d", i, entries[i].e.Seq, i+1)
		}
	}
	for i := 1; i < len(entries); i++ {
		sum := sha256.Sum256(entries[i-1].raw)
		want := hex.EncodeToString(sum[:])
		if entries[i].e.PrevHash != want {
			t.Errorf("entry %d: PrevHash breaks the chain", i)
		}
	}
}

// TestRestoreChainUltimaLineaMalformada verifies that Open returns an error
// when the last line of the file is not valid JSON.
func TestRestoreChainUltimaLineaMalformada(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "malformed.log")
	// Write a valid JSON line followed by garbage.
	content := `{"seq":1,"prev_hash":"","sig":"","time":"2026-01-01T00:00:00Z","caller":"","host":"","user":"","principal":"","command":"","ttl":"","serial":0,"outcome":"ok","exit_code":0}` + "\n" +
		"not-valid-json\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := Open(path, testKey())
	if err == nil {
		t.Fatal("expected error when parsing malformed last line")
	}
}

// TestMaybeRotateAplicaRotacion creates a Log with minimal maxFileSize and
// verifies that after rotation: (a) the rotated file exists and (b) the new
// log restarts seq from 1 (first entry after rotation has Seq=1).
func TestMaybeRotateAplicaRotacion(t *testing.T) {
	t.Parallel()
	key := testKey()
	dir := t.TempDir()
	path := filepath.Join(dir, "rotate.log")

	l, err := Open(path, key)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer l.Close()

	// Write one entry so the file has content.
	if err := l.Append(Entry{Outcome: "before-rotate"}); err != nil {
		t.Fatalf("Append before rotate: %v", err)
	}

	// Force rotation by setting maxFileSize to 1 byte.
	l.mu.Lock()
	l.maxFileSize = 1
	l.mu.Unlock()

	// The next entry must trigger rotation and then write to the new file.
	if err := l.Append(Entry{Outcome: "trigger-rotate"}); err != nil {
		t.Fatalf("Append that triggers rotation: %v", err)
	}

	// Check that a rotated file exists in the directory.
	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var rotated bool
	for _, de := range dirEntries {
		if de.Name() != "rotate.log" {
			rotated = true
			break
		}
	}
	if !rotated {
		t.Error("expected a rotated file (rotate.log.<timestamp>) in the directory")
	}

	// The entry written after rotation must have Seq=1 (chain restarted).
	entries := readEntries(t, path)
	if len(entries) == 0 {
		t.Fatal("new log must have at least one entry after rotation")
	}
	if entries[0].e.Seq != 1 {
		t.Errorf("first entry of new log: Seq=%d, want 1", entries[0].e.Seq)
	}
	if entries[0].e.PrevHash != "" {
		t.Errorf("first entry of new log: PrevHash=%q, want \"\"", entries[0].e.PrevHash)
	}
}

// TestMaybeRotateDeshabilitada checks that with maxFileSize=0 no rotation occurs.
func TestMaybeRotateDeshabilitada(t *testing.T) {
	t.Parallel()
	key := testKey()
	dir := t.TempDir()
	path := filepath.Join(dir, "norotate.log")

	l, err := Open(path, key)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer l.Close()

	l.mu.Lock()
	l.maxFileSize = 0 // disable rotation
	l.mu.Unlock()

	for i := 0; i < 5; i++ {
		if err := l.Append(Entry{Outcome: "no-rotate"}); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}

	// There must be exactly one file in the directory.
	dirEntries, _ := os.ReadDir(dir)
	if len(dirEntries) != 1 {
		t.Errorf("expected 1 file, got %d (rotation should not have occurred)", len(dirEntries))
	}
}

// TestCloseCierraCorrecto verifies that Close returns no error under normal conditions.
func TestCloseCierraCorrecto(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "close.log")
	l, err := Open(path, testKey())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := l.Append(Entry{Outcome: "before-close"}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}
