package audit

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// faultySink wraps a logFile and can inject a Sync failure after a successful
// Write, modelling a transient fsync I/O error. Used to prove that such a fault
// does not desync the in-memory chain head from the bytes on disk.
type faultySink struct {
	inner    logFile
	failSync bool
}

func (s *faultySink) Write(p []byte) (int, error) { return s.inner.Write(p) }
func (s *faultySink) Stat() (os.FileInfo, error)  { return s.inner.Stat() }
func (s *faultySink) Close() error                { return s.inner.Close() }
func (s *faultySink) Sync() error {
	if s.failSync {
		return errors.New("injected fsync failure")
	}
	return s.inner.Sync()
}

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

// TestAppendSyncFailureKeepsChainIntact is a regression test for the bug where
// l.prevHash was updated only AFTER a successful fsync: a transient Write-OK /
// Sync-fail event left the in-memory chain head stale, so the entry written
// during the fault and every entry after it failed chain verification for the
// rest of the process run — a transient I/O error masquerading as tampering.
// With the fix the chain state is committed from the bytes actually written,
// so the on-disk chain stays fully valid across the fault.
func TestAppendSyncFailureKeepsChainIntact(t *testing.T) {
	t.Parallel()
	l, path := openTmp(t)

	// Two clean entries.
	for i := 0; i < 2; i++ {
		if err := l.Append(Entry{Outcome: "pre"}); err != nil {
			t.Fatalf("pre Append %d: %v", i, err)
		}
	}

	// Inject a Sync failure for the next write: the line is still written, only
	// the fsync fails. Append must surface the error.
	sink := &faultySink{inner: l.f, failSync: true}
	l.f = sink
	if err := l.Append(Entry{Outcome: "during-fault"}); err == nil {
		t.Fatal("Append must surface the injected fsync error")
	}

	// fsync recovers; further appends succeed.
	sink.failSync = false
	if err := l.Append(Entry{Outcome: "post"}); err != nil {
		t.Fatalf("post Append: %v", err)
	}

	// The on-disk chain must be fully intact: 4 entries, contiguous seq, and
	// every PrevHash == sha256(previous raw line). Without the fix, the "post"
	// entry would carry the hash of the "pre" entry (stale head), breaking the
	// chain at the fault boundary.
	entries := readEntries(t, path)
	if len(entries) != 4 {
		t.Fatalf("expected 4 entries on disk, got %d", len(entries))
	}
	if entries[0].e.PrevHash != "" {
		t.Errorf("entry 0 PrevHash=%q, want \"\"", entries[0].e.PrevHash)
	}
	for i := 1; i < len(entries); i++ {
		sum := sha256.Sum256(entries[i-1].raw)
		if want := hex.EncodeToString(sum[:]); entries[i].e.PrevHash != want {
			t.Errorf("entry %d: PrevHash=%s, want %s (chain broken by fsync fault)", i, entries[i].e.PrevHash, want)
		}
		if entries[i].e.Seq != uint64(i+1) {
			t.Errorf("entry %d: Seq=%d, want %d (seq gap after fault)", i, entries[i].e.Seq, i+1)
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
// log restarts seq from 1 (first entry after rotation has Seq=1) while its
// PrevHash seeds from the rotated file's last line (chain continuity).
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
	var rotatedName string
	for _, de := range dirEntries {
		if de.Name() != "rotate.log" {
			rotatedName = de.Name()
			break
		}
	}
	if rotatedName == "" {
		t.Fatal("expected a rotated file (rotate.log.<timestamp>) in the directory")
	}

	// The entry written after rotation must have Seq=1 (seq restarts per file)
	// and its PrevHash must seed from the rotated file's last line.
	entries := readEntries(t, path)
	if len(entries) == 0 {
		t.Fatal("new log must have at least one entry after rotation")
	}
	if entries[0].e.Seq != 1 {
		t.Errorf("first entry of new log: Seq=%d, want 1", entries[0].e.Seq)
	}
	rotEntries := readEntries(t, filepath.Join(dir, rotatedName))
	if len(rotEntries) == 0 {
		t.Fatal("rotated file must contain the pre-rotation entries")
	}
	sum := sha256.Sum256(rotEntries[len(rotEntries)-1].raw)
	if want := hex.EncodeToString(sum[:]); entries[0].e.PrevHash != want {
		t.Errorf("first entry of new log: PrevHash=%s, want %s (hash of rotated file's last line)", entries[0].e.PrevHash, want)
	}
}

// TestMaybeRotateCadenaContinuaTrasRotacion verifies chain continuity across a
// rotation boundary: the rotated file's internal chain is intact, the new
// file's first entry carries prev_hash = hash of the rotated file's last line
// (the chain seed), and the new file's internal chain continues from there.
func TestMaybeRotateCadenaContinuaTrasRotacion(t *testing.T) {
	t.Parallel()
	key := testKey()
	dir := t.TempDir()
	path := filepath.Join(dir, "chain.log")

	l, err := Open(path, key)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer l.Close()

	// Three entries before rotation.
	for i := 0; i < 3; i++ {
		if err := l.Append(Entry{Outcome: "pre-rotate"}); err != nil {
			t.Fatalf("Append pre-rotate %d: %v", i, err)
		}
	}

	// Force rotation on the next Append.
	l.mu.Lock()
	l.maxFileSize = 1
	l.mu.Unlock()
	if err := l.Append(Entry{Outcome: "post-rotate-1"}); err != nil {
		t.Fatalf("Append post-rotate-1: %v", err)
	}
	// Disable rotation again and write a second post-rotation entry.
	l.mu.Lock()
	l.maxFileSize = 0
	l.mu.Unlock()
	if err := l.Append(Entry{Outcome: "post-rotate-2"}); err != nil {
		t.Fatalf("Append post-rotate-2: %v", err)
	}

	// Locate the rotated file.
	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var rotatedName string
	for _, de := range dirEntries {
		if de.Name() != "chain.log" {
			rotatedName = de.Name()
		}
	}
	if rotatedName == "" {
		t.Fatal("expected a rotated file in the directory")
	}

	rotEntries := readEntries(t, filepath.Join(dir, rotatedName))
	newEntries := readEntries(t, path)
	if len(rotEntries) != 3 || len(newEntries) != 2 {
		t.Fatalf("expected 3 rotated + 2 new entries, got %d + %d", len(rotEntries), len(newEntries))
	}

	// First entry of a brand-new log carries the genesis value (empty).
	if rotEntries[0].e.PrevHash != "" {
		t.Errorf("genesis entry PrevHash=%q, want \"\"", rotEntries[0].e.PrevHash)
	}

	// Verify the full chain across both files as a single sequence.
	all := append(rotEntries, newEntries...)
	for i := 1; i < len(all); i++ {
		sum := sha256.Sum256(all[i-1].raw)
		want := hex.EncodeToString(sum[:])
		if all[i].e.PrevHash != want {
			t.Errorf("entry %d: PrevHash=%s, want %s (chain broken at rotation boundary)", i, all[i].e.PrevHash, want)
		}
	}
}

// TestMaybeRotateReopenFailureRecovers is the regression test for the bug where
// a failed reopen during rotation left l.f pointing at a closed FD: Append then
// wrote to the dead handle forever and the next maybeRotate's Stat errored out,
// so a transient open failure (EMFILE/quota) at a rotation boundary permanently
// disabled the (fail-open) audit log. With the fix l.f is never left closed —
// it is set nil on failure and re-established on the next write — so the append
// during the fault errors cleanly and the log self-heals afterwards, with the
// hash chain intact across the rotation boundary.
//
// Not parallel: it swaps the package-level openFile hook.
func TestMaybeRotateReopenFailureRecovers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rotate.log")
	l, err := Open(path, testKey())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { l.Close() })

	// Three entries before rotation (rotation effectively off).
	for i := 0; i < 3; i++ {
		if err := l.Append(Entry{Outcome: "pre-rotate"}); err != nil {
			t.Fatalf("pre Append %d: %v", i, err)
		}
	}

	// Inject open failures for the next two opens: the post-rotation reopen AND
	// the immediate ensureOpen retry in the same Append, so the fault surfaces
	// as an error rather than self-healing within that one call.
	restore := openFile
	failCount := 2
	openFile = func(name string, flag int, perm os.FileMode) (*os.File, error) {
		if failCount > 0 {
			failCount--
			return nil, errors.New("injected open failure")
		}
		return restore(name, flag, perm)
	}
	defer func() { openFile = restore }()

	// Trigger rotation; both opens fail, so this Append must report an error
	// instead of silently succeeding on a closed/stale handle.
	l.maxFileSize = 1
	if err := l.Append(Entry{Outcome: "during-fault"}); err == nil {
		t.Fatal("Append must fail when the post-rotation reopen fails")
	}

	// Next Append: the open hook now succeeds, so the log must self-heal.
	if err := l.Append(Entry{Outcome: "after-recovery"}); err != nil {
		t.Fatalf("audit log must self-heal after a transient open failure: %v", err)
	}

	// Locate the rotated file and verify the full chain across both files: the
	// reopen fault must not have broken or dropped the chain.
	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var rotatedName string
	for _, de := range dirEntries {
		if de.Name() != "rotate.log" {
			rotatedName = de.Name()
		}
	}
	if rotatedName == "" {
		t.Fatal("expected a rotated file in the directory")
	}
	rotEntries := readEntries(t, filepath.Join(dir, rotatedName))
	newEntries := readEntries(t, path)
	if len(rotEntries) != 3 {
		t.Fatalf("rotated file: got %d entries, want 3 (pre-rotate)", len(rotEntries))
	}
	if len(newEntries) != 1 {
		t.Fatalf("new file: got %d entries, want 1 (only the recovered append; the faulted one was never written)", len(newEntries))
	}
	if newEntries[0].e.Seq != 1 {
		t.Errorf("recovered entry Seq=%d, want 1 (fresh per-file sequence)", newEntries[0].e.Seq)
	}
	all := append(rotEntries, newEntries...)
	if all[0].e.PrevHash != "" {
		t.Errorf("genesis entry PrevHash=%q, want \"\"", all[0].e.PrevHash)
	}
	for i := 1; i < len(all); i++ {
		sum := sha256.Sum256(all[i-1].raw)
		if want := hex.EncodeToString(sum[:]); all[i].e.PrevHash != want {
			t.Errorf("entry %d: PrevHash=%s, want %s (chain broken across the reopen fault)", i, all[i].e.PrevHash, want)
		}
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
