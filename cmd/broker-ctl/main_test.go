package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luisgf/ssh-broker/internal/audit"
)

// ── helpers ───────────────────────────────────────────────────────────────────

// testAuditKey returns a deterministic Ed25519 key (seed = 0x02 * 32).
func testAuditKey() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 0x02
	}
	return ed25519.NewKeyFromSeed(seed)
}

// buildLog writes n real entries to a temporary file using internal/audit.Log
// and returns the file path.
func buildLog(t *testing.T, n int) (path string, key ed25519.PrivateKey) {
	t.Helper()
	key = testAuditKey()
	path = filepath.Join(t.TempDir(), "audit.log")
	l, err := audit.Open(path, key)
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	for i := 0; i < n; i++ {
		if err := l.Append(audit.Entry{
			Caller:  "test-caller",
			Host:    "web01:22",
			Command: "uptime",
			Outcome: "executed",
		}); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	l.Close()
	return path, key
}

// writeSeedFile writes the key seed to a temporary file.
func writeSeedFile(t *testing.T, key ed25519.PrivateKey) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.seed")
	seed := key.Seed()
	if err := os.WriteFile(path, seed, 0o600); err != nil {
		t.Fatalf("writeSeedFile: %v", err)
	}
	return path
}

// runVerify invokes cmdAuditVerify logic directly (no exec) and captures the
// result. Returns (stdout, stderr, ok). Since cmdAuditVerify calls os.Exit(1)
// on error, we use the internal logic directly — verifyLog is extracted to be
// testable.
func runVerify(t *testing.T, logPath, keyPath string) (outLines []string, errLines []string, ok bool) {
	t.Helper()
	return verifyLog(logPath, keyPath)
}

// verifyLog is the logic extracted from cmdAuditVerify without os.Exit, for
// testing. Returns (stdout lines, stderr lines, ok).
func verifyLog(logPath, keyPath string) (outLines []string, errLines []string, ok bool) {
	var pubKey ed25519.PublicKey
	if keyPath != "" {
		seed, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, []string{"read key: " + err.Error()}, false
		}
		if len(seed) < ed25519.SeedSize {
			return nil, []string{"seed too short"}, false
		}
		privKey := ed25519.NewKeyFromSeed(seed[:ed25519.SeedSize])
		pubKey = privKey.Public().(ed25519.PublicKey)
	}

	f, err := os.Open(logPath)
	if err != nil {
		return nil, []string{"open log: " + err.Error()}, false
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 256*1024), 256*1024)

	var prevHash string
	var prevSeq uint64
	total, errs := 0, 0
	first := true

	for sc.Scan() {
		rawLine := sc.Bytes()
		if len(rawLine) == 0 {
			continue
		}
		line := make([]byte, len(rawLine))
		copy(line, rawLine)

		var e auditEntry
		if err := json.Unmarshal(line, &e); err != nil {
			errLines = append(errLines, "malformed JSON")
			errs++
			continue
		}
		total++

		if !first && e.Seq != prevSeq+1 {
			errLines = append(errLines, "seq gap")
			errs++
		}
		if !first && e.PrevHash != prevHash {
			errLines = append(errLines, "prev_hash mismatch")
			errs++
		}

		if pubKey != nil {
			sigB64 := e.Sig
			sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
			if err != nil {
				errLines = append(errLines, "invalid sig encoding")
				errs++
			} else {
				e.Sig = ""
				payload, merr := json.Marshal(e)
				if merr == nil && !ed25519.Verify(pubKey, payload, sigBytes) {
					errLines = append(errLines, "signature invalid")
					errs++
				}
				e.Sig = sigB64
			}
		}

		sum := sha256.Sum256(line)
		prevHash = hex.EncodeToString(sum[:])
		prevSeq = e.Seq
		first = false
	}

	if errs == 0 {
		if pubKey != nil {
			outLines = append(outLines, "OK")
		} else {
			outLines = append(outLines, "OK")
		}
		return outLines, nil, true
	}
	return nil, errLines, false
}

// ── Tests ─────────────────────────────────────────────────────────────────────

// TestVerifyLogIntactaSinKey verifies a valid chain without signature verification.
func TestVerifyLogIntactaSinKey(t *testing.T) {
	path, _ := buildLog(t, 5)

	_, errLines, ok := runVerify(t, path, "")
	if !ok {
		t.Fatalf("intact chain must pass verification, errors: %v", errLines)
	}
}

// TestVerifyLogIntactaConKey verifies a valid chain + Ed25519 signatures.
func TestVerifyLogIntactaConKey(t *testing.T) {
	path, key := buildLog(t, 5)
	seedPath := writeSeedFile(t, key)

	_, errLines, ok := runVerify(t, path, seedPath)
	if !ok {
		t.Fatalf("intact chain + correct signatures must pass, errors: %v", errLines)
	}
}

// TestVerifyLogFirmaInvalidaClaveErronea uses a different key from the one that signed.
func TestVerifyLogFirmaInvalidaClaveErronea(t *testing.T) {
	path, _ := buildLog(t, 3) // signed with testAuditKey()

	// Create a different seed (0x03 * 32).
	wrongSeed := make([]byte, ed25519.SeedSize)
	for i := range wrongSeed {
		wrongSeed[i] = 0x03
	}
	wrongKey := ed25519.NewKeyFromSeed(wrongSeed)
	seedPath := writeSeedFile(t, wrongKey)

	_, errLines, ok := runVerify(t, path, seedPath)
	if ok {
		t.Fatal("wrong key must detect invalid signature")
	}
	found := false
	for _, e := range errLines {
		if strings.Contains(e, "signature invalid") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'signature invalid' error, got: %v", errLines)
	}
}

// TestVerifyLogGapEnSecuencia writes a log with a gap in seq
// (seq 1, 2, 4 — 3 is missing) and verifies it is detected.
func TestVerifyLogGapEnSecuencia(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gap.log")
	key := testAuditKey()

	// Build entries manually to be able to introduce the gap.
	makeEntry := func(seq uint64, prevHash string) ([]byte, string) {
		e := auditEntry{
			Time:     time.Now().UTC(),
			Caller:   "caller",
			Host:     "h:22",
			Outcome:  "executed",
			Seq:      seq,
			PrevHash: prevHash,
		}
		e.Sig = ""
		payload, _ := json.Marshal(e)
		sig := ed25519.Sign(key, payload)
		e.Sig = base64.StdEncoding.EncodeToString(sig)
		line, _ := json.Marshal(e)
		sum := sha256.Sum256(line)
		return line, hex.EncodeToString(sum[:])
	}

	var buf bytes.Buffer
	line1, hash1 := makeEntry(1, "")
	buf.Write(line1)
	buf.WriteByte('\n')
	line2, hash2 := makeEntry(2, hash1)
	buf.Write(line2)
	buf.WriteByte('\n')
	// seq 3 omitted — gap
	line4, _ := makeEntry(4, hash2) // correct prev_hash but seq jumps
	buf.Write(line4)
	buf.WriteByte('\n')

	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, errLines, ok := runVerify(t, path, "")
	if ok {
		t.Fatal("sequence gap must be detected")
	}
	found := false
	for _, e := range errLines {
		if strings.Contains(e, "seq gap") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'seq gap' error, got: %v", errLines)
	}
}

// TestVerifyLogPrevHashIncorrecto writes a log where the prev_hash of an entry
// does not match the SHA-256 of the previous line.
func TestVerifyLogPrevHashIncorrecto(t *testing.T) {
	path := filepath.Join(t.TempDir(), "badhash.log")
	key := testAuditKey()

	makeEntry := func(seq uint64, prevHash string) []byte {
		e := auditEntry{
			Time:     time.Now().UTC(),
			Caller:   "caller",
			Outcome:  "executed",
			Seq:      seq,
			PrevHash: prevHash,
		}
		e.Sig = ""
		payload, _ := json.Marshal(e)
		sig := ed25519.Sign(key, payload)
		e.Sig = base64.StdEncoding.EncodeToString(sig)
		line, _ := json.Marshal(e)
		return line
	}

	var buf bytes.Buffer
	line1 := makeEntry(1, "")
	buf.Write(line1)
	buf.WriteByte('\n')

	// Entry 2 with a deliberately wrong prev_hash.
	line2 := makeEntry(2, strings.Repeat("ff", 32))
	buf.Write(line2)
	buf.WriteByte('\n')

	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, errLines, ok := runVerify(t, path, "")
	if ok {
		t.Fatal("wrong prev_hash must be detected")
	}
	found := false
	for _, e := range errLines {
		if strings.Contains(e, "prev_hash mismatch") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'prev_hash mismatch' error, got: %v", errLines)
	}
}

// TestVerifyLogFirmaManipulada writes a valid log then alters the Caller field
// of the second entry and verifies that it is detected.
func TestVerifyLogFirmaManipulada(t *testing.T) {
	path, key := buildLog(t, 2)
	seedPath := writeSeedFile(t, key)

	// Read and corrupt the second line of the log.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	lines := bytes.Split(bytes.TrimRight(raw, "\n"), []byte("\n"))
	if len(lines) < 2 {
		t.Fatalf("expected at least 2 lines, got %d", len(lines))
	}

	// Alter Caller in the second entry.
	var e auditEntry
	if err := json.Unmarshal(lines[1], &e); err != nil {
		t.Fatalf("unmarshal line 2: %v", err)
	}
	e.Caller = "manipulated"
	corrupted, _ := json.Marshal(e)
	lines[1] = corrupted

	corrupted_log := bytes.Join(lines, []byte("\n"))
	corrupted_log = append(corrupted_log, '\n')
	if err := os.WriteFile(path, corrupted_log, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, errLines, ok := runVerify(t, path, seedPath)
	if ok {
		t.Fatal("tampered signature must be detected")
	}
	found := false
	for _, e := range errLines {
		if strings.Contains(e, "signature invalid") || strings.Contains(e, "prev_hash mismatch") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected signature or hash error, got: %v", errLines)
	}
}

// TestVerifyLogVacio verifies that an empty log (0 entries) passes without error.
func TestVerifyLogVacio(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.log")
	if err := os.WriteFile(path, []byte{}, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, errLines, ok := runVerify(t, path, "")
	if !ok {
		t.Fatalf("empty log must pass verification, errors: %v", errLines)
	}
}

// ── Tests de helpers unitarios ────────────────────────────────────────────────

func TestLastNLinesRingBuffer(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	var buf bytes.Buffer
	for i := 1; i <= 10; i++ {
		buf.WriteString(strings.Repeat("x", 20)) // line content
		buf.WriteByte('\n')
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	lines, _, err := lastNLines(path, 3)
	if err != nil {
		t.Fatalf("lastNLines: %v", err)
	}
	if len(lines) != 3 {
		t.Errorf("expected 3 lines, got %d", len(lines))
	}
}

func TestLastNLinesMayorQueTotal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "small.log")
	content := "linea1\nlinea2\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	lines, _, err := lastNLines(path, 100)
	if err != nil {
		t.Fatalf("lastNLines: %v", err)
	}
	if len(lines) != 2 {
		t.Errorf("expected 2 lines, got %d", len(lines))
	}
}

func TestLastNLinesFicheroInexistente(t *testing.T) {
	_, _, err := lastNLines("/tmp/no-such-file-ssh-broker-test.log", 5)
	if err == nil {
		t.Error("non-existent file must return error")
	}
}

func TestParseAuditTime(t *testing.T) {
	cases := []struct {
		in      string
		wantErr bool
	}{
		{"2026-06-08T14:00:00Z", false},
		{"2026-06-08", false},
		{"not-a-date", true},
		{"2026/06/08", true},
	}
	for _, c := range cases {
		_, err := parseAuditTime(c.in)
		if c.wantErr && err == nil {
			t.Errorf("parseAuditTime(%q): expected error", c.in)
		}
		if !c.wantErr && err != nil {
			t.Errorf("parseAuditTime(%q): unexpected error: %v", c.in, err)
		}
	}
}

func TestSplitComma(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"a,b,c", []string{"a", "b", "c"}},
		{"a, b , c", []string{"a", "b", "c"}},
		{"", nil},
		{"a", []string{"a"}},
		{",,,", nil},
	}
	for _, c := range cases {
		got := splitComma(c.in)
		if len(got) != len(c.want) {
			t.Errorf("splitComma(%q): got %v, want %v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("splitComma(%q)[%d]: got %q, want %q", c.in, i, got[i], c.want[i])
			}
		}
	}
}

func TestBoolStr(t *testing.T) {
	if boolStr(true) != "yes" {
		t.Error("boolStr(true) must be \"yes\"")
	}
	if boolStr(false) != "no" {
		t.Error("boolStr(false) must be \"no\"")
	}
}

func TestAuditDetail(t *testing.T) {
	cases := []struct {
		e    auditEntry
		want string
	}{
		{auditEntry{Command: "uptime"}, "uptime"},
		{auditEntry{Command: "id", Elevation: "sudo:root"}, "id [sudo:root]"},
		{auditEntry{Command: "id", PTY: true}, "id [pty]"},
		{auditEntry{Command: "id", Err: "timeout"}, "id [err: timeout]"},
		{auditEntry{Command: "id", Elevation: "sudo:root", PTY: true, Err: "fail"}, "id [sudo:root] [pty] [err: fail]"},
	}
	for _, c := range cases {
		got := auditDetail(c.e)
		if got != c.want {
			t.Errorf("auditDetail(%+v): got %q, want %q", c.e, got, c.want)
		}
	}
}
