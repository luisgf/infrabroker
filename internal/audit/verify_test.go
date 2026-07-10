package audit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ── helpers ─────────────────────────────────────────────────────────────────

// pub returns the public half of a private key.
func pub(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

// appendN writes n real entries through the producer and returns the path.
func appendN(t *testing.T, n int) (path string, key ed25519.PrivateKey) {
	t.Helper()
	key = testKey()
	path = filepath.Join(t.TempDir(), "audit.log")
	l, err := Open(path, key)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	for i := 0; i < n; i++ {
		if err := l.Append(Entry{Caller: "c", Host: "web01:22", Command: "uptime", Outcome: "executed"}); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	l.Close()
	return path, key
}

// signEntry marshals e exactly like Append (sign over Sig="", then re-marshal
// with Sig set) and returns the JSON line plus the SHA-256 hex of that line —
// the prev_hash the next entry must carry. It lets a test craft a chain, valid
// or deliberately broken, without the producer's rotation/seq bookkeeping.
func signEntry(key ed25519.PrivateKey, e Entry) (line []byte, hash string) {
	e.Sig = ""
	payload, _ := json.Marshal(e)
	e.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(key, payload))
	line, _ = json.Marshal(e)
	sum := sha256.Sum256(line)
	return line, hex.EncodeToString(sum[:])
}

// writeSegment writes n chained UNSIGNED entries to path, starting from startSeq
// with the given starting prev_hash, and returns the SHA-256 of the last line —
// the prev_hash the next segment must carry to link continuously.
func writeSegment(t *testing.T, path string, startSeq uint64, startPrev string, n int) (lastHash string) {
	t.Helper()
	var data []byte
	prev := startPrev
	seq := startSeq
	for i := 0; i < n; i++ {
		e := Entry{Seq: seq, PrevHash: prev, Time: time.Unix(0, 0).UTC(), Caller: "c", Host: "h", Outcome: "executed"}
		line, err := json.Marshal(e)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		data = append(data, line...)
		data = append(data, '\n')
		sum := sha256.Sum256(line)
		prev = hex.EncodeToString(sum[:])
		seq++
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write segment: %v", err)
	}
	return prev
}

func discardReport(string, ...any) {}

func collectReport(msgs *[]string) func(string, ...any) {
	return func(f string, a ...any) { *msgs = append(*msgs, fmt.Sprintf(f, a...)) }
}

// ── round-trip: producer → verifier (acceptance criterion) ───────────────────

// TestVerifyRoundTrip proves the producer and the verifier agree end to end:
// a chain written by Append verifies; a chain that rotated verifies across its
// segments; a single tampered byte is caught; and a truncated tail is detected.
func TestVerifyRoundTrip(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		t.Parallel()
		path, key := appendN(t, 5)
		f, _ := os.Open(path)
		defer f.Close()
		total, errs := Verify(f, pub(key), discardReport)
		if total != 5 || errs != 0 {
			t.Fatalf("Verify(happy) = (%d,%d); want (5,0)", total, errs)
		}
	})

	t.Run("cross-segment chain", func(t *testing.T) {
		t.Parallel()
		key := testKey()
		path := filepath.Join(t.TempDir(), "audit.log")
		l, err := Open(path, key)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		l.maxFileSize = 200 // force exactly one rotation on the 2nd append
		for i := 0; i < 2; i++ {
			if err := l.Append(Entry{Caller: "c", Host: "h:22", Command: "id", Outcome: "executed"}); err != nil {
				t.Fatalf("Append %d: %v", i, err)
			}
		}
		l.Close()
		segs, _ := discoverSegments(path)
		if len(segs) < 2 {
			t.Fatalf("expected a rotated segment plus the active file, got %v", segs)
		}
		var msgs []string
		total, errs := VerifySegments(path, pub(key), collectReport(&msgs))
		if total != 2 || errs != 0 {
			t.Fatalf("VerifySegments = (%d,%d); want (2,0); msgs=%v", total, errs, msgs)
		}
	})

	t.Run("tampered entry", func(t *testing.T) {
		t.Parallel()
		path, key := appendN(t, 3)
		raw, _ := os.ReadFile(path)
		lines := bytes.Split(bytes.TrimRight(raw, "\n"), []byte("\n"))
		var e Entry
		if err := json.Unmarshal(lines[1], &e); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		e.Caller = "attacker" // re-marshal WITHOUT re-signing → signature no longer covers it
		lines[1], _ = json.Marshal(e)
		if err := os.WriteFile(path, append(bytes.Join(lines, []byte("\n")), '\n'), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		var msgs []string
		if _, errs := Verify(bytes.NewReader(mustRead(t, path)), pub(key), collectReport(&msgs)); errs == 0 {
			t.Fatalf("tampered entry must fail verification; msgs=%v", msgs)
		}
	})

	t.Run("truncated tail", func(t *testing.T) {
		t.Parallel()
		path, key := appendN(t, 4)
		raw := mustRead(t, path)
		torn := raw[:len(raw)-10] // chop the last record's tail
		if err := os.WriteFile(path, torn, 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		_, _, good, corruptTail, middle := TrailingCorruption(torn)
		if middle || len(corruptTail) == 0 || good != 3 {
			t.Fatalf("TrailingCorruption(torn) good=%d corrupt=%q middle=%v; want good=3, some corrupt, middle=false", good, corruptTail, middle)
		}
		var msgs []string
		if _, errs := Verify(bytes.NewReader(torn), pub(key), collectReport(&msgs)); errs == 0 {
			t.Fatalf("a truncated tail must be reported by Verify; msgs=%v", msgs)
		}
	})
}

// ── Verify: chain + signature semantics ──────────────────────────────────────

func TestVerifyIntactNoKey(t *testing.T) {
	t.Parallel()
	path, _ := appendN(t, 5)
	f, _ := os.Open(path)
	defer f.Close()
	if _, errs := Verify(f, nil, discardReport); errs != 0 {
		t.Fatalf("intact chain must pass without a key, errs=%d", errs)
	}
}

func TestVerifyWrongKey(t *testing.T) {
	t.Parallel()
	path, _ := appendN(t, 3) // signed with testKey() (0x01)
	wrong := make([]byte, ed25519.SeedSize)
	for i := range wrong {
		wrong[i] = 0x03
	}
	f, _ := os.Open(path)
	defer f.Close()
	var msgs []string
	_, errs := Verify(f, pub(ed25519.NewKeyFromSeed(wrong)), collectReport(&msgs))
	if errs == 0 {
		t.Fatal("wrong key must detect an invalid signature")
	}
	if !anyContains(msgs, "signature invalid") {
		t.Errorf("expected 'signature invalid', got %v", msgs)
	}
}

func TestVerifySeqGap(t *testing.T) {
	t.Parallel()
	key := testKey()
	line1, hash1 := signEntry(key, Entry{Seq: 1, Caller: "c", Host: "h:22", Outcome: "executed"})
	line2, hash2 := signEntry(key, Entry{Seq: 2, PrevHash: hash1, Caller: "c", Host: "h:22", Outcome: "executed"})
	line4, _ := signEntry(key, Entry{Seq: 4, PrevHash: hash2, Caller: "c", Host: "h:22", Outcome: "executed"}) // seq 3 missing
	data := bytes.Join([][]byte{line1, line2, line4}, []byte("\n"))
	data = append(data, '\n')
	var msgs []string
	if _, errs := Verify(bytes.NewReader(data), pub(key), collectReport(&msgs)); errs == 0 || !anyContains(msgs, "gap or reorder") {
		t.Errorf("sequence gap must be detected, msgs=%v", msgs)
	}
}

func TestVerifyPrevHashMismatch(t *testing.T) {
	t.Parallel()
	key := testKey()
	line1, _ := signEntry(key, Entry{Seq: 1, Caller: "c", Outcome: "executed"})
	line2, _ := signEntry(key, Entry{Seq: 2, PrevHash: strings.Repeat("ff", 32), Caller: "c", Outcome: "executed"})
	data := append(append(append([]byte{}, line1...), '\n'), append(line2, '\n')...)
	var msgs []string
	if _, errs := Verify(bytes.NewReader(data), pub(key), collectReport(&msgs)); errs == 0 || !anyContains(msgs, "prev_hash mismatch") {
		t.Errorf("wrong prev_hash must be detected, msgs=%v", msgs)
	}
}

func TestVerifyEmptyLog(t *testing.T) {
	t.Parallel()
	if total, errs := Verify(bytes.NewReader(nil), nil, discardReport); total != 0 || errs != 0 {
		t.Fatalf("empty log must pass: (%d,%d)", total, errs)
	}
}

// TestVerifyApprovalAndAnomalyFields is a regression guard: every signed field
// of Entry must be covered by the canonical Sig="" re-marshal, so an entry
// carrying approval/anomaly/policy fields still verifies under --key. If a new
// signed field were dropped from canonicalization, this fails here (in the
// producing package) instead of on an operator's machine.
func TestVerifyApprovalAndAnomalyFields(t *testing.T) {
	t.Parallel()
	key := testKey()
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := Open(path, key)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	for i, e := range []Entry{
		{Caller: "c", Host: "h:22", Command: "reboot", Outcome: "executed", PolicyRule: "^reboot$", ApprovalID: "req-1", ApprovedBy: "admin"},
		{Caller: "c", Host: "h:22", Command: "rm -rf /tmp/x", Outcome: "denied", DryRun: true},
		{Caller: "c", Host: "new:22", Command: "id", Outcome: "executed", Anomaly: "new-host:new"},
	} {
		if err := l.Append(e); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	l.Close()
	f, _ := os.Open(path)
	defer f.Close()
	if _, errs := Verify(f, pub(key), discardReport); errs != 0 {
		t.Fatalf("entries with approval/anomaly fields must pass --key verification, errs=%d", errs)
	}
}

// TestVerifyRotationSeed: a file whose FIRST line carries a non-empty prev_hash
// (chain continuity across rotated files) is accepted — the first line's
// prev_hash is the chain seed, not a required empty genesis.
func TestVerifyRotationSeed(t *testing.T) {
	t.Parallel()
	key := testKey()
	line1, hash1 := signEntry(key, Entry{Seq: 1, PrevHash: strings.Repeat("ab", 32), Caller: "c", Host: "h:22", Outcome: "executed"})
	line2, _ := signEntry(key, Entry{Seq: 2, PrevHash: hash1, Caller: "c", Host: "h:22", Outcome: "executed"})
	data := append(append(append([]byte{}, line1...), '\n'), append(line2, '\n')...)
	if _, errs := Verify(bytes.NewReader(data), pub(key), discardReport); errs != 0 {
		t.Fatalf("a rotated file with a non-empty seed prev_hash must pass, errs=%d", errs)
	}
}

// ── VerifyEntry ──────────────────────────────────────────────────────────────

func TestVerifyEntry(t *testing.T) {
	t.Parallel()
	key := testKey()
	line, _ := signEntry(key, Entry{Seq: 1, Caller: "c", Outcome: "executed"})
	var e Entry
	if err := json.Unmarshal(line, &e); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := VerifyEntry(e, pub(key)); err != nil {
		t.Fatalf("valid entry: %v", err)
	}
	wrong := make([]byte, ed25519.SeedSize)
	for i := range wrong {
		wrong[i] = 0x09
	}
	if err := VerifyEntry(e, pub(ed25519.NewKeyFromSeed(wrong))); err == nil || err.Error() != "signature invalid" {
		t.Fatalf("wrong key: got %v, want 'signature invalid'", err)
	}
	bad := e
	bad.Sig = "!!!not-base64!!!"
	if err := VerifyEntry(bad, pub(key)); err == nil || !strings.Contains(err.Error(), "invalid sig encoding") {
		t.Fatalf("bad sig encoding: got %v", err)
	}
}

// ── VerifySegments: cross-segment linkage ────────────────────────────────────

func TestVerifySegmentsLinked(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	active := filepath.Join(dir, "audit.log")
	rotated := active + ".20260101T000000Z"
	last := writeSegment(t, rotated, 1, "", 3) // genesis segment
	writeSegment(t, active, 4, last, 2)        // active links to rotated's last hash
	if _, errs := VerifySegments(active, nil, discardReport); errs != 0 {
		t.Fatalf("a continuously-linked rotated chain must verify, errs=%d", errs)
	}
}

func TestVerifySegmentsDroppedEarliest(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	active := filepath.Join(dir, "audit.log")
	writeSegment(t, active, 4, "deadbeef", 2) // dangling prev_hash, no genesis
	var msgs []string
	if _, errs := VerifySegments(active, nil, collectReport(&msgs)); errs == 0 {
		t.Fatalf("a dropped earliest segment must be detected; msgs=%v", msgs)
	}
}

func TestVerifySegmentsBrokenLink(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	active := filepath.Join(dir, "audit.log")
	rotated := active + ".20260101T000000Z"
	writeSegment(t, rotated, 1, "", 2)    // genesis
	writeSegment(t, active, 3, "0000", 2) // does NOT link to rotated's last hash
	if _, errs := VerifySegments(active, nil, discardReport); errs == 0 {
		t.Fatal("a broken cross-segment link must be detected")
	}
}

// TestVerifySegmentsIgnoresQuarantineFile pins #245: `audit repair` leaves a
// quarantine file named <log>.corrupt-<ts>, which shares the <log>.* glob prefix
// but is NOT a rotation segment. discoverSegments must skip it, so `verify --all`
// does not run Verify() over the (malformed by definition) quarantined bytes and
// falsely report a correctly-repaired chain as broken.
func TestVerifySegmentsIgnoresQuarantineFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	active := filepath.Join(dir, "audit.log")
	rotated := active + ".20260101T000000Z"
	last := writeSegment(t, rotated, 1, "", 3)
	writeSegment(t, active, 4, last, 2)

	// The quarantine file the repair command leaves behind: torn, malformed bytes.
	quarantine := active + ".corrupt-20260101T010000Z"
	if err := os.WriteFile(quarantine, []byte("{not valid json, torn record"), 0o600); err != nil {
		t.Fatal(err)
	}

	segs, err := discoverSegments(active)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range segs {
		if s == quarantine {
			t.Errorf("the quarantine file must not be discovered as a segment: %v", segs)
		}
	}
	if _, errs := VerifySegments(active, nil, discardReport); errs != 0 {
		t.Fatalf("a valid chain beside a quarantine file must verify cleanly, errs=%d", errs)
	}
}

// ── FileBounds ───────────────────────────────────────────────────────────────

func TestFileBounds(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	seg := filepath.Join(dir, "audit.log")
	writeSegment(t, seg, 1, "seed-prev", 3)
	firstPrev, lastHash, err := FileBounds(seg)
	if err != nil {
		t.Fatalf("FileBounds: %v", err)
	}
	if firstPrev != "seed-prev" {
		t.Errorf("firstPrev=%q; want %q", firstPrev, "seed-prev")
	}
	if len(lastHash) != 64 {
		t.Errorf("lastHash=%q; want a 64-hex-char SHA-256", lastHash)
	}
	empty := filepath.Join(dir, "empty.log")
	os.WriteFile(empty, nil, 0o600)
	if _, _, err := FileBounds(empty); err == nil {
		t.Error("empty segment must return an error")
	}
}

// ── TrailingCorruption ───────────────────────────────────────────────────────

func TestTrailingCorruption(t *testing.T) {
	t.Parallel()
	rec := func(seq int) string { return fmt.Sprintf(`{"seq":%d,"outcome":"executed"}`, seq) }
	cases := []struct {
		name        string
		data        string
		wantGood    int
		wantLastSeq uint64
		wantCorrupt string
		wantMiddle  bool
	}{
		{"clean", rec(1) + "\n" + rec(2) + "\n", 2, 2, "", false},
		{"torn_tail", rec(1) + "\n" + rec(2) + "\n" + `{"seq":3,"outc`, 2, 2, `{"seq":3,"outc`, false},
		{"complete_no_newline", rec(1) + "\n" + rec(2), 2, 2, "", false},
		{"middle_corruption", rec(1) + "\n" + "garbage\n" + rec(3) + "\n", 1, 1, "", true},
		{"all_corrupt", "garbage-line\n", 0, 0, "garbage-line\n", false},
		{"trailing_blank", rec(1) + "\n\n", 1, 1, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cleanEnd, lastSeq, good, corrupt, middle := TrailingCorruption([]byte(c.data))
			if good != c.wantGood || lastSeq != c.wantLastSeq || middle != c.wantMiddle {
				t.Errorf("good=%d lastSeq=%d middle=%v; want %d/%d/%v", good, lastSeq, middle, c.wantGood, c.wantLastSeq, c.wantMiddle)
			}
			if string(corrupt) != c.wantCorrupt {
				t.Errorf("corruptTail=%q; want %q", corrupt, c.wantCorrupt)
			}
			if string(corrupt) != "" && cleanEnd != len(c.data)-len(c.wantCorrupt) {
				t.Errorf("cleanEnd=%d; want %d", cleanEnd, len(c.data)-len(c.wantCorrupt))
			}
		})
	}
}

// ── tiny local helpers ───────────────────────────────────────────────────────

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

func anyContains(msgs []string, sub string) bool {
	for _, m := range msgs {
		if strings.Contains(m, sub) {
			return true
		}
	}
	return false
}
