package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/luisgf/infrabroker/internal/audit"
)

// writeSegment writes n chained audit entries (unsigned) to path, starting from
// startSeq with the given starting prev_hash, and returns the SHA-256 of the
// last line — the prev_hash the next segment must carry to link continuously.
func writeSegment(t *testing.T, path string, startSeq uint64, startPrev string, n int) (lastHash string) {
	t.Helper()
	var data []byte
	prev := startPrev
	seq := startSeq
	for i := 0; i < n; i++ {
		e := audit.Entry{
			Seq: seq, PrevHash: prev, Time: time.Unix(0, 0).UTC(),
			Caller: "c", Host: "h", Outcome: "executed",
		}
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

// TestVerifyAuditSegmentsLinked: a genesis rotated segment plus an active file
// that links to it must verify across the whole chain.
func TestVerifyAuditSegmentsLinked(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	active := filepath.Join(dir, "audit.log")
	rotated := active + ".20260101T000000Z"
	last := writeSegment(t, rotated, 1, "", 3) // genesis segment
	writeSegment(t, active, 4, last, 2)        // active links to rotated's last hash
	if _, errs := verifyAuditSegments(active, nil, discardReport); errs != 0 {
		t.Fatalf("a continuously-linked rotated chain must verify, errs=%d", errs)
	}
}

// TestVerifyAuditSegmentsDroppedEarliest: only the active file survives and its
// first entry links to a now-missing rotated segment (prev_hash != genesis).
// This is the dropped-segment / truncate-then-restart case the single-file
// verifier could not detect.
func TestVerifyAuditSegmentsDroppedEarliest(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	active := filepath.Join(dir, "audit.log")
	writeSegment(t, active, 4, "deadbeef", 2) // dangling prev_hash, no genesis
	var msgs []string
	if _, errs := verifyAuditSegments(active, nil, collectReport(&msgs)); errs == 0 {
		t.Fatalf("a dropped earliest segment must be detected; messages=%v", msgs)
	}
}

// TestVerifyAuditSegmentsBrokenLink: the active file's first prev_hash does not
// match the previous segment's last line — a dropped/replaced middle segment.
func TestVerifyAuditSegmentsBrokenLink(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	active := filepath.Join(dir, "audit.log")
	rotated := active + ".20260101T000000Z"
	writeSegment(t, rotated, 1, "", 2)    // genesis
	writeSegment(t, active, 3, "0000", 2) // does NOT link to rotated's last hash
	if _, errs := verifyAuditSegments(active, nil, discardReport); errs == 0 {
		t.Fatal("a broken cross-segment link must be detected")
	}
}
