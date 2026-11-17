package audit

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
)

// shortWriteSink wraps a logFile and, while failWrite is set, models a write
// that hits ENOSPC/EDQUOT part-way: it writes the first writeBytes(len(p)) bytes
// of p to the real file and returns that count with an error, exactly as
// os.File.Write does on a full disk. failTruncate makes the rollback ftruncate
// fail too, modelling a double fault.
type shortWriteSink struct {
	inner        logFile
	failWrite    bool
	writeBytes   func(n int) int // bytes actually written on a failing Write
	failTruncate bool
	truncCalls   int
}

func (s *shortWriteSink) Write(p []byte) (int, error) {
	if !s.failWrite {
		return s.inner.Write(p)
	}
	n, err := s.inner.Write(p[:s.writeBytes(len(p))])
	if err != nil {
		return n, err
	}
	return n, errors.New("injected write failure: no space left on device")
}
func (s *shortWriteSink) Stat() (os.FileInfo, error) { return s.inner.Stat() }
func (s *shortWriteSink) Close() error               { return s.inner.Close() }
func (s *shortWriteSink) Sync() error                { return s.inner.Sync() }
func (s *shortWriteSink) Truncate(size int64) error {
	s.truncCalls++
	if s.failTruncate {
		return errors.New("injected truncate failure")
	}
	return s.inner.Truncate(size)
}

func halfOf(n int) int { return n / 2 }

func verifyFile(t *testing.T, path string) (total, errs int, reports []string) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	total, errs = Verify(f, pub(testKey()), func(format string, _ ...any) {
		reports = append(reports, format)
	})
	return total, errs, reports
}

// TestAppendShortWriteRollsBack pins #814: a Write that fails after writing part
// of the line (ENOSPC/EDQUOT) must leave no fragment on disk. Before the fix the
// half line stayed there without a newline and the next successful Append — an
// "issued" record under fail-closed mode — was glued onto it: an unparseable
// line, a permanently failing Verify, and an issuance invisible to audit show.
func TestAppendShortWriteRollsBack(t *testing.T) {
	t.Parallel()
	l, path := openTmp(t)
	if err := l.Append(Entry{Outcome: "pre"}); err != nil {
		t.Fatalf("pre Append: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	sink := &shortWriteSink{inner: l.f, failWrite: true, writeBytes: halfOf}
	l.f = sink
	if err := l.Append(Entry{Outcome: "during-fault"}); err == nil {
		t.Fatal("Append must surface the injected write error")
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(after, before) {
		t.Fatalf("failed Append left %d stray bytes on disk", len(after)-len(before))
	}

	// Space is freed: the issuance and one more record succeed.
	sink.failWrite = false
	if err := l.Append(Entry{Outcome: "issued", Serial: 42}); err != nil {
		t.Fatalf("issued Append: %v", err)
	}
	if err := l.Append(Entry{Outcome: "post"}); err != nil {
		t.Fatalf("post Append: %v", err)
	}

	total, errs, reports := verifyFile(t, path)
	if total != 3 || errs != 0 {
		t.Fatalf("Verify = (%d,%d), want (3,0); reports: %v", total, errs, reports)
	}
	// readEntries fails the test on any line that is not a complete JSON entry,
	// so this also proves the file holds no fragment.
	entries := readEntries(t, path)
	if len(entries) != 3 {
		t.Fatalf("got %d lines, want 3", len(entries))
	}
	if e := entries[1].e; e.Outcome != "issued" || e.Serial != 42 || e.Seq != 2 {
		t.Fatalf("line 2 = %+v, want the issued serial-42 record at seq 2", e)
	}
}

// TestAppendShortWriteTruncateFailsKeepsNextRecordOnOwnLine covers the double
// fault: the write is short AND the rollback ftruncate fails, so the fragment
// stays on disk. The next record must still start on its own physical line.
//
// What Verify then reports, precisely: the fragment (the first half of a JSON
// object, no newline) is its own line and fails to parse — exactly one
// "malformed JSON" error. verify skips a malformed line without advancing its
// chain state, and the failed Append committed nothing (seq/prev_hash
// unchanged), so the issued record carries seq 2 and the hash of the "pre" line:
// it chains to "pre" across the fragment with no seq-gap or prev_hash error, and
// its signature is valid. So: total=3 parsed entries, errs=1 (the fragment).
func TestAppendShortWriteTruncateFailsKeepsNextRecordOnOwnLine(t *testing.T) {
	t.Parallel()
	l, path := openTmp(t)
	if err := l.Append(Entry{Outcome: "pre"}); err != nil {
		t.Fatalf("pre Append: %v", err)
	}

	sink := &shortWriteSink{inner: l.f, failWrite: true, writeBytes: halfOf, failTruncate: true}
	l.f = sink
	if err := l.Append(Entry{Outcome: "during-fault"}); err == nil {
		t.Fatal("Append must surface the injected write error")
	} else if !strings.Contains(err.Error(), "no space left") {
		t.Fatalf("Append error = %v, want the write error (not the truncate error)", err)
	}
	if sink.truncCalls != 1 {
		t.Fatalf("Truncate called %d times, want 1 rollback attempt", sink.truncCalls)
	}

	sink.failWrite = false
	if err := l.Append(Entry{Outcome: "issued", Serial: 42}); err != nil {
		t.Fatalf("issued Append: %v", err)
	}
	if err := l.Append(Entry{Outcome: "post"}); err != nil {
		t.Fatalf("post Append: %v", err)
	}

	total, errs, reports := verifyFile(t, path)
	if total != 3 || errs != 1 {
		t.Fatalf("Verify = (%d,%d), want (3,1) — only the fragment malformed; reports: %v", total, errs, reports)
	}
	if len(reports) != 1 || !strings.HasPrefix(reports[0], "malformed JSON") {
		t.Fatalf("Verify reports = %v, want exactly one malformed-JSON report", reports)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("got %d physical lines, want 4 (pre, fragment, issued, post)", len(lines))
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	ok, skipped, _ := VerifyEntries(f, pub(testKey()), discardReport)
	if skipped != 1 || len(ok) != 3 {
		t.Fatalf("VerifyEntries ok=%d skipped=%d, want 3 and 1", len(ok), skipped)
	}
	if ok[1].Outcome != "issued" || ok[1].Serial != 42 || ok[1].Seq != 2 {
		t.Fatalf("second good entry = %+v, want the issued serial-42 record at seq 2", ok[1])
	}
}

// TestAppendZeroByteWriteFailureUnchanged: a Write that fails having written
// nothing behaves as before — the error surfaces, nothing is on disk, no
// rollback is attempted, and the next records chain cleanly.
func TestAppendZeroByteWriteFailureUnchanged(t *testing.T) {
	t.Parallel()
	l, path := openTmp(t)
	if err := l.Append(Entry{Outcome: "pre"}); err != nil {
		t.Fatalf("pre Append: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	sink := &shortWriteSink{inner: l.f, failWrite: true, writeBytes: func(int) int { return 0 }}
	l.f = sink
	if err := l.Append(Entry{Outcome: "during-fault"}); err == nil {
		t.Fatal("Append must surface the injected write error")
	}
	if sink.truncCalls != 0 {
		t.Fatalf("Truncate called %d times after a zero-byte failed write, want 0", sink.truncCalls)
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(after, before) {
		t.Fatal("a zero-byte failed write changed the file")
	}

	sink.failWrite = false
	if err := l.Append(Entry{Outcome: "post"}); err != nil {
		t.Fatalf("post Append: %v", err)
	}
	total, errs, reports := verifyFile(t, path)
	if total != 2 || errs != 0 {
		t.Fatalf("Verify = (%d,%d), want (2,0); reports: %v", total, errs, reports)
	}
	if data, _ := os.ReadFile(path); bytes.Contains(data, []byte("\n\n")) {
		t.Fatal("zero-byte failure must not introduce a blank line")
	}
}
