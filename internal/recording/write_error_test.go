package recording

import (
	"path/filepath"
	"testing"
)

// TestRecordingWriteErrorMetric pins #206: an event write that fails after the
// session opened (a broken .cast fd) increments recording_write_errors_total, so
// a recording that silently fails open still leaves an operational signal.
func TestRecordingWriteErrorMetric(t *testing.T) {
	before := recordingWriteErrors.Value()

	r, err := Open(filepath.Join(t.TempDir(), "s.cast"), Meta{SessionID: "s"})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	// Close the underlying fd out from under the recorder so writes fail while
	// r.f is still non-nil (Recorder.Close would nil it and silently no-op).
	if err := r.f.Close(); err != nil {
		t.Fatalf("close fd: %v", err)
	}

	if err := r.WriteOutput("hello"); err == nil {
		t.Fatal("expected a write error on a closed fd")
	}
	if got := recordingWriteErrors.Value(); got != before+1 {
		t.Errorf("recording_write_errors_total = %d, want %d", got, before+1)
	}

	// A no-data write must not count (it returns nil before touching the fd).
	if err := r.WriteOutput(""); err != nil {
		t.Errorf("empty write should be a no-op, got %v", err)
	}
	if got := recordingWriteErrors.Value(); got != before+1 {
		t.Errorf("empty write must not increment the counter: got %d, want %d", got, before+1)
	}
}
