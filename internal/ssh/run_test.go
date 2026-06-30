package ssh

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

// waitResult is the shared cancellation/timeout core of ExecOnce; both the PTY
// and the plain (non-PTY) branch route through it, so these tests cover the
// cancellation behaviour for both — the non-PTY path silently lacked it before.

// TestWaitResultCompletes: a finished run returns (its error, true) and never
// calls onInterrupt.
func TestWaitResultCompletes(t *testing.T) {
	t.Parallel()
	done := make(chan error, 1)
	done <- nil
	interrupted := false
	err, completed := waitResult(context.Background(), done, time.Minute, func() { interrupted = true })
	if !completed || err != nil {
		t.Fatalf("completed run: got (err=%v, completed=%v), want (nil, true)", err, completed)
	}
	if interrupted {
		t.Error("onInterrupt must not be called when the run completes")
	}
}

// TestWaitResultCancel: a cancelled context aborts promptly, returns
// (ctx.Err(), false) and signals the process.
func TestWaitResultCancel(t *testing.T) {
	t.Parallel()
	done := make(chan error) // never fires
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	signalled := false
	start := time.Now()
	err, completed := waitResult(ctx, done, time.Hour, func() { signalled = true })
	if completed {
		t.Fatal("a cancelled run must report completed=false")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("want context.Canceled, got %v", err)
	}
	if !signalled {
		t.Error("onInterrupt (SIGTERM) must be called on cancellation")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("cancellation must return promptly, took %v", d)
	}
}

// TestWaitResultTimeout: with no completion and no cancel, the timeout fires,
// signals, and returns completed=false with the timeout error.
func TestWaitResultTimeout(t *testing.T) {
	t.Parallel()
	done := make(chan error) // never fires
	signalled := false
	err, completed := waitResult(context.Background(), done, 10*time.Millisecond, func() { signalled = true })
	if completed {
		t.Fatal("a timed-out run must report completed=false")
	}
	if err == nil || !strings.Contains(err.Error(), "timeout") {
		t.Errorf("want timeout error, got %v", err)
	}
	if !signalled {
		t.Error("onInterrupt (SIGTERM) must be called on timeout")
	}
}

// TestLimitedWriterConsumesAllBytes verifies the io.Writer contract: every
// Write must report the full slice as consumed (n == len(p), nil error) even
// past the cap, otherwise io.Copy inside x/crypto/ssh aborts with
// ErrShortWrite instead of delivering truncated output.
func TestLimitedWriterConsumesAllBytes(t *testing.T) {
	t.Parallel()

	lw := &limitedWriter{max: 8}
	writes := []struct {
		name string
		p    string
	}{
		{"under cap", "abc"},
		{"crosses cap", "defghij"}, // 3 already buffered, only 5 fit
		{"past cap", "klmno"},
		{"empty past cap", ""},
	}
	for _, w := range writes {
		n, err := lw.Write([]byte(w.p))
		if err != nil {
			t.Fatalf("%s: Write returned error: %v", w.name, err)
		}
		if n != len(w.p) {
			t.Fatalf("%s: Write consumed %d bytes, want %d", w.name, n, len(w.p))
		}
	}
	if got := lw.buf.String(); got != "abcdefgh" {
		t.Errorf("buffered = %q, want %q", got, "abcdefgh")
	}
	if !lw.truncated {
		t.Error("truncated flag must be set after writing past the cap")
	}
}

// TestLimitedWriterIOCopy verifies that io.Copy over a limitedWriter never
// fails (the original bug: n < len(p) with nil error made io.Copy return
// ErrShortWrite at the cap).
func TestLimitedWriterIOCopy(t *testing.T) {
	t.Parallel()

	lw := &limitedWriter{max: 16}
	src := strings.Repeat("x", 1024)
	n, err := io.Copy(lw, strings.NewReader(src))
	if err != nil {
		t.Fatalf("io.Copy must not fail at the cap: %v", err)
	}
	if n != int64(len(src)) {
		t.Errorf("io.Copy copied %d bytes, want %d", n, len(src))
	}
	if lw.buf.Len() != 16 {
		t.Errorf("buffer holds %d bytes, want %d (the cap)", lw.buf.Len(), 16)
	}
	if !lw.truncated {
		t.Error("truncated flag must be set")
	}
}

// TestLimitedWriterOutputMarker verifies the truncation marker in output().
func TestLimitedWriterOutputMarker(t *testing.T) {
	t.Parallel()

	// Not truncated: output is exactly what was written.
	lw := &limitedWriter{max: 8}
	_, _ = lw.Write([]byte("hi"))
	if got := lw.output(); got != "hi" {
		t.Errorf("output() = %q, want %q", got, "hi")
	}

	// Truncated: output carries the captured prefix plus an explicit marker.
	_, _ = lw.Write([]byte("0123456789"))
	got := lw.output()
	if !strings.HasPrefix(got, "hi012345") {
		t.Errorf("output() = %q, want prefix %q", got, "hi012345")
	}
	if !strings.Contains(got, "output truncated") {
		t.Errorf("output() = %q, want a truncation marker", got)
	}
}
