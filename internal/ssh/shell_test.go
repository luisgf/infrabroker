package ssh

import (
	"io"
	"strings"
	"testing"
	"time"
)

// nopWriteCloser wraps an io.Writer so it can stand in for the shell stdin.
type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

// testShellSession builds a ShellSession without a real SSH connection: Exec
// only touches stdin, lines, marker, and the broken flag.
func testShellSession() *ShellSession {
	return &ShellSession{
		stdin:  nopWriteCloser{io.Discard},
		lines:  make(chan lineRes),
		done:   make(chan struct{}),
		marker: "__BRK_test__",
	}
}

// TestSyncBufConsumesAllBytes verifies the io.Writer contract at the cap: a
// boundary-crossing write must report the full slice as consumed, otherwise
// the io.Copy goroutine draining stderr dies with ErrShortWrite.
func TestSyncBufConsumesAllBytes(t *testing.T) {
	t.Parallel()

	sb := &syncBuf{}
	// Fill up to three bytes below the cap.
	fill := strings.Repeat("x", maxOutputBytes-3)
	if n, err := sb.Write([]byte(fill)); n != len(fill) || err != nil {
		t.Fatalf("fill write: n=%d err=%v, want n=%d err=nil", n, err, len(fill))
	}

	// Boundary write: only 3 of 10 bytes fit, but all must be consumed.
	p := []byte("0123456789")
	n, err := sb.Write(p)
	if err != nil {
		t.Fatalf("boundary write returned error: %v", err)
	}
	if n != len(p) {
		t.Fatalf("boundary write consumed %d bytes, want %d", n, len(p))
	}

	// Past the cap: still fully consumed, silently discarded.
	n, err = sb.Write([]byte("more"))
	if n != 4 || err != nil {
		t.Fatalf("write past cap: n=%d err=%v, want n=4 err=nil", n, err)
	}

	if got := sb.snapshotLen(); got != maxOutputBytes {
		t.Errorf("buffer holds %d bytes, want exactly the cap %d", got, maxOutputBytes)
	}
	if got := sb.since(maxOutputBytes - 3); got != "012" {
		t.Errorf("tail = %q, want %q", got, "012")
	}
}

// TestShellReaderExitsOnDone verifies that the reader goroutine exits when
// done is closed even with no receiver on lines (the leak: an unbuffered send
// after Close blocked the goroutine forever).
func TestShellReaderExitsOnDone(t *testing.T) {
	t.Parallel()

	lines := make(chan lineRes) // unbuffered, nobody receives
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		shellReader(strings.NewReader("orphan line\n"), lines, done)
		close(finished)
	}()

	close(done)
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("shellReader did not exit after done was closed")
	}
}

// TestShellSessionExecHappyPath verifies the marker protocol: stdout lines up
// to the marker are returned with the exit code the marker carries.
func TestShellSessionExecHappyPath(t *testing.T) {
	t.Parallel()

	sh := testShellSession()
	go func() {
		sh.lines <- lineRes{text: "hello\n"}
		sh.lines <- lineRes{text: sh.marker + ":7\n"}
	}()

	res, err := sh.Exec("echo hello", time.Second)
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if res.Stdout != "hello\n" {
		t.Errorf("Stdout = %q, want %q", res.Stdout, "hello\n")
	}
	if res.ExitCode != 7 {
		t.Errorf("ExitCode = %d, want 7", res.ExitCode)
	}
}

// TestShellSessionExecCapturesUnterminatedLine verifies that output whose final
// line lacks a trailing newline (e.g. `printf hello`) is not dropped: the shell
// writes the marker right after it on the same line, and Exec must return the
// text before the marker as stdout.
func TestShellSessionExecCapturesUnterminatedLine(t *testing.T) {
	t.Parallel()

	sh := testShellSession()
	go func() {
		sh.lines <- lineRes{text: "hello" + sh.marker + ":0\n"}
	}()

	res, err := sh.Exec("printf hello", time.Second)
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if res.Stdout != "hello" {
		t.Errorf("Stdout = %q, want %q", res.Stdout, "hello")
	}
	if res.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", res.ExitCode)
	}
}

// TestShellSessionExecBadMarkerBreaksSession verifies that a marker line with a
// non-numeric exit code marks the session broken instead of silently reporting
// exit 0.
func TestShellSessionExecBadMarkerBreaksSession(t *testing.T) {
	t.Parallel()

	sh := testShellSession()
	go func() {
		sh.lines <- lineRes{text: sh.marker + ":notanumber\n"}
	}()

	_, err := sh.Exec("cmd", time.Second)
	if err == nil || !strings.Contains(err.Error(), "exit code") {
		t.Fatalf("Exec must fail on a non-numeric exit code, got: %v", err)
	}
	if !sh.broken {
		t.Error("session must be marked broken after a mangled marker")
	}
}

// TestShellSessionExecBrokenAfterTimeout verifies that after a timeout the
// session is marked permanently broken: the next Exec must fail immediately
// (without reading the late output of the previous command) with an error
// telling the caller to close and reopen the session.
func TestShellSessionExecBrokenAfterTimeout(t *testing.T) {
	t.Parallel()

	sh := testShellSession()

	// No line ever arrives: Exec must time out and mark the session broken.
	_, err := sh.Exec("sleep 999", 20*time.Millisecond)
	if err == nil {
		t.Fatal("Exec without output must time out")
	}
	if !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("unexpected timeout error: %v", err)
	}

	// Simulate the late output + marker of the timed-out command still in
	// flight. A desynchronised Exec would consume it and misattribute it.
	go func() {
		select {
		case sh.lines <- lineRes{text: "late output\n"}:
			t.Error("a broken session must not read in-flight lines")
		case <-sh.done:
		}
	}()

	start := time.Now()
	_, err = sh.Exec("id", time.Minute)
	if err == nil {
		t.Fatal("Exec on a broken session must fail")
	}
	if !strings.Contains(err.Error(), "close") {
		t.Errorf("error must tell the caller to close the session, got: %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("Exec on a broken session must fail immediately, took %v", elapsed)
	}
	close(sh.done) // release the helper goroutine
}

// TestShellSessionExecBrokenAfterOverflow verifies that exceeding the output
// limit mid-command (rest of the output and marker still in flight) also
// marks the session broken.
func TestShellSessionExecBrokenAfterOverflow(t *testing.T) {
	t.Parallel()

	sh := testShellSession()
	go func() {
		big := strings.Repeat("y", maxOutputBytes+1) + "\n"
		select {
		case sh.lines <- lineRes{text: big}:
		case <-sh.done:
		}
	}()

	_, err := sh.Exec("yes", time.Second)
	if err == nil || !strings.Contains(err.Error(), "exceeds limit") {
		t.Fatalf("Exec must fail with the output-limit error, got: %v", err)
	}

	_, err = sh.Exec("id", time.Second)
	if err == nil || !strings.Contains(err.Error(), "close") {
		t.Fatalf("Exec after overflow must fail telling the caller to close the session, got: %v", err)
	}
	close(sh.done)
}
