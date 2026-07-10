package ssh

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/luisgf/infrabroker/internal/recording"
)

// ShellSession keeps a live shell interpreter over an SSH connection, so that
// state (cwd, variables) persists between commands.
//
// Two variants:
//
//   - Without PTY (mode=shell): starts /bin/sh directly. stdout and stderr are
//     separate. No echo, no prompt. Not suitable for commands that check
//     isatty().
//
//   - With PTY (mode=pty): requests a pseudo-terminal and starts the shell
//     under it. stdout and stderr are merged in the PTY channel. Echo is
//     disabled and the prompt is cleared (PS1=”) so the same marker protocol
//     can be applied. Suitable for programs that require a real TTY.
//
// End-of-command is detected with a random marker that prints the exit code.
// Does not support interactive commands that read from the keyboard.
type lineRes struct {
	text string
	err  error
}

const shellReaderLineSlack = 4096

var errShellLineTooLong = errors.New("shell output line exceeds limit")

type ShellSession struct {
	mu       sync.Mutex
	session  *ssh.Session
	stdin    io.WriteCloser
	lines    chan lineRes  // fed by a single reader goroutine
	done     chan struct{} // closed on Close; releases the reader goroutine
	stderr   *syncBuf      // nil in PTY mode (merged streams)
	marker   string
	pty      bool                // true if the session uses a PTY
	recorder *recording.Recorder // nil = recording disabled

	closeOnce sync.Once
	// broken is set when the marker protocol desynchronises (e.g. an Exec
	// timeout left the command's output and marker in flight). Once broken,
	// every Exec fails: reading the channel again would attribute the
	// previous command's output to the next one.
	broken bool
}

// SetRecorder attaches a Recorder to this session. All subsequent Exec calls
// will tee stdin, stdout, and stderr (when applicable) to the recorder.
// Must be called before the first Exec.
func (s *ShellSession) SetRecorder(r *recording.Recorder) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recorder = r
	if s.stderr != nil {
		s.stderr.recorder = r
	}
}

// syncBuf is a concurrent buffer: a goroutine drains stderr into it. Exec resets
// it before each command (see reset), so the maxOutputBytes cap applies PER
// COMMAND. Capping cumulatively over the whole session would, once the total
// stderr reached the cap, make every later command silently report empty stderr.
type syncBuf struct {
	mu        sync.Mutex
	buf       strings.Builder
	truncated bool                // set when Write dropped bytes past the cap
	recorder  *recording.Recorder // nil = recording disabled
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// A3: silently discard bytes that exceed the per-command limit, recording
	// that truncation happened. The full slice is always reported as consumed:
	// returning n < len(p) with a nil error would make the io.Copy draining
	// stderr die with ErrShortWrite and lose all stderr from that point on.
	rem := maxOutputBytes - s.buf.Len()
	if rem <= 0 {
		if len(p) > 0 {
			s.truncated = true
		}
		return len(p), nil
	}
	keep := p
	if len(keep) > rem {
		keep = keep[:rem]
		s.truncated = true
	}
	n, _ := s.buf.Write(keep) // strings.Builder.Write never returns an error
	if n > 0 && s.recorder != nil {
		_ = s.recorder.WriteStderr(string(keep[:n]))
	}
	return len(p), nil
}

// reset clears the per-command stderr capture. Exec calls it before each command
// so the cap is per command rather than cumulative over the session lifetime.
func (s *syncBuf) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buf.Reset()
	s.truncated = false
}

// output returns the captured stderr, appending an explicit marker when it was
// truncated at the cap (mirrors limitedWriter.output in run.go).
func (s *syncBuf) output() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.truncated {
		return s.buf.String()
	}
	return s.buf.String() + fmt.Sprintf("\n[stderr truncated: limit of %d bytes exceeded]\n", maxOutputBytes)
}

func (s *syncBuf) snapshotLen() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Len()
}
func (s *syncBuf) since(start int) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	full := s.buf.String()
	if start > len(full) {
		return ""
	}
	return full[start:]
}

// OpenShell starts a shell (without PTY) over client. shellCmd is the command
// to execute remotely; normally "/bin/sh" but can be "sudo -n -- /bin/sh" to
// elevate the whole session.
func OpenShell(ctx context.Context, client *ssh.Client, shellCmd string) (*ShellSession, error) {
	if shellCmd == "" {
		shellCmd = "/bin/sh"
	}
	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("opening session: %w", err)
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		session.Close()
		return nil, fmt.Errorf("stdin: %w", err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		session.Close()
		return nil, fmt.Errorf("stdout: %w", err)
	}
	stderrPipe, err := session.StderrPipe()
	if err != nil {
		session.Close()
		return nil, fmt.Errorf("stderr: %w", err)
	}
	if err := session.Start(shellCmd); err != nil {
		session.Close()
		return nil, fmt.Errorf("starting shell: %w", err)
	}

	var b [8]byte
	// crypto/rand.Read never returns an error on Go 1.24+ (it crashes the process
	// if the OS RNG fails), so this cannot produce a deterministic marker; the
	// error is intentionally discarded rather than checked as dead code.
	_, _ = rand.Read(b[:])
	sh := &ShellSession{
		session: session,
		stdin:   stdin,
		lines:   make(chan lineRes),
		done:    make(chan struct{}),
		stderr:  &syncBuf{},
		marker:  "__BRK_" + hex.EncodeToString(b[:]) + "__",
		pty:     false,
	}
	go func() { _, _ = io.Copy(sh.stderr, stderrPipe) }()
	go shellReader(stdout, sh.lines, sh.done)

	if _, err := sh.Exec(ctx, ":", 10*time.Second); err != nil {
		// sh.Close (not session.Close) so the done channel releases the
		// reader goroutine.
		_ = sh.Close()
		return nil, fmt.Errorf("synchronising shell: %w", err)
	}
	return sh, nil
}

// OpenShellPTY starts a shell with a PTY over client. shellCmd works the same
// as in OpenShell (e.g. "sudo -n -- /bin/sh" to elevate).
// opts controls terminal dimensions and type.
//
// In PTY mode stdout and stderr are merged; Result.Stderr will always be empty.
func OpenShellPTY(ctx context.Context, client *ssh.Client, shellCmd string, opts ExecOptions) (*ShellSession, error) {
	if shellCmd == "" {
		shellCmd = "/bin/sh"
	}

	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("opening PTY session: %w", err)
	}

	term, rows, cols, modes := ptyParams(opts)
	if err := session.RequestPty(term, rows, cols, modes); err != nil {
		session.Close()
		return nil, fmt.Errorf("requesting PTY: %w", err)
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		session.Close()
		return nil, fmt.Errorf("PTY stdin: %w", err)
	}
	// With PTY, StdoutPipe and StderrPipe are obtained on the combined channel.
	stdout, err := session.StdoutPipe()
	if err != nil {
		session.Close()
		return nil, fmt.Errorf("PTY stdout: %w", err)
	}

	if err := session.Start(shellCmd); err != nil {
		session.Close()
		return nil, fmt.Errorf("starting PTY shell: %w", err)
	}

	var b [8]byte
	// crypto/rand.Read never returns an error on Go 1.24+ (it crashes the process
	// if the OS RNG fails), so this cannot produce a deterministic marker; the
	// error is intentionally discarded rather than checked as dead code.
	_, _ = rand.Read(b[:])
	sh := &ShellSession{
		session: session,
		stdin:   stdin,
		lines:   make(chan lineRes),
		done:    make(chan struct{}),
		stderr:  nil, // merged into stdout with PTY
		marker:  "__BRK_" + hex.EncodeToString(b[:]) + "__",
		pty:     true,
	}
	go shellReader(stdout, sh.lines, sh.done)

	// Silence the prompt and ensure echo is off.
	initCmd := "stty -echo 2>/dev/null; PS1=''; PS2=''\n"
	if _, err := io.WriteString(stdin, initCmd); err != nil {
		// sh.Close (not session.Close) so the done channel releases the
		// reader goroutine.
		_ = sh.Close()
		return nil, fmt.Errorf("initialising PTY: %w", err)
	}

	// Synchronise with a no-op to consume the init output.
	if _, err := sh.Exec(ctx, ":", 10*time.Second); err != nil {
		_ = sh.Close()
		return nil, fmt.Errorf("synchronising PTY shell: %w", err)
	}
	return sh, nil
}

// shellReader is the single reader goroutine: reads lines from stdout and
// delivers them in order. Between commands it blocks on input (no output to lose),
// but it never buffers more than maxOutputBytes plus marker slack for one logical
// line. It exits when the reader returns an error (EOF on close) or when done is
// closed — without done, a send with no receiver (session closed while output was
// in flight) would leak the goroutine forever.
func shellReader(r io.Reader, out chan<- lineRes, done <-chan struct{}) {
	br := bufio.NewReader(r)
	var line strings.Builder
	maxLine := maxOutputBytes + shellReaderLineSlack
	for {
		frag, isPrefix, err := br.ReadLine()
		if len(frag) > 0 {
			if line.Len()+len(frag) > maxLine {
				sendShellLine(out, done, lineRes{err: errShellLineTooLong})
				return
			}
			line.Write(frag)
		}

		switch {
		case err == nil && isPrefix:
			continue
		case err == nil:
			if !sendShellLine(out, done, lineRes{text: line.String() + "\n"}) {
				return
			}
			line.Reset()
		case errors.Is(err, io.EOF):
			if line.Len() > 0 {
				sendShellLine(out, done, lineRes{text: line.String(), err: err})
			} else {
				sendShellLine(out, done, lineRes{err: err})
			}
			return
		default:
			if line.Len() > 0 {
				sendShellLine(out, done, lineRes{text: line.String(), err: err})
			} else {
				sendShellLine(out, done, lineRes{err: err})
			}
			return
		}
	}
}

func sendShellLine(out chan<- lineRes, done <-chan struct{}, lr lineRes) bool {
	select {
	case out <- lr:
		return true
	case <-done:
		return false
	}
}

// Exec executes command and returns (stdout, stderr, exit code). timeout caps
// the output wait.
//
// In PTY mode Result.Stderr will be empty (streams are merged in Stdout).
func (s *ShellSession) Exec(ctx context.Context, command string, timeout time.Duration) (*Result, error) {
	// codingstyle:long-function: marker-framed exec protocol — the
	// write-command → read-until-marker → parse-exit-code sequence is one
	// indivisible unit; splitting it would obscure the framing invariants.
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.broken {
		return nil, fmt.Errorf("shell session is desynchronised after a previous timeout or overflow; close this session and open a new one")
	}

	// Reset the per-command stderr capture so the cap applies per command, not
	// cumulatively over the session lifetime (otherwise, once the session's total
	// stderr reached the cap, every later command would report empty stderr).
	if s.stderr != nil {
		s.stderr.reset()
	}

	// Record stdin before writing to the shell channel. The marker suffix is
	// internal plumbing; only the user-visible command is recorded.
	if s.recorder != nil && command != ":" {
		_ = s.recorder.WriteInput(command + "\n")
	}

	line := fmt.Sprintf("%s\n%s", command, markerLine(s.marker))
	if _, err := io.WriteString(s.stdin, line); err != nil {
		return nil, fmt.Errorf("writing command: %w", err)
	}

	var out strings.Builder
	appendOut := func(text string) error {
		if text == "" {
			return nil
		}
		// A3: limit stdout accumulation to prevent OOM. Returning mid-command
		// leaves the rest of the output and the marker in flight, so the session is
		// desynchronised too.
		if out.Len()+len(text) > maxOutputBytes {
			s.broken = true
			return fmt.Errorf("command output exceeds limit of %d bytes; the session is desynchronised: close it and open a new one", maxOutputBytes)
		}
		out.WriteString(text)
		if s.recorder != nil {
			_ = s.recorder.WriteOutput(text)
		}
		return nil
	}
	deadline := time.After(timeout)
	for {
		select {
		case <-ctx.Done():
			// The caller cancelled (client disconnected). Tear down the SSH channel
			// so the command actually stops running on the host instead of lingering
			// until the session is closed or reaped; the stream is then unusable, so
			// mark the session broken (s.session is nil only in unit tests).
			if s.session != nil {
				_ = s.session.Close()
			}
			s.broken = true
			return nil, ctx.Err()
		case <-deadline:
			// The timed-out command's output and end marker are still in
			// flight; any further Exec would read them and misattribute the
			// previous command's output (and exit code) to the next command.
			// Mark the session permanently broken.
			s.broken = true
			return nil, fmt.Errorf("timeout waiting for command output; the session is desynchronised: close it and open a new one")
		case lr := <-s.lines:
			if errors.Is(lr.err, errShellLineTooLong) {
				s.broken = true
				return nil, fmt.Errorf("command output exceeds limit of %d bytes; the session is desynchronised: close it and open a new one", maxOutputBytes)
			}
			if idx := strings.Index(lr.text, s.marker+":"); idx >= 0 {
				// Any text before the marker on the same line is genuine command
				// output whose final line lacked a trailing newline (e.g.
				// `printf hello`): the shell wrote the marker right after it.
				// Capture it instead of dropping it.
				if idx > 0 {
					if err := appendOut(lr.text[:idx]); err != nil {
						return nil, err
					}
				}
				code, err := strconv.Atoi(strings.TrimSpace(lr.text[idx+len(s.marker)+1:]))
				if err != nil {
					// A non-numeric exit code means the marker line was mangled
					// (e.g. a PTY that echoed it), so the stream is no longer
					// trustworthy. Fail loudly rather than reporting exit 0.
					s.broken = true
					return nil, fmt.Errorf("could not parse exit code from marker %q: the session is desynchronised: close it and open a new one", lr.text)
				}
				var stderrStr string
				if s.stderr != nil {
					stderrStr = s.stderr.output()
				}
				return &Result{
					Stdout:   out.String(),
					Stderr:   stderrStr,
					ExitCode: code,
				}, nil
			}
			if err := appendOut(lr.text); err != nil {
				return nil, err
			}
			if lr.err != nil {
				return nil, fmt.Errorf("read interrupted: %w", lr.err)
			}
		}
	}
}

// markerLine prints the private end-of-command marker and the previous command's
// exit code. Use absolute printf paths: in a persistent shell the user command
// can define a printf() function that shadows the builtin/command name and
// forges the reported exit code.
func markerLine(marker string) string {
	rcVar := marker + "_RC"
	return fmt.Sprintf(
		"%s=$?\n{ /usr/bin/printf '%%s:%%d\\n' '%s' \"${%s}\" 2>/dev/null || /bin/printf '%%s:%%d\\n' '%s' \"${%s}\"; }\n",
		rcVar, marker, rcVar, marker, rcVar,
	)
}

// Close closes the shell and releases the reader goroutine. Safe to call
// more than once.
func (s *ShellSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeOnce.Do(func() { close(s.done) })
	_ = s.stdin.Close()
	return s.session.Close()
}
