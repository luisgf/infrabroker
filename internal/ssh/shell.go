package ssh

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/luisgf/ssh-broker/internal/recording"
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

type ShellSession struct {
	mu       sync.Mutex
	session  *ssh.Session
	stdin    io.WriteCloser
	lines    chan lineRes // fed by a single reader goroutine
	stderr   *syncBuf     // nil in PTY mode (merged streams)
	marker   string
	pty      bool                // true if the session uses a PTY
	recorder *recording.Recorder // nil = recording disabled
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

// syncBuf is a concurrent buffer: a goroutine drains stderr into it.
// A3: accumulation is capped at maxOutputBytes to prevent OOM.
type syncBuf struct {
	mu       sync.Mutex
	buf      strings.Builder
	recorder *recording.Recorder // nil = recording disabled
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// A3: silently discard bytes that exceed the limit.
	if s.buf.Len() >= maxOutputBytes {
		return len(p), nil
	}
	rem := maxOutputBytes - s.buf.Len()
	if len(p) > rem {
		p = p[:rem]
	}
	n, err := s.buf.Write(p)
	if n > 0 && s.recorder != nil {
		_ = s.recorder.WriteStderr(string(p[:n]))
	}
	return n, err
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
func OpenShell(client *ssh.Client, shellCmd string) (*ShellSession, error) {
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
	_, _ = rand.Read(b[:])
	sh := &ShellSession{
		session: session,
		stdin:   stdin,
		lines:   make(chan lineRes),
		stderr:  &syncBuf{},
		marker:  "__BRK_" + hex.EncodeToString(b[:]) + "__",
		pty:     false,
	}
	go func() { _, _ = io.Copy(sh.stderr, stderrPipe) }()
	go shellReader(stdout, sh.lines)

	if _, err := sh.Exec(":", 10*time.Second); err != nil {
		session.Close()
		return nil, fmt.Errorf("synchronising shell: %w", err)
	}
	return sh, nil
}

// OpenShellPTY starts a shell with a PTY over client. shellCmd works the same
// as in OpenShell (e.g. "sudo -n -- /bin/sh" to elevate).
// opts controls terminal dimensions and type.
//
// In PTY mode stdout and stderr are merged; Result.Stderr will always be empty.
func OpenShellPTY(client *ssh.Client, shellCmd string, opts ExecOptions) (*ShellSession, error) {
	if shellCmd == "" {
		shellCmd = "/bin/sh"
	}

	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("opening PTY session: %w", err)
	}

	term := opts.Term
	if term == "" {
		term = defaultPTYTerm
	}
	rows := opts.Rows
	if rows == 0 {
		rows = 40
	}
	cols := opts.Cols
	if cols == 0 {
		cols = 220
	}
	modes := ssh.TerminalModes{
		ssh.ECHO:          0, // disable echo
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := session.RequestPty(term, int(rows), int(cols), modes); err != nil {
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
	_, _ = rand.Read(b[:])
	sh := &ShellSession{
		session: session,
		stdin:   stdin,
		lines:   make(chan lineRes),
		stderr:  nil, // merged into stdout with PTY
		marker:  "__BRK_" + hex.EncodeToString(b[:]) + "__",
		pty:     true,
	}
	go shellReader(stdout, sh.lines)

	// Silence the prompt and ensure echo is off.
	initCmd := "stty -echo 2>/dev/null; PS1=''; PS2=''\n"
	if _, err := io.WriteString(stdin, initCmd); err != nil {
		session.Close()
		return nil, fmt.Errorf("initialising PTY: %w", err)
	}

	// Synchronise with a no-op to consume the init output.
	if _, err := sh.Exec(":", 10*time.Second); err != nil {
		session.Close()
		return nil, fmt.Errorf("synchronising PTY shell: %w", err)
	}
	return sh, nil
}

// shellReader is the single reader goroutine: reads lines from stdout and
// delivers them in order. Between commands it blocks on ReadString (no output
// to lose).
func shellReader(r io.Reader, out chan<- lineRes) {
	br := bufio.NewReader(r)
	for {
		t, err := br.ReadString('\n')
		out <- lineRes{t, err}
		if err != nil {
			return
		}
	}
}

// Exec executes command and returns (stdout, stderr, exit code). timeout caps
// the output wait.
//
// In PTY mode Result.Stderr will be empty (streams are merged in Stdout).
func (s *ShellSession) Exec(command string, timeout time.Duration) (*Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var errStart int
	if s.stderr != nil {
		errStart = s.stderr.snapshotLen()
	}

	// Record stdin before writing to the shell channel. The marker suffix is
	// internal plumbing; only the user-visible command is recorded.
	if s.recorder != nil && command != ":" {
		_ = s.recorder.WriteInput(command + "\n")
	}

	line := fmt.Sprintf("%s\nprintf '%%s:%%d\\n' '%s' \"$?\"\n", command, s.marker)
	if _, err := io.WriteString(s.stdin, line); err != nil {
		return nil, fmt.Errorf("writing command: %w", err)
	}

	var out strings.Builder
	deadline := time.After(timeout)
	for {
		select {
		case <-deadline:
			return nil, fmt.Errorf("timeout waiting for command output")
		case lr := <-s.lines:
			if idx := strings.Index(lr.text, s.marker+":"); idx >= 0 {
				code, _ := strconv.Atoi(strings.TrimSpace(lr.text[idx+len(s.marker)+1:]))
				var stderrStr string
				if s.stderr != nil {
					stderrStr = s.stderr.since(errStart)
				}
				return &Result{
					Stdout:   out.String(),
					Stderr:   stderrStr,
					ExitCode: code,
				}, nil
			}
			if lr.text != "" {
				// A3: limit stdout accumulation to prevent OOM.
				if out.Len()+len(lr.text) > maxOutputBytes {
					return nil, fmt.Errorf("command output exceeds limit of %d bytes", maxOutputBytes)
				}
				out.WriteString(lr.text)
				// Tee stdout line to the recording.
				if s.recorder != nil {
					_ = s.recorder.WriteOutput(lr.text)
				}
			}
			if lr.err != nil {
				return nil, fmt.Errorf("read interrupted: %w", lr.err)
			}
		}
	}
}

// Close closes the shell.
func (s *ShellSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.stdin.Close()
	return s.session.Close()
}
