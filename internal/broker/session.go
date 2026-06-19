package broker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/luisgf/ssh-broker/internal/audit"
	"github.com/luisgf/ssh-broker/internal/recording"
	"github.com/luisgf/ssh-broker/internal/signer"
	sshrun "github.com/luisgf/ssh-broker/internal/ssh"
)

// shellExecTimeout caps the output wait in shell/pty sessions.
const shellExecTimeout = 120 * time.Second

// Active session limits to prevent resource exhaustion (M2).
const (
	// maxSessionsGlobal is the maximum number of concurrent sessions broker-wide.
	maxSessionsGlobal = 200
	// maxSessionsPerCaller is the maximum concurrent sessions per caller (user/CN).
	maxSessionsPerCaller = 20
)

// liveSession is a retained SSH connection (pool unit and persistent session).
// A single cert (serial) authenticated it; its commands reuse the connection.
type liveSession struct {
	id       string
	caller   string
	host     string
	serial   uint64
	mode     string // "exec" | "shell" | "pty"
	conn     *sshrun.Conn
	shell    *sshrun.ShellSession // only in "shell" and "pty" mode
	created  time.Time
	lastUsed time.Time
	// busy counts commands in flight on this session (protected by the
	// manager's mutex). The reaper never closes a busy session: the exec
	// timeout can exceed the idle TTL, and closing the connection under a
	// running command would break it mid-flight.
	busy int

	// Elevation: prefix to prepend to each command in exec sessions.
	// In shell/pty sessions the elevation is already in the shell process.
	elevationPrefix string
	// elevLabel is the audit label for the session's elevation (e.g. "sudo:root").
	// Retained for ALL modes — unlike elevationPrefix, which is cleared for
	// shell/pty (the sudo lives in the shell process) — so every session_exec
	// audit entry records that its command ran elevated.
	elevLabel string
	// pty indicates whether this session uses a PTY.
	pty bool
	// recorder captures stdin/stdout/stderr to an ASCIIcast v2 file.
	// nil when session recording is disabled.
	recorder *recording.Recorder
}

func (s *liveSession) close() {
	if s.recorder != nil {
		_ = s.recorder.Close()
		s.recorder = nil
	}
	if s.shell != nil {
		_ = s.shell.Close()
	}
	if s.conn != nil {
		_ = s.conn.Close()
	}
}

// sessionManager registers and recycles sessions by idle TTL / maximum lifetime.
type sessionManager struct {
	mu       sync.Mutex
	sessions map[string]*liveSession
	idleTTL  time.Duration
	maxLife  time.Duration
	onReap   func(*liveSession)
	stop     chan struct{}
}

func newSessionManager(idle, maxLife time.Duration, onReap func(*liveSession)) *sessionManager {
	m := &sessionManager{
		sessions: map[string]*liveSession{},
		idleTTL:  idle,
		maxLife:  maxLife,
		onReap:   onReap,
		stop:     make(chan struct{}),
	}
	go m.reaper()
	return m
}

func (m *sessionManager) reaper() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-m.stop:
			return
		case now := <-t.C:
			m.reapExpired(now)
		}
	}
}

// reapExpired closes and removes the sessions that exceeded the idle TTL or
// the maximum lifetime. Victims are collected and deleted from the map under
// the lock, then closed and audited outside it: close() does network I/O
// (and can block on the shell mutex) and onReap writes to disk, neither of
// which may stall other session operations.
func (m *sessionManager) reapExpired(now time.Time) {
	m.mu.Lock()
	var victims []*liveSession
	for id, s := range m.sessions {
		// Never reap a session with a command in flight. A busy session
		// past maxLife is reaped on the first tick after it goes idle.
		if s.busy > 0 {
			continue
		}
		if now.Sub(s.lastUsed) > m.idleTTL || now.Sub(s.created) > m.maxLife {
			delete(m.sessions, id)
			victims = append(victims, s)
		}
	}
	m.mu.Unlock()

	for _, s := range victims {
		s.close()
		if m.onReap != nil {
			m.onReap(s)
		}
	}
}

func (m *sessionManager) add(s *liveSession) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// M2: global session limit.
	if len(m.sessions) >= maxSessionsGlobal {
		return fmt.Errorf("global session limit reached (%d); close existing sessions before opening new ones", maxSessionsGlobal)
	}
	// M2: per-caller session limit.
	var callerCount int
	for _, existing := range m.sessions {
		if existing.caller == s.caller {
			callerCount++
		}
	}
	if callerCount >= maxSessionsPerCaller {
		return fmt.Errorf("per-caller session limit reached (%d); close existing sessions before opening new ones", maxSessionsPerCaller)
	}

	m.sessions[s.id] = s
	return nil
}

func (m *sessionManager) get(id string) (*liveSession, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if ok {
		s.lastUsed = time.Now()
	}
	return s, ok
}

// checkout returns the session and marks one command as in flight, so the
// reaper will not close the connection while the command runs. Every
// successful checkout must be paired with a checkin when the command ends.
func (m *sessionManager) checkout(id string) (*liveSession, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if ok {
		s.lastUsed = time.Now()
		s.busy++
	}
	return s, ok
}

// checkoutOwned is checkout with an ownership gate. It returns found=false for
// an unknown id, owned=false (WITHOUT mutating any state) when caller does not
// own the session, and otherwise marks one command in flight (busy++,
// lastUsed=now) and returns owned=true. Performing the C1 check under the lock
// before mutating prevents a non-owner from refreshing another caller's
// lastUsed or holding busy>0 to keep the reaper from closing the session.
func (m *sessionManager) checkoutOwned(id, caller string) (s *liveSession, found, owned bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, found = m.sessions[id]
	if !found {
		return nil, false, false
	}
	if s.caller != caller {
		return s, true, false
	}
	s.lastUsed = time.Now()
	s.busy++
	return s, true, true
}

// checkin marks the end of an in-flight command and refreshes lastUsed, so
// the idle TTL counts from command completion rather than from its start.
func (m *sessionManager) checkin(s *liveSession) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s.busy > 0 {
		s.busy--
	}
	s.lastUsed = time.Now()
}

func (m *sessionManager) remove(id string) (*liveSession, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if ok {
		delete(m.sessions, id)
	}
	return s, ok
}

func (m *sessionManager) closeAll() {
	close(m.stop)
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, s := range m.sessions {
		s.close()
		delete(m.sessions, id)
	}
}

// SessionResult is what a session open returns.
type SessionResult struct {
	SessionID string
	Serial    uint64
}

// OpenSession opens a persistent connection (one cert per connection, no
// force-command) and registers it. opts controls elevation and PTY.
//
// Modes:
//
//   - exec  (default): each command is isolated (ExecOnce). With sudo, the
//     prefix is prepended to each command individually.
//   - shell: a stateful /bin/sh (cd, variables persist). With sudo, the whole
//     shell is launched under sudo (elevated session).
//   - pty:   same as shell but with a PTY (permit-pty in the cert).
func (e *Engine) OpenSession(ctx context.Context, c Caller, host, mode string, ttlSeconds int, opts ExecOptions) (*SessionResult, error) {
	if _, ok := e.hostInfo(host); !ok {
		e.auditE(audit.Entry{Caller: c.ID, Host: host, Outcome: "denied", Err: "unknown host"})
		return nil, fmt.Errorf("unknown host: %q", host)
	}
	if mode == "" {
		mode = "exec"
	}
	if mode != "exec" && mode != "shell" && mode != "pty" {
		return nil, fmt.Errorf("invalid mode: %q (exec|shell|pty)", mode)
	}

	// PTY is implicit in mode=pty.
	if mode == "pty" {
		opts.PTY = true
	}

	hops, serial, elevPrefix, err := e.buildHopsWithPrefix(ctx, c, host, e.ttlFor(ttlSeconds), signer.PurposeSession, opts)
	if err != nil {
		e.auditE(audit.Entry{Caller: c.ID, Host: host, Outcome: "error", Err: err.Error()})
		return nil, err
	}
	conn, err := sshrun.Dial(ctx, hops, 0)
	if err != nil {
		e.auditE(audit.Entry{Caller: c.ID, Host: host, Serial: serial, Outcome: "error", Err: err.Error()})
		return nil, fmt.Errorf("connection: %w", err)
	}

	s := &liveSession{
		id: newSessionID(), caller: c.ID, host: host, serial: serial, mode: mode,
		conn: conn, created: time.Now(), lastUsed: time.Now(),
		elevationPrefix: elevPrefix,
		elevLabel:       opts.elevationLabel(),
		pty:             opts.PTY,
	}

	switch mode {
	case "shell":
		// shellCmd: if elevated, launch the shell directly under sudo.
		shellCmd := "/bin/sh"
		if elevPrefix != "" {
			shellCmd = elevPrefix + " -- /bin/sh"
		}
		sh, err := sshrun.OpenShell(conn.Client, shellCmd)
		if err != nil {
			conn.Close()
			e.auditE(audit.Entry{Caller: c.ID, Host: host, Serial: serial, Outcome: "error", Err: err.Error()})
			return nil, fmt.Errorf("opening shell: %w", err)
		}
		s.shell = sh
		// In an elevated shell the prefix is in the process; do not reapply per command.
		s.elevationPrefix = ""

	case "pty":
		shellCmd := "/bin/sh"
		if elevPrefix != "" {
			shellCmd = elevPrefix + " -- /bin/sh"
		}
		sh, err := sshrun.OpenShellPTY(conn.Client, shellCmd, sshrun.ExecOptions{PTY: true})
		if err != nil {
			conn.Close()
			e.auditE(audit.Entry{Caller: c.ID, Host: host, Serial: serial, Outcome: "error", Err: err.Error()})
			return nil, fmt.Errorf("opening PTY shell: %w", err)
		}
		s.shell = sh
		s.elevationPrefix = ""
	}

	if err := e.sessions.add(s); err != nil {
		s.close()
		e.auditE(audit.Entry{Caller: c.ID, Host: host, Serial: serial, Outcome: "denied", Err: err.Error()})
		return nil, err
	}

	// Start recording for shell/pty sessions when a recording directory is set.
	if e.cfg.SessionRecordingDir != "" && s.shell != nil {
		castPath := filepath.Join(e.cfg.SessionRecordingDir, s.id+".cast")
		rec, err := recording.Open(castPath, recording.Meta{
			SessionID: s.id,
			Caller:    c.ID,
			Host:      host,
			Serial:    serial,
			PTY:       opts.PTY,
			Term:      "xterm-256color",
			Width:     220,
			Height:    40,
			StartedAt: s.created,
		})
		if err != nil {
			log.Printf("warning: could not open recording file %s: %v", castPath, err)
		} else {
			s.recorder = rec
			s.shell.SetRecorder(rec)
		}
	}

	e.auditE(audit.Entry{
		Caller:    c.ID,
		Host:      host,
		Serial:    serial,
		SessionID: s.id,
		Outcome:   "session_open",
		Command:   "mode=" + mode,
		Elevation: opts.elevationLabel(),
		PTY:       opts.PTY,
	})
	return &SessionResult{SessionID: s.id, Serial: serial}, nil
}

// SessionExec executes command in an existing session, reusing the connection.
// In exec sessions with elevation, the signer-authorised prefix is prepended.
func (e *Engine) SessionExec(_ context.Context, c Caller, sessionID, command string) (*Result, error) {
	// C1: verify ownership BEFORE mutating shared state. checkoutOwned performs
	// the owner check under the manager lock and only marks the command in flight
	// (busy++/lastUsed) when the caller owns the session, so a non-owner cannot
	// keep another caller's session alive or block the reaper by probing it.
	s, found, owned := e.sessions.checkoutOwned(sessionID, c.ID)
	if !found {
		return nil, fmt.Errorf("unknown or expired session: %q", sessionID)
	}
	if !owned {
		return nil, fmt.Errorf("session %q does not belong to the current caller", sessionID)
	}
	// Mark the session idle again (and refresh lastUsed) when the command
	// finishes, so the reaper never closes a connection mid-command.
	defer e.sessions.checkin(s)
	if command == "" {
		return nil, fmt.Errorf("command is required")
	}
	// M5: in shell/pty sessions newlines would execute as additional commands in
	// the shell; reject them explicitly.
	if (s.mode == "shell" || s.mode == "pty") && strings.ContainsAny(command, "\n\r") {
		return nil, fmt.Errorf("command contains newlines; not allowed in shell/pty sessions")
	}

	// In exec sessions with elevation, build the elevated command.
	effectiveCommand := command
	if s.mode == "exec" && s.elevationPrefix != "" {
		effectiveCommand = buildElevatedExecCommand(s.elevationPrefix, command)
	}

	var res *sshrun.Result
	var err error
	switch s.mode {
	case "shell", "pty":
		res, err = s.shell.Exec(command, shellExecTimeout)
	default: // "exec"
		execOpts := sshrun.ExecOptions{PTY: s.pty}
		res, err = sshrun.ExecOnce(s.conn.Client, effectiveCommand, execOpts)
	}
	if err != nil {
		e.auditE(audit.Entry{
			Caller: c.ID, Host: s.host, Serial: s.serial, SessionID: sessionID,
			Command: command, Outcome: "error", Err: err.Error(),
		})
		return nil, fmt.Errorf("session execution: %w", err)
	}

	e.auditE(audit.Entry{
		Caller:    c.ID,
		Host:      s.host,
		Serial:    s.serial,
		SessionID: sessionID,
		Command:   command,
		Outcome:   "session_exec",
		ExitCode:  res.ExitCode,
		// s.elevLabel is set for every elevated session (incl. shell/pty, whose
		// elevationPrefix is intentionally cleared), so per-command audit always
		// reflects that the command ran elevated.
		Elevation: s.elevLabel,
		PTY:       s.pty,
	})
	return &Result{Stdout: res.Stdout, Stderr: res.Stderr, ExitCode: res.ExitCode, Serial: s.serial}, nil
}

// CloseSession closes and removes a session.
// C1: only the caller that opened the session may close it.
func (e *Engine) CloseSession(c Caller, sessionID string) error {
	// Verify ownership before removing to prevent a caller from closing another
	// caller's sessions (C1).
	s, ok := e.sessions.get(sessionID)
	if !ok {
		return fmt.Errorf("unknown session: %q", sessionID)
	}
	if s.caller != c.ID {
		return fmt.Errorf("session %q does not belong to the current caller", sessionID)
	}
	// Remove now that we know the session belongs to this caller.
	s, ok = e.sessions.remove(sessionID)
	if !ok {
		// Reaper removed it between the get and the remove; not an error.
		return nil
	}
	s.close()
	e.auditE(audit.Entry{Caller: c.ID, Host: s.host, Serial: s.serial, SessionID: sessionID, Outcome: "session_close"})
	return nil
}

// buildElevatedExecCommand wraps command with the elevation prefix for exec
// sessions (each command is sent separately).
func buildElevatedExecCommand(prefix, command string) string {
	return fmt.Sprintf("%s -- /bin/sh -c %s", prefix, shellQuoteSession(command))
}

// shellQuoteSession is a local copy of shellQuote to avoid a circular
// dependency with the signer package (which already has the function).
func shellQuoteSession(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('\'')
	for _, c := range s {
		if c == '\'' {
			b.WriteString(`'\''`)
		} else {
			b.WriteRune(c)
		}
	}
	b.WriteByte('\'')
	return b.String()
}

// elevationLabelFromPrefix builds the audit label from the prefix stored in the
// session (e.g. "sudo -n" → "sudo:root").
func elevationLabelFromPrefix(prefix string) string {
	// "sudo -n" → root; "sudo -n -u deploy" → deploy
	if prefix == "sudo -n" {
		return "sudo:root"
	}
	// Extract the user from the -u flag.
	const flag = "-u "
	if idx := len("sudo -n "); idx < len(prefix) {
		rest := prefix[idx:]
		if len(rest) > 3 && rest[:3] == "-u " {
			return "sudo:" + rest[3:]
		}
	}
	return "sudo:?"
}

func newSessionID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
