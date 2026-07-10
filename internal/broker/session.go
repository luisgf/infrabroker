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

	"github.com/luisgf/infrabroker/internal/audit"
	"github.com/luisgf/infrabroker/internal/ca"
	"github.com/luisgf/infrabroker/internal/recording"
	"github.com/luisgf/infrabroker/internal/signer"
	sshrun "github.com/luisgf/infrabroker/internal/ssh"
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
	// certNotAfter is the target certificate's ValidBefore: the session must
	// not outlive the credential that opened it (THREAT_MODEL gap #1). The
	// reaper closes the session once this passes, bounding the exposure window
	// to the cert TTL (<= max_ttl) instead of the longer session_max_seconds.
	// Zero means "no cap" (defensive; OpenSession always sets it).
	certNotAfter time.Time
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
	// Original elevation request, retained so per-command policy preflight in
	// exec sessions binds to the same sudo/sudo_user variant that will execute.
	sudo     bool
	sudoUser string
	// pty indicates whether this session uses a PTY.
	pty bool
	// connectivitySig captures the physical SSH chain used when the session was
	// opened. Session exec compares it against the current signer host view so a
	// host addr/user/host_key/jump change cannot silently keep using the old
	// connection.
	connectivitySig string
	// recorder captures stdin/stdout/stderr to an ASCIIcast v2 file.
	// nil when session recording is disabled.
	recorder *recording.Recorder
	// closeOnce makes close() idempotent. Several teardown paths can reach the
	// same session — the idle/lifetime reaper, the kill switch (killMatching),
	// closeAll, and the fail-closed OpenSession rollback — and two of them can
	// race (a revocation-poll kill landing while OpenSession rolls back). The
	// conn/shell handles and the recorder field must be torn down exactly once,
	// from one goroutine (#226).
	closeOnce sync.Once
}

func (s *liveSession) close() {
	s.closeOnce.Do(func() {
		if s.recorder != nil {
			_ = s.recorder.Close()
			s.recorder = nil
		}
		// Tear down the transport BEFORE the shell. ShellSession.Close needs the
		// shell mutex, which an in-flight Exec holds until the command completes or
		// hits shellExecTimeout (120s). Closing the connection first makes that
		// Exec's next channel read/write fail and return in milliseconds, releasing
		// the mutex so shell.Close() no longer blocks teardown — the kill switch
		// (#117) and closeAll must interrupt a busy shell/PTY session promptly
		// instead of waiting out the exec timeout (#202).
		if s.conn != nil {
			_ = s.conn.Close()
		}
		if s.shell != nil {
			_ = s.shell.Close()
		}
	})
}

// sessionManager registers and recycles sessions by idle TTL / maximum lifetime.
type sessionManager struct {
	mu        sync.Mutex
	sessions  map[string]*liveSession
	idleTTL   time.Duration
	maxLife   time.Duration
	onReap    func(*liveSession)
	stop      chan struct{}
	closeOnce sync.Once
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

// count returns the number of live sessions, for the monitoring gauge.
func (m *sessionManager) count() float64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return float64(len(m.sessions))
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
		// Never reap a session with a command in flight. A busy session past
		// maxLife or its cert expiry is reaped on the first tick after it goes
		// idle. Forcibly closing a busy session (a true kill switch) is a
		// separate, deliberate control tracked in #117.
		if s.busy > 0 {
			continue
		}
		if now.Sub(s.lastUsed) > m.idleTTL || now.Sub(s.created) > m.maxLife ||
			(!s.certNotAfter.IsZero() && now.After(s.certNotAfter)) {
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

// killMatching force-closes and removes every session for which pred returns
// true, and returns the victims. Unlike the reaper it does NOT spare a busy
// session — a kill switch (#117) must interrupt a command in flight. Closing the
// connection under a running command makes that command's next read/write fail
// and return; the recorder is mutex-safe against a concurrent write, so the
// close races cleanly. Victims are removed from the map under the lock, then
// closed outside it (close() does network I/O). The onReap callback is NOT
// invoked — the caller audits kills distinctly from idle/lifetime reaps.
func (m *sessionManager) killMatching(pred func(*liveSession) bool) []*liveSession {
	m.mu.Lock()
	var victims []*liveSession
	for id, s := range m.sessions {
		if pred(s) {
			delete(m.sessions, id)
			victims = append(victims, s)
		}
	}
	m.mu.Unlock()
	for _, s := range victims {
		s.close()
	}
	return victims
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

// remove deletes a session from the live set without closing it (the caller owns
// the teardown). Used to roll back an add when the session must not become usable
// — e.g. its open record could not be persisted in fail-closed audit mode.
func (m *sessionManager) remove(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, id)
}

// checkoutOwned looks up a session and, if caller owns it, marks one command in
// flight (busy++, lastUsed=now) and returns owned=true. It returns found=false
// for an unknown id and owned=false (WITHOUT mutating any state) when caller
// does not own the session. Every successful checkout must be paired with a
// checkin when the command ends. Performing the C1 ownership check under the
// lock before mutating prevents a non-owner from refreshing another caller's
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

// removeOwned deletes the session only if it belongs to caller, atomically and
// WITHOUT touching lastUsed (C1). This prevents a non-owner holding a leaked
// session_id from refreshing the idle timer — and so keeping another caller's
// session alive against the reaper — merely by probing CloseSession.
func (m *sessionManager) removeOwned(id, caller string) (s *liveSession, found, owned bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, found = m.sessions[id]
	if !found {
		return nil, false, false
	}
	if s.caller != caller {
		return s, true, false
	}
	delete(m.sessions, id)
	return s, true, true
}

// closeAll stops the reaper and force-closes every session. Like reapExpired and
// killMatching it collects the victims under the lock and calls close() OUTSIDE
// it: close() does network I/O and can block on a busy shell's mutex, so holding
// the manager lock across it would stall every other session operation (checkin,
// CloseSession, metrics) during shutdown and let a single busy PTY session delay
// a clean teardown past systemd's SIGKILL window (#202).
func (m *sessionManager) closeAll() {
	m.closeOnce.Do(func() {
		close(m.stop)
		m.mu.Lock()
		victims := make([]*liveSession, 0, len(m.sessions))
		for id, s := range m.sessions {
			victims = append(victims, s)
			delete(m.sessions, id)
		}
		m.mu.Unlock()
		for _, s := range victims {
			s.close()
		}
	})
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
	if err := e.refreshHostsForNewConnection(ctx); err != nil {
		e.auditE(audit.Entry{Caller: c.ID, Host: host, Outcome: "error", Err: err.Error()})
		return nil, err
	}
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

	hops, serial, elevPrefix, connectivitySig, _, certNotAfter, err := e.buildHopsWithPrefix(ctx, c, host, e.ttlFor(ttlSeconds), signer.PurposeSession, mode, opts)
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
		certNotAfter:    certNotAfter,
		elevationPrefix: elevPrefix,
		elevLabel:       opts.elevationLabel(),
		sudo:            opts.Sudo,
		sudoUser:        opts.SudoUser,
		pty:             opts.PTY,
		connectivitySig: connectivitySig,
	}

	if err := e.openShellForMode(ctx, s); err != nil {
		return nil, err
	}

	if err := e.sessions.add(s); err != nil {
		s.close()
		e.auditE(audit.Entry{Caller: c.ID, Host: host, Serial: serial, Outcome: "denied", Err: err.Error()})
		return nil, err
	}

	// Fail-closed gate: audit the open before starting recording or handing the
	// session to the caller. If the record cannot be persisted, tear the session
	// down so it never becomes usable (and no subsequent ssh_session_exec can run
	// against an unrecorded session).
	if err := e.auditE(audit.Entry{
		Caller:    c.ID,
		Host:      host,
		Serial:    serial,
		SessionID: s.id,
		Outcome:   "session_open",
		Command:   "mode=" + mode,
		Elevation: opts.elevationLabel(),
		PTY:       opts.PTY,
	}); err != nil {
		e.sessions.remove(s.id)
		s.close()
		return nil, err
	}

	// Start recording for shell/pty sessions when a recording directory is set.
	e.startSessionRecording(s)
	return &SessionResult{SessionID: s.id, Serial: serial}, nil
}

// openShellForMode opens the shell/pty channel for a shell or pty session and
// wires it onto s; for mode=exec it is a no-op. On failure it closes the
// connection, audits the error, and returns it. Must be called after s.conn,
// s.mode and s.elevationPrefix are set.
func (e *Engine) openShellForMode(ctx context.Context, s *liveSession) error {
	switch s.mode {
	case "shell":
		// shellCmd: if elevated, launch the shell directly under sudo.
		shellCmd := "/bin/sh"
		if s.elevationPrefix != "" {
			shellCmd = s.elevationPrefix + " -- /bin/sh"
		}
		sh, err := sshrun.OpenShell(ctx, s.conn.Client, shellCmd)
		if err != nil {
			s.conn.Close()
			e.auditE(audit.Entry{Caller: s.caller, Host: s.host, Serial: s.serial, Outcome: "error", Err: err.Error()})
			return fmt.Errorf("opening shell: %w", err)
		}
		s.shell = sh
		// In an elevated shell the prefix is in the process; do not reapply per command.
		s.elevationPrefix = ""

	case "pty":
		shellCmd := "/bin/sh"
		if s.elevationPrefix != "" {
			shellCmd = s.elevationPrefix + " -- /bin/sh"
		}
		sh, err := sshrun.OpenShellPTY(ctx, s.conn.Client, shellCmd, sshrun.ExecOptions{PTY: true})
		if err != nil {
			s.conn.Close()
			e.auditE(audit.Entry{Caller: s.caller, Host: s.host, Serial: s.serial, Outcome: "error", Err: err.Error()})
			return fmt.Errorf("opening PTY shell: %w", err)
		}
		s.shell = sh
		s.elevationPrefix = ""
	}
	return nil
}

// startSessionRecording opens an ASCIIcast recorder for a shell/pty session
// when a recording directory is configured, wiring it (and any redactor) onto s.
// A no-op for exec sessions (no shell) or when recording is disabled; a failure
// to open the file is logged, not fatal.
func (e *Engine) startSessionRecording(s *liveSession) {
	if e.cfg.SessionRecordingDir == "" || s.shell == nil {
		return
	}
	castPath := filepath.Join(e.cfg.SessionRecordingDir, s.id+".cast")
	rec, err := recording.Open(castPath, recording.Meta{
		SessionID: s.id,
		Caller:    s.caller,
		Host:      s.host,
		Serial:    s.serial,
		PTY:       s.pty,
		Term:      "xterm-256color",
		Width:     220,
		Height:    40,
		StartedAt: s.created,
	})
	if err != nil {
		log.Printf("warning: could not open recording file %s: %v", castPath, err)
		return
	}
	if e.redactor != nil {
		rec.SetRedactor(e.redactor)
	}
	s.recorder = rec
	s.shell.SetRecorder(rec)
}

// SessionExec executes command in an existing session, reusing the connection.
// In exec sessions with elevation, the signer-authorised prefix is prepended.
func (e *Engine) SessionExec(ctx context.Context, c Caller, sessionID, command string) (*Result, error) {
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

	dec, err := e.authorizeSessionExec(ctx, c, s, command)
	if err != nil {
		e.auditE(audit.Entry{
			Caller: c.ID, Host: s.host, Serial: s.serial, SessionID: sessionID,
			Command: command, Outcome: "session_exec_denied", Err: err.Error(),
			PolicyRule: decisionRule(dec), Warning: decisionWarning(dec),
			Elevation: s.elevLabel, PTY: s.pty,
		})
		return nil, err
	}
	warnings := decisionWarnings(dec)

	// In exec sessions with elevation, build the elevated command.
	effectiveCommand := command
	if s.mode == "exec" && s.elevationPrefix != "" {
		effectiveCommand = signer.BuildElevatedCommand(s.elevationPrefix, command)
	}

	var res *sshrun.Result
	switch s.mode {
	case "shell", "pty":
		res, err = s.shell.Exec(ctx, command, shellExecTimeout)
	default: // "exec"
		execOpts := sshrun.ExecOptions{PTY: s.pty}
		res, err = sshrun.ExecOnce(ctx, s.conn.Client, effectiveCommand, execOpts)
	}
	if err != nil {
		e.auditE(audit.Entry{
			Caller: c.ID, Host: s.host, Serial: s.serial, SessionID: sessionID,
			Command: command, Outcome: "error", Err: err.Error(),
		})
		return nil, fmt.Errorf("session execution: %w", err)
	}

	// Fail-closed gate: withhold the output if this per-command record cannot be
	// persisted (the session_open record already gated the session's existence).
	if err := e.auditE(audit.Entry{
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
		Elevation:  s.elevLabel,
		PTY:        s.pty,
		PolicyRule: decisionRule(dec),
		Warning:    strings.Join(warnings, "; "),
	}); err != nil {
		return nil, err
	}
	return &Result{Stdout: res.Stdout, Stderr: res.Stderr, ExitCode: res.ExitCode, Serial: s.serial, Warnings: warnings}, nil
}

// authorizeSessionExec asks the signer for the current policy decision before
// every session command. This deliberately runs even for sessions opened before
// a command_policy existed, so signer reloads take effect on already-open
// sessions; shell/pty sessions are then blocked if the current policy requires
// mode=exec. For sessions with a recorded connectivity signature, it also
// revalidates every current bastion hop as RoleBastion before the target
// command preflight.
func (e *Engine) authorizeSessionExec(ctx context.Context, c Caller, s *liveSession, command string) (*signer.DecisionInfo, error) {
	if s.connectivitySig != "" {
		currentSig, err := e.currentConnectivitySignature(ctx, s.host)
		if err != nil {
			return nil, fmt.Errorf("session connectivity preflight: %w", err)
		}
		if currentSig != s.connectivitySig {
			return nil, fmt.Errorf("session host connectivity changed for %q; close this session and open a new one", s.host)
		}
		if err := e.authorizeSessionBastions(ctx, c, s.host); err != nil {
			return nil, err
		}
	}
	_, pub, err := ca.GenerateEphemeralKey()
	if err != nil {
		return nil, err
	}
	sessionMode := signer.SessionModeExec
	switch s.mode {
	case "shell":
		sessionMode = signer.SessionModeShell
	case "pty":
		sessionMode = signer.SessionModePTY
	}
	issued, err := e.sgn.SignIntent(ctx, signer.Intent{
		Caller:        localCaller,
		Host:          s.host,
		Role:          signer.RoleTarget,
		Purpose:       signer.PurposeSession,
		SessionMode:   sessionMode,
		Command:       command,
		RequestedTTL:  e.maxTTL,
		PublicKey:     pub,
		Sudo:          s.sudo,
		SudoUser:      s.sudoUser,
		PTY:           s.pty,
		DryRun:        true,
		Preflight:     true,
		EndUser:       c.ID,
		EndUserGroups: c.Groups,
	})
	if err != nil {
		return nil, fmt.Errorf("session command policy preflight: %w", err)
	}
	dec := issued.Decision
	if dec == nil {
		return nil, nil
	}
	if !dec.Allowed {
		if dec.Reason != "" {
			return dec, fmt.Errorf("session command not allowed: %s", dec.Reason)
		}
		return dec, fmt.Errorf("session command not allowed by command_policy (%s)", dec.MatchedRule)
	}
	if dec.RequireApproval {
		return dec, fmt.Errorf("session command requires human approval (%s); use ssh_execute for approval-gated commands", dec.MatchedRule)
	}
	return dec, nil
}

func (e *Engine) authorizeSessionBastions(ctx context.Context, c Caller, host string) error {
	chain, err := e.resolveChain(host)
	if err != nil {
		return fmt.Errorf("session bastion preflight: %w", err)
	}
	if len(chain) <= 1 {
		return nil
	}
	_, pub, err := ca.GenerateEphemeralKey()
	if err != nil {
		return err
	}
	for _, name := range chain[:len(chain)-1] {
		issued, err := e.sgn.SignIntent(ctx, signer.Intent{
			Caller:        localCaller,
			Host:          name,
			Role:          signer.RoleBastion,
			Purpose:       signer.PurposeSession,
			RequestedTTL:  e.maxTTL,
			PublicKey:     pub,
			DryRun:        true,
			Preflight:     true,
			EndUser:       c.ID,
			EndUserGroups: c.Groups,
		})
		if err != nil {
			return fmt.Errorf("session bastion preflight for %q: %w", name, err)
		}
		if issued == nil || issued.Decision == nil {
			return fmt.Errorf("session bastion %q preflight returned no decision", name)
		}
		dec := issued.Decision
		if !dec.Allowed {
			if dec.Reason != "" {
				return fmt.Errorf("session bastion %q not allowed: %s", name, dec.Reason)
			}
			return fmt.Errorf("session bastion %q not allowed by signer policy", name)
		}
		if dec.RequireApproval {
			return fmt.Errorf("session bastion %q requires human approval; close this session and open a new one after policy is updated", name)
		}
	}
	return nil
}

// CloseSession closes and removes a session.
// C1: only the caller that opened the session may close it.
func (e *Engine) CloseSession(c Caller, sessionID string) error {
	// Verify ownership and remove atomically, without refreshing lastUsed, so a
	// non-owner probing a leaked session_id can neither close the session nor keep
	// it alive against the idle reaper (C1).
	s, found, owned := e.sessions.removeOwned(sessionID, c.ID)
	if !found {
		return fmt.Errorf("unknown session: %q", sessionID)
	}
	if !owned {
		return fmt.Errorf("session %q does not belong to the current caller", sessionID)
	}
	s.close()
	e.auditE(audit.Entry{Caller: c.ID, Host: s.host, Serial: s.serial, SessionID: sessionID, Outcome: "session_close"})
	return nil
}

func newSessionID() string {
	var b [12]byte
	// crypto/rand.Read never returns an error on Go 1.24+ (it crashes the process
	// if the OS RNG fails), so this cannot produce a deterministic id; the error is
	// intentionally discarded rather than checked as dead code.
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
