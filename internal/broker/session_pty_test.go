package broker

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/luisgf/infrabroker/internal/signer"
)

// TestSessionExecPTYRejectsOversizedCommand pins #579: a mode=pty command past
// MaxPTYCommandBytes would be silently cut at the tty line limit (4095 bytes
// on Linux), so the host would run a prefix of what the signer preflighted and
// the audit log records. It is refused with ErrBadRequest before any signer
// call and audited as session_exec_denied; shell/exec sessions are unaffected.
func TestSessionExecPTYRejectsOversizedCommand(t *testing.T) {
	e := &Engine{
		cfg:      &Config{Hosts: map[string]HostConfig{}},
		auditLog: openTestAudit(t),
		sessions: newSessionManager(5*time.Minute, 30*time.Minute, nil),
	}
	t.Cleanup(func() { e.sessions.closeAll() })
	// The dummy sessions have no shell behind them: a denying signer stops the
	// call right after the preflight, and fs.count tells whether it ran.
	fs := &sessionPolicySigner{issued: &signer.Issued{Decision: &signer.DecisionInfo{
		Allowed: false, Reason: "stop after preflight", MatchedRule: "test",
	}}}
	e.sgn = fs
	s := dummySession("sess-579-pty", "alice")
	s.mode = "pty"
	s.pty = true
	_ = e.sessions.add(s)

	long := "echo " + strings.Repeat("x", 5000)
	_, err := e.SessionExec(context.Background(), Caller{ID: "alice"}, s.id, long)
	if !errors.Is(err, ErrBadRequest) {
		t.Fatalf("a %d-byte pty command must be rejected with ErrBadRequest, got %v", len(long), err)
	}
	if fs.count != 0 {
		t.Fatalf("the oversized command must be refused before any signer call, calls=%d", fs.count)
	}
	ent := lastAuditEntry(t, e)
	if ent.Outcome != "session_exec_denied" || ent.SessionID != s.id || !ent.PTY {
		t.Errorf("audit = %+v, want session_exec_denied for the pty session", ent)
	}

	// At the limit the command still reaches the signer.
	atLimit := strings.Repeat("y", MaxPTYCommandBytes)
	_, _ = e.SessionExec(context.Background(), Caller{ID: "alice"}, s.id, atLimit)
	if fs.count != 1 {
		t.Fatalf("a command of exactly %d bytes must be preflighted, calls=%d", MaxPTYCommandBytes, fs.count)
	}

	// A shell session has no tty line discipline: the same command is preflighted.
	sh := dummySession("sess-579-shell", "alice")
	sh.mode = "shell"
	_ = e.sessions.add(sh)
	_, _ = e.SessionExec(context.Background(), Caller{ID: "alice"}, sh.id, long)
	if fs.count != 2 {
		t.Fatalf("the pty bound must not apply to shell sessions, calls=%d", fs.count)
	}
}

// TestSessionExecPTYRejectsControlBytes pins #642: the pty's canonical line
// discipline interprets control bytes (kill-line, word-erase, erase, EOF …)
// before the shell reads the line, so the host would run an edited command
// that differs from what the signer preflighted and the audit log recorded.
// Such commands are refused with ErrBadRequest before any signer call and
// audited as session_exec_denied; printable text and tab still go through.
func TestSessionExecPTYRejectsControlBytes(t *testing.T) {
	for _, cmd := range []string{"ls\x15id", "\x04", "a\x7fb", "x\x03y", "x\x17y", "x\x16y"} {
		e := &Engine{
			cfg:      &Config{Hosts: map[string]HostConfig{}},
			auditLog: openTestAudit(t),
			sessions: newSessionManager(5*time.Minute, 30*time.Minute, nil),
		}
		t.Cleanup(func() { e.sessions.closeAll() })
		fs := &sessionPolicySigner{issued: &signer.Issued{Decision: &signer.DecisionInfo{
			Allowed: false, Reason: "stop after preflight", MatchedRule: "test",
		}}}
		e.sgn = fs
		s := dummySession("sess-642-pty", "alice")
		s.mode = "pty"
		s.pty = true
		_ = e.sessions.add(s)

		_, err := e.SessionExec(context.Background(), Caller{ID: "alice"}, s.id, cmd)
		if !errors.Is(err, ErrBadRequest) {
			t.Fatalf("pty command %q must be rejected with ErrBadRequest, got %v", cmd, err)
		}
		if fs.count != 0 {
			t.Fatalf("pty command %q must be refused before any signer call, calls=%d", cmd, fs.count)
		}
		if n := len(readAuditLog(t, e)); n != 1 {
			t.Errorf("audit records for %q = %d, want exactly 1", cmd, n)
		}
		ent := lastAuditEntry(t, e)
		if ent.Outcome != "session_exec_denied" || ent.SessionID != s.id || !ent.PTY || ent.Command != cmd {
			t.Errorf("audit for %q = %+v, want session_exec_denied for the pty session", cmd, ent)
		}

		// Tab is plain input for the line discipline: it reaches the signer.
		_, _ = e.SessionExec(context.Background(), Caller{ID: "alice"}, s.id, "ls\tx")
		if fs.count != 1 {
			t.Fatalf("a pty command with a tab must be preflighted, calls=%d", fs.count)
		}
	}
}
