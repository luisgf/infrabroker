package broker

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/luisgf/ssh-broker/internal/audit"
	"github.com/luisgf/ssh-broker/internal/signer"
	sshrun "github.com/luisgf/ssh-broker/internal/ssh"
)

// shellExecTimeout acota la espera de salida en sesiones shell/pty.
const shellExecTimeout = 120 * time.Second

// liveSession es una conexión SSH retenida (= unidad de pool y de sesión
// persistente). Un solo cert (serial) la autenticó; sus comandos lo reutilizan.
type liveSession struct {
	id       string
	caller   string
	host     string
	serial   uint64
	mode     string // "exec" | "shell" | "pty"
	conn     *sshrun.Conn
	shell    *sshrun.ShellSession // solo en mode "shell" y "pty"
	created  time.Time
	lastUsed time.Time

	// Elevación: prefijo a anteponer en cada comando de sesiones exec.
	// En sesiones shell/pty la elevación ya está en el proceso shell.
	elevationPrefix string
	// pty indica si esta sesión usa PTY.
	pty bool
}

func (s *liveSession) close() {
	if s.shell != nil {
		_ = s.shell.Close()
	}
	if s.conn != nil {
		_ = s.conn.Close()
	}
}

// sessionManager registra y recicla sesiones por inactividad / vida máxima.
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
			m.mu.Lock()
			for id, s := range m.sessions {
				if now.Sub(s.lastUsed) > m.idleTTL || now.Sub(s.created) > m.maxLife {
					s.close()
					delete(m.sessions, id)
					if m.onReap != nil {
						m.onReap(s)
					}
				}
			}
			m.mu.Unlock()
		}
	}
}

func (m *sessionManager) add(s *liveSession) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[s.id] = s
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

// SessionResult es lo que devuelve la apertura de una sesión.
type SessionResult struct {
	SessionID string
	Serial    uint64
}

// OpenSession abre una conexión persistente (un cert por conexión, sin
// force-command) y la registra. opts controla la elevación y el PTY.
//
// Modos:
//
//   - exec  (default): cada comando aislado (ExecOnce). Con sudo, el prefijo
//     se antepone a cada comando individualmente.
//   - shell: un /bin/sh con estado (cd, variables). Con sudo, el shell completo
//     se lanza bajo sudo (sesión elevada).
//   - pty:   igual que shell pero con PTY (permit-pty en el cert).
func (e *Engine) OpenSession(caller, host, mode string, ttlSeconds int, opts ExecOptions) (*SessionResult, error) {
	if _, ok := e.hostInfo(host); !ok {
		e.auditE(audit.Entry{Caller: caller, Host: host, Outcome: "denied", Err: "host desconocido"})
		return nil, fmt.Errorf("host desconocido: %q", host)
	}
	if mode == "" {
		mode = "exec"
	}
	if mode != "exec" && mode != "shell" && mode != "pty" {
		return nil, fmt.Errorf("mode inválido: %q (exec|shell|pty)", mode)
	}

	// PTY implícito en mode=pty.
	if mode == "pty" {
		opts.PTY = true
	}

	hops, serial, elevPrefix, err := e.buildHopsWithPrefix(host, e.ttlFor(ttlSeconds), signer.PurposeSession, opts)
	if err != nil {
		e.auditE(audit.Entry{Caller: caller, Host: host, Outcome: "error", Err: err.Error()})
		return nil, err
	}
	conn, err := sshrun.Dial(hops, 0)
	if err != nil {
		e.auditE(audit.Entry{Caller: caller, Host: host, Serial: serial, Outcome: "error", Err: err.Error()})
		return nil, fmt.Errorf("conexión: %w", err)
	}

	s := &liveSession{
		id: newSessionID(), caller: caller, host: host, serial: serial, mode: mode,
		conn: conn, created: time.Now(), lastUsed: time.Now(),
		elevationPrefix: elevPrefix,
		pty:             opts.PTY,
	}

	switch mode {
	case "shell":
		// shellCmd: si hay elevación arranca el shell directamente bajo sudo.
		shellCmd := "/bin/sh"
		if elevPrefix != "" {
			shellCmd = elevPrefix + " -- /bin/sh"
		}
		sh, err := sshrun.OpenShell(conn.Client, shellCmd)
		if err != nil {
			conn.Close()
			e.auditE(audit.Entry{Caller: caller, Host: host, Serial: serial, Outcome: "error", Err: err.Error()})
			return nil, fmt.Errorf("abrir shell: %w", err)
		}
		s.shell = sh
		// En shell elevado el prefijo va en el proceso; no se reaplica por comando.
		s.elevationPrefix = ""

	case "pty":
		shellCmd := "/bin/sh"
		if elevPrefix != "" {
			shellCmd = elevPrefix + " -- /bin/sh"
		}
		sh, err := sshrun.OpenShellPTY(conn.Client, shellCmd, sshrun.ExecOptions{PTY: true})
		if err != nil {
			conn.Close()
			e.auditE(audit.Entry{Caller: caller, Host: host, Serial: serial, Outcome: "error", Err: err.Error()})
			return nil, fmt.Errorf("abrir shell PTY: %w", err)
		}
		s.shell = sh
		s.elevationPrefix = ""
	}

	e.sessions.add(s)
	e.auditE(audit.Entry{
		Caller:    caller,
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

// SessionExec ejecuta command en una sesión existente, reutilizando la conexión.
// En sesiones exec con elevación, antepone el prefijo autorizado por el signer.
func (e *Engine) SessionExec(caller, sessionID, command string) (*Result, error) {
	s, ok := e.sessions.get(sessionID)
	if !ok {
		return nil, fmt.Errorf("sesión desconocida o expirada: %q", sessionID)
	}
	if command == "" {
		return nil, fmt.Errorf("command obligatorio")
	}

	// En sesiones exec con elevación, construir el comando elevado.
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
			Caller: caller, Host: s.host, Serial: s.serial, SessionID: sessionID,
			Command: command, Outcome: "error", Err: err.Error(),
		})
		return nil, fmt.Errorf("ejecución en sesión: %w", err)
	}

	// Etiqueta de elevación para auditoría.
	var elevLabel string
	if s.elevationPrefix != "" {
		elevLabel = elevationLabelFromPrefix(s.elevationPrefix)
	}

	e.auditE(audit.Entry{
		Caller:    caller,
		Host:      s.host,
		Serial:    s.serial,
		SessionID: sessionID,
		Command:   command,
		Outcome:   "session_exec",
		ExitCode:  res.ExitCode,
		Elevation: elevLabel,
		PTY:       s.pty,
	})
	return &Result{Stdout: res.Stdout, Stderr: res.Stderr, ExitCode: res.ExitCode, Serial: s.serial}, nil
}

// CloseSession cierra y elimina una sesión.
func (e *Engine) CloseSession(caller, sessionID string) error {
	s, ok := e.sessions.remove(sessionID)
	if !ok {
		return fmt.Errorf("sesión desconocida: %q", sessionID)
	}
	s.close()
	e.auditE(audit.Entry{Caller: caller, Host: s.host, Serial: s.serial, SessionID: sessionID, Outcome: "session_close"})
	return nil
}

// buildElevatedExecCommand envuelve command con el prefijo de elevación para
// sesiones exec (cada comando va por separado).
func buildElevatedExecCommand(prefix, command string) string {
	return fmt.Sprintf("%s -- /bin/sh -c %s", prefix, shellQuoteSession(command))
}

// shellQuoteSession es una copia local de shellQuote para evitar dependencia
// circular con signer (que ya tiene la función).
func shellQuoteSession(s string) string {
	result := "'"
	for _, c := range s {
		if c == '\'' {
			result += `'\''`
		} else {
			result += string(c)
		}
	}
	return result + "'"
}

// elevationLabelFromPrefix construye la etiqueta de auditoría a partir del
// prefijo guardado en la sesión (p. ej. "sudo -n" → "sudo:root").
func elevationLabelFromPrefix(prefix string) string {
	// "sudo -n" → root; "sudo -n -u deploy" → deploy
	if prefix == "sudo -n" {
		return "sudo:root"
	}
	// Extraer el usuario del flag -u.
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
