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
)

// ShellSession mantiene un intérprete de shell vivo sobre una conexión SSH, de
// modo que el estado (cwd, variables) persiste entre comandos.
//
// Hay dos variantes:
//
//   - Sin PTY (mode=shell): arranca /bin/sh directamente. Stdout y stderr van
//     separados. No hay eco ni prompt. No apta para comandos que comprueben isatty().
//
//   - Con PTY (mode=pty): solicita un pseudo-terminal y arranca el shell bajo él.
//     Stdout y stderr se mezclan en el canal del PTY. Se deshabilita el eco y se
//     vacía el prompt (PS1='') para poder aplicar el mismo protocolo de marcadores.
//     Apta para programas que requieren un TTY real.
//
// El fin de cada comando se detecta con un marcador aleatorio que imprime el código
// de salida. No soporta comandos interactivos que pidan entrada por teclado.
type lineRes struct {
	text string
	err  error
}

type ShellSession struct {
	mu      sync.Mutex
	session *ssh.Session
	stdin   io.WriteCloser
	lines   chan lineRes // alimentado por una única goroutine lectora
	stderr  *syncBuf    // nil en modo PTY (streams mezclados)
	marker  string
	pty     bool // true si la sesión usa PTY
}

// syncBuf es un buffer concurrente: una goroutine vuelca stderr aquí.
// A3: limita la acumulación a maxOutputBytes para evitar OOM.
type syncBuf struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// A3: descartar silenciosamente los bytes que superen el límite.
	if s.buf.Len() >= maxOutputBytes {
		return len(p), nil
	}
	rem := maxOutputBytes - s.buf.Len()
	if len(p) > rem {
		p = p[:rem]
	}
	return s.buf.Write(p)
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

// OpenShell arranca un shell (sin PTY) sobre client. shellCmd es el comando a
// ejecutar remotamente; normalmente "/bin/sh" pero puede ser
// "sudo -n -- /bin/sh" para elevar la sesión completa.
func OpenShell(client *ssh.Client, shellCmd string) (*ShellSession, error) {
	if shellCmd == "" {
		shellCmd = "/bin/sh"
	}
	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("abrir sesión: %w", err)
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
		return nil, fmt.Errorf("arrancar shell: %w", err)
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
		return nil, fmt.Errorf("sincronizar shell: %w", err)
	}
	return sh, nil
}

// OpenShellPTY arranca un shell con PTY sobre client. shellCmd funciona igual
// que en OpenShell (p. ej. "sudo -n -- /bin/sh" para elevar).
// opts controla las dimensiones y el tipo de terminal.
//
// En modo PTY stdout y stderr se mezclan; Result.Stderr siempre estará vacío.
func OpenShellPTY(client *ssh.Client, shellCmd string, opts ExecOptions) (*ShellSession, error) {
	if shellCmd == "" {
		shellCmd = "/bin/sh"
	}

	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("abrir sesión PTY: %w", err)
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
		ssh.ECHO:          0, // deshabilitar eco
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := session.RequestPty(term, int(rows), int(cols), modes); err != nil {
		session.Close()
		return nil, fmt.Errorf("solicitar PTY: %w", err)
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		session.Close()
		return nil, fmt.Errorf("stdin PTY: %w", err)
	}
	// Con PTY, StdoutPipe y StderrPipe se obtienen en el canal combinado.
	stdout, err := session.StdoutPipe()
	if err != nil {
		session.Close()
		return nil, fmt.Errorf("stdout PTY: %w", err)
	}

	if err := session.Start(shellCmd); err != nil {
		session.Close()
		return nil, fmt.Errorf("arrancar shell PTY: %w", err)
	}

	var b [8]byte
	_, _ = rand.Read(b[:])
	sh := &ShellSession{
		session: session,
		stdin:   stdin,
		lines:   make(chan lineRes),
		stderr:  nil, // mezclado en stdout con PTY
		marker:  "__BRK_" + hex.EncodeToString(b[:]) + "__",
		pty:     true,
	}
	go shellReader(stdout, sh.lines)

	// Silenciar el prompt y asegurarnos de que el eco está off.
	initCmd := "stty -echo 2>/dev/null; PS1=''; PS2=''\n"
	if _, err := io.WriteString(stdin, initCmd); err != nil {
		session.Close()
		return nil, fmt.Errorf("inicializar PTY: %w", err)
	}

	// Sincronizar con un no-op para consumir la salida del init.
	if _, err := sh.Exec(":", 10*time.Second); err != nil {
		session.Close()
		return nil, fmt.Errorf("sincronizar shell PTY: %w", err)
	}
	return sh, nil
}

// shellReader es la goroutine lectora única: lee líneas de stdout y las entrega
// en orden. Entre comandos queda bloqueada en ReadString (sin salida que perder).
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

// Exec ejecuta command y devuelve (stdout, stderr, exit code). timeout acota la
// espera de la salida.
//
// En modo PTY Result.Stderr estará vacío (los streams se mezclan en Stdout).
func (s *ShellSession) Exec(command string, timeout time.Duration) (*Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var errStart int
	if s.stderr != nil {
		errStart = s.stderr.snapshotLen()
	}

	line := fmt.Sprintf("%s\nprintf '%%s:%%d\\n' '%s' \"$?\"\n", command, s.marker)
	if _, err := io.WriteString(s.stdin, line); err != nil {
		return nil, fmt.Errorf("escribir comando: %w", err)
	}

	var out strings.Builder
	deadline := time.After(timeout)
	for {
		select {
		case <-deadline:
			return nil, fmt.Errorf("timeout esperando salida del comando")
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
				// A3: limitar la acumulación de stdout para evitar OOM.
				if out.Len()+len(lr.text) > maxOutputBytes {
					return nil, fmt.Errorf("salida del comando supera el límite de %d bytes", maxOutputBytes)
				}
				out.WriteString(lr.text)
			}
			if lr.err != nil {
				return nil, fmt.Errorf("lectura interrumpida: %w", lr.err)
			}
		}
	}
}

// Close cierra el shell.
func (s *ShellSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.stdin.Close()
	return s.session.Close()
}
