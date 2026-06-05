// Package ssh abre la conexión al host (directa o a través de uno o varios
// bastiones) usando certificados efímeros y ejecuta comandos. Es el único punto
// donde existe el material de la credencial.
package ssh

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"io"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

// Límites de A3: timeout de ejecución y tamaño máximo de salida.
const (
	// defaultExecTimeout acota la espera de un comando SSH de un disparo.
	// Evita que sesión.Run() se bloquee indefinidamente.
	defaultExecTimeout = 10 * time.Minute
	// maxOutputBytes es el tamaño máximo del buffer de salida por stream
	// (stdout o stderr). Evita OOM ante salidas de tamaño arbitrario.
	maxOutputBytes = 10 * 1024 * 1024 // 10 MiB
)

// limitedWriter escribe en un bytes.Buffer interno hasta un máximo de max bytes.
// Cuando se supera el límite, las escrituras adicionales devuelven error para que
// el canal SSH deje de acumular datos.
type limitedWriter struct {
	buf   bytes.Buffer
	max   int
	total int
}

func (lw *limitedWriter) Write(p []byte) (int, error) {
	if lw.total >= lw.max {
		return 0, fmt.Errorf("salida truncada: límite de %d bytes superado", lw.max)
	}
	rem := lw.max - lw.total
	if len(p) > rem {
		p = p[:rem]
	}
	n, err := lw.buf.Write(p)
	lw.total += n
	return n, err
}

// Hop es un salto de la cadena de conexión (bastión o destino final). El primer
// hop se alcanza por TCP directo; los siguientes a través del canal del anterior.
type Hop struct {
	Addr    string
	User    string
	HostKey ssh.PublicKey
	// PrivateKey + Certificate forman el signer del cert efímero de este hop.
	PrivateKey  ed25519.PrivateKey
	Certificate *ssh.Certificate
}

// Conn envuelve el cliente SSH al destino final y mantiene los clientes
// intermedios para cerrarlos en orden inverso.
type Conn struct {
	Client  *ssh.Client
	closers []io.Closer
}

// Close cierra el cliente final y la cadena de intermedios.
func (c *Conn) Close() error {
	var firstErr error
	if err := c.Client.Close(); err != nil {
		firstErr = err
	}
	for i := len(c.closers) - 1; i >= 0; i-- {
		if err := c.closers[i].Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Target describe el destino de un Run de un disparo (sin saltos).
type Target struct {
	Addr           string
	User           string
	HostKey        ssh.PublicKey
	ConnectTimeout time.Duration
}

// Result es la salida capturada de la ejecución.
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

func hopClientConfig(h Hop, timeout time.Duration) (*ssh.ClientConfig, error) {
	if h.HostKey == nil {
		return nil, fmt.Errorf("host key de %s es obligatoria (no aceptar ciegamente)", h.Addr)
	}
	keySigner, err := ssh.NewSignerFromKey(h.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("signer de clave efímera (%s): %w", h.Addr, err)
	}
	certSigner, err := ssh.NewCertSigner(h.Certificate, keySigner)
	if err != nil {
		return nil, fmt.Errorf("signer de certificado (%s): %w", h.Addr, err)
	}
	return &ssh.ClientConfig{
		User:              h.User,
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(certSigner)},
		HostKeyCallback:   ssh.FixedHostKey(h.HostKey),
		HostKeyAlgorithms: []string{h.HostKey.Type()},
		Timeout:           timeout,
	}, nil
}

// Dial establece la cadena de conexión. hops[0] es el primer salto (o el destino
// si no hay bastión); el último hop es el destino final.
func Dial(hops []Hop, timeout time.Duration) (*Conn, error) {
	if len(hops) == 0 {
		return nil, fmt.Errorf("se requiere al menos un hop")
	}
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	cfg0, err := hopClientConfig(hops[0], timeout)
	if err != nil {
		return nil, err
	}
	tcp, err := net.DialTimeout("tcp", hops[0].Addr, timeout)
	if err != nil {
		return nil, fmt.Errorf("conectar a %s: %w", hops[0].Addr, err)
	}
	c0, chans, reqs, err := ssh.NewClientConn(tcp, hops[0].Addr, cfg0)
	if err != nil {
		tcp.Close()
		return nil, fmt.Errorf("handshake %s: %w", hops[0].Addr, err)
	}
	current := ssh.NewClient(c0, chans, reqs)

	conn := &Conn{Client: current}
	for i := 1; i < len(hops); i++ {
		cfg, err := hopClientConfig(hops[i], timeout)
		if err != nil {
			conn.closeAll()
			return nil, err
		}
		// Canal direct-tcpip a través del salto anterior.
		nc, err := current.Dial("tcp", hops[i].Addr)
		if err != nil {
			conn.closeAll()
			return nil, fmt.Errorf("salto a %s: %w", hops[i].Addr, err)
		}
		cc, chans, reqs, err := ssh.NewClientConn(nc, hops[i].Addr, cfg)
		if err != nil {
			nc.Close()
			conn.closeAll()
			return nil, fmt.Errorf("handshake %s (vía bastión): %w", hops[i].Addr, err)
		}
		// El cliente anterior pasa a ser intermedio (a cerrar al final).
		conn.closers = append(conn.closers, current)
		current = ssh.NewClient(cc, chans, reqs)
		conn.Client = current
	}
	return conn, nil
}

func (c *Conn) closeAll() {
	_ = c.Client.Close()
	for i := len(c.closers) - 1; i >= 0; i-- {
		_ = c.closers[i].Close()
	}
}

// ExecOptions controla opciones opcionales de ejecución de un comando remoto.
type ExecOptions struct {
	// PTY solicita un pseudo-terminal antes de ejecutar el comando. Útil para
	// programas que comprueban isatty() o que requieren un TTY real.
	// Nota: con PTY los streams stdout y stderr se mezclan en Result.Stdout;
	// Result.Stderr quedará vacío.
	PTY bool
	// Term es el tipo de terminal a anunciar (default "xterm-256color").
	Term string
	// Rows y Cols son las dimensiones del PTY (default 40×220).
	Rows uint32
	Cols uint32
	// Timeout acota la espera del comando remoto (A3). 0 = defaultExecTimeout.
	Timeout time.Duration
}

// defaultPTYTerm es el tipo de terminal por defecto.
const defaultPTYTerm = "xterm-256color"

// ExecOnce abre un canal exec sobre conn, ejecuta command y captura la salida.
// Si opts.PTY es true solicita un PTY antes de ejecutar; los streams se mezclan.
// A3: la ejecución está acotada por opts.Timeout (o defaultExecTimeout si es 0)
// y la salida se limita a maxOutputBytes por stream para evitar OOM.
func ExecOnce(client *ssh.Client, command string, opts ...ExecOptions) (*Result, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("abrir sesión: %w", err)
	}
	defer session.Close()

	var o ExecOptions
	if len(opts) > 0 {
		o = opts[0]
	}
	execTimeout := o.Timeout
	if execTimeout <= 0 {
		execTimeout = defaultExecTimeout
	}

	res := &Result{}

	if o.PTY {
		term := o.Term
		if term == "" {
			term = defaultPTYTerm
		}
		rows := o.Rows
		if rows == 0 {
			rows = 40
		}
		cols := o.Cols
		if cols == 0 {
			cols = 220
		}
		modes := ssh.TerminalModes{
			ssh.ECHO:          0, // sin eco
			ssh.TTY_OP_ISPEED: 14400,
			ssh.TTY_OP_OSPEED: 14400,
		}
		if err := session.RequestPty(term, int(rows), int(cols), modes); err != nil {
			return nil, fmt.Errorf("solicitar PTY: %w", err)
		}
		// Con PTY stdout y stderr se mezclan en el canal stdout del PTY.
		var combined limitedWriter
		combined.max = maxOutputBytes
		session.Stdout = &combined

		// A3: correr session.Run en goroutine para poder acotar el tiempo.
		type runRes struct{ err error }
		done := make(chan runRes, 1)
		go func() { done <- runRes{err: session.Run(command)} }()

		select {
		case r := <-done:
			res.Stdout = combined.buf.String()
			if r.err != nil {
				if exitErr, ok := r.err.(*ssh.ExitError); ok {
					res.ExitCode = exitErr.ExitStatus()
					return res, nil
				}
				return res, fmt.Errorf("ejecutar comando (pty): %w", r.err)
			}
		case <-time.After(execTimeout):
			_ = session.Signal(ssh.SIGTERM)
			return nil, fmt.Errorf("timeout de ejecución SSH (límite: %v)", execTimeout)
		}
		return res, nil
	}

	var stdout, stderr limitedWriter
	stdout.max = maxOutputBytes
	stderr.max = maxOutputBytes
	session.Stdout = &stdout
	session.Stderr = &stderr

	// A3: correr session.Run en goroutine para poder acotar el tiempo.
	type runRes struct{ err error }
	done := make(chan runRes, 1)
	go func() { done <- runRes{err: session.Run(command)} }()

	select {
	case r := <-done:
		res.Stdout = stdout.buf.String()
		res.Stderr = stderr.buf.String()
		if r.err != nil {
			if exitErr, ok := r.err.(*ssh.ExitError); ok {
				res.ExitCode = exitErr.ExitStatus()
				return res, nil
			}
			return res, fmt.Errorf("ejecutar comando: %w", r.err)
		}
	case <-time.After(execTimeout):
		_ = session.Signal(ssh.SIGTERM)
		return nil, fmt.Errorf("timeout de ejecución SSH (límite: %v)", execTimeout)
	}
	return res, nil
}

// Run conecta de un disparo (un solo hop, el destino) y ejecuta command.
func Run(priv ed25519.PrivateKey, cert *ssh.Certificate, t Target, command string) (*Result, error) {
	conn, err := Dial([]Hop{{
		Addr: t.Addr, User: t.User, HostKey: t.HostKey,
		PrivateKey: priv, Certificate: cert,
	}}, t.ConnectTimeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return ExecOnce(conn.Client, command)
}
