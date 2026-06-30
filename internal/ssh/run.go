// Package ssh opens the connection to the host (direct or through one or more
// bastions) using ephemeral certificates and executes commands. It is the only
// point in the system where credential material exists.
package ssh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

// A3 limits: execution timeout and maximum output size.
const (
	// defaultExecTimeout caps the wait for a one-shot SSH command.
	// Prevents session.Run() from blocking indefinitely.
	defaultExecTimeout = 10 * time.Minute
	// maxOutputBytes is the maximum output buffer size per stream
	// (stdout or stderr). Prevents OOM from arbitrarily large output.
	maxOutputBytes = 10 * 1024 * 1024 // 10 MiB
)

// limitedWriter accumulates up to max bytes in an internal bytes.Buffer and
// silently discards the overflow, recording that the output was truncated.
// It always reports the full slice as consumed: returning n < len(p) with a
// nil error would violate the io.Writer contract and make the io.Copy inside
// x/crypto/ssh abort with ErrShortWrite (failing the command or stalling the
// channel) instead of delivering truncated output.
type limitedWriter struct {
	buf       bytes.Buffer
	max       int
	truncated bool
}

func (lw *limitedWriter) Write(p []byte) (int, error) {
	rem := lw.max - lw.buf.Len()
	if rem <= 0 {
		if len(p) > 0 {
			lw.truncated = true
		}
		return len(p), nil
	}
	keep := p
	if len(keep) > rem {
		keep = keep[:rem]
		lw.truncated = true
	}
	lw.buf.Write(keep) // bytes.Buffer.Write never returns an error
	return len(p), nil
}

// output returns the captured stream, with an explicit marker appended when
// the output was truncated at the cap.
func (lw *limitedWriter) output() string {
	if !lw.truncated {
		return lw.buf.String()
	}
	return lw.buf.String() + fmt.Sprintf("\n[output truncated: limit of %d bytes exceeded]\n", lw.max)
}

// Hop is one step in the connection chain (bastion or final target). The first
// hop is reached by direct TCP; subsequent hops go through the previous hop's
// channel.
type Hop struct {
	Addr    string
	User    string
	HostKey ssh.PublicKey
	// PrivateKey + Certificate form the signer for this hop's ephemeral cert.
	PrivateKey  ed25519.PrivateKey
	Certificate *ssh.Certificate
}

// Conn wraps the SSH client to the final target and keeps intermediate clients
// so they can be closed in reverse order.
type Conn struct {
	Client  *ssh.Client
	closers []io.Closer
}

// Close closes the final client and the chain of intermediaries.
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

// Target describes the destination for a one-shot Run (single hop, no bastion).
type Target struct {
	Addr           string
	User           string
	HostKey        ssh.PublicKey
	ConnectTimeout time.Duration
}

// Result is the captured output of an execution.
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

func hopClientConfig(h Hop, timeout time.Duration) (*ssh.ClientConfig, error) {
	if h.HostKey == nil {
		return nil, fmt.Errorf("host key for %s is required (do not accept blindly)", h.Addr)
	}
	keySigner, err := ssh.NewSignerFromKey(h.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("ephemeral key signer (%s): %w", h.Addr, err)
	}
	certSigner, err := ssh.NewCertSigner(h.Certificate, keySigner)
	if err != nil {
		return nil, fmt.Errorf("certificate signer (%s): %w", h.Addr, err)
	}
	return &ssh.ClientConfig{
		User:              h.User,
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(certSigner)},
		HostKeyCallback:   ssh.FixedHostKey(h.HostKey),
		HostKeyAlgorithms: []string{h.HostKey.Type()},
		Timeout:           timeout,
	}, nil
}

// Dial establishes the connection chain. hops[0] is the first hop (or the
// target if there is no bastion); the last hop is the final target. ctx bounds
// every dial in the chain (TCP to the first hop and the direct-tcpip channel
// opens through the bastions), in addition to the per-hop timeout.
func Dial(ctx context.Context, hops []Hop, timeout time.Duration) (*Conn, error) {
	if len(hops) == 0 {
		return nil, fmt.Errorf("at least one hop is required")
	}
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	cfg0, err := hopClientConfig(hops[0], timeout)
	if err != nil {
		return nil, err
	}
	dialer := net.Dialer{Timeout: timeout}
	tcp, err := dialer.DialContext(ctx, "tcp", hops[0].Addr)
	if err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", hops[0].Addr, err)
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
		// direct-tcpip channel through the previous hop. ClientConfig.Timeout
		// only covers the SSH handshake, so the channel open needs its own
		// bound or a dead bastion would block the dial indefinitely.
		dialCtx, cancel := context.WithTimeout(ctx, timeout)
		nc, err := current.DialContext(dialCtx, "tcp", hops[i].Addr)
		cancel()
		if err != nil {
			conn.closeAll()
			return nil, fmt.Errorf("hop to %s: %w", hops[i].Addr, err)
		}
		cc, chans, reqs, err := ssh.NewClientConn(nc, hops[i].Addr, cfg)
		if err != nil {
			nc.Close()
			conn.closeAll()
			return nil, fmt.Errorf("handshake %s (via bastion): %w", hops[i].Addr, err)
		}
		// The previous client becomes an intermediate (to be closed at the end).
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

// ExecOptions controls optional parameters for a remote command execution.
type ExecOptions struct {
	// PTY requests a pseudo-terminal before executing the command. Useful for
	// programs that check isatty() or require a real TTY.
	// Note: with PTY, stdout and stderr are merged in Result.Stdout;
	// Result.Stderr will be empty.
	PTY bool
	// Term is the terminal type to announce (default "xterm-256color").
	Term string
	// Rows and Cols are the PTY dimensions (default 40×220).
	Rows uint32
	Cols uint32
	// Timeout caps the remote command wait (A3). 0 = defaultExecTimeout.
	Timeout time.Duration
}

// defaultPTYTerm is the default terminal type.
const defaultPTYTerm = "xterm-256color"

// ptyParams resolves the terminal type, dimensions, and modes for a PTY
// request, applying the defaults (xterm-256color, 40×220, echo off).
func ptyParams(o ExecOptions) (string, int, int, ssh.TerminalModes) {
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
		ssh.ECHO:          0, // disable echo
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	return term, int(rows), int(cols), modes
}

// ExecOnce opens an exec channel over conn, runs command, and captures the
// output. If opts.PTY is true a PTY is requested first; streams are merged.
// A3: execution is bounded by opts.Timeout (or defaultExecTimeout when 0) and
// output is limited to maxOutputBytes per stream to prevent OOM.
// ExecOnce honours ctx: if the caller cancels (e.g. the MCP/HTTP client
// disconnects) the remote command is aborted instead of running on to the
// timeout. Both the PTY and the plain branch share runWithTimeout, so the
// cancellation and timeout handling is identical for both.
func ExecOnce(ctx context.Context, client *ssh.Client, command string, opts ...ExecOptions) (*Result, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("opening session: %w", err)
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
		term, rows, cols, modes := ptyParams(o)
		if err := session.RequestPty(term, rows, cols, modes); err != nil {
			return nil, fmt.Errorf("requesting PTY: %w", err)
		}
		// With PTY, stdout and stderr are merged in the PTY stdout channel.
		var combined limitedWriter
		combined.max = maxOutputBytes
		session.Stdout = &combined

		runErr, completed := runWithTimeout(ctx, session, command, execTimeout)
		if !completed {
			return nil, runErr // cancelled or timed out; the process was signalled
		}
		res.Stdout = combined.output()
		return finishResult(res, runErr, "executing command (pty)")
	}

	var stdout, stderr limitedWriter
	stdout.max = maxOutputBytes
	stderr.max = maxOutputBytes
	session.Stdout = &stdout
	session.Stderr = &stderr

	runErr, completed := runWithTimeout(ctx, session, command, execTimeout)
	if !completed {
		return nil, runErr // cancelled or timed out; the process was signalled
	}
	res.Stdout = stdout.output()
	res.Stderr = stderr.output()
	return finishResult(res, runErr, "executing command")
}

// runWithTimeout runs command on session in a goroutine and waits, honouring ctx
// and execTimeout (A3). It returns (runErr, completed): completed==true means
// session.Run returned and runErr is its result; completed==false means the run
// was interrupted by cancellation or timeout — the remote process was signalled
// and runErr is ctx.Err() or the timeout error.
func runWithTimeout(ctx context.Context, session *ssh.Session, command string, execTimeout time.Duration) (error, bool) {
	done := make(chan error, 1)
	go func() { done <- session.Run(command) }()
	return waitResult(ctx, done, execTimeout, func() { _ = session.Signal(ssh.SIGTERM) })
}

// waitResult is the cancellation/timeout select, extracted (and free of any SSH
// type) so it can be unit-tested directly. onInterrupt is called once before
// returning on cancellation or timeout (in production it sends SIGTERM).
func waitResult(ctx context.Context, done <-chan error, execTimeout time.Duration, onInterrupt func()) (error, bool) {
	select {
	case err := <-done:
		return err, true
	case <-ctx.Done():
		onInterrupt()
		return ctx.Err(), false
	case <-time.After(execTimeout):
		onInterrupt()
		return fmt.Errorf("SSH execution timeout (limit: %v)", execTimeout), false
	}
}

// finishResult maps a completed session.Run error onto the Result: a non-zero
// exit becomes res.ExitCode (no error); any other error is wrapped with what.
func finishResult(res *Result, runErr error, what string) (*Result, error) {
	if runErr != nil {
		if exitErr, ok := runErr.(*ssh.ExitError); ok {
			res.ExitCode = exitErr.ExitStatus()
			return res, nil
		}
		return res, fmt.Errorf("%s: %w", what, runErr)
	}
	return res, nil
}

// Run connects in a single shot (one hop, the target) and executes command.
func Run(ctx context.Context, priv ed25519.PrivateKey, cert *ssh.Certificate, t Target, command string) (*Result, error) {
	conn, err := Dial(ctx, []Hop{{
		Addr: t.Addr, User: t.User, HostKey: t.HostKey,
		PrivateKey: priv, Certificate: cert,
	}}, t.ConnectTimeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return ExecOnce(ctx, conn.Client, command)
}
