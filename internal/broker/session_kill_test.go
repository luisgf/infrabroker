package broker

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os/exec"
	"testing"
	"time"

	sshrun "github.com/luisgf/infrabroker/internal/ssh"
	"golang.org/x/crypto/ssh"
)

// These tests exercise the kill switch / shutdown teardown of a session that has
// a command genuinely in flight, over a REAL SSH transport and a REAL shell (not
// dummySession). Only a real connection reproduces #202: an in-flight Exec holds
// the ShellSession mutex, so close() must tear the transport down BEFORE the
// shell or shell.Close() blocks on that mutex until shellExecTimeout (120s).

// mustSSHSigner returns a fresh ed25519 SSH signer for the in-process server or
// client.
func mustSSHSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	sig, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return sig
}

// newRealShellSession starts an in-process SSH server backed by /bin/sh and
// returns a dialed connection plus an open shell session over it. The server
// runs each session channel's command under a context cancelled at test end, so
// a blocking command (e.g. "sleep") never outlives the test.
func newRealShellSession(t *testing.T) (*sshrun.Conn, *sshrun.ShellSession) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	hostSigner := mustSSHSigner(t)
	srvCfg := &ssh.ServerConfig{NoClientAuth: true}
	srvCfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			nConn, err := ln.Accept()
			if err != nil {
				return // listener closed at test end
			}
			go serveShellConn(ctx, nConn, srvCfg)
		}
	}()

	clientCfg := &ssh.ClientConfig{
		User:            "test",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(mustSSHSigner(t))},
		HostKeyCallback: ssh.FixedHostKey(hostSigner.PublicKey()),
	}
	client, err := ssh.Dial("tcp", ln.Addr().String(), clientCfg)
	if err != nil {
		t.Fatalf("ssh dial: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	shell, err := sshrun.OpenShell(context.Background(), client, "/bin/sh")
	if err != nil {
		t.Fatalf("open shell: %v", err)
	}
	return &sshrun.Conn{Client: client}, shell
}

// serveShellConn handles one accepted SSH connection: every session channel runs
// its command (the persistent /bin/sh opened by OpenShell) wired to the channel.
func serveShellConn(ctx context.Context, nConn net.Conn, cfg *ssh.ServerConfig) {
	sconn, chans, reqs, err := ssh.NewServerConn(nConn, cfg)
	if err != nil {
		_ = nConn.Close()
		return
	}
	defer sconn.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "only session channels")
			continue
		}
		ch, chReqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go serveSession(ctx, ch, chReqs)
	}
}

func serveSession(ctx context.Context, ch ssh.Channel, reqs <-chan *ssh.Request) {
	for req := range reqs {
		switch req.Type {
		case "exec":
			var payload struct{ Command string }
			_ = ssh.Unmarshal(req.Payload, &payload)
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			go runShellCommand(ctx, ch, payload.Command)
		case "shell":
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			go runShellCommand(ctx, ch, "/bin/sh")
		case "pty-req", "env":
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

func runShellCommand(ctx context.Context, ch ssh.Channel, command string) {
	defer ch.Close()
	c := exec.CommandContext(ctx, "/bin/sh", "-c", command)
	c.Stdin = ch
	c.Stdout = ch
	c.Stderr = ch.Stderr()
	_ = c.Run()
	_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
}

// startBusyExec launches a command that blocks on the server (no end-of-command
// marker until it returns), so the Exec holds the shell mutex. It returns a
// channel that receives the Exec result once the command is interrupted.
func startBusyExec(shell *sshrun.ShellSession) <-chan error {
	done := make(chan error, 1)
	go func() {
		_, err := shell.Exec(context.Background(), "sleep 30", shellExecTimeout)
		done <- err
	}()
	// Give the Exec time to take the shell mutex and dispatch the command; the
	// discriminating threshold below (10s) is far larger than this slack.
	time.Sleep(500 * time.Millisecond)
	return done
}

// TestKillMatchingInterruptsBusyShellSession pins #202: the kill switch must
// interrupt a session with a command in flight promptly, not wait out the
// 120s shell exec timeout.
func TestKillMatchingInterruptsBusyShellSession(t *testing.T) {
	conn, shell := newRealShellSession(t)
	m := newSessionManager(5*time.Minute, 30*time.Minute, nil)
	t.Cleanup(m.closeAll)

	s := &liveSession{
		id: "busy", caller: "alice", host: "test:22", mode: "shell",
		conn: conn, shell: shell, created: time.Now(), lastUsed: time.Now(),
	}
	if err := m.add(s); err != nil {
		t.Fatalf("add: %v", err)
	}
	execDone := startBusyExec(shell)

	start := time.Now()
	victims := m.killMatching(func(ls *liveSession) bool { return ls.caller == "alice" })
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("killMatching of a busy shell took %v; the transport was not torn down before the shell (#202)", elapsed)
	}
	if len(victims) != 1 {
		t.Fatalf("victims = %d, want 1", len(victims))
	}
	select {
	case err := <-execDone:
		if err == nil {
			t.Fatal("busy Exec returned nil error; expected interruption by the kill")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("busy Exec was not interrupted by killMatching")
	}
}

// TestCloseAllInterruptsBusyShellSession pins the shutdown half of #202: a busy
// session must not delay closeAll (which Engine.Close drives on SIGTERM), and
// the victims are closed outside the manager lock.
func TestCloseAllInterruptsBusyShellSession(t *testing.T) {
	conn, shell := newRealShellSession(t)
	m := newSessionManager(5*time.Minute, 30*time.Minute, nil)

	s := &liveSession{
		id: "busy", caller: "alice", host: "test:22", mode: "shell",
		conn: conn, shell: shell, created: time.Now(), lastUsed: time.Now(),
	}
	if err := m.add(s); err != nil {
		t.Fatalf("add: %v", err)
	}
	execDone := startBusyExec(shell)

	closed := make(chan struct{})
	go func() {
		m.closeAll()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(10 * time.Second):
		t.Fatal("closeAll did not return promptly with a busy session open (#202)")
	}
	select {
	case <-execDone:
	case <-time.After(10 * time.Second):
		t.Fatal("busy Exec was not interrupted by closeAll")
	}
}
