package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// dialBound is the CI-safe upper bound for a Dial that must give up on a
// silent peer: far above the handshake timeouts used below, far below "hangs".
const dialBound = 5 * time.Second

// silentListener accepts TCP connections and never writes a byte (no SSH
// banner), like a wedged sshd or a tarpit. Each accepted conn is read until the
// client closes it; closed receives one value per conn the client closed, which
// proves Dial released the socket instead of leaking it.
func silentListener(t *testing.T) (addr string, closed <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	ch := make(chan struct{}, 16)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return // listener closed at test end
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(io.Discard, c) // returns when the client closes
				ch <- struct{}{}
			}()
		}
	}()
	return ln.Addr().String(), ch
}

// testSSHServer starts an in-process SSH server (no client auth required) that
// serves "exec" by sleeping execSleep then exiting 0, and forwards direct-tcpip
// channels so it can act as a bastion. It returns its address and host key.
func testSSHServer(t *testing.T, execSleep time.Duration) (string, ssh.PublicKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return // listener closed at test end
			}
			go serveTestConn(c, cfg, execSleep)
		}
	}()
	return ln.Addr().String(), hostSigner.PublicKey()
}

func serveTestConn(c net.Conn, cfg *ssh.ServerConfig, execSleep time.Duration) {
	sconn, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		_ = c.Close()
		return
	}
	defer sconn.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		switch nc.ChannelType() {
		case "session":
			ch, chReqs, err := nc.Accept()
			if err != nil {
				continue
			}
			go serveTestSession(ch, chReqs, execSleep)
		case "direct-tcpip":
			go forwardTestChannel(nc)
		default:
			_ = nc.Reject(ssh.UnknownChannelType, "unsupported")
		}
	}
}

func serveTestSession(ch ssh.Channel, reqs <-chan *ssh.Request, execSleep time.Duration) {
	for req := range reqs {
		if req.Type != "exec" {
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
			continue
		}
		if req.WantReply {
			_ = req.Reply(true, nil)
		}
		go func() {
			time.Sleep(execSleep)
			_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
			_ = ch.Close()
		}()
	}
}

func forwardTestChannel(nc ssh.NewChannel) {
	var p struct {
		Host     string
		Port     uint32
		OrigHost string
		OrigPort uint32
	}
	if err := ssh.Unmarshal(nc.ExtraData(), &p); err != nil {
		_ = nc.Reject(ssh.ConnectionFailed, "bad payload")
		return
	}
	dst, err := net.Dial("tcp", net.JoinHostPort(p.Host, strconv.Itoa(int(p.Port))))
	if err != nil {
		_ = nc.Reject(ssh.ConnectionFailed, err.Error())
		return
	}
	ch, reqs, err := nc.Accept()
	if err != nil {
		_ = dst.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	go func() {
		_, _ = io.Copy(dst, ch)
		_ = dst.Close()
	}()
	_, _ = io.Copy(ch, dst)
	_ = ch.Close()
}

// hopTo is testHop pointed at addr.
func hopTo(t *testing.T, addr string, hostKey ssh.PublicKey) Hop {
	t.Helper()
	h := testHop(t, hostKey)
	h.Addr = addr
	return h
}

// dialWithin runs Dial and fails the test if it does not return within
// dialBound (the pre-#810 behaviour was to block forever).
func dialWithin(ctx context.Context, t *testing.T, hops []Hop, timeout time.Duration) (*Conn, error) {
	t.Helper()
	type res struct {
		c   *Conn
		err error
	}
	done := make(chan res, 1)
	go func() {
		c, err := Dial(ctx, hops, timeout)
		done <- res{c, err}
	}()
	select {
	case r := <-done:
		return r.c, r.err
	case <-time.After(dialBound):
		t.Fatalf("Dial still blocked after %v: the SSH handshake is not bounded", dialBound)
		return nil, nil
	}
}

func waitClosed(t *testing.T, closed <-chan struct{}) {
	t.Helper()
	select {
	case <-closed:
	case <-time.After(dialBound):
		t.Fatal("the silent peer's connection was never closed: socket leaked")
	}
}

// TestDialHandshakeTimeoutDirect pins #810: a first hop that accepts TCP and
// never sends its banner must fail with a handshake timeout, not block forever,
// and the socket must be released.
func TestDialHandshakeTimeoutDirect(t *testing.T) {
	addr, closed := silentListener(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	c, err := dialWithin(ctx, t, []Hop{hopTo(t, addr, ed25519HostKey(t))}, 200*time.Millisecond)
	if err == nil {
		c.Close()
		t.Fatal("Dial to a silent peer succeeded")
	}
	if !strings.Contains(err.Error(), "handshake "+addr) || !strings.Contains(err.Error(), "timed out") {
		t.Errorf("err = %q, want a 'handshake %s: timed out' error", err, addr)
	}
	waitClosed(t, closed)
}

// TestDialHandshakeCtxDeadlineDirect: the request ctx's own deadline bounds the
// handshake even when the per-hop timeout is long.
func TestDialHandshakeCtxDeadlineDirect(t *testing.T) {
	addr, closed := silentListener(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	c, err := dialWithin(ctx, t, []Hop{hopTo(t, addr, ed25519HostKey(t))}, time.Minute)
	if err == nil {
		c.Close()
		t.Fatal("Dial to a silent peer succeeded")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %q, want it to wrap context.DeadlineExceeded", err)
	}
	waitClosed(t, closed)
}

// TestDialHandshakeTimeoutViaBastion: the same through a real bastion whose
// direct-tcpip channel reaches the silent listener. Channel conns do not honour
// deadlines, so the bound must come from closing the conn.
func TestDialHandshakeTimeoutViaBastion(t *testing.T) {
	silent, closed := silentListener(t)
	bastion, bastionKey := testSSHServer(t, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	hops := []Hop{hopTo(t, bastion, bastionKey), hopTo(t, silent, ed25519HostKey(t))}
	c, err := dialWithin(ctx, t, hops, time.Second)
	if err == nil {
		c.Close()
		t.Fatal("Dial to a silent target through a bastion succeeded")
	}
	if !strings.Contains(err.Error(), "handshake "+silent+" (via bastion)") || !strings.Contains(err.Error(), "timed out") {
		t.Errorf("err = %q, want a 'handshake %s (via bastion): timed out' error", err, silent)
	}
	waitClosed(t, closed)
}

// TestDialHandshakeCancel: cancelling ctx mid-handshake returns promptly with
// the cancellation error, for a direct hop and for one behind a bastion.
func TestDialHandshakeCancel(t *testing.T) {
	for _, viaBastion := range []bool{false, true} {
		t.Run("bastion="+strconv.FormatBool(viaBastion), func(t *testing.T) {
			silent, closed := silentListener(t)
			hops := []Hop{hopTo(t, silent, ed25519HostKey(t))}
			if viaBastion {
				bastion, bastionKey := testSSHServer(t, 0)
				hops = append([]Hop{hopTo(t, bastion, bastionKey)}, hops...)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			time.AfterFunc(300*time.Millisecond, cancel)

			c, err := dialWithin(ctx, t, hops, time.Minute)
			if err == nil {
				c.Close()
				t.Fatal("Dial to a silent peer succeeded")
			}
			if !errors.Is(err, context.Canceled) {
				t.Errorf("err = %q, want it to wrap context.Canceled", err)
			}
			waitClosed(t, closed)
		})
	}
}

// TestDialHandshakeBoundDoesNotOutliveDial: a normal handshake still works, and
// neither the per-hop timeout nor a later ctx cancellation tears down the
// established connection — a command running longer than the handshake
// timeout completes.
func TestDialHandshakeBoundDoesNotOutliveDial(t *testing.T) {
	const handshakeTimeout = 1500 * time.Millisecond
	const execSleep = 2500 * time.Millisecond // > handshakeTimeout
	for _, viaBastion := range []bool{false, true} {
		t.Run("bastion="+strconv.FormatBool(viaBastion), func(t *testing.T) {
			target, targetKey := testSSHServer(t, execSleep)
			hops := []Hop{hopTo(t, target, targetKey)}
			if viaBastion {
				bastion, bastionKey := testSSHServer(t, 0)
				hops = append([]Hop{hopTo(t, bastion, bastionKey)}, hops...)
			}
			dialCtx, cancelDial := context.WithCancel(context.Background())
			c, err := dialWithin(dialCtx, t, hops, handshakeTimeout)
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			defer c.Close()
			cancelDial() // the dial ctx ending must not reach the established conn

			res, err := ExecOnce(context.Background(), c.Client, "sleep")
			if err != nil {
				t.Fatalf("ExecOnce after the handshake timeout elapsed: %v", err)
			}
			if res.ExitCode != 0 {
				t.Errorf("exit code = %d, want 0", res.ExitCode)
			}
		})
	}
}
