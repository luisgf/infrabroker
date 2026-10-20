package broker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	sshrun "github.com/luisgf/infrabroker/internal/ssh"
)

// transferTestEngine builds an engine sufficient for the validation paths that
// fail before any signing or connection is attempted.
func transferTestEngine(maxBytes int) *Engine {
	return &Engine{cfg: &Config{FileTransferMaxBytes: maxBytes}}
}

func TestFileTransferMaxBytesDefault(t *testing.T) {
	t.Parallel()
	if got := transferTestEngine(0).FileTransferMaxBytes(); got != DefaultFileTransferMaxBytes {
		t.Errorf("default cap = %d, want %d", got, DefaultFileTransferMaxBytes)
	}
	if got := transferTestEngine(1024).FileTransferMaxBytes(); got != 1024 {
		t.Errorf("configured cap = %d, want 1024", got)
	}
}

// TestNewEngineRejectsFileTransferMaxBytesAboveOutputCap pins #580: a
// file_transfer_max_bytes above the SSH per-stream output cap (minus the
// truncation marker) is refused at load with an error naming the field and the
// ceiling, before any signer, CA or audit log is touched; the ceiling itself
// and the default pass the check.
func TestNewEngineRejectsFileTransferMaxBytesAboveOutputCap(t *testing.T) {
	t.Parallel()
	if MaxFileTransferMaxBytes != 10*1024*1024-sshrun.TruncationMarkerLen || MaxFileTransferMaxBytes >= sshrun.MaxOutputBytes {
		t.Fatalf("MaxFileTransferMaxBytes = %d, want the %d-byte cap minus the %d-byte marker", MaxFileTransferMaxBytes, sshrun.MaxOutputBytes, sshrun.TruncationMarkerLen)
	}
	// The number quoted in the FileTransferMaxBytes field comment (and so in
	// docs/reference/config.md) and in docs/USAGE.md §9.
	if MaxFileTransferMaxBytes != 10485706 {
		t.Fatalf("MaxFileTransferMaxBytes = %d; update the documented ceiling (10485706)", MaxFileTransferMaxBytes)
	}
	_, err := NewEngine(&Config{FileTransferMaxBytes: 20 * 1024 * 1024})
	if err == nil {
		t.Fatal("file_transfer_max_bytes of 20 MiB must be rejected at load")
	}
	if !strings.Contains(err.Error(), "file_transfer_max_bytes") || !strings.Contains(err.Error(), strconv.Itoa(MaxFileTransferMaxBytes)) {
		t.Errorf("error should name the field and the ceiling, got: %v", err)
	}
	_, err = NewEngine(&Config{FileTransferMaxBytes: MaxFileTransferMaxBytes + 1})
	if err == nil || !strings.Contains(err.Error(), "file_transfer_max_bytes") {
		t.Errorf("one byte above the ceiling must be rejected, got: %v", err)
	}
	for _, ok := range []int{0, DefaultFileTransferMaxBytes, MaxFileTransferMaxBytes} {
		if err := validateFileTransferMaxBytes(&Config{FileTransferMaxBytes: ok}); err != nil {
			t.Errorf("file_transfer_max_bytes %d must be accepted: %v", ok, err)
		}
	}
}

func TestPutFileValidation(t *testing.T) {
	t.Parallel()
	e := transferTestEngine(8)
	c := Caller{ID: "test"}

	for name, tc := range map[string]struct {
		path, mode string
		content    []byte
		wantSubstr string
	}{
		"empty path":      {path: "", content: []byte("x"), wantSubstr: "path is required"},
		"null byte":       {path: "/tmp/\x00f", content: []byte("x"), wantSubstr: "null bytes"},
		"newline in path": {path: "/tmp/a\nb", content: []byte("x"), wantSubstr: "newline"},
		// #331: spaces would splice forged key=value tokens into the audit Command.
		"space in path":    {path: "/tmp/x bytes=0 sha256=00", content: []byte("x"), wantSubstr: "whitespace or control"},
		"tab in path":      {path: "/tmp/a\tb", content: []byte("x"), wantSubstr: "whitespace or control"},
		"oversized":        {path: "/tmp/f", content: bytes.Repeat([]byte("a"), 9), wantSubstr: "transfer limit is 8"},
		"bad mode":         {path: "/tmp/f", mode: "rwx", content: []byte("x"), wantSubstr: "invalid mode"},
		"mode with prefix": {path: "/tmp/f", mode: "u+x", content: []byte("x"), wantSubstr: "invalid mode"},
	} {
		_, err := e.PutFile(context.Background(), c, "web01", tc.path, tc.content, tc.mode, 0)
		if err == nil || !strings.Contains(err.Error(), tc.wantSubstr) {
			t.Errorf("%s: err = %v, want substring %q", name, err, tc.wantSubstr)
		}
		if !errors.Is(err, ErrBadRequest) {
			t.Errorf("%s: err must wrap ErrBadRequest, got %v", name, err)
		}
	}
}

func TestGetFileValidation(t *testing.T) {
	t.Parallel()
	e := transferTestEngine(8)
	_, err := e.GetFile(context.Background(), Caller{ID: "test"}, "web01", "", 0, 0)
	if err == nil || !errors.Is(err, ErrBadRequest) {
		t.Errorf("empty path must be ErrBadRequest, got %v", err)
	}
}

// failingExecHost starts an in-process SSH server (no client auth) whose every
// exec request writes stderr to the channel and exits with status 1, and
// returns its address plus the authorized_keys-style host key to pin.
func failingExecHost(t *testing.T, stderr string) (addr, hostKey string) {
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
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				sconn, chans, reqs, err := ssh.NewServerConn(nc, cfg)
				if err != nil {
					_ = nc.Close()
					return
				}
				defer sconn.Close()
				go ssh.DiscardRequests(reqs)
				for newCh := range chans {
					ch, chReqs, err := newCh.Accept()
					if err != nil {
						continue
					}
					go func() {
						for req := range chReqs {
							if req.WantReply {
								_ = req.Reply(true, nil)
							}
							if req.Type == "exec" {
								_, _ = ch.Stderr().Write([]byte(stderr))
								_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{1}))
								_ = ch.Close()
							}
						}
					}()
				}
			}()
		}
	}()
	return ln.Addr().String(), strings.TrimSpace(string(ssh.MarshalAuthorizedKey(hostSigner.PublicKey())))
}

// TestFileTransferRemoteFailureIsErrRemoteCommand pins #644: a non-zero exit of
// the remote cat/head behind PutFile / GetFile is an ErrRemoteCommand carrying
// the exit code and the remote stderr (not an ErrUpstream, which the frontends
// mask), so the agent can tell "Permission denied" from an outage.
func TestFileTransferRemoteFailureIsErrRemoteCommand(t *testing.T) {
	const remoteErr = "cat: /srv/app/x: Permission denied"
	addr, hostKey := failingExecHost(t, remoteErr+"\n")
	cfg := redactEngineConfig(t, nil)
	cfg.Hosts = map[string]HostConfig{
		"web01": {Addr: addr, User: "deploy", Principal: "host:web01", HostKey: hostKey, AllowFileTransfer: true},
	}
	e, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer e.Close()

	check := func(op string, err error) {
		t.Helper()
		if !errors.Is(err, ErrRemoteCommand) {
			t.Fatalf("%s: want ErrRemoteCommand, got %v", op, err)
		}
		if errors.Is(err, ErrUpstream) {
			t.Errorf("%s: a remote command failure must not be an ErrUpstream: %v", op, err)
		}
		if !strings.Contains(err.Error(), remoteErr) || !strings.Contains(err.Error(), "exit 1") {
			t.Errorf("%s: error must carry the exit code and remote stderr, got %q", op, err.Error())
		}
	}
	_, err = e.PutFile(context.Background(), Caller{ID: "alice"}, "web01", "/srv/app/x", []byte("data"), "", 0)
	check("PutFile", err)
	_, err = e.GetFile(context.Background(), Caller{ID: "alice"}, "web01", "/srv/app/x", 0, 0)
	check("GetFile", err)
}
