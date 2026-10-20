package mcpserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/crypto/ssh"

	"github.com/luisgf/infrabroker/internal/broker"
)

// serveTestShellHost starts an in-process SSH server (no client auth) that
// runs every exec/shell request through /bin/sh, and returns its address and
// the matching authorized_keys-style host key to pin in HostConfig.
func serveTestShellHost(t *testing.T) (addr, hostKey string) {
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
					if newCh.ChannelType() != "session" {
						_ = newCh.Reject(ssh.UnknownChannelType, "session only")
						continue
					}
					ch, chReqs, err := newCh.Accept()
					if err != nil {
						continue
					}
					go func() {
						for req := range chReqs {
							switch req.Type {
							case "exec", "shell":
								command := "/bin/sh"
								if req.Type == "exec" {
									var p struct{ Command string }
									_ = ssh.Unmarshal(req.Payload, &p)
									command = p.Command
								}
								if req.WantReply {
									_ = req.Reply(true, nil)
								}
								go func() {
									defer ch.Close()
									c := exec.Command("/bin/sh", "-c", command)
									c.Stdin = ch
									c.Stdout = ch
									c.Stderr = ch.Stderr()
									_ = c.Run()
								}()
							default:
								if req.WantReply {
									_ = req.Reply(true, nil)
								}
							}
						}
					}()
				}
			}()
		}
	}()
	return ln.Addr().String(), strings.TrimSpace(string(ssh.MarshalAuthorizedKey(hostSigner.PublicKey())))
}

// TestSessionOpenRecordingFailureMasked pins #645: with session_recording_strict
// and an unwritable session_recording_dir, ssh_session_open fails after the
// shell is up, and the recorder's "open <dir>/<id>.cast: ..." text must not
// reach the model; it gets the generic upstream message (the audit record
// carries the detail).
func TestSessionOpenRecordingFailureMasked(t *testing.T) {
	t.Parallel()
	addr, hostKey := serveTestShellHost(t)

	// A regular file used as the recording directory makes recording.Open fail.
	notADir := filepath.Join(t.TempDir(), "recdir-is-a-file")
	if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	eng := newTestEngineWith(t, map[string]broker.HostConfig{
		"web": {Addr: addr, User: "deploy", Principal: "host:web", HostKey: hostKey},
	}, func(c *broker.Config) {
		c.SessionRecordingDir = notADir
		c.SessionRecordingStrict = true
	})
	sess := sshTestSession(t, eng)

	res, err := sess.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "ssh_session_open", Arguments: map[string]any{"server": "web", "mode": "shell"},
	})
	if err != nil {
		t.Fatalf("CallTool transport error: %v", err)
	}
	if !res.IsError {
		t.Fatalf("expected a tool error, got success: %s", k8sToolText(t, res))
	}
	text := k8sToolText(t, res)
	if text != upstreamToolMessage {
		t.Errorf("strict recording-open failure = %q, want the generic %q", text, upstreamToolMessage)
	}
	if strings.Contains(text, notADir) || strings.Contains(text, ".cast") {
		t.Errorf("recording path must not reach the model, got %q", text)
	}
}
