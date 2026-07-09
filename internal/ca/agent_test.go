package ca

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// serveKeyring serves an in-memory ssh-agent (keyring) over a unix socket,
// standing in for a real ssh-agent / hardware token backing the CA key.
func serveKeyring(t *testing.T, keyring agent.Agent) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "agent.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = agent.ServeAgent(keyring, conn) }()
		}
	}()
	return sock
}

func writePub(t *testing.T, pub ssh.PublicKey) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ca.pub")
	if err := os.WriteFile(p, ssh.MarshalAuthorizedKey(pub), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestAgentCASignsCert: an Ed25519 CA key held in an ssh-agent signs a real
// certificate through the production BuildAndSign path, and the cert verifies
// against the agent-held CA. This is the Ed25519-in-agent case AKV cannot do.
func TestAgentCASignsCert(t *testing.T) {
	t.Parallel()
	caPub, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshCAPub, err := ssh.NewPublicKey(caPub)
	if err != nil {
		t.Fatal(err)
	}
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: &caPriv}); err != nil {
		t.Fatalf("keyring add: %v", err)
	}
	sock := serveKeyring(t, keyring)
	pubPath := writePub(t, sshCAPub)

	caSigner, err := LoadCA(context.Background(), CAKeyConfig{Type: "agent", Socket: sock, PublicKeyPath: pubPath})
	if err != nil {
		t.Fatalf("LoadCA(agent): %v", err)
	}
	if !bytes.Equal(caSigner.PublicKey().Marshal(), sshCAPub.Marshal()) {
		t.Fatal("loaded signer's public key does not match the pinned CA key")
	}

	userEdPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	userPub, err := ssh.NewPublicKey(userEdPub)
	if err != nil {
		t.Fatal(err)
	}
	cert, _, err := BuildAndSign(context.Background(), caSigner, userPub,
		Constraints{Principal: "host:lab", TTL: time.Minute, KeyID: "k"})
	if err != nil {
		t.Fatalf("BuildAndSign with agent CA: %v", err)
	}

	checker := &ssh.CertChecker{IsUserAuthority: func(a ssh.PublicKey) bool {
		return bytes.Equal(a.Marshal(), sshCAPub.Marshal())
	}}
	if err := checker.CheckCert("host:lab", cert); err != nil {
		t.Errorf("cert signed by the agent CA failed verification: %v", err)
	}
}

// TestAgentCAFailFast: LoadCA reports a misconfigured agent backend at startup.
func TestAgentCAFailFast(t *testing.T) {
	caPub, _, _ := ed25519.GenerateKey(rand.Reader)
	sshCAPub, _ := ssh.NewPublicKey(caPub)
	pubPath := writePub(t, sshCAPub)
	sock := serveKeyring(t, agent.NewKeyring()) // empty agent

	// Pinned key absent from the agent.
	if _, err := LoadCA(context.Background(), CAKeyConfig{Type: "agent", Socket: sock, PublicKeyPath: pubPath}); err == nil {
		t.Error("LoadCA must fail when the pinned key is absent from the agent")
	}
	// Missing public_key_path.
	if _, err := LoadCA(context.Background(), CAKeyConfig{Type: "agent", Socket: sock}); err == nil {
		t.Error("LoadCA must fail without public_key_path")
	}
	// No socket and no SSH_AUTH_SOCK.
	t.Setenv("SSH_AUTH_SOCK", "")
	if _, err := LoadCA(context.Background(), CAKeyConfig{Type: "agent", PublicKeyPath: pubPath}); err == nil {
		t.Error("LoadCA must fail without a socket")
	}
}
