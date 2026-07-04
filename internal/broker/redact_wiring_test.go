package broker

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/luisgf/infrabroker/internal/redact"
)

// redactEngineConfig builds a minimal local-mode config (CA key + audit key in
// a temp dir) carrying the given redact config.
func redactEngineConfig(t *testing.T, rc *redact.Config) *Config {
	t.Helper()
	dir := t.TempDir()

	_, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	blk, err := ssh.MarshalPrivateKey(caPriv, "ca-test")
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(dir, "ca")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(blk), 0o600); err != nil {
		t.Fatal(err)
	}
	seedPath := filepath.Join(dir, "audit.seed")
	if err := os.WriteFile(seedPath, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	return &Config{
		CAKey:         caPath,
		AuditLog:      filepath.Join(dir, "audit.log"),
		AuditKey:      seedPath,
		SourceAddress: "127.0.0.1",
		MaxTTLSeconds: 120,
		Redact:        rc,
		Hosts: map[string]HostConfig{
			"web01": {Addr: "10.0.0.21:22", User: "deploy", Principal: "host:web01",
				HostKey: "ssh-ed25519 AAAAC3Nz"},
		},
	}
}

// TestNewEngineRedactWiring verifies that a "redact" config block reaches the
// engine's audit log: an entry written by the engine must be persisted with
// the secret masked.
func TestNewEngineRedactWiring(t *testing.T) {
	cfg := redactEngineConfig(t, &redact.Config{}) // empty block = defaults
	e, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer e.Close()
	if e.redactor == nil {
		t.Fatal("engine must hold the compiled redactor for session recorders")
	}

	// Unknown host: Execute audits a denial that carries the command verbatim.
	_, err = e.Execute(context.Background(), Caller{ID: "tester"}, "nope", "mysql --password=hunter2", 0, ExecOptions{})
	if err == nil {
		t.Fatal("unknown host must fail")
	}

	raw, err := os.ReadFile(cfg.AuditLog)
	if err != nil {
		t.Fatalf("reading audit log: %v", err)
	}
	if strings.Contains(string(raw), "hunter2") {
		t.Errorf("secret survived in the engine audit log: %s", raw)
	}
	if !strings.Contains(string(raw), "[REDACTED:flag-password]") {
		t.Errorf("redaction marker missing in the engine audit log: %s", raw)
	}
}

// TestNewEngineInvalidRedactPatternFailsClosed pins the fail-closed contract:
// an invalid redact pattern is a startup error, not a silently smaller rule set.
func TestNewEngineInvalidRedactPatternFailsClosed(t *testing.T) {
	cfg := redactEngineConfig(t, &redact.Config{Patterns: []redact.Pattern{{Name: "bad", Regex: "("}}})
	if _, err := NewEngine(cfg); err == nil {
		t.Fatal("NewEngine must fail on an invalid redact pattern")
	}
}
