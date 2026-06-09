package ca

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

// writePEMKey is a test helper that writes an Ed25519 private key to a
// temporary file in OpenSSH PEM format and returns the path.
func writePEMKey(t *testing.T, dir, name string) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if werr := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); werr != nil {
		t.Fatal(werr)
	}
	return path
}

// TestLoadCAFromPEMType verifies that LoadCA with type "pem" and a valid PEM
// file produces a usable ssh.Signer.
func TestLoadCAFromPEMType(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := writePEMKey(t, dir, "ca.pem")

	s, err := LoadCA(context.Background(), CAKeyConfig{Type: "pem", Path: path})
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	if s == nil {
		t.Fatal("expected non-nil signer")
	}
}

// TestLoadCAUnknownType verifies that an unknown type returns an error.
func TestLoadCAUnknownType(t *testing.T) {
	t.Parallel()
	_, err := LoadCA(context.Background(), CAKeyConfig{Type: "gcp-kms"})
	if err == nil {
		t.Fatal("expected error for unknown type")
	}
}

// TestLoadCAPEMPathRequired verifies that an empty path returns an error.
func TestLoadCAPEMPathRequired(t *testing.T) {
	t.Parallel()
	_, err := LoadCA(context.Background(), CAKeyConfig{Type: "pem", Path: ""})
	if err == nil {
		t.Fatal("expected error for empty path")
	}
}

// TestLoadCAPEMInvalidPath verifies that a non-existent path returns an error.
func TestLoadCAPEMInvalidPath(t *testing.T) {
	t.Parallel()
	_, err := LoadCA(context.Background(), CAKeyConfig{Type: "pem", Path: "/nonexistent/ca.pem"})
	if err == nil {
		t.Fatal("expected error for non-existent path")
	}
}

// TestLoadCAAKVMissingVaultURL verifies that AKV config without vault_url fails.
func TestLoadCAAKVMissingVaultURL(t *testing.T) {
	t.Parallel()
	_, err := LoadCA(context.Background(), CAKeyConfig{Type: "akv", KeyName: "my-key"})
	if err == nil {
		t.Fatal("expected error for missing vault_url")
	}
}

// TestLoadCAAKVMissingKeyName verifies that AKV config without key_name fails.
func TestLoadCAAKVMissingKeyName(t *testing.T) {
	t.Parallel()
	_, err := LoadCA(context.Background(), CAKeyConfig{Type: "akv", VaultURL: "https://vault.azure.net"})
	if err == nil {
		t.Fatal("expected error for missing key_name")
	}
}

// TestLoadGroupCAsDefaults verifies LoadGroupCAs with only a legacy ca_key.
func TestLoadGroupCAsDefaults(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := writePEMKey(t, dir, "ca.pem")

	def, groups, err := LoadGroupCAs(context.Background(), path, nil)
	if err != nil {
		t.Fatalf("LoadGroupCAs: %v", err)
	}
	if def == nil {
		t.Fatal("expected non-nil default CA")
	}
	if groups != nil {
		t.Fatalf("expected nil groupCAs, got %v", groups)
	}
}

// TestLoadGroupCAsWithGroupOverride verifies LoadGroupCAs with a per-group CA.
func TestLoadGroupCAsWithGroupOverride(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	defPath := writePEMKey(t, dir, "default.pem")
	grpPath := writePEMKey(t, dir, "prod-web.pem")

	def, groups, err := LoadGroupCAs(context.Background(), defPath, map[string]CAKeyConfig{
		"prod-web": {Type: "pem", Path: grpPath},
	})
	if err != nil {
		t.Fatalf("LoadGroupCAs: %v", err)
	}
	if def == nil {
		t.Fatal("expected non-nil default CA")
	}
	if len(groups) != 1 {
		t.Fatalf("expected 1 group CA, got %d", len(groups))
	}
	if groups["prod-web"] == nil {
		t.Fatal("expected non-nil CA for prod-web")
	}
}

// TestLoadGroupCAsDefaultKeyInCAKeys verifies that ca_keys["_default"] wins
// over the legacy ca_key string.
func TestLoadGroupCAsDefaultKeyInCAKeys(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	legacyPath := writePEMKey(t, dir, "legacy.pem")
	overridePath := writePEMKey(t, dir, "override.pem")

	// Load the override CA directly so we can compare public keys.
	overrideCA, err := LoadCA(context.Background(), CAKeyConfig{Type: "pem", Path: overridePath})
	if err != nil {
		t.Fatal(err)
	}

	def, _, err := LoadGroupCAs(context.Background(), legacyPath, map[string]CAKeyConfig{
		"_default": {Type: "pem", Path: overridePath},
	})
	if err != nil {
		t.Fatalf("LoadGroupCAs: %v", err)
	}
	if def == nil {
		t.Fatal("expected non-nil default CA")
	}
	// The default CA must be the override, not the legacy one.
	if string(def.PublicKey().Marshal()) != string(overrideCA.PublicKey().Marshal()) {
		t.Error("expected _default to override legacy ca_key")
	}
}

// TestLoadGroupCAsNoCAKey verifies that missing ca_key and no _default fails.
func TestLoadGroupCAsNoCAKey(t *testing.T) {
	t.Parallel()
	_, _, err := LoadGroupCAs(context.Background(), "", nil)
	if err == nil {
		t.Fatal("expected error when no CA is configured")
	}
}
