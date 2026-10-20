package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/luisgf/infrabroker/internal/signer"
)

// writeSignerConfig writes a minimal, buildable signer.json (PEM CA key, one
// host, the given sign_rate_limit_per_min and reload_callers) and returns its
// path.
func writeSignerConfig(t *testing.T, signRate int, reloadCallers string) string {
	t.Helper()
	dir := t.TempDir()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := `{
  "ca_key": "` + caPath + `",
  "sign_rate_limit_per_min": ` + strconv.Itoa(signRate) + `,
  "reload_callers": [` + reloadCallers + `],
  "hosts": {
    "web01": {"addr": "10.0.0.1:22", "user": "deploy", "principal": "host:web01"}
  }
}
`
	cfgPath := filepath.Join(dir, "signer.json")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath
}

// TestMutateAllowSwapsWholeState pins #466: a policy mutation re-reads
// signer.json and rebuilds the full state from it, so it must apply EVERYTHING
// the file says — not only hosts/callers/admin tiers but also the sign rate
// limit (and the end-user verifier) that reload() swaps. With a file edited
// but not yet reloaded (sign_rate_limit_per_min 42 on disk, 7 in memory;
// "admin" in reload_callers on disk, none in memory), the mutation leaves
// memory equal to the file: no hybrid of new tables with the old limit.
func TestMutateAllowSwapsWholeState(t *testing.T) {
	t.Parallel()
	cfgPath := writeSignerConfig(t, 42, `"admin"`)
	srv := &server{
		cfgPath:     cfgPath,
		signRateMin: 7, // memory lags the file: operator edited it, no SIGHUP yet
		grants:      signer.NewGrantStore(),
	}

	n, err := srv.mutateAllow("web01", "^uptime$", true)
	if err != nil {
		t.Fatalf("mutateAllow: %v", err)
	}
	if n != 1 {
		t.Errorf("hosts = %d, want 1", n)
	}
	if got := srv.signRate(); got != 42 {
		t.Errorf("after a mutation signRate() = %d, want the file's 42 (the swap applied a hybrid state)", got)
	}
	srv.mu.RLock()
	_, admin := srv.reloadCN["admin"]
	_, hasHost := srv.hosts["web01"]
	srv.mu.RUnlock()
	if !admin || !hasHost {
		t.Errorf("reloadCN has admin=%v, hosts has web01=%v; want both true", admin, hasHost)
	}
	// And the file carries the mutation, so a later reload() agrees with memory.
	if m, err := srv.reload(); err != nil || m != 1 {
		t.Fatalf("reload after mutation: n=%d err=%v", m, err)
	}
	if got := srv.signRate(); got != 42 {
		t.Errorf("after reload signRate() = %d, want 42", got)
	}
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "^uptime$") {
		t.Errorf("config on disk lacks the added pattern:\n%s", raw)
	}
}

// TestReloadAndMutateShareSwapState: reload() installs the same set of fields
// as a mutation, through swapState, so the two paths cannot drift apart again.
func TestReloadAndMutateShareSwapState(t *testing.T) {
	t.Parallel()
	cfgPath := writeSignerConfig(t, 5, `"ops"`)
	srv := &server{cfgPath: cfgPath, signRateMin: 99, grants: signer.NewGrantStore()}
	if _, err := srv.reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := srv.signRate(); got != 5 {
		t.Fatalf("reload signRate() = %d, want 5", got)
	}
	// Edit the file behind the server's back, then mutate: memory must follow.
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(raw), `"sign_rate_limit_per_min": 5`, `"sign_rate_limit_per_min": 11`, 1)
	if edited == string(raw) {
		t.Fatal("test setup: rate limit not found in file")
	}
	if err := os.WriteFile(cfgPath, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.mutateAllow("web01", "^id$", true); err != nil {
		t.Fatalf("mutateAllow: %v", err)
	}
	if got := srv.signRate(); got != 11 {
		t.Errorf("after mutation signRate() = %d, want the file's 11", got)
	}
}
