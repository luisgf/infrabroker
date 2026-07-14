package initcmd

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/luisgf/infrabroker/internal/broker"
	"github.com/luisgf/infrabroker/internal/ca"
	"github.com/luisgf/infrabroker/internal/signer"
)

// TestGenerateProducesLoadableArtifacts is the core guarantee: `init` emits a PKI
// and configs that the real loaders accept, so `signer -config …` + `infrabroker
// serve-* -config …` boot against them.
func TestGenerateProducesLoadableArtifacts(t *testing.T) {
	dir := t.TempDir()
	if _, err := generate(dir, false); err != nil {
		t.Fatalf("generate: %v", err)
	}
	pki := filepath.Join(dir, "pki")

	// The broker config loads via the real exported loader (validates field names
	// and confcheck strictness) and is remote-mode (no CA key).
	bcfg, err := broker.LoadConfig(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatalf("broker.LoadConfig: %v", err)
	}
	if bcfg.Signer == nil || bcfg.Signer.URL != signerURL {
		t.Errorf("broker config signer block = %+v, want url %q", bcfg.Signer, signerURL)
	}
	if bcfg.CAKey != "" {
		t.Errorf("remote broker must hold no CA key, got %q", bcfg.CAKey)
	}

	// The SSH CA loads in the exact OpenSSH-PEM form internal/ca expects.
	caPEM, err := os.ReadFile(filepath.Join(pki, "ssh_ca"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.LoadCAFromPEM(caPEM); err != nil {
		t.Fatalf("ca.LoadCAFromPEM(ssh_ca): %v", err)
	}

	// Both mTLS leaf pairs load, and the broker client cert verifies against the
	// shared CA with the expected CN (which must equal the callers key).
	if _, err := tls.LoadX509KeyPair(filepath.Join(pki, "signer.crt"), filepath.Join(pki, "signer.key")); err != nil {
		t.Errorf("signer mTLS pair: %v", err)
	}
	brokerTLS, err := tls.LoadX509KeyPair(filepath.Join(pki, "broker.crt"), filepath.Join(pki, "broker.key"))
	if err != nil {
		t.Fatalf("broker mTLS pair: %v", err)
	}
	leaf, err := x509.ParseCertificate(brokerTLS.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != brokerCN {
		t.Errorf("broker cert CN = %q, want %q", leaf.Subject.CommonName, brokerCN)
	}
	caPool := x509.NewCertPool()
	caCrt, _ := os.ReadFile(filepath.Join(pki, "mtls_ca.crt"))
	if !caPool.AppendCertsFromPEM(caCrt) {
		t.Fatal("mtls_ca.crt not a valid CA PEM")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: caPool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Errorf("broker cert does not verify against mtls_ca: %v", err)
	}

	// Audit seeds are raw >= 32 bytes (ed25519 seed size).
	for _, s := range []string{"signer_audit.seed", "audit.seed"} {
		b, err := os.ReadFile(filepath.Join(pki, s))
		if err != nil {
			t.Fatal(err)
		}
		if len(b) < ed25519.SeedSize {
			t.Errorf("%s is %d bytes, want >= %d", s, len(b), ed25519.SeedSize)
		}
	}

	// The signer's hosts + default-deny policy compile through the real validator.
	var sc struct {
		Callers              map[string]signer.CallerPolicy  `json:"callers"`
		CommandPolicies      map[string]signer.CommandPolicy `json:"command_policies"`
		GroupCommandPolicies map[string][]string             `json:"group_command_policies"`
		Hosts                signer.PolicyTable              `json:"hosts"`
	}
	sb, _ := os.ReadFile(filepath.Join(dir, "signer.json"))
	if err := json.Unmarshal(sb, &sc); err != nil {
		t.Fatalf("unmarshal signer.json: %v", err)
	}
	if _, err := signer.CompileHostPolicies(sc.Hosts, sc.CommandPolicies, sc.GroupCommandPolicies); err != nil {
		t.Fatalf("signer.CompileHostPolicies on emitted signer.json: %v", err)
	}
	if g := sc.Callers[brokerCN].AllowedGroups; len(g) != 1 || g[0] != localGroup {
		t.Errorf("callers[%q].allowed_groups = %v, want [%q]", brokerCN, g, localGroup)
	}
}

// TestGenerateIsIdempotent: a second run without --force refuses; --force
// regenerates.
func TestGenerateIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	if _, err := generate(dir, false); err != nil {
		t.Fatalf("first generate: %v", err)
	}
	if _, err := generate(dir, false); err == nil {
		t.Fatal("second generate without --force must refuse to overwrite")
	}
	if _, err := generate(dir, true); err != nil {
		t.Fatalf("generate --force must overwrite: %v", err)
	}
}

// TestBuildSignerJSONHostInvariant: when a starter host is present, its group
// intersects the broker caller's allowed_groups (or default-deny hides it).
func TestBuildSignerJSONHostInvariant(t *testing.T) {
	s := buildSignerJSON(&starterHost{name: "localhost", addr: "127.0.0.1:22", user: "deploy", hostKey: "ssh-ed25519 AAAA"})
	h, ok := s.Hosts["localhost"]
	if !ok {
		t.Fatal("starter host not written")
	}
	if h.Principal != "host:localhost" {
		t.Errorf("principal = %q, want host:localhost", h.Principal)
	}
	callerGroups := s.Callers[brokerCN].AllowedGroups
	if !intersects(h.Groups, callerGroups) {
		t.Errorf("host groups %v do not intersect caller groups %v — default-deny would hide the host", h.Groups, callerGroups)
	}
}

func intersects(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}
