package ca

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func newTestCAKey(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestBuildAndSignConstraints verifies that the cert carries the expected
// critical options and extensions, a correct validity window, and a non-zero serial.
func TestBuildAndSignConstraints(t *testing.T) {
	t.Parallel()
	caKey := newTestCAKey(t)
	_, pub, err := GenerateEphemeralKey()
	if err != nil {
		t.Fatal(err)
	}
	cert, serial, err := BuildAndSign(caKey, pub, Constraints{
		Principal: "host:web01", TTL: 2 * time.Minute, SourceAddress: "10.0.0.1",
		ForceCommand: "uptime", KeyID: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := cert.Permissions.CriticalOptions["source-address"]; got != "10.0.0.1" {
		t.Errorf("source-address = %q", got)
	}
	if got := cert.Permissions.CriticalOptions["force-command"]; got != "uptime" {
		t.Errorf("force-command = %q", got)
	}
	if _, ok := cert.Permissions.Extensions["permit-port-forwarding"]; ok {
		t.Error("must not have permit-port-forwarding without AllowPortForwarding")
	}
	if cert.ValidPrincipals[0] != "host:web01" {
		t.Errorf("principals = %v", cert.ValidPrincipals)
	}
	if serial == 0 || cert.Serial != serial {
		t.Errorf("inconsistent serial: %d vs %d", serial, cert.Serial)
	}
	window := time.Duration(cert.ValidBefore-cert.ValidAfter) * time.Second
	if window < 2*time.Minute || window > 3*time.Minute {
		t.Errorf("validity window = %s", window)
	}
}

func TestBuildAndSignBastionForwarding(t *testing.T) {
	t.Parallel()
	caKey := newTestCAKey(t)
	_, pub, _ := GenerateEphemeralKey()
	cert, _, err := BuildAndSign(caKey, pub, Constraints{
		Principal: "host:bastion", TTL: time.Minute, AllowPortForwarding: true, KeyID: "b",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cert.Permissions.Extensions["permit-port-forwarding"]; !ok {
		t.Error("missing permit-port-forwarding on bastion hop")
	}
}

func TestBuildAndSignRejectsBadTTL(t *testing.T) {
	t.Parallel()
	caKey := newTestCAKey(t)
	_, pub, _ := GenerateEphemeralKey()
	if _, _, err := BuildAndSign(caKey, pub, Constraints{Principal: "host:x", TTL: time.Hour}); err == nil {
		t.Error("expected error for TTL > 15m")
	}
	if _, _, err := BuildAndSign(caKey, pub, Constraints{Principal: "", TTL: time.Minute}); err == nil {
		t.Error("expected error for empty principal")
	}
}

// TestVerifyAgainstCA confirms that the cert validates with the same checker
// that sshd would use.
func TestVerifyAgainstCA(t *testing.T) {
	t.Parallel()
	caKey := newTestCAKey(t)
	_, pub, _ := GenerateEphemeralKey()
	cert, _, err := BuildAndSign(caKey, pub, Constraints{Principal: "host:lab", TTL: time.Minute, KeyID: "k"})
	if err != nil {
		t.Fatal(err)
	}
	checker := &ssh.CertChecker{IsUserAuthority: func(a ssh.PublicKey) bool {
		return string(a.Marshal()) == string(caKey.PublicKey().Marshal())
	}}
	if err := checker.CheckCert("host:lab", cert); err != nil {
		t.Errorf("CheckCert: %v", err)
	}
	if err := checker.CheckCert("host:otro", cert); err == nil {
		t.Error("expected failure for unauthorised principal")
	}
}
