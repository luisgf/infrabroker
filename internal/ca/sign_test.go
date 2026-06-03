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

// TestBuildAndSignConstraints verifica que el cert lleva las opciones críticas y
// extensiones esperadas, ventana de validez correcta y serial no nulo.
func TestBuildAndSignConstraints(t *testing.T) {
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
		t.Error("no debería tener permit-port-forwarding sin AllowPortForwarding")
	}
	if cert.ValidPrincipals[0] != "host:web01" {
		t.Errorf("principals = %v", cert.ValidPrincipals)
	}
	if serial == 0 || cert.Serial != serial {
		t.Errorf("serial inconsistente: %d vs %d", serial, cert.Serial)
	}
	window := time.Duration(cert.ValidBefore-cert.ValidAfter) * time.Second
	if window < 2*time.Minute || window > 3*time.Minute {
		t.Errorf("ventana = %s", window)
	}
}

func TestBuildAndSignBastionForwarding(t *testing.T) {
	caKey := newTestCAKey(t)
	_, pub, _ := GenerateEphemeralKey()
	cert, _, err := BuildAndSign(caKey, pub, Constraints{
		Principal: "host:bastion", TTL: time.Minute, AllowPortForwarding: true, KeyID: "b",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cert.Permissions.Extensions["permit-port-forwarding"]; !ok {
		t.Error("falta permit-port-forwarding en hop bastión")
	}
}

func TestBuildAndSignRejectsBadTTL(t *testing.T) {
	caKey := newTestCAKey(t)
	_, pub, _ := GenerateEphemeralKey()
	if _, _, err := BuildAndSign(caKey, pub, Constraints{Principal: "host:x", TTL: time.Hour}); err == nil {
		t.Error("esperaba error por TTL > 15m")
	}
	if _, _, err := BuildAndSign(caKey, pub, Constraints{Principal: "", TTL: time.Minute}); err == nil {
		t.Error("esperaba error por principal vacío")
	}
}

// TestVerifyAgainstCA confirma que el cert valida con el mismo checker que sshd.
func TestVerifyAgainstCA(t *testing.T) {
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
		t.Error("esperaba fallo para principal no autorizado")
	}
}
