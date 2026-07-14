package initcmd

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"
)

// certValidity is the lifetime of every generated mTLS certificate. Long, because
// this is a local dev/lab PKI a human regenerates with `infrabroker init --force`,
// not a rotating production CA.
const certValidity = 10 * 365 * 24 * time.Hour

// brokerCN is the broker client-certificate CN. It MUST equal the key used for
// the broker in the signer's `callers` table (config.go), or default-deny hides
// every host from the broker.
const brokerCN = "broker-local"

// generatePKI writes the full local PKI into pkiDir: the SSH CA (that signs host
// certificates), the shared mTLS CA and the signer/broker leaf certs for the
// broker↔signer link, and the two per-service audit seeds. All pure Go — no
// ssh-keygen/openssl.
func generatePKI(pkiDir string) error {
	if err := generateSSHCA(pkiDir); err != nil {
		return fmt.Errorf("ssh ca: %w", err)
	}
	if err := generateMTLS(pkiDir); err != nil {
		return fmt.Errorf("mtls: %w", err)
	}
	for _, seed := range []string{"signer_audit.seed", "audit.seed"} {
		if err := generateAuditSeed(filepath.Join(pkiDir, seed)); err != nil {
			return fmt.Errorf("audit seed %s: %w", seed, err)
		}
	}
	return nil
}

// generateSSHCA writes the SSH certificate authority: ssh_ca (Ed25519 private key
// in OpenSSH PEM, the format internal/ca's "pem" backend loads via
// ssh.ParsePrivateKey) and ssh_ca.pub (the authorized_keys line for the managed
// hosts' TrustedUserCAKeys).
func generateSSHCA(pkiDir string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	block, err := ssh.MarshalPrivateKey(priv, "infrabroker-ssh-ca")
	if err != nil {
		return err
	}
	if err := writeSecret(filepath.Join(pkiDir, "ssh_ca"), pem.EncodeToMemory(block)); err != nil {
		return err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return err
	}
	return writePublic(filepath.Join(pkiDir, "ssh_ca.pub"), ssh.MarshalAuthorizedKey(sshPub))
}

// generateMTLS writes one shared mTLS CA and two leaf certs off it: the signer's
// server cert (CN=localhost, SAN localhost/127.0.0.1) and the broker's client
// cert (CN=broker-local). One CA signs both, so it is the signer's client_ca AND
// the broker's signer.ca — matching the shipped pki/ layout.
func generateMTLS(pkiDir string) error {
	caCert, caKey, err := makeCA("infrabroker local mTLS CA")
	if err != nil {
		return err
	}
	if err := writeCert(filepath.Join(pkiDir, "mtls_ca.crt"), caCert.Raw); err != nil {
		return err
	}
	if err := writeKey(filepath.Join(pkiDir, "mtls_ca.key"), caKey); err != nil {
		return err
	}

	// Signer server cert: verified by the broker against mtls_ca; needs SANs.
	if err := makeLeaf(pkiDir, "signer", "localhost", x509.ExtKeyUsageServerAuth,
		[]string{"localhost"}, []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}, caCert, caKey); err != nil {
		return err
	}
	// Broker client cert: its CN is the audit/RBAC identity (must be in callers).
	return makeLeaf(pkiDir, "broker", brokerCN, x509.ExtKeyUsageClientAuth, nil, nil, caCert, caKey)
}

// makeCA creates a self-signed Ed25519 CA certificate and its private key.
func makeCA(cn string) (*x509.Certificate, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(certValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, priv, nil
}

// makeLeaf creates a leaf cert (CN, EKU, optional SANs) signed by the CA, and
// writes <name>.crt / <name>.key into pkiDir.
func makeLeaf(pkiDir, name, cn string, eku x509.ExtKeyUsage, dns []string, ips []net.IP, ca *x509.Certificate, caKey ed25519.PrivateKey) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(certValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{eku},
		DNSNames:     dns,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, pub, caKey)
	if err != nil {
		return err
	}
	if err := writeCert(filepath.Join(pkiDir, name+".crt"), der); err != nil {
		return err
	}
	return writeKey(filepath.Join(pkiDir, name+".key"), priv)
}

// generateAuditSeed writes 32 random bytes (raw, not encoded): the audit log's
// Ed25519 signing seed. engine.go requires >= ed25519.SeedSize (32).
func generateAuditSeed(path string) error {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return err
	}
	return writeSecret(path, seed)
}

func serial() *big.Int {
	// 128-bit random serial (RFC 5280 §4.1.2.2: positive, <= 20 octets).
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		// crypto/rand should not fail; a fixed serial is acceptable for a local CA.
		return big.NewInt(time.Now().UnixNano())
	}
	return n
}

// writeCert / writeKey / writeSecret / writePublic centralise the file modes:
// certs and public keys are world-readable metadata, private keys and seeds are
// 0600.
func writeCert(path string, der []byte) error {
	return writePublic(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func writeKey(path string, key ed25519.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	return writeSecret(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func writeSecret(path string, data []byte) error { return os.WriteFile(path, data, 0o600) }
func writePublic(path string, data []byte) error { return os.WriteFile(path, data, 0o644) }
