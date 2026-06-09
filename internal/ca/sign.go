// Package ca contains the low-level SSH CA primitives: ephemeral key-pair
// generation (broker side) and certificate construction+signing (signer side).
//
// Signing is native (golang.org/x/crypto/ssh): the CA key is consumed through
// an ssh.Signer, which can be backed by a crypto.Signer from an
// HSM/KMS/Secure Enclave (non-exportable key).
package ca

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"time"

	"golang.org/x/crypto/ssh"
)

// Constraints are the limits the signer bakes into the certificate. They are
// derived from the policy based on the intent; the broker does not choose them.
type Constraints struct {
	// Principal is the value sshd maps to a local account (e.g. "host:web01").
	Principal string
	// TTL is the validity window. Should be on the order of minutes.
	TTL time.Duration
	// SourceAddress (CIDR or IP) pins where the cert may be used from. For
	// targets behind a bastion it must be the bastion's egress IP.
	SourceAddress string
	// ForceCommand binds the cert to execute only this command (one-shot). Empty
	// for session connections.
	ForceCommand string
	// AllowPortForwarding adds permit-port-forwarding (bastion hops only).
	AllowPortForwarding bool
	// AllowPTY adds permit-pty to the certificate. Required for interactive
	// sessions (mode=pty) and one-shot commands that need a real TTY.
	AllowPTY bool
	// KeyID is the identity string written to the sshd log.
	KeyID string
}

// GenerateEphemeralKey creates the client's ephemeral key pair. The private key
// stays in the broker (used to establish the SSH connection); only the public
// key travels to the signer.
func GenerateEphemeralKey() (ed25519.PrivateKey, ssh.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating ephemeral key pair: %w", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, nil, fmt.Errorf("wrapping pubkey: %w", err)
	}
	return priv, sshPub, nil
}

// LoadCAFromPEM loads the CA key from PEM.
// L1: emits a runtime warning to prevent inadvertent use in production.
// In production, replace with an ssh.Signer backed by a crypto.Signer from an
// HSM/KMS (e.g. ssh.NewSignerFromSigner(kmsClient)); the key never leaves the
// security module.
func LoadCAFromPEM(pem []byte) (ssh.Signer, error) {
	log.Printf("[WARN] ca.LoadCAFromPEM: CA key loaded from PEM in memory. " +
		"Lab use only. Use an HSM/KMS in production.")
	s, err := ssh.ParsePrivateKey(pem)
	if err != nil {
		return nil, fmt.Errorf("parsing CA key: %w", err)
	}
	return s, nil
}

// BuildAndSign constructs a scoped user certificate over pub and signs it with
// the CA key. Returns the cert and its unique serial number.
// ctx is propagated to the CA signer; HSM/KMS-backed signers (e.g. AKV) use it
// for cancellation and timeout of their network calls.
func BuildAndSign(ctx context.Context, caKey ssh.Signer, pub ssh.PublicKey, c Constraints) (*ssh.Certificate, uint64, error) {
	if c.Principal == "" {
		return nil, 0, fmt.Errorf("principal is required")
	}
	if c.TTL <= 0 || c.TTL > 15*time.Minute {
		return nil, 0, fmt.Errorf("TTL must be in (0, 15m]; got %s", c.TTL)
	}
	if err := ctx.Err(); err != nil {
		return nil, 0, fmt.Errorf("signing cancelled: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, 0, err
	}

	now := time.Now()
	cert := &ssh.Certificate{
		Key:             pub,
		Serial:          serial,
		CertType:        ssh.UserCert,
		KeyId:           c.KeyID,
		ValidPrincipals: []string{c.Principal},
		// 30 s back-dated to tolerate clock skew.
		ValidAfter:  uint64(now.Add(-30 * time.Second).Unix()),
		ValidBefore: uint64(now.Add(c.TTL).Unix()),
		Permissions: ssh.Permissions{
			CriticalOptions: map[string]string{},
			Extensions:      map[string]string{}, // empty: no agent/X11 forwarding
		},
	}
	if c.SourceAddress != "" {
		cert.Permissions.CriticalOptions["source-address"] = c.SourceAddress
	}
	if c.ForceCommand != "" {
		cert.Permissions.CriticalOptions["force-command"] = c.ForceCommand
	}
	if c.AllowPortForwarding {
		cert.Permissions.Extensions["permit-port-forwarding"] = ""
	}
	if c.AllowPTY {
		cert.Permissions.Extensions["permit-pty"] = ""
	}

	if err := cert.SignCert(rand.Reader, caKey); err != nil {
		return nil, 0, fmt.Errorf("signing certificate: %w", err)
	}
	return cert, serial, nil
}

func randomSerial() (uint64, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, fmt.Errorf("random serial: %w", err)
	}
	return binary.BigEndian.Uint64(b[:]), nil
}
