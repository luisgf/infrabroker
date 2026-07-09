package ca

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// agentDialTimeout bounds each connection to the ssh-agent socket.
const agentDialTimeout = 5 * time.Second

// loadCAFromAgent returns a CA signer whose private key lives in a running
// ssh-agent — e.g. a YubiKey PIV slot, a SoftHSM token, or a TPM, loaded with
// `ssh-add -s <pkcs11.so>` (stock OpenSSH, no cgo in this process). The private
// key never leaves the agent; every signature is a fresh agent round trip. The
// pinned public key (PublicKeyPath) selects which agent key is the CA, and its
// presence is verified at startup (fail-fast on a misconfigured or empty agent).
func loadCAFromAgent(cfg CAKeyConfig) (ssh.Signer, error) {
	socket := cfg.Socket
	if socket == "" {
		socket = os.Getenv("SSH_AUTH_SOCK")
	}
	if socket == "" {
		return nil, fmt.Errorf("agent CA: no socket configured and SSH_AUTH_SOCK is unset")
	}
	if cfg.PublicKeyPath == "" {
		return nil, fmt.Errorf("agent CA: public_key_path is required to pin the CA key in the agent")
	}
	pubBytes, err := os.ReadFile(cfg.PublicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("agent CA: reading public_key_path: %w", err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(pubBytes)
	if err != nil {
		return nil, fmt.Errorf("agent CA: parsing public key %s: %w", cfg.PublicKeyPath, err)
	}
	s := &agentSigner{socket: socket, pub: pub}
	// Fail-fast: confirm the pinned key is present in the agent now, so a
	// misconfiguration surfaces at startup rather than on the first sign.
	if err := s.withSigner(func(ssh.Signer) error { return nil }); err != nil {
		return nil, err
	}
	return s, nil
}

// agentSigner is an ssh.Signer (and ssh.AlgorithmSigner) that re-dials the
// ssh-agent for every signature, so a dropped agent connection does not
// permanently break signing on a long-running signer.
type agentSigner struct {
	socket string
	pub    ssh.PublicKey
}

func (s *agentSigner) PublicKey() ssh.PublicKey { return s.pub }

func (s *agentSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	return s.SignWithAlgorithm(rand, data, "")
}

// SignWithAlgorithm signs data, requesting algorithm when non-empty (e.g.
// rsa-sha2-256/512 for an RSA CA; crypto/ssh selects it when signing the cert).
// Ed25519 keys have a single algorithm and ignore it.
func (s *agentSigner) SignWithAlgorithm(rand io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	var sig *ssh.Signature
	err := s.withSigner(func(as ssh.Signer) error {
		var serr error
		if algorithm != "" {
			alg, ok := as.(ssh.AlgorithmSigner)
			if !ok {
				return fmt.Errorf("agent CA: agent signer does not support algorithm %q", algorithm)
			}
			sig, serr = alg.SignWithAlgorithm(rand, data, algorithm)
		} else {
			sig, serr = as.Sign(rand, data)
		}
		return serr
	})
	return sig, err
}

// withSigner dials the agent, finds the pinned CA signer, and runs fn with it.
func (s *agentSigner) withSigner(fn func(ssh.Signer) error) error {
	conn, err := net.DialTimeout("unix", s.socket, agentDialTimeout)
	if err != nil {
		return fmt.Errorf("agent CA: dialing ssh-agent at %s: %w", s.socket, err)
	}
	defer conn.Close()
	signer, err := matchAgentSigner(agent.NewClient(conn), s.pub)
	if err != nil {
		return err
	}
	return fn(signer)
}

// matchAgentSigner returns the agent signer whose public key equals pub.
func matchAgentSigner(ag agent.Agent, pub ssh.PublicKey) (ssh.Signer, error) {
	signers, err := ag.Signers()
	if err != nil {
		return nil, fmt.Errorf("agent CA: listing ssh-agent keys: %w", err)
	}
	want := pub.Marshal()
	for _, sg := range signers {
		if bytes.Equal(sg.PublicKey().Marshal(), want) {
			return sg, nil
		}
	}
	return nil, fmt.Errorf("agent CA: pinned public key (%s) not found among %d ssh-agent key(s)",
		ssh.FingerprintSHA256(pub), len(signers))
}
