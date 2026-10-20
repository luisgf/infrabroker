package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"reflect"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// testHop builds a Hop pinned to hostKey with a freshly minted ephemeral
// ed25519 key and a certificate signed by a throwaway CA: hopClientConfig
// needs both to build the auth signer.
func testHop(t *testing.T, hostKey ssh.PublicKey) Hop {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caSigner, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatal(err)
	}
	cert := &ssh.Certificate{
		Key:         sshPub,
		CertType:    ssh.UserCert,
		KeyId:       "test",
		ValidAfter:  uint64(time.Now().Add(-time.Minute).Unix()),
		ValidBefore: uint64(time.Now().Add(time.Minute).Unix()),
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatal(err)
	}
	return Hop{Addr: "10.0.0.1:22", User: "u", HostKey: hostKey, PrivateKey: priv, Certificate: cert}
}

func rsaHostKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := ssh.NewPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pk
}

func ed25519HostKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return pk
}

// TestHopClientConfigRSAHostKeyAlgorithms pins #471: a pinned ssh-rsa host key
// must make the client offer the SHA-2 RSA signature algorithms too, otherwise
// an OpenSSH >= 8.8 sshd (which drops ssh-rsa from its default
// HostKeyAlgorithms) finds no common host-key algorithm and the handshake
// fails. The hop still pins the same key bytes through FixedHostKey. An
// ed25519 key keeps the single-algorithm list.
func TestHopClientConfigRSAHostKeyAlgorithms(t *testing.T) {
	t.Parallel()
	rsaKey := rsaHostKey(t)
	cfg, err := hopClientConfig(testHop(t, rsaKey), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}
	if !reflect.DeepEqual(cfg.HostKeyAlgorithms, want) {
		t.Errorf("RSA host key: HostKeyAlgorithms = %v, want %v", cfg.HostKeyAlgorithms, want)
	}
	// The pin is unchanged: the same key is accepted, a different one is not.
	if err := cfg.HostKeyCallback("h:22", nil, rsaKey); err != nil {
		t.Errorf("pinned RSA key rejected: %v", err)
	}
	if err := cfg.HostKeyCallback("h:22", nil, rsaHostKey(t)); err == nil {
		t.Error("a different RSA key must be rejected by the pin")
	}

	edKey := ed25519HostKey(t)
	cfg, err = hopClientConfig(testHop(t, edKey), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{ssh.KeyAlgoED25519}; !reflect.DeepEqual(cfg.HostKeyAlgorithms, want) {
		t.Errorf("ed25519 host key: HostKeyAlgorithms = %v, want %v", cfg.HostKeyAlgorithms, want)
	}
}

// TestHostKeyAlgorithmsForMirrorsKeyFormats: the table matches x/crypto's
// algorithmsForKeyFormat for every format infrabroker can pin.
func TestHostKeyAlgorithmsForMirrorsKeyFormats(t *testing.T) {
	t.Parallel()
	ed := ed25519HostKey(t)
	for _, tc := range []struct {
		key  ssh.PublicKey
		want []string
	}{
		{rsaHostKey(t), []string{"rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"}},
		{ed, []string{"ssh-ed25519"}},
	} {
		if got := hostKeyAlgorithmsFor(tc.key); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("hostKeyAlgorithmsFor(%s) = %v, want %v", tc.key.Type(), got, tc.want)
		}
	}
}
