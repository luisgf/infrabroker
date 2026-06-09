package ca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"golang.org/x/crypto/ssh"
)

// mockAKVOps is a test double for akvKeyOps.
type mockAKVOps struct {
	getKeyFn func(ctx context.Context, name, version string, opts *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error)
	signFn   func(ctx context.Context, name, version string, params azkeys.SignParameters, opts *azkeys.SignOptions) (azkeys.SignResponse, error)
}

func (m *mockAKVOps) GetKey(ctx context.Context, name, version string, opts *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error) {
	return m.getKeyFn(ctx, name, version, opts)
}

func (m *mockAKVOps) Sign(ctx context.Context, name, version string, params azkeys.SignParameters, opts *azkeys.SignOptions) (azkeys.SignResponse, error) {
	return m.signFn(ctx, name, version, params, opts)
}

// ecP256Mock returns a mockAKVOps backed by a real ECDSA P-256 private key,
// converting real DER signatures to raw R||S to simulate AKV behaviour.
func ecP256Mock(t *testing.T) (*mockAKVOps, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kty := azkeys.KeyTypeEC
	crv := azkeys.CurveNameP256
	mock := &mockAKVOps{
		getKeyFn: func(_ context.Context, _, _ string, _ *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error) {
			return azkeys.GetKeyResponse{
				KeyBundle: azkeys.KeyBundle{
					Key: &azkeys.JSONWebKey{
						Kty: &kty,
						Crv: &crv,
						X:   priv.PublicKey.X.FillBytes(make([]byte, 32)),
						Y:   priv.PublicKey.Y.FillBytes(make([]byte, 32)),
					},
				},
			}, nil
		},
		signFn: func(_ context.Context, _, _ string, params azkeys.SignParameters, _ *azkeys.SignOptions) (azkeys.SignResponse, error) {
			// Sign with the real key, then convert DER → R||S (AKV format).
			r, s, err := ecdsa.Sign(rand.Reader, priv, params.Value)
			if err != nil {
				return azkeys.SignResponse{}, err
			}
			raw := make([]byte, 64) // 32 bytes each for P-256
			r.FillBytes(raw[:32])
			s.FillBytes(raw[32:])
			return azkeys.SignResponse{
				KeyOperationResult: azkeys.KeyOperationResult{Result: raw},
			}, nil
		},
	}
	return mock, priv
}

// rsaMock returns a mockAKVOps backed by a real RSA-2048 private key.
func rsaMock(t *testing.T) (*mockAKVOps, *rsa.PrivateKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	kty := azkeys.KeyTypeRSA
	mock := &mockAKVOps{
		getKeyFn: func(_ context.Context, _, _ string, _ *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error) {
			return azkeys.GetKeyResponse{
				KeyBundle: azkeys.KeyBundle{
					Key: &azkeys.JSONWebKey{
						Kty: &kty,
						N:   priv.PublicKey.N.Bytes(),
						E:   big.NewInt(int64(priv.PublicKey.E)).Bytes(),
					},
				},
			}, nil
		},
		signFn: func(_ context.Context, _, _ string, params azkeys.SignParameters, _ *azkeys.SignOptions) (azkeys.SignResponse, error) {
			// Sign with PKCS1v15 SHA-256 (matches RS256).
			sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, params.Value)
			if err != nil {
				return azkeys.SignResponse{}, err
			}
			return azkeys.SignResponse{
				KeyOperationResult: azkeys.KeyOperationResult{Result: sig},
			}, nil
		},
	}
	return mock, priv
}

// TestAKVSignerConstructorECP256 verifies that newAKVSignerWithOps succeeds
// for a valid EC P-256 mock and the signer's PublicKey matches the original.
func TestAKVSignerConstructorECP256(t *testing.T) {
	t.Parallel()
	mock, priv := ecP256Mock(t)

	s, err := newAKVSignerWithOps(context.Background(), mock, "my-key", "")
	if err != nil {
		t.Fatalf("newAKVSignerWithOps: %v", err)
	}
	ecPub, ok := s.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", s.Public())
	}
	if ecPub.X.Cmp(priv.PublicKey.X) != 0 || ecPub.Y.Cmp(priv.PublicKey.Y) != 0 {
		t.Error("public key mismatch")
	}
}

// TestAKVSignerConstructorRSA verifies that newAKVSignerWithOps succeeds
// for a valid RSA mock and the signer's PublicKey matches the original.
func TestAKVSignerConstructorRSA(t *testing.T) {
	t.Parallel()
	mock, priv := rsaMock(t)

	s, err := newAKVSignerWithOps(context.Background(), mock, "rsa-key", "")
	if err != nil {
		t.Fatalf("newAKVSignerWithOps: %v", err)
	}
	rsaPub, ok := s.Public().(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", s.Public())
	}
	if rsaPub.N.Cmp(priv.PublicKey.N) != 0 {
		t.Error("RSA public key (N) mismatch")
	}
}

// TestAKVSignerSignECP256 verifies the full EC P-256 sign path: the akvSigner
// calls the mock, converts R||S to DER, and produces a signature that the
// ssh.CertChecker can verify.
func TestAKVSignerSignECP256(t *testing.T) {
	t.Parallel()
	mock, priv := ecP256Mock(t)

	raw, err := newAKVSignerWithOps(context.Background(), mock, "my-key", "")
	if err != nil {
		t.Fatal(err)
	}
	sshSigner, err := ssh.NewSignerFromSigner(raw)
	if err != nil {
		t.Fatal(err)
	}

	// Sign arbitrary data via the ssh.Signer interface.
	data := []byte("test payload for EC P-256 AKV signing")
	sig, err := sshSigner.Sign(rand.Reader, data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if sig == nil || len(sig.Blob) == 0 {
		t.Fatal("expected non-empty signature")
	}

	// sig.Blob is in SSH ECDSA wire format (two mpints), not raw DER.
	// Verification via ssh.PublicKey.Verify exercises the full path.
	// Verify against the real public key.
	sshPub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if verr := sshPub.Verify(data, sig); verr != nil {
		t.Errorf("Verify: %v", verr)
	}
}

// TestAKVSignerSignRSA verifies that RSA signatures pass through unchanged.
func TestAKVSignerSignRSA(t *testing.T) {
	t.Parallel()
	mock, priv := rsaMock(t)

	raw, err := newAKVSignerWithOps(context.Background(), mock, "rsa-key", "")
	if err != nil {
		t.Fatal(err)
	}
	sshSigner, err := ssh.NewSignerFromSigner(raw)
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("test payload for RSA AKV signing")
	// Use rsa-sha2-256; the default Sign uses ssh-rsa (SHA-1) which AKV rejects.
	algSigner, ok := sshSigner.(ssh.AlgorithmSigner)
	if !ok {
		t.Fatal("expected ssh.AlgorithmSigner for RSA key")
	}
	sig, err := algSigner.SignWithAlgorithm(rand.Reader, data, ssh.KeyAlgoRSASHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if sig == nil || len(sig.Blob) == 0 {
		t.Fatal("expected non-empty RSA signature")
	}

	sshPub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if verr := sshPub.Verify(data, sig); verr != nil {
		t.Errorf("Verify: %v", verr)
	}
}

// TestRawECSignatureToDER verifies the R||S → DER conversion with known values.
func TestRawECSignatureToDER(t *testing.T) {
	t.Parallel()
	r := big.NewInt(0xDEADBEEF)
	s := big.NewInt(0xCAFEBABE)

	rBytes := r.FillBytes(make([]byte, 32))
	sBytes := s.FillBytes(make([]byte, 32))
	raw := append(rBytes, sBytes...)

	der, err := rawECSignatureToDER(raw, 32)
	if err != nil {
		t.Fatalf("rawECSignatureToDER: %v", err)
	}
	var decoded ecdsaSignatureDER
	if _, derr := asn1.Unmarshal(der, &decoded); derr != nil {
		t.Fatalf("DER decode: %v", derr)
	}
	if decoded.R.Cmp(r) != 0 {
		t.Errorf("R mismatch: got %v, want %v", decoded.R, r)
	}
	if decoded.S.Cmp(s) != 0 {
		t.Errorf("S mismatch: got %v, want %v", decoded.S, s)
	}
}

// TestRawECSignatureToDERWrongLen verifies that an incorrect length returns an error.
func TestRawECSignatureToDERWrongLen(t *testing.T) {
	t.Parallel()
	_, err := rawECSignatureToDER(make([]byte, 40), 32) // 40 ≠ 64
	if err == nil {
		t.Fatal("expected error for wrong length")
	}
}

// TestAKVAlgorithmEC verifies algorithm selection for EC keys.
func TestAKVAlgorithmEC(t *testing.T) {
	t.Parallel()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	alg, err := akvAlgorithm(&priv.PublicKey, crypto.SHA256)
	if err != nil {
		t.Fatalf("akvAlgorithm: %v", err)
	}
	if alg != azkeys.SignatureAlgorithmES256 {
		t.Errorf("expected ES256, got %v", alg)
	}
}

// TestAKVAlgorithmRSA verifies algorithm selection for RSA keys.
func TestAKVAlgorithmRSA(t *testing.T) {
	t.Parallel()
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	tests := []struct {
		hash crypto.Hash
		want azkeys.SignatureAlgorithm
	}{
		{crypto.SHA256, azkeys.SignatureAlgorithmRS256},
		{crypto.SHA384, azkeys.SignatureAlgorithmRS384},
		{crypto.SHA512, azkeys.SignatureAlgorithmRS512},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.hash.String(), func(t *testing.T) {
			t.Parallel()
			alg, err := akvAlgorithm(&priv.PublicKey, tc.hash)
			if err != nil {
				t.Fatalf("akvAlgorithm: %v", err)
			}
			if alg != tc.want {
				t.Errorf("got %v, want %v", alg, tc.want)
			}
		})
	}
}

// TestAKVSignerSignedByCACert verifies that a cert signed by the AKV-backed CA
// validates against the CA's public key (end-to-end with BuildAndSign).
func TestAKVSignerSignedByCACert(t *testing.T) {
	t.Parallel()
	mock, caPriv := ecP256Mock(t)

	raw, err := newAKVSignerWithOps(context.Background(), mock, "ca-key", "")
	if err != nil {
		t.Fatal(err)
	}
	caKey, err := ssh.NewSignerFromSigner(raw)
	if err != nil {
		t.Fatal(err)
	}

	_, ephPub, err := GenerateEphemeralKey()
	if err != nil {
		t.Fatal(err)
	}

	cert, _, err := BuildAndSign(context.Background(), caKey, ephPub, Constraints{
		Principal: "host:web01",
		TTL:       time.Minute,
		KeyID:     "akv-test",
	})
	if err != nil {
		t.Fatalf("BuildAndSign: %v", err)
	}

	// Verify the cert was signed by our AKV-backed CA.
	caPub, err := ssh.NewPublicKey(&caPriv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	checker := &ssh.CertChecker{
		IsUserAuthority: func(k ssh.PublicKey) bool {
			return string(k.Marshal()) == string(caPub.Marshal())
		},
	}
	if cerr := checker.CheckCert("host:web01", cert); cerr != nil {
		t.Errorf("CheckCert: %v", cerr)
	}
}
