// akv.go implements an Azure Key Vault-backed crypto.Signer.
// The private key never leaves AKV; only the public key is held locally.
// All signing operations are performed via the AKV REST API.
package ca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"os"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

// akvKeyOps abstracts the AKV operations used by akvSigner.
// *azkeys.Client satisfies this interface in production; a mock is used in tests.
type akvKeyOps interface {
	GetKey(ctx context.Context, name, version string, opts *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error)
	Sign(ctx context.Context, name, version string, params azkeys.SignParameters, opts *azkeys.SignOptions) (azkeys.SignResponse, error)
}

// akvSigner implements crypto.Signer backed by Azure Key Vault.
// The private key never leaves AKV; only the public key is held locally.
type akvSigner struct {
	ops        akvKeyOps
	keyName    string
	keyVersion string // "" = latest
	pubKey     crypto.PublicKey
}

// newAKVSigner creates an akvSigner from a config: builds the AKV client,
// authenticates, and fetches the public key immediately (fail-fast on
// misconfiguration or unreachable vault).
func newAKVSigner(ctx context.Context, cfg CAKeyConfig) (*akvSigner, error) {
	cred, err := akvCredential(cfg)
	if err != nil {
		return nil, fmt.Errorf("AKV credential: %w", err)
	}
	client, err := azkeys.NewClient(cfg.VaultURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("AKV client: %w", err)
	}
	return newAKVSignerWithOps(ctx, client, cfg.KeyName, cfg.KeyVersion)
}

// newAKVSignerWithOps is the testable constructor: accepts an akvKeyOps
// implementation in place of the real *azkeys.Client.
func newAKVSignerWithOps(ctx context.Context, ops akvKeyOps, keyName, keyVersion string) (*akvSigner, error) {
	resp, err := ops.GetKey(ctx, keyName, keyVersion, nil)
	if err != nil {
		return nil, fmt.Errorf("AKV GetKey %q: %w", keyName, err)
	}
	pub, err := parseAKVPublicKey(resp.Key)
	if err != nil {
		return nil, fmt.Errorf("AKV key %q: %w", keyName, err)
	}
	return &akvSigner{ops: ops, keyName: keyName, keyVersion: keyVersion, pubKey: pub}, nil
}

// Public implements crypto.Signer.
func (a *akvSigner) Public() crypto.PublicKey { return a.pubKey }

// Sign implements crypto.Signer. digest is the pre-computed hash of the data,
// computed by ssh.NewSignerFromSigner before calling this method. opts carries
// the hash algorithm, which determines the AKV signing algorithm for RSA keys.
// A 10-second timeout is applied to the AKV network call.
func (a *akvSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	var hash crypto.Hash
	if opts != nil {
		hash = opts.HashFunc()
	}
	alg, err := akvAlgorithm(a.pubKey, hash)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := a.ops.Sign(ctx, a.keyName, a.keyVersion, azkeys.SignParameters{
		Algorithm: &alg,
		Value:     digest,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("AKV Sign %q: %w", a.keyName, err)
	}

	// AKV returns EC signatures as raw R||S bytes; convert to DER for crypto.Signer.
	if ecPub, ok := a.pubKey.(*ecdsa.PublicKey); ok {
		coordBytes := (ecPub.Curve.Params().BitSize + 7) / 8
		return rawECSignatureToDER(resp.Result, coordBytes)
	}
	// RSA signatures are returned as PKCS1v15 bytes, which is what crypto.Signer expects.
	return resp.Result, nil
}

// akvCredential builds an Azure credential. When TenantID and ClientID are both
// empty, DefaultAzureCredential is used (recommended for production: picks up
// managed identity, workload identity, AZURE_* env vars, and Azure CLI).
func akvCredential(cfg CAKeyConfig) (azcore.TokenCredential, error) {
	if cfg.TenantID != "" && cfg.ClientID != "" && cfg.ClientSecretEnv != "" {
		secret := os.Getenv(cfg.ClientSecretEnv)
		if secret == "" {
			return nil, fmt.Errorf("env var %q for AKV client secret is empty", cfg.ClientSecretEnv)
		}
		return azidentity.NewClientSecretCredential(cfg.TenantID, cfg.ClientID, secret, nil)
	}
	return azidentity.NewDefaultAzureCredential(nil)
}

// akvAlgorithm maps a key type and hash function to the AKV signing algorithm.
// For EC keys the algorithm is determined by the curve (which sets the hash);
// for RSA keys the algorithm is determined by the requested hash function.
func akvAlgorithm(pub crypto.PublicKey, h crypto.Hash) (azkeys.SignatureAlgorithm, error) {
	switch pub.(type) {
	case *ecdsa.PublicKey:
		switch h {
		case crypto.SHA256:
			return azkeys.SignatureAlgorithmES256, nil
		case crypto.SHA384:
			return azkeys.SignatureAlgorithmES384, nil
		case crypto.SHA512:
			return azkeys.SignatureAlgorithmES512, nil
		default:
			return "", fmt.Errorf("unsupported hash %v for EC AKV key", h)
		}
	case *rsa.PublicKey:
		switch h {
		case crypto.SHA256:
			return azkeys.SignatureAlgorithmRS256, nil
		case crypto.SHA384:
			return azkeys.SignatureAlgorithmRS384, nil
		case crypto.SHA512:
			return azkeys.SignatureAlgorithmRS512, nil
		default:
			return "", fmt.Errorf("unsupported hash %v for RSA AKV key", h)
		}
	default:
		return "", fmt.Errorf("unsupported key type %T for AKV signing", pub)
	}
}

// parseAKVPublicKey converts an AKV JSON Web Key into a crypto.PublicKey.
// Ed25519 is not supported in AKV; only EC and RSA keys are accepted.
func parseAKVPublicKey(k *azkeys.JSONWebKey) (crypto.PublicKey, error) {
	if k == nil || k.Kty == nil {
		return nil, fmt.Errorf("nil key type in AKV response")
	}
	switch *k.Kty {
	case azkeys.KeyTypeEC, azkeys.KeyTypeECHSM:
		return parseAKVECKey(k)
	case azkeys.KeyTypeRSA, azkeys.KeyTypeRSAHSM:
		return parseAKVRSAKey(k)
	default:
		return nil, fmt.Errorf("unsupported AKV key type %q (Ed25519 is not available in AKV; supported: RSA, EC P-256/P-384/P-521)", *k.Kty)
	}
}

// ecdsaSignatureDER is the ASN.1 structure for DER-encoding ECDSA signatures.
type ecdsaSignatureDER struct {
	R, S *big.Int
}

// rawECSignatureToDER converts a raw R||S EC signature (as returned by AKV) to
// DER-encoded SEQUENCE { INTEGER R, INTEGER S } (as expected by crypto.Signer).
// coordBytes is the byte length of each coordinate (32 for P-256, 48 for P-384,
// 66 for P-521).
func rawECSignatureToDER(raw []byte, coordBytes int) ([]byte, error) {
	if len(raw) != 2*coordBytes {
		return nil, fmt.Errorf("EC signature: expected %d bytes (R||S), got %d", 2*coordBytes, len(raw))
	}
	r := new(big.Int).SetBytes(raw[:coordBytes])
	s := new(big.Int).SetBytes(raw[coordBytes:])
	return asn1.Marshal(ecdsaSignatureDER{R: r, S: s})
}

func parseAKVECKey(k *azkeys.JSONWebKey) (crypto.PublicKey, error) {
	if k.Crv == nil {
		return nil, fmt.Errorf("EC key missing curve name")
	}
	var curve elliptic.Curve
	switch *k.Crv {
	case azkeys.CurveNameP256:
		curve = elliptic.P256()
	case azkeys.CurveNameP384:
		curve = elliptic.P384()
	case azkeys.CurveNameP521:
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported EC curve %q (supported: P-256, P-384, P-521)", *k.Crv)
	}
	if len(k.X) == 0 || len(k.Y) == 0 {
		return nil, fmt.Errorf("EC key missing X or Y coordinate")
	}
	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(k.X),
		Y:     new(big.Int).SetBytes(k.Y),
	}, nil
}

func parseAKVRSAKey(k *azkeys.JSONWebKey) (crypto.PublicKey, error) {
	if len(k.N) == 0 || len(k.E) == 0 {
		return nil, fmt.Errorf("RSA key missing N or E")
	}
	e := new(big.Int).SetBytes(k.E)
	if !e.IsInt64() || e.Int64() > 1<<31-1 {
		return nil, fmt.Errorf("RSA exponent too large")
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(k.N),
		E: int(e.Int64()),
	}, nil
}
