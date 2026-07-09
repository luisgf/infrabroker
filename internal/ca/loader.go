// loader.go provides the abstraction layer for loading CA keys from different
// sources (local PEM file or Azure Key Vault) and for resolving the default and
// per-group CA signers used by the signer service and the broker's local mode.
package ca

import (
	"context"
	"fmt"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

// CAKeyConfig describes a CA key source used in signer.json and config.json.
// Type selects the backend:
//
//   - "pem": loads from a local PEM file (Path). Lab/dev use; emits a runtime
//     warning. In production, prefer "akv", "agent", or another HSM/KMS backend.
//   - "akv": Azure Key Vault. The private key never leaves AKV; only the public
//     key is fetched on startup. All signing operations execute inside the service.
//   - "agent": the private key lives in a running ssh-agent (Socket, or
//     $SSH_AUTH_SOCK) and is pinned by its public key (PublicKeyPath). Backs a
//     YubiKey PIV slot / SoftHSM / TPM via `ssh-add -s`, with no cgo in this
//     process. Unlike AKV it supports **Ed25519** CA keys.
//
// AKV only supports RSA (2048/3072/4096) and EC (P-256/P-384/P-521); Ed25519 is
// not available in AKV, so use "agent" (hardware) or "pem" for an Ed25519 CA.
//
// A CAKeyConfig can appear as the global default (key "_default" in ca_keys),
// or as a per-group override. When ca_key (legacy PEM string) is present and
// ca_keys is absent, the behaviour is identical to CAKeyConfig{Type:"pem", Path: ca_key}.
type CAKeyConfig struct {
	Type string `json:"type"` // "pem" | "akv" | "agent"

	// PEM backend.
	Path string `json:"path,omitempty"`

	// ssh-agent backend. Socket empty = $SSH_AUTH_SOCK. PublicKeyPath is the CA
	// public key (.pub / authorized_keys line) used to pin which agent key is the CA.
	Socket        string `json:"socket,omitempty"`
	PublicKeyPath string `json:"public_key_path,omitempty"`

	// Azure Key Vault backend.
	VaultURL   string `json:"vault_url,omitempty"`
	KeyName    string `json:"key_name,omitempty"`
	KeyVersion string `json:"key_version,omitempty"` // empty = latest version

	// AKV authentication overrides. When TenantID and ClientID are both empty,
	// DefaultAzureCredential is used (recommended for production: picks up
	// managed identity, workload identity, AZURE_* env vars, and Azure CLI).
	TenantID string `json:"tenant_id,omitempty"`
	ClientID string `json:"client_id,omitempty"`
	// ClientSecretEnv is the name of the environment variable holding the client
	// secret. The secret is never stored in the config file.
	ClientSecretEnv string `json:"client_secret_env,omitempty"`
}

// LoadCA loads a CA ssh.Signer from the given configuration.
//
// For "pem": the key is read from disk and parsed in memory. A runtime warning
// is emitted (lab/dev use only). In production use "akv" or another HSM/KMS.
//
// For "akv": the AKV client is initialised and the public key is fetched
// immediately (fail-fast on misconfiguration). The private key never leaves AKV.
//
// For "agent": the ssh-agent is dialled and the pinned public key is confirmed
// present immediately (fail-fast). The private key never leaves the agent.
func LoadCA(ctx context.Context, cfg CAKeyConfig) (ssh.Signer, error) {
	switch cfg.Type {
	case "pem":
		return loadCAFromFile(cfg.Path)
	case "akv":
		return loadCAFromAKV(ctx, cfg)
	case "agent":
		return loadCAFromAgent(cfg)
	default:
		return nil, fmt.Errorf("unknown CA key type %q: supported types are \"pem\", \"akv\", and \"agent\"", cfg.Type)
	}
}

// LoadGroupCAs resolves the default CA and per-group CA signers from the two
// config fields shared by signer.json and config.json:
//
//   - caKey: legacy path to a PEM file (backward compatible).
//   - caKeys: per-group CA configs. The reserved key "_default" overrides caKey.
//
// Returns the default CA signer and a map from group name to group CA signer.
// The returned groupCAs map is nil when no per-group CAs are configured.
// A 30-second timeout is applied to the total loading time (covers AKV GetKey calls).
func LoadGroupCAs(ctx context.Context, caKey string, caKeys map[string]CAKeyConfig) (ssh.Signer, map[string]ssh.Signer, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var defaultCA ssh.Signer
	var err error

	// "_default" in caKeys wins over the legacy caKey string.
	if def, ok := caKeys["_default"]; ok {
		defaultCA, err = LoadCA(ctx, def)
	} else if caKey != "" {
		defaultCA, err = LoadCA(ctx, CAKeyConfig{Type: "pem", Path: caKey})
	} else {
		return nil, nil, fmt.Errorf("no default CA key configured: set ca_key or ca_keys._default")
	}
	if err != nil {
		return nil, nil, fmt.Errorf("default CA: %w", err)
	}

	if len(caKeys) == 0 {
		return defaultCA, nil, nil
	}

	groupCAs := make(map[string]ssh.Signer, len(caKeys))
	for group, kcfg := range caKeys {
		if group == "_default" {
			continue
		}
		s, kerr := LoadCA(ctx, kcfg)
		if kerr != nil {
			return nil, nil, fmt.Errorf("CA for group %q: %w", group, kerr)
		}
		groupCAs[group] = s
	}
	if len(groupCAs) == 0 {
		groupCAs = nil
	}

	return defaultCA, groupCAs, nil
}

// loadCAFromFile reads a PEM-encoded CA key from disk.
func loadCAFromFile(path string) (ssh.Signer, error) {
	if path == "" {
		return nil, fmt.Errorf("pem CA key: path is required")
	}
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading CA key %q: %w", path, err)
	}
	return LoadCAFromPEM(pemBytes)
}

// loadCAFromAKV creates an ssh.Signer backed by Azure Key Vault.
func loadCAFromAKV(ctx context.Context, cfg CAKeyConfig) (ssh.Signer, error) {
	if cfg.VaultURL == "" {
		return nil, fmt.Errorf("akv CA key: vault_url is required")
	}
	if cfg.KeyName == "" {
		return nil, fmt.Errorf("akv CA key: key_name is required")
	}
	s, err := newAKVSigner(ctx, cfg)
	if err != nil {
		return nil, err
	}
	sshSigner, err := ssh.NewSignerFromSigner(s)
	if err != nil {
		return nil, fmt.Errorf("wrapping AKV signer: %w", err)
	}
	return sshSigner, nil
}
