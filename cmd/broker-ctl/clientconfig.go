// clientconfig.go implements the optional broker-ctl client parameters file
// and its environment-variable overrides, so remote commands (reload, policy,
// approval, host list --remote) do not need --url/--cert/--key/--ca on every
// invocation.
//
// This is CLIENT configuration (where to reach the services, which mTLS
// identity to present) — deliberately separate from signer.json, which is the
// service's policy. Precedence, per parameter:
//
//	explicit flag  >  BROKER_CTL_* env var  >  client config file  >  built-in default
//
// The file is JSON with one section per target service:
//
//	{
//	  "signer":        { "url": "127.0.0.1:9443", "cert": "...", "key": "...", "ca": "..." },
//	  "control_plane": { "url": "127.0.0.1:7443", "cert": "...", "key": "...", "ca": "..." }
//	}
//
// Search order: --client-config (global flag) → $BROKER_CTL_CONFIG →
// <user config dir>/broker-ctl/config.json → /etc/ssh-broker/broker-ctl.json.
// The first two are explicit choices and must exist; the rest are skipped when
// absent. The current working directory is deliberately NOT searched — an
// implicit ./broker-ctl.json would let a planted file redirect this privileged
// CLI's mTLS endpoint and CA trust anchor; use --client-config for a CWD file.
// A file that exists but does not parse is always a hard error — never silently
// ignored.
//
// Environment variables: BROKER_CTL_SIGNER_{URL,CERT,KEY,CA} and
// BROKER_CTL_CP_{URL,CERT,KEY,CA}.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

// clientTarget holds the connection parameters for one remote service.
type clientTarget struct {
	URL  string `json:"url,omitempty"`
	Cert string `json:"cert,omitempty"`
	Key  string `json:"key,omitempty"`
	CA   string `json:"ca,omitempty"`
}

// clientConfig is the parsed broker-ctl client parameters file.
type clientConfig struct {
	Signer       clientTarget `json:"signer"`
	ControlPlane clientTarget `json:"control_plane"`
}

// clientConfigPath is the value of the global --client-config flag (set by
// parseGlobalFlags; empty = use env/search order).
var clientConfigPath string

// ccCandidate is one entry of the client-config search order. A required
// candidate was named explicitly (flag or env) and must exist.
type ccCandidate struct {
	path     string
	required bool
}

// clientConfigCandidates returns the search order for the client config file.
func clientConfigCandidates() []ccCandidate {
	var cands []ccCandidate
	if clientConfigPath != "" {
		cands = append(cands, ccCandidate{clientConfigPath, true})
	}
	if p := os.Getenv("BROKER_CTL_CONFIG"); p != "" {
		cands = append(cands, ccCandidate{p, true})
	}
	// Deliberately NOT the current working directory: this CLI presents a
	// privileged mTLS identity, and an implicit ./broker-ctl.json would let a
	// file planted in whatever directory the admin happens to run from silently
	// redirect the signer/control-plane URL and CA trust anchor. A CWD file must
	// be selected explicitly via --client-config or $BROKER_CTL_CONFIG.
	if dir, err := os.UserConfigDir(); err == nil {
		cands = append(cands, ccCandidate{filepath.Join(dir, "broker-ctl", "config.json"), false})
	}
	cands = append(cands, ccCandidate{"/etc/ssh-broker/broker-ctl.json", false})
	return cands
}

// loadClientConfigFrom resolves the first usable candidate. It returns the
// parsed config and the path it came from ("" when no file was found, which
// is not an error: flags/env/defaults still apply).
func loadClientConfigFrom(cands []ccCandidate) (clientConfig, string, error) {
	for _, c := range cands {
		b, err := os.ReadFile(c.path)
		if err != nil {
			if os.IsNotExist(err) && !c.required {
				continue
			}
			return clientConfig{}, "", fmt.Errorf("client config %s: %w", c.path, err)
		}
		var cfg clientConfig
		if err := json.Unmarshal(b, &cfg); err != nil {
			return clientConfig{}, "", fmt.Errorf("client config %s: %w", c.path, err)
		}
		return cfg, c.path, nil
	}
	return clientConfig{}, "", nil
}

// cachedClientConfig memoizes the result of the first load for the process.
var cachedClientConfig *clientConfig

// loadClientConfig loads the client config once, fatally on a malformed or
// explicitly-named-but-missing file.
func loadClientConfig() clientConfig {
	if cachedClientConfig != nil {
		return *cachedClientConfig
	}
	cfg, _, err := loadClientConfigFrom(clientConfigCandidates())
	if err != nil {
		fatalf("%v", err)
	}
	cachedClientConfig = &cfg
	return cfg
}

// resolveTarget applies the client-parameter precedence to the url/cert/key/ca
// flags of an already-parsed FlagSet: a flag the user set explicitly wins; an
// unset flag takes the BROKER_CTL_<env>_{URL,CERT,KEY,CA} variable, then the
// client config file value, and otherwise keeps its built-in default. Flags
// the FlagSet does not define are skipped.
func resolveTarget(fs *flag.FlagSet, env string, file clientTarget) {
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	apply := func(name, envSuffix, fileVal string) {
		if set[name] {
			return
		}
		f := fs.Lookup(name)
		if f == nil {
			return
		}
		if v := os.Getenv(env + envSuffix); v != "" {
			f.Value.Set(v)
			return
		}
		if fileVal != "" {
			f.Value.Set(fileVal)
		}
	}
	apply("url", "_URL", file.URL)
	apply("cert", "_CERT", file.Cert)
	apply("key", "_KEY", file.Key)
	apply("ca", "_CA", file.CA)
}

// resolveSignerTarget resolves the signer-facing flags of fs (env prefix
// BROKER_CTL_SIGNER, file section "signer").
func resolveSignerTarget(fs *flag.FlagSet) {
	resolveTarget(fs, "BROKER_CTL_SIGNER", loadClientConfig().Signer)
}

// resolveControlPlaneTarget resolves the control-plane-facing flags of fs
// (env prefix BROKER_CTL_CP, file section "control_plane").
func resolveControlPlaneTarget(fs *flag.FlagSet) {
	resolveTarget(fs, "BROKER_CTL_CP", loadClientConfig().ControlPlane)
}

// signerFlags registers the shared flags of the signer-facing remote commands.
// The empty --url default means "resolve via env/file, else the listen field
// of the signer config" (see policyHTTP).
func signerFlags(fs *flag.FlagSet) (url, cert, key, ca *string) {
	url = fs.String("url", "", "signer host:port (default: broker-ctl.json / BROKER_CTL_SIGNER_URL, else the config file's listen)")
	cert = fs.String("cert", "./pki/broker.crt", "mTLS client cert")
	key = fs.String("key", "./pki/broker.key", "mTLS client key")
	ca = fs.String("ca", "./pki/mtls_ca.crt", "mTLS CA")
	return
}
