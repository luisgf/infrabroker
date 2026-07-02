package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeClientConfig(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const ccFixture = `{
  "signer":        {"url": "signer.example:9443", "cert": "/etc/pki/s.crt", "key": "/etc/pki/s.key", "ca": "/etc/pki/ca.crt"},
  "control_plane": {"url": "cp.example:7443", "cert": "/etc/pki/a.crt", "key": "/etc/pki/a.key", "ca": "/etc/pki/ca.crt"}
}`

func TestLoadClientConfigFrom(t *testing.T) {
	dir := t.TempDir()
	good := writeClientConfig(t, dir, "good.json", ccFixture)
	bad := writeClientConfig(t, dir, "bad.json", "{not json")
	missing := filepath.Join(dir, "absent.json")

	// First usable candidate wins; optional missing candidates are skipped.
	cfg, src, err := loadClientConfigFrom([]ccCandidate{{missing, false}, {good, false}})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if src != good || cfg.Signer.URL != "signer.example:9443" || cfg.ControlPlane.Cert != "/etc/pki/a.crt" {
		t.Errorf("unexpected result: src=%q cfg=%+v", src, cfg)
	}

	// No candidate found: not an error, empty config.
	cfg, src, err = loadClientConfigFrom([]ccCandidate{{missing, false}})
	if err != nil || src != "" || cfg.Signer.URL != "" {
		t.Errorf("absent optional: cfg=%+v src=%q err=%v", cfg, src, err)
	}

	// An explicitly-named file must exist.
	if _, _, err = loadClientConfigFrom([]ccCandidate{{missing, true}}); err == nil {
		t.Error("required missing file: expected error")
	}

	// A file that exists but does not parse is a hard error, never skipped.
	if _, _, err = loadClientConfigFrom([]ccCandidate{{bad, false}, {good, false}}); err == nil {
		t.Error("malformed file: expected error, got silent skip")
	} else if !strings.Contains(err.Error(), "bad.json") {
		t.Errorf("error should name the offending file: %v", err)
	}
}

// TestResolveTargetPrecedence: explicit flag > env var > file > built-in
// default, independently per parameter.
func TestResolveTargetPrecedence(t *testing.T) {
	t.Setenv("BROKER_CTL_SIGNER_URL", "env.example:9443")
	t.Setenv("BROKER_CTL_SIGNER_CERT", "")
	t.Setenv("BROKER_CTL_SIGNER_KEY", "")
	t.Setenv("BROKER_CTL_SIGNER_CA", "")

	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	url, cert, key, ca := signerFlags(fs)
	// --cert passed explicitly; --url/--key/--ca left unset.
	if err := fs.Parse([]string{"--cert", "/flag/cert.crt"}); err != nil {
		t.Fatal(err)
	}
	file := clientTarget{URL: "file.example:9443", Cert: "/file/cert.crt", Key: "/file/key.pem"}
	resolveTarget(fs, "BROKER_CTL_SIGNER", file)

	if *cert != "/flag/cert.crt" {
		t.Errorf("flag must win: cert = %q", *cert)
	}
	if *url != "env.example:9443" {
		t.Errorf("env must beat file: url = %q", *url)
	}
	if *key != "/file/key.pem" {
		t.Errorf("file must beat default: key = %q", *key)
	}
	if *ca != "./pki/mtls_ca.crt" {
		t.Errorf("built-in default must survive when nothing overrides: ca = %q", *ca)
	}
}

// TestClientConfigCandidatesOrder: --client-config and $BROKER_CTL_CONFIG are
// explicit (required) and come first, in that order.
func TestClientConfigCandidatesOrder(t *testing.T) {
	t.Setenv("BROKER_CTL_CONFIG", "/env/cc.json")
	old := clientConfigPath
	clientConfigPath = "/flag/cc.json"
	defer func() { clientConfigPath = old }()

	cands := clientConfigCandidates()
	if len(cands) < 3 {
		t.Fatalf("too few candidates: %+v", cands)
	}
	if cands[0].path != "/flag/cc.json" || !cands[0].required {
		t.Errorf("first candidate must be the --client-config flag: %+v", cands[0])
	}
	if cands[1].path != "/env/cc.json" || !cands[1].required {
		t.Errorf("second candidate must be $BROKER_CTL_CONFIG: %+v", cands[1])
	}
	last := cands[len(cands)-1]
	if last.path != "/etc/ssh-broker/broker-ctl.json" || last.required {
		t.Errorf("last candidate must be the system path, optional: %+v", last)
	}
}
