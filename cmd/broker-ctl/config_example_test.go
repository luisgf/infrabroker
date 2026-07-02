package main

import (
	"os"
	"testing"

	"github.com/luisgf/ssh-broker/internal/confcheck"
)

// TestClientExampleConfigMatchesStruct fails if broker-ctl.example.json uses a
// key that no longer exists on the clientConfig struct — i.e. the example
// drifted from the code. Comment keys ("_*") are stripped first.
func TestClientExampleConfigMatchesStruct(t *testing.T) {
	raw, err := os.ReadFile("../../broker-ctl.example.json")
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	clean, err := confcheck.StripUnderscoreKeys(raw)
	if err != nil {
		t.Fatalf("strip comments: %v", err)
	}
	var cfg clientConfig
	if err := confcheck.DecodeStrict(clean, &cfg); err != nil {
		t.Fatalf("broker-ctl.example.json has a key not in clientConfig (doc/code drift?): %v", err)
	}
	if cfg.Signer.URL == "" || cfg.ControlPlane.Cert == "" {
		t.Errorf("example should populate both sections: %+v", cfg)
	}
}
