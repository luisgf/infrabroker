package main

import (
	"os"
	"testing"

	"github.com/luisgf/ssh-broker/internal/confcheck"
)

// TestSignerExampleConfigMatchesStruct fails if signer.example.json uses a key
// that no longer exists on the signer Config struct — i.e. the example drifted
// from the code. Comment keys ("_*") are stripped first.
func TestSignerExampleConfigMatchesStruct(t *testing.T) {
	raw, err := os.ReadFile("../../signer.example.json")
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	clean, err := confcheck.StripUnderscoreKeys(raw)
	if err != nil {
		t.Fatalf("strip comments: %v", err)
	}
	var cfg Config
	if err := confcheck.DecodeStrict(clean, &cfg); err != nil {
		t.Fatalf("signer.example.json has a key not in Config (doc/code drift?): %v", err)
	}
}
