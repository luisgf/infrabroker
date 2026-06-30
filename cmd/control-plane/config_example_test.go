package main

import (
	"os"
	"testing"

	"github.com/luisgf/ssh-broker/internal/confcheck"
)

// TestControlPlaneExampleConfigMatchesStruct fails if control-plane.example.json
// uses a key that no longer exists on the control-plane Config struct.
func TestControlPlaneExampleConfigMatchesStruct(t *testing.T) {
	raw, err := os.ReadFile("../../control-plane.example.json")
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	clean, err := confcheck.StripUnderscoreKeys(raw)
	if err != nil {
		t.Fatalf("strip comments: %v", err)
	}
	var cfg Config
	if err := confcheck.DecodeStrict(clean, &cfg); err != nil {
		t.Fatalf("control-plane.example.json has a key not in Config (doc/code drift?): %v", err)
	}
}
