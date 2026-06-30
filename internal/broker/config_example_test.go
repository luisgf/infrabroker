package broker

import (
	"os"
	"testing"

	"github.com/luisgf/ssh-broker/internal/confcheck"
)

// TestBrokerExampleConfigMatchesStruct fails if config.example.json uses a key
// that no longer exists on the broker Config struct.
func TestBrokerExampleConfigMatchesStruct(t *testing.T) {
	raw, err := os.ReadFile("../../config.example.json")
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	clean, err := confcheck.StripUnderscoreKeys(raw)
	if err != nil {
		t.Fatalf("strip comments: %v", err)
	}
	var cfg Config
	if err := confcheck.DecodeStrict(clean, &cfg); err != nil {
		t.Fatalf("config.example.json has a key not in Config (doc/code drift?): %v", err)
	}
}
