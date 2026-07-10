package broker

import (
	"os"
	"testing"

	"github.com/luisgf/infrabroker/internal/confcheck"
)

// TestBrokerExampleConfigMatchesStruct fails if a shipped example config uses a
// key that no longer exists on the broker Config struct — the anti-drift guard
// for both the full reference (config.example.json) and the single-binary
// quickstart minimal config (config.minimal.example.json, docs/QUICKSTART.md).
func TestBrokerExampleConfigMatchesStruct(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"../../config.example.json", "../../config.minimal.example.json"} {
		t.Run(path, func(t *testing.T) {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read example: %v", err)
			}
			clean, err := confcheck.StripUnderscoreKeys(raw)
			if err != nil {
				t.Fatalf("strip comments: %v", err)
			}
			var cfg Config
			if err := confcheck.DecodeStrict(clean, &cfg); err != nil {
				t.Fatalf("%s has a key not in Config (doc/code drift?): %v", path, err)
			}
		})
	}
}
