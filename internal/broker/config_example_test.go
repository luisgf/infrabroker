package broker

import (
	"os"
	"path/filepath"
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

// TestLoadConfigAcceptsJSONC proves the broker's real load path (LoadConfig →
// confcheck.Strict) accepts // and /* */ comments and a trailing comma (#183).
func TestLoadConfigAcceptsJSONC(t *testing.T) {
	t.Parallel()
	p := filepath.Join(t.TempDir(), "config.json")
	jsonc := "{\n" +
		"  // canonical comment style\n" +
		"  \"listen\": \":9000\",       // trailing line comment\n" +
		"  \"max_ttl_seconds\": 60,   /* block */\n" +
		"}\n"
	if err := os.WriteFile(p, []byte(jsonc), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatalf("a JSONC config.json must load: %v", err)
	}
	if cfg.Listen != ":9000" || cfg.MaxTTLSeconds != 60 {
		t.Errorf("JSONC values must decode: listen=%q ttl=%d", cfg.Listen, cfg.MaxTTLSeconds)
	}
}
