package main

import (
	"context"
	"strings"
	"testing"
)

// TestBuildStateRejectsExcessiveGlobalMaxTTL is the regression test for the gap
// where the global max_ttl_seconds (unlike the per-host one, validated in
// CompileHostPolicies) was not checked at load, so a value above the 900s
// certificate cap made every issuance for an uncapped host fail at request
// time. buildState now rejects it up front.
func TestBuildStateRejectsExcessiveGlobalMaxTTL(t *testing.T) {
	t.Parallel()

	// 901s is over the 15m certificate cap: rejected at load with a clear error.
	if _, err := buildState(context.Background(), &Config{MaxTTLSeconds: 901}, nil); err == nil {
		t.Fatal("buildState accepted max_ttl_seconds=901 (over the 900s cap)")
	} else if !strings.Contains(err.Error(), "exceeds the 900s") {
		t.Fatalf("wrong rejection error: %v", err)
	}

	// 900s is exactly the cap and must pass the TTL gate — the build then fails
	// later (no CA key configured), which must NOT be the TTL error.
	if _, err := buildState(context.Background(), &Config{MaxTTLSeconds: 900}, nil); err == nil {
		t.Fatal("expected a later build error (missing CA key) for max_ttl_seconds=900")
	} else if strings.Contains(err.Error(), "exceeds the 900s") {
		t.Fatalf("max_ttl_seconds=900 must pass the TTL gate, got: %v", err)
	}
}
