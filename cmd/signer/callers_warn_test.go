package main

import (
	"bytes"
	"context"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/luisgf/infrabroker/internal/signer"
)

// TestBuildStateWarnsOnEmptyCallers pins #207: an empty callers table is the one
// genuine fail-open RBAC config (allow-all), so the signer warns at boot. buildState
// fails later (no CA configured) but the warning is emitted before that, which is
// all we assert. Not parallel: it swaps the global log output.
func TestBuildStateWarnsOnEmptyCallers(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	// Empty callers table → allow-all warning.
	_, _ = buildState(context.Background(), &Config{}, nil)
	if !strings.Contains(buf.String(), "allow-all") {
		t.Errorf("empty callers table must log an allow-all warning; log was:\n%s", buf.String())
	}

	// A non-empty callers table must NOT warn allow-all.
	buf.Reset()
	_, _ = buildState(context.Background(), &Config{Callers: signer.CallerTable{"brk": {}}}, nil)
	if strings.Contains(buf.String(), "allow-all") {
		t.Errorf("a non-empty callers table must not log allow-all; log was:\n%s", buf.String())
	}
}
