package broker

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/luisgf/infrabroker/internal/audit"
)

// brokenAuditLog returns an opened audit log whose backing directory has been
// removed, so the next Append fails — models an unwritable sink for the
// fail-closed tests.
func brokenAuditLog(t *testing.T) *audit.Log {
	t.Helper()
	dir := t.TempDir()
	seed := make([]byte, ed25519.SeedSize)
	al, err := audit.Open(filepath.Join(dir, "audit.log"), ed25519.NewKeyFromSeed(seed))
	if err != nil {
		t.Fatalf("audit open: %v", err)
	}
	al.Close()
	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("remove audit dir: %v", err)
	}
	return al
}

// TestEngineAuditFailMode covers auditE, the funnel every action-completion site
// checks: closed mode denies (ErrAuditUnavailable so the caller withholds the
// result), open mode logs and proceeds.
func TestEngineAuditFailMode(t *testing.T) {
	t.Parallel()
	closed := &Engine{cfg: &Config{}, auditLog: brokenAuditLog(t), auditFailClosed: true}
	if err := closed.auditE(audit.Entry{Host: "web01", Outcome: "executed"}); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("closed mode must return ErrAuditUnavailable, got %v", err)
	}
	open := &Engine{cfg: &Config{}, auditLog: brokenAuditLog(t), auditFailClosed: false}
	if err := open.auditE(audit.Entry{Host: "web01", Outcome: "executed"}); err != nil {
		t.Fatalf("open mode must proceed, got %v", err)
	}
}
