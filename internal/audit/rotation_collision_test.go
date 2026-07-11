package audit

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestRotatedSegmentPathCollisionAvoidance pins #257: rotatedSegmentPath never
// returns a path that already exists, so a same-second rotation cannot rename
// over (and destroy) a prior segment. The first name is the plain timestamp
// (backward-compatible with pre-fix segments); collisions get a ".<n>" suffix.
func TestRotatedSegmentPathCollisionAvoidance(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	ts := time.Date(2026, 7, 11, 10, 22, 24, 0, time.UTC)
	base := logPath + ".20260711T102224Z"

	if got := rotatedSegmentPath(logPath, ts); got != base {
		t.Fatalf("first rotation path = %q, want %q", got, base)
	}
	mustTouch(t, base)
	if got := rotatedSegmentPath(logPath, ts); got != base+".1" {
		t.Fatalf("second same-second rotation = %q, want %q", got, base+".1")
	}
	mustTouch(t, base+".1")
	if got := rotatedSegmentPath(logPath, ts); got != base+".2" {
		t.Fatalf("third same-second rotation = %q, want %q", got, base+".2")
	}
}

func mustTouch(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("x\n"), 0o600); err != nil {
		t.Fatalf("touch %s: %v", path, err)
	}
}

// TestIsRotatedSegment pins that discovery recognises exactly what rotation
// writes — the timestamp, optionally with a ".<n>" disambiguator — and nothing
// else (notably the audit-repair quarantine file).
func TestIsRotatedSegment(t *testing.T) {
	for _, c := range []struct {
		suffix string
		want   bool
	}{
		{"20260711T102224Z", true},          // base
		{"20260711T102224Z.1", true},        // same-second disambiguator
		{"20260711T102224Z.42", true},       // multi-digit
		{"corrupt-20260711T102224Z", false}, // audit-repair quarantine
		{"20260711T102224Z.", false},        // trailing dot, no digits
		{"20260711T102224Z.x", false},       // non-numeric suffix
		{"20260711T102224Z.1.2", false},     // second dot
		{"notatimestamp", false},
		{"", false},
	} {
		if got := isRotatedSegment(c.suffix); got != c.want {
			t.Errorf("isRotatedSegment(%q) = %v, want %v", c.suffix, got, c.want)
		}
	}
}

// TestRotationSameSecondNoRecordLoss pins the end-to-end #257 fix: many rotations
// within the same second must each land in a distinct segment, so no records are
// lost and the cross-segment chain still verifies. Before the fix, same-second
// rotations renamed onto one filename and silently overwrote prior segments.
func TestRotationSameSecondNoRecordLoss(t *testing.T) {
	l, path := openTmp(t)
	l.maxFileSize = 1 // every append after a non-empty file rotates the previous one

	const n = 6
	for i := 0; i < n; i++ {
		if err := l.Append(Entry{Caller: "c", Host: "h:22", Command: "id", Outcome: "executed"}); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	l.Close()

	total, errs := VerifySegments(path, pub(testKey()), discardReport)
	if total != n || errs != 0 {
		t.Fatalf("VerifySegments = (%d,%d); want (%d,0) — same-second rotations lost records (#257)", total, errs, n)
	}
}
