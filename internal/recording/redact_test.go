package recording

import (
	"strings"
	"testing"
)

// maskRedactor is a trivial Redactor for tests, mirroring the real redact
// package's contract.
type maskRedactor struct{}

func (maskRedactor) Redact(s string) string {
	return strings.ReplaceAll(s, "hunter2", "[REDACTED:test]")
}

// TestRedactorMasksEvents verifies that a configured redactor masks input,
// output, and stderr event data before it reaches the .cast file.
func TestRedactorMasksEvents(t *testing.T) {
	r, path := openTmp(t)
	r.SetRedactor(maskRedactor{})

	if err := r.WriteInput("mysql -phunter2 app\n"); err != nil {
		t.Fatalf("WriteInput: %v", err)
	}
	if err := r.WriteOutput("Enter password: hunter2\r\n"); err != nil {
		t.Fatalf("WriteOutput: %v", err)
	}
	if err := r.WriteStderr("auth failed for hunter2\n"); err != nil {
		t.Fatalf("WriteStderr: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	lines := readLines(t, path)
	if len(lines) != 4 { // header + 3 events
		t.Fatalf("expected 4 lines, got %d", len(lines))
	}
	for i, l := range lines[1:] {
		if strings.Contains(l, "hunter2") {
			t.Errorf("event %d: secret survived redaction: %q", i, l)
		}
		if !strings.Contains(l, "[REDACTED:test]") {
			t.Errorf("event %d: marker missing: %q", i, l)
		}
	}
}

// TestNoRedactorUnchanged pins the nil-redactor behaviour: without SetRedactor
// the data is written verbatim (today's behaviour).
func TestNoRedactorUnchanged(t *testing.T) {
	r, path := openTmp(t)
	if err := r.WriteInput("mysql -phunter2\n"); err != nil {
		t.Fatalf("WriteInput: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	lines := readLines(t, path)
	if !strings.Contains(lines[1], "hunter2") {
		t.Errorf("without a redactor the data must be verbatim: %q", lines[1])
	}
}
