package audit

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// maskRedactor is a trivial Redactor for tests: it replaces every occurrence
// of "hunter2" with a marker, mirroring the real redact package's contract.
type maskRedactor struct{}

func (maskRedactor) Redact(s string) string {
	return strings.ReplaceAll(s, "hunter2", "[REDACTED:test]")
}

// TestAppendRedactaCamposLibres verifies that a configured redactor masks the
// free-text fields (Command, Err, Warning, Anomaly) in the persisted line and
// leaves the metadata fields untouched.
func TestAppendRedactaCamposLibres(t *testing.T) {
	t.Parallel()
	l, path := openTmp(t)
	l.SetRedactor(maskRedactor{})

	if err := l.Append(Entry{
		Caller:  "agent",
		Host:    "db01",
		Command: "mysql -phunter2 app",
		Err:     "exec failed: mysql -phunter2",
		Warning: "would_deny: mysql -phunter2",
		Anomaly: "new-command:mysql -phunter2",
		Outcome: "executed",
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}

	entries := readEntries(t, path)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	e := entries[0].e
	for name, got := range map[string]string{
		"Command": e.Command, "Err": e.Err, "Warning": e.Warning, "Anomaly": e.Anomaly,
	} {
		if strings.Contains(got, "hunter2") {
			t.Errorf("%s: secret survived redaction: %q", name, got)
		}
		if !strings.Contains(got, "[REDACTED:test]") {
			t.Errorf("%s: marker missing: %q", name, got)
		}
	}
	if strings.Contains(string(entries[0].raw), "hunter2") {
		t.Error("secret present in the raw persisted line")
	}
	if e.Caller != "agent" || e.Host != "db01" || e.Outcome != "executed" {
		t.Errorf("metadata fields must not be altered: %+v", e)
	}
}

// TestAppendFirmaCubreContenidoRedactado verifies that the Ed25519 signature
// is computed over the REDACTED content: the persisted line must verify as-is,
// so redaction is invisible to `broker-ctl audit verify` and the chain.
func TestAppendFirmaCubreContenidoRedactado(t *testing.T) {
	t.Parallel()
	key := testKey()
	pub := key.Public().(ed25519.PublicKey)

	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := Open(path, key)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer l.Close()
	l.SetRedactor(maskRedactor{})

	if err := l.Append(Entry{Outcome: "executed", Command: "mysql -phunter2"}); err != nil {
		t.Fatalf("Append: %v", err)
	}

	entries := readEntries(t, path)
	e := entries[0].e
	sigBytes, err := base64.StdEncoding.DecodeString(e.Sig)
	if err != nil {
		t.Fatalf("signature is not base64: %v", err)
	}
	e.Sig = ""
	payload, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal for verification: %v", err)
	}
	if !ed25519.Verify(pub, payload, sigBytes) {
		t.Error("signature must verify over the redacted content")
	}
}
