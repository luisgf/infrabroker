package main

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luisgf/infrabroker/internal/audit"
)

// buildRecommendLog writes three signed, chained entries (uptime, df -h,
// uptime) and returns the path and the signing key.
func buildRecommendLog(t *testing.T) (string, ed25519.PrivateKey) {
	t.Helper()
	key := testAuditKey()
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := audit.Open(path, key)
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	for _, cmd := range []string{"uptime", "df -h", "uptime"} {
		if err := l.Append(audit.Entry{Caller: "broker-1", Host: "web01", Command: cmd, Outcome: "executed"}); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	l.Close()
	return path, key
}

func commandsOf(entries []audit.Entry) []string {
	var out []string
	for _, e := range entries {
		out = append(out, e.Command)
	}
	return out
}

// TestLoadAuditEntriesRejectsTamperedLine locks in #454: a line edited in place
// (here the command of entry 2, signature left as-is) must be rejected when the
// audit key is given, and the skipped count must be reported — previously
// loadAuditEntries fed the tampered command to policyrec verbatim.
func TestLoadAuditEntriesRejectsTamperedLine(t *testing.T) {
	path, key := buildRecommendLog(t)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Replace(data, []byte(`"command":"df -h"`), []byte(`"command":"rm -rf /srv"`), 1)
	if bytes.Equal(tampered, data) {
		t.Fatal("test setup: tamper target not found")
	}
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}

	var warn bytes.Buffer
	entries, skipped := loadAuditEntries(path, key.Public().(ed25519.PublicKey), &warn)

	// Entry 2 fails its signature; entry 3's prev_hash no longer matches the
	// rewritten line 2. Only the untouched entry 1 may be mined.
	if skipped != 2 {
		t.Errorf("skipped = %d, want 2 (tampered line + the line chained to it); warn:\n%s", skipped, warn.String())
	}
	if got := commandsOf(entries); len(got) != 1 || got[0] != "uptime" {
		t.Errorf("mined commands = %q, want only the untouched first entry", got)
	}
	for _, e := range entries {
		if e.Command == "rm -rf /srv" {
			t.Fatal("tampered entry must never be mined")
		}
	}
	out := warn.String()
	if !strings.Contains(out, "signature invalid") {
		t.Errorf("the bad signature must be reported; got:\n%s", out)
	}
	if !strings.Contains(out, "2 line(s) of "+path+" skipped") {
		t.Errorf("the skipped count must be reported; got:\n%s", out)
	}

	// Without the key (--unverified) the signature is not checked, so the edited
	// line itself passes and only the chain break after it is caught — which is
	// exactly why the key is required unless --unverified is asked for.
	warn.Reset()
	entries, skipped = loadAuditEntries(path, nil, &warn)
	if skipped != 1 {
		t.Errorf("unverified: skipped = %d, want 1 (only the chain break)", skipped)
	}
	if got := commandsOf(entries); len(got) != 2 || got[1] != "rm -rf /srv" {
		t.Errorf("unverified: mined commands = %q, want the edited line to slip through (documents the --unverified risk)", got)
	}
}

// TestLoadAuditEntriesCountsMalformedLines: a malformed line is no longer
// dropped silently — it is counted and reported, and the intact chain around it
// is still mined.
func TestLoadAuditEntriesCountsMalformedLines(t *testing.T) {
	path, key := buildRecommendLog(t)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("{not json\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()

	var warn bytes.Buffer
	entries, skipped := loadAuditEntries(path, key.Public().(ed25519.PublicKey), &warn)
	if skipped != 1 {
		t.Errorf("skipped = %d, want 1; warn:\n%s", skipped, warn.String())
	}
	if len(entries) != 3 {
		t.Errorf("mined %d entries, want the 3 intact ones", len(entries))
	}
	if out := warn.String(); !strings.Contains(out, "malformed JSON") || !strings.Contains(out, "1 line(s) of "+path+" skipped") {
		t.Errorf("malformed line and skipped count must be reported; got:\n%s", out)
	}

	// A clean log is silent.
	clean, _ := buildRecommendLog(t)
	warn.Reset()
	entries, skipped = loadAuditEntries(clean, key.Public().(ed25519.PublicKey), &warn)
	if skipped != 0 || len(entries) != 3 || warn.Len() != 0 {
		t.Errorf("clean log: skipped=%d entries=%d warn=%q", skipped, len(entries), warn.String())
	}
}

// TestAuditPubFromSeedMatchesAuditVerify: --key has the same contract as
// `audit verify --key` (first ed25519.SeedSize bytes of the seed file).
func TestAuditPubFromSeedMatchesAuditVerify(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 0x02
	}
	p := filepath.Join(t.TempDir(), "audit.seed")
	if err := os.WriteFile(p, append(seed, []byte("trailing-ignored")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if !auditPubFromSeed(p).Equal(testAuditKey().Public().(ed25519.PublicKey)) {
		t.Error("auditPubFromSeed must derive the same public key as audit verify")
	}
}
