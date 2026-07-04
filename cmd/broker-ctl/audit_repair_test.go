package main

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/luisgf/infrabroker/internal/audit"
)

func rec(seq int) string { return fmt.Sprintf(`{"seq":%d,"outcome":"executed"}`, seq) }

func TestAuditTrailingCorruption(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		data        string
		wantGood    int
		wantLastSeq uint64
		wantCorrupt string // expected corruptTail contents ("" = none)
		wantMiddle  bool
	}{
		{"clean", rec(1) + "\n" + rec(2) + "\n", 2, 2, "", false},
		{"torn_tail", rec(1) + "\n" + rec(2) + "\n" + `{"seq":3,"outc`, 2, 2, `{"seq":3,"outc`, false},
		{"complete_no_newline", rec(1) + "\n" + rec(2), 2, 2, "", false},
		{"middle_corruption", rec(1) + "\n" + "garbage\n" + rec(3) + "\n", 1, 1, "", true},
		{"all_corrupt", "garbage-line\n", 0, 0, "garbage-line\n", false},
		{"trailing_blank", rec(1) + "\n\n", 1, 1, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cleanEnd, lastSeq, good, corrupt, middle := auditTrailingCorruption([]byte(c.data))
			if good != c.wantGood || lastSeq != c.wantLastSeq || middle != c.wantMiddle {
				t.Errorf("good=%d lastSeq=%d middle=%v; want %d/%d/%v", good, lastSeq, middle, c.wantGood, c.wantLastSeq, c.wantMiddle)
			}
			if string(corrupt) != c.wantCorrupt {
				t.Errorf("corruptTail=%q; want %q", corrupt, c.wantCorrupt)
			}
			// cleanEnd must point exactly past the kept prefix.
			if string(corrupt) != "" && cleanEnd != len(c.data)-len(c.wantCorrupt) {
				t.Errorf("cleanEnd=%d; want %d", cleanEnd, len(c.data)-len(c.wantCorrupt))
			}
		})
	}
}

// TestAuditRepairEndToEnd reproduces the #101 startup brick (a torn final
// record makes audit.Open fail) and proves that `audit repair --apply`
// quarantines the corrupt bytes, restores bootability, and keeps the chain
// verifiable.
func TestAuditRepairEndToEnd(t *testing.T) {
	path, key := buildLog(t, 3)
	good, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read good log: %v", err)
	}

	// Simulate a torn write: a truncated JSON record with no closing brace and
	// no trailing newline appended after the last good record.
	torn := append(append([]byte{}, good...), []byte(`{"seq":4,"caller":"x","comm`)...)
	if err := os.WriteFile(path, torn, 0o600); err != nil {
		t.Fatalf("write torn log: %v", err)
	}

	// Repro: the signer path (audit.Open -> restoreChain) refuses to boot.
	if _, err := audit.Open(path, key); err == nil {
		t.Fatal("expected audit.Open to fail on a torn trailing record (repro #101)")
	}

	// Recover with the explicit operator command.
	cmdAuditRepair([]string{"--log", path, "--apply"})

	// The signer can boot again.
	l, err := audit.Open(path, key)
	if err != nil {
		t.Fatalf("audit.Open after repair still fails: %v", err)
	}
	l.Close()

	// The repaired file is exactly the well-formed prefix.
	repaired, _ := os.ReadFile(path)
	if !bytes.Equal(repaired, good) {
		t.Errorf("repaired file != good prefix\n got  %q\n want %q", repaired, good)
	}

	// The chain still verifies end to end (signatures included).
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open repaired log: %v", err)
	}
	defer f.Close()
	if _, errs := verifyAuditChain(f, key.Public().(ed25519.PublicKey), func(string, ...any) {}); errs != 0 {
		t.Errorf("repaired log fails verification: %d error(s)", errs)
	}

	// The torn bytes are preserved in a single quarantine sidecar (forensics).
	matches, _ := filepath.Glob(path + ".corrupt-*")
	if len(matches) != 1 {
		t.Fatalf("expected exactly 1 quarantine file, got %d: %v", len(matches), matches)
	}
	qb, _ := os.ReadFile(matches[0])
	if !bytes.Contains(qb, []byte(`"seq":4`)) {
		t.Errorf("quarantine file missing the torn bytes: %q", qb)
	}
}

// TestAuditRepairCleanLogIsNoop confirms repair does not touch a healthy log.
func TestAuditRepairCleanLogIsNoop(t *testing.T) {
	path, _ := buildLog(t, 2)
	before, _ := os.ReadFile(path)
	cmdAuditRepair([]string{"--log", path}) // dry-run
	cmdAuditRepair([]string{"--log", path, "--apply"})
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Error("repair modified a clean log")
	}
	if matches, _ := filepath.Glob(path + ".corrupt-*"); len(matches) != 0 {
		t.Errorf("repair quarantined bytes from a clean log: %v", matches)
	}
}
