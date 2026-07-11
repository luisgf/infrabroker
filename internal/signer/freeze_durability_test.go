package signer

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// copyMainDBFile copies ONLY the main SQLite database file (not the -wal/-shm
// sidecars). In WAL mode the main file is stable between checkpoints, so a copy
// taken while the source is open (never cleanly closed) is a faithful stand-in
// for what survives a power loss: the fsynced main db, minus the WAL frames that
// synchronous=NORMAL had not yet flushed.
func copyMainDBFile(t *testing.T, src, dst string) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read %s: %v", src, err)
	}
	if err := os.WriteFile(dst, b, 0o600); err != nil {
		t.Fatalf("write %s: %v", dst, err)
	}
}

// TestFreezeSurvivesSimulatedPowerLoss pins #210: a freeze committed via the API
// (Add returning success) must survive a power loss, not just an application
// crash. The state db runs synchronous=NORMAL (fsync only at a checkpoint), so
// without the durability checkpoint the committed freeze lived only in the
// un-fsynced WAL and vanished on power loss — the blocked subject regaining
// access (fail-open on break-glass).
//
// The source db is deliberately left OPEN throughout (never cleanly closed, which
// would checkpoint on close and mask the bug); "power loss" is modelled by copying
// only the main db file and reopening that copy.
func TestFreezeSurvivesSimulatedPowerLoss(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	db := openStateDB(t, dbPath)
	fs, err := NewFreezeStoreDB(db)
	if err != nil {
		t.Fatalf("NewFreezeStoreDB: %v", err)
	}

	subj := FreezeSubject{Kind: FreezeCaller, Value: "compromised"}
	if _, err := fs.Add(subj, "incident", "admin", time.Now()); err != nil {
		t.Fatalf("Add (the API returns 200 here): %v", err)
	}

	// Power loss right after the API returned 200: main db survives, WAL is lost.
	crashPath := filepath.Join(dir, "crash.db")
	copyMainDBFile(t, dbPath, crashPath)

	fs2, err := NewFreezeStoreDB(openStateDB(t, crashPath))
	if err != nil {
		t.Fatalf("reopen after power loss: %v", err)
	}
	if _, frozen := fs2.Frozen("compromised", ""); !frozen {
		t.Fatal("a committed freeze must survive power loss (WAL lost, main db intact) (#210)")
	}

	// An unfreeze is durable too: after Remove, the deletion must survive power
	// loss so a released subject is not re-blocked on restart. (Add checkpointed the
	// freeze into the main db, so without Remove's checkpoint the copy would still
	// carry it.)
	if _, err := fs.Remove(subj); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	crashPath2 := filepath.Join(dir, "crash2.db")
	copyMainDBFile(t, dbPath, crashPath2)

	fs3, err := NewFreezeStoreDB(openStateDB(t, crashPath2))
	if err != nil {
		t.Fatalf("reopen after unfreeze power loss: %v", err)
	}
	if _, frozen := fs3.Frozen("compromised", ""); frozen {
		t.Fatal("an unfreeze must survive power loss too (#210)")
	}
}
