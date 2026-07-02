package statedb

import (
	"os"
	"path/filepath"
	"testing"
)

var testMigrations = []string{
	`CREATE TABLE t (id TEXT PRIMARY KEY, v INTEGER NOT NULL);`,
	`ALTER TABLE t ADD COLUMN extra TEXT;`,
}

func TestOpenMigratesFromZero(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := Open(path, testMigrations)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != len(testMigrations) {
		t.Errorf("user_version = %d, want %d", version, len(testMigrations))
	}
	if _, err := db.Exec("INSERT INTO t (id, v, extra) VALUES ('a', 1, 'x')"); err != nil {
		t.Errorf("schema must include every migration: %v", err)
	}
}

func TestOpenIsIdempotentAndPreservesData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := Open(path, testMigrations[:1]) // old binary: schema v1
	if err != nil {
		t.Fatalf("Open v1: %v", err)
	}
	if _, err := db.Exec("INSERT INTO t (id, v) VALUES ('a', 1)"); err != nil {
		t.Fatal(err)
	}
	db.Close()

	// New binary applies only the pending migration and keeps the data.
	db, err = Open(path, testMigrations)
	if err != nil {
		t.Fatalf("Open v2: %v", err)
	}
	defer db.Close()
	var v int
	if err := db.QueryRow("SELECT v FROM t WHERE id = 'a'").Scan(&v); err != nil || v != 1 {
		t.Errorf("data must survive a migration: v=%d err=%v", v, err)
	}
}

func TestOpenRefusesNewerSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := Open(path, testMigrations)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	db.Close()

	// An older binary (fewer migrations) must refuse the newer database.
	if _, err := Open(path, testMigrations[:1]); err == nil {
		t.Fatal("a schema from a newer binary must be refused (fail-closed)")
	}
}

func TestOpenCorruptFileFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	if err := os.WriteFile(path, []byte("this is not a sqlite database at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, testMigrations); err == nil {
		t.Fatal("a corrupt database file must fail Open (fail-closed)")
	}
}
