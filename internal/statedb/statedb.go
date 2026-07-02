// Package statedb opens the embedded SQLite database that persists a
// service's dynamic state across restarts (the signer's runtime grants, the
// control plane's approval registry). The driver is modernc.org/sqlite — pure
// Go, no CGO, no system dependency — so the static release builds are
// unaffected.
//
// The database is an availability enhancement, not a decision-path component:
// consumers keep their in-memory state as the source of truth on the hot path
// and mirror mutations here (write-through). Losing a best-effort write fails
// safe — the state re-derives to something more restrictive.
package statedb

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

// Consumers report best-effort persistence failures on the shared
// "statedb_errors_total" counter (monitor.GetCounter is get-or-create), so
// this package stays a thin opener: only the driver and the migration runner
// live here, and the sqlite driver is linked only into the binaries that
// actually persist state.

// Open opens (or creates) the state database at path and applies the pending
// migrations. migrations[i] brings the schema from user_version i to i+1;
// each runs in its own transaction. A database whose user_version is beyond
// len(migrations) was written by a newer binary and is refused (fail-closed —
// same criterion as an unreadable audit key).
//
// The connection pool is capped at one connection: every consumer mutates
// under its own mutex (single writer), and a single connection sidesteps
// SQLITE_BUSY between concurrent readers and the writer.
func Open(path string, migrations []string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("statedb: open %s: %w", path, err)
	}
	db.SetMaxOpenConns(1)

	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",   // readers never block the writer; -wal/-shm sidecar files
		"PRAGMA busy_timeout=5000",  // wait up to 5s instead of failing on a transient lock
		"PRAGMA synchronous=NORMAL", // fsync at checkpoint; safe with WAL, much cheaper than FULL
		"PRAGMA foreign_keys=ON",
	} {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("statedb: %s: %w", pragma, err)
		}
	}

	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		db.Close()
		return nil, fmt.Errorf("statedb: reading user_version: %w", err)
	}
	if version > len(migrations) {
		db.Close()
		return nil, fmt.Errorf("statedb: %s is at schema version %d, newer than this binary supports (%d)",
			path, version, len(migrations))
	}
	for i := version; i < len(migrations); i++ {
		tx, err := db.Begin()
		if err != nil {
			db.Close()
			return nil, fmt.Errorf("statedb: migration %d→%d: %w", i, i+1, err)
		}
		if _, err := tx.Exec(migrations[i]); err != nil {
			tx.Rollback()
			db.Close()
			return nil, fmt.Errorf("statedb: migration %d→%d: %w", i, i+1, err)
		}
		if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version=%d", i+1)); err != nil {
			tx.Rollback()
			db.Close()
			return nil, fmt.Errorf("statedb: migration %d→%d: setting user_version: %w", i, i+1, err)
		}
		if err := tx.Commit(); err != nil {
			db.Close()
			return nil, fmt.Errorf("statedb: migration %d→%d: commit: %w", i, i+1, err)
		}
	}
	return db, nil
}
