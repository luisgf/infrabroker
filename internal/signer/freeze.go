package signer

import (
	"database/sql"
	"fmt"
	"sync"
	"time"
)

// Freeze subject kinds. A frozen subject is denied on the signer decision path
// (/v1/sign, /v1/hosts) and drives the broker's live-session kill (#117).
const (
	FreezeCaller    = "caller"     // broker mTLS CN (or on_behalf_of identity)
	FreezeEndUser   = "end_user"   // asserted end-user identity
	FreezeSessionID = "session_id" // a specific live broker session
	FreezeSerial    = "serial"     // a specific issued certificate serial
)

// ValidFreezeKind reports whether kind is a recognised freeze subject kind.
func ValidFreezeKind(kind string) bool {
	switch kind {
	case FreezeCaller, FreezeEndUser, FreezeSessionID, FreezeSerial:
		return true
	}
	return false
}

// FreezeSubject identifies who/what is frozen. It is used as a map key, so it
// must stay comparable.
type FreezeSubject struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

// FrozenEntry is a FreezeSubject plus its provenance, returned by List and
// served on GET /v1/revocations.
type FrozenEntry struct {
	FreezeSubject
	Reason   string    `json:"reason,omitempty"`
	FrozenBy string    `json:"frozen_by"`
	FrozenAt time.Time `json:"frozen_at"`
}

// FreezeMigration is statedb migration #2 for the signer (grants is #1). Times
// are unix seconds. Append-only: never reorder or edit once shipped, or an
// existing database refuses to open under the old binary.
var FreezeMigration = `
CREATE TABLE freezes (
	kind      TEXT NOT NULL,
	value     TEXT NOT NULL,
	reason    TEXT NOT NULL DEFAULT '',
	frozen_by TEXT NOT NULL DEFAULT '',
	frozen_at INTEGER NOT NULL,
	PRIMARY KEY (kind, value)
);`

// StateMigrations is the ordered statedb migration list for the signer: grants
// (schema v0→1) then freezes (v1→2). Append-only — never reorder or edit a
// shipped entry.
func StateMigrations() []string {
	out := make([]string, 0, len(GrantSchema)+1)
	out = append(out, GrantSchema...)
	out = append(out, FreezeMigration)
	return out
}

// FreezeStore is an in-memory, concurrency-safe set of frozen subjects. Its
// persistence discipline is the INVERSE of the GrantStore's: a lost grant fails
// safe (policy narrows to the file baseline), but a lost freeze fails OPEN — a
// subject the operator blocked silently regains access. So the load path is
// fail-closed (any read error aborts startup rather than starting with a partial
// set) and mutations are durable (insert/delete first, fail the caller on a db
// error), never best-effort.
type FreezeStore struct {
	mu     sync.Mutex
	frozen map[FreezeSubject]FrozenEntry
	db     *sql.DB // nil = memory-only (does NOT survive restart; set state_db in prod)
}

// NewFreezeStore returns an empty memory-only store. Without a state db a freeze
// does not survive a restart, which fails OPEN, so production deployments must
// set state_db (see [NewFreezeStoreDB]).
func NewFreezeStore() *FreezeStore {
	return &FreezeStore{frozen: map[FreezeSubject]FrozenEntry{}}
}

// NewFreezeStoreDB returns a store backed by db, preloaded with every persisted
// freeze. Fail-closed: any read/scan error — or a row whose kind this binary
// does not recognise (written by a newer binary) — aborts with an error rather
// than starting with a partial freeze set, because a dropped freeze silently
// restores access to a subject the operator blocked.
func NewFreezeStoreDB(db *sql.DB) (*FreezeStore, error) {
	s := &FreezeStore{frozen: map[FreezeSubject]FrozenEntry{}, db: db}
	rows, err := db.Query(`SELECT kind, value, reason, frozen_by, frozen_at FROM freezes`)
	if err != nil {
		return nil, fmt.Errorf("loading freezes: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			e        FrozenEntry
			frozenAt int64
		)
		if err := rows.Scan(&e.Kind, &e.Value, &e.Reason, &e.FrozenBy, &frozenAt); err != nil {
			return nil, fmt.Errorf("scanning freeze row: %w", err)
		}
		if !ValidFreezeKind(e.Kind) {
			return nil, fmt.Errorf("freeze row has unknown kind %q (state db written by a newer binary?)", e.Kind)
		}
		e.FrozenAt = time.Unix(frozenAt, 0).UTC()
		s.frozen[e.FreezeSubject] = e
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("loading freezes: %w", err)
	}
	return s, nil
}

// Volatile reports whether this store is memory-only (no state db). A freeze in
// a volatile store does NOT survive a signer restart, so it fails OPEN — the
// freeze handler requires an explicit opt-in (allow_volatile) before accepting
// one, and production deployments should set state_db instead.
func (s *FreezeStore) Volatile() bool { return s.db == nil }

// Add freezes subj. Write-through, insert-first: if it cannot be persisted the
// call fails and the in-memory set does not diverge from disk (an in-memory-only
// freeze would vanish on restart — fail-open). Re-freezing a subject refreshes
// its reason/provenance. Returns whether the subject was newly frozen.
func (s *FreezeStore) Add(subj FreezeSubject, reason, by string, now time.Time) (bool, error) {
	if !ValidFreezeKind(subj.Kind) {
		return false, fmt.Errorf("invalid freeze kind %q", subj.Kind)
	}
	if subj.Value == "" {
		return false, fmt.Errorf("freeze value must not be empty")
	}
	e := FrozenEntry{FreezeSubject: subj, Reason: reason, FrozenBy: by, FrozenAt: now.UTC()}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db != nil {
		if _, err := s.db.Exec(`INSERT INTO freezes (kind, value, reason, frozen_by, frozen_at)
			VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(kind, value) DO UPDATE SET
				reason=excluded.reason, frozen_by=excluded.frozen_by, frozen_at=excluded.frozen_at`,
			subj.Kind, subj.Value, reason, by, e.FrozenAt.Unix()); err != nil {
			return false, fmt.Errorf("persisting freeze: %w", err)
		}
	}
	_, existed := s.frozen[subj]
	s.frozen[subj] = e
	return !existed, nil
}

// Remove unfreezes subj. The db delete is durable (delete-first, fail the caller
// on error): a freeze that survives on disk after a successful-looking unfreeze
// would resurrect on restart and keep denying a subject the operator released.
// Returns whether the subject was frozen.
func (s *FreezeStore) Remove(subj FreezeSubject) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.frozen[subj]; !ok {
		return false, nil
	}
	if s.db != nil {
		if _, err := s.db.Exec(`DELETE FROM freezes WHERE kind = ? AND value = ?`, subj.Kind, subj.Value); err != nil {
			return false, fmt.Errorf("removing freeze in state db: %w", err)
		}
	}
	delete(s.frozen, subj)
	return true, nil
}

// Frozen reports whether the caller CN or the asserted end user is frozen,
// returning the matching subject. Consulted on the signer decision path; an
// empty caller or endUser skips that half of the check. A nil store (only test
// doubles — main always constructs one) reports "not frozen".
func (s *FreezeStore) Frozen(caller, endUser string) (FreezeSubject, bool) {
	if s == nil {
		return FreezeSubject{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if caller != "" {
		subj := FreezeSubject{Kind: FreezeCaller, Value: caller}
		if _, ok := s.frozen[subj]; ok {
			return subj, true
		}
	}
	if endUser != "" {
		subj := FreezeSubject{Kind: FreezeEndUser, Value: endUser}
		if _, ok := s.frozen[subj]; ok {
			return subj, true
		}
	}
	return FreezeSubject{}, false
}

// List returns every frozen subject with provenance, for GET /v1/revocations and
// operator listing. A nil store (test doubles only) returns no entries.
func (s *FreezeStore) List() []FrozenEntry {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]FrozenEntry, 0, len(s.frozen))
	for _, e := range s.frozen {
		out = append(out, e)
	}
	return out
}
