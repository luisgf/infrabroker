package signer

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/luisgf/infrabroker/internal/statedb"
)

// openStateDB opens (or reopens) a state db with the full signer migration set
// (grants + freezes).
func openStateDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := statedb.Open(path, StateMigrations())
	if err != nil {
		t.Fatalf("statedb.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestFreezeStoreMemoryBasic(t *testing.T) {
	t.Parallel()
	s := NewFreezeStore()
	now := time.Now()

	newly, err := s.Add(FreezeSubject{Kind: FreezeCaller, Value: "brk1"}, "incident", "admin", now)
	if err != nil || !newly {
		t.Fatalf("Add caller: newly=%v err=%v", newly, err)
	}
	// Re-freeze refreshes provenance, reports not-newly.
	if newly, err := s.Add(FreezeSubject{Kind: FreezeCaller, Value: "brk1"}, "incident2", "admin", now); err != nil || newly {
		t.Fatalf("re-Add caller: newly=%v err=%v (want newly=false)", newly, err)
	}

	if subj, ok := s.Frozen("brk1", ""); !ok || subj.Kind != FreezeCaller || subj.Value != "brk1" {
		t.Fatalf("Frozen(brk1) = %+v, %v; want caller=brk1, true", subj, ok)
	}
	if _, ok := s.Frozen("brk2", ""); ok {
		t.Error("brk2 must not be frozen")
	}
	if _, ok := s.Frozen("", "alice"); ok {
		t.Error("end user alice must not be frozen yet")
	}

	if _, err := s.Add(FreezeSubject{Kind: FreezeEndUser, Value: "alice"}, "", "admin", now); err != nil {
		t.Fatalf("Add end_user: %v", err)
	}
	if _, ok := s.Frozen("brk2", "alice"); !ok {
		t.Error("Frozen must match on end_user even when caller is not frozen")
	}

	if len(s.List()) != 2 {
		t.Fatalf("List len = %d, want 2", len(s.List()))
	}

	existed, err := s.Remove(FreezeSubject{Kind: FreezeCaller, Value: "brk1"})
	if err != nil || !existed {
		t.Fatalf("Remove: existed=%v err=%v", existed, err)
	}
	if _, ok := s.Frozen("brk1", ""); ok {
		t.Error("brk1 must not be frozen after Remove")
	}
	if existed, _ := s.Remove(FreezeSubject{Kind: FreezeCaller, Value: "brk1"}); existed {
		t.Error("second Remove must report not-existed")
	}
}

// TestFreezeStoreSessionSerialNotOnSignPath: session_id/serial freezes are for
// the broker's live-session kill; the signer sign-path check (Frozen) must not
// match them (a new sign carries neither).
func TestFreezeStoreSessionSerialNotOnSignPath(t *testing.T) {
	t.Parallel()
	s := NewFreezeStore()
	now := time.Now()
	_, _ = s.Add(FreezeSubject{Kind: FreezeSessionID, Value: "sess-123"}, "", "admin", now)
	_, _ = s.Add(FreezeSubject{Kind: FreezeSerial, Value: "42"}, "", "admin", now)

	// Passing those values as caller/end_user must NOT be treated as frozen:
	// Frozen only checks the caller/end_user kinds.
	if _, ok := s.Frozen("sess-123", "42"); ok {
		t.Error("Frozen must not match a session_id/serial value on the sign path")
	}
	if len(s.List()) != 2 {
		t.Fatalf("List len = %d, want 2 (both stored for the broker)", len(s.List()))
	}
}

func TestFreezeStoreInvalidInput(t *testing.T) {
	t.Parallel()
	s := NewFreezeStore()
	now := time.Now()
	if _, err := s.Add(FreezeSubject{Kind: "bogus", Value: "x"}, "", "admin", now); err == nil {
		t.Error("Add with invalid kind must fail")
	}
	if _, err := s.Add(FreezeSubject{Kind: FreezeCaller, Value: ""}, "", "admin", now); err == nil {
		t.Error("Add with empty value must fail")
	}
}

func TestFreezeStoreSurvivesRestart(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "state.db")
	now := time.Now()

	s1, err := NewFreezeStoreDB(openStateDB(t, path))
	if err != nil {
		t.Fatalf("NewFreezeStoreDB: %v", err)
	}
	if _, err := s1.Add(FreezeSubject{Kind: FreezeCaller, Value: "brk1"}, "incident", "admin", now); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, err := s1.Add(FreezeSubject{Kind: FreezeSessionID, Value: "sess-9"}, "", "admin", now); err != nil {
		t.Fatalf("Add session: %v", err)
	}

	// "Restart": a new store over the same db.
	s2, err := NewFreezeStoreDB(openStateDB(t, path))
	if err != nil {
		t.Fatalf("NewFreezeStoreDB after restart: %v", err)
	}
	if _, ok := s2.Frozen("brk1", ""); !ok {
		t.Error("caller freeze must survive restart")
	}
	if len(s2.List()) != 2 {
		t.Errorf("List len after restart = %d, want 2", len(s2.List()))
	}
}

func TestFreezeStoreRemoveDurable(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "state.db")
	now := time.Now()

	s1, err := NewFreezeStoreDB(openStateDB(t, path))
	if err != nil {
		t.Fatalf("NewFreezeStoreDB: %v", err)
	}
	subj := FreezeSubject{Kind: FreezeCaller, Value: "brk1"}
	if _, err := s1.Add(subj, "", "admin", now); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, err := s1.Remove(subj); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	// A removed freeze must NOT resurrect on restart (durable delete).
	s2, err := NewFreezeStoreDB(openStateDB(t, path))
	if err != nil {
		t.Fatalf("NewFreezeStoreDB after restart: %v", err)
	}
	if _, ok := s2.Frozen("brk1", ""); ok {
		t.Error("a removed freeze must not resurrect on restart")
	}
}

// TestFreezeStoreLoadFailClosed: a persisted row this binary cannot enforce
// (unknown kind, e.g. written by a newer binary) must abort the load rather than
// starting with a partial freeze set that silently un-freezes a subject.
func TestFreezeStoreLoadFailClosed(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "state.db")
	db := openStateDB(t, path)
	if _, err := db.Exec(`INSERT INTO freezes (kind, value, frozen_at) VALUES ('future_kind', 'x', ?)`, time.Now().Unix()); err != nil {
		t.Fatalf("seed row: %v", err)
	}
	if _, err := NewFreezeStoreDB(db); err == nil {
		t.Fatal("NewFreezeStoreDB must fail closed on an unknown freeze kind")
	}
}

func TestGrantStoreRevokeForSubject(t *testing.T) {
	t.Parallel()
	s := NewGrantStore()
	exp := time.Now().Add(time.Hour)
	mustAdd := func(g Grant) {
		t.Helper()
		if _, err := s.Add(g); err != nil {
			t.Fatalf("Add grant: %v", err)
		}
	}
	mustAdd(Grant{Host: "h1", Allow: []string{"^ls"}, Caller: "brk1", ExpiresAt: exp})
	mustAdd(Grant{Host: "h1", Allow: []string{"^cat"}, EndUser: "alice", ExpiresAt: exp})
	mustAdd(Grant{Host: "h1", Allow: []string{"^df"}, ExpiresAt: exp}) // host-wide

	// Freezing caller brk1 removes only the brk1-scoped grant.
	n, err := s.RevokeForSubject(FreezeCaller, "brk1")
	if err != nil || n != 1 {
		t.Fatalf("RevokeForSubject(caller brk1) = %d, %v; want 1, nil", n, err)
	}
	if got := len(s.List(time.Now())); got != 2 {
		t.Fatalf("after revoke: %d grants, want 2 (host-wide + alice)", got)
	}

	// Freezing end_user alice removes the alice-scoped grant; host-wide stays.
	n, err = s.RevokeForSubject(FreezeEndUser, "alice")
	if err != nil || n != 1 {
		t.Fatalf("RevokeForSubject(end_user alice) = %d, %v; want 1, nil", n, err)
	}
	remaining := s.List(time.Now())
	if len(remaining) != 1 || remaining[0].Host != "h1" || remaining[0].Caller != "" || remaining[0].EndUser != "" {
		t.Fatalf("host-wide grant must survive; remaining=%+v", remaining)
	}

	// session_id/serial kinds match no grants.
	if n, err := s.RevokeForSubject(FreezeSessionID, "sess-1"); err != nil || n != 0 {
		t.Fatalf("RevokeForSubject(session_id) = %d, %v; want 0, nil", n, err)
	}
}
