package signer

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/luisgf/infrabroker/internal/statedb"
)

// openGrantDB opens a fresh state db (or reopens an existing one) with the
// grant schema.
func openGrantDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := statedb.Open(path, GrantSchema)
	if err != nil {
		t.Fatalf("statedb.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// TestGrantStoreSurvivesRestart pins the whole point of the state db: a grant
// and an approval waiver added before a "restart" (new store over the same
// db) are still live and still decide identically afterwards.
func TestGrantStoreSurvivesRestart(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "state.db")
	now := time.Now()

	s1, err := NewGrantStoreDB(openGrantDB(t, path))
	if err != nil {
		t.Fatalf("NewGrantStoreDB: %v", err)
	}
	allowID, err := s1.Add(Grant{Host: "web01", Allow: []string{"^systemctl restart nginx$"},
		GrantedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatalf("add allow grant: %v", err)
	}
	_, err = s1.Add(Grant{Host: "web01", WaiveApproval: []string{`^\Qreboot\E$`},
		Caller: "broker-1", EndUser: "alice", Sudo: true,
		Approver: "admin", ApprovalID: "ap-1",
		GrantedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatalf("add waiver grant: %v", err)
	}
	// Expired grant: must not come back after the restart.
	_, err = s1.Add(Grant{Host: "web01", Allow: []string{"^old$"},
		GrantedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour)})
	if err != nil {
		t.Fatalf("add expired grant: %v", err)
	}

	// "Restart": a brand-new store loads from the same database.
	s2, err := NewGrantStoreDB(openGrantDB(t, path))
	if err != nil {
		t.Fatalf("NewGrantStoreDB after restart: %v", err)
	}

	live := s2.List(now)
	if len(live) != 2 {
		t.Fatalf("after restart: %d live grants, want 2 (expired must not load): %+v", len(live), live)
	}
	// The allow grant still widens the policy for its host.
	if ps := s2.GrantsFor("web01", Intent{Host: "web01"}, now); len(ps) != 1 {
		t.Errorf("allow grant must survive the restart: %d policies", len(ps))
	}
	// The waiver still matches the exact approved subject and elevation…
	in := Intent{Host: "web01", Caller: "broker-1", EndUser: "alice", Command: "reboot", Sudo: true}
	if !s2.WaiverMatches("web01", in, now) {
		t.Error("approval waiver must survive the restart (recompiled patterns)")
	}
	// …and still refuses a different elevation (sudo binding intact).
	in.Sudo = false
	if s2.WaiverMatches("web01", in, now) {
		t.Error("restored waiver must keep its elevation binding")
	}

	// A revoke on the restarted store must also be durable.
	if ok, err := s2.Revoke(allowID); err != nil || !ok {
		t.Fatalf("revoke after restart: ok=%v err=%v", ok, err)
	}
	s3, err := NewGrantStoreDB(openGrantDB(t, path))
	if err != nil {
		t.Fatal(err)
	}
	if ps := s3.GrantsFor("web01", Intent{Host: "web01"}, now); len(ps) != 0 {
		t.Error("a revoked grant must not resurrect on restart")
	}
}

// TestGrantStorePurgeCleansDB verifies the periodic sweep also bounds the
// database, including rows that expired while the process was down.
func TestGrantStorePurgeCleansDB(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "state.db")
	now := time.Now()

	db := openGrantDB(t, path)
	s, err := NewGrantStoreDB(db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add(Grant{Host: "web01", Allow: []string{"^x$"},
		GrantedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	s.Purge(now)

	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM grants").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("purge must delete expired rows from the db: %d left", n)
	}
}

// TestGrantStoreSupersedeWaiverCleansDB: re-learning a command refreshes the
// single waiver in the db as well, so a restart cannot resurrect the
// superseded twin.
func TestGrantStoreSupersedeWaiverCleansDB(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "state.db")
	now := time.Now()

	s, err := NewGrantStoreDB(openGrantDB(t, path))
	if err != nil {
		t.Fatal(err)
	}
	waiver := Grant{Host: "web01", WaiveApproval: []string{`^\Qreboot\E$`}, Caller: "broker-1",
		GrantedAt: now, ExpiresAt: now.Add(time.Hour)}
	if _, err := s.Add(waiver); err != nil {
		t.Fatal(err)
	}
	if n := s.SupersedeWaiver(waiver); n != 1 {
		t.Fatalf("supersede removed %d, want 1", n)
	}
	refreshed := waiver
	refreshed.ExpiresAt = now.Add(2 * time.Hour)
	if _, err := s.Add(refreshed); err != nil {
		t.Fatal(err)
	}

	s2, err := NewGrantStoreDB(openGrantDB(t, path))
	if err != nil {
		t.Fatal(err)
	}
	if got := s2.List(now); len(got) != 1 {
		t.Errorf("exactly one waiver must survive the restart, got %d", len(got))
	}
}
