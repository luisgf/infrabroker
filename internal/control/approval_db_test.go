package control

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/luisgf/ssh-broker/internal/signer"
	"github.com/luisgf/ssh-broker/internal/statedb"
)

func openRegistryDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := statedb.Open(path, RegistrySchema)
	if err != nil {
		t.Fatalf("statedb.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func testWireReq(command string) signer.WireRequest {
	return signer.WireRequest{
		Host: "web01", Role: signer.RoleTarget, Purpose: signer.PurposeOneshot,
		Command: command, PublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFake",
		EndUser: "alice",
	}
}

// TestRegistryPendingSurvivesRestartAndIsApprovable: a pending approval
// created before a restart can still be listed, approved, and consumed
// afterwards — with its original WireRequest intact for the signer forward.
func TestRegistryPendingSurvivesRestartAndIsApprovable(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "state.db")

	r1, err := NewRegistryDB(time.Minute, openRegistryDB(t, path))
	if err != nil {
		t.Fatalf("NewRegistryDB: %v", err)
	}
	a, err := r1.Create(testWireReq("reboot"), "broker-1", &signer.DecisionInfo{RequireApproval: true, MatchedRule: "^reboot"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// "Restart": a fresh registry over the same database.
	r2, err := NewRegistryDB(time.Minute, openRegistryDB(t, path))
	if err != nil {
		t.Fatalf("NewRegistryDB after restart: %v", err)
	}
	got, ok := r2.Get(a.ID)
	if !ok {
		t.Fatal("pending approval must survive the restart")
	}
	if got.Status != StatusPending || got.Command != "reboot" || got.Rule != "^reboot" || got.EndUser != "alice" {
		t.Fatalf("restored approval lost fields: %+v", got)
	}
	req, ok := r2.Request(a.ID)
	if !ok || req.PublicKey == "" || req.Command != "reboot" {
		t.Fatalf("the original WireRequest must be restored for the signer forward: %+v", req)
	}

	// The human decision and the consume flow work on the restored entry.
	if _, err := r2.Decide(a.ID, true, "admin", time.Hour); err != nil {
		t.Fatalf("Decide after restart: %v", err)
	}
	started, retry := r2.BeginConsume(a.ID)
	if !started || retry {
		t.Fatalf("BeginConsume after restart: started=%v retry=%v", started, retry)
	}
	r2.FinishConsume(a.ID, true)
	if started, _ := r2.BeginConsume(a.ID); started {
		t.Fatal("a consumed approval must not be consumable twice")
	}
}

// TestRegistryApprovedSurvivesRestartAndConsumesOnce: the decided state and
// its learn TTL persist; after a restart the approval is consumable exactly
// once (the `issuing` gate is intra-process and intentionally not persisted).
func TestRegistryApprovedSurvivesRestartAndConsumesOnce(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "state.db")

	r1, err := NewRegistryDB(time.Minute, openRegistryDB(t, path))
	if err != nil {
		t.Fatal(err)
	}
	a, err := r1.Create(testWireReq("reboot"), "broker-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r1.Decide(a.ID, true, "admin", 30*time.Minute); err != nil {
		t.Fatal(err)
	}
	// Claim it but crash before the signer answers: issuing must not persist.
	if started, _ := r1.BeginConsume(a.ID); !started {
		t.Fatal("BeginConsume should start")
	}

	r2, err := NewRegistryDB(time.Minute, openRegistryDB(t, path))
	if err != nil {
		t.Fatal(err)
	}
	got, ok := r2.Get(a.ID)
	if !ok || got.Status != StatusApproved || got.DecidedBy != "admin" {
		t.Fatalf("approved state must survive: %+v", got)
	}
	if got.LearnTTL != 30*time.Minute {
		t.Errorf("learn TTL must survive: %v", got.LearnTTL)
	}
	started, retry := r2.BeginConsume(a.ID)
	if !started || retry {
		t.Fatalf("approved-but-unconsumed must be consumable after restart: started=%v retry=%v", started, retry)
	}
	r2.FinishConsume(a.ID, true)

	// A third restart must see it consumed — it cannot come back to life.
	r3, err := NewRegistryDB(time.Minute, openRegistryDB(t, path))
	if err != nil {
		t.Fatal(err)
	}
	if started, _ := r3.BeginConsume(a.ID); started {
		t.Fatal("a consumed approval must stay consumed across restarts")
	}
}

// TestRegistryDeniedAndPurgeAcrossRestart: a denial persists (a poller after
// the restart sees denied, not pending), and purged rows do not reload.
func TestRegistryDeniedAndPurgeAcrossRestart(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "state.db")

	db := openRegistryDB(t, path)
	r1, err := NewRegistryDB(time.Minute, db)
	if err != nil {
		t.Fatal(err)
	}
	a, err := r1.Create(testWireReq("reboot"), "broker-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r1.Decide(a.ID, false, "admin", 0); err != nil {
		t.Fatal(err)
	}

	r2, err := NewRegistryDB(time.Minute, db)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := r2.Get(a.ID); !ok || got.Status != StatusDenied {
		t.Fatalf("denied state must survive the restart: %+v", got)
	}

	// Age the row beyond the purge window directly in the db: neither a new
	// load nor a purge sweep may keep it.
	if _, err := db.Exec("UPDATE approvals SET created_at = ? WHERE id = ?",
		time.Now().Add(-time.Hour).Unix(), a.ID); err != nil {
		t.Fatal(err)
	}
	r3, err := NewRegistryDB(time.Minute, db)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := r3.Get(a.ID); ok {
		t.Fatal("a row beyond the purge window must not reload")
	}
	r3.List() // triggers purgeLocked → db sweep
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM approvals").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("purge must delete aged rows from the db: %d left", n)
	}
}
