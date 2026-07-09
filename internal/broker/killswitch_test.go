package broker

import (
	"testing"
	"time"

	"github.com/luisgf/infrabroker/internal/signer"
)

// TestKillMatchingClosesBusySessions pins the core of the kill switch (#117):
// unlike the reaper, killMatching force-closes a session with a command in
// flight (busy). Non-matching sessions are untouched.
func TestKillMatchingClosesBusySessions(t *testing.T) {
	t.Parallel()
	m := newSessionManager(5*time.Minute, 30*time.Minute, nil)
	t.Cleanup(func() { m.closeAll() })

	a := dummySession("a", "alice")
	b := dummySession("b", "bob")
	_ = m.add(a)
	_ = m.add(b)
	// Mark "a" busy — the reaper would spare it; killMatching must not.
	if _, _, owned := m.checkoutOwned("a", "alice"); !owned {
		t.Fatal("checkoutOwned failed")
	}

	victims := m.killMatching(func(s *liveSession) bool { return s.caller == "alice" })
	if len(victims) != 1 || victims[0].id != "a" {
		t.Fatalf("victims = %+v, want exactly [a]", victims)
	}
	if _, ok := peek(m, "a"); ok {
		t.Error("a busy matching session must be force-closed by killMatching")
	}
	if _, ok := peek(m, "b"); !ok {
		t.Error("a non-matching session must survive")
	}
}

func TestRevocationPredicate(t *testing.T) {
	t.Parallel()
	sess := func(id, caller string, serial uint64) *liveSession {
		return &liveSession{id: id, caller: caller, serial: serial}
	}
	entry := func(kind, value string) signer.FrozenEntry {
		return signer.FrozenEntry{FreezeSubject: signer.FreezeSubject{Kind: kind, Value: value}}
	}

	// A frozen end_user matches liveSession.caller (the broker sends the end
	// user as the signer's end_user); session_id and serial match directly.
	pred := revocationPredicate([]signer.FrozenEntry{
		entry(signer.FreezeEndUser, "alice"),
		entry(signer.FreezeSessionID, "s9"),
		entry(signer.FreezeSerial, "42"),
	}, "broker-1")
	if pred == nil {
		t.Fatal("predicate must be non-nil when the set has matchable subjects")
	}
	if !pred(sess("x", "alice", 1)) {
		t.Error("frozen end_user must match a session whose caller is that end user")
	}
	if !pred(sess("s9", "bob", 1)) {
		t.Error("frozen session_id must match")
	}
	if !pred(sess("x", "bob", 42)) {
		t.Error("frozen serial must match")
	}
	if pred(sess("x", "bob", 7)) {
		t.Error("an unrelated session must not match")
	}

	// A frozen caller CN equal to our own identity kills every session.
	predSelf := revocationPredicate([]signer.FrozenEntry{entry(signer.FreezeCaller, "broker-1")}, "broker-1")
	if predSelf == nil || !predSelf(sess("any", "anyone", 99)) {
		t.Error("our broker's CN frozen → every session matches")
	}

	// A different broker's freeze produces no predicate (nothing to sweep here).
	if revocationPredicate([]signer.FrozenEntry{entry(signer.FreezeCaller, "other-broker")}, "broker-1") != nil {
		t.Error("another broker's caller freeze must not sweep our sessions")
	}
	// Empty set → nil (skip the sweep).
	if revocationPredicate(nil, "broker-1") != nil {
		t.Error("empty freeze set → nil predicate")
	}
}
