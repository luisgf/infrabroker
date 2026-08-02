package main

import (
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/luisgf/infrabroker/internal/signer"
)

// TestMaybeLearnWaiver exercises the approve-and-learn mint: a scoped approval
// waiver is created after an approved sign that asked for it, the guards suppress
// it otherwise, and the TTL is clamped to max_grant_ttl_seconds.
func TestMaybeLearnWaiver(t *testing.T) {
	t.Parallel()
	srv := grantTestServer(t, time.Hour) // cap grant/waiver TTL at 1h
	issuedOK := &signer.Issued{Certificate: &ssh.Certificate{}, Decision: &signer.DecisionInfo{RequireApproval: true}}

	// Happy path: a scoped waiver for the exact command, with provenance.
	srv.maybeLearnWaiver("broker-1", signer.WireRequest{
		Host: "web01", EndUser: "alice", Command: "systemctl restart nginx",
		LearnTTLSeconds: 600, LearnApprover: "alice", LearnApprovalID: "ap1",
	}, issuedOK)
	gs := srv.grants.List(time.Now())
	if len(gs) != 1 {
		t.Fatalf("expected exactly one waiver, got %d", len(gs))
	}
	g := gs[0]
	if len(g.WaiveApproval) != 1 || g.WaiveApproval[0] != "^systemctl restart nginx$" {
		t.Errorf("waiver pattern wrong: %+v", g.WaiveApproval)
	}
	if len(g.Allow) != 0 {
		t.Errorf("an approve-and-learn waiver must carry no allow patterns: %+v", g.Allow)
	}
	if g.Approver != "alice" || g.ApprovalID != "ap1" {
		t.Errorf("waiver provenance wrong: approver=%q approvalID=%q", g.Approver, g.ApprovalID)
	}
	if g.Caller != "broker-1" || g.EndUser != "alice" {
		t.Errorf("approve-and-learn waiver scope wrong: %+v", g)
	}
	if !srv.grants.WaiverMatches("web01", signer.Intent{
		Host: "web01", Caller: "broker-1", EndUser: "alice", Command: "systemctl restart nginx",
	}, time.Now()) {
		t.Error("waiver should match the approved caller/end-user")
	}
	if srv.grants.WaiverMatches("web01", signer.Intent{
		Host: "web01", Caller: "broker-2", EndUser: "alice", Command: "systemctl restart nginx",
	}, time.Now()) {
		t.Error("waiver must not match another broker caller")
	}
	if srv.grants.WaiverMatches("web01", signer.Intent{
		Host: "web01", Caller: "broker-1", EndUser: "bob", Command: "systemctl restart nginx",
	}, time.Now()) {
		t.Error("waiver must not match another end user")
	}

	// Guards: none of these should mint anything.
	before := len(srv.grants.List(time.Now()))
	noApprovalCert := &signer.Issued{Decision: &signer.DecisionInfo{RequireApproval: true}}                                  // no certificate issued
	notGated := &signer.Issued{Certificate: &ssh.Certificate{}, Decision: &signer.DecisionInfo{RequireApproval: false}}      // command was not approval-gated
	srv.maybeLearnWaiver("b", signer.WireRequest{Host: "web01", Command: "x", LearnTTLSeconds: 0}, issuedOK)                 // no learn ttl
	srv.maybeLearnWaiver("b", signer.WireRequest{Host: "web01", Command: "x", LearnTTLSeconds: 600, DryRun: true}, issuedOK) // dry-run
	srv.maybeLearnWaiver("b", signer.WireRequest{Host: "web01", Command: "x", LearnTTLSeconds: 600}, noApprovalCert)         // no cert
	srv.maybeLearnWaiver("b", signer.WireRequest{Host: "web01", Command: "x", LearnTTLSeconds: 600}, notGated)               // not gated
	if after := len(srv.grants.List(time.Now())); after != before {
		t.Errorf("guards should mint nothing: before=%d after=%d", before, after)
	}

	// Clamp: a TTL above max_grant_ttl_seconds is clamped, not rejected.
	srv2 := grantTestServer(t, time.Hour)
	srv2.maybeLearnWaiver("b", signer.WireRequest{
		Host: "web01", Command: "y", LearnTTLSeconds: 99999, LearnApprover: "a",
	}, issuedOK)
	g2 := srv2.grants.List(time.Now())
	if len(g2) != 1 {
		t.Fatalf("clamp case: expected one waiver, got %d", len(g2))
	}
	if g2[0].Caller != "b" {
		t.Errorf("clamp case: waiver caller scope = %q, want b", g2[0].Caller)
	}
	if d := time.Until(g2[0].ExpiresAt); d > time.Hour+time.Minute {
		t.Errorf("TTL should be clamped to ~1h, got %s", d)
	}
}

// TestMaybeLearnWaiverRefusesFrozenSubject pins #330: a learn-mint scoped to a
// frozen caller/end_user must not store a durable waiver that would survive the
// freeze's RevokeForSubject and re-suppress require_approval the moment the
// subject is unfrozen (sibling of #224 for the admin grant path).
func TestMaybeLearnWaiverRefusesFrozenSubject(t *testing.T) {
	t.Parallel()
	issuedOK := &signer.Issued{Certificate: &ssh.Certificate{}, Decision: &signer.DecisionInfo{RequireApproval: true}}
	req := signer.WireRequest{
		Host: "web01", EndUser: "alice", Command: "systemctl restart nginx",
		LearnTTLSeconds: 600, LearnApprover: "approver", LearnApprovalID: "ap1",
	}

	// Frozen caller: no waiver stored.
	srv := grantTestServer(t, time.Hour)
	srv.freezes = signer.NewFreezeStore()
	if _, err := srv.freezes.Add(signer.FreezeSubject{Kind: signer.FreezeCaller, Value: "broker-1"}, "", "admin", time.Now()); err != nil {
		t.Fatalf("freeze caller: %v", err)
	}
	srv.maybeLearnWaiver("broker-1", req, issuedOK)
	if n := len(srv.grants.List(time.Now())); n != 0 {
		t.Fatalf("learn for a frozen caller must store no waiver, found %d", n)
	}
	if srv.grants.WaiverMatches("web01", signer.Intent{
		Host: "web01", Caller: "broker-1", EndUser: "alice", Command: "systemctl restart nginx",
	}, time.Now()) {
		t.Error("frozen-caller learn must not match a later WaiverMatches")
	}

	// Frozen end_user: same refuse.
	srv2 := grantTestServer(t, time.Hour)
	srv2.freezes = signer.NewFreezeStore()
	if _, err := srv2.freezes.Add(signer.FreezeSubject{Kind: signer.FreezeEndUser, Value: "alice"}, "", "admin", time.Now()); err != nil {
		t.Fatalf("freeze end_user: %v", err)
	}
	srv2.maybeLearnWaiver("broker-1", req, issuedOK)
	if n := len(srv2.grants.List(time.Now())); n != 0 {
		t.Fatalf("learn for a frozen end_user must store no waiver, found %d", n)
	}

	// Non-frozen subject still mints (control).
	srv3 := grantTestServer(t, time.Hour)
	srv3.freezes = signer.NewFreezeStore()
	srv3.maybeLearnWaiver("broker-1", req, issuedOK)
	if n := len(srv3.grants.List(time.Now())); n != 1 {
		t.Fatalf("learn for a non-frozen subject: expected 1 waiver, got %d", n)
	}
}
