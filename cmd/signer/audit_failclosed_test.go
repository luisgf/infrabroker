package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/luisgf/infrabroker/internal/audit"
	"github.com/luisgf/infrabroker/internal/monitor"
	"github.com/luisgf/infrabroker/internal/signer"
)

// brokenAuditLog returns an opened audit log whose backing directory has been
// removed, so the next Append fails (ensureOpen cannot reopen the path). Models
// an unwritable audit sink (full disk, revoked permissions) for the fail-closed
// tests without an in-package test seam.
func brokenAuditLog(t *testing.T) *audit.Log {
	t.Helper()
	dir := t.TempDir()
	seed := make([]byte, ed25519.SeedSize)
	al, err := audit.Open(filepath.Join(dir, "audit.log"), ed25519.NewKeyFromSeed(seed))
	if err != nil {
		t.Fatalf("audit open: %v", err)
	}
	al.Close()
	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("remove audit dir: %v", err)
	}
	return al
}

// TestSignerAppendAuditFailMode covers the helper both services funnel through:
// closed denies (returns errAuditUnavailable), open logs and proceeds.
func TestSignerAppendAuditFailMode(t *testing.T) {
	t.Parallel()
	closed := &server{audit: brokenAuditLog(t), auditFailClosed: true}
	if err := closed.appendAudit(audit.Entry{Outcome: "x"}); !errors.Is(err, errAuditUnavailable) {
		t.Fatalf("closed mode must return errAuditUnavailable, got %v", err)
	}
	open := &server{audit: brokenAuditLog(t), auditFailClosed: false}
	if err := open.appendAudit(audit.Entry{Outcome: "x"}); err != nil {
		t.Fatalf("open mode must proceed, got %v", err)
	}
}

// TestAuditFailClosedModeParsing asserts the config parser: default + explicit
// closed fail closed, open fails open, anything else is a config error.
func TestAuditFailClosedModeParsing(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		mode       string
		wantClosed bool
		wantErr    bool
	}{
		{"", true, false},
		{"closed", true, false},
		{"open", false, false},
		{"nonsense", false, true},
	} {
		got, err := audit.FailClosed(tc.mode)
		if (err != nil) != tc.wantErr {
			t.Errorf("mode %q: err = %v, wantErr %v", tc.mode, err, tc.wantErr)
		}
		if err == nil && got != tc.wantClosed {
			t.Errorf("mode %q: closed = %v, want %v", tc.mode, got, tc.wantClosed)
		}
	}
}

// issuingApprovedSigner is a localSigner stub that issues an SSH certificate for
// an approval-gated command, to drive handleSign's issued path in tests.
type issuingApprovedSigner struct{}

func (issuingApprovedSigner) SignIntent(context.Context, signer.Intent) (*signer.Issued, error) {
	return &signer.Issued{
		Certificate: &ssh.Certificate{},
		Serial:      7,
		Decision:    &signer.DecisionInfo{Allowed: true, RequireApproval: true},
	}, nil
}
func (issuingApprovedSigner) HostAllowlistActive(string) (bool, bool) { return true, true }
func (issuingApprovedSigner) Clusters() signer.ClusterTable           { return nil }

// TestSignIssuedGateFailClosedSkipsWaiver pins #222: when a forwarder-approved,
// learn-requesting sign reaches the issued gate but the audit append fails in
// fail-closed mode, the request is denied (500) AND no approve-and-learn waiver
// is persisted. Under the pre-fix ordering the waiver was written through to the
// grant store before the gate, leaving a durable approval-bypass for a request
// whose issuance was withheld.
func TestSignIssuedGateFailClosedSkipsWaiver(t *testing.T) {
	t.Parallel()
	srv := &server{
		local:           issuingApprovedSigner{},
		hosts:           signer.PolicyTable{"web01": {Addr: "10.0.0.1:22", User: "deploy", Principal: "host:web01"}},
		forwarders:      map[string]struct{}{"fwd": {}},
		audit:           brokenAuditLog(t),
		auditFailClosed: true,
		grants:          signer.NewGrantStore(),
		freezes:         signer.NewFreezeStore(),
	}
	rec := httptest.NewRecorder()
	srv.handleSign(rec, signRequestAs(t, "fwd", signer.WireRequest{
		Host: "web01", Role: signer.RoleTarget, Purpose: signer.PurposeOneshot,
		Command: "systemctl restart nginx", OnBehalfOf: "brk1",
		Approved: true, LearnTTLSeconds: 600, LearnApprover: "alice", LearnApprovalID: "ap1",
	}))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("issued gate with a broken log → status %d, want 500 (body %s)", rec.Code, rec.Body.String())
	}
	if n := len(srv.grants.List(time.Now())); n != 0 {
		t.Errorf("a fail-closed issuance must persist no approve-and-learn waiver, found %d grants", n)
	}
}

// TestSignFrozenAuditFailClosed drives the /v1/sign audit gate through the frozen
// denial (which does not need a CA or host policy): with a broken log the closed
// signer returns 500 "audit unavailable" and increments audit_blocked_total,
// while the open signer still returns the normal 403 (unaudited).
func TestSignFrozenAuditFailClosed(t *testing.T) {
	// Not parallel: it reads the process-global audit_blocked_total counter.
	frozenSign := func(failClosed bool) *httptest.ResponseRecorder {
		srv := &server{
			audit:           brokenAuditLog(t),
			auditFailClosed: failClosed,
			reloadCN:        map[string]struct{}{"admin": {}},
			grants:          signer.NewGrantStore(),
			freezes:         signer.NewFreezeStore(),
		}
		// Freeze brk1 directly in the store (bypassing the freeze handler and its
		// own volatile gate); the sign path then hits the frozen denial.
		if _, err := srv.freezes.Add(signer.FreezeSubject{Kind: "caller", Value: "brk1"}, "", "admin", time.Now()); err != nil {
			t.Fatalf("freeze add: %v", err)
		}
		rec := httptest.NewRecorder()
		freezeMux(srv).ServeHTTP(rec, grantRequest(http.MethodPost, "/v1/sign", "brk1", signer.WireRequest{
			Host: "web01", Role: signer.RoleTarget, Purpose: signer.PurposeOneshot, Command: "uptime",
		}))
		return rec
	}

	before := monitor.GetCounter("audit_blocked_total", "").Value()
	if rec := frozenSign(true); rec.Code != http.StatusInternalServerError {
		t.Fatalf("closed mode: frozen sign with a broken log → status %d, want 500 (body %s)", rec.Code, rec.Body.String())
	}
	if got := monitor.GetCounter("audit_blocked_total", "").Value(); got <= before {
		t.Fatalf("audit_blocked_total must increment on a blocked action: before=%d after=%d", before, got)
	}

	// Open mode: the append still fails, but the operation proceeds to the normal
	// frozen denial (403) rather than 500.
	if rec := frozenSign(false); rec.Code != http.StatusForbidden {
		t.Fatalf("open mode: frozen sign with a broken log → status %d, want 403 (body %s)", rec.Code, rec.Body.String())
	}
}
