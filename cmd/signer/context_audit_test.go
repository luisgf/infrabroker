package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luisgf/infrabroker/internal/audit"
	"github.com/luisgf/infrabroker/internal/signer"
)

// lastAuditEntry reads the last record of the audit log at path.
func lastAuditEntry(t *testing.T, path string) audit.Entry {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	var e audit.Entry
	if err := json.Unmarshal(lines[len(lines)-1], &e); err != nil {
		t.Fatalf("parse audit line: %v", err)
	}
	return e
}

// TestHandleSignCarriesContextToIntentAndAudit pins, for a non-gated caller,
// the attribution context's path through the signer (docs/SANDBOX.md): the
// broker-asserted end_user_context reaches the Intent (hence the KeyID) and the
// issuance audit record — both the ` ctx=` token of the command stream, which
// mirrors the KeyID, and the structured end_user_context field.
func TestHandleSignCarriesContextToIntentAndAudit(t *testing.T) {
	t.Parallel()
	auditPath := filepath.Join(t.TempDir(), "audit.log")
	al, err := audit.Open(auditPath, auditSeed())
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	hosts := signer.PolicyTable{"web": {Addr: "10.0.0.1:22", User: "deploy", Principal: "host:web"}}
	capture := &captureLocalSigner{}
	srv := &server{local: capture, hosts: hosts, audit: al, freezes: signer.NewFreezeStore()}

	rec := httptest.NewRecorder()
	srv.handleSign(rec, signRequestAs(t, "broker-1", signer.WireRequest{
		Host: "web", Role: signer.RoleTarget, Purpose: signer.PurposeOneshot,
		Command: "uptime", DryRun: true,
		EndUser: "alice", EndUserContext: "abc123",
	}))
	if rec.Code != http.StatusOK {
		t.Fatalf("dry-run status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if capture.got.EndUserContext != "abc123" {
		t.Errorf("Intent.EndUserContext = %q, want abc123", capture.got.EndUserContext)
	}
	al.Close()
	e := lastAuditEntry(t, auditPath)
	if e.EndUserContext != "abc123" {
		t.Errorf("audit end_user_context = %q, want abc123", e.EndUserContext)
	}
	if !strings.Contains(e.Command, " user=alice ctx=abc123") {
		t.Errorf("audit command = %q, want ' user=alice ctx=abc123' (the KeyID order)", e.Command)
	}

	// The token-char gate covers the context like end_user: a value that would
	// splice a token into the KeyID/audit stream is rejected before any audit.
	rec = httptest.NewRecorder()
	srv.handleSign(rec, signRequestAs(t, "broker-1", signer.WireRequest{
		Host: "web", Role: signer.RoleTarget, Purpose: signer.PurposeOneshot,
		Command: "uptime", DryRun: true, EndUserContext: "abc elev=sudo:root",
	}))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("a context with whitespace must be 400, got %d", rec.Code)
	}
}

// TestAuditK8sCarriesContext pins the same path on the Kubernetes side of the
// signer, which builds its Intent and audit record separately from the SSH one:
// a k8s request's end_user_context reaches the audit (structured field and
// ` ctx=` token). The unknown-cluster denial path is used because a
// captureLocalSigner has no clusters; the audit record is written all the same.
func TestAuditK8sCarriesContext(t *testing.T) {
	t.Parallel()
	auditPath := filepath.Join(t.TempDir(), "audit.log")
	al, err := audit.Open(auditPath, auditSeed())
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	srv := &server{local: &captureLocalSigner{}, audit: al}
	rec := httptest.NewRecorder()
	srv.handleSign(rec, signRequestAs(t, "broker-1", signer.WireRequest{
		TargetType: signer.TargetTypeK8s, Host: "ghost", Role: signer.RoleTarget, Purpose: signer.PurposeOneshot,
		K8sVerb: "get", K8sResource: "pods", K8sNamespace: "p", K8sName: "x", Command: "get pods p/x",
		EndUser: "alice", EndUserContext: "abc123",
	}))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("unknown cluster must be 403, got %d: %s", rec.Code, rec.Body.String())
	}
	al.Close()
	e := lastAuditEntry(t, auditPath)
	if e.EndUserContext != "abc123" {
		t.Errorf("k8s audit end_user_context = %q, want abc123", e.EndUserContext)
	}
	if !strings.HasSuffix(e.Command, " user=alice ctx=abc123") {
		t.Errorf("k8s audit command = %q, want it to end with ' user=alice ctx=abc123'", e.Command)
	}
}
