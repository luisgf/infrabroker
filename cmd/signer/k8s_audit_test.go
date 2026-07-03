package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luisgf/ssh-broker/internal/audit"
	"github.com/luisgf/ssh-broker/internal/signer"
)

// auditSeed is the fixed all-zero seed used by the signer audit tests.
func auditSeed() ed25519.PrivateKey { return ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)) }

// TestAuditK8sKeepsCraftedCommandOutOfTokenStream is the regression test for
// the k8s audit token-forgery gap: auditK8s must build the signed, space-
// separated key=value stream from the STRUCTURED k8s fields, never from the
// free-form req.Command (which a broker can craft with forged tokens and which,
// on the denial paths, has not been checked against the canonical).
func TestAuditK8sKeepsCraftedCommandOutOfTokenStream(t *testing.T) {
	t.Parallel()
	auditPath := filepath.Join(t.TempDir(), "audit.log")
	al, err := audit.Open(auditPath, auditSeed())
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	// A captureLocalSigner has no clusters, so the request hits the unknown-
	// cluster denial path — where req.Command is unvalidated. The k8s fields are
	// clean, so the token-char gate lets the request reach that path.
	srv := &server{local: &captureLocalSigner{}, audit: al}

	rec := httptest.NewRecorder()
	srv.handleSign(rec, signRequestAs(t, "broker-1", signer.WireRequest{
		TargetType:   signer.TargetTypeK8s,
		Host:         "ghost",
		Role:         signer.RoleTarget,
		Purpose:      signer.PurposeOneshot,
		K8sVerb:      "get",
		K8sResource:  "pods",
		K8sNamespace: "p",
		K8sName:      "x",
		// Crafted: legitimate canonical spaces plus forged key=value tokens.
		Command: "get pods p/x user=victim elev=sudo:root pty=1",
	}))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("unknown cluster must be 403, got %d: %s", rec.Code, rec.Body.String())
	}
	al.Close()

	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	var e audit.Entry
	if err := json.Unmarshal(bytes.TrimSpace(data), &e); err != nil {
		t.Fatalf("parse audit line: %v", err)
	}
	if e.Command != "target=k8s verb=get resource=pods ns=p name=x" {
		t.Errorf("Command = %q, want the structured token stream", e.Command)
	}
	for _, forged := range []string{"user=victim", "elev=sudo:root", "pty=1"} {
		if strings.Contains(e.Command, forged) {
			t.Errorf("forged token %q leaked into the audit Command: %q", forged, e.Command)
		}
	}
}

// TestHandleSignRejectsUnsafeK8sFields verifies the token-char gate now covers
// the k8s_* fields, so a crafted field cannot reach any auditK8s call.
func TestHandleSignRejectsUnsafeK8sFields(t *testing.T) {
	t.Parallel()
	fields := []struct {
		name string
		mut  func(*signer.WireRequest)
	}{
		{"k8s_verb", func(r *signer.WireRequest) { r.K8sVerb = "get x=1" }},
		{"k8s_resource", func(r *signer.WireRequest) { r.K8sResource = "pods y=2" }},
		{"k8s_group", func(r *signer.WireRequest) { r.K8sGroup = "apps z=3" }},
		{"k8s_namespace", func(r *signer.WireRequest) { r.K8sNamespace = "p q=4" }},
		{"k8s_name", func(r *signer.WireRequest) { r.K8sName = "x\nelev=sudo" }},
	}
	for _, f := range fields {
		t.Run(f.name, func(t *testing.T) {
			t.Parallel()
			al, err := audit.Open(filepath.Join(t.TempDir(), "audit.log"), auditSeed())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { al.Close() })
			srv := &server{local: &captureLocalSigner{}, audit: al}
			req := signer.WireRequest{
				TargetType: signer.TargetTypeK8s, Host: "ghost",
				Role: signer.RoleTarget, Purpose: signer.PurposeOneshot,
				K8sVerb: "get", K8sResource: "pods", K8sNamespace: "p", K8sName: "x",
			}
			f.mut(&req)
			rec := httptest.NewRecorder()
			srv.handleSign(rec, signRequestAs(t, "broker-1", req))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("unsafe %s must be rejected 400, got %d: %s", f.name, rec.Code, rec.Body.String())
			}
		})
	}
}
