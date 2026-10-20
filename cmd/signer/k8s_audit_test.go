package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luisgf/infrabroker/internal/audit"
	"github.com/luisgf/infrabroker/internal/signer"
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

// mintFailingLocalSigner has one cluster and fails every k8s sign the way a
// TokenRequest failure does (signer.K8sMintError carrying the SA binding and
// the API path in its Detail).
type mintFailingLocalSigner struct{ captureLocalSigner }

func (m *mintFailingLocalSigner) Clusters() signer.ClusterTable {
	return signer.ClusterTable{"prod-k8s": signer.ClusterPolicy{APIServer: "https://k8s.internal:6443"}}
}

func (m *mintFailingLocalSigner) SignIntent(_ context.Context, in signer.Intent) (*signer.Issued, error) {
	m.got = in
	return nil, &signer.K8sMintError{Cluster: in.Host,
		Detail: fmt.Errorf("minting token for agents/broker-platform on %q: k8s: POST /api/v1/namespaces/agents/serviceaccounts/broker-platform/token: 401 Unauthorized", in.Host)}
}

// TestHandleSignK8sMintFailureIs502WithoutBindingLeak locks in #455 at the
// HTTP boundary: a mint failure answers 502 (not 403) with a generic body that
// names neither the SA binding nor the TokenRequest path, and is audited as
// outcome "error" (not "denied") with the detail kept on the signer side.
func TestHandleSignK8sMintFailureIs502WithoutBindingLeak(t *testing.T) {
	t.Parallel()
	auditPath := filepath.Join(t.TempDir(), "audit.log")
	al, err := audit.Open(auditPath, auditSeed())
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	srv := &server{local: &mintFailingLocalSigner{}, audit: al}

	rec := httptest.NewRecorder()
	srv.handleSign(rec, signRequestAs(t, "broker-1", signer.WireRequest{
		TargetType:   signer.TargetTypeK8s,
		Host:         "prod-k8s",
		Role:         signer.RoleTarget,
		Purpose:      signer.PurposeOneshot,
		K8sVerb:      "get",
		K8sResource:  "pods",
		K8sNamespace: "p",
		K8sName:      "x",
		Command:      "get pods p/x",
	}))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("mint failure must be 502, got %d: %s", rec.Code, rec.Body.String())
	}
	for _, leak := range []string{"serviceaccounts", "/token", "401", "broker-platform", "agents/"} {
		if strings.Contains(rec.Body.String(), leak) {
			t.Errorf("response body leaks %q: %q", leak, rec.Body.String())
		}
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
	if e.Outcome != "error" {
		t.Errorf("Outcome = %q, want error (an infrastructure failure is not a denial)", e.Outcome)
	}
	if !strings.Contains(e.Err, "serviceaccounts/broker-platform/token") {
		t.Errorf("the signer's own audit record must keep the minter detail, got Err=%q", e.Err)
	}
	if e.Command != "target=k8s verb=get resource=pods ns=p name=x" {
		t.Errorf("Command = %q, want the structured token stream", e.Command)
	}
}
