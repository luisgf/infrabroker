package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

// TestHandleSignK8sRejectsSSHOnlyWireKnobs pins #597 at the HTTP boundary,
// mirroring TestResolveK8sRejectsSSHKnobsAndMismatch: a k8s sign request that
// carries an SSH-only knob (sudo, sudo_user, pty, file_transfer, session_mode)
// or a role/purpose other than target/oneshot is rejected 400 and audited as
// denied — never signed as if the knob were absent. Without the gate the
// Intent is built with a fixed role/purpose and the knobs are dropped, so
// resolveK8s's own rejection is unreachable over the wire and a learned
// waiver could bind to a sudo elevation no k8s intent ever matches.
func TestHandleSignK8sRejectsSSHOnlyWireKnobs(t *testing.T) {
	t.Parallel()
	mutations := []struct {
		name string
		mut  func(*signer.WireRequest)
		want string
	}{
		{"sudo", func(r *signer.WireRequest) { r.Sudo = true }, "do not support sudo"},
		{"sudo_user", func(r *signer.WireRequest) { r.SudoUser = "postgres" }, "do not support sudo"},
		{"pty", func(r *signer.WireRequest) { r.PTY = true }, "do not support pty"},
		{"file_transfer", func(r *signer.WireRequest) { r.FileTransfer = true }, "do not support file transfer"},
		{"session_mode", func(r *signer.WireRequest) { r.SessionMode = signer.SessionModeShell }, "one-shot only"},
		{"purpose session", func(r *signer.WireRequest) { r.Purpose = signer.PurposeSession }, "one-shot only"},
		{"role bastion", func(r *signer.WireRequest) { r.Role = signer.RoleBastion }, "must have role"},
		{"all at once", func(r *signer.WireRequest) {
			r.Role, r.Purpose, r.SessionMode = signer.RoleBastion, signer.PurposeSession, signer.SessionModeShell
			r.Sudo, r.PTY, r.FileTransfer = true, true, true
		}, "k8s intents"},
	}
	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv, auditPath := realK8sServer(t, []signer.K8sRule{{Verbs: []string{"get"}, Resources: []string{"pods"}, Effect: "allow"}})
			req := signer.WireRequest{TargetType: signer.TargetTypeK8s, Host: "prod-k8s",
				Role: signer.RoleTarget, Purpose: signer.PurposeOneshot,
				K8sVerb: "get", K8sResource: "pods", K8sNamespace: "prod", K8sName: "web-1",
				Command: "get pods prod/web-1"}
			tc.mut(&req)
			rec := httptest.NewRecorder()
			srv.handleSign(rec, signRequestAs(t, "broker-1", req))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("want 400, got %d: %s", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tc.want) {
				t.Errorf("body = %q, want it to contain %q", rec.Body.String(), tc.want)
			}
			if strings.Contains(rec.Body.String(), "k8s_token") {
				t.Error("a bound token must never be issued for a malformed k8s request")
			}
			entries := readAuditEntries(t, auditPath)
			if len(entries) != 1 {
				t.Fatalf("want exactly one audit entry (denied), got %d", len(entries))
			}
			e := entries[0]
			if e.Outcome != "denied" {
				t.Errorf("Outcome = %q, want denied", e.Outcome)
			}
			if !strings.Contains(e.Err, tc.want) {
				t.Errorf("audit Err = %q, want it to contain %q", e.Err, tc.want)
			}
			if e.Command != "target=k8s verb=get resource=pods ns=prod name=web-1" {
				t.Errorf("audit Command = %q, want the structured k8s action", e.Command)
			}
		})
	}
	// The well-formed request still issues (the gate rejects nothing else).
	srv, _ := realK8sServer(t, []signer.K8sRule{{Verbs: []string{"get"}, Resources: []string{"pods"}, Effect: "allow"}})
	rec := httptest.NewRecorder()
	srv.handleSign(rec, signRequestAs(t, "broker-1", signer.WireRequest{TargetType: signer.TargetTypeK8s, Host: "prod-k8s",
		Role: signer.RoleTarget, Purpose: signer.PurposeOneshot,
		K8sVerb: "get", K8sResource: "pods", K8sNamespace: "prod", K8sName: "web-1",
		Command: "get pods prod/web-1"}))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "k8s_token") {
		t.Fatalf("well-formed k8s request must issue: %d %s", rec.Code, rec.Body.String())
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

// fakeK8sMinter satisfies signer.TokenMinter with a fixed token.
type fakeK8sMinter struct{}

func (fakeK8sMinter) MintToken(_ context.Context, _, _, sa string, ttl time.Duration) (string, time.Time, error) {
	return "tok-" + sa, time.Now().Add(ttl), nil
}

// realK8sServer builds a server over a REAL signer.Local with one compiled
// cluster (a self-signed CA file, a minter token file, the given rules) so the
// /v1/sign k8s branch runs the actual resolveK8s normalization.
func realK8sServer(t *testing.T, rules []signer.K8sRule) (*server, string) {
	t.Helper()
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-k8s-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	tokPath := filepath.Join(dir, "minter.token")
	if err := os.WriteFile(tokPath, []byte("minter"), 0o600); err != nil {
		t.Fatal(err)
	}
	ct, err := signer.CompileClusterPolicies(signer.ClusterTable{"prod-k8s": {
		APIServer:  "https://10.0.0.5:6443",
		CACert:     caPath,
		TokenFile:  tokPath,
		SABindings: []signer.SABinding{{Namespace: "agents", ServiceAccount: "broker-default"}},
		Rules:      rules,
	}}, nil)
	if err != nil {
		t.Fatalf("CompileClusterPolicies: %v", err)
	}
	auditPath := filepath.Join(dir, "audit.log")
	al, err := audit.Open(auditPath, auditSeed())
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	t.Cleanup(func() { al.Close() })
	local := signer.NewLocal(nil, nil, time.Minute).WithK8s(ct, fakeK8sMinter{})
	return &server{local: local, audit: al}, auditPath
}

// readAuditEntries parses every line of the signer audit log.
func readAuditEntries(t *testing.T, path string) []audit.Entry {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []audit.Entry
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
		var e audit.Entry
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatalf("parse audit line %q: %v", line, err)
		}
		out = append(out, e)
	}
	return out
}

// TestAuditK8sIssuedRecordUsesNormalizedAction pins #456: the signed k8s
// record on the issued / approval-required / dry-run paths names the
// NORMALIZED action the policy decided on — the group filled in from the
// resource table and the namespace dropped for cluster-scoped resources — not
// the raw request fields, so the tamper-evident log and the broker's own record
// describe the same canonical.
func TestAuditK8sIssuedRecordUsesNormalizedAction(t *testing.T) {
	t.Parallel()
	srv, auditPath := realK8sServer(t, []signer.K8sRule{
		{Verbs: []string{"get"}, Resources: []string{"deployments"}, Effect: "allow"},
		{Verbs: []string{"delete"}, Resources: []string{"nodes"}, Effect: "allow"},
		{Verbs: []string{"delete"}, Resources: []string{"namespaces"}, Effect: "require_approval"},
	})
	base := signer.WireRequest{TargetType: signer.TargetTypeK8s, Host: "prod-k8s",
		Role: signer.RoleTarget, Purpose: signer.PurposeOneshot}

	cases := []struct {
		name        string
		mut         func(*signer.WireRequest)
		wantOutcome string
		wantCommand string
	}{
		{"cluster-scoped: client namespace dropped", func(r *signer.WireRequest) {
			r.K8sVerb, r.K8sResource, r.K8sNamespace, r.K8sName = "delete", "nodes", "kube-system", "victim"
			r.Command = "delete nodes -/victim"
		}, "issued", "target=k8s verb=delete resource=nodes ns=- name=victim"},
		{"grouped: empty group filled in", func(r *signer.WireRequest) {
			r.K8sVerb, r.K8sResource, r.K8sNamespace, r.K8sName = "get", "deployments", "prod", "api"
			r.Command = "get deployments.apps prod/api"
		}, "issued", "target=k8s verb=get resource=deployments.apps ns=prod name=api"},
		{"approval-required: normalized too", func(r *signer.WireRequest) {
			r.K8sVerb, r.K8sResource, r.K8sNamespace, r.K8sName = "delete", "namespaces", "kube-system", "victim"
			r.Command = "delete namespaces -/victim"
		}, "approval-required", "target=k8s verb=delete resource=namespaces ns=- name=victim"},
		{"dry-run: normalized too", func(r *signer.WireRequest) {
			r.K8sVerb, r.K8sResource, r.K8sNamespace, r.K8sName = "get", "deployments", "prod", "api"
			r.Command, r.DryRun = "get deployments.apps prod/api", true
		}, "dry_run_allowed", "target=k8s verb=get resource=deployments.apps ns=prod name=api"},
	}
	for i, tc := range cases {
		req := base
		tc.mut(&req)
		rec := httptest.NewRecorder()
		srv.handleSign(rec, signRequestAs(t, "broker-1", req))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: want 200, got %d: %s", tc.name, rec.Code, rec.Body.String())
		}
		entries := readAuditEntries(t, auditPath)
		if len(entries) != i+1 {
			t.Fatalf("%s: want %d audit entries, got %d", tc.name, i+1, len(entries))
		}
		e := entries[i]
		if e.Outcome != tc.wantOutcome {
			t.Errorf("%s: Outcome = %q, want %q", tc.name, e.Outcome, tc.wantOutcome)
		}
		if e.Command != tc.wantCommand {
			t.Errorf("%s: Command = %q, want the normalized canonical %q", tc.name, e.Command, tc.wantCommand)
		}
		if e.Host != "https://10.0.0.5:6443" {
			t.Errorf("%s: Host = %q, want the api_server", tc.name, e.Host)
		}
	}
}
