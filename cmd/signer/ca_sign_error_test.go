package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/luisgf/infrabroker/internal/audit"
	"github.com/luisgf/infrabroker/internal/signer"
)

// failingCA is an ssh.Signer whose Sign always fails with the kind of message
// the ssh-agent CA backend produces: it names the agent socket path.
type failingCA struct{ pub ssh.PublicKey }

const failingCADetail = "agent CA: dialing ssh-agent at /run/infrabroker/signer/agent.sock: connect: no such file or directory"

func (f failingCA) PublicKey() ssh.PublicKey { return f.pub }
func (f failingCA) Sign(io.Reader, []byte) (*ssh.Signature, error) {
	return nil, errors.New(failingCADetail)
}

func newFailingCA(t *testing.T) ssh.Signer {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return failingCA{pub: sshPub}
}

// TestHandleSignCASignFailureIsNotADenial pins #465: when the policy allows
// the intent but the CA backend cannot sign (ssh-agent unreachable, AKV Sign
// failing), /v1/sign must answer 502 with a generic body — not 403 "denied" —
// audit the request as outcome "error" (with the backend detail on the
// signer's side only) and keep the agent socket path out of the response.
func TestHandleSignCASignFailureIsNotADenial(t *testing.T) {
	t.Parallel()
	auditPath := filepath.Join(t.TempDir(), "audit.log")
	al, err := audit.Open(auditPath, auditSeed())
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	hosts, err := signer.CompileHostPolicies(signer.PolicyTable{
		"web": {Addr: "10.0.0.1:22", User: "deploy", Principal: "host:web", MaxTTLSeconds: 60},
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	local := signer.NewLocal(newFailingCA(t), hosts, time.Minute)
	srv := &server{local: local, hosts: hosts, audit: al, freezes: signer.NewFreezeStore()}

	rec := httptest.NewRecorder()
	srv.handleSign(rec, signRequestAs(t, "broker-1", signer.WireRequest{
		Host: "web", Role: signer.RoleTarget, Purpose: signer.PurposeOneshot, Command: "uptime",
	}))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 (body %s)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "agent.sock") || strings.Contains(body, "ssh-agent") {
		t.Errorf("response body leaks the CA backend detail: %q", body)
	}
	if !strings.Contains(body, "certificate signing failed") {
		t.Errorf("response body = %q, want the generic 'certificate signing failed'", body)
	}

	al.Close()
	e := lastAuditEntry(t, auditPath)
	if e.Outcome != "error" {
		t.Errorf("audit outcome = %q, want \"error\" (a backend failure is not a denial)", e.Outcome)
	}
	if !strings.Contains(e.Err, "agent.sock") {
		t.Errorf("audit err = %q, want the backend detail recorded signer-side", e.Err)
	}
}

// TestHandleSignPolicyDenialStays403: the #465 mapping must not swallow real
// policy denials — an unknown host is still 403 and audited "denied".
func TestHandleSignPolicyDenialStays403(t *testing.T) {
	t.Parallel()
	auditPath := filepath.Join(t.TempDir(), "audit.log")
	al, err := audit.Open(auditPath, auditSeed())
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	hosts, err := signer.CompileHostPolicies(signer.PolicyTable{
		"web": {Addr: "10.0.0.1:22", User: "deploy", Principal: "host:web", MaxTTLSeconds: 60},
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	local := signer.NewLocal(newFailingCA(t), hosts, time.Minute)
	srv := &server{local: local, hosts: hosts, audit: al, freezes: signer.NewFreezeStore()}

	rec := httptest.NewRecorder()
	srv.handleSign(rec, signRequestAs(t, "broker-1", signer.WireRequest{
		Host: "ghost", Role: signer.RoleTarget, Purpose: signer.PurposeOneshot, Command: "uptime",
	}))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body %s)", rec.Code, rec.Body.String())
	}
	al.Close()
	if e := lastAuditEntry(t, auditPath); e.Outcome != "denied" {
		t.Errorf("audit outcome = %q, want \"denied\"", e.Outcome)
	}
}
