package signer

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// erroringCA is an ssh.Signer whose Sign fails with a backend-style message
// naming the ssh-agent socket path.
type erroringCA struct{ pub ssh.PublicKey }

func (e erroringCA) PublicKey() ssh.PublicKey { return e.pub }
func (e erroringCA) Sign(io.Reader, []byte) (*ssh.Signature, error) {
	return nil, errors.New("agent CA: dialing ssh-agent at /run/infrabroker/agent.sock: connection refused")
}

func newErroringCA(t *testing.T) ssh.Signer {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return erroringCA{pub: sshPub}
}

// TestSignIntentCASignFailureIsTyped pins #465: a CA-backend failure after the
// policy allowed the intent surfaces as a CASignError — identified by
// ErrCASignFailed and, for the broker's upstream classification, by
// ErrSignerUnavailable — whose Error() is generic while Detail keeps the
// backend message for the signer's own log and audit.
func TestSignIntentCASignFailureIsTyped(t *testing.T) {
	t.Parallel()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	l := NewLocal(newErroringCA(t), PolicyTable{
		"web": {Addr: "10.0.0.1:22", User: "deploy", Principal: "host:web"},
	}, time.Minute)
	_, err = l.SignIntent(context.Background(), Intent{
		Caller: "x", Host: "web", Role: RoleTarget, Purpose: PurposeOneshot,
		Command: "uptime", RequestedTTL: time.Minute, PublicKey: sshPub,
	})
	if err == nil {
		t.Fatal("SignIntent must fail when the CA backend cannot sign")
	}
	if !errors.Is(err, ErrCASignFailed) {
		t.Errorf("errors.Is(err, ErrCASignFailed) = false for %v", err)
	}
	if errors.Is(err, ErrSignerUnavailable) {
		t.Errorf("a CA-backend failure must not masquerade as ErrSignerUnavailable; the broker classifies ErrCASignFailed itself: %v", err)
	}
	if strings.Contains(err.Error(), "agent.sock") {
		t.Errorf("Error() must not carry the backend detail: %q", err.Error())
	}
	var ce *CASignError
	if !errors.As(err, &ce) {
		t.Fatalf("want *CASignError, got %T", err)
	}
	if ce.Host != "web" || ce.Detail == nil || !strings.Contains(ce.Detail.Error(), "agent.sock") {
		t.Errorf("CASignError{Host:%q Detail:%v}: want host web and the backend detail", ce.Host, ce.Detail)
	}
}

// TestSignIntentMissingEnvelopeKeyIsTyped: a sealed_exec host whose signer has
// no envelope_key is a signer-side configuration failure on the session-exec
// preflight, not a policy denial of that command.
func TestSignIntentMissingEnvelopeKeyIsTyped(t *testing.T) {
	t.Parallel()
	l := NewLocal(nil, sealedPolicy(), 5*time.Minute) // no WithEnvelopeKey
	_, err := l.SignIntent(context.Background(), Intent{
		Caller: "x", Host: "sealed", Role: RoleTarget, Purpose: PurposeSession,
		SessionMode: SessionModeExec, Command: "uptime",
		DryRun: true, Preflight: true, RequestedTTL: time.Minute,
	})
	if !errors.Is(err, ErrCASignFailed) {
		t.Fatalf("want ErrCASignFailed for a missing envelope_key, got %v", err)
	}
	var ce *CASignError
	if !errors.As(err, &ce) || ce.Detail == nil || !strings.Contains(ce.Detail.Error(), "envelope_key") {
		t.Errorf("Detail must name the missing envelope_key, got %v", err)
	}
}

// TestSignIntentPolicyDenialIsNotCASignError: a denial before signing stays a
// plain error, so the frontends keep answering 403/"denied".
func TestSignIntentPolicyDenialIsNotCASignError(t *testing.T) {
	t.Parallel()
	l := NewLocal(newErroringCA(t), PolicyTable{
		"web": {Addr: "10.0.0.1:22", User: "deploy", Principal: "host:web"},
	}, time.Minute)
	_, err := l.SignIntent(context.Background(), Intent{
		Caller: "x", Host: "web", Role: RoleTarget, Purpose: PurposeOneshot,
		Command: "uptime", Sudo: true, RequestedTTL: time.Minute,
	})
	if err == nil {
		t.Fatal("sudo on a host without allow_sudo must be denied")
	}
	if errors.Is(err, ErrCASignFailed) || errors.Is(err, ErrSignerUnavailable) {
		t.Errorf("a policy denial must not classify as a CA-sign/upstream failure: %v", err)
	}
}
