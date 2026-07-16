package signer

import (
	"context"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/luisgf/infrabroker/internal/sealed"
)

func sealedPolicy() PolicyTable {
	return PolicyTable{
		"sealed": {
			Addr: "10.0.0.1:22", User: "deploy", Principal: "host:sealed",
			SealedExec: true, AllowSudo: true, AllowPTY: true,
		},
		"plain": {
			Addr: "10.0.0.2:22", User: "deploy", Principal: "host:plain",
			AllowPTY: true,
		},
	}
}

func envelopeTestKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	k, err := sealed.KeyFromSeed(make([]byte, ed25519.SeedSize))
	if err != nil {
		t.Fatalf("KeyFromSeed: %v", err)
	}
	return k
}

// TestResolveSealedSessionPinsShim: on a sealed host the session certificate is
// pinned to the shim rather than to a command, so the cert alone authorises
// nothing — every exec must additionally present a verifiable envelope (#144).
// A non-sealed host's session cert still carries no force-command at all.
func TestResolveSealedSessionPinsShim(t *testing.T) {
	t.Parallel()
	p := sealedPolicy()

	d, err := p.Resolve(Intent{
		Caller: "x", Host: "sealed", Role: RoleTarget, Purpose: PurposeSession,
		SessionMode: SessionModeExec, RequestedTTL: time.Minute,
	}, 5*time.Minute)
	if err != nil {
		t.Fatalf("sealed session open: %v", err)
	}
	wantFC, err := sealed.ForceCommand("sealed")
	if err != nil {
		t.Fatal(err)
	}
	if d.Constraints.ForceCommand != wantFC {
		t.Errorf("sealed session force-command = %q, want %q", d.Constraints.ForceCommand, wantFC)
	}

	d2, err := p.Resolve(Intent{
		Caller: "x", Host: "plain", Role: RoleTarget, Purpose: PurposeSession,
		SessionMode: SessionModeExec, RequestedTTL: time.Minute,
	}, 5*time.Minute)
	if err != nil {
		t.Fatalf("plain session open: %v", err)
	}
	if d2.Constraints.ForceCommand != "" {
		t.Errorf("a non-sealed session must carry no force-command, got %q", d2.Constraints.ForceCommand)
	}
}

// TestResolveSealedPinsEveryCert closes the bastion bypass: on a sealed host no
// certificate may ever leave without a force-command. A cert for role=bastion (of
// either purpose) used to carry none, so a compromised broker could simply ask
// for one and get a free shell on the very host the shim is meant to seal. Only
// the one-shot target is exempt — it already bakes the exact command.
func TestResolveSealedPinsEveryCert(t *testing.T) {
	t.Parallel()
	p := PolicyTable{
		"sealed": {
			Addr: "10.0.0.1:22", User: "deploy", Principal: "host:sealed",
			SealedExec: true, AllowAsBastion: true,
		},
	}
	wantFC, err := sealed.ForceCommand("sealed")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct{ purpose, role string }{
		{PurposeSession, RoleBastion},
		{PurposeOneshot, RoleBastion},
		{PurposeSession, RoleTarget},
	}
	for _, tc := range cases {
		d, err := p.Resolve(Intent{
			Caller: "x", Host: "sealed", Role: tc.role, Purpose: tc.purpose,
			SessionMode: SessionModeExec, RequestedTTL: time.Minute,
		}, 5*time.Minute)
		if err != nil {
			t.Fatalf("purpose=%s role=%s: %v", tc.purpose, tc.role, err)
		}
		if d.Constraints.ForceCommand != wantFC {
			t.Errorf("purpose=%s role=%s: force-command = %q, want %q — a sealed host must never issue an unpinned cert",
				tc.purpose, tc.role, d.Constraints.ForceCommand, wantFC)
		}
	}

	// The one-shot target keeps the real command, not the shim: that path is
	// already host-enforced by the baked force-command.
	d, err := p.Resolve(Intent{
		Caller: "x", Host: "sealed", Role: RoleTarget, Purpose: PurposeOneshot,
		Command: "uptime", RequestedTTL: time.Minute,
	}, 5*time.Minute)
	if err != nil {
		t.Fatalf("one-shot target: %v", err)
	}
	if d.Constraints.ForceCommand != "uptime" {
		t.Errorf("one-shot target force-command = %q, want the command itself", d.Constraints.ForceCommand)
	}
}

// TestResolveSealedRejectsShellAndPTY: only mode=exec is envelope-verifiable —
// a shell/pty session multiplexes commands with no per-command signer round-trip,
// so nothing could be signed or checked by the shim. Unlike the command_policy
// rule, this holds even with no rules configured.
func TestResolveSealedRejectsShellAndPTY(t *testing.T) {
	t.Parallel()
	p := sealedPolicy()
	for _, mode := range []string{SessionModeShell, SessionModePTY} {
		_, err := p.Resolve(Intent{
			Caller: "x", Host: "sealed", Role: RoleTarget, Purpose: PurposeSession,
			SessionMode: mode, RequestedTTL: time.Minute,
		}, 5*time.Minute)
		if err == nil {
			t.Errorf("a sealed host must reject session mode %q", mode)
		}
	}
	// The same modes stay allowed on a non-sealed host with no command policy.
	if _, err := p.Resolve(Intent{
		Caller: "x", Host: "plain", Role: RoleTarget, Purpose: PurposeSession,
		SessionMode: SessionModeShell, RequestedTTL: time.Minute,
	}, 5*time.Minute); err != nil {
		t.Errorf("a non-sealed host must still allow shell sessions: %v", err)
	}
}

// TestSealedEnvelopeMintedOnPreflight: the session-exec preflight is where the
// envelope is produced, and it verifies against the configured key and binds the
// exact host and command.
func TestSealedEnvelopeMintedOnPreflight(t *testing.T) {
	t.Parallel()
	key := envelopeTestKey(t)
	l := NewLocal(nil, sealedPolicy(), 5*time.Minute).WithEnvelopeKey(key)

	issued, err := l.SignIntent(context.Background(), Intent{
		Caller: "x", Host: "sealed", Role: RoleTarget, Purpose: PurposeSession,
		SessionMode: SessionModeExec, Command: "uptime",
		DryRun: true, Preflight: true, RequestedTTL: time.Minute,
	})
	if err != nil {
		t.Fatalf("SignIntent: %v", err)
	}
	if issued.Envelope == "" {
		t.Fatal("a sealed host's session-exec preflight must mint an envelope")
	}
	env, err := sealed.Verify(key.Public().(ed25519.PublicKey), issued.Envelope, "sealed", time.Now())
	if err != nil {
		t.Fatalf("the minted envelope must verify against the configured key: %v", err)
	}
	if env.Host != "sealed" || env.Command != "uptime" {
		t.Errorf("envelope binds host=%q command=%q, want sealed/uptime", env.Host, env.Command)
	}
}

// TestSealedEnvelopeCarriesElevation: the sudo prefix travels INSIDE the signed
// envelope, so the shim applies it — a broker cannot elevate on its own, and it
// must not prefix the command again.
func TestSealedEnvelopeCarriesElevation(t *testing.T) {
	t.Parallel()
	key := envelopeTestKey(t)
	l := NewLocal(nil, sealedPolicy(), 5*time.Minute).WithEnvelopeKey(key)

	issued, err := l.SignIntent(context.Background(), Intent{
		Caller: "x", Host: "sealed", Role: RoleTarget, Purpose: PurposeSession,
		SessionMode: SessionModeExec, Command: "systemctl restart nginx",
		Sudo: true, DryRun: true, Preflight: true, RequestedTTL: time.Minute,
	})
	if err != nil {
		t.Fatalf("SignIntent: %v", err)
	}
	env, err := sealed.Verify(key.Public().(ed25519.PublicKey), issued.Envelope, "sealed", time.Now())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !strings.Contains(env.Command, "sudo") || !strings.Contains(env.Command, "systemctl restart nginx") {
		t.Errorf("the signed command must carry the elevation prefix, got %q", env.Command)
	}
}

// TestSealedEnvelopeOnlyForSealedPreflight: no envelope leaks onto intents that
// are not a sealed host's session-exec preflight.
func TestSealedEnvelopeOnlyForSealedPreflight(t *testing.T) {
	t.Parallel()
	key := envelopeTestKey(t)
	l := NewLocal(nil, sealedPolicy(), 5*time.Minute).WithEnvelopeKey(key)

	cases := map[string]Intent{
		"non-sealed host": {
			Caller: "x", Host: "plain", Role: RoleTarget, Purpose: PurposeSession,
			SessionMode: SessionModeExec, Command: "uptime", DryRun: true, Preflight: true,
		},
		"session open (no command)": {
			Caller: "x", Host: "sealed", Role: RoleTarget, Purpose: PurposeSession,
			SessionMode: SessionModeExec, DryRun: true, Preflight: true,
		},
		"plain dry-run (not a preflight)": {
			Caller: "x", Host: "sealed", Role: RoleTarget, Purpose: PurposeSession,
			SessionMode: SessionModeExec, Command: "uptime", DryRun: true,
		},
	}
	for name, in := range cases {
		in.RequestedTTL = time.Minute
		issued, err := l.SignIntent(context.Background(), in)
		if err != nil {
			t.Fatalf("%s: SignIntent: %v", name, err)
		}
		if issued.Envelope != "" {
			t.Errorf("%s: must not mint an envelope, got %q", name, issued.Envelope)
		}
	}
}

// TestSealedWithoutEnvelopeKeyFailsClosed: a sealed host whose signer has no
// envelope key refuses rather than returning an unsigned command the broker
// could send (the shim would reject it anyway — this just fails earlier and
// louder).
func TestSealedWithoutEnvelopeKeyFailsClosed(t *testing.T) {
	t.Parallel()
	l := NewLocal(nil, sealedPolicy(), 5*time.Minute) // no envelope key

	_, err := l.SignIntent(context.Background(), Intent{
		Caller: "x", Host: "sealed", Role: RoleTarget, Purpose: PurposeSession,
		SessionMode: SessionModeExec, Command: "uptime",
		DryRun: true, Preflight: true, RequestedTTL: time.Minute,
	})
	if err == nil {
		t.Error("a sealed host with no envelope_key must fail closed")
	}
}
