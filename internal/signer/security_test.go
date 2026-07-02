package signer

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestResolveBastionRoleRejectedOnCommandPolicyHost is the regression test for
// the command-firewall bypass: a host with a command_policy must never be
// issuable with role=bastion. A bastion certificate carries no force-command
// (and grants port-forwarding), so it would hand out an unrestricted credential
// for the host's principal and evade the allow/deny rules entirely.
func TestResolveBastionRoleRejectedOnCommandPolicyHost(t *testing.T) {
	t.Parallel()
	pt := PolicyTable{
		"web01": {
			Principal:      "host:web01",
			AllowAsBastion: true, // local mode forced this for every host; a signer.json may set it
			MaxTTL:         2 * time.Minute,
			CommandPolicy:  CommandPolicy{Mode: CmdPolicyAllowlist, Allow: []string{"^uptime$"}},
		},
	}
	// Sanity: a non-allowed command as a one-shot target is denied by the firewall.
	if _, err := pt.Resolve(Intent{
		Caller: "broker-1", Host: "web01", Role: RoleTarget, Purpose: PurposeOneshot,
		Command: "rm -rf /", RequestedTTL: time.Minute,
	}, time.Minute); err == nil {
		t.Fatal("one-shot target with a non-allowed command must be denied by command_policy")
	}
	// The bypass: role=bastion must be rejected outright on a command-policy host,
	// for every purpose.
	for _, purpose := range []string{PurposeOneshot, PurposeSession} {
		if _, err := pt.Resolve(Intent{
			Caller: "broker-1", Host: "web01", Role: RoleBastion, Purpose: purpose,
			Command: "rm -rf /", RequestedTTL: time.Minute,
		}, time.Minute); err == nil {
			t.Errorf("role=bastion purpose=%s on a command-policy host must be rejected (firewall bypass)", purpose)
		}
	}
}

// TestResolveRejectsEmptyOneShotCommand is the regression test for the
// force-command bypass: an empty (or whitespace-only) one-shot target command
// bakes no force-command into the certificate (ca.BuildAndSign omits the
// critical option when empty), producing an unrestricted host credential that
// also evades denylist and require_approval evaluation. The authoritative
// signer must reject it, mirroring the broker's "command is required" guard.
func TestResolveRejectsEmptyOneShotCommand(t *testing.T) {
	t.Parallel()
	pt := PolicyTable{
		// Denylist host: an empty command matches no deny rule (default-allow),
		// so without the guard it would be issued with no force-command.
		"deny01": {
			Principal:     "host:deny01",
			MaxTTL:        2 * time.Minute,
			CommandPolicy: CommandPolicy{Mode: CmdPolicyDenylist, Deny: []string{"^rm "}},
		},
		// Require-approval-only host: an empty command matches no approval
		// pattern, so RequireApproval would be false and the approval gate would
		// never fire.
		"appr01": {
			Principal:     "host:appr01",
			MaxTTL:        2 * time.Minute,
			CommandPolicy: CommandPolicy{Mode: CmdPolicyOff, RequireApproval: []string{"^systemctl "}},
		},
	}
	for _, host := range []string{"deny01", "appr01"} {
		for _, cmd := range []string{"", "   ", "\t"} {
			if _, err := pt.Resolve(Intent{
				Caller: "broker-1", Host: host, Role: RoleTarget, Purpose: PurposeOneshot,
				Command: cmd, RequestedTTL: time.Minute,
			}, time.Minute); err == nil {
				t.Errorf("host %q: empty/whitespace one-shot command %q must be rejected (force-command bypass)", host, cmd)
			}
		}
	}
	// A non-empty command on the same denylist host is still allowed — the guard
	// must not over-reject.
	if _, err := pt.Resolve(Intent{
		Caller: "broker-1", Host: "deny01", Role: RoleTarget, Purpose: PurposeOneshot,
		Command: "uptime", RequestedTTL: time.Minute,
	}, time.Minute); err != nil {
		t.Errorf("non-empty command must still be allowed on the denylist host: %v", err)
	}
}

// TestValidateRejectsBastionPlusCommandPolicy ensures the unsafe combination is
// caught at config load/reload, not only at request time.
func TestValidateRejectsBastionPlusCommandPolicy(t *testing.T) {
	t.Parallel()
	pt := PolicyTable{
		"web01": {
			Principal:      "host:web01",
			AllowAsBastion: true,
			CommandPolicy:  CommandPolicy{Mode: CmdPolicyDenylist, Deny: []string{"rm -rf"}},
		},
	}
	if err := pt.Validate(); err == nil {
		t.Fatal("Validate must reject a host that is both allow_as_bastion and command_policy")
	}
	// A command-policy host that is NOT a bastion validates fine.
	pt["web01"] = HostPolicy{Principal: "host:web01", CommandPolicy: CommandPolicy{Mode: CmdPolicyDenylist, Deny: []string{"rm -rf"}}}
	if err := pt.Validate(); err != nil {
		t.Errorf("a command-policy non-bastion host must validate: %v", err)
	}
}

// TestResolveRejectsControlCharsInIdentity is the regression test for cert
// KeyID / sshd auth-log injection via broker-controlled identity fields.
func TestResolveRejectsControlCharsInIdentity(t *testing.T) {
	t.Parallel()
	pt := PolicyTable{"web01": {Principal: "host:web01", MaxTTL: time.Minute}}
	base := Intent{Host: "web01", Role: RoleTarget, Purpose: PurposeOneshot, Command: "uptime", RequestedTTL: time.Minute}

	bad := base
	bad.Caller = "broker-1\nAccepted publickey for root"
	if _, err := pt.Resolve(bad, time.Minute); err == nil {
		t.Error("caller containing a newline must be rejected")
	}
	bad = base
	bad.EndUser = "alice\nfoo=bar"
	if _, err := pt.Resolve(bad, time.Minute); err == nil {
		t.Error("end_user containing a newline must be rejected")
	}
	// Token-splicing via whitespace: the KeyID/audit record is a space-separated
	// key=value stream, so a space lets a value forge extra tokens (elevation,
	// host, role) even with no control characters present.
	for _, tc := range []struct {
		name   string
		mutate func(*Intent)
	}{
		{"end_user with space forges elev token", func(in *Intent) { in.EndUser = "alice elev=sudo:root pty=1" }},
		{"caller with space forges host/role", func(in *Intent) { in.Caller = "b host=db role=bastion" }},
		{"caller with a single space", func(in *Intent) { in.Caller = "broker 1" }},
		{"end_user with a tab", func(in *Intent) { in.EndUser = "alice\tbob" }},
	} {
		bad = base
		bad.Caller = "broker-1"
		bad.EndUser = "alice"
		tc.mutate(&bad)
		if _, err := pt.Resolve(bad, time.Minute); err == nil {
			t.Errorf("%s: must be rejected", tc.name)
		}
	}
	// A clean request still succeeds. '=' is allowed inside a value (e.g. a
	// base64 sub with padding), since a bare '=' cannot splice a new token.
	for _, ok := range []Intent{
		mutateIntent(base, "broker-1", "alice@example.com"),
		mutateIntent(base, "broker-1", "dXNlcjEyMw=="),
	} {
		if _, err := pt.Resolve(ok, time.Minute); err != nil {
			t.Errorf("clean identity %q/%q must be accepted: %v", ok.Caller, ok.EndUser, err)
		}
	}
}

// mutateIntent returns a copy of base with Caller and EndUser set.
func mutateIntent(base Intent, caller, endUser string) Intent {
	base.Caller = caller
	base.EndUser = endUser
	return base
}

// TestWireEndUserGroupsNilVsEmpty is the regression test for the per-user RBAC
// bypass where an empty (deny-all) groups list collapsed to nil (unrestricted)
// across the broker->signer wire because of omitempty.
func TestWireEndUserGroupsNilVsEmpty(t *testing.T) {
	t.Parallel()
	// nil (no end-user identity asserted) must round-trip to nil (no per-user filter).
	nilBody, _ := json.Marshal(WireRequest{Host: "h", EndUserGroups: nil})
	var gotNil WireRequest
	if err := json.Unmarshal(nilBody, &gotNil); err != nil {
		t.Fatal(err)
	}
	if gotNil.EndUserGroups != nil {
		t.Errorf("nil groups must round-trip to nil, got %#v", gotNil.EndUserGroups)
	}
	// empty (authenticated user with zero groups = deny-all) must serialise as []
	// and round-trip to a non-nil empty slice — NOT vanish, which the signer would
	// read as unrestricted.
	emptyBody, _ := json.Marshal(WireRequest{Host: "h", EndUserGroups: []string{}})
	if !strings.Contains(string(emptyBody), `"end_user_groups":[]`) {
		t.Errorf("empty groups must serialise as [] (no omitempty), got %s", emptyBody)
	}
	var gotEmpty WireRequest
	if err := json.Unmarshal(emptyBody, &gotEmpty); err != nil {
		t.Fatal(err)
	}
	if gotEmpty.EndUserGroups == nil {
		t.Error("empty groups must round-trip to a non-nil empty slice (deny-all preserved)")
	}
	// And the signer's per-user gate then denies every host for the empty case.
	pt := PolicyTable{"h": {Principal: "host:h", Groups: []string{"prod"}, MaxTTL: time.Minute}}
	if _, err := pt.Resolve(Intent{
		Caller: "b", Host: "h", Role: RoleTarget, Purpose: PurposeOneshot, Command: "x",
		RequestedTTL: time.Minute, EndUserGroups: gotEmpty.EndUserGroups,
	}, time.Minute); err == nil {
		t.Error("a user with zero groups must be denied every host (deny-all)")
	}
}
