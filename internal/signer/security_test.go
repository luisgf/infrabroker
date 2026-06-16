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
	// A clean request still succeeds.
	ok := base
	ok.Caller = "broker-1"
	ok.EndUser = "alice@example.com"
	if _, err := pt.Resolve(ok, time.Minute); err != nil {
		t.Errorf("clean identity must be accepted: %v", err)
	}
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
