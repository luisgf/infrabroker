package signer

import (
	"strings"
	"testing"
	"time"
)

// policyWithGroups adds group-labelled hosts to test per-end-user RBAC
// (EndUserGroups in the Intent).
func policyWithGroups() PolicyTable {
	return PolicyTable{
		"prod-web": {Principal: "host:prod-web", MaxTTL: 2 * time.Minute, Groups: []string{"prod", "web"}},
		"dev-web":  {Principal: "host:dev-web", MaxTTL: 2 * time.Minute, Groups: []string{"dev"}},
		"nogroups": {Principal: "host:nogroups", MaxTTL: 2 * time.Minute},
	}
}

func TestResolveEndUserGroupsIntersect(t *testing.T) {
	// User belongs to "prod"; prod-web is in {prod,web} → allowed.
	_, err := policyWithGroups().Resolve(Intent{
		Caller: "broker", Host: "prod-web", Role: RoleTarget, Purpose: PurposeOneshot,
		Command: "uptime", RequestedTTL: time.Minute,
		EndUser: "alice", EndUserGroups: []string{"prod", "ops"},
	}, 5*time.Minute)
	if err != nil {
		t.Fatalf("expected allowed, error: %v", err)
	}
}

func TestResolveEndUserGroupsNoIntersect(t *testing.T) {
	// User is only in "dev"; prod-web shares no group → denied.
	_, err := policyWithGroups().Resolve(Intent{
		Caller: "broker", Host: "prod-web", Role: RoleTarget, Purpose: PurposeOneshot,
		Command: "uptime", RequestedTTL: time.Minute,
		EndUser: "bob", EndUserGroups: []string{"dev"},
	}, 5*time.Minute)
	if err == nil {
		t.Fatal("expected denial by groups, got no error")
	}
}

func TestResolveEndUserGroupsHostWithoutGroups(t *testing.T) {
	// A host with no groups is not accessible under per-user RBAC.
	_, err := policyWithGroups().Resolve(Intent{
		Caller: "broker", Host: "nogroups", Role: RoleTarget, Purpose: PurposeOneshot,
		Command: "uptime", RequestedTTL: time.Minute,
		EndUser: "alice", EndUserGroups: []string{"prod"},
	}, 5*time.Minute)
	if err == nil {
		t.Fatal("host with no groups must not be accessible under per-user RBAC")
	}
}

func TestResolveEndUserGroupsNilNoRBAC(t *testing.T) {
	// EndUserGroups nil (stdio/mTLS requests): no per-user filter applied;
	// access depends only on the rest of the policy. Host with groups is accessible.
	_, err := policyWithGroups().Resolve(Intent{
		Caller: "broker", Host: "prod-web", Role: RoleTarget, Purpose: PurposeOneshot,
		Command: "uptime", RequestedTTL: time.Minute,
		EndUser: "", EndUserGroups: nil,
	}, 5*time.Minute)
	if err != nil {
		t.Fatalf("nil user groups must not apply RBAC filter, error: %v", err)
	}
}

func TestResolveEndUserKeyID(t *testing.T) {
	// EndUser must appear in KeyID for traceability in sshd.
	d, err := policyWithGroups().Resolve(Intent{
		Caller: "broker", Host: "prod-web", Role: RoleTarget, Purpose: PurposeOneshot,
		Command: "uptime", RequestedTTL: time.Minute,
		EndUser: "alice", EndUserGroups: []string{"prod"},
	}, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(d.Constraints.KeyID, "user=alice") {
		t.Errorf("KeyID must include user=alice, got %q", d.Constraints.KeyID)
	}
}
