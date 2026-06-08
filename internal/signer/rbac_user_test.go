package signer

import (
	"strings"
	"testing"
	"time"
)

// policyWithGroups añade hosts etiquetados con grupos para probar el RBAC por
// usuario final (EndUserGroups en el Intent).
func policyWithGroups() PolicyTable {
	return PolicyTable{
		"prod-web": {Principal: "host:prod-web", MaxTTL: 2 * time.Minute, Groups: []string{"prod", "web"}},
		"dev-web":  {Principal: "host:dev-web", MaxTTL: 2 * time.Minute, Groups: []string{"dev"}},
		"nogroups": {Principal: "host:nogroups", MaxTTL: 2 * time.Minute},
	}
}

func TestResolveEndUserGroupsIntersect(t *testing.T) {
	// El usuario pertenece a "prod"; el host prod-web está en {prod,web} → permitido.
	_, err := policyWithGroups().Resolve(Intent{
		Caller: "broker", Host: "prod-web", Role: RoleTarget, Purpose: PurposeOneshot,
		Command: "uptime", RequestedTTL: time.Minute,
		EndUser: "alice", EndUserGroups: []string{"prod", "ops"},
	}, 5*time.Minute)
	if err != nil {
		t.Fatalf("esperaba permitido, error: %v", err)
	}
}

func TestResolveEndUserGroupsNoIntersect(t *testing.T) {
	// El usuario solo está en "dev"; prod-web no comparte grupo → denegado.
	_, err := policyWithGroups().Resolve(Intent{
		Caller: "broker", Host: "prod-web", Role: RoleTarget, Purpose: PurposeOneshot,
		Command: "uptime", RequestedTTL: time.Minute,
		EndUser: "bob", EndUserGroups: []string{"dev"},
	}, 5*time.Minute)
	if err == nil {
		t.Fatal("esperaba denegación por grupos, no hubo error")
	}
}

func TestResolveEndUserGroupsHostWithoutGroups(t *testing.T) {
	// Un host sin grupos no es accesible bajo RBAC de usuario.
	_, err := policyWithGroups().Resolve(Intent{
		Caller: "broker", Host: "nogroups", Role: RoleTarget, Purpose: PurposeOneshot,
		Command: "uptime", RequestedTTL: time.Minute,
		EndUser: "alice", EndUserGroups: []string{"prod"},
	}, 5*time.Minute)
	if err == nil {
		t.Fatal("host sin grupos no debe ser accesible con RBAC de usuario")
	}
}

func TestResolveEndUserGroupsNilNoRBAC(t *testing.T) {
	// EndUserGroups nil (peticiones stdio/mTLS): no se aplica filtro por usuario,
	// el acceso depende solo del resto de la política. Host con grupos accesible.
	_, err := policyWithGroups().Resolve(Intent{
		Caller: "broker", Host: "prod-web", Role: RoleTarget, Purpose: PurposeOneshot,
		Command: "uptime", RequestedTTL: time.Minute,
		EndUser: "", EndUserGroups: nil,
	}, 5*time.Minute)
	if err != nil {
		t.Fatalf("sin grupos de usuario no debe haber filtro RBAC, error: %v", err)
	}
}

func TestResolveEndUserKeyID(t *testing.T) {
	// El EndUser debe aparecer en el KeyID para trazabilidad en sshd.
	d, err := policyWithGroups().Resolve(Intent{
		Caller: "broker", Host: "prod-web", Role: RoleTarget, Purpose: PurposeOneshot,
		Command: "uptime", RequestedTTL: time.Minute,
		EndUser: "alice", EndUserGroups: []string{"prod"},
	}, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(d.Constraints.KeyID, "user=alice") {
		t.Errorf("KeyID debe incluir user=alice, es %q", d.Constraints.KeyID)
	}
}
