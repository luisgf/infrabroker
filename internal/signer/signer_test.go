package signer

import (
	"testing"
	"time"
)

func testPolicy() PolicyTable {
	return PolicyTable{
		"web01":   {Principal: "host:web01", SourceAddress: "10.0.0.1", MaxTTL: 2 * time.Minute},
		"bastion": {Principal: "host:bastion", AllowAsBastion: true},
		"locked":  {Principal: "host:locked", AllowedCallers: []string{"broker-a"}},
		"sudohost": {
			Principal: "host:sudohost", SourceAddress: "10.0.0.3", MaxTTL: 2 * time.Minute,
			AllowSudo: true, AllowedSudoUsers: []string{"root", "deploy"}, AllowPTY: true,
		},
		"nosudohost": {Principal: "host:nosudohost", SourceAddress: "10.0.0.4", MaxTTL: 2 * time.Minute},
	}
}

func TestResolveTargetOneshot(t *testing.T) {
	c, _, err := testPolicy().Resolve(Intent{
		Caller: "x", Host: "web01", Role: RoleTarget, Purpose: PurposeOneshot,
		Command: "uptime", RequestedTTL: time.Minute,
	}, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if c.ForceCommand != "uptime" {
		t.Errorf("force-command = %q, quiero uptime", c.ForceCommand)
	}
	if c.AllowPortForwarding {
		t.Error("destino no debe tener port-forwarding")
	}
	if c.SourceAddress != "10.0.0.1" || c.Principal != "host:web01" {
		t.Errorf("constraints = %+v", c)
	}
}

func TestResolveSessionNoForceCommand(t *testing.T) {
	c, _, _ := testPolicy().Resolve(Intent{
		Caller: "x", Host: "web01", Role: RoleTarget, Purpose: PurposeSession,
		Command: "ignorado", RequestedTTL: time.Minute,
	}, 5*time.Minute)
	if c.ForceCommand != "" {
		t.Errorf("sesión no debe llevar force-command, tiene %q", c.ForceCommand)
	}
}

func TestResolveBastionForwarding(t *testing.T) {
	c, _, err := testPolicy().Resolve(Intent{
		Caller: "x", Host: "bastion", Role: RoleBastion, Purpose: PurposeSession,
		RequestedTTL: time.Minute,
	}, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !c.AllowPortForwarding {
		t.Error("bastión debe permitir port-forwarding")
	}
}

func TestResolveTTLCap(t *testing.T) {
	c, _, _ := testPolicy().Resolve(Intent{
		Caller: "x", Host: "web01", Role: RoleTarget, Purpose: PurposeOneshot,
		RequestedTTL: time.Hour, // mayor que MaxTTL=2m
	}, 5*time.Minute)
	if c.TTL != 2*time.Minute {
		t.Errorf("TTL = %s, quiero capado a 2m", c.TTL)
	}
}

func TestResolveAuthz(t *testing.T) {
	p := testPolicy()
	if _, _, err := p.Resolve(Intent{Caller: "broker-b", Host: "locked", Role: RoleTarget, Purpose: PurposeOneshot, RequestedTTL: time.Minute}, time.Minute); err == nil {
		t.Error("esperaba denegación para caller no autorizado")
	}
	if _, _, err := p.Resolve(Intent{Caller: "broker-a", Host: "locked", Role: RoleTarget, Purpose: PurposeOneshot, RequestedTTL: time.Minute}, time.Minute); err != nil {
		t.Errorf("caller autorizado no debería fallar: %v", err)
	}
}

func TestResolveErrors(t *testing.T) {
	p := testPolicy()
	if _, _, err := p.Resolve(Intent{Caller: "x", Host: "inexistente", Role: RoleTarget, RequestedTTL: time.Minute}, time.Minute); err == nil {
		t.Error("esperaba error por host sin política")
	}
	// web01 no tiene AllowAsBastion → no puede usarse como bastión.
	if _, _, err := p.Resolve(Intent{Caller: "x", Host: "web01", Role: RoleBastion, RequestedTTL: time.Minute}, time.Minute); err == nil {
		t.Error("esperaba error: web01 no permitido como bastión")
	}
}

// --- Tests de elevación (sudo NOPASSWD) ---

func TestResolveSudoOneshotRoot(t *testing.T) {
	c, elevPrefix, err := testPolicy().Resolve(Intent{
		Caller: "x", Host: "sudohost", Role: RoleTarget, Purpose: PurposeOneshot,
		Command: "id", RequestedTTL: time.Minute,
		Sudo: true, // SudoUser vacío = root
	}, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	// One-shot: el prefijo va en ForceCommand, no en elevPrefix.
	if elevPrefix != "" {
		t.Errorf("elevPrefix debe ser vacío en one-shot, got %q", elevPrefix)
	}
	want := "sudo -n -- /bin/sh -c 'id'"
	if c.ForceCommand != want {
		t.Errorf("force-command = %q, quiero %q", c.ForceCommand, want)
	}
}

func TestResolveSudoOneshotUser(t *testing.T) {
	c, _, err := testPolicy().Resolve(Intent{
		Caller: "x", Host: "sudohost", Role: RoleTarget, Purpose: PurposeOneshot,
		Command: "whoami", RequestedTTL: time.Minute,
		Sudo: true, SudoUser: "deploy",
	}, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	want := "sudo -n -u deploy -- /bin/sh -c 'whoami'"
	if c.ForceCommand != want {
		t.Errorf("force-command = %q, quiero %q", c.ForceCommand, want)
	}
}

func TestResolveSudoSessionReturnsPrefix(t *testing.T) {
	_, elevPrefix, err := testPolicy().Resolve(Intent{
		Caller: "x", Host: "sudohost", Role: RoleTarget, Purpose: PurposeSession,
		RequestedTTL: time.Minute, Sudo: true,
	}, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if elevPrefix != "sudo -n" {
		t.Errorf("elevPrefix = %q, quiero 'sudo -n'", elevPrefix)
	}
}

func TestResolveSudoDeniedNoPolicy(t *testing.T) {
	_, _, err := testPolicy().Resolve(Intent{
		Caller: "x", Host: "nosudohost", Role: RoleTarget, Purpose: PurposeOneshot,
		Command: "id", RequestedTTL: time.Minute, Sudo: true,
	}, 5*time.Minute)
	if err == nil {
		t.Error("esperaba denegación por allow_sudo=false")
	}
}

func TestResolveSudoUserNotAllowed(t *testing.T) {
	_, _, err := testPolicy().Resolve(Intent{
		Caller: "x", Host: "sudohost", Role: RoleTarget, Purpose: PurposeOneshot,
		Command: "id", RequestedTTL: time.Minute,
		Sudo: true, SudoUser: "notallowed",
	}, 5*time.Minute)
	if err == nil {
		t.Error("esperaba denegación por usuario no en whitelist")
	}
}

func TestResolveSudoUserMalicious(t *testing.T) {
	// Intentos de inyección.
	for _, bad := range []string{"-rf /", "root; rm -rf /", "../etc/passwd", "root --option"} {
		_, _, err := testPolicy().Resolve(Intent{
			Caller: "x", Host: "sudohost", Role: RoleTarget, Purpose: PurposeOneshot,
			Command: "id", RequestedTTL: time.Minute, Sudo: true, SudoUser: bad,
		}, 5*time.Minute)
		if err == nil {
			t.Errorf("esperaba error para sudo_user malicioso %q", bad)
		}
	}
}

func TestResolveSudoOneshotCommandWithQuotes(t *testing.T) {
	// El quoting debe escapar las comillas simples del comando.
	c, _, err := testPolicy().Resolve(Intent{
		Caller: "x", Host: "sudohost", Role: RoleTarget, Purpose: PurposeOneshot,
		Command: "echo 'hello world'", RequestedTTL: time.Minute, Sudo: true,
	}, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	want := `sudo -n -- /bin/sh -c 'echo '\''hello world'\'''`
	if c.ForceCommand != want {
		t.Errorf("force-command = %q, quiero %q", c.ForceCommand, want)
	}
}

// --- Tests de PTY ---

func TestResolvePTYAllowed(t *testing.T) {
	c, _, err := testPolicy().Resolve(Intent{
		Caller: "x", Host: "sudohost", Role: RoleTarget, Purpose: PurposeSession,
		RequestedTTL: time.Minute, PTY: true,
	}, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !c.AllowPTY {
		t.Error("AllowPTY debe ser true cuando se pide y la política lo permite")
	}
}

func TestResolvePTYDenied(t *testing.T) {
	_, _, err := testPolicy().Resolve(Intent{
		Caller: "x", Host: "nosudohost", Role: RoleTarget, Purpose: PurposeSession,
		RequestedTTL: time.Minute, PTY: true,
	}, 5*time.Minute)
	if err == nil {
		t.Error("esperaba denegación por allow_pty=false")
	}
}

// --- Tests de RBAC por grupos (HostSetForCaller) ---

func testGroupPolicy() PolicyTable {
	return PolicyTable{
		"web01":   {Principal: "host:web01", Groups: []string{"prod-web"}},
		"web02":   {Principal: "host:web02", Groups: []string{"prod-web"}},
		"bastion": {Principal: "host:bastion", Groups: []string{"prod-web"}, AllowAsBastion: true},
		"db01":    {Principal: "host:db01", Groups: []string{"databases"}},
		"shared":  {Principal: "host:shared", Groups: []string{"prod-web", "databases"}},
		"ungrouped": {Principal: "host:ungrouped"},
	}
}

func TestHostSetForCallerNotInTable(t *testing.T) {
	_, restricted := HostSetForCaller("unknown-broker", testGroupPolicy(), CallerTable{
		"broker-prod": {AllowedGroups: []string{"prod-web"}},
	})
	if restricted {
		t.Error("caller no en CallerTable no debe tener restricción")
	}
}

func TestHostSetForCallerWithGroup(t *testing.T) {
	set, restricted := HostSetForCaller("broker-prod", testGroupPolicy(), CallerTable{
		"broker-prod": {AllowedGroups: []string{"prod-web"}},
	})
	if !restricted {
		t.Fatal("broker-prod debe tener restricción")
	}
	for _, want := range []string{"web01", "web02", "bastion", "shared"} {
		if _, ok := set[want]; !ok {
			t.Errorf("host %q debe estar en el set", want)
		}
	}
	for _, notWant := range []string{"db01", "ungrouped"} {
		if _, ok := set[notWant]; ok {
			t.Errorf("host %q no debe estar en el set", notWant)
		}
	}
}

func TestHostSetForCallerEmptyGroups(t *testing.T) {
	set, restricted := HostSetForCaller("broker-limited", testGroupPolicy(), CallerTable{
		"broker-limited": {AllowedGroups: []string{}},
	})
	if !restricted {
		t.Fatal("caller con allowed_groups vacío debe tener restricción")
	}
	if len(set) != 0 {
		t.Errorf("set debe ser vacío, tiene %d hosts", len(set))
	}
}

func TestHostSetForCallerMultipleGroups(t *testing.T) {
	set, restricted := HostSetForCaller("broker-all", testGroupPolicy(), CallerTable{
		"broker-all": {AllowedGroups: []string{"prod-web", "databases"}},
	})
	if !restricted {
		t.Fatal("broker-all debe tener restricción")
	}
	for _, want := range []string{"web01", "web02", "bastion", "db01", "shared"} {
		if _, ok := set[want]; !ok {
			t.Errorf("host %q debe estar en el set", want)
		}
	}
	if _, ok := set["ungrouped"]; ok {
		t.Error("ungrouped no debe estar en el set")
	}
}

func TestHostSetForCallerUnknownGroup(t *testing.T) {
	set, restricted := HostSetForCaller("broker-x", testGroupPolicy(), CallerTable{
		"broker-x": {AllowedGroups: []string{"nonexistent-group"}},
	})
	if !restricted {
		t.Fatal("broker-x debe tener restricción")
	}
	if len(set) != 0 {
		t.Errorf("grupo inexistente no debe añadir hosts, tiene %d", len(set))
	}
}

func TestHostSetForCallerSharedHost(t *testing.T) {
	// 'shared' pertenece a prod-web y databases; ambos callers deben verlo.
	for _, cn := range []string{"broker-prod", "broker-db"} {
		callers := CallerTable{
			"broker-prod": {AllowedGroups: []string{"prod-web"}},
			"broker-db":   {AllowedGroups: []string{"databases"}},
		}
		set, _ := HostSetForCaller(cn, testGroupPolicy(), callers)
		if _, ok := set["shared"]; !ok {
			t.Errorf("%s debe ver el host shared", cn)
		}
	}
}

func TestShellQuote(t *testing.T) {
	cases := []struct{ in, want string }{
		{"hello", "'hello'"},
		{"it's", `'it'\''s'`},
		{"a'b'c", `'a'\''b'\''c'`},
		{"", "''"},
	}
	for _, tc := range cases {
		got := shellQuote(tc.in)
		if got != tc.want {
			t.Errorf("shellQuote(%q) = %q, quiero %q", tc.in, got, tc.want)
		}
	}
}
