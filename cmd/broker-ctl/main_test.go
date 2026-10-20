package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/luisgf/infrabroker/internal/audit"
	"github.com/luisgf/infrabroker/internal/confcheck"
	"golang.org/x/crypto/ssh"
)

// TestWriteConfigAtomicPreservesGroup is the #559 guard: the atomic rewrite
// keeps the config's group (the production signer.json is
// infrabroker-signer:infrabroker-signer and edited by a root-run broker-ctl).
// The file is chgrp'd to a secondary group of the test user so the temp's
// egid differs from the file's gid; skipped when the user has none.
func TestWriteConfigAtomicPreservesGroup(t *testing.T) {
	t.Parallel()
	groups, err := os.Getgroups()
	if err != nil {
		t.Skipf("Getgroups: %v", err)
	}
	gid := -1
	for _, g := range groups {
		if g != os.Getegid() {
			gid = g
			break
		}
	}
	if gid == -1 {
		t.Skip("test user has no secondary group")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "signer.json")
	if err := os.WriteFile(path, []byte("{}"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, -1, gid); err != nil {
		t.Skipf("chgrp to secondary group %d: %v", gid, err)
	}
	if err := writeConfigAtomic(path, []byte(`{"b":2}`)); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := int(fi.Sys().(*syscall.Stat_t).Gid); got != gid {
		t.Errorf("gid = %d after rewrite, want %d (group must survive)", got, gid)
	}
	if fi.Mode().Perm() != 0o640 {
		t.Errorf("mode = %o, want 0640", fi.Mode().Perm())
	}
}

// TestWriteConfigAtomicPreservesOwner is the root half of #559: only euid 0
// can give a file away, so the owner check runs when the tests do (e.g. in a
// container) and is skipped otherwise.
func TestWriteConfigAtomicPreservesOwner(t *testing.T) {
	t.Parallel()
	if os.Geteuid() != 0 {
		t.Skip("owner preservation needs euid 0")
	}
	u, err := user.Lookup("nobody")
	if err != nil {
		t.Skipf("lookup nobody: %v", err)
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	dir := t.TempDir()
	path := filepath.Join(dir, "signer.json")
	if err := os.WriteFile(path, []byte("{}"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, uid, gid); err != nil {
		t.Fatal(err)
	}
	if err := writeConfigAtomic(path, []byte(`{"b":2}`)); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	if int(st.Uid) != uid || int(st.Gid) != gid {
		t.Errorf("owner = %d:%d after rewrite, want %d:%d", st.Uid, st.Gid, uid, gid)
	}
}

// TestWriteConfigAtomicPreservesModeNoLitter is the #220 guard: the atomic
// rewrite keeps the config's existing permissions rather than adopting a
// stale/planted temp's mode, and leaves no temp file behind.
func TestWriteConfigAtomicPreservesModeNoLitter(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "broker-ctl.json")
	if err := os.WriteFile(path, []byte("{}"), 0o640); err != nil {
		t.Fatal(err)
	}
	fi0, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	want := fi0.Mode().Perm()

	if err := writeConfigAtomic(path, []byte(`{"b":2}`)); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); string(got) != `{"b":2}` {
		t.Errorf("content = %q, want {\"b\":2}", got)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != want {
		t.Errorf("permissions changed from %o to %o (must not widen)", want, fi.Mode().Perm())
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 || entries[0].Name() != "broker-ctl.json" {
		t.Errorf("expected only broker-ctl.json (no temp litter), got %v", entries)
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

// testAuditKey returns a deterministic Ed25519 key (seed = 0x02 * 32).
func testAuditKey() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 0x02
	}
	return ed25519.NewKeyFromSeed(seed)
}

// buildLog writes n real entries to a temporary file using internal/audit.Log
// and returns the file path.
func buildLog(t *testing.T, n int) (path string, key ed25519.PrivateKey) {
	t.Helper()
	key = testAuditKey()
	path = filepath.Join(t.TempDir(), "audit.log")
	l, err := audit.Open(path, key)
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	for i := 0; i < n; i++ {
		if err := l.Append(audit.Entry{
			Caller:  "test-caller",
			Host:    "web01:22",
			Command: "uptime",
			Outcome: "executed",
		}); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	l.Close()
	return path, key
}

// ── Audit helper unit tests ───────────────────────────────────────────────────

func TestLastNLinesRingBuffer(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	var buf bytes.Buffer
	for i := 1; i <= 10; i++ {
		buf.WriteString(strings.Repeat("x", 20)) // line content
		buf.WriteByte('\n')
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	lines, _, err := lastNLines(path, 3)
	if err != nil {
		t.Fatalf("lastNLines: %v", err)
	}
	if len(lines) != 3 {
		t.Errorf("expected 3 lines, got %d", len(lines))
	}
}

func TestLastNLinesMayorQueTotal(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "small.log")
	content := "linea1\nlinea2\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	lines, _, err := lastNLines(path, 100)
	if err != nil {
		t.Fatalf("lastNLines: %v", err)
	}
	if len(lines) != 2 {
		t.Errorf("expected 2 lines, got %d", len(lines))
	}
}

func TestLastNLinesFicheroInexistente(t *testing.T) {
	t.Parallel()
	_, _, err := lastNLines("/tmp/no-such-file-infrabroker-test.log", 5)
	if err == nil {
		t.Error("non-existent file must return error")
	}
}

func TestParseAuditTime(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in      string
		wantErr bool
	}{
		{"2026-06-08T14:00:00Z", false},
		{"2026-06-08", false},
		{"not-a-date", true},
		{"2026/06/08", true},
	}
	for _, c := range cases {
		_, err := parseAuditTime(c.in)
		if c.wantErr && err == nil {
			t.Errorf("parseAuditTime(%q): expected error", c.in)
		}
		if !c.wantErr && err != nil {
			t.Errorf("parseAuditTime(%q): unexpected error: %v", c.in, err)
		}
	}
}

func TestSplitComma(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want []string
	}{
		{"a,b,c", []string{"a", "b", "c"}},
		{"a, b , c", []string{"a", "b", "c"}},
		{"", nil},
		{"a", []string{"a"}},
		{",,,", nil},
	}
	for _, c := range cases {
		got := splitComma(c.in)
		if len(got) != len(c.want) {
			t.Errorf("splitComma(%q): got %v, want %v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("splitComma(%q)[%d]: got %q, want %q", c.in, i, got[i], c.want[i])
			}
		}
	}
}

func TestBoolStr(t *testing.T) {
	t.Parallel()
	if boolStr(true) != "yes" {
		t.Error("boolStr(true) must be \"yes\"")
	}
	if boolStr(false) != "no" {
		t.Error("boolStr(false) must be \"no\"")
	}
}

func TestAuditDetail(t *testing.T) {
	t.Parallel()
	cases := []struct {
		e    audit.Entry
		want string
	}{
		{audit.Entry{Command: "uptime"}, "uptime"},
		{audit.Entry{Command: "id", Elevation: "sudo:root"}, "id [sudo:root]"},
		{audit.Entry{Command: "id", PTY: true}, "id [pty]"},
		{audit.Entry{Command: "id", Err: "timeout"}, "id [err: timeout]"},
		{audit.Entry{Command: "id", Elevation: "sudo:root", PTY: true, Err: "fail"}, "id [sudo:root] [pty] [err: fail]"},
		{audit.Entry{Command: "id", PolicyRule: "^id$"}, "id [rule: ^id$]"},
		{audit.Entry{Command: "id", DryRun: true}, "id [dry-run]"},
		{audit.Entry{Command: "reboot", ApprovedBy: "admin"}, "reboot [approved-by: admin]"},
		{audit.Entry{Command: "id", Anomaly: "rate-exceeded"}, "id [anomaly: rate-exceeded]"},
		{audit.Entry{Command: "id", Warning: "command_policy audit: would deny"}, "id [warning: command_policy audit: would deny]"},
		{audit.Entry{Command: "reboot", PolicyRule: "^reboot$", ApprovedBy: "admin", Anomaly: "new-host:web02"},
			"reboot [rule: ^reboot$] [approved-by: admin] [anomaly: new-host:web02]"},
	}
	for _, c := range cases {
		got := auditDetail(c.e)
		if got != c.want {
			t.Errorf("auditDetail(%+v): got %q, want %q", c.e, got, c.want)
		}
	}
}

// ── commandPolicyLabel tests ──────────────────────────────────────────────────

func TestCommandPolicyLabel(t *testing.T) {
	t.Parallel()
	cases := []struct {
		raw  json.RawMessage
		want string
	}{
		{nil, "—"},
		{json.RawMessage(`{}`), "—"},
		{json.RawMessage(`{"mode":"allowlist","allow":["^ls","^cat"]}`), "allowlist(2)"},
		{json.RawMessage(`{"mode":"allowlist","enforcement":"audit","allow":["^ls"]}`), "allowlist(1) audit"},
		{json.RawMessage(`{"mode":"allowlist","allow":["^uptime$"]}`), "allowlist(1)"},
		{json.RawMessage(`{"mode":"denylist","deny":["rm -rf","dd"]}`), "denylist(2)"},
		{json.RawMessage(`{"mode":"denylist","deny":["rm"]}`), "denylist(1)"},
		{json.RawMessage(`{"mode":"off"}`), "off"},
		{json.RawMessage(`{"mode":"off","require_approval":["^reboot"]}`), "off+approval(1)"},
		{json.RawMessage(`{"require_approval":["^reboot","^shutdown"]}`), "approval(2)"},
		{json.RawMessage(`{"require_approval":["^reboot"]}`), "approval(1)"},
	}
	for _, c := range cases {
		got := commandPolicyLabel(c.raw)
		if got != c.want {
			t.Errorf("commandPolicyLabel(%s) = %q, want %q", c.raw, got, c.want)
		}
	}
}

// ── buildCommandPolicyJSON tests ──────────────────────────────────────────────

func TestBuildCommandPolicyJSONAllowlist(t *testing.T) {
	t.Parallel()
	raw, err := buildCommandPolicyJSON("allowlist", "", "^ls,^cat", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	var cp struct {
		Mode  string   `json:"mode"`
		Allow []string `json:"allow"`
	}
	if err := json.Unmarshal(raw, &cp); err != nil {
		t.Fatal(err)
	}
	if cp.Mode != "allowlist" {
		t.Errorf("mode = %q, want allowlist", cp.Mode)
	}
	if len(cp.Allow) != 2 {
		t.Errorf("allow = %v, want 2 items", cp.Allow)
	}
}

func TestBuildCommandPolicyJSONDenylist(t *testing.T) {
	t.Parallel()
	raw, err := buildCommandPolicyJSON("denylist", "", "", "rm -rf,dd", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	var cp struct {
		Mode string   `json:"mode"`
		Deny []string `json:"deny"`
	}
	if err := json.Unmarshal(raw, &cp); err != nil {
		t.Fatal(err)
	}
	if cp.Mode != "denylist" {
		t.Errorf("mode = %q, want denylist", cp.Mode)
	}
	if len(cp.Deny) != 2 {
		t.Errorf("deny = %v, want 2 items", cp.Deny)
	}
}

func TestBuildCommandPolicyJSONShellParse(t *testing.T) {
	t.Parallel()
	boolPtr := func(b bool) *bool { return &b }

	// nil (flag not passed) omits the key so the host inherits the signer's
	// parse-on default; explicit true/false author the key verbatim.
	tests := []struct {
		name      string
		arg       *bool
		wantKey   bool
		wantValue bool
	}{
		{"unset omits key (default on)", nil, false, false},
		{"explicit true", boolPtr(true), true, true},
		{"explicit false (opt-out)", boolPtr(false), true, false},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			raw, err := buildCommandPolicyJSON("allowlist", "", "^uptime$", "", "", tc.arg)
			if err != nil {
				t.Fatal(err)
			}
			var cp struct {
				ShellParse *bool `json:"shell_parse"`
			}
			if err := json.Unmarshal(raw, &cp); err != nil {
				t.Fatal(err)
			}
			if tc.wantKey {
				if cp.ShellParse == nil {
					t.Fatalf("shell_parse key missing, want %v", tc.wantValue)
				}
				if *cp.ShellParse != tc.wantValue {
					t.Errorf("shell_parse = %v, want %v", *cp.ShellParse, tc.wantValue)
				}
			} else if cp.ShellParse != nil {
				t.Errorf("shell_parse present (%v), want omitted", *cp.ShellParse)
			}
		})
	}
}

func TestBuildCommandPolicyJSONEnforcement(t *testing.T) {
	t.Parallel()
	raw, err := buildCommandPolicyJSON("allowlist", "audit", "^uptime$", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	var cp struct {
		Enforcement string `json:"enforcement"`
	}
	if err := json.Unmarshal(raw, &cp); err != nil {
		t.Fatal(err)
	}
	if cp.Enforcement != "audit" {
		t.Errorf("enforcement = %q, want audit", cp.Enforcement)
	}
}

func TestMergeCommandPolicyJSONPreservesEnforcement(t *testing.T) {
	t.Parallel()
	existing := json.RawMessage(`{"mode":"allowlist","enforcement":"audit","allow":["^uptime$"]}`)
	raw, err := mergeCommandPolicyJSON(existing, map[string]bool{"allow": true}, "", "", "^df -h$", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	var cp struct {
		Enforcement string   `json:"enforcement"`
		Allow       []string `json:"allow"`
	}
	if err := json.Unmarshal(raw, &cp); err != nil {
		t.Fatal(err)
	}
	if cp.Enforcement != "audit" {
		t.Errorf("enforcement = %q, want audit", cp.Enforcement)
	}
	if len(cp.Allow) != 1 || cp.Allow[0] != "^df -h$" {
		t.Errorf("allow = %v", cp.Allow)
	}
}

// ── extractCAKeys / writeCAKeys tests ─────────────────────────────────────────

func TestExtractCAKeysEmpty(t *testing.T) {
	t.Parallel()
	raw := map[string]json.RawMessage{}
	keys, err := extractCAKeys(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Error("expected empty map")
	}
}

func TestExtractCAKeysParsed(t *testing.T) {
	t.Parallel()
	raw := map[string]json.RawMessage{
		"ca_keys": json.RawMessage(`{"_default":{"type":"pem","path":"/etc/ca.key"},"prod":{"type":"akv","vault_url":"https://v.vault.azure.net","key_name":"ca"}}`),
	}
	keys, err := extractCAKeys(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}
	var def, prod caKeyEntry
	if err := json.Unmarshal(keys["_default"], &def); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(keys["prod"], &prod); err != nil {
		t.Fatal(err)
	}
	if def.Type != "pem" {
		t.Errorf("_default.type = %q, want pem", def.Type)
	}
	if def.Path != "/etc/ca.key" {
		t.Errorf("_default.path = %q, want /etc/ca.key", def.Path)
	}
	if prod.Type != "akv" {
		t.Errorf("prod.type = %q, want akv", prod.Type)
	}
	if prod.VaultURL != "https://v.vault.azure.net" {
		t.Errorf("prod.vault_url = %q", prod.VaultURL)
	}
}

// mustMarshalCAKey marshals a caKeyEntry as raw JSON, as cmdCAKeysAdd does.
func mustMarshalCAKey(t *testing.T, e caKeyEntry) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal caKeyEntry: %v", err)
	}
	return b
}

func TestCAKeysRoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "signer.json")
	if err := os.WriteFile(cfgPath, []byte(`{"ca_key":"/etc/ca.key","hosts":{}}`), 0640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if err := patchConfigEntry(cfgPath, "ca_keys", "_default", mustMarshalCAKey(t, caKeyEntry{Type: "pem", Path: "/new/ca.key"}), false); err != nil {
		t.Fatal(err)
	}
	if err := patchConfigEntry(cfgPath, "ca_keys", "prod", mustMarshalCAKey(t, caKeyEntry{Type: "akv", VaultURL: "https://prod.vault.azure.net", KeyName: "ssh-ca"}), false); err != nil {
		t.Fatal(err)
	}

	raw2, err := loadRaw(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	keys2, err := extractCAKeys(raw2)
	if err != nil {
		t.Fatal(err)
	}

	var def, prod caKeyEntry
	if err := json.Unmarshal(keys2["_default"], &def); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(keys2["prod"], &prod); err != nil {
		t.Fatal(err)
	}
	if def.Type != "pem" || def.Path != "/new/ca.key" {
		t.Errorf("_default not preserved: %+v", def)
	}
	if prod.Type != "akv" || prod.KeyName != "ssh-ca" {
		t.Errorf("prod not preserved: %+v", prod)
	}
	// Original ca_key field must still be present (other fields preserved).
	if _, ok := raw2["ca_key"]; !ok {
		t.Error("ca_key field must be preserved by writeCAKeys")
	}
}

func TestCAKeysRemoveRoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "signer.json")
	initial := `{"ca_key":"/etc/ca.key","ca_keys":{"_default":{"type":"pem","path":"/etc/ca.key"},"prod":{"type":"akv","vault_url":"https://v.vault.azure.net","key_name":"ca"}},"hosts":{}}`
	if err := os.WriteFile(cfgPath, []byte(initial), 0640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if err := patchConfigEntry(cfgPath, "ca_keys", "prod", nil, true); err != nil {
		t.Fatal(err)
	}

	raw2, err := loadRaw(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	keys2, err := extractCAKeys(raw2)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := keys2["prod"]; exists {
		t.Error("prod must have been removed")
	}
	if _, exists := keys2["_default"]; !exists {
		t.Error("_default must still be present")
	}
}

// TestCAKeysAddRemovePreservaCamposAKV is a regression test: the old 4-field
// mirror struct re-serialised the whole ca_keys map on every add/remove,
// silently stripping key_version, tenant_id, client_id and client_secret_env
// from ALL entries. Entries not being touched must round-trip intact.
func TestCAKeysAddRemovePreservaCamposAKV(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "signer.json")
	initial := `{"ca_keys":{"prod":{"type":"akv","vault_url":"https://v.vault.azure.net","key_name":"ca","key_version":"abc123","tenant_id":"tid-1","client_id":"cid-1","client_secret_env":"AKV_SECRET"}},"hosts":{}}`
	if err := os.WriteFile(cfgPath, []byte(initial), 0640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Add an unrelated entry (as cmdCAKeysAdd does), then remove it again.
	if err := patchConfigEntry(cfgPath, "ca_keys", "lab", mustMarshalCAKey(t, caKeyEntry{Type: "pem", Path: "/lab/ca.key"}), false); err != nil {
		t.Fatal(err)
	}
	if err := patchConfigEntry(cfgPath, "ca_keys", "lab", nil, true); err != nil {
		t.Fatal(err)
	}

	// The prod entry must still carry every AKV field.
	raw3, err := loadRaw(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	keys3, err := extractCAKeys(raw3)
	if err != nil {
		t.Fatal(err)
	}
	var prod map[string]string
	if err := json.Unmarshal(keys3["prod"], &prod); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"type": "akv", "vault_url": "https://v.vault.azure.net", "key_name": "ca",
		"key_version": "abc123", "tenant_id": "tid-1", "client_id": "cid-1",
		"client_secret_env": "AKV_SECRET",
	}
	for k, v := range want {
		if prod[k] != v {
			t.Errorf("prod[%q] = %q, want %q (field stripped by add/remove round-trip)", k, prod[k], v)
		}
	}
}

// TestCAKeysAddForcePreservesUnmodeledKeys is the #560 guard: a --force
// key_name change on an AKV entry must keep the pinned key_version and the
// service-principal override (tenant_id, client_id, client_secret_env) that
// broker-ctl has no flags for, instead of replacing the whole object.
func TestCAKeysAddForcePreservesUnmodeledKeys(t *testing.T) {
	t.Parallel()
	cfgPath := filepath.Join(t.TempDir(), "signer.json")
	orig := `{"ca_keys":{"_default":{"type":"akv","vault_url":"https://v.vault.azure.net","key_name":"k","key_version":"v1","tenant_id":"t","client_id":"c","client_secret_env":"AZ"}}}`
	if err := os.WriteFile(cfgPath, []byte(orig), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, _, err := caKeysAdd(cfgPath, "_default", caKeyEntry{Type: "akv", VaultURL: "https://v.vault.azure.net", KeyName: "k2"}, false); err == nil {
		t.Fatal("existing entry without --force must be refused")
	}
	action, dropped, err := caKeysAdd(cfgPath, "_default", caKeyEntry{Type: "akv", VaultURL: "https://v.vault.azure.net", KeyName: "k2"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if action != "updated" || dropped != nil {
		t.Errorf("action=%q dropped=%v, want updated / nil (same type drops nothing)", action, dropped)
	}
	raw, err := loadRaw(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := extractCAKeys(raw)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	if err := json.Unmarshal(keys["_default"], &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"type": "akv", "vault_url": "https://v.vault.azure.net", "key_name": "k2",
		"key_version": "v1", "tenant_id": "t", "client_id": "c", "client_secret_env": "AZ",
	}
	if len(got) != len(want) {
		t.Errorf("entry = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}

// TestOverlayCAKeyEntryTypeChangeDropsBackendKeys verifies the other half of
// #560: when --force changes the backend type the old backend's keys are
// removed explicitly (and reported), while unrelated keys stay.
func TestOverlayCAKeyEntryTypeChangeDropsBackendKeys(t *testing.T) {
	t.Parallel()
	existing := json.RawMessage(`{"type":"akv","vault_url":"https://v","key_name":"k","key_version":"v1","tenant_id":"t","client_id":"c","client_secret_env":"AZ","future_key":1}`)
	merged, dropped, err := overlayCAKeyEntry(existing, caKeyEntry{Type: "pem", Path: "/ca.key"})
	if err != nil {
		t.Fatal(err)
	}
	if len(dropped) != 7 || dropped[0] != "akv" {
		t.Errorf("dropped = %v, want [akv + the six akv keys]", dropped)
	}
	for _, k := range []string{"vault_url", "key_name", "key_version", "tenant_id", "client_id", "client_secret_env"} {
		if _, ok := merged[k]; ok {
			t.Errorf("%s must be dropped on a type change", k)
		}
	}
	if string(merged["type"]) != `"pem"` || string(merged["path"]) != `"/ca.key"` {
		t.Errorf("merged = %v, want type pem + path", merged)
	}
	if string(merged["future_key"]) != "1" {
		t.Errorf("future_key = %q, want preserved", merged["future_key"])
	}
	// Same type, nothing dropped; the unflagged socket survives.
	m2, d2, err := overlayCAKeyEntry(json.RawMessage(`{"type":"agent","socket":"/run/agent","public_key_path":"/old.pub"}`), caKeyEntry{Type: "agent", PublicKeyPath: "/new.pub"})
	if err != nil || d2 != nil || string(m2["socket"]) != `"/run/agent"` || string(m2["public_key_path"]) != `"/new.pub"` {
		t.Errorf("agent overlay: merged=%v dropped=%v err=%v", m2, d2, err)
	}
}

// TestCAKeysAddSoloCamposDeFlags verifies that a new entry contains exactly
// the fields provided via flags: no empty key_version/tenant_id/... appear.
func TestCAKeysAddSoloCamposDeFlags(t *testing.T) {
	t.Parallel()
	b := mustMarshalCAKey(t, caKeyEntry{Type: "akv", VaultURL: "https://v.vault.azure.net", KeyName: "ca"})
	var fields map[string]any
	if err := json.Unmarshal(b, &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 3 {
		t.Errorf("expected exactly 3 fields (type, vault_url, key_name), got %v", fields)
	}
}

// ── extractCallers / writeCallers tests ───────────────────────────────────────

func TestExtractCallersEmpty(t *testing.T) {
	t.Parallel()
	raw := map[string]json.RawMessage{}
	callers, err := extractCallers(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(callers) != 0 {
		t.Error("expected empty map")
	}
}

func TestExtractCallersParsed(t *testing.T) {
	t.Parallel()
	raw := map[string]json.RawMessage{
		"callers": json.RawMessage(`{"broker-prod":{"allowed_groups":["prod","staging"]},"broker-dev":{"allowed_groups":["dev"]}}`),
	}
	callers, err := extractCallers(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(callers) != 2 {
		t.Fatalf("expected 2 callers, got %d", len(callers))
	}
	c := callers["broker-prod"]
	if len(c.AllowedGroups) != 2 {
		t.Errorf("broker-prod groups = %v, want [prod staging]", c.AllowedGroups)
	}
	c2 := callers["broker-dev"]
	if len(c2.AllowedGroups) != 1 || c2.AllowedGroups[0] != "dev" {
		t.Errorf("broker-dev groups = %v, want [dev]", c2.AllowedGroups)
	}
}

func TestCallersRoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "signer.json")
	if err := os.WriteFile(cfgPath, []byte(`{"ca_key":"/etc/ca.key","hosts":{}}`), 0640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if err := patchConfigEntry(cfgPath, "callers", "broker-prod", callerEntry{AllowedGroups: []string{"prod", "staging"}}, false); err != nil {
		t.Fatal(err)
	}
	if err := patchConfigEntry(cfgPath, "callers", "broker-dev", callerEntry{AllowedGroups: []string{"dev"}}, false); err != nil {
		t.Fatal(err)
	}

	raw2, err := loadRaw(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	callers2, err := extractCallers(raw2)
	if err != nil {
		t.Fatal(err)
	}

	c := callers2["broker-prod"]
	if len(c.AllowedGroups) != 2 {
		t.Errorf("broker-prod groups = %v, want [prod staging]", c.AllowedGroups)
	}
	c2 := callers2["broker-dev"]
	if len(c2.AllowedGroups) != 1 || c2.AllowedGroups[0] != "dev" {
		t.Errorf("broker-dev groups = %v, want [dev]", c2.AllowedGroups)
	}
}

func TestCallersEmptyGroupsSerialisedAsArray(t *testing.T) {
	t.Parallel()
	// AllowedGroups has no omitempty; an empty list must serialise as [] not null.
	entry := callerEntry{AllowedGroups: []string{}}
	b, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"allowed_groups":[]`) {
		t.Errorf("empty AllowedGroups must serialise as []: got %s", b)
	}
}

// TestCallersAddForcePreservesSecurityFlags locks in #439: `callers add
// --force` must replace ONLY allowed_groups. Before the fix the whole object
// was rewritten as {allowed_groups}, silently dropping self_approve and
// require_verified_end_user (and any key broker-ctl does not model).
func TestCallersAddForcePreservesSecurityFlags(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "signer.json")
	initial := `{
  // comment that must survive
  "ca_key": "/etc/ca.key",
  "hosts": {},
  "callers": {
    "mcp-http": {"allowed_groups": ["web"], "self_approve": true, "require_verified_end_user": true, "future_key": "kept"},
    "other": {"allowed_groups": ["db"], "require_verified_end_user": true}
  }
}
`
	if err := os.WriteFile(cfgPath, []byte(initial), 0640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Without --force an existing entry is refused and the file is untouched.
	if _, err := callersAdd(cfgPath, "mcp-http", []string{"web", "db"}, false); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected already-exists error without --force, got %v", err)
	}

	action, err := callersAdd(cfgPath, "mcp-http", []string{"web", "db"}, true)
	if err != nil {
		t.Fatalf("callersAdd --force: %v", err)
	}
	if action != "updated" {
		t.Errorf("action = %q, want updated", action)
	}

	b, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "// comment that must survive") {
		t.Errorf("config comment lost:\n%s", b)
	}
	raw, err := loadRaw(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	// Raw view: both flags and the unknown key survive, groups updated.
	var rawCallers map[string]map[string]any
	if err := json.Unmarshal(raw["callers"], &rawCallers); err != nil {
		t.Fatal(err)
	}
	got := rawCallers["mcp-http"]
	if got["self_approve"] != true {
		t.Errorf("self_approve dropped by --force: %v", got)
	}
	if got["require_verified_end_user"] != true {
		t.Errorf("require_verified_end_user dropped by --force: %v", got)
	}
	if got["future_key"] != "kept" {
		t.Errorf("unknown key dropped by --force: %v", got)
	}
	if g, _ := json.Marshal(got["allowed_groups"]); string(g) != `["web","db"]` {
		t.Errorf("allowed_groups = %s, want [\"web\",\"db\"]", g)
	}
	// Sibling entry untouched.
	if rawCallers["other"]["require_verified_end_user"] != true || len(rawCallers["other"]) != 2 {
		t.Errorf("sibling entry modified: %v", rawCallers["other"])
	}

	// Typed view (what `callers list` renders) sees the flags too.
	callers, err := extractCallers(raw)
	if err != nil {
		t.Fatal(err)
	}
	c := callers["mcp-http"]
	if !c.SelfApprove || !c.RequireVerifiedEndUser {
		t.Errorf("typed entry lost flags: %+v", c)
	}
	if len(c.AllowedGroups) != 2 || c.AllowedGroups[0] != "web" || c.AllowedGroups[1] != "db" {
		t.Errorf("typed groups = %v, want [web db]", c.AllowedGroups)
	}

	// A brand-new CN still gets a plain {allowed_groups} object with [] for
	// an empty list, and an explicit --groups "" on --force keeps the flags
	// (deny-all by groups does not silently waive the other controls).
	if action, err := callersAdd(cfgPath, "new-cn", nil, false); err != nil || action != "added" {
		t.Fatalf("add new-cn: action=%q err=%v", action, err)
	}
	if _, err := callersAdd(cfgPath, "mcp-http", nil, true); err != nil {
		t.Fatal(err)
	}
	raw, err = loadRaw(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw["callers"], &rawCallers); err != nil {
		t.Fatal(err)
	}
	if g, _ := json.Marshal(rawCallers["new-cn"]); string(g) != `{"allowed_groups":[]}` {
		t.Errorf("new-cn = %s, want {\"allowed_groups\":[]}", g)
	}
	if g, _ := json.Marshal(rawCallers["mcp-http"]["allowed_groups"]); string(g) != `[]` || rawCallers["mcp-http"]["require_verified_end_user"] != true {
		t.Errorf("empty-groups --force: %v", rawCallers["mcp-http"])
	}
}

// TestRenderCallerTableShowsSecurityFlags: `callers list` must surface
// self_approve and require_verified_end_user so an operator can see (and miss)
// them (#439).
func TestRenderCallerTableShowsSecurityFlags(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	renderCallerTable(&buf, map[string]callerEntry{
		"b-plain": {AllowedGroups: []string{"dev"}},
		"a-http":  {AllowedGroups: []string{"web", "db"}, SelfApprove: true, RequireVerifiedEndUser: true},
	})
	out := buf.String()
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 {
		t.Fatalf("want header + 2 rows, got:\n%s", out)
	}
	for _, want := range []string{"NAME", "ALLOWED_GROUPS", "SELF_APPROVE", "REQUIRE_VERIFIED_END_USER"} {
		if !strings.Contains(lines[0], want) {
			t.Errorf("header missing %s: %q", want, lines[0])
		}
	}
	if f := strings.Fields(lines[1]); len(f) != 4 || f[0] != "a-http" || f[1] != "web,db" || f[2] != "yes" || f[3] != "yes" {
		t.Errorf("a-http row = %q", lines[1])
	}
	if f := strings.Fields(lines[2]); len(f) != 4 || f[0] != "b-plain" || f[1] != "dev" || f[2] != "-" || f[3] != "-" {
		t.Errorf("b-plain row = %q", lines[2])
	}
}

// ── CommandPolicy preservation tests ─────────────────────────────────────────

func TestCommandPolicyPreservedOnForce(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "signer.json")

	// Initial config with a host that has command_policy.
	initial := `{"ca_key":"/etc/ca.key","hosts":{"web01":{"addr":"10.0.0.1:22","user":"ubuntu","host_key":"ssh-ed25519 AAAA","principal":"host:web01","max_ttl_seconds":120,"command_policy":{"mode":"allowlist","allow":["^uptime$"]}}}}`
	if err := os.WriteFile(cfgPath, []byte(initial), 0640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Load and verify command_policy is captured.
	raw, err := loadRaw(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	hosts, err := extractHosts(raw)
	if err != nil {
		t.Fatal(err)
	}

	existing := hosts["web01"]
	if len(existing.CommandPolicy) == 0 {
		t.Fatal("CommandPolicy must be loaded from JSON")
	}

	// Simulate --force without policy flags: copy CommandPolicy to new entry.
	newEntry := hostEntry{
		Addr:          "10.0.0.1:22",
		User:          "ubuntu",
		HostKey:       "ssh-ed25519 AAAA",
		Principal:     "host:web01",
		MaxTTLSeconds: 300, // updated TTL
		CommandPolicy: existing.CommandPolicy,
	}
	if err := patchConfigEntry(cfgPath, "hosts", "web01", newEntry, false); err != nil {
		t.Fatal(err)
	}

	// Reload and verify CommandPolicy survived the round-trip.
	raw2, err := loadRaw(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	hosts2, err := extractHosts(raw2)
	if err != nil {
		t.Fatal(err)
	}
	h2 := hosts2["web01"]
	if len(h2.CommandPolicy) == 0 {
		t.Fatal("CommandPolicy must survive write+reload round-trip")
	}

	label := commandPolicyLabel(h2.CommandPolicy)
	if label != "allowlist(1)" {
		t.Errorf("commandPolicyLabel = %q, want allowlist(1)", label)
	}

	// Also verify the TTL update was applied.
	if h2.MaxTTLSeconds != 300 {
		t.Errorf("MaxTTLSeconds = %d, want 300", h2.MaxTTLSeconds)
	}
}

func TestCommandPolicyErasedWhenPolicyFlagsSet(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "signer.json")

	initial := `{"ca_key":"/etc/ca.key","hosts":{"web01":{"addr":"10.0.0.1:22","user":"ubuntu","host_key":"ssh-ed25519 AAAA","principal":"host:web01","command_policy":{"mode":"allowlist","allow":["^uptime$"]}}}}`
	if err := os.WriteFile(cfgPath, []byte(initial), 0640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	raw, err := loadRaw(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	hosts, err := extractHosts(raw)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate policy flags being set: build a new policy and do NOT copy the old one.
	newCP, err := buildCommandPolicyJSON("denylist", "", "", "rm -rf", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	newEntry := hosts["web01"]
	newEntry.CommandPolicy = newCP
	if err := patchConfigEntry(cfgPath, "hosts", "web01", newEntry, false); err != nil {
		t.Fatal(err)
	}

	raw2, err := loadRaw(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	hosts2, err := extractHosts(raw2)
	if err != nil {
		t.Fatal(err)
	}
	label := commandPolicyLabel(hosts2["web01"].CommandPolicy)
	if label != "denylist(1)" {
		t.Errorf("commandPolicyLabel = %q, want denylist(1)", label)
	}
}

func TestCommandPolicyNilWhenHostHasNone(t *testing.T) {
	t.Parallel()
	raw := map[string]json.RawMessage{
		"hosts": json.RawMessage(`{"web01":{"addr":"10.0.0.1:22","user":"ubuntu","host_key":"ssh-ed25519 AAAA","principal":"host:web01"}}`),
	}
	hosts, err := extractHosts(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts["web01"].CommandPolicy) != 0 {
		t.Error("CommandPolicy must be nil/empty for hosts without command_policy")
	}
	if label := commandPolicyLabel(hosts["web01"].CommandPolicy); label != "—" {
		t.Errorf("commandPolicyLabel for nil = %q, want —", label)
	}
}

// ── splitHostPortDefault tests ────────────────────────────────────────────────

func TestSplitHostPortDefault(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		addr     string
		wantHost string
		wantPort string
		wantErr  bool
	}{
		{"host-port", "10.0.0.1:22", "10.0.0.1", "22", false},
		{"host-custom-port", "web01.example.com:2222", "web01.example.com", "2222", false},
		{"bare-host", "web01.example.com", "web01.example.com", "22", false},
		{"bare-ipv4", "10.0.0.1", "10.0.0.1", "22", false},
		{"ipv6-bracketed-port", "[2001:db8::1]:2222", "2001:db8::1", "2222", false},
		{"ipv6-bracketed-no-port", "[2001:db8::1]", "2001:db8::1", "22", false},
		{"ipv6-bare", "2001:db8::1", "2001:db8::1", "22", false},
		{"empty-port", "web01:", "web01", "22", false},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			host, port, err := splitHostPortDefault(tc.addr)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("splitHostPortDefault(%q): expected error", tc.addr)
				}
				return
			}
			if err != nil {
				t.Fatalf("splitHostPortDefault(%q): %v", tc.addr, err)
			}
			if host != tc.wantHost || port != tc.wantPort {
				t.Errorf("splitHostPortDefault(%q) = (%q, %q), want (%q, %q)",
					tc.addr, host, port, tc.wantHost, tc.wantPort)
			}
		})
	}
}

// ── mergeUnsetHostFields tests ────────────────────────────────────────────────

// existingHostFixture returns a fully populated host entry, as stored in
// signer.json before a --force update.
func existingHostFixture() hostEntry {
	return hostEntry{
		Addr:             "10.0.0.1:22",
		User:             "ubuntu",
		HostKey:          "ssh-ed25519 OLD",
		Jump:             "bastion01",
		Principal:        "host:custom",
		SourceAddress:    "10.0.0.0/24",
		MaxTTLSeconds:    300,
		AllowAsBastion:   true,
		AllowedCallers:   []string{"broker-prod"},
		AllowSudo:        true,
		AllowedSudoUsers: []string{"root", "deploy"},
		AllowPTY:         true,
		Groups:           []string{"prod"},
	}
}

// TestMergeUnsetHostFieldsPreservaCampos is a regression test: a --force
// update must start from the existing entry and override only the fields
// whose flags were explicitly set.
func TestMergeUnsetHostFieldsPreservaCampos(t *testing.T) {
	t.Parallel()
	existing := existingHostFixture()

	// Simulate: host add --name web01 --addr ... --user ... --host-key NEW
	// --ttl 600 --force  (only addr/user/host-key/ttl explicitly set).
	hp := hostEntry{
		Addr:          "10.0.0.2:22",
		User:          "admin",
		HostKey:       "ssh-ed25519 NEW",
		Principal:     "host:web01", // default computed from --name
		MaxTTLSeconds: 600,
	}
	set := map[string]bool{"name": true, "addr": true, "user": true, "host-key": true, "ttl": true, "force": true}
	mergeUnsetHostFields(&hp, existing, set)

	// Explicitly set flags must win.
	if hp.Addr != "10.0.0.2:22" || hp.User != "admin" || hp.HostKey != "ssh-ed25519 NEW" || hp.MaxTTLSeconds != 600 {
		t.Errorf("explicitly set fields must override: %+v", hp)
	}
	// Every unset field must be preserved from the existing entry.
	if hp.Principal != "host:custom" {
		t.Errorf("Principal = %q, want host:custom (preserved)", hp.Principal)
	}
	if hp.Jump != "bastion01" || hp.SourceAddress != "10.0.0.0/24" {
		t.Errorf("Jump/SourceAddress not preserved: %+v", hp)
	}
	if !hp.AllowAsBastion || !hp.AllowSudo || !hp.AllowPTY {
		t.Errorf("bool fields not preserved: %+v", hp)
	}
	if len(hp.AllowedSudoUsers) != 2 || len(hp.Groups) != 1 || len(hp.AllowedCallers) != 1 {
		t.Errorf("list fields not preserved: %+v", hp)
	}
}

// TestHostAddForcePreservesUnmodeledFields is the #438 regression guard: a
// --force update must keep every host key broker-ctl has no flag for
// (sealed_exec, or a key added after this binary was built) instead of
// silently dropping it by rewriting the entry from the typed hostEntry. It
// runs the real cmdHostAdd against a temp config, so it is not parallel
// (configPath is package state).
func TestHostAddForcePreservesUnmodeledFields(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "signer.json")
	initial := `{
  "ca_key": "/etc/ca.key",
  "hosts": {
    "web01": {
      "addr": "10.0.0.1:22",
      "user": "deploy",
      "host_key": "ssh-ed25519 AAAA",
      "principal": "host:web01",
      "max_ttl_seconds": 120,
      "allow_sudo": true,
      "groups": ["old"],
      "sealed_exec": true,
      "future_unknown_key": {"nested": [1, 2]},
      "command_policy": {"mode": "allowlist", "allow": ["^uptime$"]}
    }
  }
}`
	if err := os.WriteFile(cfgPath, []byte(initial), 0o640); err != nil {
		t.Fatal(err)
	}
	prev := configPath
	configPath = cfgPath
	t.Cleanup(func() { configPath = prev })

	cmdHostAdd([]string{"--name", "web01", "--addr", "10.0.0.1:22", "--user", "deploy",
		"--host-key", "ssh-ed25519 AAAA", "--groups", "web,new", "--force"})

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Hosts map[string]map[string]json.RawMessage `json:"hosts"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("rewritten config is not valid JSON: %v\n%s", err, data)
	}
	h := cfg.Hosts["web01"]
	if h == nil {
		t.Fatalf("web01 missing after --force:\n%s", data)
	}
	if got := string(h["sealed_exec"]); got != "true" {
		t.Errorf("sealed_exec = %q, want true (unmodeled key dropped by --force)", got)
	}
	var unknown struct {
		Nested []int `json:"nested"`
	}
	if err := json.Unmarshal(h["future_unknown_key"], &unknown); err != nil || len(unknown.Nested) != 2 {
		t.Errorf("future_unknown_key = %s, want preserved (err=%v)", h["future_unknown_key"], err)
	}
	var groups []string
	if err := json.Unmarshal(h["groups"], &groups); err != nil || len(groups) != 2 || groups[0] != "web" || groups[1] != "new" {
		t.Errorf("groups = %s, want [web new] (explicit flag must win)", h["groups"])
	}
	// Unset modeled flags keep their field-granular merge semantics.
	if got := string(h["allow_sudo"]); got != "true" {
		t.Errorf("allow_sudo = %q, want true (unset flag preserved)", got)
	}
	if got := commandPolicyLabel(h["command_policy"]); got != "allowlist(1)" {
		t.Errorf("command_policy label = %q, want allowlist(1)", got)
	}
	if got := string(h["max_ttl_seconds"]); got != "120" {
		t.Errorf("max_ttl_seconds = %q, want 120 (unset flag preserved)", got)
	}
}

// TestHostEntryDeltaClearsModeledKeys verifies the delta's other half: a
// modeled key that hp omits (a bool flag explicitly cleared, a list flag set to
// "") is removed from the raw entry rather than kept from the existing one,
// unchanged modeled keys are not rewritten, and unmodeled keys are never part
// of the delta.
func TestHostEntryDeltaClearsModeledKeys(t *testing.T) {
	t.Parallel()
	existing := json.RawMessage(`{"addr":"a:22","user":"u","host_key":"k","principal":"p","allow_sudo":true,"groups":["g"],"sealed_exec":true}`)
	hp := hostEntry{Addr: "a:22", User: "u", HostKey: "k2", Principal: "p"} // sudo/groups cleared, host_key changed
	set, remove, err := hostEntryDelta(existing, hp)
	if err != nil {
		t.Fatal(err)
	}
	if len(remove) != 2 || remove[0] != "allow_sudo" || remove[1] != "groups" {
		t.Errorf("remove = %v, want [allow_sudo groups]", remove)
	}
	if len(set) != 1 || string(set["host_key"]) != `"k2"` {
		t.Errorf("set = %v, want only host_key (unchanged keys are not rewritten)", set)
	}
	if _, ok := set["sealed_exec"]; ok {
		t.Error("sealed_exec is not modeled and must never be in the delta")
	}
	set2, remove2, err := hostEntryDelta(json.RawMessage("null"), hp)
	if err != nil || len(remove2) != 0 || len(set2) != 4 || string(set2["addr"]) != `"a:22"` {
		t.Errorf("null existing: set=%v remove=%v err=%v", set2, remove2, err)
	}
}

// TestHostAddForcePreservesCommentsAndOrder is the #561 guard: a --force
// update is written per key, so a // comment inside the updated entry and its
// key order survive, and the untouched one-line sibling entry stays
// byte-for-byte (no document-wide reformat). Not parallel (configPath).
func TestHostAddForcePreservesCommentsAndOrder(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "signer.json")
	initial := `{
  "hosts": {
    "web01": {
      "user": "deploy",
      "addr": "10.0.0.1:22", // the addr
      "host_key": "ssh-ed25519 AAAA",
      // sealed on purpose
      "sealed_exec": true,
      "groups": ["old"],
      "command_policy": {
        "mode": "allowlist", // keep the mode
        "allow": ["^uptime$"]
      }
    },
    "db01": {"addr": "10.0.0.2:22", "user": "pg", "host_key": "ssh-ed25519 BBBB", "principal": "host:db01"}
  }
}`
	if err := os.WriteFile(cfgPath, []byte(initial), 0o640); err != nil {
		t.Fatal(err)
	}
	prev := configPath
	configPath = cfgPath
	t.Cleanup(func() { configPath = prev })

	cmdHostAdd([]string{"--name", "web01", "--addr", "10.0.0.9:22", "--user", "deploy",
		"--host-key", "ssh-ed25519 AAAA", "--groups", "web,new", "--force"})

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	for _, want := range []string{"// the addr", "// sealed on purpose", "// keep the mode"} {
		if !strings.Contains(s, want) {
			t.Errorf("comment %q inside the updated entry must survive --force:\n%s", want, s)
		}
	}
	if !strings.Contains(s, `    "db01": {"addr": "10.0.0.2:22", "user": "pg", "host_key": "ssh-ed25519 BBBB", "principal": "host:db01"}`+"\n") {
		t.Errorf("the untouched db01 line must stay byte-for-byte:\n%s", s)
	}
	if strings.Contains(s, "\t") {
		t.Errorf("the file must keep its own indentation (no tabs):\n%s", s)
	}
	// Key order: user before addr before host_key, as authored (a re-marshal
	// would sort them).
	if iu, ia, ik := strings.Index(s, `"user"`), strings.Index(s, `"addr"`), strings.Index(s, `"host_key"`); !(iu < ia && ia < ik) {
		t.Errorf("key order of web01 must be preserved (user, addr, host_key):\n%s", s)
	}
	if !strings.Contains(s, `"addr": "10.0.0.9:22", // the addr`) {
		t.Errorf("addr must be replaced in place, keeping its trailing comment:\n%s", s)
	}
	if !strings.Contains(s, `"groups": ["web", "new"]`) {
		t.Errorf("groups must carry the new value:\n%s", s)
	}
	var cfg struct {
		Hosts map[string]hostEntry `json:"hosts"`
	}
	if err := confcheck.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("rewritten config must load: %v", err)
	}
	if h := cfg.Hosts["web01"]; h.Addr != "10.0.0.9:22" || len(h.Groups) != 2 || h.HostKey != "ssh-ed25519 AAAA" {
		t.Errorf("web01 = %+v", h)
	}
}

// testHostKey returns a deterministic ed25519 host key as an authorized_keys
// line (no trailing newline) and its SHA256 fingerprint.
func testHostKey(t *testing.T, seed byte) (line, fp string) {
	t.Helper()
	pub := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize)).Public()
	pk, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk))), ssh.FingerprintSHA256(pk)
}

// captureStderr runs fn with os.Stderr redirected and returns what it wrote.
// Not parallel-safe (os.Stderr is process state).
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	prev := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = prev }()
	done := make(chan string)
	go func() {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r)
		done <- buf.String()
	}()
	fn()
	_ = w.Close()
	return <-done
}

// writeHostConfig writes a one-host signer.json pinned to hostKey and points
// configPath at it for the test.
func writeHostConfig(t *testing.T, hostKey string) string {
	t.Helper()
	cfgPath := filepath.Join(t.TempDir(), "signer.json")
	initial := `{
  "hosts": {
    "web01": {"addr": "10.0.0.1:22", "user": "deploy", "host_key": ` + strconv.Quote(hostKey) + `, "principal": "host:web01", "groups": ["old"]}
  }
}`
	if err := os.WriteFile(cfgPath, []byte(initial), 0o640); err != nil {
		t.Fatal(err)
	}
	prev := configPath
	configPath = cfgPath
	t.Cleanup(func() { configPath = prev })
	return cfgPath
}

// readHost reloads cfgPath with the strict decoder and returns web01.
func readHost(t *testing.T, cfgPath string) hostEntry {
	t.Helper()
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Hosts map[string]hostEntry `json:"hosts"`
	}
	if err := confcheck.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("rewritten config must load: %v\n%s", err, data)
	}
	return cfg.Hosts["web01"]
}

// TestHostAddForcePreservesHostKeyWithoutKeyFlags is the #638 guard: a --force
// update that passes neither --host-key nor --scan (an explicit --scan=false
// included) keeps the pinned host_key instead of re-pinning it, while the
// fields it did pass are updated. Not parallel (configPath).
func TestHostAddForcePreservesHostKeyWithoutKeyFlags(t *testing.T) {
	oldKey, _ := testHostKey(t, 1)
	for _, extra := range [][]string{nil, {"--scan=false"}} {
		cfgPath := writeHostConfig(t, oldKey)
		args := append([]string{"--name", "web01", "--addr", "10.0.0.1:22", "--user", "deploy",
			"--groups", "web,db", "--force"}, extra...)
		stderr := captureStderr(t, func() { cmdHostAdd(args) })
		h := readHost(t, cfgPath)
		if h.HostKey != oldKey {
			t.Errorf("%v: host_key = %q, want the existing pin %q", extra, h.HostKey, oldKey)
		}
		if len(h.Groups) != 2 || h.Groups[0] != "web" || h.Groups[1] != "db" {
			t.Errorf("%v: groups = %v, want [web db]", extra, h.Groups)
		}
		if strings.Contains(stderr, "CHANGED") {
			t.Errorf("%v: no key supplied, so no CHANGED warning: %q", extra, stderr)
		}
	}
}

// TestHostAddForceWarnsOnChangedHostKey is the other #638 half: a --force
// update that supplies a key differing from the pin prints a CHANGED warning
// with both fingerprints to stderr (and still writes the new key: operators do
// rotate keys), while re-supplying the same key prints nothing. Not parallel
// (configPath, os.Stderr).
func TestHostAddForceWarnsOnChangedHostKey(t *testing.T) {
	oldKey, oldFP := testHostKey(t, 1)
	newKey, newFP := testHostKey(t, 2)

	cfgPath := writeHostConfig(t, oldKey)
	stderr := captureStderr(t, func() {
		cmdHostAdd([]string{"--name", "web01", "--addr", "10.0.0.1:22", "--user", "deploy",
			"--host-key", newKey, "--groups", "web", "--force"})
	})
	if !strings.Contains(stderr, `warning: host key for "web01" CHANGED (was `+oldFP+`, now `+newFP+`)`) {
		t.Errorf("differing key: stderr = %q, want a CHANGED warning with both fingerprints", stderr)
	}
	if strings.Contains(stderr, "ssh-keyscan") {
		t.Errorf("--host-key is not a scan; the keyscan note must not appear: %q", stderr)
	}
	if h := readHost(t, cfgPath); h.HostKey != newKey {
		t.Errorf("host_key = %q, want the supplied key %q (the warning does not block)", h.HostKey, newKey)
	}

	cfgPath = writeHostConfig(t, oldKey)
	stderr = captureStderr(t, func() {
		cmdHostAdd([]string{"--name", "web01", "--addr", "10.0.0.1:22", "--user", "deploy",
			"--host-key", oldKey + " root@web01", "--groups", "web", "--force"})
	})
	if strings.Contains(stderr, "CHANGED") {
		t.Errorf("same key (comment aside): no warning expected, got %q", stderr)
	}
	if h := readHost(t, cfgPath); len(h.Groups) != 1 || h.Groups[0] != "web" {
		t.Errorf("groups = %v, want [web]", h.Groups)
	}
}

// TestWarnHostKeyChangedScanNote checks the ssh-keyscan note on a scanned key
// and the raw-prefix fallback for a key that does not parse.
func TestWarnHostKeyChangedScanNote(t *testing.T) {
	t.Parallel()
	newKey, newFP := testHostKey(t, 3)
	var buf bytes.Buffer
	warnHostKeyChanged(&buf, "web01", "ssh-ed25519 AAAAOLD", newKey, true)
	got := buf.String()
	for _, want := range []string{`CHANGED (was "ssh-ed25519 AAAAOLD", now ` + newFP + `)`, "fetched unauthenticated with ssh-keyscan; verify out of band"} {
		if !strings.Contains(got, want) {
			t.Errorf("warning = %q, want it to contain %q", got, want)
		}
	}
}

// TestCallersAddForcePreservesComments is the callers half of #561: a --force
// group change writes only /callers/<cn>/allowed_groups, so the comment and
// the other keys inside the entry survive in place.
func TestCallersAddForcePreservesComments(t *testing.T) {
	t.Parallel()
	cfgPath := filepath.Join(t.TempDir(), "signer.json")
	initial := `{
  "callers": {
    "broker-prod": {
      // OIDC re-validation is mandatory for this CN
      "require_verified_end_user": true,
      "allowed_groups": ["prod"], // groups
      "self_approve": false
    }
  }
}`
	if err := os.WriteFile(cfgPath, []byte(initial), 0o640); err != nil {
		t.Fatal(err)
	}
	action, err := callersAdd(cfgPath, "broker-prod", []string{"prod", "staging"}, true)
	if err != nil || action != "updated" {
		t.Fatalf("callersAdd: action=%q err=%v", action, err)
	}
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if !strings.Contains(s, "// OIDC re-validation is mandatory for this CN") || !strings.Contains(s, `"allowed_groups": ["prod", "staging"], // groups`) {
		t.Errorf("comments inside the entry must survive and allowed_groups must be replaced in place:\n%s", s)
	}
	if ir, ia, isa := strings.Index(s, `"require_verified_end_user"`), strings.Index(s, `"allowed_groups"`), strings.Index(s, `"self_approve"`); !(ir < ia && ia < isa) {
		t.Errorf("key order must be preserved:\n%s", s)
	}
	var cfg struct {
		Callers map[string]callerEntry `json:"callers"`
	}
	if err := confcheck.Strict(data, &cfg); err != nil {
		t.Fatalf("rewritten config must load: %v", err)
	}
	if c := cfg.Callers["broker-prod"]; !c.RequireVerifiedEndUser || len(c.AllowedGroups) != 2 {
		t.Errorf("broker-prod = %+v", c)
	}
}

// TestMergeUnsetHostFieldsVacioExplicitoSobrescribe verifies that a flag
// explicitly set to empty (e.g. --groups "") clears the field: flag.Visit
// fires for it, so it must not be merged from the existing entry.
func TestMergeUnsetHostFieldsVacioExplicitoSobrescribe(t *testing.T) {
	t.Parallel()
	existing := existingHostFixture()

	// Simulate: --groups "" --jump "" --sudo=false explicitly set.
	hp := hostEntry{
		Addr:    "10.0.0.1:22",
		User:    "ubuntu",
		HostKey: "ssh-ed25519 OLD",
	}
	set := map[string]bool{
		"name": true, "addr": true, "user": true, "host-key": true,
		"groups": true, "jump": true, "sudo": true,
	}
	mergeUnsetHostFields(&hp, existing, set)

	if hp.Groups != nil {
		t.Errorf("Groups = %v, want nil (explicit empty must clear)", hp.Groups)
	}
	if hp.Jump != "" {
		t.Errorf("Jump = %q, want empty (explicit empty must clear)", hp.Jump)
	}
	if hp.AllowSudo {
		t.Error("AllowSudo must be false (--sudo=false explicitly set)")
	}
	// Untouched fields still preserved.
	if hp.Principal != "host:custom" || hp.MaxTTLSeconds != 300 || !hp.AllowPTY {
		t.Errorf("unset fields must be preserved: %+v", hp)
	}
}

func TestCommandLooksLikeSigner(t *testing.T) {
	cases := []struct {
		cmdline string
		want    bool
	}{
		{"/Users/x/bin/signer -config signer.json", true},
		{"signer", true},
		{"/usr/bin/SIGNER", true}, // case-insensitive
		{"/usr/bin/cosigner -config signer.json", false},
		{"/opt/not-signer --reload", false},
		{"designer", false},
		{"/usr/bin/sshd", false},
		{"/bin/zsh", false},
		{"", false},
	}
	for _, c := range cases {
		if got := commandLooksLikeSigner(c.cmdline); got != c.want {
			t.Errorf("commandLooksLikeSigner(%q) = %v, want %v", c.cmdline, got, c.want)
		}
	}
}

// TestParseGlobalFlags verifies the global --config option is parsed before the
// subcommand and that subcommand flags (after the subcommand) are left untouched
// for the subcommand's own FlagSet — the contract that lets `--config` move to a
// single, leading position consistent with the other binaries.
func TestParseGlobalFlags(t *testing.T) {
	cases := []struct {
		name        string
		args        []string
		wantCfg     string
		wantRest    []string
		wantVersion bool
		wantVerbose bool
	}{
		{"default config", []string{"host", "list"}, "./signer.json", []string{"host", "list"}, false, false},
		{"global config before subcommand", []string{"--config", "s.json", "host", "list"}, "s.json", []string{"host", "list"}, false, false},
		{"equals form", []string{"--config=s.json", "host", "add"}, "s.json", []string{"host", "add"}, false, false},
		{"single dash form", []string{"-config", "s.json", "reload"}, "s.json", []string{"reload"}, false, false},
		{"subcommand flags pass through untouched", []string{"--config", "s.json", "audit", "show", "--log", "a.log", "--json"}, "s.json", []string{"audit", "show", "--log", "a.log", "--json"}, false, false},
		{"version flag", []string{"--version"}, "./signer.json", []string{}, true, false},
		{"version verbose", []string{"--version", "--verbose"}, "./signer.json", []string{}, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, rest, showVersion, verbose, err := parseGlobalFlags(tc.args)
			if err != nil {
				t.Fatalf("parseGlobalFlags(%v) error: %v", tc.args, err)
			}
			if cfg != tc.wantCfg {
				t.Errorf("cfg = %q, want %q", cfg, tc.wantCfg)
			}
			if strings.Join(rest, " ") != strings.Join(tc.wantRest, " ") {
				t.Errorf("rest = %v, want %v", rest, tc.wantRest)
			}
			if showVersion != tc.wantVersion {
				t.Errorf("showVersion = %v, want %v", showVersion, tc.wantVersion)
			}
			if verbose != tc.wantVerbose {
				t.Errorf("verbose = %v, want %v", verbose, tc.wantVerbose)
			}
		})
	}
}

// TestParseGlobalFlagsRejectsConfigAfterSubcommand documents the breaking change:
// a per-subcommand --config no longer exists, so `host list --config x` leaves
// the flag in rest for the subcommand FlagSet, which rejects it. parseGlobalFlags
// stops at "host" and never consumes the trailing --config.
func TestParseGlobalFlagsRejectsConfigAfterSubcommand(t *testing.T) {
	cfg, rest, _, _, err := parseGlobalFlags([]string{"host", "list", "--config", "s.json"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg != "./signer.json" {
		t.Errorf("cfg = %q, want the default (trailing --config must NOT be consumed globally)", cfg)
	}
	want := "host list --config s.json"
	if strings.Join(rest, " ") != want {
		t.Errorf("rest = %v, want %q passed through to the subcommand", rest, want)
	}
}

// TestParseGlobalFlagsUnknownFlag verifies an unknown leading flag is an error
// (main turns it into usage + non-zero exit).
func TestParseGlobalFlagsUnknownFlag(t *testing.T) {
	if _, _, _, _, err := parseGlobalFlags([]string{"--nope", "host", "list"}); err == nil {
		t.Fatal("expected an error for an unknown global flag")
	}
}

// TestPatchConfigEntryPreservesComments is the #183 round-trip for broker-ctl's
// raw config edits: a signer.json carrying // comments has a host added (then the
// original removed), and the operator's comments survive on disk alongside the
// change — the whole-map re-marshal used to flatten them.
func TestPatchConfigEntryPreservesComments(t *testing.T) {
	t.Parallel()
	cfgPath := filepath.Join(t.TempDir(), "signer.json")
	jsonc := `{
  // operator note: managed hosts
  "ca_key": "/etc/ca.key",
  "hosts": {
    "web01": { "addr": "10.0.0.1:22", "user": "ubuntu" } // pinned
  }
}`
	if err := os.WriteFile(cfgPath, []byte(jsonc), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := patchConfigEntry(cfgPath, "hosts", "db01", hostEntry{Addr: "10.0.0.2:22", User: "postgres"}, false); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(cfgPath)
	if s := string(b); !strings.Contains(s, "// operator note: managed hosts") || !strings.Contains(s, "// pinned") {
		t.Errorf("operator // comments must survive a host add:\n%s", s)
	}
	raw, err := loadRaw(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	hosts, err := extractHosts(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := hosts["db01"]; !ok || len(hosts) != 2 {
		t.Errorf("the added host must be present alongside the existing one: %v", hosts)
	}

	// Removing the original host also preserves the top-level comment.
	if err := patchConfigEntry(cfgPath, "hosts", "web01", nil, true); err != nil {
		t.Fatal(err)
	}
	b2, _ := os.ReadFile(cfgPath)
	if !strings.Contains(string(b2), "// operator note: managed hosts") {
		t.Errorf("the top-level comment must survive a host removal:\n%s", b2)
	}
}
