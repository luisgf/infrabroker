package redact

import (
	"strings"
	"testing"
)

// mustNew builds a defaults-only Redactor or fails the test.
func mustNew(t *testing.T) *Redactor {
	t.Helper()
	r, err := New(nil)
	if err != nil {
		t.Fatalf("New(nil): %v", err)
	}
	if r == nil {
		t.Fatal("New(nil) returned a nil redactor with defaults enabled")
	}
	return r
}

func TestDefaultsRedact(t *testing.T) {
	r := mustNew(t)
	cases := []struct {
		name string
		in   string
		want string
	}{
		// flag-password: long-form flags keep the flag as context.
		{"flag equals", "mysql --password=hunter2 -h db", "mysql --password=[REDACTED:flag-password] -h db"},
		{"flag space", "vault login --token hunter2", "vault login --token [REDACTED:flag-password]"},
		{"flag quoted", `cmd --password="h 2" x`, `cmd --password=[REDACTED:flag-password] x`},
		{"flag apikey", "tool --api-key=abc123", "tool --api-key=[REDACTED:flag-password]"},
		{"two flags", "cmd --password=a --token=b", "cmd --password=[REDACTED:flag-password] --token=[REDACTED:flag-password]"},

		// mysql-p-attached: the gap #8 example. Scoped to the mysql family.
		{"mysql attached", "mysql -u root -phunter2 db", "mysql -u root -p[REDACTED:mysql-p-attached] db"},
		{"mysqldump attached", "mysqldump -pS3cr3t! app", "mysqldump -p[REDACTED:mysql-p-attached] app"},
		{"mysql prompt form", "mysql -p -u root db", "mysql -p -u root db"},         // -p alone prompts; nothing to mask
		{"non-mysql -p", "ssh -p 2222 host uptime", "ssh -p 2222 host uptime"},      // port, not a password
		{"scope breaks at ;", "mysql db; rm -paxos.txt", "mysql db; rm -paxos.txt"}, // -p after a separator is out of scope

		// env-assignment: keyword must be a full _-delimited component.
		{"env password", "export DB_PASSWORD=hunter2", "export DB_PASSWORD=[REDACTED:env-assignment]"},
		{"env token", "GITHUB_TOKEN=ghx123 make deploy", "GITHUB_TOKEN=[REDACTED:env-assignment] make deploy"},
		{"env quoted", `SECRET="two words" run`, `SECRET=[REDACTED:env-assignment] run`},
		{"env auth alone", "AUTH=abc cmd", "AUTH=[REDACTED:env-assignment] cmd"},
		{"env author untouched", "AUTHOR=luis git commit", "AUTHOR=luis git commit"},
		{"env xauthority untouched", "XAUTHORITY=/home/x/.Xauthority startx", "XAUTHORITY=/home/x/.Xauthority startx"},

		// uri-userinfo: only the password component is masked.
		{"uri", "curl https://user:hunter2@example.com/x", "curl https://user:[REDACTED:uri-userinfo]@example.com/x"},
		{"uri no pass", "curl https://example.com/a:b@c", "curl https://example.com/a:b@c"},

		// auth-header.
		{"auth header", "curl -H 'Authorization: Bearer abc.def-123'", "curl -H 'Authorization: Bearer [REDACTED:auth-header]'"},

		// curl-user.
		{"curl user", "curl -u admin:hunter2 https://x", "curl -u admin:[REDACTED:curl-user] https://x"},
		{"curl user no pass", "useradd -u 1000 luis", "useradd -u 1000 luis"},

		// Whole-match vendor tokens.
		{"jwt", "kubectl --token eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ.eyJzdWIiOiJ4In0abcdefgh.sig-abcdefgh123", "kubectl --token [REDACTED:flag-password]"},
		{"aws key id", "aws --profile x AKIAIOSFODNN7EXAMPLE", "aws --profile x [REDACTED:aws-key-id]"},
		{"github token", "git clone https://ghp_abcdefghijklmnopqrstuvwxyz012345@github.com/x", "git clone https://[REDACTED:github-token]@github.com/x"},

		// Neutral commands must pass through byte-identical.
		{"neutral", "systemctl restart nginx && df -h /", "systemctl restart nginx && df -h /"},
		{"neutral passwd file", "cat /etc/passwd", "cat /etc/passwd"},
		{"neutral flag path", "restic --password-file=/etc/restic.pass backup", "restic --password-file=/etc/restic.pass backup"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := r.Redact(tc.in); got != tc.want {
				t.Errorf("Redact(%q)\n got  %q\n want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestPrivateKeyBlock(t *testing.T) {
	r := mustNew(t)
	pem := "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\nmore\n-----END OPENSSH PRIVATE KEY-----"
	got := r.Redact("echo '" + pem + "' > key")
	if strings.Contains(got, "b3BlbnNzaC1rZXk") {
		t.Fatalf("key material survived: %q", got)
	}
	if !strings.Contains(got, "[REDACTED:private-key-block]") {
		t.Fatalf("marker missing: %q", got)
	}
	// A truncated block (chunk boundary) must still be masked to the end.
	got = r.Redact("-----BEGIN RSA PRIVATE KEY-----\nAAAA...")
	if strings.Contains(got, "AAAA") {
		t.Fatalf("truncated key material survived: %q", got)
	}
}

// TestNoCascade: two rules whose patterns overlap on the same input must not
// re-mask each other's marker (the rule name in the marker is forensic data).
func TestNoCascade(t *testing.T) {
	r := mustNew(t)
	got := r.Redact("run --password=hunter2")
	if got != "run --password=[REDACTED:flag-password]" {
		t.Fatalf("marker was cascaded: %q", got)
	}
	if strings.Count(got, Marker) != 1 {
		t.Fatalf("expected exactly one marker: %q", got)
	}
}

func TestOperatorPatterns(t *testing.T) {
	r, err := New(&Config{Patterns: []Pattern{{Name: "acme-id", Regex: `\bACME-[0-9]{6}\b`}}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got := r.Redact("login ACME-123456 --password=x")
	if !strings.Contains(got, "[REDACTED:acme-id]") || !strings.Contains(got, "[REDACTED:flag-password]") {
		t.Fatalf("operator pattern must compose with defaults: %q", got)
	}

	// DisableDefaults leaves only the operator's rules.
	r, err = New(&Config{DisableDefaults: true, Patterns: []Pattern{{Name: "acme-id", Regex: `\bACME-[0-9]{6}\b`}}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got = r.Redact("login ACME-123456 --password=x")
	if !strings.Contains(got, "[REDACTED:acme-id]") || strings.Contains(got, "flag-password") {
		t.Fatalf("defaults must be off: %q", got)
	}

	// DisableDefaults with no patterns = redaction disabled.
	r, err = New(&Config{DisableDefaults: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if r != nil {
		t.Fatal("empty effective rule set must return a nil redactor")
	}
}

func TestNewValidation(t *testing.T) {
	if _, err := New(&Config{Patterns: []Pattern{{Name: "bad", Regex: `(`}}}); err == nil {
		t.Fatal("invalid regex must fail New (fail-closed)")
	}
	if _, err := New(&Config{Patterns: []Pattern{{Name: "spaces not ok", Regex: `x`}}}); err == nil {
		t.Fatal("invalid rule name must fail New")
	}
}

func TestNilRedactor(t *testing.T) {
	var r *Redactor
	if got := r.Redact("mysql -phunter2"); got != "mysql -phunter2" {
		t.Fatalf("nil redactor must be a no-op, got %q", got)
	}
}

// TestDefaultsCompile guards the built-in list itself: every default must
// compile and carry a valid name (New already enforces it; this test makes a
// broken default fail loudly on its own).
func TestDefaultsCompile(t *testing.T) {
	if _, err := New(nil); err != nil {
		t.Fatalf("defaults must compile: %v", err)
	}
}
