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
		// PWD demands a leading component: prefixed forms are secrets, the bare
		// shell working-directory variable is not.
		{"env mysql_pwd masked", "MYSQL_PWD=hunter2 mysql -e x", "MYSQL_PWD=[REDACTED:env-assignment] mysql -e x"},
		{"env db_pwd masked", "DB_PWD=s3cr3t app", "DB_PWD=[REDACTED:env-assignment] app"},
		{"env bare pwd untouched", "PWD=/home/luis make build", "PWD=/home/luis make build"},
		{"env passwd bare still masked", "PASSWD=hunter2 cmd", "PASSWD=[REDACTED:env-assignment] cmd"},

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

		// A secret that merely STARTS with the marker prefix is author-chosen
		// text, not an earlier rule's replacement: it must still be masked (#447).
		{"marker-prefixed flag secret", "cmd --password=[REDACTED:x]hunter2", "cmd --password=[REDACTED:flag-password]"},
		{"marker-prefixed env secret", "DB_PASSWORD=[REDACTED:x]hunter2 run", "DB_PASSWORD=[REDACTED:env-assignment] run"},
		{"marker-prefixed uri secret", "curl https://user:[REDACTED:x]pw@example.com/x", "curl https://user:[REDACTED:uri-userinfo]@example.com/x"},

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

// TestQuotedSecretDoesNotCrossShellStages pins #829: a quoted-value alternative
// must not run across a shell stage separator, or a requester can open a quote
// inside another quoted word and have every following stage masked out of the
// approval card and the audit log while the signer authorizes them.
func TestQuotedSecretDoesNotCrossShellStages(t *testing.T) {
	r := mustNew(t)
	for _, in := range []string{
		`systemctl restart nginx ; echo '--token "' ; systemctl stop auditd ; iptables -F ; echo '"'`,
		`echo "--password '" | systemctl stop auditd ; echo "'"`,
		`echo 'DB_PASSWORD="' && systemctl stop auditd ; echo '"'`,
		`echo 'curl -u admin:"' ; iptables -F ; echo '"'`,
	} {
		got := r.Redact(in)
		for _, stage := range []string{"systemctl stop auditd", "iptables -F"} {
			if strings.Contains(in, stage) && !strings.Contains(got, stage) {
				t.Errorf("Redact(%q) = %q: the %q stage was masked away", in, got, stage)
			}
		}
	}
	// A quoted secret with no separator in it is still masked whole.
	for in, want := range map[string]string{
		`cmd --token 'two words' x`:       `cmd --token [REDACTED:flag-password] x`,
		`DB_PASSWORD='s3 cr3t' run`:       `DB_PASSWORD=[REDACTED:env-assignment] run`,
		`curl -u admin:"pa ss" https://x`: `curl -u admin:[REDACTED:curl-user] https://x`,
	} {
		if got := r.Redact(in); got != want {
			t.Errorf("Redact(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestSecretValueStopsAtStageSeparator pins #829 for the unquoted value and the
// quoted-prefix fallback: the secret is masked, and the stage after the
// separator stays visible.
func TestSecretValueStopsAtStageSeparator(t *testing.T) {
	r := mustNew(t)
	for _, tc := range []struct{ in, want string }{
		// Unquoted values end at a separator, as the shell word does.
		{"echo --token=x;iptables -F", "echo --token=[REDACTED:flag-password];iptables -F"},
		{"A_TOKEN=x;iptables -F", "A_TOKEN=[REDACTED:env-assignment];iptables -F"},
		{"mysql -px;iptables -F", "mysql -p[REDACTED:mysql-p-attached];iptables -F"},
		{"curl -u a:b;iptables -F", "curl -u a:[REDACTED:curl-user];iptables -F"},
		{"run --password=x|tee log", "run --password=[REDACTED:flag-password]|tee log"},
		{"DB_PASSWORD=x&& iptables -F", "DB_PASSWORD=[REDACTED:env-assignment]&& iptables -F"},
		// A quoted secret containing a separator: the prefix up to it is masked
		// (best-effort), and nothing after the separator is.
		{`mysql --password="p&ss" db`, `mysql --password=[REDACTED:flag-password]&ss" db`},
		{`DB_PASSWORD='p;ss' run`, `DB_PASSWORD=[REDACTED:env-assignment];ss' run`},
		{`curl -u admin:"p|ss" https://x`, `curl -u admin:[REDACTED:curl-user]|ss" https://x`},
		{`echo '--token "' ; systemctl stop auditd`, `echo '--token [REDACTED:flag-password]; systemctl stop auditd`},
	} {
		if got := r.Redact(tc.in); got != tc.want {
			t.Errorf("Redact(%q)\n got  %q\n want %q", tc.in, got, tc.want)
		}
	}
}

// TestPrivateKeyBlockDoesNotCrossShellStages pins #829: neither the
// end-of-text nor the END-marker alternative of private-key-block may run
// across a shell stage, while a real PEM block (headers, newlines) is masked.
func TestPrivateKeyBlockDoesNotCrossShellStages(t *testing.T) {
	r := mustNew(t)
	for _, tc := range []struct{ name, in, visible string }{
		{"no END marker", "echo -----BEGIN PRIVATE KEY----- ; systemctl stop auditd ; iptables -F", "systemctl stop auditd ; iptables -F"},
		{"END marker after a stage", "echo -----BEGIN PRIVATE KEY----- ; systemctl stop auditd ; echo -----END PRIVATE KEY-----", "systemctl stop auditd"},
		{"substitution", "echo -----BEGIN PRIVATE KEY----- $(iptables -F)", "$(iptables -F)"},
	} {
		if got := r.Redact(tc.in); !strings.Contains(got, tc.visible) || !strings.Contains(got, "[REDACTED:private-key-block]") {
			t.Errorf("%s: Redact(%q) = %q; want %q visible and the BEGIN masked", tc.name, tc.in, got, tc.visible)
		}
	}

	// A complete block followed by more output: only the block is masked.
	pem := "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\nb3BlbnNzaA==\n-----END RSA PRIVATE KEY-----"
	in := "key:\n" + pem + "\nuptime\n 10:00 up 3 days\n"
	if got, want := r.Redact(in), "key:\n[REDACTED:private-key-block]\nuptime\n 10:00 up 3 days\n"; got != want {
		t.Errorf("complete block:\n got  %q\n want %q", got, want)
	}

	// An encrypted legacy PEM, with Proc-Type / DEK-Info headers, is masked whole.
	enc := "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0123456789ABCDEF0123456789ABCDEF\n\nc2VjcmV0a2V5\n-----END RSA PRIVATE KEY-----"
	if got := r.Redact(enc + "\n$ "); got != "[REDACTED:private-key-block]\n$ " {
		t.Errorf("encrypted PEM: got %q", got)
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
