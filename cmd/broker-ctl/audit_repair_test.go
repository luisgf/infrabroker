package main

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luisgf/infrabroker/internal/audit"
)

// TestAuditRepairEndToEnd reproduces the #101 startup brick (a torn final
// record makes audit.Open fail) and proves that `audit repair --apply`
// quarantines the corrupt bytes, restores bootability, and keeps the chain
// verifiable.
func TestAuditRepairEndToEnd(t *testing.T) {
	path, key := buildLog(t, 3)
	good, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read good log: %v", err)
	}

	// Simulate a torn write: a truncated JSON record with no closing brace and
	// no trailing newline appended after the last good record.
	torn := append(append([]byte{}, good...), []byte(`{"seq":4,"caller":"x","comm`)...)
	if err := os.WriteFile(path, torn, 0o600); err != nil {
		t.Fatalf("write torn log: %v", err)
	}

	// Repro: the signer path (audit.Open -> restoreChain) refuses to boot.
	if _, err := audit.Open(path, key); err == nil {
		t.Fatal("expected audit.Open to fail on a torn trailing record (repro #101)")
	}

	// Recover with the explicit operator command.
	cmdAuditRepair([]string{"--log", path, "--apply"})

	// The signer can boot again.
	l, err := audit.Open(path, key)
	if err != nil {
		t.Fatalf("audit.Open after repair still fails: %v", err)
	}
	l.Close()

	// The repaired file is exactly the well-formed prefix.
	repaired, _ := os.ReadFile(path)
	if !bytes.Equal(repaired, good) {
		t.Errorf("repaired file != good prefix\n got  %q\n want %q", repaired, good)
	}

	// The chain still verifies end to end (signatures included).
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open repaired log: %v", err)
	}
	defer f.Close()
	if _, errs := audit.Verify(f, key.Public().(ed25519.PublicKey), func(string, ...any) {}); errs != 0 {
		t.Errorf("repaired log fails verification: %d error(s)", errs)
	}

	// The torn bytes are preserved in a single quarantine sidecar (forensics).
	matches, _ := filepath.Glob(path + ".corrupt-*")
	if len(matches) != 1 {
		t.Fatalf("expected exactly 1 quarantine file, got %d: %v", len(matches), matches)
	}
	qb, _ := os.ReadFile(matches[0])
	if !bytes.Contains(qb, []byte(`"seq":4`)) {
		t.Errorf("quarantine file missing the torn bytes: %q", qb)
	}
}

// TestAuditRepairCleanLogIsNoop confirms repair does not touch a healthy log.
func TestAuditRepairCleanLogIsNoop(t *testing.T) {
	path, _ := buildLog(t, 2)
	before, _ := os.ReadFile(path)
	cmdAuditRepair([]string{"--log", path}) // dry-run
	cmdAuditRepair([]string{"--log", path, "--apply"})
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Error("repair modified a clean log")
	}
	if matches, _ := filepath.Glob(path + ".corrupt-*"); len(matches) != 0 {
		t.Errorf("repair quarantined bytes from a clean log: %v", matches)
	}
}

// repairHelperEnv marks the re-executed test binary as the child side of
// runRepairSubprocess; the cmdAuditRepair arguments follow "--" on its
// command line.
const repairHelperEnv = "BROKERCTL_AUDIT_REPAIR_HELPER"

// TestAuditRepairHelperProcess is not a real test: it is the child side of
// runRepairSubprocess. cmdAuditRepair reports failures through fatalf →
// os.Exit, so the refusal paths can only be observed from a separate process.
func TestAuditRepairHelperProcess(t *testing.T) {
	if os.Getenv(repairHelperEnv) != "1" {
		t.Skip("helper process for runRepairSubprocess")
	}
	args := os.Args
	for i, a := range args {
		if a == "--" {
			args = args[i+1:]
			break
		}
	}
	cmdAuditRepair(args)
	os.Exit(0)
}

// runRepairSubprocess runs cmdAuditRepair(args) in a re-executed copy of the
// test binary and returns its exit code and combined output.
func runRepairSubprocess(t *testing.T, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], append([]string{"-test.run=^TestAuditRepairHelperProcess$", "--"}, args...)...)
	cmd.Env = append(os.Environ(), repairHelperEnv+"=1")
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0, string(out)
	case errors.As(err, &ee):
		return ee.ExitCode(), string(out)
	default:
		t.Fatalf("running helper process: %v", err)
		return -1, ""
	}
}

// tornLog builds a 3-record signed log and appends tail (a non-JSON torn final
// record). It returns the log path and the well-formed prefix.
func tornLog(t *testing.T, tail string) (path string, good []byte) {
	t.Helper()
	path, _ = buildLog(t, 3)
	good, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read good log: %v", err)
	}
	if err := os.WriteFile(path, append(append([]byte{}, good...), tail...), 0o600); err != nil {
		t.Fatalf("write torn log: %v", err)
	}
	return path, good
}

// TestAuditRepairRefusesPlantedQuarantineSymlink is the #812 repro: a
// compromised service user owns the log directory, tears its own log's tail
// (the payload) and pre-plants <log>.corrupt-<timestamp> symlinks for the
// coming seconds. Root's `repair --apply` must not write through them, and
// must leave the log untouched.
func TestAuditRepairRefusesPlantedQuarantineSymlink(t *testing.T) {
	const payload = "* * * * * root /tmp/pwn\n"
	path, _ := tornLog(t, payload)
	before, _ := os.ReadFile(path)

	victim := filepath.Join(t.TempDir(), "etc-cron.d-pwn") // does not exist
	now := time.Now().UTC()
	for i := -30; i <= 30; i++ {
		name := path + ".corrupt-" + now.Add(time.Duration(i)*time.Second).Format("20060102T150405Z")
		if err := os.Symlink(victim, name); err != nil {
			t.Fatalf("plant symlink: %v", err)
		}
	}

	code, out := runRepairSubprocess(t, "--log", path, "--apply")
	if code == 0 {
		t.Errorf("repair succeeded with a planted quarantine symlink; output:\n%s", out)
	}
	if _, err := os.Lstat(victim); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("victim %s was created through the planted symlink (err=%v); output:\n%s", victim, err, out)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Errorf("log was modified although the quarantine could not be created safely\n got  %q\n want %q", after, before)
	}
}

// TestAuditRepairRefusesSymlinkedLog covers the read variant of #812: --log is
// a symlink to a file the service user cannot read. Repair must refuse rather
// than copy that file's "tail" out and truncate it.
func TestAuditRepairRefusesSymlinkedLog(t *testing.T) {
	path, _ := tornLog(t, "secret-material-not-json")
	target, _ := os.ReadFile(path)
	link := filepath.Join(t.TempDir(), "audit.log")
	if err := os.Symlink(path, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	for _, args := range [][]string{{"--log", link}, {"--log", link, "--apply"}} {
		code, out := runRepairSubprocess(t, args...)
		if code == 0 {
			t.Errorf("repair %v accepted a symlinked log; output:\n%s", args, out)
		}
		if !strings.Contains(out, "symlink") {
			t.Errorf("repair %v: refusal does not mention the symlink; output:\n%s", args, out)
		}
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(after, target) {
		t.Error("symlink target was modified")
	}
	if m, _ := filepath.Glob(link + ".corrupt-*"); len(m) != 0 {
		t.Errorf("quarantine written for a symlinked log: %v", m)
	}
}

// TestAuditRepairRefusesHardlinkedLog: a hard link aliases another file into
// the service-owned directory without tripping O_NOFOLLOW, so a log with more
// than one link is refused too.
func TestAuditRepairRefusesHardlinkedLog(t *testing.T) {
	path, _ := tornLog(t, "secret-material-not-json")
	target, _ := os.ReadFile(path)
	link := filepath.Join(filepath.Dir(path), "alias.log")
	if err := os.Link(path, link); err != nil {
		t.Skipf("hard link unsupported here: %v", err)
	}
	code, out := runRepairSubprocess(t, "--log", link, "--apply")
	if code == 0 || !strings.Contains(out, "hard link") {
		t.Errorf("repair accepted a hard-linked log (exit %d); output:\n%s", code, out)
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(after, target) {
		t.Error("hard-linked target was modified")
	}
}

// TestAuditRepairQuarantineContentAndMode pins the happy path after the #812
// hardening: the quarantine holds exactly the torn bytes with mode 0600, the
// log is truncated to the clean end, and the chain verifies.
func TestAuditRepairQuarantineContentAndMode(t *testing.T) {
	const tail = `{"seq":4,"caller":"x","comm`
	path, good := tornLog(t, tail)

	code, out := runRepairSubprocess(t, "--log", path, "--apply")
	if code != 0 {
		t.Fatalf("repair failed (exit %d):\n%s", code, out)
	}
	repaired, _ := os.ReadFile(path)
	if !bytes.Equal(repaired, good) {
		t.Errorf("log not truncated to the clean end\n got  %q\n want %q", repaired, good)
	}
	matches, _ := filepath.Glob(path + ".corrupt-*")
	if len(matches) != 1 {
		t.Fatalf("expected exactly 1 quarantine file, got %v", matches)
	}
	fi, err := os.Lstat(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
		t.Errorf("quarantine mode = %v, want regular 0600", fi.Mode())
	}
	if qb, _ := os.ReadFile(matches[0]); string(qb) != tail {
		t.Errorf("quarantine content = %q, want %q", qb, tail)
	}
	if code, out := runRepairSubprocess(t, "--log", path); code != 0 || !strings.Contains(out, "nothing to repair") {
		t.Errorf("post-repair dry-run: exit %d, output:\n%s", code, out)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, errs := audit.Verify(f, testAuditKey().Public().(ed25519.PublicKey), func(string, ...any) {}); errs != 0 {
		t.Errorf("repaired log fails verification: %d error(s)", errs)
	}
}
