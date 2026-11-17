package main

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// symlinkFixture is the #813 layout: svc/real.json is a valid config (the
// service user's own file), victim is a non-JSON file the editing user must
// never overwrite, and link is a symlink to real.json.
type symlinkFixture struct {
	dir, real, victim, link string
	victimBody              string
}

func newSymlinkFixture(t *testing.T, nHosts int) symlinkFixture {
	t.Helper()
	dir := t.TempDir()
	svc := filepath.Join(dir, "svc")
	rootonly := filepath.Join(dir, "rootonly")
	for _, d := range []string{svc, rootonly} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	var hosts strings.Builder
	for i := 0; i < nHosts; i++ {
		if i > 0 {
			hosts.WriteString(",\n")
		}
		fmt.Fprintf(&hosts, `    "h%d": {"addr": "10.0.%d.%d:22", "user": "ops", "host_key": "ssh-ed25519 AAAA", "principal": "host:h%d"}`, i, i/250, i%250, i)
	}
	cfg := "/* ssh-ed25519 AAAAattacker attacker */\n{\n  \"hosts\": {\n" + hosts.String() + "\n  },\n  \"callers\": {}\n}\n"
	fx := symlinkFixture{
		dir:        dir,
		real:       filepath.Join(svc, "real.json"),
		victim:     filepath.Join(rootonly, "authorized_keys"),
		link:       filepath.Join(svc, "signer.json"),
		victimBody: "ssh-ed25519 AAAAvictim operator@host\n",
	}
	if err := os.WriteFile(fx.real, []byte(cfg), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fx.victim, []byte(fx.victimBody), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(fx.real, fx.link); err != nil {
		t.Fatal(err)
	}
	return fx
}

// repoint atomically retargets the symlink at link (new link + rename over it),
// the way an attacker owning the directory would.
func repoint(t *testing.T, link, target string) {
	t.Helper()
	tmp := link + ".flip"
	_ = os.Remove(tmp)
	if err := os.Symlink(target, tmp); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, link); err != nil {
		t.Fatal(err)
	}
}

func (fx symlinkFixture) assertVictimUntouched(t *testing.T) {
	t.Helper()
	got, err := os.ReadFile(fx.victim)
	if err != nil {
		t.Fatalf("read victim: %v", err)
	}
	if string(got) != fx.victimBody {
		t.Fatalf("victim was overwritten (%d bytes, starts %q)", len(got), firstLine(got))
	}
}

func firstLine(b []byte) string {
	s, _, _ := strings.Cut(string(b), "\n")
	return s
}

// TestEditConfigResolvedOnce is the deterministic half of #813: the --config
// path is resolved once, before the first read, and every later step uses that
// resolved path. Retargeting the original link after resolution does not move
// the write; turning the resolved path itself into a symlink makes the read
// and the write refuse instead of following it.
func TestEditConfigResolvedOnce(t *testing.T) {
	t.Parallel()
	t.Run("link retargeted after resolve", func(t *testing.T) {
		t.Parallel()
		fx := newSymlinkFixture(t, 2)
		resolved, err := resolveEditConfig(fx.link)
		if err != nil {
			t.Fatalf("resolveEditConfig: %v", err)
		}
		repoint(t, fx.link, fx.victim)
		if err := patchConfigEntry(resolved, "callers", "new", callerEntry{AllowedGroups: []string{}}, false); err != nil {
			t.Fatalf("patchConfigEntry(resolved): %v", err)
		}
		fx.assertVictimUntouched(t)
		if got, _ := os.ReadFile(fx.real); !strings.Contains(string(got), `"new"`) {
			t.Errorf("the edit must land on the file resolved up front")
		}
	})
	t.Run("resolved path swapped for a symlink", func(t *testing.T) {
		t.Parallel()
		fx := newSymlinkFixture(t, 2)
		resolved, err := resolveEditConfig(fx.link)
		if err != nil {
			t.Fatalf("resolveEditConfig: %v", err)
		}
		saved := resolved + ".saved"
		if err := os.Rename(resolved, saved); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(fx.victim, resolved); err != nil {
			t.Fatal(err)
		}
		if err := patchConfigEntry(resolved, "callers", "new", callerEntry{AllowedGroups: []string{}}, false); err == nil {
			t.Fatal("patchConfigEntry must refuse to read a resolved path that became a symlink")
		}
		if err := writeConfigAtomic(resolved, []byte(`{"b":2}`)); err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("writeConfigAtomic must refuse a symlinked final component, got %v", err)
		}
		fx.assertVictimUntouched(t)
		if fi, err := os.Lstat(resolved); err != nil || fi.Mode()&os.ModeSymlink == 0 {
			t.Errorf("the planted link must be left as it was, got %v %v", fi, err)
		}
	})
}

// TestEditConfigSymlinkRace is the #813 repro, bounded: a goroutine flips the
// config link between the real config and a victim file while edits run
// through the link. The victim must never change.
func TestEditConfigSymlinkRace(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("race loop skipped in -short mode")
	}
	fx := newSymlinkFixture(t, 1000)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		targets := []string{fx.victim, fx.real}
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			tmp := fx.link + ".flip"
			_ = os.Remove(tmp)
			if os.Symlink(targets[i%2], tmp) == nil {
				_ = os.Rename(tmp, fx.link)
			}
			time.Sleep(200 * time.Microsecond)
		}
	}()
	deadline := time.Now().Add(2 * time.Second)
	for i := 0; i < 25 && time.Now().Before(deadline); i++ {
		_, _ = callersAdd(fx.link, "new"+strconv.Itoa(i), nil, false) // errors expected: the link may name the victim
		if got, _ := os.ReadFile(fx.victim); string(got) != fx.victimBody {
			break
		}
	}
	close(stop)
	wg.Wait()
	fx.assertVictimUntouched(t)
}

// TestEditConfigThroughSelfOwnedLink keeps #750 working end to end: an
// operator's own convenience link (and a chain of them) is edited through,
// the edit lands on the target and the links survive.
func TestEditConfigThroughSelfOwnedLink(t *testing.T) {
	t.Parallel()
	fx := newSymlinkFixture(t, 1)
	outer := filepath.Join(fx.dir, "outer.json")
	if err := os.Symlink(fx.link, outer); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{fx.link, outer} {
		name := "via-" + filepath.Base(p)
		if action, err := callersAdd(p, name, nil, false); err != nil || action != "added" {
			t.Fatalf("callersAdd(%s) = %q, %v", p, action, err)
		}
		if got, _ := os.ReadFile(fx.real); !strings.Contains(string(got), name) {
			t.Errorf("edit through %s did not land on the target", p)
		}
		if fi, err := os.Lstat(p); err != nil || fi.Mode()&os.ModeSymlink == 0 {
			t.Errorf("link %s must survive the edit, got %v %v", p, fi, err)
		}
	}
	fx.assertVictimUntouched(t)
}

// TestEditConfigRefusesForeignOwnedLink: a symlinked --config whose link (any
// hop of it) is owned by another uid — root editing a link the service user
// planted in its own directory — is refused with a pointer to the real path.
// Creating a link owned by someone else needs root, so the test skips otherwise.
func TestEditConfigRefusesForeignOwnedLink(t *testing.T) {
	t.Parallel()
	if os.Geteuid() != 0 {
		t.Skip("lchown of a symlink to another uid needs euid 0")
	}
	u, err := user.Lookup("nobody")
	if err != nil {
		t.Skipf("lookup nobody: %v", err)
	}
	uid, _ := strconv.Atoi(u.Uid)
	t.Run("direct", func(t *testing.T) {
		t.Parallel()
		fx := newSymlinkFixture(t, 1)
		if err := os.Lchown(fx.link, uid, -1); err != nil {
			t.Fatal(err)
		}
		_, err := callersAdd(fx.link, "new", nil, false)
		if err == nil || !strings.Contains(err.Error(), "pass the real config path") {
			t.Fatalf("want refusal of a foreign-owned link, got %v", err)
		}
	})
	t.Run("second hop", func(t *testing.T) {
		t.Parallel()
		fx := newSymlinkFixture(t, 1)
		if err := os.Lchown(fx.link, uid, -1); err != nil {
			t.Fatal(err)
		}
		outer := filepath.Join(fx.dir, "outer.json") // root-owned link -> foreign-owned link
		if err := os.Symlink(fx.link, outer); err != nil {
			t.Fatal(err)
		}
		_, err := callersAdd(outer, "new", nil, false)
		if err == nil || !strings.Contains(err.Error(), "pass the real config path") {
			t.Fatalf("want refusal of a foreign-owned hop, got %v", err)
		}
	})
}
