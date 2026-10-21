package ssh

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luisgf/infrabroker/internal/recording"
)

// cappedRecorder opens a Recorder that has already reached its size cap, or
// (allowEvents > 0) one that accepts exactly one more event before the cap.
func cappedRecorder(t *testing.T, allowEvents int) *recording.Recorder {
	t.Helper()
	path := filepath.Join(t.TempDir(), "s.cast")
	r, err := recording.Open(path, recording.Meta{SessionID: "s"})
	if err != nil {
		t.Fatalf("recording.Open: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	if allowEvents == 0 {
		r.SetMaxBytes(1) // the header alone already exceeds it
		return r
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// written == header size now: the next event is accepted (written < cap)
	// and pushes written past the cap, so the one after it is capped.
	r.SetMaxBytes(fi.Size() + 1)
	return r
}

// TestShellSessionExecStrictRecordingCapped pins #646: the recorder's size cap
// (ErrRecordingCapped) is a recording failure in strict mode, on the stdin,
// stdout and stderr paths alike, so the session stops instead of continuing
// unrecorded. Non-strict sessions keep ignoring recorder errors.
func TestShellSessionExecStrictRecordingCapped(t *testing.T) {
	t.Parallel()

	feed := func(sh *ShellSession, stderr bool) {
		go func() {
			select {
			case sh.lines <- lineRes{text: "out\n"}:
			case <-sh.done:
				return
			}
			if stderr {
				if _, err := sh.stderr.Write([]byte("permission denied\n")); err != nil {
					return
				}
			}
			select {
			case sh.lines <- lineRes{text: sh.marker + ":1\n"}:
			case <-sh.done:
			}
		}()
	}
	newSession := func(t *testing.T) *ShellSession {
		sh := testShellSession()
		sh.stderr = &syncBuf{}
		t.Cleanup(func() { close(sh.done) })
		return sh
	}
	wantStrictCapped := func(t *testing.T, sh *ShellSession, res *Result, err error) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), "session recording failed (strict mode)") {
			t.Fatalf("Exec = (%+v, %v), want the strict-mode recording error", res, err)
		}
		if !errors.Is(err, recording.ErrRecordingCapped) {
			t.Errorf("error %v must wrap recording.ErrRecordingCapped", err)
		}
		if !sh.broken {
			t.Error("the session must be marked broken once strict recording hit the cap")
		}
		if !channelClosed(sh) {
			t.Error("strict recording failure must close the SSH channel so the in-flight command aborts on the host (#755)")
		}
		if _, err := sh.Exec(context.Background(), "id", time.Second); err == nil {
			t.Error("a broken session must reject further commands")
		}
	}

	t.Run("strict_stdin_capped", func(t *testing.T) {
		t.Parallel()
		sh := newSession(t)
		sh.recorder = cappedRecorder(t, 0)
		sh.recordStrict = true
		res, err := sh.Exec(context.Background(), "id", time.Second)
		wantStrictCapped(t, sh, res, err)
	})
	t.Run("strict_stdout_capped", func(t *testing.T) {
		t.Parallel()
		sh := newSession(t)
		sh.recorder = cappedRecorder(t, 1) // the input event fits, the output one is capped
		sh.recordStrict = true
		feed(sh, false)
		res, err := sh.Exec(context.Background(), "id", time.Second)
		wantStrictCapped(t, sh, res, err)
	})
	t.Run("strict_stderr_capped", func(t *testing.T) {
		t.Parallel()
		sh := newSession(t)
		sh.stderr.setRecorder(cappedRecorder(t, 0), true)
		sh.recordStrict = true
		feed(sh, true)
		res, err := sh.Exec(context.Background(), "cat /etc/shadow", time.Second)
		wantStrictCapped(t, sh, res, err)
	})
	t.Run("non_strict_unaffected", func(t *testing.T) {
		t.Parallel()
		sh := newSession(t)
		sh.recorder = cappedRecorder(t, 0)
		sh.stderr.setRecorder(cappedRecorder(t, 0), false)
		sh.recordStrict = false
		feed(sh, true)
		res, err := sh.Exec(context.Background(), "cat /etc/shadow", time.Second)
		if err != nil {
			t.Fatalf("non-strict recording must ignore the size cap: %v", err)
		}
		if res.ExitCode != 1 || res.Stderr != "permission denied\n" || sh.broken {
			t.Errorf("non-strict result = %+v broken=%v, want exit 1 with stderr captured", res, sh.broken)
		}
	})
}
