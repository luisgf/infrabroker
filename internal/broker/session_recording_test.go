package broker

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/luisgf/infrabroker/internal/recording"
	sshrun "github.com/luisgf/infrabroker/internal/ssh"
)

// TestStartSessionRecordingStrictOpenFailure pins the strict-mode half of #206:
// when recording is a compliance control (SessionRecordingStrict), a recording
// that cannot be opened aborts the session open instead of being logged and
// tolerated.
func TestStartSessionRecordingStrictOpenFailure(t *testing.T) {
	// A recording dir whose parent does not exist makes recording.Open fail.
	badDir := filepath.Join(t.TempDir(), "missing")
	s := &liveSession{id: "s1", caller: "alice", shell: &sshrun.ShellSession{}, created: time.Now()}

	strict := &Engine{cfg: &Config{SessionRecordingDir: badDir, SessionRecordingStrict: true}}
	if err := strict.startSessionRecording(s); err == nil {
		t.Fatal("strict mode must abort the session when the recording cannot be opened")
	}
	if s.recorder != nil {
		t.Error("no recorder must be attached when a strict open fails")
	}

	// The same failure is tolerated (logged, non-fatal) when strict is off.
	lax := &Engine{cfg: &Config{SessionRecordingDir: badDir, SessionRecordingStrict: false}}
	if err := lax.startSessionRecording(s); err != nil {
		t.Fatalf("non-strict mode must tolerate an open failure: %v", err)
	}
}

// TestSessionRecorderOpenKillNoRace pins the race half of #206: the recorder is
// set BEFORE the session is published, so a concurrent kill/closeAll reading
// s.recorder in close() cannot race the assignment. Run under `go test -race`.
func TestSessionRecorderOpenKillNoRace(t *testing.T) {
	dir := t.TempDir()
	m := newSessionManager(time.Minute, time.Minute, nil)
	t.Cleanup(m.closeAll)

	var wg sync.WaitGroup
	for i := 0; i < 25; i++ {
		id := fmt.Sprintf("s%d", i)
		rec, err := recording.Open(filepath.Join(dir, id+".cast"), recording.Meta{SessionID: id})
		if err != nil {
			t.Fatalf("open recorder: %v", err)
		}
		s := &liveSession{id: id, caller: "alice", created: time.Now(), lastUsed: time.Now()}
		// Mirror OpenSession's fixed order: recorder set before publishing (add).
		s.recorder = rec
		wg.Add(2)
		go func() { defer wg.Done(); _ = m.add(s) }()
		go func() { defer wg.Done(); m.killMatching(func(ls *liveSession) bool { return ls.id == id }) }()
	}
	wg.Wait()
}
