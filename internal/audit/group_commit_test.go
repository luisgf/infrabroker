package audit

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestAppendConcurrentChainIntact pins the correctness half of #209: many
// goroutines appending at once (the group-commit path) must still produce a
// totally-ordered, unbroken, fully-durable hash chain — every entry persisted,
// contiguous seq, valid signatures. Runs under `go test -race`.
func TestAppendConcurrentChainIntact(t *testing.T) {
	t.Parallel()
	l, path := openTmp(t)

	const workers, per = 12, 40
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < per; i++ {
				if err := l.Append(Entry{Caller: "c", Host: "h:22", Command: "id", Outcome: "executed"}); err != nil {
					t.Errorf("Append: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
	l.Close()

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	total, errs := Verify(f, pub(testKey()), discardReport)
	if total != workers*per || errs != 0 {
		t.Fatalf("Verify = (%d,%d); want (%d,0) — chain broken or entries lost under concurrency", total, errs, workers*per)
	}
}

// blockingSink blocks the FIRST Sync until released, counting every Sync. It lets
// a test park one append inside its fsync (as the group-commit leader) while
// others queue behind it.
type blockingSink struct {
	inner   logFile
	calls   atomic.Int32
	entered chan struct{} // closed when the first Sync is entered
	release chan struct{} // the first Sync blocks until this is closed
}

func (s *blockingSink) Write(p []byte) (int, error) { return s.inner.Write(p) }
func (s *blockingSink) Stat() (os.FileInfo, error)  { return s.inner.Stat() }
func (s *blockingSink) Close() error                { return s.inner.Close() }
func (s *blockingSink) Sync() error {
	if s.calls.Add(1) == 1 {
		close(s.entered)
		<-s.release
	}
	return s.inner.Sync()
}

// waitWriteCount blocks until the log has committed at least n writes, i.e. all n
// appends have written their line and parked (the leader in Sync, the rest in
// cond.Wait).
func waitWriteCount(t *testing.T, l *Log, n uint64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		l.mu.Lock()
		wc := l.writeCount
		l.mu.Unlock()
		if wc >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for writeCount=%d (have %d)", n, wc)
		}
		time.Sleep(time.Millisecond)
	}
}

// TestAppendGroupCommitBatchesFsync pins the performance half of #209: N
// concurrent appends must NOT cost N fsyncs. One append is parked inside its
// fsync as the leader; the rest write and queue behind it; when the leader is
// released a single follower fsyncs all of them at once — 2 fsyncs for N appends
// (the leader, then one batched sync), not N. Before the fix each Append fsynced
// under the lock, so this would be N.
func TestAppendGroupCommitBatchesFsync(t *testing.T) {
	l, path := openTmp(t)
	sink := &blockingSink{inner: l.f, entered: make(chan struct{}), release: make(chan struct{})}
	l.f = sink

	const n = 8
	var wg sync.WaitGroup

	// The first append becomes the leader and blocks inside Sync.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := l.Append(Entry{Outcome: "a0"}); err != nil {
			t.Errorf("Append a0: %v", err)
		}
	}()
	<-sink.entered // the leader is now inside its fsync

	// The rest write and queue as followers behind the blocked leader.
	for i := 1; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := l.Append(Entry{Outcome: fmt.Sprintf("a%d", i)}); err != nil {
				t.Errorf("Append a%d: %v", i, err)
			}
		}(i)
	}
	waitWriteCount(t, l, n) // all n written and parked

	close(sink.release) // let the leader's fsync complete; one follower syncs the rest
	wg.Wait()

	if got := sink.calls.Load(); got != 2 {
		t.Fatalf("group commit: %d fsyncs for %d concurrent appends, want 2 (leader + one batched sync)", got, n)
	}

	l.Close()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	if total, errs := Verify(f, pub(testKey()), discardReport); total != n || errs != 0 {
		t.Fatalf("Verify = (%d,%d); want (%d,0)", total, errs, n)
	}
}

// TestRotationDeferredOnFsyncFailure pins the group-commit rotation barrier
// (#209): maybeRotate flushes the old file before closing it, and if that
// pre-rotation fsync fails it DEFERS rotation rather than closing an un-fsynced
// file (which would lose the pending appends on power loss). Once fsync recovers,
// rotation proceeds and the cross-segment chain stays intact.
func TestRotationDeferredOnFsyncFailure(t *testing.T) {
	l, path := openTmp(t)
	l.maxFileSize = 1 // any non-empty file makes the next append want to rotate

	if err := l.Append(Entry{Outcome: "a"}); err != nil {
		t.Fatalf("Append a: %v", err)
	}

	// Inject an fsync failure: the next append's pre-rotation fsync fails, so
	// rotation is deferred (no segment created) and the append itself errors.
	sink := &faultySink{inner: l.f, failSync: true}
	l.f = sink
	if err := l.Append(Entry{Outcome: "b"}); err == nil {
		t.Fatal("Append must fail while the fsync is failing")
	}
	if segs, _ := discoverSegments(path); len(segs) != 1 {
		t.Fatalf("rotation must be deferred on an fsync failure (no segment); segments=%v", segs)
	}

	// fsync recovers: the next append rotates cleanly and the chain across the
	// rotation boundary verifies.
	sink.failSync = false
	if err := l.Append(Entry{Outcome: "c"}); err != nil {
		t.Fatalf("post-recovery Append: %v", err)
	}
	l.Close()
	if total, errs := VerifySegments(path, pub(testKey()), discardReport); errs != 0 {
		t.Fatalf("VerifySegments = (%d,%d); chain broken across the deferred-then-performed rotation", total, errs)
	}
}

// latencySink injects a fixed per-Sync delay to model fsync latency in the
// benchmark below.
type latencySink struct {
	inner logFile
	delay time.Duration
}

func (s *latencySink) Write(p []byte) (int, error) { return s.inner.Write(p) }
func (s *latencySink) Stat() (os.FileInfo, error)  { return s.inner.Stat() }
func (s *latencySink) Close() error                { return s.inner.Close() }
func (s *latencySink) Sync() error {
	time.Sleep(s.delay)
	return s.inner.Sync()
}

// BenchmarkAppendParallelSlowFsync demonstrates the #209 acceptance: with a
// simulated per-fsync latency, concurrent audited-action throughput is no longer
// capped at 1/fsync. Group commit lets parallel appends share a single fsync, so
// throughput scales well past the ~1/delay ceiling the old per-append fsync
// imposed. Run: go test ./internal/audit/ -run x -bench AppendParallelSlowFsync
func BenchmarkAppendParallelSlowFsync(b *testing.B) {
	l, err := Open(fmt.Sprintf("%s/audit.log", b.TempDir()), testKey())
	if err != nil {
		b.Fatalf("Open: %v", err)
	}
	b.Cleanup(func() { l.Close() })
	l.f = &latencySink{inner: l.f, delay: 2 * time.Millisecond}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if err := l.Append(Entry{Outcome: "bench"}); err != nil {
				b.Fatalf("Append: %v", err)
			}
		}
	})
}
