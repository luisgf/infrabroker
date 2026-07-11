package monitor

import (
	"strings"
	"sync"
	"testing"
)

// TestVecConcurrentLockFreeAndExposition pins #215: labelled counter increments
// are lock-free and correct under concurrency (the sync.Map hot path), With
// returns a stable shared *Counter per label, and the text exposition still
// renders the family after the map→sync.Map switch. Run under `go test -race`.
func TestVecConcurrentLockFreeAndExposition(t *testing.T) {
	v := GetCounterVec("test_vec_polish_total", "polish help", "outcome")

	const goroutines, incs = 16, 500
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < incs; i++ {
				v.With("hot").Inc()
			}
		}()
	}
	wg.Wait()

	if got := v.With("hot").Value(); got != int64(goroutines*incs) {
		t.Errorf("With(hot) = %d, want %d", got, goroutines*incs)
	}
	// A label must resolve to one shared counter, not a fresh one per call.
	if v.With("hot") != v.With("hot") {
		t.Error("With must return a stable shared *Counter for a label")
	}

	var b strings.Builder
	writeMetrics(&b)
	if out := b.String(); !strings.Contains(out, `test_vec_polish_total{outcome="hot"}`) {
		t.Errorf("exposition missing the vec family after the sync.Map switch:\n%s", out)
	}
}
