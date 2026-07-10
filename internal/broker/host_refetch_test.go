package broker

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// TestRefreshHostsForNewConnectionCoalesces pins #208: a burst of one-shot
// connections must not each pay a /v1/hosts round-trip on top of /v1/sign. The
// per-connection refetch is coalesced within hostRefreshCoalesce, so under
// sustained load Execute issues a single signer round-trip in the common case.
func TestRefreshHostsForNewConnectionCoalesces(t *testing.T) {
	var calls int32
	e := &Engine{fetcher: countingFetcher{n: &calls}}
	ctx := context.Background()

	// Cold cache (lastHostRefresh zero) → one refetch.
	if err := e.refreshHostsForNewConnection(ctx); err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	// Again within the coalesce window → reuse the cached view, no second fetch.
	if err := e.refreshHostsForNewConnection(ctx); err != nil {
		t.Fatalf("second refresh: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("within the coalesce window a new connection must reuse the cached host view: FetchHosts called %d times, want 1", got)
	}

	// Age the cache past the window → the next new connection refetches.
	e.mu.Lock()
	e.lastHostRefresh = time.Now().Add(-2 * hostRefreshCoalesce)
	e.mu.Unlock()
	if err := e.refreshHostsForNewConnection(ctx); err != nil {
		t.Fatalf("post-expiry refresh: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("after the coalesce window a new connection must refetch: FetchHosts called %d times, want 2", got)
	}

	// Local mode (no fetcher) never refetches.
	local := &Engine{}
	if err := local.refreshHostsForNewConnection(ctx); err != nil {
		t.Fatalf("local mode refresh: %v", err)
	}
}
