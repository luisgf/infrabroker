package signer

import (
	"fmt"
	"testing"
	"time"
)

// fakeClock returns a limiter whose clock the test controls.
func fakeClock(l *RateLimiter) *time.Time {
	now := time.Unix(1_700_000_000, 0)
	l.now = func() time.Time { return now }
	return &now
}

func TestRateLimiterDisabled(t *testing.T) {
	t.Parallel()
	l := NewRateLimiter()
	for i := 0; i < 1000; i++ {
		if !l.Allow("cn", 0) {
			t.Fatal("perMin=0 must always allow")
		}
	}
}

func TestRateLimiterBurstThenDeny(t *testing.T) {
	t.Parallel()
	l := NewRateLimiter()
	fakeClock(l)
	for i := 0; i < 5; i++ {
		if !l.Allow("cn", 5) {
			t.Fatalf("request %d within the burst must be allowed", i+1)
		}
	}
	if l.Allow("cn", 5) {
		t.Error("request beyond the burst must be denied")
	}
}

func TestRateLimiterRefill(t *testing.T) {
	t.Parallel()
	l := NewRateLimiter()
	now := fakeClock(l)
	for i := 0; i < 5; i++ {
		l.Allow("cn", 5)
	}
	if l.Allow("cn", 5) {
		t.Fatal("bucket must be empty")
	}
	*now = now.Add(12 * time.Second) // 5/min → one token per 12 s
	if !l.Allow("cn", 5) {
		t.Error("one token must have refilled after 12 s")
	}
	if l.Allow("cn", 5) {
		t.Error("only one token must have refilled")
	}
}

func TestRateLimiterRefillCapped(t *testing.T) {
	t.Parallel()
	l := NewRateLimiter()
	now := fakeClock(l)
	l.Allow("cn", 5)
	*now = now.Add(time.Hour)
	for i := 0; i < 5; i++ {
		if !l.Allow("cn", 5) {
			t.Fatalf("refill must cap at the burst, request %d denied", i+1)
		}
	}
	if l.Allow("cn", 5) {
		t.Error("refill must not exceed the one-minute budget")
	}
}

func TestRateLimiterPerKeyIsolation(t *testing.T) {
	t.Parallel()
	l := NewRateLimiter()
	fakeClock(l)
	for i := 0; i < 5; i++ {
		l.Allow("cn-a", 5)
	}
	if l.Allow("cn-a", 5) {
		t.Fatal("cn-a must be exhausted")
	}
	if !l.Allow("cn-b", 5) {
		t.Error("cn-b must have its own bucket")
	}
}

func TestRateLimiterHotReloadedLimit(t *testing.T) {
	t.Parallel()
	l := NewRateLimiter()
	fakeClock(l)
	for i := 0; i < 5; i++ {
		l.Allow("cn", 5)
	}
	if l.Allow("cn", 5) {
		t.Fatal("bucket must be exhausted at limit 5")
	}
	// A raised limit takes effect on the next call without resetting state:
	// refill happens at the new rate against the same bucket.
	if l.Allow("cn", 6) {
		t.Error("raising the limit must not mint tokens retroactively")
	}
}

func TestRateLimiterPruneBound(t *testing.T) {
	t.Parallel()
	l := NewRateLimiter()
	now := fakeClock(l)
	for i := 0; i < maxRateLimitKeys; i++ {
		l.Allow(fmt.Sprintf("cn-%d", i), 5)
	}
	if len(l.buckets) != maxRateLimitKeys {
		t.Fatalf("expected %d buckets, got %d", maxRateLimitKeys, len(l.buckets))
	}
	*now = now.Add(2 * time.Minute) // all idle → prunable
	l.Allow("cn-new", 5)
	if len(l.buckets) != 1 {
		t.Errorf("idle buckets must be pruned at the bound, got %d", len(l.buckets))
	}
}

func TestRetryAfter(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ perMin, want int }{
		{0, 0}, {5, 12}, {7, 9}, {60, 1}, {600, 1},
	} {
		if got := RetryAfter(tc.perMin); got != tc.want {
			t.Errorf("RetryAfter(%d) = %d, want %d", tc.perMin, got, tc.want)
		}
	}
}
