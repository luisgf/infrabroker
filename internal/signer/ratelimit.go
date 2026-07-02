package signer

import (
	"sync"
	"time"
)

// maxRateLimitKeys bounds the bucket map. Keys are authenticated mTLS CNs, so
// cardinality is naturally bounded by the client certificates the operator has
// issued; the bound is a backstop against pathological CN churn, mirroring the
// control plane's max_subjects guardrail.
const maxRateLimitKeys = 4096

// rateBucket is one token bucket. Tokens refill continuously at limit/60 per
// second up to the limit (burst = one minute's budget); each allowed request
// consumes one token.
type rateBucket struct {
	tokens float64
	last   time.Time
}

// RateLimiter enforces a per-key token-bucket rate limit. The limit is passed
// on every Allow call rather than stored, so a hot-reloaded config value takes
// effect immediately without touching the limiter. The zero limit disables the
// check. Safe for concurrent use.
type RateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*rateBucket
	now     func() time.Time // test seam
}

// NewRateLimiter creates an empty limiter.
func NewRateLimiter() *RateLimiter {
	return &RateLimiter{buckets: make(map[string]*rateBucket), now: time.Now}
}

// Allow reports whether one request by key fits within perMin requests per
// minute, consuming a token when it does. perMin <= 0 disables the limit
// (always allowed).
func (l *RateLimiter) Allow(key string, perMin int) bool {
	if perMin <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= maxRateLimitKeys {
			l.prune(now)
		}
		b = &rateBucket{tokens: float64(perMin), last: now}
		l.buckets[key] = b
	}
	capacity := float64(perMin)
	b.tokens += now.Sub(b.last).Seconds() * capacity / 60
	if b.tokens > capacity {
		b.tokens = capacity
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// RetryAfter returns a conservative client hint, in whole seconds, for when
// the next token becomes available at perMin requests per minute.
func RetryAfter(perMin int) int {
	if perMin <= 0 {
		return 0
	}
	secs := 60 / perMin
	if 60%perMin != 0 {
		secs++
	}
	if secs < 1 {
		secs = 1
	}
	return secs
}

// prune drops buckets idle long enough to be full again (they carry no state a
// fresh bucket would not have). Called with l.mu held, only when the map is at
// its bound; if every entry is active the map simply stays at the bound and
// new keys are still admitted.
func (l *RateLimiter) prune(now time.Time) {
	for k, b := range l.buckets {
		if now.Sub(b.last) > time.Minute {
			delete(l.buckets, k)
		}
	}
}
