package signer

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestRemoteSignIntent429IsErrRateLimited: a 429 from the signer (or the
// control plane relaying it) maps to ErrRateLimited — not ErrSignerUnavailable,
// not a plain rejection — and carries the Retry-After header (#662).
func TestRemoteSignIntent429IsErrRateLimited(t *testing.T) {
	for _, tc := range []struct {
		name, header, want string
	}{
		{name: "with_retry_after", header: "7", want: "7"},
		{name: "without_retry_after", header: "", want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tc.header != "" {
					w.Header().Set("Retry-After", tc.header)
				}
				http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			}))
			defer srv.Close()

			_, err := NewRemote(srv.URL, nil, 5*time.Second).SignIntent(context.Background(), Intent{
				Host: "web01", Role: RoleTarget, Purpose: PurposeOneshot, Command: "uptime", DryRun: true,
			})
			if !errors.Is(err, ErrRateLimited) {
				t.Fatalf("errors.Is(err, ErrRateLimited) = false: %v", err)
			}
			if errors.Is(err, ErrSignerUnavailable) {
				t.Errorf("a 429 must not be classified as an outage: %v", err)
			}
			var rl *RateLimitedError
			if !errors.As(err, &rl) {
				t.Fatalf("err is not a *RateLimitedError: %T", err)
			}
			if rl.RetryAfter != tc.want {
				t.Errorf("RetryAfter = %q, want %q", rl.RetryAfter, tc.want)
			}
			if rl.Msg != "rate limit exceeded" {
				t.Errorf("Msg = %q, want the signer's text", rl.Msg)
			}
		})
	}
}
