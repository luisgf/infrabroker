package brokermain

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/luisgf/infrabroker/internal/broker"
	"github.com/luisgf/infrabroker/internal/signer"
)

func TestClassifyError(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantMsgHas string
	}{
		{"bad request → 400", fmt.Errorf("%w: command is required", broker.ErrBadRequest), http.StatusBadRequest, "command is required"},
		{"unknown host → 404", fmt.Errorf("%w: %q", broker.ErrUnknownHost, "web01"), http.StatusNotFound, "web01"},
		{"upstream → 502 generic", fmt.Errorf("%w: connection: boom", broker.ErrUpstream), http.StatusBadGateway, "upstream failure"},
		{"audit unavailable → 500", fmt.Errorf("%w", broker.ErrAuditUnavailable), http.StatusInternalServerError, "audit unavailable"},
		{"denial → 403 default", fmt.Errorf("caller %q not authorised", "x"), http.StatusForbidden, "not authorised"},
		{"signer rate limit → 429", fmt.Errorf("signing cert for %q: %w", "web01", &signer.RateLimitedError{RetryAfter: "7", Msg: "rate limit exceeded"}), http.StatusTooManyRequests, "rate limit exceeded"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			status, msg := classifyError(tc.err)
			if status != tc.wantStatus {
				t.Errorf("status = %d, want %d", status, tc.wantStatus)
			}
			if !strings.Contains(msg, tc.wantMsgHas) {
				t.Errorf("msg = %q, want substring %q", msg, tc.wantMsgHas)
			}
		})
	}
}

// TestClassifyErrorUpstreamHidesInternalAddr verifies that an infrastructure
// error does not leak internal addresses (from dial errors) to the client.
func TestClassifyErrorUpstreamHidesInternalAddr(t *testing.T) {
	_, msg := classifyError(fmt.Errorf("%w: connection: dial tcp 10.1.2.3:22: refused", broker.ErrUpstream))
	if strings.Contains(msg, "10.1.2.3") {
		t.Errorf("upstream message must not leak internal addresses, got %q", msg)
	}
}

// TestRetryAfterFromRateLimitedError: the handler relays the signer's
// Retry-After carried by a (wrapped) rate-limit error, and nothing otherwise
// (#662).
func TestRetryAfterFromRateLimitedError(t *testing.T) {
	wrapped := fmt.Errorf("signing cert for %q: %w", "web01", &signer.RateLimitedError{RetryAfter: "7"})
	if got := retryAfter(wrapped); got != "7" {
		t.Errorf("retryAfter(rate-limited) = %q, want \"7\"", got)
	}
	if got := retryAfter(fmt.Errorf("caller %q not authorised", "x")); got != "" {
		t.Errorf("retryAfter(denial) = %q, want \"\"", got)
	}
}
