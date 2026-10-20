package brokermain

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
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

// TestSSHRunRejectsNULAndOversizedIdentifiers pins #648: the mTLS HTTP
// frontend applies the same input validation as the MCP frontends, so a NUL
// byte or an oversized identifier is refused with 400 before Execute (and the
// audit log) sees it, while a well-formed request still reaches the engine.
func TestSSHRunRejectsNULAndOversizedIdentifiers(t *testing.T) {
	eng, _ := testEngine(t, "https://idp.test")
	h := sshRunHandler(eng)
	post := func(body map[string]any) *httptest.ResponseRecorder {
		b, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/v1/ssh_run", bytes.NewReader(b))
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: "agent-1"}}}}
		rec := httptest.NewRecorder()
		h(rec, req)
		return rec
	}

	for _, tc := range []struct {
		name    string
		body    map[string]any
		wantMsg string
	}{
		{"NUL in command", map[string]any{"host": "web01", "command": "id\x00; rm -rf /"}, `field "command" contains null bytes`},
		{"2 KiB host", map[string]any{"host": strings.Repeat("h", 2048), "command": "id"}, `field "server" exceeds the limit of 1024 bytes`},
		{"2 KiB sudo_user", map[string]any{"host": "web01", "command": "id", "sudo": true, "sudo_user": strings.Repeat("u", 2048)}, `field "sudo_user" exceeds the limit of 1024 bytes`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := post(tc.body)
			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), tc.wantMsg) {
				t.Fatalf("status = %d body %q, want 400 with %q", rec.Code, rec.Body.String(), tc.wantMsg)
			}
		})
	}

	// A well-formed request passes validation and reaches the engine, which
	// answers for the unknown host (no SSH is attempted).
	if rec := post(map[string]any{"host": "nope", "command": "id"}); rec.Code != http.StatusNotFound {
		t.Fatalf("valid request for an unknown host: status = %d body %q, want 404 from the engine", rec.Code, rec.Body.String())
	}
}
