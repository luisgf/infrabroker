package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestReloadHTTPSurfacesPlainTextError pins #441: the signer's handleReload
// answers a rejected reload via http.Error (text/plain, never JSON), so the
// CLI must check the status before decoding and show the raw body — decoding
// first turned "hosts: invalid regex" into "parse response: invalid character
// 'h' looking for beginning of value" and the real reason was lost.
func TestReloadHTTPSurfacesPlainTextError(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{"config error", http.StatusInternalServerError, "hosts: invalid regex"},
		{"unauthorised CN", http.StatusForbidden, "not authorised to reload"},
		{"unauthenticated", http.StatusUnauthorized, "unauthenticated"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("method %s, want POST", r.Method)
				}
				http.Error(w, tc.body, tc.status) // exactly what the signer does
			}))
			defer srv.Close()

			_, err := reloadHTTP(srv.Client(), srv.URL+"/v1/reload")
			if err == nil {
				t.Fatal("a non-200 reload must fail")
			}
			msg := err.Error()
			if !strings.Contains(msg, fmt.Sprintf("HTTP %d", tc.status)) {
				t.Errorf("error %q must carry the status", msg)
			}
			if !strings.Contains(msg, tc.body) {
				t.Errorf("error %q must surface the signer's reason %q", msg, tc.body)
			}
			if strings.Contains(msg, "parse response") || strings.Contains(msg, "invalid character") {
				t.Errorf("error %q must not be a JSON-decode failure", msg)
			}
		})
	}
}

// TestReloadVerdictVsUnavailable is the #564 guard for the HTTP-first reload:
// a 500 is the signer's own verdict on the new config ("keeping previous
// config") and must be surfaced rather than masked by a SIGHUP fallback,
// while an auth refusal, a transport failure or missing mTLS material only
// mean the HTTP path is unavailable (a confirmed local signer may still get
// SIGHUP). The SIGHUP hint must point at where a silent failure is visible.
func TestReloadVerdictVsUnavailable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		status  int
		verdict bool
	}{
		{"config error", http.StatusInternalServerError, true},
		{"unauthorised CN", http.StatusForbidden, false},
		{"unauthenticated", http.StatusUnauthorized, false},
	}
	for _, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "reason", tc.status)
		}))
		_, err := reloadHTTP(srv.Client(), srv.URL+"/v1/reload")
		srv.Close()
		if err == nil {
			t.Fatalf("%s: a non-200 reload must fail", tc.name)
		}
		if got := isReloadVerdict(err); got != tc.verdict {
			t.Errorf("%s: isReloadVerdict = %v, want %v (%v)", tc.name, got, tc.verdict, err)
		}
	}
	// Transport failure (nothing listening) and missing mTLS material are not
	// verdicts either.
	if _, err := reloadHTTP(http.DefaultClient, "http://127.0.0.1:1/v1/reload"); err == nil || isReloadVerdict(err) {
		t.Errorf("a transport failure must be a non-verdict error, got %v", err)
	}
	if _, err := reloadOverHTTP("127.0.0.1:1", "/nonexistent.crt", "/nonexistent.key", "/nonexistent.ca"); err == nil || isReloadVerdict(err) {
		t.Errorf("missing mTLS material must be a non-verdict error, got %v", err)
	}
	for _, want := range []string{"journalctl -u infrabroker-signer", "audit show --outcome reload-failed"} {
		if !strings.Contains(sighupHint, want) {
			t.Errorf("the SIGHUP hint must mention %q: %s", want, sighupHint)
		}
	}
}

// TestReloadHTTPSuccess: a 200 JSON answer yields the reloaded host count.
func TestReloadHTTPSuccess(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"ok","hosts":3}`)
	}))
	defer srv.Close()

	hosts, err := reloadHTTP(srv.Client(), srv.URL+"/v1/reload")
	if err != nil {
		t.Fatalf("reloadHTTP: %v", err)
	}
	if hosts != 3 {
		t.Errorf("hosts = %d, want 3", hosts)
	}
}
