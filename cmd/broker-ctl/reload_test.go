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
