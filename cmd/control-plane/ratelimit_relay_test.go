package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// auditLineCount returns the number of records in the audit log at path.
func auditLineCount(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0
		}
		t.Fatal(err)
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return 0
	}
	return len(bytes.Split(data, []byte("\n")))
}

// TestControlPlaneRelaysSignerRateLimit: a signer 429 (sign_rate_limit_per_min)
// is relayed as 429 with the signer's Retry-After, is NOT audited (the signer
// deliberately leaves its 429s out of the tamper-evident log, #464), and bumps
// controlplane_signer_rate_limited_total — on the live and the dry-run paths
// (#662).
func TestControlPlaneRelaysSignerRateLimit(t *testing.T) {
	for _, tc := range []struct {
		name              string
		dryRun, preflight bool
	}{
		{name: "live"},
		{name: "dry_run", dryRun: true},
		{name: "preflight", dryRun: true, preflight: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sig := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Retry-After", "7")
				http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			}))
			defer sig.Close()
			s, auditPath := testServerWithAudit(t, sig.URL)
			before := auditLineCount(t, auditPath)
			metricBefore := signerRateLimitedTotal.Value()

			wr := wireReq(t, "uptime")
			wr.DryRun, wr.Preflight = tc.dryRun, tc.preflight
			w := httptest.NewRecorder()
			s.handleSign(w, signReq(t, "broker-1", wr))
			if w.Code != http.StatusTooManyRequests {
				t.Fatalf("signer 429 must be relayed as 429, got %d: %s", w.Code, w.Body.String())
			}
			if got := w.Header().Get("Retry-After"); got != "7" {
				t.Errorf("Retry-After = %q, want the signer's \"7\"", got)
			}
			if !bytes.Contains(w.Body.Bytes(), []byte("rate limit exceeded")) {
				t.Errorf("body must carry the signer's text, got %q", w.Body.String())
			}
			if after := auditLineCount(t, auditPath); after != before {
				t.Errorf("a relayed signer 429 must not be audited: %d -> %d records", before, after)
			}
			if got := signerRateLimitedTotal.Value() - metricBefore; got != 1 {
				t.Errorf("controlplane_signer_rate_limited_total delta = %d, want 1", got)
			}
		})
	}
}
