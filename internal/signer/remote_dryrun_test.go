package signer

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestRemoteDryRunStatusClassification: the control plane relays a signer
// outage on a dry-run/preflight as 502 and a denial as 403 (#660); Remote must
// map the 502 to ErrSignerUnavailable (infrastructure) and keep the 403 a
// plain rejection (policy), for both kinds of dry-run intent.
func TestRemoteDryRunStatusClassification(t *testing.T) {
	for _, tc := range []struct {
		name        string
		status      int
		preflight   bool
		unavailable bool
	}{
		{name: "dry_run_502", status: http.StatusBadGateway, unavailable: true},
		{name: "preflight_502", status: http.StatusBadGateway, preflight: true, unavailable: true},
		{name: "dry_run_403", status: http.StatusForbidden},
		{name: "preflight_403", status: http.StatusForbidden, preflight: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "upstream says no", tc.status)
			}))
			defer cp.Close()

			rm := NewRemote(cp.URL, nil, 5*time.Second)
			_, err := rm.SignIntent(context.Background(), Intent{
				Host: "web01", Role: RoleTarget, Purpose: PurposeOneshot,
				Command: "uptime", DryRun: true, Preflight: tc.preflight,
			})
			if err == nil {
				t.Fatalf("status %d must be an error", tc.status)
			}
			if got := errors.Is(err, ErrSignerUnavailable); got != tc.unavailable {
				t.Errorf("errors.Is(err, ErrSignerUnavailable) = %v, want %v (err: %v)", got, tc.unavailable, err)
			}
		})
	}
}
