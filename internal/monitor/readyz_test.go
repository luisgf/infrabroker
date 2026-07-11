package monitor

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestReadyzGate pins #213: /readyz is 503 until SetReady(true) and 200 after,
// while /healthz (liveness) stays 200 regardless. Serial: it toggles the global
// readiness flag.
func TestReadyzGate(t *testing.T) {
	defer SetReady(false)
	mux := Mux()

	code := func(path string) int {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec.Code
	}

	SetReady(false)
	if got := code("/readyz"); got != http.StatusServiceUnavailable {
		t.Errorf("/readyz before ready = %d, want 503", got)
	}
	// Liveness is independent of readiness.
	if got := code("/healthz"); got != http.StatusOK {
		t.Errorf("/healthz = %d, want 200 (liveness, independent of readiness)", got)
	}

	SetReady(true)
	if got := code("/readyz"); got != http.StatusOK {
		t.Errorf("/readyz after SetReady(true) = %d, want 200", got)
	}
}
