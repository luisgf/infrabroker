package monitor

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCounterAndVec(t *testing.T) {
	t.Parallel()
	c := GetCounter("test_counter_total", "help text")
	c.Inc()
	c.Add(2)
	c.Add(-5) // ignored: counters only go up
	if got := c.Value(); got != 3 {
		t.Errorf("counter = %d, want 3", got)
	}
	if again := GetCounter("test_counter_total", "other"); again != c {
		t.Error("GetCounter must be get-or-create by name")
	}

	v := GetCounterVec("test_vec_total", "help", "outcome")
	v.With("ok").Inc()
	v.With("ok").Inc()
	v.With("error").Inc()
	if got := v.With("ok").Value(); got != 2 {
		t.Errorf("vec[ok] = %d, want 2", got)
	}
}

func TestGaugeFuncReplacement(t *testing.T) {
	t.Parallel()
	SetGaugeFunc("test_gauge", "help", func() float64 { return 1 })
	SetGaugeFunc("test_gauge", "help", func() float64 { return 42 })
	var b strings.Builder
	writeMetrics(&b)
	if !strings.Contains(b.String(), "test_gauge 42") {
		t.Errorf("re-registered gauge must expose the new callback, got:\n%s", b.String())
	}
}

func TestExposition(t *testing.T) {
	t.Parallel()
	GetCounter("test_expo_total", "a counter").Inc()
	GetCounterVec("test_expo_vec_total", "a vec", "outcome").With(`quo"te`).Inc()

	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body := rec.Body.String()

	for _, want := range []string{
		"# HELP test_expo_total a counter",
		"# TYPE test_expo_total counter",
		"test_expo_total 1",
		"# TYPE test_expo_vec_total counter",
		`test_expo_vec_total{outcome="quo\"te"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("exposition missing %q, got:\n%s", want, body)
		}
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("unexpected content type %q", ct)
	}
}

func TestHealthz(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	Mux().ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "ok") {
		t.Errorf("healthz = %d %q, want 200 ok", rec.Code, rec.Body.String())
	}
}
