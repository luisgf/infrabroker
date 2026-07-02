// Package monitor provides a minimal process-wide metrics registry and the
// plain-HTTP /healthz + /metrics listener the services expose when
// monitor_listen is configured. Metrics are exposed in the Prometheus text
// exposition format without external dependencies.
//
// The registry is package-level (like expvar): any package increments its
// counters directly and the binary decides whether to serve them. Registration
// is get-or-create by name, so instrumented code paths are safe to construct
// repeatedly (e.g. in tests); a GaugeFunc re-registration replaces the
// callback, so a rebuilt component (broker engine, approval registry) simply
// rebinds its gauge.
//
// The listener speaks plain HTTP and has no authentication: bind it to
// localhost or a private scrape interface, never to a public address.
package monitor

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Counter is a monotonically increasing metric.
type Counter struct {
	v atomic.Int64
}

// Inc adds one.
func (c *Counter) Inc() { c.v.Add(1) }

// Add adds n (negative deltas are ignored — counters only go up).
func (c *Counter) Add(n int64) {
	if n > 0 {
		c.v.Add(n)
	}
}

// Value returns the current count.
func (c *Counter) Value() int64 { return c.v.Load() }

// Vec is a family of counters sharing a name and differing in one label value.
type Vec struct {
	label string
	mu    sync.Mutex
	elems map[string]*Counter
}

// With returns the counter for the given label value, creating it on first use.
func (v *Vec) With(value string) *Counter {
	v.mu.Lock()
	defer v.mu.Unlock()
	c, ok := v.elems[value]
	if !ok {
		c = &Counter{}
		v.elems[value] = c
	}
	return c
}

type registry struct {
	mu       sync.Mutex
	order    []string // names in registration order (exposition sorts anyway)
	counters map[string]*Counter
	vecs     map[string]*Vec
	gauges   map[string]func() float64
	help     map[string]string
}

var std = &registry{
	counters: map[string]*Counter{},
	vecs:     map[string]*Vec{},
	gauges:   map[string]func() float64{},
	help:     map[string]string{},
}

// GetCounter returns the counter registered under name, creating it if needed.
func GetCounter(name, help string) *Counter {
	std.mu.Lock()
	defer std.mu.Unlock()
	c, ok := std.counters[name]
	if !ok {
		c = &Counter{}
		std.counters[name] = c
		std.order = append(std.order, name)
		std.help[name] = help
	}
	return c
}

// GetCounterVec returns the labelled counter family registered under name,
// creating it if needed. The label name is fixed at first registration.
func GetCounterVec(name, help, label string) *Vec {
	std.mu.Lock()
	defer std.mu.Unlock()
	v, ok := std.vecs[name]
	if !ok {
		v = &Vec{label: label, elems: map[string]*Counter{}}
		std.vecs[name] = v
		std.order = append(std.order, name)
		std.help[name] = help
	}
	return v
}

// SetGaugeFunc registers (or replaces) a gauge whose value is read at scrape
// time. Replacement is deliberate: a rebuilt component rebinds its gauge.
func SetGaugeFunc(name, help string, f func() float64) {
	std.mu.Lock()
	defer std.mu.Unlock()
	if _, ok := std.gauges[name]; !ok {
		std.order = append(std.order, name)
	}
	std.gauges[name] = f
	std.help[name] = help
}

// escapeLabel makes a label value safe for the text exposition format.
func escapeLabel(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return r.Replace(s)
}

// writeMetrics renders the registry in the Prometheus text exposition format,
// sorted by metric name (and by label value within a family) so the output is
// deterministic.
func writeMetrics(w *strings.Builder) {
	std.mu.Lock()
	defer std.mu.Unlock()
	names := make([]string, len(std.order))
	copy(names, std.order)
	sort.Strings(names)
	for _, name := range names {
		if c, ok := std.counters[name]; ok {
			fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", name, std.help[name], name, name, c.Value())
			continue
		}
		if v, ok := std.vecs[name]; ok {
			fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n", name, std.help[name], name)
			v.mu.Lock()
			labels := make([]string, 0, len(v.elems))
			for lv := range v.elems {
				labels = append(labels, lv)
			}
			sort.Strings(labels)
			for _, lv := range labels {
				fmt.Fprintf(w, "%s{%s=\"%s\"} %d\n", name, v.label, escapeLabel(lv), v.elems[lv].Value())
			}
			v.mu.Unlock()
			continue
		}
		if f, ok := std.gauges[name]; ok {
			fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n%s %g\n", name, std.help[name], name, name, f())
		}
	}
}

// Handler serves the /metrics text exposition.
func Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b strings.Builder
		writeMetrics(&b)
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		fmt.Fprint(w, b.String())
	})
}

// Mux returns the monitoring mux: /healthz (liveness, always 200 while the
// process serves) and /metrics.
func Mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, "ok")
	})
	mux.Handle("/metrics", Handler())
	return mux
}

// Serve starts the monitoring listener on addr (plain HTTP — bind to localhost
// or a private interface) and blocks until ctx is cancelled, then shuts down
// gracefully. An empty addr is a no-op. Serve failures are logged, not fatal:
// monitoring must never take the service down.
func Serve(ctx context.Context, addr, name string) {
	if addr == "" {
		return
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           Mux(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	errc := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()
	log.Printf("%s: monitoring on http://%s (/healthz, /metrics)", name, addr)
	select {
	case err := <-errc:
		log.Printf("%s: monitoring listener failed: %v", name, err)
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}
}
