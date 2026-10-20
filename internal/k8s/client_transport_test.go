package k8s

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestDoHidesAPIServerAddressOnTransportError pins #204: a call against an
// unreachable API server must return an error to the model that contains
// neither the host nor the port. The transport-error branch used to wrap the
// raw *url.Error, whose text is `METHOD "https://host:port/path": <cause>`.
func TestDoHidesAPIServerAddressOnTransportError(t *testing.T) {
	t.Parallel()
	const host = "k8s-secret-host.invalid" // RFC 6761: never resolves
	const port = "6443"

	// newFakeAPI only supplies a parseable CA PEM; the client points elsewhere.
	f := newFakeAPI(t)
	c, err := NewClient(Target{APIServer: "https://" + host + ":" + port, CAPEM: f.caPEM}, "tok", time.Second)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, err = c.Get(context.Background(), mustDef(t, "pods"), "default", "web-1")
	if err == nil {
		t.Fatal("expected a transport error against an unreachable API server")
	}
	msg := err.Error()
	if strings.Contains(msg, host) {
		t.Errorf("error leaks the API-server host: %q", msg)
	}
	if strings.Contains(msg, port) {
		t.Errorf("error leaks the API-server port: %q", msg)
	}
	// The method and the address-free REST path are still surfaced, so the model
	// can tell what failed without learning where the API server lives.
	if !strings.Contains(msg, "GET") || !strings.Contains(msg, "/api/v1/namespaces/default/pods/web-1") {
		t.Errorf("error should still name the method and REST path: %q", msg)
	}
}

// readLoopGoroutines counts the net/http persistConn readLoop goroutines
// alive in the process: one per pooled keep-alive connection, so it is the
// direct measure of connections a discarded single-use Client left behind.
func readLoopGoroutines() int {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	return strings.Count(string(buf), "net/http.(*persistConn).readLoop")
}

// TestClientLeavesNoIdleConnections pins #596: a Client (and its Transport)
// is built per operation — one per K8sExecute in the broker, one per
// MintToken in the signer — and discarded with the token, but nothing closed
// the Transport's idle pool, so every call parked a keep-alive TLS connection
// plus its readLoop/writeLoop goroutines until the SERVER's idle timeout
// (unbounded behind a load balancer with long keep-alives). The single-use
// transport must not keep connections alive: after N operations the number of
// readLoop goroutines returns to the baseline.
func TestClientLeavesNoIdleConnections(t *testing.T) {
	f := newFakeAPI(t)
	def := mustDef(t, "pods")
	// Settle any goroutines left by earlier tests before taking the baseline.
	time.Sleep(50 * time.Millisecond)
	before := readLoopGoroutines()

	const n = 25
	for i := 0; i < n; i++ {
		c := f.client(t)
		if _, err := c.Get(context.Background(), def, "default", "web-1"); err != nil {
			t.Fatalf("Get %d: %v", i, err)
		}
	}

	// Connection teardown after the response is asynchronous; poll briefly.
	deadline := time.Now().Add(3 * time.Second)
	var after int
	for {
		after = readLoopGoroutines()
		if after <= before || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if after > before {
		t.Fatalf("%d single-use clients left %d keep-alive connections behind (readLoop goroutines before=%d after=%d)", n, after-before, before, after)
	}
}
