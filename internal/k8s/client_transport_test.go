package k8s

import (
	"context"
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
