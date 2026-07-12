package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestDoJSONDecodesSuccess: a 200 + JSON body decodes into out and the raw bytes
// are returned for callers that also want them.
func TestDoJSONDecodesSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"id":"g1","expires_at":"soon"}`)
	}))
	defer srv.Close()

	var out struct {
		ID        string `json:"id"`
		ExpiresAt string `json:"expires_at"`
	}
	rb := doJSON(srv.Client(), http.MethodGet, srv.URL, nil, &out)
	if out.ID != "g1" || out.ExpiresAt != "soon" {
		t.Fatalf("decoded %+v, want {g1 soon}", out)
	}
	if len(rb) == 0 {
		t.Error("doJSON returned no raw bytes")
	}
}

// TestDoJSONAccepts2xx: a 201 Created (what POST .../grants returns) is a success,
// not an error — a naive `!= 200` check would have wrongly failed it.
func TestDoJSONAccepts2xx(t *testing.T) {
	var gotBody bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody = r.ContentLength > 0 && r.Header.Get("Content-Type") == "application/json"
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"id":"g1"}`)
	}))
	defer srv.Close()

	var out struct {
		ID string `json:"id"`
	}
	doJSON(srv.Client(), http.MethodPost, srv.URL, map[string]any{"allow": "^ls"}, &out)
	if out.ID != "g1" {
		t.Fatalf("id=%q, want g1", out.ID)
	}
	if !gotBody {
		t.Error("a non-nil reqBody must be sent as application/json")
	}
}

// TestDoJSONBoundsResponse: a peer streaming more than the cap must not make the
// CLI read without limit — doJSON stops at maxRespBytes (#212).
func TestDoJSONBoundsResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(make([]byte, maxRespBytes+4096))
	}))
	defer srv.Close()

	rb := doJSON(srv.Client(), http.MethodGet, srv.URL, nil, nil) // nil out → no decode
	if len(rb) != maxRespBytes {
		t.Fatalf("read %d bytes, want the %d-byte cap", len(rb), maxRespBytes)
	}
}
