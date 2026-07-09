package bridge

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPControlPlaneListAndDecide(t *testing.T) {
	t.Parallel()

	var (
		gotDecidePath  string
		gotContentType string
		gotBody        map[string]any
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/approvals":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"id": "a1", "host": "web01", "command": "systemctl restart nginx"},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/approvals/a1":
			gotDecidePath = r.URL.Path
			gotContentType = r.Header.Get("Content-Type")
			rb, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(rb, &gotBody)
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	cp := newControlPlane(srv.URL, srv.Client())

	pending, err := cp.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(pending) != 1 || pending[0].ID != "a1" || pending[0].Host != "web01" {
		t.Fatalf("List = %+v, want one a1/web01", pending)
	}

	if err := cp.Decide(context.Background(), "a1", true); err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if gotDecidePath != "/v1/approvals/a1" {
		t.Errorf("Decide path = %q", gotDecidePath)
	}
	if gotContentType != "application/json" {
		t.Errorf("Decide Content-Type = %q, want application/json", gotContentType)
	}
	if gotBody["approve"] != true {
		t.Errorf("Decide body = %v, want approve:true", gotBody)
	}
}

func TestHTTPControlPlaneDecideSurfacesError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "self-approval not allowed", http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	cp := newControlPlane(srv.URL, srv.Client())
	if err := cp.Decide(context.Background(), "a1", true); err == nil {
		t.Fatal("Decide must return an error on a non-200 from the control plane")
	}
}
