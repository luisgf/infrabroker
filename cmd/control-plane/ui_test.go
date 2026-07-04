package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luisgf/infrabroker/internal/control"
	"github.com/luisgf/infrabroker/internal/signer"
)

// uiApproval seeds one pending approval in the server's registry.
func uiApproval(t *testing.T, s *server, command string) control.Approval {
	t.Helper()
	a, err := s.registry.Create(signer.WireRequest{Host: "web01", Command: command},
		"broker-1", &signer.DecisionInfo{MatchedRule: "require_approval:^reboot"})
	if err != nil {
		t.Fatal(err)
	}
	return *a
}

func TestUIListRequiresApprover(t *testing.T) {
	t.Parallel()
	s := testServer(t, "http://unused")
	w := httptest.NewRecorder()
	s.handleUIList(w, req(t, "GET", "/ui/approvals", "broker-1", nil)) // not an approver
	if w.Code != http.StatusForbidden {
		t.Fatalf("non-approver must get 403, got %d", w.Code)
	}
}

func TestUIListRendersApprovals(t *testing.T) {
	t.Parallel()
	s := testServer(t, "http://unused")
	a := uiApproval(t, s, "reboot <script>alert(1)</script>")

	w := httptest.NewRecorder()
	s.handleUIList(w, req(t, "GET", "/ui/approvals", "broker-admin", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("approver list must be 200, got %d", w.Code)
	}
	body := w.Body.String()
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("content type = %q, want text/html", ct)
	}
	if !strings.Contains(body, a.ID) || !strings.Contains(body, "web01") {
		t.Error("list must show the pending approval")
	}
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Error("command must be HTML-escaped in the list")
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Error("escaped command must still be visible")
	}
}

func TestUIDetailShowsActionsOnlyWhenPending(t *testing.T) {
	t.Parallel()
	s := testServer(t, "http://unused")
	a := uiApproval(t, s, "reboot now")

	get := func(id string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := req(t, "GET", "/ui/approvals/"+id, "broker-admin", nil)
		r.SetPathValue("id", id)
		s.handleUIDetail(w, r)
		return w
	}

	w := get(a.ID)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "decide(true)") {
		t.Fatalf("pending detail must render the decision actions: %d", w.Code)
	}

	if _, err := s.registry.Decide(a.ID, false, "broker-admin", 0); err != nil {
		t.Fatal(err)
	}
	w = get(a.ID)
	if w.Code != http.StatusOK {
		t.Fatalf("decided detail must render, got %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "decide(true)") {
		t.Error("decided request must not offer decision actions")
	}

	w = get("does-not-exist")
	if w.Code != http.StatusNotFound {
		t.Errorf("unknown id must be 404, got %d", w.Code)
	}
}

// TestDecideRequiresJSONContentType is the CSRF regression test: an HTML form
// (enctype=text/plain) can smuggle a JSON-shaped body cross-site with the
// approver's ambient mTLS credential, so the decide endpoint must reject any
// media type other than application/json.
func TestDecideRequiresJSONContentType(t *testing.T) {
	t.Parallel()
	s := testServer(t, "http://unused")
	a := uiApproval(t, s, "reboot now")

	w := httptest.NewRecorder()
	r := req(t, "POST", "/v1/approvals/"+a.ID, "broker-admin", map[string]bool{"approve": true})
	r.Header.Set("Content-Type", "text/plain")
	r.SetPathValue("id", a.ID)
	s.handleApprovalDecide(w, r)
	if w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("text/plain decide must be 415, got %d", w.Code)
	}
	if got, _ := s.registry.Get(a.ID); got.Status != control.StatusPending {
		t.Fatal("the approval must remain pending after a rejected media type")
	}

	// application/json with a charset parameter is accepted.
	w = httptest.NewRecorder()
	r = req(t, "POST", "/v1/approvals/"+a.ID, "broker-admin", map[string]bool{"approve": false})
	r.Header.Set("Content-Type", "application/json; charset=utf-8")
	r.SetPathValue("id", a.ID)
	s.handleApprovalDecide(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("application/json;charset must be accepted, got %d: %s", w.Code, w.Body.String())
	}
}
