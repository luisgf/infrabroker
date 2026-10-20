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

// TestUIResponsesDenyFraming is the clickjacking regression test: the detail
// page's Approve button POSTs with the approver's ambient mTLS certificate, so
// an attacker who can host a page (any notification audience holds the
// approval id) could frame it invisibly under a decoy. Every UI page must
// forbid framing, forbid caching and forbid MIME sniffing.
func TestUIResponsesDenyFraming(t *testing.T) {
	t.Parallel()
	s := testServer(t, "http://unused")
	a := uiApproval(t, s, "reboot now")

	want := map[string]string{
		"X-Frame-Options":         "DENY",
		"Content-Security-Policy": "frame-ancestors 'none'",
		"Cache-Control":           "no-store",
		"X-Content-Type-Options":  "nosniff",
	}
	check := func(name string, w *httptest.ResponseRecorder) {
		t.Helper()
		if w.Code != http.StatusOK {
			t.Fatalf("%s: want 200, got %d", name, w.Code)
		}
		for h, v := range want {
			if got := w.Header().Get(h); got != v {
				t.Errorf("%s: header %s = %q, want %q", name, h, got, v)
			}
		}
	}
	detail := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := req(t, "GET", "/ui/approvals/"+a.ID, "broker-admin", nil)
		r.SetPathValue("id", a.ID)
		s.handleUIDetail(w, r)
		return w
	}

	w := httptest.NewRecorder()
	s.handleUIList(w, req(t, "GET", "/ui/approvals", "broker-admin", nil))
	check("list", w)
	check("pending detail", detail())

	if _, err := s.registry.Decide(a.ID, false, "broker-admin", 0); err != nil {
		t.Fatal(err)
	}
	check("decided detail", detail())
}

// TestUILabelsClusterForK8s: the list and detail pages label a k8s request's
// target "Cluster" instead of "Host" (#664); SSH requests keep "Host".
func TestUILabelsClusterForK8s(t *testing.T) {
	t.Parallel()
	s := testServer(t, "http://unused")
	k8s, err := s.registry.Create(signer.WireRequest{
		TargetType: signer.TargetTypeK8s, Host: "prod-aks", Command: "delete pods prod/web-1",
	}, "broker-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	ssh := uiApproval(t, s, "reboot now")

	detail := func(id string) string {
		w := httptest.NewRecorder()
		r := req(t, "GET", "/ui/approvals/"+id, "broker-admin", nil)
		r.SetPathValue("id", id)
		s.handleUIDetail(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("detail must be 200, got %d", w.Code)
		}
		return w.Body.String()
	}
	if body := detail(k8s.ID); !strings.Contains(body, "<dt>Cluster</dt><dd>prod-aks</dd>") {
		t.Errorf("k8s detail must label the target Cluster:\n%s", body)
	}
	if body := detail(ssh.ID); !strings.Contains(body, "<dt>Host</dt><dd>web01</dd>") {
		t.Errorf("SSH detail must keep the Host label:\n%s", body)
	}

	w := httptest.NewRecorder()
	s.handleUIList(w, req(t, "GET", "/ui/approvals", "broker-admin", nil))
	if body := w.Body.String(); !strings.Contains(body, "<em>Cluster</em> prod-aks") || strings.Contains(body, "<em>Cluster</em> web01") {
		t.Errorf("list must mark only the k8s row as a cluster:\n%s", body)
	}
}
