package control

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
)

// TestLogNotifierShowsElevation verifies that the default notifier surfaces the
// sudo elevation, so a human approver sees that an innocuous-looking command
// would have its force-command issued under sudo. (Not parallel: it redirects
// the global logger.)
func TestLogNotifierShowsElevation(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	err := LogNotifier{}.Notify(Approval{
		ID: "x", Caller: "broker-1", Host: "web01",
		Command: "systemctl restart nginx", Sudo: true, SudoUser: "root",
	})
	if err != nil {
		t.Fatalf("Notify: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "elevation=sudo:root") {
		t.Errorf("LogNotifier must surface the elevation; got %q", out)
	}

	// No sudo → elevation=none.
	buf.Reset()
	_ = LogNotifier{}.Notify(Approval{ID: "y", Caller: "broker-1", Host: "web01", Command: "uptime"})
	if out := buf.String(); !strings.Contains(out, "elevation=none") {
		t.Errorf("non-elevated request must show elevation=none; got %q", out)
	}
}

// redirectingWebhook starts two httptest servers: the first answers every
// request with a 307 whose Location points at the second. It returns the first
// server's URL and a counter of requests the second (redirect target) received.
// A 307 preserves method and body, so a client that follows it would re-POST
// the full approval payload to the target (#453).
func redirectingWebhook(t *testing.T) (string, *int32) {
	t.Helper()
	var hits int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(target.Close)
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/leak", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(first.Close)
	return first.URL, &hits
}

// TestWebhookNotifierDoesNotFollowRedirect locks in that the webhook notifier
// never follows a redirect: the https-only guard (#44/#401) only validates the
// configured URL, so following a 307/308 would let the webhook host downgrade
// the delivery to http:// or re-route the payload to a private host (#453).
func TestWebhookNotifierDoesNotFollowRedirect(t *testing.T) {
	url, hits := redirectingWebhook(t)
	err := NewWebhookNotifier(url).Notify(Approval{ID: "x", Caller: "broker-1", Host: "web01", Command: "uptime"})
	if err == nil {
		t.Fatal("Notify must fail on a 307 redirect instead of following it")
	}
	if !strings.Contains(err.Error(), "307") {
		t.Errorf("error must surface the 307 status, got: %v", err)
	}
	if n := atomic.LoadInt32(hits); n != 0 {
		t.Errorf("redirect target must receive nothing, got %d request(s)", n)
	}
}

// TestTeamsNotifierDoesNotFollowRedirect is the Teams twin of
// TestWebhookNotifierDoesNotFollowRedirect (#453).
func TestTeamsNotifierDoesNotFollowRedirect(t *testing.T) {
	url, hits := redirectingWebhook(t)
	err := NewTeamsNotifier(url, TeamsFormatWorkflow, "").Notify(Approval{ID: "x", Caller: "broker-1", Host: "web01", Command: "uptime"})
	if err == nil {
		t.Fatal("Notify must fail on a 307 redirect instead of following it")
	}
	if !strings.Contains(err.Error(), "307") {
		t.Errorf("error must surface the 307 status, got: %v", err)
	}
	if n := atomic.LoadInt32(hits); n != 0 {
		t.Errorf("redirect target must receive nothing, got %d request(s)", n)
	}
}
