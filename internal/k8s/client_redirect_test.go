package k8s

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// redirectPair returns a CA-pinned TLS API server that answers every request
// with a 307 to a plain-HTTP server on the same host, plus a counter of the
// requests the plain server received. A followed redirect would carry the
// Authorization header and (307) the body outside the pinned TLS channel (#801).
func redirectPair(t *testing.T) (*fakeAPI, *atomic.Int32, string) {
	t.Helper()
	var hits atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	t.Cleanup(plain.Close)
	f := newFakeAPI(t)
	f.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/leak", http.StatusTemporaryRedirect)
	})
	return f, &hits, plain.URL
}

func checkRedirectErr(t *testing.T, err error, plainURL string) {
	t.Helper()
	if err == nil {
		t.Fatal("a 3xx must surface as an error")
	}
	if !strings.Contains(err.Error(), "307") {
		t.Errorf("error should carry the 3xx status: %v", err)
	}
	if strings.Contains(err.Error(), "/leak") || strings.Contains(err.Error(), plainURL) {
		t.Errorf("error must not echo the redirect target: %v", err)
	}
}

func TestClientDoesNotFollowRedirects(t *testing.T) {
	f, hits, plainURL := redirectPair(t)
	c := f.client(t)
	def := mustDef(t, "configmaps")

	_, err := c.Apply(context.Background(), def, "ns", "cm", []byte(`{"kind":"ConfigMap"}`))
	checkRedirectErr(t, err, plainURL)
	_, err = c.Get(context.Background(), def, "ns", "cm")
	checkRedirectErr(t, err, plainURL)
	if n := hits.Load(); n != 0 {
		t.Fatalf("redirect target contacted %d time(s); token/body leaked off the pinned channel", n)
	}
}

func TestMinterDoesNotFollowRedirects(t *testing.T) {
	f, hits, plainURL := redirectPair(t)
	tokFile := filepath.Join(t.TempDir(), "minter.token")
	if err := os.WriteFile(tokFile, []byte("minter-credential\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := NewMinter(map[string]MinterTarget{
		"c": {Target: Target{APIServer: f.srv.URL, CAPEM: f.caPEM}, TokenFile: tokFile},
	})
	_, _, err := m.MintToken(context.Background(), "c", "a", "b", time.Minute)
	checkRedirectErr(t, err, plainURL)
	if n := hits.Load(); n != 0 {
		t.Fatalf("redirect target contacted %d time(s); standing minter token leaked", n)
	}
}
