package brokermain

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/luisgf/infrabroker/internal/oauth"
)

// swappableBearer injects the current bearer into every request; the token can
// be replaced mid-session, as a client refreshing its access token does.
type swappableBearer struct {
	mu    sync.Mutex
	token string
	base  http.RoundTripper
}

func (b *swappableBearer) set(tok string) {
	b.mu.Lock()
	b.token = tok
	b.mu.Unlock()
}

func (b *swappableBearer) RoundTrip(r *http.Request) (*http.Response, error) {
	b.mu.Lock()
	tok := b.token
	b.mu.Unlock()
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+tok)
	return b.base.RoundTrip(r)
}

// TestHTTPCallerFollowsCurrentToken pins #807: on the stateful streamable
// handler every tool call is authorised with the claims of the bearer token of
// THAT request, not of the token presented at initialize. A user whose IdP
// groups were reduced loses the revoked access on the very next call of the
// same MCP session, the context_claim attribution follows the current token,
// and a token for a different user is still refused on the session (SDK
// hijack guard).
func TestHTTPCallerFollowsCurrentToken(t *testing.T) {
	idp := newFakeIdP(t)
	eng, cfg := testEngine(t, idp.srv.URL)
	cfg.OAuth.GroupsClaim = "groups"
	cfg.OAuth.ContextClaim = "sandbox_id"

	mux, err := newMux(context.Background(), eng, cfg)
	if err != nil {
		t.Fatalf("newMux: %v", err)
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	bearer := &swappableBearer{
		token: idp.tokenWith(t, "alice", map[string]any{"groups": []string{"sre"}, "sandbox_id": "first"}),
		base:  http.DefaultTransport,
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	sess, err := client.Connect(context.Background(),
		&mcp.StreamableClientTransport{Endpoint: srv.URL, HTTPClient: &http.Client{Transport: bearer}}, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })

	dryRun := func(t *testing.T) string {
		t.Helper()
		res, err := sess.CallTool(context.Background(), &mcp.CallToolParams{
			Name: "ssh_execute", Arguments: map[string]any{"server": "web01", "command": "uptime", "dry_run": true},
		})
		if err != nil {
			t.Fatalf("ssh_execute dry-run: %v", err)
		}
		if res.IsError {
			t.Fatalf("ssh_execute dry-run returned error: %+v", res.Content)
		}
		return textContent(res)
	}
	listServers := func(t *testing.T) string {
		t.Helper()
		res, err := sess.CallTool(context.Background(), &mcp.CallToolParams{Name: "ssh_list_servers"})
		if err != nil {
			t.Fatalf("ssh_list_servers: %v", err)
		}
		if res.IsError {
			t.Fatalf("ssh_list_servers returned error: %+v", res.Content)
		}
		return textContent(res)
	}
	lastAudit := func(t *testing.T) map[string]any {
		t.Helper()
		raw, err := os.ReadFile(cfg.AuditLog)
		if err != nil {
			t.Fatalf("read audit log: %v", err)
		}
		lines := bytes.Split(bytes.TrimSpace(raw), []byte("\n"))
		var ent map[string]any
		if err := json.Unmarshal(lines[len(lines)-1], &ent); err != nil {
			t.Fatalf("decode audit entry: %v", err)
		}
		return ent
	}

	// Initialize-time token: alice in "sre" reaches web01.
	if txt := dryRun(t); !strings.Contains(txt, "ALLOWED") {
		t.Fatalf("dry-run with the sre token = %q, want ALLOWED", txt)
	}
	if got := lastAudit(t)["end_user_context"]; got != "first" {
		t.Errorf("audit end_user_context = %v, want first", got)
	}
	if txt := listServers(t); !strings.Contains(txt, "web01") {
		t.Fatalf("ssh_list_servers with the sre token = %q, want web01 listed", txt)
	}

	// Same user, refreshed token without "sre" — on the SAME MCP session.
	bearer.set(idp.tokenWith(t, "alice", map[string]any{"groups": []string{"db-admins"}, "sandbox_id": "second"}))

	if txt := dryRun(t); !strings.Contains(txt, "DENIED") || !strings.Contains(txt, "(groups)") {
		t.Errorf("dry-run after the groups were reduced = %q, want the per-user RBAC (groups) denial", txt)
	}
	ent := lastAudit(t)
	if got := ent["caller"]; got != "alice" {
		t.Errorf("audit caller = %v, want alice", got)
	}
	if got := ent["end_user_context"]; got != "second" {
		t.Errorf("audit end_user_context = %v, want the current token's sandbox_id 'second'", got)
	}
	if txt := listServers(t); strings.Contains(txt, "web01") {
		t.Errorf("ssh_list_servers after the groups were reduced still lists web01: %q", txt)
	}

	// A different user's token on alice's session is refused by the SDK's
	// session-hijack guard (403 "session user mismatch"), as before.
	bearer.set(idp.tokenWith(t, "mallory", map[string]any{"groups": []string{"sre"}}))
	_, err = sess.CallTool(context.Background(), &mcp.CallToolParams{Name: "ssh_list_servers"})
	if err == nil {
		t.Fatal("a token for a different user must not be accepted on another user's MCP session")
	}
	if !strings.Contains(err.Error(), "Forbidden") {
		t.Errorf("different-user call error = %v, want the SDK's 403 session user mismatch", err)
	}
}

// TestHTTPCallerReadsRequestTokenOnly pins that httpCaller derives every field
// (ID, groups, raw token, context) from the request's own TokenInfo and that a
// request without one yields the empty, unauthenticated caller — there is no
// fallback to a token held by the session context (#807).
func TestHTTPCallerReadsRequestTokenOnly(t *testing.T) {
	t.Parallel()
	ti := &auth.TokenInfo{UserID: "alice", Extra: map[string]any{
		oauth.ExtraGroupsKey:   []string{"db-admins"},
		oauth.ExtraRawTokenKey: "raw-current",
		oauth.ExtraContextKey:  "ctx-current",
	}}
	c := httpCaller(context.Background(), &mcp.CallToolRequest{Extra: &mcp.RequestExtra{TokenInfo: ti}})
	if c.ID != "alice" || len(c.Groups) != 1 || c.Groups[0] != "db-admins" || c.RawToken != "raw-current" || c.Context != "ctx-current" {
		t.Errorf("httpCaller = %+v, want every field from the request's TokenInfo", c)
	}

	for name, req := range map[string]*mcp.CallToolRequest{
		"nil request":     nil,
		"no extra":        {},
		"extra, no token": {Extra: &mcp.RequestExtra{}},
	} {
		if c := httpCaller(context.Background(), req); c.ID != "" || c.Groups != nil || c.RawToken != "" || c.Context != "" {
			t.Errorf("%s: httpCaller = %+v, want the empty caller", name, c)
		}
	}
}
