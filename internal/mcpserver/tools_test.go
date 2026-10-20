package mcpserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/crypto/ssh"

	"github.com/luisgf/infrabroker/internal/broker"
)

// newTestEngine builds a local-mode engine (fresh CA key, audit log in a temp
// dir) over the given hosts. No signing service or network is needed until a
// tool actually dials a host.
func newTestEngine(t *testing.T, hosts map[string]broker.HostConfig) *broker.Engine {
	t.Helper()
	dir := t.TempDir()

	_, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	blk, err := ssh.MarshalPrivateKey(caPriv, "ca-test")
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(dir, "ca")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(blk), 0o600); err != nil {
		t.Fatal(err)
	}
	seedPath := filepath.Join(dir, "audit.seed")
	seed := make([]byte, 32)
	_, _ = rand.Read(seed)
	if err := os.WriteFile(seedPath, seed, 0o600); err != nil {
		t.Fatal(err)
	}

	eng, err := broker.NewEngine(&broker.Config{
		CAKey:         caPath,
		AuditLog:      filepath.Join(dir, "audit.log"),
		AuditKey:      seedPath,
		SourceAddress: "127.0.0.1",
		MaxTTLSeconds: 120,
		Hosts:         hosts,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { eng.Close() })
	return eng
}

// sshTestSession registers the SSH tools on an in-memory server and returns a
// connected client session.
func sshTestSession(t *testing.T, eng *broker.Engine) *mcp.ClientSession {
	t.Helper()
	srv := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	Register(srv, eng, func(context.Context) broker.Caller { return broker.Caller{ID: "test"} }, false)

	ct, st := mcp.NewInMemoryTransports()
	if _, err := srv.Connect(context.Background(), st, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	sess, err := client.Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { sess.Close() })
	return sess
}

// unreachableHost returns a 127.0.0.1 address nothing listens on (a port that
// was just bound and released) and a syntactically valid host key for it.
func unreachableHost(t *testing.T) (addr, hostKey string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr = ln.Addr().String()
	_ = ln.Close()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return addr, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
}

// TestSessionOpenUnreachableHostMasked pins #545 end to end: ssh_session_open
// against a host whose address nothing listens on must answer the model with
// the generic upstream text, not the engine's "connection: connecting to
// <addr>: dial tcp ..." detail. TestToolErrorHidesUpstreamAddress only feeds
// pre-wrapped ErrUpstream errors to toolError; this drives the real
// OpenSession dial failure through the tool, so the engine-side wrapping is
// covered too.
func TestSessionOpenUnreachableHostMasked(t *testing.T) {
	t.Parallel()
	addr, hostKey := unreachableHost(t)
	eng := newTestEngine(t, map[string]broker.HostConfig{
		"dead": {Addr: addr, User: "deploy", Principal: "host:dead", HostKey: hostKey},
	})
	sess := sshTestSession(t, eng)

	res, err := sess.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "ssh_session_open", Arguments: map[string]any{"server": "dead"},
	})
	if err != nil {
		t.Fatalf("CallTool transport error: %v", err)
	}
	if !res.IsError {
		t.Fatalf("expected a tool error, got success: %s", k8sToolText(t, res))
	}
	text := k8sToolText(t, res)
	if text != upstreamToolMessage {
		t.Errorf("ssh_session_open on an unreachable host = %q, want the generic %q", text, upstreamToolMessage)
	}
	if strings.Contains(text, addr) || strings.Contains(text, "127.0.0.1") || strings.Contains(text, "dial tcp") {
		t.Errorf("dial detail must not reach the model, got %q", text)
	}
}

// TestToolErrorHidesUpstreamAddress pins #472: an infrastructure error from the
// engine (SSH dial/hop failure, signing service unreachable) must not reach the
// model verbatim, since it carries the internal ip:port of the target or the
// jump host. Mirrors brokermain's TestClassifyErrorUpstreamHidesInternalAddr:
// the HTTP frontend masks ErrUpstream, so the MCP frontends must as well.
func TestToolErrorHidesUpstreamAddress(t *testing.T) {
	t.Parallel()
	cases := []error{
		fmt.Errorf("%w: connection: connecting to 10.1.2.3:22: dial tcp 10.1.2.3:22: i/o timeout", broker.ErrUpstream),
		fmt.Errorf("%w: connection: hop to 10.1.2.3:22: dial tcp 10.1.2.3:22: connection refused", broker.ErrUpstream),
		fmt.Errorf("%w: refreshing host list: Get \"https://10.1.2.3:8443/v1/hosts\": connection refused", broker.ErrUpstream),
	}
	for _, err := range cases {
		res := toolError(err)
		if !res.IsError {
			t.Fatalf("toolError(%v): IsError must be true", err)
		}
		if len(res.Content) != 1 {
			t.Fatalf("toolError(%v): want 1 content item, got %d", err, len(res.Content))
		}
		text := res.Content[0].(*mcp.TextContent).Text
		if strings.Contains(text, "10.1.2.3") {
			t.Errorf("upstream tool error must not leak internal addresses, got %q", text)
		}
		if text != upstreamToolMessage {
			t.Errorf("upstream tool error = %q, want the generic %q", text, upstreamToolMessage)
		}
	}
}

// TestToolErrorKeepsPolicyText: denials and other non-infrastructure errors
// keep their text, which is what the model needs to self-correct.
func TestToolErrorKeepsPolicyText(t *testing.T) {
	t.Parallel()
	for _, err := range []error{
		errors.New("command denied by host policy: deny:^rm "),
		fmt.Errorf("%w: unknown field", broker.ErrBadRequest),
		fmt.Errorf("%w: nope", broker.ErrUnknownHost),
	} {
		text := toolError(err).Content[0].(*mcp.TextContent).Text
		if text != err.Error() {
			t.Errorf("toolError(%v) = %q, want the error text verbatim", err, text)
		}
	}
}

// TestEncodedBoundAndOversizedContentReject pins #396: ssh_put_file content
// bypasses broker.MaxInputLen, so the handler must bound the raw (base64-encoded)
// content at base64(4/3 of the transfer cap)+padding BEFORE decoding it.
func TestEncodedBoundAndOversizedContentReject(t *testing.T) {
	t.Parallel()
	max := 512 * 1024
	bound := encodedBound(max)
	// Exact base64 length for max bytes: 4*ceil(max/3). The bound is a
	// slightly looser (max/3 + 4) variant — it must never be UNDER it, and
	// within 32 bytes of it.
	want := ((max + 2) / 3) * 4
	if bound < want {
		t.Errorf("encodedBound(%d) = %d, must be at least the exact base64 length %d", max, bound, want)
	}
	if bound-want > 32 {
		t.Errorf("encodedBound(%d) = %d, unnecessarily loose vs exact %d", max, bound, want)
	}
}

// TestValidateInputIdentifierCaps locks in #572: identifiers (server,
// sudo_user, cluster, …) are capped far below the free-text limit so a hostile
// 64 KiB "server" name cannot reach the signed audit log's metadata fields.
func TestValidateInputIdentifierCaps(t *testing.T) {
	long := strings.Repeat("<", 2048)
	if err := validateInput(map[string]string{"server": long}); err == nil {
		t.Error("a 2 KiB server name must be rejected")
	}
	if err := validateInput(map[string]string{"sudo_user": long}); err == nil {
		t.Error("a 2 KiB sudo_user must be rejected")
	}
	if err := validateInput(map[string]string{"command": strings.Repeat("x", 60*1024)}); err != nil {
		t.Errorf("free text up to broker.MaxInputLen must still pass: %v", err)
	}
	if err := validateInput(map[string]string{"server": "web01", "path": strings.Repeat("a", 3000)}); err != nil {
		t.Errorf("ordinary identifiers and a 3 KB path must pass: %v", err)
	}
}
