package mcpserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/crypto/ssh"

	"github.com/luisgf/infrabroker/internal/broker"
	"github.com/luisgf/infrabroker/internal/signer"
)

// approvalSession registers the SSH tools over an in-memory transport against a
// local-mode engine whose host web01 requires approval for `systemctl restart`.
// elicit toggles in-conversation approval; elicitHandler (when non-nil) answers
// the server's elicitation on the client side.
func approvalSession(t *testing.T, elicit bool, elicitHandler func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error)) *mcp.ClientSession {
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
		Hosts: map[string]broker.HostConfig{
			// Unreachable addr + short key: after approval the sign succeeds and
			// the flow fails LATER (host key / connect), never on the approval gate.
			"web01": {Addr: "127.0.0.1:1", User: "deploy", Principal: "host:web01", HostKey: "ssh-ed25519 AAAAC3Nz",
				CommandPolicy: signer.CommandPolicy{RequireApproval: []string{"^systemctl restart"}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { eng.Close() })

	srv := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	Register(srv, eng, func(context.Context) broker.Caller { return broker.Caller{ID: "test"} }, elicit)
	ct, st := mcp.NewInMemoryTransports()
	if _, err := srv.Connect(context.Background(), st, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, &mcp.ClientOptions{ElicitationHandler: elicitHandler})
	sess, err := client.Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { sess.Close() })
	return sess
}

func callRestart(t *testing.T, sess *mcp.ClientSession) *mcp.CallToolResult {
	t.Helper()
	res, err := sess.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "ssh_execute",
		Arguments: map[string]any{"server": "web01", "command": "systemctl restart nginx"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	return res
}

// TestApprovalRequiredWithoutElicitation: with elicitation off, a require_approval
// command is denied with an approval message (the existing behaviour).
func TestApprovalRequiredWithoutElicitation(t *testing.T) {
	t.Parallel()
	sess := approvalSession(t, false, nil)
	res := callRestart(t, sess)
	if !res.IsError || !strings.Contains(k8sToolText(t, res), "requires human approval") {
		t.Fatalf("want approval-required error; got IsError=%v text=%q", res.IsError, k8sToolText(t, res))
	}
}

// TestApprovalAcceptedViaElicitation: with elicitation on and the human accepting,
// the command passes the approval gate — proven by the error no longer being an
// approval error (it fails later on the unreachable host instead).
func TestApprovalAcceptedViaElicitation(t *testing.T) {
	t.Parallel()
	accept := func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approve": true}}, nil
	}
	sess := approvalSession(t, true, accept)
	res := callRestart(t, sess)
	text := k8sToolText(t, res)
	if strings.Contains(text, "requires human approval") {
		t.Fatalf("approval should have been granted via elicitation; still blocked: %q", text)
	}
	// It got past approval; the unreachable host makes it fail afterwards.
	if !res.IsError {
		t.Logf("note: command returned success (unexpected without a real host), text=%q", text)
	}
}

// TestApprovalDeclinedViaElicitation: the human declines, so the command does not run.
func TestApprovalDeclinedViaElicitation(t *testing.T) {
	t.Parallel()
	decline := func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approve": false}}, nil
	}
	sess := approvalSession(t, true, decline)
	res := callRestart(t, sess)
	if !res.IsError || !strings.Contains(k8sToolText(t, res), "declined") {
		t.Fatalf("want declined error; got IsError=%v text=%q", res.IsError, k8sToolText(t, res))
	}
}

func TestCallerTableMaySelfApprove(t *testing.T) {
	t.Parallel()
	tbl := signer.CallerTable{
		"broker-1": {SelfApprove: true},
		"broker-2": {AllowedGroups: []string{"web"}},
	}
	if !tbl.MaySelfApprove("broker-1") {
		t.Error("broker-1 opted into self-approve")
	}
	if tbl.MaySelfApprove("broker-2") {
		t.Error("broker-2 did not opt in")
	}
	if tbl.MaySelfApprove("unknown") {
		t.Error("unknown caller must not self-approve without an explicit opt-in")
	}
	// self_approve on _default is IGNORED (#207): a single _default entry must not
	// waive four-eyes for every unlisted caller. Explicit CNs keep their opt-in.
	tbl["_default"] = signer.CallerPolicy{SelfApprove: true}
	if tbl.MaySelfApprove("unknown") {
		t.Error("_default self_approve must NOT let an unlisted caller self-approve")
	}
	if !tbl.MaySelfApprove("broker-1") {
		t.Error("an explicit self_approve CN must still self-approve alongside _default")
	}
}
