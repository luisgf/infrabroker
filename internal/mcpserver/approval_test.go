package mcpserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/crypto/ssh"

	"github.com/luisgf/infrabroker/internal/audit"
	"github.com/luisgf/infrabroker/internal/broker"
	"github.com/luisgf/infrabroker/internal/signer"
)

// approvalSession registers the SSH tools over an in-memory transport against a
// local-mode engine whose host web01 requires approval for `systemctl restart`.
// elicit toggles in-conversation approval; elicitHandler (when non-nil) answers
// the server's elicitation on the client side.
func approvalSession(t *testing.T, elicit bool, elicitHandler func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error)) (*mcp.ClientSession, string) {
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
	return sess, filepath.Join(dir, "audit.log")
}

// auditContains reports whether the audit log at path has an entry with the given
// outcome, and returns that entry (the last match) for further assertions.
func auditContains(t *testing.T, path, outcome string) (audit.Entry, bool) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	var found audit.Entry
	ok := false
	for _, line := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		if line == "" {
			continue
		}
		var e audit.Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("unmarshal audit line: %v", err)
		}
		if e.Outcome == outcome {
			found, ok = e, true
		}
	}
	return found, ok
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
	sess, _ := approvalSession(t, false, nil)
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
	sess, auditLog := approvalSession(t, true, accept)
	res := callRestart(t, sess)
	text := k8sToolText(t, res)
	if strings.Contains(text, "requires human approval") {
		t.Fatalf("approval should have been granted via elicitation; still blocked: %q", text)
	}
	// It got past approval; the unreachable host makes it fail afterwards.
	if !res.IsError {
		t.Logf("note: command returned success (unexpected without a real host), text=%q", text)
	}
	// #280: the approval decision is recorded before execution, with the channel,
	// even though the exec later fails on the unreachable host.
	e, ok := auditContains(t, auditLog, "approval_granted")
	if !ok {
		t.Fatal("expected an approval_granted audit entry after an elicited approval")
	}
	if e.ApprovedVia != "elicitation" {
		t.Errorf("approval_granted approved_via=%q, want %q", e.ApprovedVia, "elicitation")
	}
	if e.Command != "systemctl restart nginx" || e.Host != "web01" {
		t.Errorf("approval_granted entry = %+v, want the elicited command/host", e)
	}
}

// TestApprovalDeclinedViaElicitation: the human declines, so the command does not run.
func TestApprovalDeclinedViaElicitation(t *testing.T) {
	t.Parallel()
	decline := func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approve": false}}, nil
	}
	sess, auditLog := approvalSession(t, true, decline)
	res := callRestart(t, sess)
	if !res.IsError || !strings.Contains(k8sToolText(t, res), "declined") {
		t.Fatalf("want declined error; got IsError=%v text=%q", res.IsError, k8sToolText(t, res))
	}
	// #280: the decline must be audited (was silently dropped before), and no
	// command must have executed.
	e, ok := auditContains(t, auditLog, "approval_declined")
	if !ok {
		t.Fatal("expected an approval_declined audit entry after the human declined")
	}
	if e.Command != "systemctl restart nginx" || e.PolicyRule == "" {
		t.Errorf("approval_declined entry = %+v, want the declined command and its rule", e)
	}
	if _, executed := auditContains(t, auditLog, "executed"); executed {
		t.Error("a declined command must not produce an executed audit entry")
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
