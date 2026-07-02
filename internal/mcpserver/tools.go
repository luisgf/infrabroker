// Package mcpserver registers the broker's MCP tools on a *mcp.Server, so
// that both the stdio frontend (cmd/mcp-broker) and the HTTP+OAuth frontend
// (cmd/mcp-broker-http) share exactly the same tool surface and the same
// logic. The only difference between frontends is how the caller identity is
// obtained (callerFn), injected by dependency.
package mcpserver

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/luisgf/ssh-broker/internal/broker"
	"github.com/luisgf/ssh-broker/internal/signer"
)

// maxInputLen is the maximum size of any MCP text input field.
// L4: prevents malformed inputs from reaching the engine without a prior filter.
const maxInputLen = 64 * 1024 // 64 KiB

// validateInput checks that all fields do not exceed the length limit and do
// not contain null bytes (which could cause unexpected behaviour in the shell
// or in logs).
func validateInput(fields map[string]string) error {
	for name, val := range fields {
		if len(val) > maxInputLen {
			return fmt.Errorf("field %q exceeds the limit of %d bytes", name, maxInputLen)
		}
		if strings.ContainsRune(val, 0) {
			return fmt.Errorf("field %q contains null bytes", name)
		}
	}
	return nil
}

// CallerFunc derives the caller identity from the request context. In stdio it
// returns a fixed identity; in HTTP it extracts it from the validated token.
type CallerFunc func(context.Context) broker.Caller

type executeInput struct {
	Server     string `json:"server"                jsonschema:"logical name of the target host (see ssh_list_servers)"`
	Command    string `json:"command"               jsonschema:"command to execute on the host"`
	TTLSeconds int    `json:"ttl_seconds,omitempty" jsonschema:"ephemeral certificate validity in seconds; omit to use the maximum allowed by the host policy"`
	Sudo       bool   `json:"sudo,omitempty"        jsonschema:"if true, execute with sudo -n (NOPASSWD). Requires allow_sudo=true in ssh_list_servers. If allow_sudo=false DO NOT retry: inform the user that the host does not allow elevation."`
	SudoUser   string `json:"sudo_user,omitempty"   jsonschema:"target user for sudo (empty = root). Must be in the host's allowed_sudo_users list."`
	PTY        bool   `json:"pty,omitempty"         jsonschema:"if true, request a pseudo-terminal (stdout and stderr are merged). Requires allow_pty=true in ssh_list_servers. Use only for commands that need a TTY. If allow_pty=false DO NOT retry."`
	DryRun     bool   `json:"dry_run,omitempty"     jsonschema:"if true, SIMULATE: check whether the command would be allowed by the host policy (allow/deny and whether it requires approval) WITHOUT executing it. Does not connect to the host or produce stdout. Useful to preview before executing."`
}

type executeOutput struct {
	Stdout   string   `json:"stdout"             jsonschema:"standard output of the remote command"`
	Stderr   string   `json:"stderr"             jsonschema:"error output of the remote command (empty when pty=true, since stdout and stderr are merged)"`
	ExitCode int      `json:"exit_code"          jsonschema:"exit code of the remote command: 0=success, non-zero=command failure (NOT a tool error)"`
	Serial   uint64   `json:"serial"             jsonschema:"audit identifier; ignore when reasoning about the result"`
	Warnings []string `json:"warnings,omitempty" jsonschema:"advisory warnings; command_policy audit-mode warnings mean the command was allowed but would have been blocked or approval-gated in enforce mode"`
}

type listInput struct{}

type serverEntry struct {
	Name              string `json:"name"`
	AllowSudo         bool   `json:"allow_sudo"`
	AllowPTY          bool   `json:"allow_pty"`
	AllowFileTransfer bool   `json:"allow_file_transfer"`
	Jump              string `json:"jump,omitempty"`
}

type listOutput struct {
	Servers []serverEntry `json:"servers"`
}

type sessionOpenInput struct {
	Server     string `json:"server"                jsonschema:"logical name of the target host (see ssh_list_servers)"`
	Mode       string `json:"mode,omitempty"        jsonschema:"exec (default): isolated commands with no shared state. shell: persistent sh, cd and environment variables survive across ssh_session_exec calls. pty: shell with pseudo-terminal for interactive programs (editors, less, etc.); requires allow_pty=true. If allow_pty=false DO NOT use pty."`
	TTLSeconds int    `json:"ttl_seconds,omitempty" jsonschema:"connection certificate validity in seconds; omit to use the maximum allowed by the host policy"`
	Sudo       bool   `json:"sudo,omitempty"        jsonschema:"if true, start with sudo -n elevation (NOPASSWD). In mode=shell/pty elevates the whole shell process. In mode=exec prepends sudo to each individual command. Requires allow_sudo=true in ssh_list_servers. If allow_sudo=false DO NOT retry."`
	SudoUser   string `json:"sudo_user,omitempty"   jsonschema:"target user for sudo (empty = root). Must be in the host's allowed_sudo_users list."`
}

type sessionExecInput struct {
	SessionID string `json:"session_id" jsonschema:"id returned by ssh_session_open"`
	Command   string `json:"command"    jsonschema:"command to execute in the session"`
}

type sessionCloseInput struct {
	SessionID string `json:"session_id" jsonschema:"id of the session to close"`
}

type okOutput struct {
	OK bool `json:"ok"`
}

type putFileInput struct {
	Server        string `json:"server"                   jsonschema:"logical name of the target host (see ssh_list_servers)"`
	Path          string `json:"path"                     jsonschema:"absolute destination path on the host; the file is created or overwritten"`
	Content       string `json:"content"                  jsonschema:"file content. Text as-is, or base64 with content_base64=true for binary data."`
	ContentBase64 bool   `json:"content_base64,omitempty" jsonschema:"if true, content is base64-encoded and is decoded before writing (required for binary files)"`
	Mode          string `json:"mode,omitempty"           jsonschema:"optional octal permissions to chmod after writing, e.g. 0644 or 0755"`
	TTLSeconds    int    `json:"ttl_seconds,omitempty"    jsonschema:"ephemeral certificate validity in seconds; omit to use the maximum allowed by the host policy"`
}

type putFileOutput struct {
	BytesWritten int      `json:"bytes_written"      jsonschema:"number of bytes written to the remote file"`
	SHA256       string   `json:"sha256"             jsonschema:"hex sha256 of the written content, recorded in the audit log"`
	Serial       uint64   `json:"serial"             jsonschema:"audit identifier; ignore when reasoning about the result"`
	Warnings     []string `json:"warnings,omitempty" jsonschema:"advisory command-policy warnings"`
}

type getFileInput struct {
	Server     string `json:"server"                jsonschema:"logical name of the target host (see ssh_list_servers)"`
	Path       string `json:"path"                  jsonschema:"absolute path of the file to read on the host"`
	MaxBytes   int    `json:"max_bytes,omitempty"   jsonschema:"read at most this many bytes; a larger file is an error, not a truncation. Omit for the broker's configured limit."`
	TTLSeconds int    `json:"ttl_seconds,omitempty" jsonschema:"ephemeral certificate validity in seconds; omit to use the maximum allowed by the host policy"`
}

type getFileOutput struct {
	Content  string   `json:"content"            jsonschema:"file content: text as-is, or base64 when base64=true (binary file)"`
	Base64   bool     `json:"base64"             jsonschema:"true when content is base64-encoded because the file is not valid UTF-8 text"`
	Size     int      `json:"size"               jsonschema:"file size in bytes (decoded)"`
	SHA256   string   `json:"sha256"             jsonschema:"hex sha256 of the file content, recorded in the audit log"`
	Serial   uint64   `json:"serial"             jsonschema:"audit identifier; ignore when reasoning about the result"`
	Warnings []string `json:"warnings,omitempty" jsonschema:"advisory command-policy warnings"`
}

type sessionOpenOutput struct {
	SessionID string `json:"session_id"`
	Serial    uint64 `json:"serial"`
}

// Register adds the 7 broker tools to the MCP server. callerFn provides the
// caller identity for each invocation (audit and signer RBAC).
func Register(srv *mcp.Server, eng *broker.Engine, callerFn CallerFunc) {
	mcp.AddTool(srv, &mcp.Tool{
		Name: "ssh_execute",
		Description: "Execute a single command on a Linux host via SSH with an ephemeral credential. " +
			"Prefer this tool over ssh_session_open when you only need to run one command or independent commands. " +
			"Returns stdout, stderr and exit_code. " +
			"exit_code != 0 means remote command failure, NOT a tool error; treat it like a process that exits with an error. " +
			"BEFORE calling: use ssh_list_servers to learn the host capabilities. " +
			"sudo=true ONLY if allow_sudo=true; if allow_sudo=false, DO NOT retry with sudo and inform the user. " +
			"pty=true ONLY if allow_pty=true and the command needs a TTY (with pty, stdout and stderr are merged). " +
			"ttl_seconds is optional; omit to use the maximum allowed by the host policy.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in executeInput) (*mcp.CallToolResult, executeOutput, error) {
		if err := validateInput(map[string]string{"server": in.Server, "command": in.Command, "sudo_user": in.SudoUser}); err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}, executeOutput{}, nil
		}
		opts := broker.ExecOptions{Sudo: in.Sudo, SudoUser: in.SudoUser, PTY: in.PTY, DryRun: in.DryRun}
		res, err := eng.Execute(ctx, callerFn(ctx), in.Server, in.Command, in.TTLSeconds, opts)
		if err != nil {
			return &mcp.CallToolResult{
				IsError: true,
				Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}},
			}, executeOutput{}, nil
		}
		// Dry-run: return the policy decision instead of executed output.
		if res.DryRun != nil {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: renderDecision(res.DryRun)}}}, executeOutput{}, nil
		}
		out := executeOutput{Stdout: res.Stdout, Stderr: res.Stderr, ExitCode: res.ExitCode, Serial: res.Serial, Warnings: res.Warnings}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: renderResult(out)}}}, out, nil
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name: "ssh_list_servers",
		Description: "List the hosts accessible to the caller with their capabilities " +
			"(hosts outside the user's RBAC groups are not listed). " +
			"ALWAYS call before ssh_execute or ssh_session_open. " +
			"Fields per host: " +
			"allow_sudo=true → the host accepts NOPASSWD sudo elevation (sudo=true may be used); " +
			"allow_sudo=false → DO NOT attempt sudo, the signer will reject it. " +
			"allow_pty=true → the host accepts PTY (pty=true or mode=pty may be used); " +
			"allow_pty=false → DO NOT attempt PTY. " +
			"allow_file_transfer=true → ssh_put_file and ssh_get_file may be used; " +
			"allow_file_transfer=false → DO NOT attempt file transfers, the signer will reject them. " +
			"jump → name of the bastion through which the host is reached (informational).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ listInput) (*mcp.CallToolResult, listOutput, error) {
		infos := eng.ServerInfos(callerFn(ctx))
		entries := make([]serverEntry, len(infos))
		var sb strings.Builder
		for i, s := range infos {
			entries[i] = serverEntry{Name: s.Name, AllowSudo: s.AllowSudo, AllowPTY: s.AllowPTY, AllowFileTransfer: s.AllowFileTransfer, Jump: s.Jump}
			fmt.Fprintf(&sb, "%s (sudo=%v pty=%v file_transfer=%v", s.Name, s.AllowSudo, s.AllowPTY, s.AllowFileTransfer)
			if s.Jump != "" {
				fmt.Fprintf(&sb, " via=%s", s.Jump)
			}
			sb.WriteString(")\n")
		}
		out := listOutput{Servers: entries}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: sb.String()}}}, out, nil
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name: "ssh_session_open",
		Description: "Open a persistent SSH session that reuses the connection across commands. " +
			"Use when you need multiple commands with shared state (e.g. cd to a directory and then operate in it) or interactive programs. " +
			"For isolated commands prefer ssh_execute (simpler, stronger isolation guarantee). " +
			"Available modes: exec (default, independent commands), shell (stateful sh: cd and variables persist), pty (shell with TTY for interactive programs). " +
			"sudo=true ONLY if allow_sudo=true (see ssh_list_servers); if allow_sudo=false DO NOT retry. " +
			"mode=pty ONLY if allow_pty=true. " +
			"Every ssh_session_exec is preflighted against the current signer policy, so policy reloads revalidate target and bastion access, end-user groups, sudo, sudo_user, PTY, and the host's physical route for already-open sessions. " +
			"On command-policy hosts, mode=exec is allowed; mode=shell and mode=pty are rejected. " +
			"Returns session_id for use with ssh_session_exec. " +
			"IMPORTANT: always close the session with ssh_session_close when done; an open session holds an SSH connection and is otherwise closed only after an idle or maximum-lifetime timeout (it is NOT bound to the certificate TTL).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in sessionOpenInput) (*mcp.CallToolResult, sessionOpenOutput, error) {
		if err := validateInput(map[string]string{"server": in.Server, "mode": in.Mode, "sudo_user": in.SudoUser}); err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}, sessionOpenOutput{}, nil
		}
		opts := broker.ExecOptions{Sudo: in.Sudo, SudoUser: in.SudoUser}
		r, err := eng.OpenSession(ctx, callerFn(ctx), in.Server, in.Mode, in.TTLSeconds, opts)
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}, sessionOpenOutput{}, nil
		}
		out := sessionOpenOutput{SessionID: r.SessionID, Serial: r.Serial}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("session_id=%s serial=%d", r.SessionID, r.Serial)}}}, out, nil
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name: "ssh_session_exec",
		Description: "Execute a command in a session opened with ssh_session_open. " +
			"Returns stdout, stderr and exit_code. " +
			"exit_code != 0 means remote command failure, NOT a tool error. " +
			"The command is preflighted against the current signer policy before execution; target and bastion access, end-user groups, sudo, sudo_user, PTY, and the host's physical route are revalidated, and audit-mode policy warnings are returned in warnings. " +
			"If a policy is enabled after a shell/pty session was opened, later commands in that session are rejected. " +
			"Session state (current directory, environment variables) persists across calls when mode=shell or mode=pty.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in sessionExecInput) (*mcp.CallToolResult, executeOutput, error) {
		if err := validateInput(map[string]string{"session_id": in.SessionID, "command": in.Command}); err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}, executeOutput{}, nil
		}
		res, err := eng.SessionExec(ctx, callerFn(ctx), in.SessionID, in.Command)
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}, executeOutput{}, nil
		}
		out := executeOutput{Stdout: res.Stdout, Stderr: res.Stderr, ExitCode: res.ExitCode, Serial: res.Serial, Warnings: res.Warnings}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: renderResult(out)}}}, out, nil
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name: "ssh_session_close",
		Description: "Close a persistent SSH session and release the connection. " +
			"Always call when done working with a session; an unclosed session keeps its SSH connection until it is reaped by the idle or maximum-lifetime timeout (not by the certificate TTL).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in sessionCloseInput) (*mcp.CallToolResult, okOutput, error) {
		if err := validateInput(map[string]string{"session_id": in.SessionID}); err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}, okOutput{}, nil
		}
		if err := eng.CloseSession(callerFn(ctx), in.SessionID); err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}, okOutput{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "closed"}}}, okOutput{OK: true}, nil
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name: "ssh_put_file",
		Description: "Write a file on a Linux host via SSH with an ephemeral credential. " +
			"Creates or OVERWRITES the destination file with the given content. " +
			"Use content_base64=true for binary data (the content field is decoded before writing). " +
			"REQUIRES allow_file_transfer=true on the host (see ssh_list_servers); if false DO NOT retry, the signer will reject it. " +
			"The write runs as the host's configured SSH user (no sudo); the destination must be writable by that user. " +
			"On hosts with a command policy the transfer command (cat > path) must also be allowed by the policy. " +
			"Content is limited by the broker's file_transfer_max_bytes (default 512 KiB). " +
			"The content's sha256 is recorded in the audit log.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in putFileInput) (*mcp.CallToolResult, putFileOutput, error) {
		if err := validateInput(map[string]string{"server": in.Server, "path": in.Path, "mode": in.Mode}); err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}, putFileOutput{}, nil
		}
		content := []byte(in.Content)
		if in.ContentBase64 {
			decoded, err := base64.StdEncoding.DecodeString(in.Content)
			if err != nil {
				return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "invalid base64 content: " + err.Error()}}}, putFileOutput{}, nil
			}
			content = decoded
		}
		res, err := eng.PutFile(ctx, callerFn(ctx), in.Server, in.Path, content, in.Mode, in.TTLSeconds)
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}, putFileOutput{}, nil
		}
		out := putFileOutput{BytesWritten: res.Size, SHA256: res.SHA256, Serial: res.Serial, Warnings: res.Warnings}
		text := fmt.Sprintf("wrote %d bytes to %s (sha256=%s) [serial=%d]", res.Size, in.Path, res.SHA256, res.Serial)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, out, nil
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name: "ssh_get_file",
		Description: "Read a file from a Linux host via SSH with an ephemeral credential. " +
			"Returns the content as text, or base64 (base64=true in the result) when the file is not valid UTF-8. " +
			"REQUIRES allow_file_transfer=true on the host (see ssh_list_servers); if false DO NOT retry, the signer will reject it. " +
			"The read runs as the host's configured SSH user (no sudo); the file must be readable by that user. " +
			"A file larger than max_bytes (default: the broker's file_transfer_max_bytes, 512 KiB) is an ERROR, not a truncation. " +
			"The content's sha256 is recorded in the audit log.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in getFileInput) (*mcp.CallToolResult, getFileOutput, error) {
		if err := validateInput(map[string]string{"server": in.Server, "path": in.Path}); err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}, getFileOutput{}, nil
		}
		res, err := eng.GetFile(ctx, callerFn(ctx), in.Server, in.Path, in.MaxBytes, in.TTLSeconds)
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}, getFileOutput{}, nil
		}
		out := getFileOutput{Size: res.Size, SHA256: res.SHA256, Serial: res.Serial, Warnings: res.Warnings}
		var text string
		if utf8.Valid(res.Content) && !bytes.ContainsRune(res.Content, 0) {
			out.Content = string(res.Content)
			text = out.Content + fmt.Sprintf("\n[%d bytes sha256=%s serial=%d]", res.Size, res.SHA256, res.Serial)
		} else {
			out.Content = base64.StdEncoding.EncodeToString(res.Content)
			out.Base64 = true
			text = fmt.Sprintf("[binary content: %d bytes, returned base64-encoded; sha256=%s serial=%d]", res.Size, res.SHA256, res.Serial)
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, out, nil
	})
}

// renderDecision formats the result of a dry-run (policy simulation).
func renderDecision(d *signer.DecisionInfo) string {
	var b strings.Builder
	if d.Allowed {
		b.WriteString("[dry-run] ALLOWED")
		if d.RequireApproval {
			b.WriteString(" (requires human approval before executing)")
		}
	} else {
		b.WriteString("[dry-run] DENIED")
		if d.Reason != "" {
			fmt.Fprintf(&b, ": %s", d.Reason)
		}
	}
	if d.MatchedRule != "" {
		fmt.Fprintf(&b, "\nrule: %s", d.MatchedRule)
	}
	if d.Warning != "" {
		fmt.Fprintf(&b, "\nwarning: %s", d.Warning)
	}
	if d.ForceCommand != "" {
		fmt.Fprintf(&b, "\nforce-command: %s", d.ForceCommand)
	}
	if d.TTLSeconds > 0 {
		fmt.Fprintf(&b, "\nttl: %ds", d.TTLSeconds)
	}
	return b.String()
}

func renderResult(o executeOutput) string {
	var b strings.Builder
	if o.Stdout != "" {
		b.WriteString(o.Stdout)
	}
	if o.Stderr != "" {
		fmt.Fprintf(&b, "\n[stderr]\n%s", o.Stderr)
	}
	for _, warning := range o.Warnings {
		fmt.Fprintf(&b, "\n[warning] %s", warning)
	}
	fmt.Fprintf(&b, "\n[exit=%d serial=%d]", o.ExitCode, o.Serial)
	return b.String()
}
