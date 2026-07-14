package initcmd

import (
	"fmt"
	"os"
	"os/exec"
)

// mcpAddArgs builds the `claude mcp add` argument vector that registers the stdio
// MCP server (`infrabroker serve-mcp -config <config>`) with Claude Code. Split
// out for testing.
func mcpAddArgs(binary, config string) []string {
	return []string{"mcp", "add", "infrabroker", "--", binary, "serve-mcp", "-config", config}
}

// registerMCP runs `claude mcp add …`, letting the Claude CLI own the ~/.claude.json
// merge. Best-effort: it returns an error (e.g. the CLI is not installed) that the
// caller turns into a printed fallback rather than failing init.
func registerMCP(binary, config string) error {
	if _, err := exec.LookPath("claude"); err != nil {
		return fmt.Errorf("the `claude` CLI is not on PATH")
	}
	cmd := exec.Command("claude", mcpAddArgs(binary, config)...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}
