// Lab MCP client: launches mcp-broker over stdio and exercises a complete
// scenario (one-shot, exec session with connection reuse, stateful shell
// session). For verification only; not part of the product.
//
// Usage: mcpclient <broker-bin> <config> <target-host>
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	brokerBin, cfg, target := os.Args[1], os.Args[2], os.Args[3]

	ctx := context.Background()
	client := mcp.NewClient(&mcp.Implementation{Name: "lab-client", Version: "0"}, nil)
	cmd := exec.Command(brokerBin, "-config", cfg)
	cmd.Stderr = os.Stderr
	sess, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer sess.Close()

	tools, _ := sess.ListTools(ctx, nil)
	fmt.Print("TOOLS:")
	for _, t := range tools.Tools {
		fmt.Printf(" %s", t.Name)
	}
	fmt.Println()

	call := func(name string, args map[string]any) *mcp.CallToolResult {
		r, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if err != nil {
			log.Fatalf("%s: %v", name, err)
		}
		return r
	}
	text := func(r *mcp.CallToolResult) string {
		for _, c := range r.Content {
			if tc, ok := c.(*mcp.TextContent); ok {
				return tc.Text
			}
		}
		return ""
	}

	// LAB_SUDO=1 runs only the elevation scenario (run_sudo_lab.sh) and exits.
	if os.Getenv("LAB_SUDO") == "1" {
		runSudoScenario(call, text, target)
		return
	}

	fmt.Println("\n## 1. ssh_execute one-shot (via bastion):")
	r := call("ssh_execute", map[string]any{"server": target, "command": "hostname; echo OK_ONESHOT"})
	fmt.Printf("isError=%v\n%s\n", r.IsError, text(r))

	fmt.Println("\n## 2. exec session: two commands reuse the connection:")
	r = call("ssh_session_open", map[string]any{"server": target, "mode": "exec"})
	sid := r.StructuredContent.(map[string]any)["session_id"].(string)
	fmt.Printf("open -> %s\n", text(r))
	fmt.Printf("exec1 -> %s\n", text(call("ssh_session_exec", map[string]any{"session_id": sid, "command": "echo A"})))
	fmt.Printf("exec2 -> %s\n", text(call("ssh_session_exec", map[string]any{"session_id": sid, "command": "echo B"})))
	call("ssh_session_close", map[string]any{"session_id": sid})

	fmt.Println("\n## 3. shell session: state persists (cd -> pwd):")
	r = call("ssh_session_open", map[string]any{"server": target, "mode": "shell"})
	sid = r.StructuredContent.(map[string]any)["session_id"].(string)
	fmt.Printf("open -> %s\n", text(r))
	fmt.Printf("cd /tmp -> %s\n", text(call("ssh_session_exec", map[string]any{"session_id": sid, "command": "cd /tmp"})))
	fmt.Printf("pwd -> %s\n", text(call("ssh_session_exec", map[string]any{"session_id": sid, "command": "pwd"})))
	call("ssh_session_close", map[string]any{"session_id": sid})

	fmt.Println("\n## 4. server load:")
	r = call("ssh_execute", map[string]any{"server": target, "command": "uptime && echo '---' && cat /proc/loadavg && echo '---' && nproc && echo '---' && free -h && echo '---' && top -bn1 | head -15"})
	fmt.Printf("%s\n", text(r))

	// 5. (optional) host that the signer does NOT authorise → must fail.
	if len(os.Args) >= 5 {
		denied := os.Args[4]
		fmt.Printf("\n## 5. host denied by policy (%s):\n", denied)
		r = call("ssh_execute", map[string]any{"server": denied, "command": "id"})
		fmt.Printf("isError=%v\n%s\n", r.IsError, text(r))
	}
}

// runSudoScenario exercises the elevation path end to end: a one-shot
// ssh_execute(sudo=true) and a pty session opened with sudo=true. Each asserts
// the command ran (the marker is echoed) and is non-error; run_sudo_lab.sh
// additionally checks that the host's `sudo` was actually invoked (shim log) and
// that the audit trail records the elevation label.
func runSudoScenario(
	call func(string, map[string]any) *mcp.CallToolResult,
	text func(*mcp.CallToolResult) string,
	target string,
) {
	fmt.Println("## sudo one-shot: ssh_execute(sudo=true)")
	r := call("ssh_execute", map[string]any{"server": target, "command": "id -un; echo ONESHOT_SUDO_OK", "sudo": true})
	fmt.Printf("isError=%v\n%s\n", r.IsError, text(r))
	if r.IsError || !strings.Contains(text(r), "ONESHOT_SUDO_OK") {
		log.Fatalf("sudo one-shot must run the command; got isError=%v %q", r.IsError, text(r))
	}

	fmt.Println("\n## pty session with elevation: ssh_session_open(mode=pty, sudo=true)")
	r = call("ssh_session_open", map[string]any{"server": target, "mode": "pty", "sudo": true})
	if r.IsError {
		log.Fatalf("pty+sudo session open must succeed: %s", text(r))
	}
	sid := r.StructuredContent.(map[string]any)["session_id"].(string)
	fmt.Printf("open -> %s\n", text(r))
	out := text(call("ssh_session_exec", map[string]any{"session_id": sid, "command": "echo PTY_SUDO_OK"}))
	fmt.Printf("pty exec -> %s\n", out)
	call("ssh_session_close", map[string]any{"session_id": sid})
	if !strings.Contains(out, "PTY_SUDO_OK") {
		log.Fatalf("pty+sudo exec must run the command; got %q", out)
	}
	fmt.Println("\nSUDO_SCENARIO_OK")
}
