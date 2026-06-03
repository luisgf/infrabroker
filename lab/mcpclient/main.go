// Cliente MCP de laboratorio: lanza mcp-broker por stdio y ejecuta un escenario
// completo (one-shot, sesión exec con reuso, sesión shell con estado). Solo para
// verificación; no forma parte del producto.
//
// Uso: mcpclient <broker-bin> <config> <target-host>
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"

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

	fmt.Println("\n## 1. ssh_execute one-shot (vía bastión):")
	r := call("ssh_execute", map[string]any{"server": target, "command": "hostname; echo OK_ONESHOT"})
	fmt.Printf("isError=%v\n%s\n", r.IsError, text(r))

	fmt.Println("\n## 2. sesión exec: dos comandos reutilizan la conexión:")
	r = call("ssh_session_open", map[string]any{"server": target, "mode": "exec"})
	sid := r.StructuredContent.(map[string]any)["session_id"].(string)
	fmt.Printf("open -> %s\n", text(r))
	fmt.Printf("exec1 -> %s\n", text(call("ssh_session_exec", map[string]any{"session_id": sid, "command": "echo A"})))
	fmt.Printf("exec2 -> %s\n", text(call("ssh_session_exec", map[string]any{"session_id": sid, "command": "echo B"})))
	call("ssh_session_close", map[string]any{"session_id": sid})

	fmt.Println("\n## 3. sesión shell: estado persiste (cd -> pwd):")
	r = call("ssh_session_open", map[string]any{"server": target, "mode": "shell"})
	sid = r.StructuredContent.(map[string]any)["session_id"].(string)
	fmt.Printf("open -> %s\n", text(r))
	fmt.Printf("cd /tmp -> %s\n", text(call("ssh_session_exec", map[string]any{"session_id": sid, "command": "cd /tmp"})))
	fmt.Printf("pwd -> %s\n", text(call("ssh_session_exec", map[string]any{"session_id": sid, "command": "pwd"})))
	call("ssh_session_close", map[string]any{"session_id": sid})

	fmt.Println("\n## 4. carga del servidor:")
	r = call("ssh_execute", map[string]any{"server": target, "command": "uptime && echo '---' && cat /proc/loadavg && echo '---' && nproc && echo '---' && free -h && echo '---' && top -bn1 | head -15"})
	fmt.Printf("%s\n", text(r))

	// 5. (opcional) host que el firmante NO autoriza → debe fallar en el servicio.
	if len(os.Args) >= 5 {
		denied := os.Args[4]
		fmt.Printf("\n## 5. host denegado por politica (%s):\n", denied)
		r = call("ssh_execute", map[string]any{"server": denied, "command": "id"})
		fmt.Printf("isError=%v\n%s\n", r.IsError, text(r))
	}
}
