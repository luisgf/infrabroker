// Command mcp-broker expone el broker como servidor MCP sobre stdio. El modelo
// invoca la herramienta ssh_execute(server, command) y recibe solo la salida:
// por cada llamada se firma un certificado SSH efímero y acotado, se ejecuta el
// comando y se audita. El modelo nunca ve clave ni certificado.
//
// Lanzar desde el cliente MCP, p. ej. en ~/.claude.json:
//
//	"ssh-broker": { "type": "stdio", "command": "/ruta/mcp-broker",
//	                "args": ["-config", "/ruta/config.json"] }
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/luisgf/ssh-broker/internal/broker"
)

// caller identifica el origen en la auditoría. Sobre stdio el llamante es el
// proceso cliente local que lanzó el broker (no hay mTLS); el aislamiento lo da
// que el proceso lo arranca el propio usuario/cliente MCP.
const caller = "mcp-stdio"

type executeInput struct {
	Server     string `json:"server"      jsonschema:"nombre lógico del host destino (ver ssh_list_servers)"`
	Command    string `json:"command"     jsonschema:"comando a ejecutar en el host"`
	TTLSeconds int    `json:"ttl_seconds,omitempty" jsonschema:"validez del certificado efímero en segundos (opcional)"`
	// Elevación NOPASSWD: el host debe tener allow_sudo=true en su política.
	Sudo     bool   `json:"sudo,omitempty"      jsonschema:"si true ejecuta el comando con sudo -n (NOPASSWD). El host debe tener allow_sudo=true."`
	SudoUser string `json:"sudo_user,omitempty" jsonschema:"usuario destino del sudo (vacío = root). Debe estar en allowed_sudo_users de la política."`
	// PTY: solicita un pseudo-terminal. El host debe tener allow_pty=true.
	PTY bool `json:"pty,omitempty" jsonschema:"si true solicita un PTY para el comando. Stdout y stderr se mezclan. El host debe tener allow_pty=true."`
}

type executeOutput struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exit_code"`
	Serial   uint64 `json:"serial"`
}

type listInput struct{}

type listOutput struct {
	Servers []string `json:"servers"`
}

type sessionOpenInput struct {
	Server     string `json:"server"      jsonschema:"nombre lógico del host destino"`
	Mode       string `json:"mode,omitempty" jsonschema:"exec (por defecto, sin estado) | shell (sh con estado: cd/env persisten) | pty (shell con PTY: para programas que requieren TTY)"`
	TTLSeconds int    `json:"ttl_seconds,omitempty" jsonschema:"validez del certificado de la conexión en segundos (opcional)"`
	// Elevación NOPASSWD.
	Sudo     bool   `json:"sudo,omitempty"      jsonschema:"si true arranca la sesión con elevación sudo -n (NOPASSWD). En shell/pty eleva el proceso shell completo; en exec antepone sudo a cada comando."`
	SudoUser string `json:"sudo_user,omitempty" jsonschema:"usuario destino del sudo (vacío = root)."`
}

type sessionExecInput struct {
	SessionID string `json:"session_id" jsonschema:"id devuelto por ssh_session_open"`
	Command   string `json:"command"    jsonschema:"comando a ejecutar en la sesión"`
}

type sessionCloseInput struct {
	SessionID string `json:"session_id" jsonschema:"id de la sesión a cerrar"`
}

type okOutput struct {
	OK bool `json:"ok"`
}

func main() {
	cfgPath := flag.String("config", "config.json", "ruta al fichero de configuración JSON")
	flag.Parse()

	cfg, err := broker.LoadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	eng, err := broker.NewEngine(cfg)
	if err != nil {
		log.Fatalf("inicializar broker: %v", err)
	}
	defer eng.Close()

	srv := mcp.NewServer(&mcp.Implementation{
		Name:    "ssh-broker",
		Title:   "SSH Broker (CA efímera)",
		Version: "0.2.0",
	}, nil)

	mcp.AddTool(srv, &mcp.Tool{
		Name: "ssh_execute",
		Description: "Ejecuta un comando en un host Linux configurado vía SSH usando una " +
			"credencial efímera de un solo uso (certificado SSH de corta duración, " +
			"acotado a ese host). Devuelve stdout/stderr/exit_code. No expone credenciales. " +
			"Soporta elevación de privilegio (sudo NOPASSWD, requiere allow_sudo=true en la " +
			"política del host) y PTY (requiere allow_pty=true).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in executeInput) (*mcp.CallToolResult, executeOutput, error) {
		opts := broker.ExecOptions{Sudo: in.Sudo, SudoUser: in.SudoUser, PTY: in.PTY}
		res, err := eng.Execute(caller, in.Server, in.Command, in.TTLSeconds, opts)
		if err != nil {
			return &mcp.CallToolResult{
				IsError: true,
				Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}},
			}, executeOutput{}, nil
		}
		out := executeOutput{Stdout: res.Stdout, Stderr: res.Stderr, ExitCode: res.ExitCode, Serial: res.Serial}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: renderResult(out)}}}, out, nil
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "ssh_list_servers",
		Description: "Lista los nombres lógicos de los hosts configurados en el broker.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ listInput) (*mcp.CallToolResult, listOutput, error) {
		names := eng.Servers()
		out := listOutput{Servers: names}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: strings.Join(names, "\n")}}}, out, nil
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name: "ssh_session_open",
		Description: "Abre una sesión SSH persistente a un host (reutiliza la conexión entre " +
			"comandos). Modos: exec (por defecto, cada comando aislado), shell (sh con estado: " +
			"cd/variables persisten), pty (shell con PTY para programas que requieren TTY). " +
			"Soporta elevación sudo NOPASSWD (require allow_sudo=true). " +
			"Devuelve session_id para ssh_session_exec. Usa una credencial efímera por conexión.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in sessionOpenInput) (*mcp.CallToolResult, sessionOpenOutput, error) {
		opts := broker.ExecOptions{Sudo: in.Sudo, SudoUser: in.SudoUser}
		r, err := eng.OpenSession(caller, in.Server, in.Mode, in.TTLSeconds, opts)
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}, sessionOpenOutput{}, nil
		}
		out := sessionOpenOutput{SessionID: r.SessionID, Serial: r.Serial}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("session_id=%s serial=%d", r.SessionID, r.Serial)}}}, out, nil
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "ssh_session_exec",
		Description: "Ejecuta un comando en una sesión abierta con ssh_session_open. Devuelve stdout/stderr/exit_code.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in sessionExecInput) (*mcp.CallToolResult, executeOutput, error) {
		res, err := eng.SessionExec(caller, in.SessionID, in.Command)
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}, executeOutput{}, nil
		}
		out := executeOutput{Stdout: res.Stdout, Stderr: res.Stderr, ExitCode: res.ExitCode, Serial: res.Serial}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: renderResult(out)}}}, out, nil
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "ssh_session_close",
		Description: "Cierra una sesión SSH persistente y libera la conexión.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in sessionCloseInput) (*mcp.CallToolResult, okOutput, error) {
		if err := eng.CloseSession(caller, in.SessionID); err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}, okOutput{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "cerrada"}}}, okOutput{OK: true}, nil
	})

	log.Printf("mcp-broker (stdio) listo; %d hosts configurados", len(eng.Servers()))
	if err := srv.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatalf("servidor MCP: %v", err)
	}
}

// sessionOpenOutput debe estar definido aquí para que mcp.AddTool lo use como tipo de retorno.
type sessionOpenOutput struct {
	SessionID string `json:"session_id"`
	Serial    uint64 `json:"serial"`
}

func renderResult(o executeOutput) string {
	var b strings.Builder
	if o.Stdout != "" {
		b.WriteString(o.Stdout)
	}
	if o.Stderr != "" {
		fmt.Fprintf(&b, "\n[stderr]\n%s", o.Stderr)
	}
	fmt.Fprintf(&b, "\n[exit=%d serial=%d]", o.ExitCode, o.Serial)
	return b.String()
}
