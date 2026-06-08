// Package mcpserver registra las herramientas MCP del broker sobre un *mcp.Server,
// de modo que tanto el frontend stdio (cmd/mcp-broker) como el frontend HTTP+OAuth
// (cmd/mcp-broker-http) compartan exactamente la misma superficie de tools y la
// misma lógica. La única diferencia entre frontends es cómo se obtiene la identidad
// del llamante (callerFn), inyectada por dependencia.
package mcpserver

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/luisgf/ssh-broker/internal/broker"
	"github.com/luisgf/ssh-broker/internal/signer"
)

// maxInputLen es el tamaño máximo de cualquier campo de texto de entrada MCP.
// L4: evita que inputs malformados lleguen al engine sin un filtro previo.
const maxInputLen = 64 * 1024 // 64 KiB

// validateInput comprueba que todos los campos no superen el límite de longitud
// y no contengan bytes nulos (que podrían causar comportamientos inesperados
// en el shell o en los logs).
func validateInput(fields map[string]string) error {
	for name, val := range fields {
		if len(val) > maxInputLen {
			return fmt.Errorf("campo %q excede el límite de %d bytes", name, maxInputLen)
		}
		if strings.ContainsRune(val, 0) {
			return fmt.Errorf("campo %q contiene bytes nulos", name)
		}
	}
	return nil
}

// CallerFunc deriva la identidad del llamante a partir del contexto de la petición.
// En stdio devuelve una identidad fija; en HTTP la extrae del token validado.
type CallerFunc func(context.Context) broker.Caller

type executeInput struct {
	Server     string `json:"server"               jsonschema:"nombre lógico del host destino (ver ssh_list_servers)"`
	Command    string `json:"command"              jsonschema:"comando a ejecutar en el host"`
	TTLSeconds int    `json:"ttl_seconds,omitempty" jsonschema:"validez del certificado efímero en segundos; omitir para usar el máximo permitido por la política del host"`
	Sudo       bool   `json:"sudo,omitempty"       jsonschema:"si true ejecuta con sudo -n (NOPASSWD). Requiere allow_sudo=true en ssh_list_servers. Si allow_sudo=false NO reintentes: informa al usuario de que el host no permite elevación."`
	SudoUser   string `json:"sudo_user,omitempty"  jsonschema:"usuario destino del sudo (vacío = root). Debe estar en la lista allowed_sudo_users del host."`
	PTY        bool   `json:"pty,omitempty"        jsonschema:"si true solicita un pseudo-terminal (stdout y stderr se mezclan). Requiere allow_pty=true en ssh_list_servers. Usar solo para comandos que necesitan TTY. Si allow_pty=false NO reintentes."`
	DryRun     bool   `json:"dry_run,omitempty"    jsonschema:"si true SIMULA: comprueba si el comando sería permitido por la política del host (allow/deny y si requiere aprobación) SIN ejecutarlo. No conecta al host ni produce stdout. Útil para previsualizar antes de ejecutar."`
}

type executeOutput struct {
	Stdout   string `json:"stdout"    jsonschema:"salida estándar del comando remoto"`
	Stderr   string `json:"stderr"    jsonschema:"salida de error del comando remoto (vacío si se usó pty=true, ya que stdout y stderr se mezclan)"`
	ExitCode int    `json:"exit_code" jsonschema:"código de salida del comando remoto: 0=éxito, distinto de 0=fallo del comando (NO es un error de la tool)"`
	Serial   uint64 `json:"serial"    jsonschema:"identificador de auditoría; ignorar para razonar sobre el resultado"`
}

type listInput struct{}

type serverEntry struct {
	Name      string `json:"name"`
	AllowSudo bool   `json:"allow_sudo"`
	AllowPTY  bool   `json:"allow_pty"`
	Jump      string `json:"jump,omitempty"`
}

type listOutput struct {
	Servers []serverEntry `json:"servers"`
}

type sessionOpenInput struct {
	Server     string `json:"server"               jsonschema:"nombre lógico del host destino (ver ssh_list_servers)"`
	Mode       string `json:"mode,omitempty"       jsonschema:"exec (por defecto): comandos aislados sin estado compartido. shell: sh persistente, cd y variables de entorno sobreviven entre ssh_session_exec. pty: shell con pseudo-terminal para programas interactivos (editores, less, etc.); requiere allow_pty=true. Si allow_pty=false NO uses pty."`
	TTLSeconds int    `json:"ttl_seconds,omitempty" jsonschema:"validez del certificado de conexión en segundos; omitir para usar el máximo permitido por la política del host"`
	Sudo       bool   `json:"sudo,omitempty"       jsonschema:"si true arranca con elevación sudo -n (NOPASSWD). En mode=shell/pty eleva el proceso shell completo. En mode=exec antepone sudo a cada comando individual. Requiere allow_sudo=true en ssh_list_servers. Si allow_sudo=false NO reintentes."`
	SudoUser   string `json:"sudo_user,omitempty"  jsonschema:"usuario destino del sudo (vacío = root). Debe estar en la lista allowed_sudo_users del host."`
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

type sessionOpenOutput struct {
	SessionID string `json:"session_id"`
	Serial    uint64 `json:"serial"`
}

// Register añade las 5 tools del broker al servidor MCP. callerFn provee la
// identidad del llamante para cada invocación (auditoría y RBAC del signer).
func Register(srv *mcp.Server, eng *broker.Engine, callerFn CallerFunc) {
	mcp.AddTool(srv, &mcp.Tool{
		Name: "ssh_execute",
		Description: "Ejecuta un único comando en un host Linux vía SSH con credencial efímera. " +
			"Preferir esta tool frente a ssh_session_open cuando solo se necesita ejecutar un comando o comandos independientes entre sí. " +
			"Devuelve stdout, stderr y exit_code. " +
			"exit_code != 0 indica fallo del comando remoto, NO un error de la tool; tratar igual que un proceso que termina con error. " +
			"ANTES de llamar: usar ssh_list_servers para conocer las capacidades del host. " +
			"sudo=true SOLO si allow_sudo=true; si allow_sudo=false, NO reintentar con sudo e informar al usuario. " +
			"pty=true SOLO si allow_pty=true y el comando necesita TTY (con pty stdout y stderr se mezclan). " +
			"ttl_seconds es opcional; omitir para usar el máximo que permita la política del host.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in executeInput) (*mcp.CallToolResult, executeOutput, error) {
		if err := validateInput(map[string]string{"server": in.Server, "command": in.Command, "sudo_user": in.SudoUser}); err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}, executeOutput{}, nil
		}
		opts := broker.ExecOptions{Sudo: in.Sudo, SudoUser: in.SudoUser, PTY: in.PTY, DryRun: in.DryRun}
		res, err := eng.Execute(callerFn(ctx), in.Server, in.Command, in.TTLSeconds, opts)
		if err != nil {
			return &mcp.CallToolResult{
				IsError: true,
				Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}},
			}, executeOutput{}, nil
		}
		// Dry-run: devolver la decisión de política en lugar de salida ejecutada.
		if res.DryRun != nil {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: renderDecision(res.DryRun)}}}, executeOutput{}, nil
		}
		out := executeOutput{Stdout: res.Stdout, Stderr: res.Stderr, ExitCode: res.ExitCode, Serial: res.Serial}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: renderResult(out)}}}, out, nil
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name: "ssh_list_servers",
		Description: "Lista los hosts configurados en el broker con sus capacidades. " +
			"Llamar SIEMPRE antes de ssh_execute o ssh_session_open. " +
			"Campos por host: " +
			"allow_sudo=true → el host acepta elevación sudo NOPASSWD (se puede usar sudo=true); " +
			"allow_sudo=false → NO intentar sudo, el signer lo rechazará. " +
			"allow_pty=true → el host acepta PTY (se puede usar pty=true o mode=pty); " +
			"allow_pty=false → NO intentar PTY. " +
			"jump → nombre del bastión por el que se alcanza el host (informativo).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ listInput) (*mcp.CallToolResult, listOutput, error) {
		infos := eng.ServerInfos()
		entries := make([]serverEntry, len(infos))
		var sb strings.Builder
		for i, s := range infos {
			entries[i] = serverEntry{Name: s.Name, AllowSudo: s.AllowSudo, AllowPTY: s.AllowPTY, Jump: s.Jump}
			fmt.Fprintf(&sb, "%s (sudo=%v pty=%v", s.Name, s.AllowSudo, s.AllowPTY)
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
		Description: "Abre una sesión SSH persistente que reutiliza la conexión entre comandos. " +
			"Usar cuando se necesiten varios comandos con estado compartido (ej. cd a un directorio y luego operar en él) o programas interactivos. " +
			"Para comandos aislados preferir ssh_execute (más simple y con mayor garantía de aislamiento). " +
			"Modos disponibles: exec (por defecto, comandos independientes), shell (sh con estado: cd y variables persisten), pty (shell con TTY para programas interactivos). " +
			"sudo=true SOLO si allow_sudo=true (ver ssh_list_servers); si allow_sudo=false NO reintentar. " +
			"mode=pty SOLO si allow_pty=true. " +
			"Devuelve session_id para usar con ssh_session_exec. " +
			"IMPORTANTE: cerrar siempre la sesión con ssh_session_close al terminar; las sesiones consumen recursos y expiran por TTL.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in sessionOpenInput) (*mcp.CallToolResult, sessionOpenOutput, error) {
		if err := validateInput(map[string]string{"server": in.Server, "mode": in.Mode, "sudo_user": in.SudoUser}); err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}, sessionOpenOutput{}, nil
		}
		opts := broker.ExecOptions{Sudo: in.Sudo, SudoUser: in.SudoUser}
		r, err := eng.OpenSession(callerFn(ctx), in.Server, in.Mode, in.TTLSeconds, opts)
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}, sessionOpenOutput{}, nil
		}
		out := sessionOpenOutput{SessionID: r.SessionID, Serial: r.Serial}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("session_id=%s serial=%d", r.SessionID, r.Serial)}}}, out, nil
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name: "ssh_session_exec",
		Description: "Ejecuta un comando en una sesión abierta con ssh_session_open. " +
			"Devuelve stdout, stderr y exit_code. " +
			"exit_code != 0 indica fallo del comando remoto, NO un error de la tool. " +
			"El estado de la sesión (directorio actual, variables de entorno) persiste entre llamadas si mode=shell o mode=pty.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in sessionExecInput) (*mcp.CallToolResult, executeOutput, error) {
		if err := validateInput(map[string]string{"session_id": in.SessionID, "command": in.Command}); err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}, executeOutput{}, nil
		}
		res, err := eng.SessionExec(callerFn(ctx), in.SessionID, in.Command)
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}, executeOutput{}, nil
		}
		out := executeOutput{Stdout: res.Stdout, Stderr: res.Stderr, ExitCode: res.ExitCode, Serial: res.Serial}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: renderResult(out)}}}, out, nil
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name: "ssh_session_close",
		Description: "Cierra una sesión SSH persistente y libera la conexión. " +
			"Llamar siempre al terminar de trabajar con una sesión; no cerrarla consume recursos hasta que expira el TTL del certificado.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in sessionCloseInput) (*mcp.CallToolResult, okOutput, error) {
		if err := validateInput(map[string]string{"session_id": in.SessionID}); err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}, okOutput{}, nil
		}
		if err := eng.CloseSession(callerFn(ctx), in.SessionID); err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}, okOutput{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "cerrada"}}}, okOutput{OK: true}, nil
	})
}

// renderDecision formatea el resultado de un dry-run (simulación de política).
func renderDecision(d *signer.DecisionInfo) string {
	var b strings.Builder
	if d.Allowed {
		b.WriteString("[dry-run] PERMITIDO")
		if d.RequireApproval {
			b.WriteString(" (requiere aprobación humana antes de ejecutar)")
		}
	} else {
		b.WriteString("[dry-run] DENEGADO")
		if d.Reason != "" {
			fmt.Fprintf(&b, ": %s", d.Reason)
		}
	}
	if d.MatchedRule != "" {
		fmt.Fprintf(&b, "\nregla: %s", d.MatchedRule)
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
	fmt.Fprintf(&b, "\n[exit=%d serial=%d]", o.ExitCode, o.Serial)
	return b.String()
}
