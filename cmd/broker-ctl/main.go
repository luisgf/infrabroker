// broker-ctl gestiona la configuración del signer (signer.json) y fuerza recargas.
//
// Uso:
//
//	broker-ctl host add    [flags]          # Añade o actualiza un host
//	broker-ctl host list   [--config f]     # Lista hosts configurados
//	broker-ctl host remove [--config f] <nombre>
//	broker-ctl reload      [flags]          # Recarga signer (SIGHUP local o HTTP)
package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"
)

const defaultConfig = "./signer.json"

func main() {
	if len(os.Args) < 2 {
		usageTop()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "host":
		cmdHost(os.Args[2:])
	case "reload":
		cmdReload(os.Args[2:])
	case "help", "--help", "-h":
		usageTop()
	default:
		fmt.Fprintf(os.Stderr, "subcomando desconocido: %q\n", os.Args[1])
		usageTop()
		os.Exit(1)
	}
}

func usageTop() {
	fmt.Fprintln(os.Stderr, `broker-ctl — gestión de configuración del SSH broker

Uso:
  broker-ctl host add    [--config f] [flags]     Añade o actualiza un host
  broker-ctl host list   [--config f]             Lista hosts configurados
  broker-ctl host remove [--config f] <nombre>    Elimina un host
  broker-ctl reload      [--config f] [flags]     Recarga el signer

Opciones globales:
  --config   Ruta a signer.json (default: ./signer.json)`)
}

// ── host ──────────────────────────────────────────────────────────────────────

func cmdHost(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Uso: broker-ctl host {add|list|remove} [args]")
		os.Exit(1)
	}
	switch args[0] {
	case "add":
		cmdHostAdd(args[1:])
	case "list":
		cmdHostList(args[1:])
	case "remove", "rm", "del":
		cmdHostRemove(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "subcomando host desconocido: %q\n", args[0])
		os.Exit(1)
	}
}

func cmdHostAdd(args []string) {
	fs := flag.NewFlagSet("host add", flag.ExitOnError)
	config := fs.String("config", defaultConfig, "ruta a signer.json")
	name := fs.String("name", "", "nombre lógico del host (obligatorio)")
	addr := fs.String("addr", "", "host:port del servidor SSH (obligatorio)")
	user := fs.String("user", "", "cuenta SSH remota (obligatorio)")
	hostKey := fs.String("host-key", "", "host key en formato authorized_keys (o '-' para stdin)")
	scan := fs.Bool("scan", false, "obtener host key automáticamente con ssh-keyscan")
	principal := fs.String("principal", "", "principal SSH en el cert (default: host:<name>)")
	ttl := fs.Int("ttl", 120, "max_ttl_seconds")
	jump := fs.String("jump", "", "nombre lógico del bastión previo")
	sourceAddr := fs.String("source-address", "", "IP/CIDR de egreso del bastión")
	allowSudo := fs.Bool("sudo", false, "allow_sudo=true")
	sudoUsers := fs.String("sudo-users", "", "allowed_sudo_users separados por comas")
	allowPTY := fs.Bool("pty", false, "allow_pty=true")
	groups := fs.String("groups", "", "grupos RBAC separados por comas")
	callers := fs.String("callers", "", "CNs permitidos separados por comas")
	bastion := fs.Bool("bastion", false, "allow_as_bastion=true")
	force := fs.Bool("force", false, "sobrescribir si ya existe")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Uso: broker-ctl host add --name <n> --addr <h:p> --user <u> {--host-key <k>|--scan} [flags]")
		fs.PrintDefaults()
	}
	must(fs.Parse(args))

	if *name == "" || *addr == "" || *user == "" {
		fs.Usage()
		os.Exit(1)
	}
	if !*scan && *hostKey == "" {
		fmt.Fprintln(os.Stderr, "error: se requiere --host-key o --scan")
		fs.Usage()
		os.Exit(1)
	}
	if *scan && *hostKey != "" {
		fmt.Fprintln(os.Stderr, "error: --host-key y --scan son excluyentes")
		os.Exit(1)
	}

	var hk string
	if *scan {
		host, _, _ := strings.Cut(*addr, ":")
		var err error
		hk, err = sshKeyscan(host)
		if err != nil {
			fatalf("ssh-keyscan: %v", err)
		}
	} else if *hostKey == "-" {
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(os.Stdin); err != nil {
			fatalf("leer stdin: %v", err)
		}
		hk = strings.TrimSpace(buf.String())
	} else {
		hk = *hostKey
	}

	if *principal == "" {
		*principal = "host:" + *name
	}

	hp := hostEntry{
		Addr:          *addr,
		User:          *user,
		HostKey:       hk,
		Principal:     *principal,
		MaxTTLSeconds: *ttl,
	}
	if *jump != "" {
		hp.Jump = *jump
	}
	if *sourceAddr != "" {
		hp.SourceAddress = *sourceAddr
	}
	if *bastion {
		hp.AllowAsBastion = true
	}
	if *allowSudo {
		hp.AllowSudo = true
	}
	if *sudoUsers != "" {
		hp.AllowedSudoUsers = splitComma(*sudoUsers)
	}
	if *allowPTY {
		hp.AllowPTY = true
	}
	if *groups != "" {
		hp.Groups = splitComma(*groups)
	}
	if *callers != "" {
		hp.AllowedCallers = splitComma(*callers)
	}

	raw, err := loadRaw(*config)
	if err != nil {
		fatalf("leer config: %v", err)
	}

	hosts, err := extractHosts(raw)
	if err != nil {
		fatalf("parsear hosts: %v", err)
	}
	if _, exists := hosts[*name]; exists && !*force {
		fatalf("host %q ya existe (usa --force para sobrescribir)", *name)
	}

	hosts[*name] = hp
	if err := writeHosts(*config, raw, hosts); err != nil {
		fatalf("escribir config: %v", err)
	}

	action := "añadido"
	if _, exists := hosts[*name]; exists && *force {
		action = "actualizado"
	}
	fmt.Printf("host %q %s (addr=%s, user=%s, principal=%s)\n", *name, action, *addr, *user, *principal)
}

func cmdHostList(args []string) {
	fs := flag.NewFlagSet("host list", flag.ExitOnError)
	config := fs.String("config", defaultConfig, "ruta a signer.json")
	must(fs.Parse(args))

	raw, err := loadRaw(*config)
	if err != nil {
		fatalf("leer config: %v", err)
	}
	hosts, err := extractHosts(raw)
	if err != nil {
		fatalf("parsear hosts: %v", err)
	}

	if len(hosts) == 0 {
		fmt.Println("(no hay hosts configurados)")
		return
	}

	names := make([]string, 0, len(hosts))
	for n := range hosts {
		names = append(names, n)
	}
	sort.Strings(names)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tADDR\tUSER\tPRINCIPAL\tTTL\tSUDO\tPTY\tBASTION\tGROUPS")
	for _, n := range names {
		h := hosts[n]
		sudo := boolStr(h.AllowSudo)
		pty := boolStr(h.AllowPTY)
		bas := boolStr(h.AllowAsBastion)
		grps := strings.Join(h.Groups, ",")
		if grps == "" {
			grps = "—"
		}
		ttl := strconv.Itoa(h.MaxTTLSeconds) + "s"
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			n, h.Addr, h.User, h.Principal, ttl, sudo, pty, bas, grps)
	}
	w.Flush()
}

func cmdHostRemove(args []string) {
	fs := flag.NewFlagSet("host remove", flag.ExitOnError)
	config := fs.String("config", defaultConfig, "ruta a signer.json")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Uso: broker-ctl host remove [--config f] <nombre>")
	}
	must(fs.Parse(args))

	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(1)
	}
	name := fs.Arg(0)

	raw, err := loadRaw(*config)
	if err != nil {
		fatalf("leer config: %v", err)
	}
	hosts, err := extractHosts(raw)
	if err != nil {
		fatalf("parsear hosts: %v", err)
	}
	if _, exists := hosts[name]; !exists {
		fatalf("host %q no encontrado", name)
	}

	delete(hosts, name)
	if err := writeHosts(*config, raw, hosts); err != nil {
		fatalf("escribir config: %v", err)
	}
	fmt.Printf("host %q eliminado\n", name)
}

// ── reload ────────────────────────────────────────────────────────────────────

func cmdReload(args []string) {
	fs := flag.NewFlagSet("reload", flag.ExitOnError)
	config := fs.String("config", defaultConfig, "ruta a signer.json")
	pidFile := fs.String("pid-file", "./signer.pid", "ruta al PID file del signer")
	cert := fs.String("cert", "./pki/broker.crt", "cert cliente mTLS para /v1/reload")
	key := fs.String("key", "./pki/broker.key", "clave cliente mTLS")
	ca := fs.String("ca", "./pki/mtls_ca.crt", "CA mTLS")
	must(fs.Parse(args))

	// Intentar SIGHUP local primero.
	if pid, err := readPID(*pidFile); err == nil {
		if isAlive(pid) {
			if err := syscall.Kill(pid, syscall.SIGHUP); err != nil {
				fatalf("SIGHUP a PID %d: %v", pid, err)
			}
			fmt.Printf("SIGHUP enviado al signer (PID %d)\n", pid)
			return
		}
	}

	// Fallback: POST /v1/reload vía mTLS.
	signerURL, err := readSignerURL(*config)
	if err != nil {
		fatalf("leer URL del signer desde config: %v", err)
	}
	url := "https://" + signerURL + "/v1/reload"

	tlsCfg, err := buildTLSConfig(*cert, *key, *ca)
	if err != nil {
		fatalf("TLS: %v", err)
	}
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}
	resp, err := client.Post(url, "application/json", nil)
	if err != nil {
		fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()

	var result struct {
		Status string `json:"status"`
		Hosts  int    `json:"hosts"`
		Error  string `json:"error,omitempty"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		fatalf("parsear respuesta: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		fatalf("signer rechazó recarga (HTTP %d): %s", resp.StatusCode, result.Error)
	}
	fmt.Printf("signer recargado vía HTTP (hosts: %d)\n", result.Hosts)
}

// ── JSON helpers ──────────────────────────────────────────────────────────────

// hostEntry es la representación JSON de un host en signer.json.
type hostEntry struct {
	Addr             string   `json:"addr"`
	User             string   `json:"user"`
	HostKey          string   `json:"host_key"`
	Jump             string   `json:"jump,omitempty"`
	Principal        string   `json:"principal"`
	SourceAddress    string   `json:"source_address,omitempty"`
	MaxTTLSeconds    int      `json:"max_ttl_seconds,omitempty"`
	AllowAsBastion   bool     `json:"allow_as_bastion,omitempty"`
	AllowedCallers   []string `json:"allowed_callers,omitempty"`
	AllowSudo        bool     `json:"allow_sudo,omitempty"`
	AllowedSudoUsers []string `json:"allowed_sudo_users,omitempty"`
	AllowPTY         bool     `json:"allow_pty,omitempty"`
	Groups           []string `json:"groups,omitempty"`
}

// loadRaw lee signer.json como mapa de RawMessage para preservar campos desconocidos.
func loadRaw(path string) (map[string]json.RawMessage, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("JSON inválido: %w", err)
	}
	return raw, nil
}

// extractHosts extrae y parsea la clave "hosts" del raw map.
func extractHosts(raw map[string]json.RawMessage) (map[string]hostEntry, error) {
	hostsRaw, ok := raw["hosts"]
	if !ok {
		return map[string]hostEntry{}, nil
	}
	var hosts map[string]hostEntry
	if err := json.Unmarshal(hostsRaw, &hosts); err != nil {
		return nil, err
	}
	if hosts == nil {
		hosts = map[string]hostEntry{}
	}
	return hosts, nil
}

// writeHosts serializa hosts de vuelta al raw map y escribe el archivo.
func writeHosts(path string, raw map[string]json.RawMessage, hosts map[string]hostEntry) error {
	hostsJSON, err := json.MarshalIndent(hosts, "  ", "  ")
	if err != nil {
		return err
	}
	raw["hosts"] = hostsJSON

	out, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return err
	}
	// Escritura atómica: escribir a temp y renombrar.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(out, '\n'), 0640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// readSignerURL extrae el campo "listen" de signer.json para construir la URL HTTP.
func readSignerURL(configPath string) (string, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return "", err
	}
	var cfg struct {
		Listen string `json:"listen"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return "", err
	}
	if cfg.Listen == "" {
		return "", errors.New("campo 'listen' vacío en signer.json")
	}
	// Si listen es ":9443" (sin host), usar 127.0.0.1.
	if strings.HasPrefix(cfg.Listen, ":") {
		return "127.0.0.1" + cfg.Listen, nil
	}
	return cfg.Listen, nil
}

// ── TLS / PID helpers ─────────────────────────────────────────────────────────

func buildTLSConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("cargar cert cliente: %w", err)
	}
	caData, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("leer CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caData) {
		return nil, errors.New("CA PEM inválido")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
	}, nil
}

func readPID(pidFile string) (int, error) {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("PID inválido en %s: %w", pidFile, err)
	}
	return pid, nil
}

func isAlive(pid int) bool {
	return syscall.Kill(pid, 0) == nil
}

// sshKeyscan ejecuta ssh-keyscan y extrae la primera línea ed25519.
func sshKeyscan(host string) (string, error) {
	out, err := exec.Command("ssh-keyscan", "-t", "ed25519", host).Output()
	if err != nil {
		return "", fmt.Errorf("ssh-keyscan falló: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Formato: "hostname ssh-ed25519 AAAA..."
		// Eliminar el prefijo del hostname.
		parts := strings.Fields(line)
		if len(parts) >= 3 {
			return strings.Join(parts[1:], " "), nil
		}
	}
	return "", fmt.Errorf("ssh-keyscan no devolvió una clave ed25519 para %s", host)
}

// ── misc ──────────────────────────────────────────────────────────────────────

func splitComma(s string) []string {
	var result []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			result = append(result, p)
		}
	}
	return result
}

func boolStr(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}

func must(err error) {
	if err != nil {
		fatalf("%v", err)
	}
}
