// Package broker contiene el núcleo compartido: configuración y el motor que,
// por cada petición, firma un certificado SSH efímero, ejecuta el comando y lo
// audita. Lo usan tanto el frontend HTTP/mTLS (cmd/broker) como el servidor MCP
// (cmd/mcp-broker), de modo que la lógica de seguridad vive en un solo sitio.
package broker

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/luisgf/ssh-broker/internal/audit"
	"github.com/luisgf/ssh-broker/internal/auth"
	"github.com/luisgf/ssh-broker/internal/ca"
	"github.com/luisgf/ssh-broker/internal/signer"
	sshrun "github.com/luisgf/ssh-broker/internal/ssh"
)

// Config se carga desde un fichero JSON.
type Config struct {
	Listen string `json:"listen"` // solo HTTP: p. ej. ":8443"

	// TLS / mTLS del frontend HTTP (no usado por el MCP, que va sobre stdio).
	ServerCert string `json:"server_cert"`
	ServerKey  string `json:"server_key"`
	ClientCA   string `json:"client_ca"`

	// CAKey — SOLO modo local (firma en proceso). Si se define el bloque Signer,
	// este campo se ignora y el broker no custodia clave de CA.
	CAKey string `json:"ca_key,omitempty"`

	// Signer, si está presente, externaliza la firma a un servicio remoto
	// (HTTP+mTLS). El broker deja de tener la clave de CA y la política.
	Signer *SignerClientConfig `json:"signer,omitempty"`

	// Auditoría.
	AuditLog string `json:"audit_log"`
	AuditKey string `json:"audit_key"` // semilla Ed25519 (>=32 bytes)

	// SourceAddress: IP/CIDR de egreso del broker, usado en modo local.
	SourceAddress string `json:"source_address"`

	// MaxTTLSeconds limita superiormente el TTL solicitable.
	MaxTTLSeconds int `json:"max_ttl_seconds"`

	// HostsRefreshSeconds: intervalo de recarga del listado de hosts desde el
	// signer. Solo aplica en modo remoto. Default: 300 (5 minutos).
	HostsRefreshSeconds int `json:"hosts_refresh_seconds"`

	// Sesiones persistentes: cierre por inactividad y vida máxima.
	SessionIdleSeconds int `json:"session_idle_seconds"` // default 300
	SessionMaxSeconds  int `json:"session_max_seconds"`  // default 1800

	// Hosts: solo usado en modo local (single-binary). En modo remoto la lista
	// de hosts se obtiene del signer vía /v1/hosts y se recarga periódicamente.
	Hosts map[string]HostConfig `json:"hosts,omitempty"`
}

// HostConfig describe un destino en modo local.
type HostConfig struct {
	Addr      string `json:"addr"`
	User      string `json:"user"`
	Principal string `json:"principal"`
	HostKey   string `json:"host_key"`
	Jump      string `json:"jump,omitempty"`
	// SourceAddress: override del global para el cert de ESTE host.
	// SOLO modo local.
	SourceAddress string `json:"source_address,omitempty"`

	// Elevación (NOPASSWD) — modo local.
	AllowSudo        bool     `json:"allow_sudo,omitempty"`
	AllowedSudoUsers []string `json:"allowed_sudo_users,omitempty"`

	// AllowPTY — modo local.
	AllowPTY bool `json:"allow_pty,omitempty"`
}

// SignerClientConfig configura el cliente del servicio de firma externo.
type SignerClientConfig struct {
	URL        string `json:"url"`
	ClientCert string `json:"client_cert"`
	ClientKey  string `json:"client_key"`
	CA         string `json:"ca"`
}

// ExecOptions contiene las opciones de elevación y PTY para una ejecución.
type ExecOptions struct {
	// Sudo solicita elevación de privilegio vía sudo NOPASSWD.
	Sudo bool
	// SudoUser es el usuario destino del sudo (vacío = root).
	SudoUser string
	// PTY solicita un pseudo-terminal para la ejecución.
	PTY bool
}

// elevationLabel construye la etiqueta de auditoría para la elevación.
func (o ExecOptions) elevationLabel() string {
	if !o.Sudo {
		return ""
	}
	u := o.SudoUser
	if u == "" {
		u = "root"
	}
	return "sudo:" + u
}

// LoadConfig lee y valida la configuración JSON.
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	if c.Listen == "" {
		c.Listen = ":8443"
	}
	return &c, nil
}

// Result es el resultado de una ejecución.
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Serial   uint64
}

// Engine ejecuta comandos firmando credenciales efímeras y auditando.
type Engine struct {
	cfg      *Config
	sgn      signer.Signer
	fetcher  *signer.Remote // nil en modo local
	auditLog *audit.Log
	maxTTL   time.Duration
	sessions *sessionManager

	mu    sync.RWMutex
	hosts map[string]signer.HostInfo // cache recargado periódicamente (modo remoto)
	// En modo local los hosts vienen de cfg.Hosts; hosts no se usa.
}

// localCaller es la identidad del broker frente a un firmante local.
const localCaller = "local"

// NewEngine inicializa el firmante (local o remoto) y el log de auditoría.
func NewEngine(cfg *Config) (*Engine, error) {
	maxTTL := time.Duration(cfg.MaxTTLSeconds) * time.Second
	if maxTTL <= 0 {
		maxTTL = 5 * time.Minute
	}

	sgn, fetcher, err := buildSigner(cfg, maxTTL)
	if err != nil {
		return nil, err
	}

	seed, err := os.ReadFile(cfg.AuditKey)
	if err != nil {
		return nil, fmt.Errorf("leer clave de auditoría: %w", err)
	}
	if len(seed) < ed25519.SeedSize {
		return nil, fmt.Errorf("clave de auditoría demasiado corta")
	}
	al, err := audit.Open(cfg.AuditLog, ed25519.NewKeyFromSeed(seed[:ed25519.SeedSize]))
	if err != nil {
		return nil, err
	}

	idle := time.Duration(cfg.SessionIdleSeconds) * time.Second
	if idle <= 0 {
		idle = 5 * time.Minute
	}
	maxLife := time.Duration(cfg.SessionMaxSeconds) * time.Second
	if maxLife <= 0 {
		maxLife = 30 * time.Minute
	}

	e := &Engine{cfg: cfg, sgn: sgn, fetcher: fetcher, auditLog: al, maxTTL: maxTTL}
	e.sessions = newSessionManager(idle, maxLife, func(s *liveSession) {
		e.auditE(audit.Entry{Caller: s.caller, Host: s.host, Serial: s.serial,
			SessionID: s.id, Outcome: "session_close", Err: "reaped (idle/lifetime)"})
	})

	// Modo remoto: carga inicial de hosts y arranca la goroutine de recarga.
	if fetcher != nil {
		h, err := fetcher.FetchHosts()
		if err != nil {
			al.Close()
			return nil, fmt.Errorf("carga inicial de hosts desde signer: %w", err)
		}
		e.hosts = h
		log.Printf("hosts cargados desde signer: %d entradas", len(h))

		refresh := time.Duration(cfg.HostsRefreshSeconds) * time.Second
		if refresh <= 0 {
			refresh = 5 * time.Minute
		}
		e.startHostRefresh(refresh)
	}

	return e, nil
}

// startHostRefresh arranca la goroutine que recarga la lista de hosts
// periódicamente desde el signer.
func (e *Engine) startHostRefresh(interval time.Duration) {
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for range t.C {
			h, err := e.fetcher.FetchHosts()
			if err != nil {
				log.Printf("advertencia: recarga de hosts fallida: %v (manteniendo cache anterior)", err)
				continue
			}
			e.mu.Lock()
			e.hosts = h
			e.mu.Unlock()
			log.Printf("hosts recargados desde signer: %d entradas", len(h))
		}
	}()
}

// buildSigner construye un firmante remoto (si hay bloque Signer) o local.
// Devuelve también el *Remote para FetchHosts (nil en modo local).
func buildSigner(cfg *Config, maxTTL time.Duration) (signer.Signer, *signer.Remote, error) {
	if cfg.Signer != nil {
		tlsCfg, err := auth.ClientTLSConfig(cfg.Signer.ClientCert, cfg.Signer.ClientKey, cfg.Signer.CA)
		if err != nil {
			return nil, nil, fmt.Errorf("tls cliente de firma: %w", err)
		}
		r := signer.NewRemote(cfg.Signer.URL, tlsCfg, 0)
		return r, r, nil
	}
	// Modo local: clave de CA en proceso + política derivada de los hosts.
	caPEM, err := os.ReadFile(cfg.CAKey)
	if err != nil {
		return nil, nil, fmt.Errorf("leer clave de CA (modo local): %w", err)
	}
	caKey, err := ca.LoadCAFromPEM(caPEM)
	if err != nil {
		return nil, nil, err
	}
	return signer.NewLocal(caKey, policyFromHosts(cfg), maxTTL), nil, nil
}

// policyFromHosts deriva la PolicyTable del firmante local a partir de la config
// de hosts del broker (modo single-binary, sin servicio externo).
func policyFromHosts(cfg *Config) signer.PolicyTable {
	pt := signer.PolicyTable{}
	for name, hc := range cfg.Hosts {
		src := cfg.SourceAddress
		if hc.SourceAddress != "" {
			src = hc.SourceAddress
		}
		pt[name] = signer.HostPolicy{
			Addr:             hc.Addr,
			User:             hc.User,
			HostKey:          hc.HostKey,
			Jump:             hc.Jump,
			Principal:        hc.Principal,
			SourceAddress:    src,
			AllowAsBastion:   true,
			AllowSudo:        hc.AllowSudo,
			AllowedSudoUsers: hc.AllowedSudoUsers,
			AllowPTY:         hc.AllowPTY,
		}
	}
	return pt
}

// hostInfo devuelve los datos de conectividad de un host, independientemente
// del modo (local o remoto).
func (e *Engine) hostInfo(name string) (signer.HostInfo, bool) {
	if e.fetcher != nil {
		// Modo remoto: cache protegido por RWMutex.
		e.mu.RLock()
		h, ok := e.hosts[name]
		e.mu.RUnlock()
		return h, ok
	}
	// Modo local: leer de cfg.Hosts.
	hc, ok := e.cfg.Hosts[name]
	if !ok {
		return signer.HostInfo{}, false
	}
	return signer.HostInfo{Addr: hc.Addr, User: hc.User, HostKey: hc.HostKey, Jump: hc.Jump, AllowSudo: hc.AllowSudo, AllowPTY: hc.AllowPTY}, true
}

// ServerInfo contiene el nombre lógico y las capacidades de un host,
// para que el modelo pueda elegir la estrategia de ejecución adecuada.
type ServerInfo struct {
	Name      string
	AllowSudo bool
	AllowPTY  bool
	Jump      string // nombre del bastión, si lo tiene
}

// ServerInfos devuelve los hosts configurados con sus capacidades (orden estable).
func (e *Engine) ServerInfos() []ServerInfo {
	var infos []ServerInfo
	if e.fetcher != nil {
		e.mu.RLock()
		infos = make([]ServerInfo, 0, len(e.hosts))
		for name, h := range e.hosts {
			infos = append(infos, ServerInfo{Name: name, AllowSudo: h.AllowSudo, AllowPTY: h.AllowPTY, Jump: h.Jump})
		}
		e.mu.RUnlock()
	} else {
		infos = make([]ServerInfo, 0, len(e.cfg.Hosts))
		for name, hc := range e.cfg.Hosts {
			infos = append(infos, ServerInfo{Name: name, AllowSudo: hc.AllowSudo, AllowPTY: hc.AllowPTY, Jump: hc.Jump})
		}
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].Name < infos[j].Name })
	return infos
}

// Servers devuelve los nombres de host configurados (orden estable).
func (e *Engine) Servers() []string {
	var names []string
	if e.fetcher != nil {
		e.mu.RLock()
		names = make([]string, 0, len(e.hosts))
		for k := range e.hosts {
			names = append(names, k)
		}
		e.mu.RUnlock()
	} else {
		names = make([]string, 0, len(e.cfg.Hosts))
		for k := range e.cfg.Hosts {
			names = append(names, k)
		}
	}
	sort.Strings(names)
	return names
}

// Execute firma un cert efímero acotado (con force-command, y sudo si se pide),
// ejecuta command en host de un disparo (a través de bastión si está configurado)
// y audita.
func (e *Engine) Execute(caller, host, command string, ttlSeconds int, opts ExecOptions) (*Result, error) {
	if _, ok := e.hostInfo(host); !ok {
		e.auditE(audit.Entry{Caller: caller, Host: host, Command: command, Outcome: "denied", Err: "host desconocido"})
		return nil, fmt.Errorf("host desconocido: %q", host)
	}
	if command == "" {
		return nil, fmt.Errorf("command obligatorio")
	}

	hops, serial, err := e.buildHops(host, e.ttlFor(ttlSeconds), signer.PurposeOneshot, command, opts)
	if err != nil {
		e.auditE(audit.Entry{Caller: caller, Host: host, Command: command, Outcome: "error", Err: err.Error()})
		return nil, err
	}
	conn, err := sshrun.Dial(hops, 0)
	if err != nil {
		e.auditE(audit.Entry{Caller: caller, Host: host, Command: command, Serial: serial, Outcome: "error", Err: err.Error()})
		return nil, fmt.Errorf("conexión: %w", err)
	}
	defer conn.Close()

	execOpts := sshrun.ExecOptions{PTY: opts.PTY}
	res, err := sshrun.ExecOnce(conn.Client, command, execOpts)
	if err != nil {
		e.auditE(audit.Entry{Caller: caller, Host: host, Command: command, Serial: serial, Outcome: "error", Err: err.Error()})
		return nil, fmt.Errorf("ejecución: %w", err)
	}
	e.auditE(audit.Entry{
		Caller:    caller,
		Host:      host,
		Command:   command,
		Serial:    serial,
		Outcome:   "executed",
		ExitCode:  res.ExitCode,
		Elevation: opts.elevationLabel(),
		PTY:       opts.PTY,
	})
	return &Result{Stdout: res.Stdout, Stderr: res.Stderr, ExitCode: res.ExitCode, Serial: serial}, nil
}

func (e *Engine) ttlFor(ttlSeconds int) time.Duration {
	ttl := time.Duration(ttlSeconds) * time.Second
	if ttl <= 0 || ttl > e.maxTTL {
		ttl = e.maxTTL
	}
	return ttl
}

// buildHops resuelve la cadena destino→…→bastión y, por hop, genera un par efímero
// y pide al firmante un cert para la intención.
func (e *Engine) buildHops(host string, ttl time.Duration, purpose, command string, opts ExecOptions) ([]sshrun.Hop, uint64, error) {
	chain, err := e.resolveChain(host)
	if err != nil {
		return nil, 0, err
	}

	hops := make([]sshrun.Hop, 0, len(chain))
	var finalSerial uint64
	for i, name := range chain {
		hi, _ := e.hostInfo(name)
		isTarget := i == len(chain)-1

		priv, pub, err := ca.GenerateEphemeralKey()
		if err != nil {
			return nil, 0, err
		}
		in := signer.Intent{
			Caller:       localCaller,
			Host:         name,
			Role:         signer.RoleBastion,
			Purpose:      purpose,
			RequestedTTL: ttl,
			PublicKey:    pub,
		}
		if isTarget {
			in.Role = signer.RoleTarget
			in.Command = command
			// Elevación y PTY solo en el hop destino.
			in.Sudo = opts.Sudo
			in.SudoUser = opts.SudoUser
			in.PTY = opts.PTY
		}
		issued, err := e.sgn.SignIntent(in)
		if err != nil {
			return nil, 0, fmt.Errorf("firmar cert de %q: %w", name, err)
		}
		hostKey, err := ParseHostKey(hi.HostKey)
		if err != nil {
			return nil, 0, fmt.Errorf("host key de %q: %w", name, err)
		}
		hops = append(hops, sshrun.Hop{
			Addr: hi.Addr, User: hi.User, HostKey: hostKey,
			PrivateKey: priv, Certificate: issued.Certificate,
		})
		if isTarget {
			finalSerial = issued.Serial
		}
	}
	return hops, finalSerial, nil
}

// buildHopsWithPrefix es igual que buildHops pero además devuelve el
// ElevationPrefix emitido por el firmante para el hop target (sesiones).
func (e *Engine) buildHopsWithPrefix(host string, ttl time.Duration, purpose string, opts ExecOptions) ([]sshrun.Hop, uint64, string, error) {
	chain, err := e.resolveChain(host)
	if err != nil {
		return nil, 0, "", err
	}

	hops := make([]sshrun.Hop, 0, len(chain))
	var finalSerial uint64
	var elevPrefix string
	for i, name := range chain {
		hi, _ := e.hostInfo(name)
		isTarget := i == len(chain)-1

		priv, pub, err := ca.GenerateEphemeralKey()
		if err != nil {
			return nil, 0, "", err
		}
		in := signer.Intent{
			Caller:       localCaller,
			Host:         name,
			Role:         signer.RoleBastion,
			Purpose:      purpose,
			RequestedTTL: ttl,
			PublicKey:    pub,
		}
		if isTarget {
			in.Role = signer.RoleTarget
			in.Sudo = opts.Sudo
			in.SudoUser = opts.SudoUser
			in.PTY = opts.PTY
		}
		issued, err := e.sgn.SignIntent(in)
		if err != nil {
			return nil, 0, "", fmt.Errorf("firmar cert de %q: %w", name, err)
		}
		hostKey, err := ParseHostKey(hi.HostKey)
		if err != nil {
			return nil, 0, "", fmt.Errorf("host key de %q: %w", name, err)
		}
		hops = append(hops, sshrun.Hop{
			Addr: hi.Addr, User: hi.User, HostKey: hostKey,
			PrivateKey: priv, Certificate: issued.Certificate,
		})
		if isTarget {
			finalSerial = issued.Serial
			elevPrefix = issued.ElevationPrefix
		}
	}
	return hops, finalSerial, elevPrefix, nil
}

// resolveChain devuelve la cadena de hosts en orden de marcado (bastión más
// externo primero, destino último), siguiendo el campo Jump y detectando ciclos.
func (e *Engine) resolveChain(host string) ([]string, error) {
	var chain []string
	seen := map[string]bool{}
	for cur := host; cur != ""; {
		if seen[cur] {
			return nil, fmt.Errorf("ciclo de bastión en %q", cur)
		}
		seen[cur] = true
		hi, ok := e.hostInfo(cur)
		if !ok {
			return nil, fmt.Errorf("host desconocido en cadena: %q", cur)
		}
		chain = append([]string{cur}, chain...)
		cur = hi.Jump
	}
	return chain, nil
}

// Close cierra todas las sesiones y el log de auditoría.
func (e *Engine) Close() error {
	e.sessions.closeAll()
	return e.auditLog.Close()
}

func (e *Engine) auditE(ent audit.Entry) {
	if hi, ok := e.hostInfo(ent.Host); ok {
		if ent.User == "" {
			ent.User = hi.User
		}
	}
	_ = e.auditLog.Append(ent)
}

// ParseHostKey convierte una línea authorized_keys en ssh.PublicKey.
func ParseHostKey(authorizedKeyLine string) (ssh.PublicKey, error) {
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKeyLine))
	if err != nil {
		return nil, fmt.Errorf("parsear host key: %w", err)
	}
	return pk, nil
}
