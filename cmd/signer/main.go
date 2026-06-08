// Command signer es el servicio de firma externo: custodia la clave de CA y la
// política, y emite certificados SSH efímeros a brokers autenticados por mTLS. El
// broker nunca tiene la clave de CA; manda una intención y recibe el cert firmado.
//
// El cuerpo del servicio es un signer.Local expuesto por HTTP+mTLS, con su propio
// log de emisión (auditoría independiente del broker).
package main

import (
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/luisgf/ssh-broker/internal/audit"
	"github.com/luisgf/ssh-broker/internal/auth"
	"github.com/luisgf/ssh-broker/internal/ca"
	"github.com/luisgf/ssh-broker/internal/signer"
)

// Config del servicio de firma.
type Config struct {
	Listen string `json:"listen"` // p. ej. ":9443"

	// mTLS del servicio: presenta server_cert y exige clientes firmados por client_ca.
	ServerCert string `json:"server_cert"`
	ServerKey  string `json:"server_key"`
	ClientCA   string `json:"client_ca"` // CA que firma a los brokers autorizados

	// Custodia de la clave de CA. PEM por ahora; sustituible por crypto.Signer de
	// KMS/Secure Enclave/HSM sin tocar el resto (ca.LoadCAFromPEM -> ssh.Signer).
	CAKey string `json:"ca_key"`

	// Auditoría de emisión (independiente del broker).
	AuditLog string `json:"audit_log"`
	AuditKey string `json:"audit_key"`

	// MaxTTLSeconds: tope global si la política del host no fija uno.
	MaxTTLSeconds int `json:"max_ttl_seconds"`

	// ReloadCallers: CNs (de cert de cliente) autorizados a invocar POST
	// /v1/reload. Si está vacío, el endpoint HTTP queda deshabilitado (403);
	// SIGHUP sigue funcionando porque es local al host.
	ReloadCallers []string `json:"reload_callers"`

	// TrustedForwarders: CNs (de cert de cliente) autorizados a actuar en nombre
	// de otro broker (campo on_behalf_of / cabecera X-On-Behalf-Of). Es el CN del
	// control plane. Solo estos CNs pueden suplantar la identidad del broker para
	// RBAC; cualquier otro que mande on_behalf_of es rechazado.
	TrustedForwarders []string `json:"trusted_forwarders,omitempty"`

	// Hosts: política de emisión + conectividad por host. Es la única fuente de
	// verdad: el broker obtiene addr/user/host_key/jump vía GET /v1/hosts.
	Hosts signer.PolicyTable `json:"hosts"`

	// Callers: RBAC por grupos. Mapea CN del cert mTLS del broker → grupos permitidos.
	// Un CN ausente no tiene restricción de grupo (backward compatible).
	// Un CN presente solo puede ver y firmar hosts cuyo campo groups intersecte
	// con sus allowed_groups.
	Callers signer.CallerTable `json:"callers,omitempty"`
}

func main() {
	cfgPath := flag.String("config", "signer.json", "ruta al fichero de configuración JSON")
	flag.Parse()

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	local, err := buildState(cfg)
	if err != nil {
		log.Fatalf("%v", err)
	}

	seed, err := os.ReadFile(cfg.AuditKey)
	if err != nil {
		log.Fatalf("leer clave de auditoría: %v", err)
	}
	if len(seed) < ed25519.SeedSize {
		log.Fatalf("clave de auditoría demasiado corta")
	}
	auditLog, err := audit.Open(cfg.AuditLog, ed25519.NewKeyFromSeed(seed[:ed25519.SeedSize]))
	if err != nil {
		log.Fatalf("auditoría: %v", err)
	}
	defer auditLog.Close()

	tlsCfg, err := auth.ServerTLSConfig(cfg.ServerCert, cfg.ServerKey, cfg.ClientCA)
	if err != nil {
		log.Fatalf("tls: %v", err)
	}

	srv := &server{
		local:      local,
		audit:      auditLog,
		hosts:      cfg.Hosts,
		callers:    cfg.Callers,
		reloadCN:   reloadSet(cfg.ReloadCallers),
		forwarders: reloadSet(cfg.TrustedForwarders),
		cfgPath:    *cfgPath,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sign", srv.handleSign)
	mux.HandleFunc("/v1/hosts", srv.handleHosts)
	mux.HandleFunc("/v1/reload", srv.handleReload)

	// Recarga en caliente vía SIGHUP (además del endpoint HTTP). Es local al
	// host, por eso no pasa por la allowlist de reload_callers.
	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGHUP)
		for range ch {
			n, err := srv.reload()
			if err != nil {
				log.Printf("reload (SIGHUP): error: %v (se conserva la config anterior)", err)
				srv.auditReload("SIGHUP", 0, "reload-failed", err)
				continue
			}
			log.Printf("reload (SIGHUP): %d hosts en política", n)
			srv.auditReload("SIGHUP", n, "reloaded", nil)
		}
	}()

	// A1: timeouts para evitar agotamiento de conexiones (slowloris y conexiones colgadas).
	httpSrv := &http.Server{
		Addr:         cfg.Listen,
		Handler:      mux,
		TLSConfig:    tlsCfg,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	log.Printf("signer (mTLS) en %s; %d hosts en política", cfg.Listen, len(cfg.Hosts))
	log.Fatal(httpSrv.ListenAndServeTLS("", ""))
}

// buildState construye el estado recargable (firmante + política de hosts) a
// partir de la config: lee la clave de CA del fichero y materializa el TTL por
// defecto. Devuelve error sin tocar nada si algo falla, de modo que un reload
// inválido no deja el signer en estado roto.
func buildState(cfg *Config) (*signer.Local, error) {
	caPEM, err := os.ReadFile(cfg.CAKey)
	if err != nil {
		return nil, fmt.Errorf("leer clave de CA: %w", err)
	}
	caKey, err := ca.LoadCAFromPEM(caPEM)
	if err != nil {
		return nil, fmt.Errorf("clave de CA: %w", err)
	}
	defaultTTL := time.Duration(cfg.MaxTTLSeconds) * time.Second
	if defaultTTL <= 0 {
		defaultTTL = 5 * time.Minute
	}
	return signer.NewLocal(caKey, cfg.Hosts, defaultTTL), nil
}

// reloadSet convierte la lista de CNs admin en un conjunto para lookup O(1).
func reloadSet(cns []string) map[string]struct{} {
	m := make(map[string]struct{}, len(cns))
	for _, cn := range cns {
		if cn != "" {
			m[cn] = struct{}{}
		}
	}
	return m
}

type server struct {
	// mu protege el estado recargable en caliente.
	mu         sync.RWMutex
	local      *signer.Local
	hosts      signer.PolicyTable
	callers    signer.CallerTable
	reloadCN   map[string]struct{}
	forwarders map[string]struct{}

	// Inmutables tras el arranque.
	audit   *audit.Log
	cfgPath string
}

// snapshot devuelve el estado vigente bajo RLock, para que los handlers no lean
// los campos mientras un reload los está sustituyendo.
func (s *server) snapshot() (*signer.Local, signer.PolicyTable, signer.CallerTable, map[string]struct{}) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.local, s.hosts, s.callers, s.forwarders
}

// resolveCaller determina la identidad efectiva para RBAC. Si onBehalfOf no es
// vacío, solo se honra cuando mtlsCN es un forwarder de confianza; en otro caso
// devuelve ok=false (la petición debe rechazarse con 403).
func resolveCaller(mtlsCN, onBehalfOf string, forwarders map[string]struct{}) (caller string, ok bool) {
	if onBehalfOf == "" {
		return mtlsCN, true
	}
	if _, trusted := forwarders[mtlsCN]; trusted {
		return onBehalfOf, true
	}
	return "", false
}

// reload relee el fichero de config y, si es válido, sustituye atómicamente el
// firmante, la política de hosts y la allowlist de reload. Si algo falla, no
// modifica el estado y devuelve error. Devuelve el número de hosts cargados.
func (s *server) reload() (int, error) {
	cfg, err := loadConfig(s.cfgPath)
	if err != nil {
		return 0, fmt.Errorf("config: %w", err)
	}
	local, err := buildState(cfg)
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	s.local = local
	s.hosts = cfg.Hosts
	s.callers = cfg.Callers
	s.reloadCN = reloadSet(cfg.ReloadCallers)
	s.forwarders = reloadSet(cfg.TrustedForwarders)
	s.mu.Unlock()
	return len(cfg.Hosts), nil
}

func (s *server) handleSign(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "método no permitido", http.StatusMethodNotAllowed)
		return
	}
	caller, err := auth.CallerCN(r)
	if err != nil {
		http.Error(w, "no autenticado", http.StatusUnauthorized)
		return
	}

	// A2: limitar el tamaño del cuerpo para evitar OOM por payloads gigantes.
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024) // 64 KiB es más que suficiente
	var req signer.WireRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "petición inválida", http.StatusBadRequest)
		return
	}
	pub, err := signer.ParsePublicKey(req.PublicKey)
	if err != nil {
		http.Error(w, "pubkey inválida", http.StatusBadRequest)
		return
	}

	local, hosts, callers, forwarders := s.snapshot()

	// approved solo se honra desde un forwarder de confianza (control plane); un
	// broker no puede auto-aprobarse.
	_, isForwarder := forwarders[caller]
	effectiveApproved := req.Approved && isForwarder

	// Resolver identidad efectiva: un forwarder de confianza (control plane) puede
	// actuar en nombre del broker original vía on_behalf_of.
	caller, ok := resolveCaller(caller, req.OnBehalfOf, forwarders)
	if !ok {
		http.Error(w, "on_behalf_of no permitido para este caller", http.StatusForbidden)
		return
	}

	// Verificar acceso por grupo antes de Resolve: si el caller tiene restricción
	// de grupo, el host solicitado debe pertenecer a alguno de sus grupos.
	if hostSet, restricted := signer.HostSetForCaller(caller, hosts, callers); restricted {
		if _, ok := hostSet[req.Host]; !ok {
			s.auditEmission(caller, req, hosts, 0, "denied", fmt.Errorf("host %q fuera del grupo para %q", req.Host, caller))
			http.Error(w, "host no autorizado", http.StatusForbidden)
			return
		}
	}

	in := signer.Intent{
		Caller:        caller,
		Host:          req.Host,
		Role:          req.Role,
		Purpose:       req.Purpose,
		Command:       req.Command,
		RequestedTTL:  time.Duration(req.TTLSeconds) * time.Second,
		PublicKey:     pub,
		Sudo:          req.Sudo,
		SudoUser:      req.SudoUser,
		PTY:           req.PTY,
		DryRun:        req.DryRun,
		Approved:      effectiveApproved,
		EndUser:       req.EndUser,
		EndUserGroups: req.EndUserGroups,
	}
	issued, err := local.SignIntent(in)
	if err != nil {
		s.auditEmission(caller, req, hosts, 0, "denied", err)
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	// Dry-run: no se emite certificado; se devuelve solo la decisión y se audita.
	if req.DryRun {
		outcome := "dry_run_allowed"
		if issued.Decision != nil && !issued.Decision.Allowed {
			outcome = "dry_run_denied"
		}
		s.auditEmission(caller, req, hosts, 0, outcome, nil)
		writeJSON(w, http.StatusOK, signer.WireResponse{Decision: issued.Decision})
		return
	}

	// Sin certificado pero permitido: la operación requiere aprobación humana y no
	// ha sido aprobada. Se devuelve la decisión (cert vacío) para que el control
	// plane orqueste la aprobación.
	if issued.Certificate == nil {
		s.auditEmission(caller, req, hosts, 0, "approval-required", nil)
		writeJSON(w, http.StatusOK, signer.WireResponse{Decision: issued.Decision})
		return
	}

	s.auditEmission(caller, req, hosts, issued.Serial, "issued", nil)
	writeJSON(w, http.StatusOK, signer.WireResponse{
		Certificate:     string(ssh.MarshalAuthorizedKey(issued.Certificate)),
		Serial:          issued.Serial,
		ElevationPrefix: issued.ElevationPrefix,
		Decision:        issued.Decision,
	})
}

// handleHosts sirve GET /v1/hosts: devuelve los datos de conectividad de los
// hosts accesibles al caller. Si el caller tiene restricción de grupos, solo
// recibe los hosts cuyo campo groups intersecta con sus allowed_groups.
// No expone datos de política (principal, source_address, allowed_callers).
func (s *server) handleHosts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "método no permitido", http.StatusMethodNotAllowed)
		return
	}
	caller, err := auth.CallerCN(r)
	if err != nil {
		http.Error(w, "no autenticado", http.StatusUnauthorized)
		return
	}

	_, hosts, callers, forwarders := s.snapshot()

	// Un forwarder de confianza puede pedir la lista en nombre de un broker
	// (cabecera X-On-Behalf-Of) para que el filtrado por grupos sea el del broker.
	caller, ok := resolveCaller(caller, r.Header.Get(signer.HeaderOnBehalfOf), forwarders)
	if !ok {
		http.Error(w, "on_behalf_of no permitido para este caller", http.StatusForbidden)
		return
	}

	result := make(map[string]signer.WireHostInfo, len(hosts))
	for name, hp := range hosts {
		result[name] = signer.WireHostInfo{
			Addr:      hp.Addr,
			User:      hp.User,
			HostKey:   hp.HostKey,
			Jump:      hp.Jump,
			AllowSudo: hp.AllowSudo,
			AllowPTY:  hp.AllowPTY,
		}
	}

	// Filtrar por grupos si el caller tiene restricción.
	if hostSet, restricted := signer.HostSetForCaller(caller, hosts, callers); restricted {
		for name := range result {
			if _, ok := hostSet[name]; !ok {
				delete(result, name)
			}
		}
	}

	writeJSON(w, http.StatusOK, result)
}

// handleReload sirve POST /v1/reload: relee el fichero de configuración y
// sustituye en caliente la política de hosts, el TTL global y la clave de CA.
// Solo CNs en reload_callers pueden invocarlo. Si la nueva config es inválida,
// el estado anterior se conserva intacto y se devuelve 500.
func (s *server) handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "método no permitido", http.StatusMethodNotAllowed)
		return
	}
	caller, err := auth.CallerCN(r)
	if err != nil {
		http.Error(w, "no autenticado", http.StatusUnauthorized)
		return
	}

	s.mu.RLock()
	_, allowed := s.reloadCN[caller]
	s.mu.RUnlock()
	if !allowed {
		s.auditReload(caller, 0, "reload-denied", fmt.Errorf("caller no autorizado"))
		http.Error(w, "no autorizado para recargar", http.StatusForbidden)
		return
	}

	n, err := s.reload()
	if err != nil {
		s.auditReload(caller, 0, "reload-failed", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.auditReload(caller, n, "reloaded", nil)
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "hosts": n})
}

// auditReload registra una operación de recarga en el log de auditoría.
func (s *server) auditReload(caller string, hosts int, outcome string, err error) {
	e := audit.Entry{
		Caller:  caller,
		Command: fmt.Sprintf("reload hosts=%d", hosts),
		Outcome: outcome,
	}
	if err != nil {
		e.Err = err.Error()
	}
	// M1: registrar el error en lugar de descartarlo silenciosamente.
	if aerr := s.audit.Append(e); aerr != nil {
		log.Printf("advertencia: error escribiendo audit log del signer: %v", aerr)
	}
}

func (s *server) auditEmission(caller string, req signer.WireRequest, hosts signer.PolicyTable, serial uint64, outcome string, err error) {
	cmd := "role=" + req.Role + " purpose=" + req.Purpose
	if req.EndUser != "" {
		cmd += " user=" + req.EndUser
	}
	if req.Sudo {
		u := req.SudoUser
		if u == "" {
			u = "root"
		}
		cmd += " elev=sudo:" + u
	}
	if req.PTY {
		cmd += " pty=1"
	}
	// Usar la dirección real (FQDN) y los metadatos de la política en lugar del
	// nombre lógico, que no identifica unívocamente el destino en el log.
	host := req.Host
	var user, principal string
	if hp, ok := hosts[req.Host]; ok {
		host = hp.Addr
		user = hp.User
		principal = hp.Principal
	}
	e := audit.Entry{
		Caller:    caller,
		Host:      host,
		User:      user,
		Principal: principal,
		Command:   cmd,
		Serial:    serial,
		Outcome:   outcome,
	}
	if err != nil {
		e.Err = err.Error()
	}
	// M1: registrar el error en lugar de descartarlo silenciosamente.
	if aerr := s.audit.Append(e); aerr != nil {
		log.Printf("advertencia: error escribiendo audit log del signer: %v", aerr)
	}
}

// writeJSON serialises v as JSON with the given HTTP status code.
// Errors writing the response body are logged but cannot be remediated once
// headers are sent.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("writeJSON: %v", err)
	}
}

func loadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	if c.Listen == "" {
		c.Listen = ":9443"
	}
	// Materializa MaxTTL por host desde los segundos del JSON.
	for name, hp := range c.Hosts {
		if hp.MaxTTLSeconds > 0 {
			hp.MaxTTL = time.Duration(hp.MaxTTLSeconds) * time.Second
			c.Hosts[name] = hp
		}
	}
	return &c, nil
}
