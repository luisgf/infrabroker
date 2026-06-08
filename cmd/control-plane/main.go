// Command control-plane es el Policy Enforcement Point entre el broker y el signer.
// Reenvía las peticiones de firma al signer propagando la identidad del broker
// (on_behalf_of) y orquesta la aprobación humana de los comandos que la command
// policy marca como require_approval. NO custodia la clave de CA (vive en el signer).
//
// Flujo de aprobación (polling asíncrono, para no mantener conexiones abiertas):
//  1. broker → POST /v1/sign. El control plane reenvía al signer (approved=false).
//  2. Si el signer responde sin certificado (requiere aprobación), el control plane
//     crea una solicitud, notifica out-of-band y responde 202 {approval_id}.
//  3. El broker hace polling de GET /v1/sign/result/{id}.
//  4. Un humano aprueba con POST /v1/approvals/{id} (broker-ctl approval allow).
//  5. El siguiente poll reenvía al signer con approved=true y devuelve el cert.
package main

import (
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/luisgf/ssh-broker/internal/audit"
	"github.com/luisgf/ssh-broker/internal/auth"
	"github.com/luisgf/ssh-broker/internal/control"
	"github.com/luisgf/ssh-broker/internal/signer"
)

// Config del control plane.
type Config struct {
	Listen string `json:"listen"` // p. ej. ":7443"

	// mTLS de cara al broker: presenta server_cert y exige clientes firmados por client_ca.
	ServerCert string `json:"server_cert"`
	ServerKey  string `json:"server_key"`
	ClientCA   string `json:"client_ca"`

	// Signer: cliente mTLS hacia el servicio de firma.
	Signer struct {
		URL        string `json:"url"`
		ClientCert string `json:"client_cert"`
		ClientKey  string `json:"client_key"`
		CA         string `json:"ca"`
	} `json:"signer"`

	// Approval: orquestación de la aprobación humana.
	Approval struct {
		Notifier       string   `json:"notifier"`        // "webhook" | "teams" | "log" (default)
		WebhookURL     string   `json:"webhook_url"`     // requerido si notifier=webhook o teams
		TimeoutSeconds int      `json:"timeout_seconds"` // TTL de las solicitudes pendientes
		Callers        []string `json:"callers"`         // CNs autorizados a aprobar/denegar

		// Campos específicos de Teams (notifier=teams).
		TeamsFormat         string `json:"teams_format"`          // "workflow" (default) | "messagecard"
		ApprovalURLTemplate string `json:"approval_url_template"` // URL con "{id}" para enlazar la solicitud
	} `json:"approval"`

	// Behavior: guardrails de comportamiento (anomalías + rate limiting).
	Behavior control.BehaviorConfig `json:"behavior"`

	// Auditoría del control plane (independiente del broker y del signer).
	AuditLog string `json:"audit_log"`
	AuditKey string `json:"audit_key"`
}

type server struct {
	remote    *signer.Remote
	registry  *control.Registry
	notifier  control.Notifier
	behavior  *control.BehaviorTracker
	audit     *audit.Log
	approveCN map[string]struct{}
}

func main() {
	cfgPath := flag.String("config", "control-plane.json", "ruta al fichero de configuración JSON")
	flag.Parse()

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	signerTLS, err := auth.ClientTLSConfig(cfg.Signer.ClientCert, cfg.Signer.ClientKey, cfg.Signer.CA)
	if err != nil {
		log.Fatalf("tls cliente del signer: %v", err)
	}
	remote := signer.NewRemote(cfg.Signer.URL, signerTLS, 10*time.Second)

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

	var notifier control.Notifier = control.LogNotifier{}
	switch cfg.Approval.Notifier {
	case "webhook":
		if cfg.Approval.WebhookURL == "" {
			log.Fatalf("notifier=webhook requiere webhook_url")
		}
		notifier = control.NewWebhookNotifier(cfg.Approval.WebhookURL)
	case "teams":
		if cfg.Approval.WebhookURL == "" {
			log.Fatalf("notifier=teams requiere webhook_url")
		}
		notifier = control.NewTeamsNotifier(
			cfg.Approval.WebhookURL,
			cfg.Approval.TeamsFormat,
			cfg.Approval.ApprovalURLTemplate,
		)
	}

	srv := &server{
		remote:    remote,
		registry:  control.NewRegistry(time.Duration(cfg.Approval.TimeoutSeconds) * time.Second),
		notifier:  notifier,
		behavior:  control.NewBehaviorTracker(cfg.Behavior),
		audit:     auditLog,
		approveCN: cnSet(cfg.Approval.Callers),
	}

	tlsCfg, err := auth.ServerTLSConfig(cfg.ServerCert, cfg.ServerKey, cfg.ClientCA)
	if err != nil {
		log.Fatalf("tls: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/sign", srv.handleSign)
	mux.HandleFunc("GET /v1/hosts", srv.handleHosts)
	mux.HandleFunc("GET /v1/sign/result/{id}", srv.handleResult)
	mux.HandleFunc("GET /v1/approvals", srv.handleApprovalsList)
	mux.HandleFunc("POST /v1/approvals/{id}", srv.handleApprovalDecide)

	httpSrv := &http.Server{
		Addr:         cfg.Listen,
		Handler:      mux,
		TLSConfig:    tlsCfg,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	behaviorMode := cfg.Behavior.Mode
	if behaviorMode == "" {
		behaviorMode = control.BehaviorOff
	}
	log.Printf("control-plane (mTLS) en %s; signer=%s; aprobadores=%d; behavior=%s", cfg.Listen, cfg.Signer.URL, len(srv.approveCN), behaviorMode)
	log.Fatal(httpSrv.ListenAndServeTLS("", ""))
}

// handleSign reenvía la petición al signer en nombre del broker. Si el signer no
// emite certificado (requiere aprobación), crea una solicitud y responde 202.
func (s *server) handleSign(w http.ResponseWriter, r *http.Request) {
	brokerCN, err := auth.CallerCN(r)
	if err != nil {
		http.Error(w, "no autenticado", http.StatusUnauthorized)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	var req signer.WireRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "petición inválida", http.StatusBadRequest)
		return
	}

	// Dry-run: passthrough de la decisión (no pasa por los guardrails ni cuenta
	// para el rate limit, ya que no ejecuta nada).
	if req.DryRun {
		in, err := intentFrom(req, brokerCN, false)
		if err != nil {
			http.Error(w, "pubkey inválida", http.StatusBadRequest)
			return
		}
		issued, err := s.remote.SignIntent(in)
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		writeJSON(w, http.StatusOK, signer.WireResponse{Decision: issued.Decision})
		return
	}

	// Guardrails de comportamiento. El sujeto es el usuario final si la petición lo
	// porta (frontend OIDC); si no, el CN del broker.
	if s.behavior.Enabled() {
		subject := req.EndUser
		if subject == "" {
			subject = brokerCN
		}
		anomalies, exceeded := s.behavior.Check(subject, req.Host, req.Command)
		if s.behavior.Enforcing() {
			if exceeded {
				s.auditE(audit.Entry{Caller: brokerCN, Host: req.Host, Command: req.Command, Outcome: "rate-limited", Anomaly: "rate-exceeded"})
				http.Error(w, "límite de tasa excedido", http.StatusTooManyRequests)
				return
			}
			if len(anomalies) > 0 {
				// Verificar que el comando sería permitido antes de molestar a un humano.
				din, err := intentFrom(req, brokerCN, false)
				if err != nil {
					http.Error(w, "pubkey inválida", http.StatusBadRequest)
					return
				}
				din.DryRun = true
				d, err := s.remote.SignIntent(din)
				if err != nil || d.Decision == nil || !d.Decision.Allowed {
					s.auditE(audit.Entry{Caller: brokerCN, Host: req.Host, Command: req.Command, Outcome: "denied", Anomaly: strings.Join(anomalies, ","), Err: errString(err)})
					http.Error(w, "comando no permitido", http.StatusForbidden)
					return
				}
				s.requireApproval(w, brokerCN, req, "behavior", strings.Join(anomalies, ","))
				return
			}
		} else if len(anomalies) > 0 || exceeded {
			// Modo observe: auditar la anomalía y continuar.
			s.auditE(audit.Entry{Caller: brokerCN, Host: req.Host, Command: req.Command, Outcome: "anomaly", Anomaly: strings.Join(anomalies, ",")})
		}
	}

	in, err := intentFrom(req, brokerCN, false)
	if err != nil {
		http.Error(w, "pubkey inválida", http.StatusBadRequest)
		return
	}
	issued, err := s.remote.SignIntent(in)
	if err != nil {
		s.auditE(audit.Entry{Caller: brokerCN, Host: req.Host, Command: req.Command, Outcome: "denied", Err: err.Error()})
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	// Permitido y emitido: reenviar el certificado.
	if issued.Certificate != nil {
		s.auditE(audit.Entry{Caller: brokerCN, Host: req.Host, Command: req.Command, Serial: issued.Serial, Outcome: "forwarded"})
		writeJSON(w, http.StatusOK, signer.WireResponse{
			Certificate:     string(ssh.MarshalAuthorizedKey(issued.Certificate)),
			Serial:          issued.Serial,
			ElevationPrefix: issued.ElevationPrefix,
			Decision:        issued.Decision,
		})
		return
	}

	// Sin certificado: la command policy requiere aprobación humana.
	if issued.Decision != nil && issued.Decision.RequireApproval {
		s.requireApproval(w, brokerCN, req, issued.Decision.MatchedRule, "")
		return
	}

	// Estado inesperado: ni cert, ni dry-run, ni aprobación.
	http.Error(w, "respuesta del signer sin certificado", http.StatusBadGateway)
}

// requireApproval crea una solicitud de aprobación, notifica y responde 202.
// rule documenta el motivo (regla de command policy o "behavior"); anomaly lista
// las anomalías de comportamiento si la escalada vino de los guardrails.
func (s *server) requireApproval(w http.ResponseWriter, brokerCN string, req signer.WireRequest, rule, anomaly string) {
	a, err := s.registry.Create(req, brokerCN, &signer.DecisionInfo{RequireApproval: true, MatchedRule: rule})
	if err != nil {
		http.Error(w, "no se pudo crear la solicitud de aprobación", http.StatusInternalServerError)
		return
	}
	if nerr := s.notifier.Notify(*a); nerr != nil {
		log.Printf("advertencia: notificación de aprobación fallida: %v", nerr)
	}
	s.auditE(audit.Entry{Caller: brokerCN, Host: req.Host, Command: req.Command, Outcome: "approval-required", ApprovalID: a.ID, PolicyRule: rule, Anomaly: anomaly})
	writeJSON(w, http.StatusAccepted, map[string]string{"approval_id": a.ID, "status": string(control.StatusPending)})
}

// handleResult sirve el polling del broker sobre una solicitud de aprobación.
// Cuando está aprobada, reenvía al signer con approved=true y devuelve el cert.
func (s *server) handleResult(w http.ResponseWriter, r *http.Request) {
	pollerCN, err := auth.CallerCN(r)
	if err != nil {
		http.Error(w, "no autenticado", http.StatusUnauthorized)
		return
	}
	id := r.PathValue("id")
	a, ok := s.registry.Get(id)
	if !ok {
		http.Error(w, "solicitud desconocida", http.StatusNotFound)
		return
	}
	// Solo el broker que originó la solicitud puede recoger su resultado.
	if a.Caller != pollerCN {
		http.Error(w, "no autorizado", http.StatusForbidden)
		return
	}

	switch a.Status {
	case control.StatusPending:
		writeJSON(w, http.StatusAccepted, map[string]string{"status": string(a.Status)})
	case control.StatusDenied:
		s.auditE(audit.Entry{Caller: a.Caller, Host: a.Host, Command: a.Command, Outcome: "approval-denied", ApprovalID: a.ID, ApprovedBy: a.DecidedBy})
		http.Error(w, "aprobación denegada", http.StatusForbidden)
	case control.StatusExpired:
		s.auditE(audit.Entry{Caller: a.Caller, Host: a.Host, Command: a.Command, Outcome: "approval-timeout", ApprovalID: a.ID})
		http.Error(w, "aprobación expirada", http.StatusRequestTimeout)
	case control.StatusApproved:
		// Consumir la aprobación (una sola emisión por aprobación).
		if !s.registry.Consume(id) {
			http.Error(w, "aprobación ya utilizada", http.StatusGone)
			return
		}
		req, _ := s.registry.Request(id)
		in, err := intentFrom(req, a.Caller, true)
		if err != nil {
			http.Error(w, "pubkey inválida", http.StatusBadRequest)
			return
		}
		issued, err := s.remote.SignIntent(in)
		if err != nil || issued.Certificate == nil {
			s.auditE(audit.Entry{Caller: a.Caller, Host: a.Host, Command: a.Command, Outcome: "error", ApprovalID: a.ID, Err: errString(err)})
			http.Error(w, "firma tras aprobación fallida", http.StatusBadGateway)
			return
		}
		s.auditE(audit.Entry{Caller: a.Caller, Host: a.Host, Command: a.Command, Serial: issued.Serial, Outcome: "approval-granted", ApprovalID: a.ID, ApprovedBy: a.DecidedBy})
		writeJSON(w, http.StatusOK, signer.WireResponse{
			Certificate:     string(ssh.MarshalAuthorizedKey(issued.Certificate)),
			Serial:          issued.Serial,
			ElevationPrefix: issued.ElevationPrefix,
			Decision:        issued.Decision,
		})
	}
}

// handleHosts reenvía GET /v1/hosts al signer en nombre del broker (la cabecera
// X-On-Behalf-Of asegura que el filtrado por grupos sea el del broker original).
func (s *server) handleHosts(w http.ResponseWriter, r *http.Request) {
	brokerCN, err := auth.CallerCN(r)
	if err != nil {
		http.Error(w, "no autenticado", http.StatusUnauthorized)
		return
	}
	hosts, err := s.remote.FetchHosts(brokerCN)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	out := make(map[string]signer.WireHostInfo, len(hosts))
	for name, h := range hosts {
		out[name] = signer.WireHostInfo{
			Addr: h.Addr, User: h.User, HostKey: h.HostKey, Jump: h.Jump,
			AllowSudo: h.AllowSudo, AllowPTY: h.AllowPTY,
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// handleApprovalsList lista las solicitudes (solo aprobadores autorizados).
func (s *server) handleApprovalsList(w http.ResponseWriter, r *http.Request) {
	if !s.isApprover(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, s.registry.List())
}

// handleApprovalDecide resuelve una solicitud como aprobada o denegada.
func (s *server) handleApprovalDecide(w http.ResponseWriter, r *http.Request) {
	cn, ok := s.approver(r)
	if !ok {
		http.Error(w, "no autorizado para aprobar", http.StatusForbidden)
		return
	}
	id := r.PathValue("id")
	r.Body = http.MaxBytesReader(w, r.Body, 4*1024)
	var body struct {
		Approve bool `json:"approve"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "petición inválida", http.StatusBadRequest)
		return
	}
	a, err := s.registry.Decide(id, body.Approve, cn)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	outcome := "approval-denied"
	if body.Approve {
		outcome = "approval-decision-allow"
	}
	s.auditE(audit.Entry{Caller: a.Caller, Host: a.Host, Command: a.Command, Outcome: outcome, ApprovalID: a.ID, ApprovedBy: cn})
	writeJSON(w, http.StatusOK, a)
}

// approver devuelve el CN si está autorizado a aprobar; ok=false en otro caso.
func (s *server) approver(r *http.Request) (string, bool) {
	cn, err := auth.CallerCN(r)
	if err != nil {
		return "", false
	}
	if _, ok := s.approveCN[cn]; !ok {
		return "", false
	}
	return cn, true
}

func (s *server) isApprover(w http.ResponseWriter, r *http.Request) bool {
	if _, ok := s.approver(r); !ok {
		http.Error(w, "no autorizado", http.StatusForbidden)
		return false
	}
	return true
}

func (s *server) auditE(e audit.Entry) {
	if err := s.audit.Append(e); err != nil {
		log.Printf("advertencia: error escribiendo audit log del control plane: %v", err)
	}
}

// intentFrom convierte una WireRequest entrante en un Intent para el signer,
// fijando on_behalf_of (CN del broker) y, opcionalmente, approved.
func intentFrom(req signer.WireRequest, onBehalfOf string, approved bool) (signer.Intent, error) {
	pub, err := signer.ParsePublicKey(req.PublicKey)
	if err != nil {
		return signer.Intent{}, err
	}
	return signer.Intent{
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
		OnBehalfOf:    onBehalfOf,
		Approved:      approved,
		EndUser:       req.EndUser,
		EndUserGroups: req.EndUserGroups,
	}, nil
}

func cnSet(cns []string) map[string]struct{} {
	m := make(map[string]struct{}, len(cns))
	for _, cn := range cns {
		if cn != "" {
			m[cn] = struct{}{}
		}
	}
	return m
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("writeJSON: %v", err)
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
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
		c.Listen = ":7443"
	}
	return &c, nil
}
