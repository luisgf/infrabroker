package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/luisgf/ssh-broker/internal/audit"
	"github.com/luisgf/ssh-broker/internal/ca"
	"github.com/luisgf/ssh-broker/internal/control"
	"github.com/luisgf/ssh-broker/internal/signer"
)

// stubSigner devuelve un signer falso (HTTP plano) que emite un cert salvo para
// comandos "reboot*" sin approved, donde responde "requiere aprobación" (sin cert).
func stubSigner(t *testing.T) *httptest.Server {
	t.Helper()
	_, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	caSigner, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req signer.WireRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		needsApproval := strings.HasPrefix(req.Command, "reboot")
		// Dry-run: devolver solo la decisión (sin cert), como el signer real.
		if req.DryRun {
			_ = json.NewEncoder(w).Encode(signer.WireResponse{
				Decision: &signer.DecisionInfo{Allowed: true, RequireApproval: needsApproval},
			})
			return
		}
		if needsApproval && !req.Approved {
			_ = json.NewEncoder(w).Encode(signer.WireResponse{
				Decision: &signer.DecisionInfo{Allowed: true, RequireApproval: true, MatchedRule: "require_approval:^reboot"},
			})
			return
		}
		pub, _ := signer.ParsePublicKey(req.PublicKey)
		cert, serial, err := ca.BuildAndSign(caSigner, pub, ca.Constraints{Principal: "host:x", TTL: time.Minute})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(signer.WireResponse{
			Certificate: string(ssh.MarshalAuthorizedKey(cert)), Serial: serial,
		})
	}))
}

func testServer(t *testing.T, signerURL string) *server {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	al, err := audit.Open(filepath.Join(t.TempDir(), "cp_audit.log"), ed25519.NewKeyFromSeed(seed))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { al.Close() })
	return &server{
		remote:    signer.NewRemote(signerURL, nil, time.Second),
		registry:  control.NewRegistry(time.Minute),
		notifier:  control.LogNotifier{},
		behavior:  control.NewBehaviorTracker(control.BehaviorConfig{}), // off por defecto
		audit:     al,
		approveCN: map[string]struct{}{"broker-admin": {}},
	}
}

// req construye una petición con un CN de cliente mTLS sintético.
func req(t *testing.T, method, target, cn string, body any) *http.Request {
	t.Helper()
	var r *http.Request
	if body != nil {
		b, _ := json.Marshal(body)
		r = httptest.NewRequest(method, target, bytes.NewReader(b))
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: cn}}}}
	return r
}

// signReq construye una petición POST /v1/sign con el WireRequest dado.
func signReq(t *testing.T, cn string, body signer.WireRequest) *http.Request {
	t.Helper()
	return req(t, "POST", "/v1/sign", cn, body)
}

func wireReq(t *testing.T, command string) signer.WireRequest {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sshPub, _ := ssh.NewPublicKey(pub)
	return signer.WireRequest{
		Host: "web01", Role: signer.RoleTarget, Purpose: signer.PurposeOneshot,
		Command: command, PublicKey: string(ssh.MarshalAuthorizedKey(sshPub)),
	}
}

func TestControlPlaneForwardsAllowed(t *testing.T) {
	sig := stubSigner(t)
	defer sig.Close()
	s := testServer(t, sig.URL)

	w := httptest.NewRecorder()
	s.handleSign(w, req(t, "POST", "/v1/sign", "broker-1", wireReq(t, "uptime")))
	if w.Code != http.StatusOK {
		t.Fatalf("comando permitido debe devolver 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp signer.WireResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Certificate == "" {
		t.Error("debe devolver certificado")
	}
}

func TestControlPlaneApprovalFlow(t *testing.T) {
	sig := stubSigner(t)
	defer sig.Close()
	s := testServer(t, sig.URL)

	// 1. Petición que requiere aprobación → 202 + approval_id.
	w := httptest.NewRecorder()
	s.handleSign(w, req(t, "POST", "/v1/sign", "broker-1", wireReq(t, "reboot now")))
	if w.Code != http.StatusAccepted {
		t.Fatalf("debe devolver 202, got %d: %s", w.Code, w.Body.String())
	}
	var acc struct {
		ApprovalID string `json:"approval_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &acc); err != nil || acc.ApprovalID == "" {
		t.Fatalf("respuesta 202 inválida: %s", w.Body.String())
	}

	// 2. Poll antes de aprobar → 202 (pendiente).
	w = httptest.NewRecorder()
	rr := req(t, "GET", "/v1/sign/result/"+acc.ApprovalID, "broker-1", nil)
	rr.SetPathValue("id", acc.ApprovalID)
	s.handleResult(w, rr)
	if w.Code != http.StatusAccepted {
		t.Fatalf("pendiente debe devolver 202, got %d", w.Code)
	}

	// 3. Aprobar con un CN autorizado.
	w = httptest.NewRecorder()
	dr := req(t, "POST", "/v1/approvals/"+acc.ApprovalID, "broker-admin", map[string]bool{"approve": true})
	dr.SetPathValue("id", acc.ApprovalID)
	s.handleApprovalDecide(w, dr)
	if w.Code != http.StatusOK {
		t.Fatalf("aprobación debe devolver 200, got %d: %s", w.Code, w.Body.String())
	}

	// 4. Poll tras aprobar → 200 con certificado.
	w = httptest.NewRecorder()
	rr = req(t, "GET", "/v1/sign/result/"+acc.ApprovalID, "broker-1", nil)
	rr.SetPathValue("id", acc.ApprovalID)
	s.handleResult(w, rr)
	if w.Code != http.StatusOK {
		t.Fatalf("tras aprobar debe devolver 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp signer.WireResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Certificate == "" {
		t.Error("debe devolver certificado tras aprobación")
	}

	// 5. Segundo poll tras consumir → 410 Gone.
	w = httptest.NewRecorder()
	rr = req(t, "GET", "/v1/sign/result/"+acc.ApprovalID, "broker-1", nil)
	rr.SetPathValue("id", acc.ApprovalID)
	s.handleResult(w, rr)
	if w.Code != http.StatusGone {
		t.Errorf("segundo poll debe devolver 410, got %d", w.Code)
	}
}

func TestControlPlaneApprovalDenied(t *testing.T) {
	sig := stubSigner(t)
	defer sig.Close()
	s := testServer(t, sig.URL)

	w := httptest.NewRecorder()
	s.handleSign(w, req(t, "POST", "/v1/sign", "broker-1", wireReq(t, "reboot now")))
	var acc struct {
		ApprovalID string `json:"approval_id"`
	}
	json.Unmarshal(w.Body.Bytes(), &acc)

	// Denegar.
	w = httptest.NewRecorder()
	dr := req(t, "POST", "/v1/approvals/"+acc.ApprovalID, "broker-admin", map[string]bool{"approve": false})
	dr.SetPathValue("id", acc.ApprovalID)
	s.handleApprovalDecide(w, dr)
	if w.Code != http.StatusOK {
		t.Fatalf("decisión debe devolver 200, got %d", w.Code)
	}

	// Poll tras denegar → 403.
	w = httptest.NewRecorder()
	rr := req(t, "GET", "/v1/sign/result/"+acc.ApprovalID, "broker-1", nil)
	rr.SetPathValue("id", acc.ApprovalID)
	s.handleResult(w, rr)
	if w.Code != http.StatusForbidden {
		t.Errorf("denegada debe devolver 403, got %d", w.Code)
	}
}

func TestControlPlaneApproverAuthz(t *testing.T) {
	sig := stubSigner(t)
	defer sig.Close()
	s := testServer(t, sig.URL)

	w := httptest.NewRecorder()
	s.handleSign(w, req(t, "POST", "/v1/sign", "broker-1", wireReq(t, "reboot now")))
	var acc struct {
		ApprovalID string `json:"approval_id"`
	}
	json.Unmarshal(w.Body.Bytes(), &acc)

	// Un CN no autorizado no puede aprobar.
	w = httptest.NewRecorder()
	dr := req(t, "POST", "/v1/approvals/"+acc.ApprovalID, "broker-1", map[string]bool{"approve": true})
	dr.SetPathValue("id", acc.ApprovalID)
	s.handleApprovalDecide(w, dr)
	if w.Code != http.StatusForbidden {
		t.Errorf("CN no aprobador debe recibir 403, got %d", w.Code)
	}
}

func TestControlPlaneBehaviorEnforceEscalates(t *testing.T) {
	sig := stubSigner(t)
	defer sig.Close()
	s := testServer(t, sig.URL)
	s.behavior = control.NewBehaviorTracker(control.BehaviorConfig{Mode: control.BehaviorEnforce})

	// 1ª petición: línea base → se emite normalmente (200 con cert).
	w := httptest.NewRecorder()
	s.handleSign(w, req(t, "POST", "/v1/sign", "broker-1", wireReq(t, "uptime")))
	if w.Code != http.StatusOK {
		t.Fatalf("línea base debe emitir cert (200), got %d: %s", w.Code, w.Body.String())
	}

	// 2ª petición a un host nuevo (uptime es comando conocido, db99 host nuevo)
	// → anomalía → en enforce escala a aprobación (202).
	w = httptest.NewRecorder()
	r := wireReq(t, "uptime")
	r.Host = "db99"
	s.handleSign(w, signReq(t, "broker-1", r))
	if w.Code != http.StatusAccepted {
		t.Fatalf("host nuevo en enforce debe escalar a aprobación (202), got %d: %s", w.Code, w.Body.String())
	}
}

func TestControlPlaneBehaviorRateLimit(t *testing.T) {
	sig := stubSigner(t)
	defer sig.Close()
	s := testServer(t, sig.URL)
	s.behavior = control.NewBehaviorTracker(control.BehaviorConfig{Mode: control.BehaviorEnforce, RateLimitPerMin: 2})

	codes := make([]int, 0, 3)
	for i := 0; i < 3; i++ {
		w := httptest.NewRecorder()
		s.handleSign(w, signReq(t, "broker-1", wireReq(t, "uptime")))
		codes = append(codes, w.Code)
	}
	// Las dos primeras pasan; la tercera supera el límite → 429.
	if codes[2] != http.StatusTooManyRequests {
		t.Errorf("3ª petición debe ser 429 (límite 2/min), got %v", codes)
	}
}

func TestControlPlaneBehaviorObserveDoesNotBlock(t *testing.T) {
	sig := stubSigner(t)
	defer sig.Close()
	s := testServer(t, sig.URL)
	s.behavior = control.NewBehaviorTracker(control.BehaviorConfig{Mode: control.BehaviorObserve, RateLimitPerMin: 1})

	// Aunque se supere el límite, observe NO bloquea: ambas devuelven cert.
	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		s.handleSign(w, signReq(t, "broker-1", wireReq(t, "uptime")))
		if w.Code != http.StatusOK {
			t.Fatalf("observe no debe bloquear, petición %d got %d", i, w.Code)
		}
	}
}

func TestControlPlaneResultOwnerOnly(t *testing.T) {
	sig := stubSigner(t)
	defer sig.Close()
	s := testServer(t, sig.URL)

	w := httptest.NewRecorder()
	s.handleSign(w, req(t, "POST", "/v1/sign", "broker-1", wireReq(t, "reboot now")))
	var acc struct {
		ApprovalID string `json:"approval_id"`
	}
	json.Unmarshal(w.Body.Bytes(), &acc)

	// Otro broker no puede recoger el resultado.
	w = httptest.NewRecorder()
	rr := req(t, "GET", "/v1/sign/result/"+acc.ApprovalID, "broker-2", nil)
	rr.SetPathValue("id", acc.ApprovalID)
	s.handleResult(w, rr)
	if w.Code != http.StatusForbidden {
		t.Errorf("otro broker debe recibir 403, got %d", w.Code)
	}
}
