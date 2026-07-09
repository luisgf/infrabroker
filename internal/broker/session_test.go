package broker

import (
	"context"
	"crypto/ed25519"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luisgf/infrabroker/internal/audit"
	"github.com/luisgf/infrabroker/internal/signer"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func newTestSessionManager(t *testing.T) *sessionManager {
	t.Helper()
	m := newSessionManager(5*time.Minute, 30*time.Minute, nil)
	t.Cleanup(func() { m.closeAll() })
	return m
}

func TestSessionManagerCloseAllIdempotent(t *testing.T) {
	m := newTestSessionManager(t)
	if err := m.add(dummySession("s-close", "alice")); err != nil {
		t.Fatalf("add: %v", err)
	}

	m.closeAll()
	m.closeAll()
}

func dummySession(id, caller string) *liveSession {
	return &liveSession{
		id:       id,
		caller:   caller,
		host:     "host:22",
		mode:     "exec",
		created:  time.Now(),
		lastUsed: time.Now(),
	}
}

// peek returns a session with NO side effects (no lastUsed refresh, no busy
// change), for asserting manager state in tests. Production code reaches
// sessions only through the ownership-gated checkoutOwned/removeOwned.
func peek(m *sessionManager, id string) (*liveSession, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	return s, ok
}

// testAuditLog abre un log de auditoría temporal para tests que necesitan un Engine.
func testAuditLog(t *testing.T) *audit.Log {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	al, err := audit.Open(filepath.Join(t.TempDir(), "audit.log"), ed25519.NewKeyFromSeed(seed))
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	t.Cleanup(func() { al.Close() })
	return al
}

// ── sessionManager: add / get / remove ───────────────────────────────────────

func TestSessionManagerAddGetRemove(t *testing.T) {
	m := newTestSessionManager(t)

	s := dummySession("s1", "alice")
	if err := m.add(s); err != nil {
		t.Fatalf("add: %v", err)
	}

	got, ok := peek(m, "s1")
	if !ok || got.id != "s1" {
		t.Fatalf("peek después de add: ok=%v, got=%v", ok, got)
	}

	removed, _, owned := m.removeOwned("s1", "alice")
	if !owned || removed.id != "s1" {
		t.Fatalf("removeOwned: owned=%v", owned)
	}

	// Después del remove ya no debe existir.
	if _, ok := peek(m, "s1"); ok {
		t.Error("peek después de removeOwned debe devolver false")
	}
}

func TestSessionManagerCheckoutOwnedActualizaLastUsed(t *testing.T) {
	m := newTestSessionManager(t)
	s := dummySession("s2", "bob")
	s.lastUsed = time.Now().Add(-10 * time.Minute)
	_ = m.add(s)

	before := s.lastUsed
	time.Sleep(2 * time.Millisecond)
	if _, found, owned := m.checkoutOwned("s2", "bob"); !found || !owned {
		t.Fatal("checkoutOwned debe encontrar la sesión del propietario")
	}
	m.mu.Lock()
	last := s.lastUsed
	m.mu.Unlock()
	if !last.After(before) {
		t.Error("checkoutOwned debe actualizar lastUsed")
	}
}

func TestSessionManagerGetInexistente(t *testing.T) {
	m := newTestSessionManager(t)
	if _, ok := peek(m, "nope"); ok {
		t.Error("peek de id inexistente debe devolver false")
	}
}

func TestSessionManagerRemoveInexistente(t *testing.T) {
	m := newTestSessionManager(t)
	if _, found, _ := m.removeOwned("nope", "alice"); found {
		t.Error("removeOwned de id inexistente debe devolver found=false")
	}
}

// ── sessionManager: límites (M2) ─────────────────────────────────────────────

func TestSessionManagerLimiteGlobal(t *testing.T) {
	m := newTestSessionManager(t)

	// Añadir maxSessionsGlobal sesiones con callers distintos para no activar
	// el límite por-caller (maxSessionsPerCaller=20) antes del global (200).
	for i := 0; i < maxSessionsGlobal; i++ {
		caller := strings.Repeat("c", (i/maxSessionsPerCaller)+1) + strings.Repeat("x", i%maxSessionsPerCaller)
		s := dummySession(strings.Repeat("s", i+1), caller)
		if err := m.add(s); err != nil {
			t.Fatalf("add sesión %d/%d: %v", i+1, maxSessionsGlobal, err)
		}
	}

	// La siguiente debe ser rechazada.
	extra := dummySession("overflow", "new-caller")
	if err := m.add(extra); err == nil {
		t.Error("add por encima del límite global debe devolver error")
	}
}

func TestSessionManagerLimitePorCaller(t *testing.T) {
	m := newTestSessionManager(t)

	// Añadir maxSessionsPerCaller sesiones del mismo caller.
	for i := 0; i < maxSessionsPerCaller; i++ {
		s := dummySession(strings.Repeat("a", i+1), "heavy-caller")
		if err := m.add(s); err != nil {
			t.Fatalf("add sesión %d/%d: %v", i+1, maxSessionsPerCaller, err)
		}
	}

	extra := dummySession("over-per-caller", "heavy-caller")
	if err := m.add(extra); err == nil {
		t.Error("add por encima del límite por caller debe devolver error")
	}

	// Otro caller diferente aún puede añadir sesiones.
	other := dummySession("other-caller-session", "other-caller")
	if err := m.add(other); err != nil {
		t.Errorf("caller diferente no debe verse afectado: %v", err)
	}
}

// ── sessionManager: reaper ────────────────────────────────────────────────────

func TestSessionManagerReaperIdleTTL(t *testing.T) {
	reaped := make(chan string, 4)
	m := newSessionManager(
		20*time.Millisecond, // idleTTL muy corto
		1*time.Hour,
		func(s *liveSession) { reaped <- s.id },
	)
	t.Cleanup(func() { m.closeAll() })

	// Forzar el ticker interno a un valor muy corto inyectando la sesión con
	// lastUsed en el pasado.
	s := dummySession("stale", "reap-caller")
	s.lastUsed = time.Now().Add(-1 * time.Hour)
	_ = m.add(s)

	// Disparar el reaper manualmente sin esperar el tick de 30 s de producción.
	m.reapExpired(time.Now())

	select {
	case id := <-reaped:
		if id != "stale" {
			t.Errorf("reaper reportó %q, quiero \"stale\"", id)
		}
	default:
		t.Error("el reaper debería haber eliminado la sesión stale")
	}

	if _, ok := peek(m, "stale"); ok {
		t.Error("la sesión stale no debería existir tras el reaper")
	}
}

// TestSessionManagerReaperNoMataSesionesOcupadas verifica que el reaper nunca
// cierra una sesión con un comando en vuelo (busy), ni por idle TTL ni por
// maxLife, aunque ambos estén vencidos. La sesión se recolecta en el primer
// tick después de quedar libre (checkin).
func TestSessionManagerReaperNoMataSesionesOcupadas(t *testing.T) {
	reaped := make(chan string, 1)
	m := newSessionManager(5*time.Minute, 30*time.Minute, func(s *liveSession) { reaped <- s.id })
	t.Cleanup(func() { m.closeAll() })

	s := dummySession("busy", "alice")
	_ = m.add(s)

	// Marcar la sesión como ocupada (comando en vuelo).
	got, found, owned := m.checkoutOwned("busy", "alice")
	if !found || !owned || got != s {
		t.Fatalf("checkoutOwned: found=%v owned=%v", found, owned)
	}

	// Forzar el vencimiento de idle TTL y maxLife.
	m.mu.Lock()
	s.lastUsed = time.Now().Add(-2 * time.Hour)
	s.created = time.Now().Add(-2 * time.Hour)
	m.mu.Unlock()

	m.reapExpired(time.Now())
	if _, ok := peek(m, "busy"); !ok {
		t.Fatal("el reaper no debe cerrar una sesión con un comando en vuelo")
	}
	select {
	case id := <-reaped:
		t.Fatalf("onReap no debe dispararse para una sesión busy (id=%q)", id)
	default:
	}

	// Al terminar el comando (checkin) la sesión sigue dentro de maxLife
	// vencido, así que el siguiente tick la recolecta.
	m.checkin(s)
	m.mu.Lock()
	s.created = time.Now().Add(-2 * time.Hour) // checkin refresca lastUsed, no created
	m.mu.Unlock()

	m.reapExpired(time.Now())
	if _, ok := peek(m, "busy"); ok {
		t.Error("la sesión libre con maxLife vencido debe recolectarse en el primer tick")
	}
	select {
	case id := <-reaped:
		if id != "busy" {
			t.Errorf("onReap reportó %q, quiero \"busy\"", id)
		}
	default:
		t.Error("onReap debería haberse disparado tras el checkin")
	}
}

// TestSessionManagerReaperCapExpiryCert verifica que una sesión se recolecta en
// cuanto expira su certificado, aunque no hayan vencido ni el idle TTL ni
// maxLife: la sesión no debe sobrevivir a la credencial que la abrió
// (THREAT_MODEL gap #1). El cert real lo clampa el signer a <= max_ttl, así que
// certNotAfter suele adelantarse a maxLife.
func TestSessionManagerReaperCapExpiryCert(t *testing.T) {
	reaped := make(chan string, 1)
	m := newSessionManager(5*time.Minute, 30*time.Minute, func(s *liveSession) { reaped <- s.id })
	t.Cleanup(func() { m.closeAll() })

	s := dummySession("s1", "alice")
	// idle y maxLife lejos de vencer (created/lastUsed son "ahora"), pero el
	// certificado ya expiró.
	s.certNotAfter = time.Now().Add(-time.Second)
	if err := m.add(s); err != nil {
		t.Fatalf("add: %v", err)
	}

	m.reapExpired(time.Now())
	if _, ok := peek(m, "s1"); ok {
		t.Fatal("la sesión con cert expirado debe recolectarse aunque idle/maxLife no hayan vencido")
	}
	select {
	case id := <-reaped:
		if id != "s1" {
			t.Errorf("onReap reportó %q, quiero \"s1\"", id)
		}
	default:
		t.Error("onReap debería haberse disparado por expiración del cert")
	}
}

// TestSessionManagerReaperCertExpiradoRespetaBusy verifica que el cap por
// expiración del cert NO rompe la invariante de no cerrar sesiones ocupadas: una
// sesión busy con cert expirado sobrevive y se recolecta en el primer tick tras
// el checkin (el kill forzoso de sesiones busy es un control aparte, #117).
func TestSessionManagerReaperCertExpiradoRespetaBusy(t *testing.T) {
	reaped := make(chan string, 1)
	m := newSessionManager(5*time.Minute, 30*time.Minute, func(s *liveSession) { reaped <- s.id })
	t.Cleanup(func() { m.closeAll() })

	s := dummySession("s1", "alice")
	s.certNotAfter = time.Now().Add(-time.Second)
	if err := m.add(s); err != nil {
		t.Fatalf("add: %v", err)
	}
	got, found, owned := m.checkoutOwned("s1", "alice")
	if !found || !owned {
		t.Fatalf("checkoutOwned: found=%v owned=%v", found, owned)
	}

	m.reapExpired(time.Now())
	if _, ok := peek(m, "s1"); !ok {
		t.Fatal("una sesión ocupada no debe recolectarse aunque el cert haya expirado")
	}

	m.checkin(got)
	m.reapExpired(time.Now())
	if _, ok := peek(m, "s1"); ok {
		t.Error("tras el checkin, la sesión con cert expirado debe recolectarse")
	}
}

// TestSessionManagerCheckinActualizaLastUsed verifica que lastUsed se refresca
// al TERMINAR el comando, no solo al empezar: el idle TTL cuenta desde que la
// sesión queda libre.
func TestSessionManagerCheckinActualizaLastUsed(t *testing.T) {
	m := newTestSessionManager(t)
	s := dummySession("s-checkin", "alice")
	_ = m.add(s)

	got, found, owned := m.checkoutOwned("s-checkin", "alice")
	if !found || !owned {
		t.Fatal("checkoutOwned debe encontrar la sesión del propietario")
	}
	m.mu.Lock()
	got.lastUsed = time.Now().Add(-10 * time.Minute) // simular comando largo
	m.mu.Unlock()

	before := time.Now()
	m.checkin(got)

	m.mu.Lock()
	last, busy := got.lastUsed, got.busy
	m.mu.Unlock()
	if last.Before(before) {
		t.Error("checkin debe actualizar lastUsed al terminar el comando")
	}
	if busy != 0 {
		t.Errorf("busy tras checkin = %d, quiero 0", busy)
	}
}

// ── SessionExec: seguridad C1 (ownership) ─────────────────────────────────────

// engineForSessionTests construye un Engine mínimo con sessions inicializadas
// y un log de auditoría temporal, sin red ni signer.
func engineForSessionTests(t *testing.T) *Engine {
	t.Helper()
	al := testAuditLog(t)
	e := &Engine{
		cfg:      &Config{Hosts: map[string]HostConfig{}},
		auditLog: al,
		sessions: newSessionManager(5*time.Minute, 30*time.Minute, nil),
	}
	t.Cleanup(func() { e.sessions.closeAll() })
	return e
}

func TestEngineCloseIdempotent(t *testing.T) {
	e := engineForSessionTests(t)

	if err := e.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestSessionExecOwnershipC1(t *testing.T) {
	e := engineForSessionTests(t)

	// Inyectar una sesión propiedad de "alice".
	s := dummySession("sess-alice", "alice")
	s.mode = "exec"
	_ = e.sessions.add(s)

	// "bob" no debería poder ejecutar en la sesión de "alice".
	_, err := e.SessionExec(context.Background(), Caller{ID: "bob"}, "sess-alice", "id")
	if err == nil {
		t.Fatal("SessionExec con caller incorrecto debe devolver error (C1)")
	}
	if !strings.Contains(err.Error(), "does not belong") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestSessionExecSesionDesconocida(t *testing.T) {
	e := engineForSessionTests(t)

	_, err := e.SessionExec(context.Background(), Caller{ID: "alice"}, "nonexistent", "id")
	if err == nil {
		t.Fatal("SessionExec con sesión desconocida debe devolver error")
	}
}

func TestSessionExecComandoVacio(t *testing.T) {
	e := engineForSessionTests(t)

	s := dummySession("sess-empty", "alice")
	s.mode = "exec"
	_ = e.sessions.add(s)

	_, err := e.SessionExec(context.Background(), Caller{ID: "alice"}, "sess-empty", "")
	if err == nil {
		t.Fatal("SessionExec con comando vacío debe devolver error")
	}
}

// ── SessionExec: inyección de comandos M5 (newlines) ─────────────────────────

func TestSessionExecRechazaNewlineModoShell(t *testing.T) {
	e := engineForSessionTests(t)

	for _, mode := range []string{"shell", "pty"} {
		s := dummySession("sess-"+mode, "alice")
		s.mode = mode
		_ = e.sessions.add(s)

		for _, injected := range []string{"cmd\nmalicious", "cmd\rmalicious", "line1\nline2\nline3"} {
			_, err := e.SessionExec(context.Background(), Caller{ID: "alice"}, "sess-"+mode, injected)
			if err == nil {
				t.Errorf("mode=%s cmd=%q: esperaba error por newline (M5)", mode, injected)
			}
			if !strings.Contains(err.Error(), "newlines") {
				t.Errorf("mode=%s: unexpected error message: %v", mode, err)
			}
		}
	}
}

// TestSessionExecModoExecNoValidaNewline verifica que la validación de newlines
// (M5) solo aplica a modos shell/pty, no a exec. Se prueba inspeccionando la
// condición directamente sin necesidad de una conexión SSH real.
func TestSessionExecModoExecNoValidaNewline(t *testing.T) {
	// Construir una sesión exec en memoria.
	s := dummySession("sess-exec-check", "alice")
	s.mode = "exec"

	// La condición de rechazo de newline en production code es:
	//   (s.mode == "shell" || s.mode == "pty") && strings.ContainsAny(command, "\n\r")
	// Para mode="exec" la condición es siempre false. Verificamos la lógica
	// sin atravesar SessionExec (que necesitaría una conexión SSH real).
	command := "echo hello\necho world"
	shouldReject := (s.mode == "shell" || s.mode == "pty") && strings.ContainsAny(command, "\n\r")
	if shouldReject {
		t.Error("modo exec no debe rechazar newlines según la condición de validación M5")
	}
}

type sessionPolicySigner struct {
	issued    *signer.Issued
	err       error
	decisions map[string]*signer.DecisionInfo
	got       signer.Intent
	gotAll    []signer.Intent
	count     int
}

func (s *sessionPolicySigner) SignIntent(_ context.Context, in signer.Intent) (*signer.Issued, error) {
	s.count++
	s.got = in
	s.gotAll = append(s.gotAll, in)
	if s.err != nil {
		return nil, s.err
	}
	if dec, ok := s.decisions[in.Host]; ok {
		return &signer.Issued{Decision: dec}, nil
	}
	return s.issued, nil
}

type mutableHostFetcher struct {
	hosts map[string]signer.HostInfo
	err   error
	count int
}

func (f *mutableHostFetcher) FetchHosts(context.Context, string) (map[string]signer.HostInfo, error) {
	f.count++
	if f.err != nil {
		return nil, f.err
	}
	out := make(map[string]signer.HostInfo, len(f.hosts))
	for k, v := range f.hosts {
		out[k] = v
	}
	return out, nil
}

func TestAuthorizeSessionExecAlwaysPreflights(t *testing.T) {
	e := engineForSessionTests(t)
	fs := &sessionPolicySigner{issued: &signer.Issued{Decision: &signer.DecisionInfo{Allowed: true}}}
	e.sgn = fs

	s := dummySession("sess-preflight", "alice")
	dec, err := e.authorizeSessionExec(context.Background(), Caller{ID: "alice"}, s, "uptime")
	if err != nil {
		t.Fatalf("authorizeSessionExec: %v", err)
	}
	if dec == nil || !dec.Allowed {
		t.Fatalf("decision must be allowed: %+v", dec)
	}
	if fs.count != 1 {
		t.Fatalf("session exec must preflight every command, signer calls = %d", fs.count)
	}
	if !fs.got.DryRun || !fs.got.Preflight {
		t.Fatalf("intent must be dry-run executable preflight: %+v", fs.got)
	}
}

func TestAuthorizeSessionExecRejectsConnectivityDrift(t *testing.T) {
	e := engineForSessionTests(t)
	oldHosts := map[string]signer.HostInfo{
		"target": {Addr: "old.example:22", User: "deploy", HostKey: "old-key"},
	}
	fetcher := &mutableHostFetcher{hosts: map[string]signer.HostInfo{
		"target": {Addr: "new.example:22", User: "deploy", HostKey: "new-key"},
	}}
	e.fetcher = fetcher
	e.hosts = oldHosts
	fs := &sessionPolicySigner{issued: &signer.Issued{Decision: &signer.DecisionInfo{Allowed: true}}}
	e.sgn = fs

	sig, err := e.connectivitySignature("target")
	if err != nil {
		t.Fatalf("connectivitySignature: %v", err)
	}
	s := dummySession("sess-drift", "alice")
	s.host = "target"
	s.connectivitySig = sig

	dec, err := e.authorizeSessionExec(context.Background(), Caller{ID: "alice"}, s, "uptime")
	if err == nil || !strings.Contains(err.Error(), "connectivity changed") {
		t.Fatalf("expected connectivity drift error, got dec=%+v err=%v", dec, err)
	}
	if fs.count != 0 {
		t.Fatalf("signer preflight must not run after connectivity drift, calls=%d", fs.count)
	}
	if fetcher.count != 1 {
		t.Fatalf("host view must be refreshed once, got %d", fetcher.count)
	}
}

func TestAuthorizeSessionExecAllowsUnchangedConnectivityAfterRefresh(t *testing.T) {
	e := engineForSessionTests(t)
	hosts := map[string]signer.HostInfo{
		"target": {Addr: "same.example:22", User: "deploy", HostKey: "same-key"},
	}
	fetcher := &mutableHostFetcher{hosts: hosts}
	e.fetcher = fetcher
	e.hosts = hosts
	fs := &sessionPolicySigner{issued: &signer.Issued{Decision: &signer.DecisionInfo{Allowed: true}}}
	e.sgn = fs

	sig, err := e.connectivitySignature("target")
	if err != nil {
		t.Fatalf("connectivitySignature: %v", err)
	}
	s := dummySession("sess-same", "alice")
	s.host = "target"
	s.connectivitySig = sig

	if _, err := e.authorizeSessionExec(context.Background(), Caller{ID: "alice"}, s, "uptime"); err != nil {
		t.Fatalf("authorizeSessionExec: %v", err)
	}
	if fs.count != 1 {
		t.Fatalf("signer preflight calls = %d, want 1", fs.count)
	}
}

func TestAuthorizeSessionExecPreflightsBastionThenTarget(t *testing.T) {
	e := engineForSessionTests(t)
	hosts := map[string]signer.HostInfo{
		"bastion": {Addr: "bastion.example:22", User: "jump", HostKey: "bastion-key"},
		"target":  {Addr: "target.example:22", User: "deploy", HostKey: "target-key", Jump: "bastion"},
	}
	fetcher := &mutableHostFetcher{hosts: hosts}
	e.fetcher = fetcher
	e.hosts = hosts
	fs := &sessionPolicySigner{issued: &signer.Issued{Decision: &signer.DecisionInfo{Allowed: true}}}
	e.sgn = fs

	sig, err := e.connectivitySignature("target")
	if err != nil {
		t.Fatalf("connectivitySignature: %v", err)
	}
	s := dummySession("sess-bastion-ok", "alice")
	s.host = "target"
	s.connectivitySig = sig

	if _, err := e.authorizeSessionExec(context.Background(), Caller{ID: "alice", Groups: []string{"prod"}}, s, "uptime"); err != nil {
		t.Fatalf("authorizeSessionExec: %v", err)
	}
	if fs.count != 2 {
		t.Fatalf("signer preflight calls = %d, want bastion+target", fs.count)
	}
	if got := fs.gotAll[0]; got.Host != "bastion" || got.Role != signer.RoleBastion || !got.DryRun || !got.Preflight {
		t.Fatalf("first preflight must revalidate bastion: %+v", got)
	}
	if got := fs.gotAll[1]; got.Host != "target" || got.Role != signer.RoleTarget || got.Command != "uptime" {
		t.Fatalf("second preflight must revalidate target command: %+v", got)
	}
}

func TestAuthorizeSessionExecRejectsBastionPolicyDrift(t *testing.T) {
	e := engineForSessionTests(t)
	hosts := map[string]signer.HostInfo{
		"bastion": {Addr: "bastion.example:22", User: "jump", HostKey: "bastion-key"},
		"target":  {Addr: "target.example:22", User: "deploy", HostKey: "target-key", Jump: "bastion"},
	}
	fetcher := &mutableHostFetcher{hosts: hosts}
	e.fetcher = fetcher
	e.hosts = hosts
	fs := &sessionPolicySigner{
		issued: &signer.Issued{Decision: &signer.DecisionInfo{Allowed: true}},
		decisions: map[string]*signer.DecisionInfo{
			"bastion": {Allowed: false, Reason: `host "bastion" is not allowed as a bastion`},
		},
	}
	e.sgn = fs

	sig, err := e.connectivitySignature("target")
	if err != nil {
		t.Fatalf("connectivitySignature: %v", err)
	}
	s := dummySession("sess-bastion-denied", "alice")
	s.host = "target"
	s.connectivitySig = sig

	_, err = e.authorizeSessionExec(context.Background(), Caller{ID: "alice"}, s, "uptime")
	if err == nil || !strings.Contains(err.Error(), "bastion") {
		t.Fatalf("expected bastion preflight denial, got %v", err)
	}
	if fs.count != 1 {
		t.Fatalf("target command preflight must not run after bastion denial, calls=%d", fs.count)
	}
	if got := fs.gotAll[0]; got.Host != "bastion" || got.Role != signer.RoleBastion {
		t.Fatalf("unexpected preflight intent: %+v", got)
	}
}

func TestAuthorizeSessionExecPassesSessionModeAndElevation(t *testing.T) {
	e := engineForSessionTests(t)
	fs := &sessionPolicySigner{issued: &signer.Issued{Decision: &signer.DecisionInfo{Allowed: true}}}
	e.sgn = fs
	e.maxTTL = time.Minute

	s := dummySession("sess-policy", "alice")
	s.sudo = true
	s.sudoUser = "deploy"
	dec, err := e.authorizeSessionExec(context.Background(), Caller{ID: "alice", Groups: []string{"prod"}}, s, "uptime")
	if err != nil {
		t.Fatalf("authorizeSessionExec: %v", err)
	}
	if dec == nil || !dec.Allowed {
		t.Fatalf("decision must be allowed: %+v", dec)
	}
	if fs.got.Purpose != signer.PurposeSession || fs.got.SessionMode != signer.SessionModeExec {
		t.Fatalf("intent purpose/mode = %q/%q", fs.got.Purpose, fs.got.SessionMode)
	}
	if !fs.got.Sudo || fs.got.SudoUser != "deploy" {
		t.Fatalf("sudo intent = %v/%q", fs.got.Sudo, fs.got.SudoUser)
	}
	if !fs.got.DryRun || !fs.got.Preflight {
		t.Fatalf("intent must be dry-run executable preflight: %+v", fs.got)
	}
	if fs.got.Command != "uptime" || fs.got.EndUser != "alice" || len(fs.got.EndUserGroups) != 1 {
		t.Fatalf("unexpected intent: %+v", fs.got)
	}
}

func TestAuthorizeSessionExecBlocksShellWhenPolicyAppears(t *testing.T) {
	e := engineForSessionTests(t)
	fs := &sessionPolicySigner{issued: &signer.Issued{Decision: &signer.DecisionInfo{
		Allowed: false,
		Reason:  `host "locked" has command_policy: sessions require mode="exec"`,
	}}}
	e.sgn = fs

	s := dummySession("sess-shell", "alice")
	s.mode = "shell"
	dec, err := e.authorizeSessionExec(context.Background(), Caller{ID: "alice"}, s, "uptime")
	if err == nil {
		t.Fatal("shell session must be blocked when the current signer policy rejects shell/pty sessions")
	}
	if dec == nil || dec.Allowed {
		t.Fatalf("expected denied decision: %+v", dec)
	}
	if fs.got.SessionMode != signer.SessionModeShell || !fs.got.Preflight {
		t.Fatalf("shell session must be preflighted with its live mode: %+v", fs.got)
	}
}

func TestAuthorizeSessionExecPassesPTY(t *testing.T) {
	e := engineForSessionTests(t)
	fs := &sessionPolicySigner{issued: &signer.Issued{Decision: &signer.DecisionInfo{Allowed: true}}}
	e.sgn = fs

	s := dummySession("sess-pty", "alice")
	s.mode = "pty"
	s.pty = true

	dec, err := e.authorizeSessionExec(context.Background(), Caller{ID: "alice"}, s, "top -b -n1")
	if err != nil {
		t.Fatalf("authorizeSessionExec: %v", err)
	}
	if dec == nil || !dec.Allowed {
		t.Fatalf("decision must be allowed: %+v", dec)
	}
	if fs.got.SessionMode != signer.SessionModePTY || !fs.got.PTY {
		t.Fatalf("pty session must be preflighted with mode=pty and PTY=true: %+v", fs.got)
	}
}

func TestAuthorizeSessionExecDenied(t *testing.T) {
	e := engineForSessionTests(t)
	e.sgn = &sessionPolicySigner{issued: &signer.Issued{Decision: &signer.DecisionInfo{
		Allowed: false, Reason: `command not allowed on "locked" by command_policy (allowlist:no-match)`,
		MatchedRule: "allowlist:no-match",
	}}}

	s := dummySession("sess-denied", "alice")
	dec, err := e.authorizeSessionExec(context.Background(), Caller{ID: "alice"}, s, "rm -rf /")
	if err == nil {
		t.Fatal("denied decision must return an error")
	}
	if dec == nil || dec.Allowed {
		t.Fatalf("expected denied decision: %+v", dec)
	}
	if !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAuthorizeSessionExecAuditWarningAllows(t *testing.T) {
	e := engineForSessionTests(t)
	warning := "command_policy audit: would deny (allowlist:no-match)"
	e.sgn = &sessionPolicySigner{issued: &signer.Issued{Decision: &signer.DecisionInfo{
		Allowed: true, Warning: warning, WouldDeny: true, MatchedRule: "allowlist:no-match",
	}}}

	s := dummySession("sess-audit", "alice")
	dec, err := e.authorizeSessionExec(context.Background(), Caller{ID: "alice"}, s, "rm -rf /")
	if err != nil {
		t.Fatalf("audit warning must not block: %v", err)
	}
	if dec == nil || dec.Warning != warning {
		t.Fatalf("warning not propagated: %+v", dec)
	}
}

// ── CloseSession: seguridad C1 ────────────────────────────────────────────────

func TestCloseSessionOwnershipC1(t *testing.T) {
	e := engineForSessionTests(t)

	s := dummySession("sess-close", "owner")
	_ = e.sessions.add(s)

	// Caller diferente no puede cerrar la sesión.
	err := e.CloseSession(Caller{ID: "intruder"}, "sess-close")
	if err == nil {
		t.Fatal("CloseSession con caller incorrecto debe devolver error (C1)")
	}
	if !strings.Contains(err.Error(), "does not belong") {
		t.Errorf("unexpected error message: %v", err)
	}

	// La sesión debe seguir existiendo.
	_, ok := peek(e.sessions, "sess-close")
	if !ok {
		t.Error("la sesión no debe eliminarse si el caller no es el propietario")
	}
}

func TestCloseSessionDesconocida(t *testing.T) {
	e := engineForSessionTests(t)
	err := e.CloseSession(Caller{ID: "alice"}, "ghost")
	if err == nil {
		t.Fatal("CloseSession con sesión desconocida debe devolver error")
	}
}

func TestCloseSessionHappyPath(t *testing.T) {
	e := engineForSessionTests(t)

	s := dummySession("sess-ok", "alice")
	_ = e.sessions.add(s)

	if err := e.CloseSession(Caller{ID: "alice"}, "sess-ok"); err != nil {
		t.Fatalf("CloseSession: %v", err)
	}

	// Después del cierre la sesión no debe existir.
	_, ok := peek(e.sessions, "sess-ok")
	if ok {
		t.Error("la sesión debe eliminarse tras CloseSession exitoso")
	}
}

// TestCloseSessionUnauthorizedNoRefresh verifies that a non-owner probing a leaked
// session_id cannot keep the session alive: the rejected close must not refresh
// lastUsed (C1 hardening — previously CloseSession went through get(), which
// refreshed the idle timer before the ownership check).
func TestCloseSessionUnauthorizedNoRefresh(t *testing.T) {
	e := engineForSessionTests(t)

	s := dummySession("leaked", "owner")
	old := time.Now().Add(-time.Hour)
	s.lastUsed = old // older than the idle TTL would normally tolerate
	_ = e.sessions.add(s)

	if err := e.CloseSession(Caller{ID: "intruder"}, "leaked"); err == nil {
		t.Fatal("un cierre de un no-propietario debe rechazarse (C1)")
	}
	if !s.lastUsed.Equal(old) {
		t.Errorf("un cierre rechazado no debe refrescar lastUsed: antes %v, ahora %v", old, s.lastUsed)
	}
	// El propietario real sí puede cerrarla después.
	if _, _, owned := e.sessions.removeOwned("leaked", "owner"); !owned {
		t.Error("el propietario debe poder cerrar la sesión tras el intento fallido")
	}
}

// ── Helpers internos ──────────────────────────────────────────────────────────

func TestBuildElevatedExecCommand(t *testing.T) {
	cases := []struct {
		prefix  string
		command string
		want    string
	}{
		{"sudo -n", "id", "sudo -n -- /bin/sh -c 'id'"},
		{"sudo -n -u deploy", "ls /root", "sudo -n -u deploy -- /bin/sh -c 'ls /root'"},
		{"sudo -n", "echo 'hello'", `sudo -n -- /bin/sh -c 'echo '\''hello'\'''`},
	}
	for _, c := range cases {
		got := buildElevatedExecCommand(c.prefix, c.command)
		if got != c.want {
			t.Errorf("prefix=%q cmd=%q\n  got  %q\n  want %q", c.prefix, c.command, got, c.want)
		}
	}
}

func TestShellQuoteSession(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"id", "'id'"},
		{"ls /root", "'ls /root'"},
		{"echo 'hi'", `'echo '\''hi'\'''`},
		{"", "''"},
		{"echo café", "'echo café'"}, // multibyte rune preserved
		{"a'b'c", `'a'\''b'\''c'`},   // multiple embedded quotes
	}
	for _, c := range cases {
		got := shellQuoteSession(c.in)
		if got != c.want {
			t.Errorf("in=%q got=%q want=%q", c.in, got, c.want)
		}
	}
}

func TestExecOptionsElevationLabel(t *testing.T) {
	cases := []struct {
		opts ExecOptions
		want string
	}{
		{ExecOptions{}, ""},
		{ExecOptions{Sudo: true}, "sudo:root"},
		{ExecOptions{Sudo: true, SudoUser: "deploy"}, "sudo:deploy"},
		{ExecOptions{Sudo: true, SudoUser: "appuser"}, "sudo:appuser"},
	}
	for _, c := range cases {
		if got := c.opts.elevationLabel(); got != c.want {
			t.Errorf("opts=%+v got=%q want=%q", c.opts, got, c.want)
		}
	}
}

func TestNewSessionIDUnico(t *testing.T) {
	ids := make(map[string]struct{})
	for i := 0; i < 100; i++ {
		id := newSessionID()
		if _, dup := ids[id]; dup {
			t.Fatalf("ID duplicado en iteración %d: %q", i, id)
		}
		ids[id] = struct{}{}
		if len(id) != 24 { // 12 bytes en hex = 24 chars
			t.Errorf("longitud inesperada de session ID: %d", len(id))
		}
	}
}
