package audit

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// testKey devuelve una clave Ed25519 determinista (semilla = 0x01*32).
func testKey() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 0x01
	}
	return ed25519.NewKeyFromSeed(seed)
}

// openTmp abre un Log en un fichero temporal nuevo.
func openTmp(t *testing.T) (*Log, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := Open(path, testKey())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	return l, path
}

// readEntries lee todas las entradas del fichero de log y las devuelve como
// pares (rawLine, Entry), preservando el orden.
func readEntries(t *testing.T, path string) []struct {
	raw []byte
	e   Entry
} {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("readEntries open: %v", err)
	}
	defer f.Close()

	var out []struct {
		raw []byte
		e   Entry
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 256*1024), 256*1024)
	for sc.Scan() {
		b := sc.Bytes()
		if len(b) == 0 {
			continue
		}
		line := make([]byte, len(b))
		copy(line, b)
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatalf("readEntries unmarshal: %v", err)
		}
		out = append(out, struct {
			raw []byte
			e   Entry
		}{line, e})
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("readEntries scan: %v", err)
	}
	return out
}

// ── Tests ─────────────────────────────────────────────────────────────────────

// TestAppendSeqIncrementa verifica que Seq sube de 1 en 1 a partir de 1.
func TestAppendSeqIncrementa(t *testing.T) {
	t.Parallel()
	l, path := openTmp(t)
	for i := 0; i < 5; i++ {
		if err := l.Append(Entry{Outcome: "test"}); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	entries := readEntries(t, path)
	if len(entries) != 5 {
		t.Fatalf("esperaba 5 entradas, got %d", len(entries))
	}
	for i, pair := range entries {
		wantSeq := uint64(i + 1)
		if pair.e.Seq != wantSeq {
			t.Errorf("entrada %d: Seq=%d, quiero %d", i, pair.e.Seq, wantSeq)
		}
	}
}

// TestAppendPrevHashEncadena verifica que PrevHash de la entrada N es el
// SHA-256 de la línea raw N-1.
func TestAppendPrevHashEncadena(t *testing.T) {
	t.Parallel()
	l, path := openTmp(t)
	for i := 0; i < 4; i++ {
		if err := l.Append(Entry{Outcome: "chain", Command: "cmd"}); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	entries := readEntries(t, path)
	if len(entries) != 4 {
		t.Fatalf("esperaba 4 entradas, got %d", len(entries))
	}

	// Primera entrada: PrevHash debe ser cadena vacía.
	if entries[0].e.PrevHash != "" {
		t.Errorf("primera entrada PrevHash=%q, quiero \"\"", entries[0].e.PrevHash)
	}

	// Para cada entrada siguiente, PrevHash == SHA-256(raw anterior).
	for i := 1; i < len(entries); i++ {
		sum := sha256.Sum256(entries[i-1].raw)
		want := hex.EncodeToString(sum[:])
		if entries[i].e.PrevHash != want {
			t.Errorf("entrada %d: PrevHash=%s, quiero %s", i, entries[i].e.PrevHash, want)
		}
	}
}

// TestAppendFirmaValida verifica que la firma Ed25519 de cada entrada es
// válida contra la clave pública derivada de la semilla.
func TestAppendFirmaValida(t *testing.T) {
	t.Parallel()
	key := testKey()
	pub := key.Public().(ed25519.PublicKey)

	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := Open(path, key)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer l.Close()

	for i := 0; i < 3; i++ {
		if err := l.Append(Entry{Outcome: "sig-test", Caller: "agent"}); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}

	entries := readEntries(t, path)
	for i, pair := range entries {
		sigB64 := pair.e.Sig
		sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
		if err != nil {
			t.Fatalf("entrada %d: firma no es base64: %v", i, err)
		}

		// El payload canónico se firma con Sig="".
		pair.e.Sig = ""
		payload, err := json.Marshal(pair.e)
		if err != nil {
			t.Fatalf("entrada %d: marshal para verificación: %v", i, err)
		}

		if !ed25519.Verify(pub, payload, sigBytes) {
			t.Errorf("entrada %d: firma Ed25519 inválida", i)
		}
	}
}

// TestAppendFirmaInvalidaTrasManipulacion comprueba que si se altera el
// contenido de una entrada, la firma deja de verificar.
func TestAppendFirmaInvalidaTrasManipulacion(t *testing.T) {
	t.Parallel()
	key := testKey()
	pub := key.Public().(ed25519.PublicKey)

	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := Open(path, key)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer l.Close()

	if err := l.Append(Entry{Outcome: "ok", Caller: "honest"}); err != nil {
		t.Fatalf("Append: %v", err)
	}

	entries := readEntries(t, path)
	e := entries[0].e
	sigBytes, _ := base64.StdEncoding.DecodeString(e.Sig)

	// Alterar el campo Caller.
	e.Caller = "attacker"
	e.Sig = ""
	payload, _ := json.Marshal(e)

	if ed25519.Verify(pub, payload, sigBytes) {
		t.Error("la firma no debería verificar tras manipular Caller")
	}
}

// TestRestoreChainFicheroNuevo verifica que abrir un log en un path
// inexistente no produce error y empieza con seq=0.
func TestRestoreChainFicheroNuevo(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "nuevo.log")
	l, err := Open(path, testKey())
	if err != nil {
		t.Fatalf("Open en fichero nuevo: %v", err)
	}
	defer l.Close()

	if l.seq != 0 {
		t.Errorf("seq inicial=%d, quiero 0", l.seq)
	}
	if l.prevHash != "" {
		t.Errorf("prevHash inicial=%q, quiero \"\"", l.prevHash)
	}
}

// TestRestoreChainFicheroVacio verifica que un fichero vacío no produce error
// y la cadena arranca desde cero.
func TestRestoreChainFicheroVacio(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "empty.log")
	// Crear el fichero vacío.
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	f.Close()

	l, err := Open(path, testKey())
	if err != nil {
		t.Fatalf("Open en fichero vacío: %v", err)
	}
	defer l.Close()

	if l.seq != 0 || l.prevHash != "" {
		t.Errorf("seq=%d prevHash=%q, quiero 0/\"\"", l.seq, l.prevHash)
	}
}

// TestRestoreChainPreservaEstadoTrasReinicio abre un log, escribe varias
// entradas, cierra y vuelve a abrir. El segundo Open debe restaurar seq y
// prevHash para que la cadena continúe sin rotura.
func TestRestoreChainPreservaEstadoTrasReinicio(t *testing.T) {
	t.Parallel()
	key := testKey()
	path := filepath.Join(t.TempDir(), "restart.log")

	// Primera sesión: escribir 3 entradas.
	l1, err := Open(path, key)
	if err != nil {
		t.Fatalf("Open sesión 1: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := l1.Append(Entry{Outcome: "s1"}); err != nil {
			t.Fatalf("Append s1 %d: %v", i, err)
		}
	}
	l1.Close()

	// Segunda sesión: abrir de nuevo y escribir 2 entradas más.
	l2, err := Open(path, key)
	if err != nil {
		t.Fatalf("Open sesión 2: %v", err)
	}
	defer l2.Close()

	// Seq restaurado debe ser 3 (la última del log).
	if l2.seq != 3 {
		t.Errorf("seq restaurado=%d, quiero 3", l2.seq)
	}

	for i := 0; i < 2; i++ {
		if err := l2.Append(Entry{Outcome: "s2"}); err != nil {
			t.Fatalf("Append s2 %d: %v", i, err)
		}
	}

	// Verificar la cadena completa (5 entradas, cadena ininterrumpida).
	entries := readEntries(t, path)
	if len(entries) != 5 {
		t.Fatalf("esperaba 5 entradas totales, got %d", len(entries))
	}
	for i := 0; i < 5; i++ {
		if entries[i].e.Seq != uint64(i+1) {
			t.Errorf("entrada %d: Seq=%d, quiero %d", i, entries[i].e.Seq, i+1)
		}
	}
	for i := 1; i < len(entries); i++ {
		sum := sha256.Sum256(entries[i-1].raw)
		want := hex.EncodeToString(sum[:])
		if entries[i].e.PrevHash != want {
			t.Errorf("entrada %d: PrevHash rompe la cadena", i)
		}
	}
}

// TestRestoreChainUltimaLineaMalformada verifica que Open devuelve error si
// la última línea del fichero no es JSON válido.
func TestRestoreChainUltimaLineaMalformada(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "malformed.log")
	// Escribir una línea JSON válida seguida de basura.
	content := `{"seq":1,"prev_hash":"","sig":"","time":"2026-01-01T00:00:00Z","caller":"","host":"","user":"","principal":"","command":"","ttl":"","serial":0,"outcome":"ok","exit_code":0}` + "\n" +
		"not-valid-json\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := Open(path, testKey())
	if err == nil {
		t.Fatal("esperaba error al parsear última línea malformada")
	}
}

// TestMaybeRotateAplicaRotacion crea un Log con maxFileSize mínimo y verifica
// que tras la rotación: (a) el fichero rotado existe y (b) el log nuevo
// reinicia seq desde 1 (primera entrada tras rotar tiene Seq=1).
func TestMaybeRotateAplicaRotacion(t *testing.T) {
	t.Parallel()
	key := testKey()
	dir := t.TempDir()
	path := filepath.Join(dir, "rotate.log")

	l, err := Open(path, key)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer l.Close()

	// Escribir una entrada para que el fichero tenga contenido.
	if err := l.Append(Entry{Outcome: "before-rotate"}); err != nil {
		t.Fatalf("Append before rotate: %v", err)
	}

	// Forzar rotación poniendo maxFileSize a 1 byte.
	l.mu.Lock()
	l.maxFileSize = 1
	l.mu.Unlock()

	// La siguiente entrada debe disparar la rotación y luego escribir en el nuevo fichero.
	if err := l.Append(Entry{Outcome: "trigger-rotate"}); err != nil {
		t.Fatalf("Append que dispara rotación: %v", err)
	}

	// Comprobar que hay un fichero rotado en el directorio.
	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var rotated bool
	for _, de := range dirEntries {
		if de.Name() != "rotate.log" {
			rotated = true
			break
		}
	}
	if !rotated {
		t.Error("esperaba un fichero rotado (rotate.log.<timestamp>) en el directorio")
	}

	// La entrada escrita tras la rotación debe tener Seq=1 (cadena reiniciada).
	entries := readEntries(t, path)
	if len(entries) == 0 {
		t.Fatal("el log nuevo debe tener al menos una entrada tras la rotación")
	}
	if entries[0].e.Seq != 1 {
		t.Errorf("primera entrada del log nuevo: Seq=%d, quiero 1", entries[0].e.Seq)
	}
	if entries[0].e.PrevHash != "" {
		t.Errorf("primera entrada del log nuevo: PrevHash=%q, quiero \"\"", entries[0].e.PrevHash)
	}
}

// TestMaybeRotateDeshabilitada comprueba que con maxFileSize=0 no hay rotación.
func TestMaybeRotateDeshabilitada(t *testing.T) {
	t.Parallel()
	key := testKey()
	dir := t.TempDir()
	path := filepath.Join(dir, "norotate.log")

	l, err := Open(path, key)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer l.Close()

	l.mu.Lock()
	l.maxFileSize = 0 // deshabilitar rotación
	l.mu.Unlock()

	for i := 0; i < 5; i++ {
		if err := l.Append(Entry{Outcome: "no-rotate"}); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}

	// Debe haber exactamente un fichero en el directorio.
	dirEntries, _ := os.ReadDir(dir)
	if len(dirEntries) != 1 {
		t.Errorf("esperaba 1 fichero, got %d (rotación no debería haber ocurrido)", len(dirEntries))
	}
}

// TestCloseCierraCorrecto verifica que Close no devuelve error en condiciones normales.
func TestCloseCierraCorrecto(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "close.log")
	l, err := Open(path, testKey())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := l.Append(Entry{Outcome: "before-close"}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}
