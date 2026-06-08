// Package audit escribe un registro append-only y a prueba de manipulación de
// cada firma/ejecución: encadena entradas por hash (estilo cadena) y firma cada
// una con una clave de auditoría Ed25519, de modo que no se puede alterar ni
// reordenar el histórico sin detectarlo.
package audit

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

// AuditLogMaxSize es el tamaño máximo del fichero de auditoría antes de rotar
// a un fichero con sufijo de marca de tiempo. 0 deshabilita la rotación.
// El valor por defecto (100 MiB) evita que el disco se llene y que la escritura
// falle silenciosamente.
const AuditLogMaxSize int64 = 100 * 1024 * 1024 // 100 MiB

// Entry es un registro de auditoría. Nunca contiene la clave ni el certificado,
// solo metadatos (incluida la huella del cert y su serial).
type Entry struct {
	Time      time.Time `json:"time"`
	Caller    string    `json:"caller"`     // identidad del agente (CN del cert mTLS)
	Host      string    `json:"host"`       // destino
	User      string    `json:"user"`       // cuenta remota
	Principal string    `json:"principal"`  // principal del cert efímero
	Command   string    `json:"command"`    // comando solicitado
	TTL       string    `json:"ttl"`        // ventana de validez emitida
	Serial    uint64    `json:"serial"`     // serie del cert (correla con sshd)
	SessionID string    `json:"session_id,omitempty"` // sesión persistente, si aplica
	Outcome   string    `json:"outcome"`    // executed|denied|error|session_open|session_exec|session_close
	ExitCode  int       `json:"exit_code"`  // código de salida si se ejecutó
	Err       string    `json:"err,omitempty"`

	// Elevación y PTY (trazabilidad de privilegio).
	Elevation string `json:"elevation,omitempty"` // p. ej. "sudo:root" o "sudo:deploy"
	PTY       bool   `json:"pty,omitempty"`        // true si se usó PTY

	// AI-action firewall: trazabilidad de la decisión de command policy.
	PolicyRule string `json:"policy_rule,omitempty"` // regla de command_policy que casó
	DryRun     bool   `json:"dry_run,omitempty"`     // true si fue una simulación (no se ejecutó)

	// Campos de integridad (rellenados por Log.Append).
	Seq      uint64 `json:"seq"`
	PrevHash string `json:"prev_hash"`
	Sig      string `json:"sig"`
}

// Log es un escritor de auditoría concurrente que encadena y firma entradas.
type Log struct {
	mu          sync.Mutex
	f           *os.File
	path        string
	signKey     ed25519.PrivateKey
	prevHash    string
	seq         uint64
	maxFileSize int64 // 0 = sin rotación
}

// Open abre (o crea) el fichero de auditoría en append y prepara la firma.
// A4: restaura seq y prevHash desde la última entrada existente para preservar
// la cadena de integridad entre reinicios del proceso.
// L2: aplica rotación automática cuando el fichero supera AuditLogMaxSize.
func Open(path string, signKey ed25519.PrivateKey) (*Log, error) {
	l := &Log{
		path:        path,
		signKey:     signKey,
		maxFileSize: AuditLogMaxSize,
	}
	// A4: restaurar la cadena desde el log existente (si lo hay).
	if err := l.restoreChain(); err != nil {
		return nil, fmt.Errorf("restaurar cadena de auditoría: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("abrir log de auditoría: %w", err)
	}
	l.f = f
	return l, nil
}

// restoreChain lee la última línea del log existente y restaura seq y prevHash.
// Esto garantiza que la cadena no se rompe cuando el proceso se reinicia.
func (l *Log) restoreChain() error {
	f, err := os.Open(l.path)
	if os.IsNotExist(err) {
		return nil // fichero nuevo — cadena arranca desde cero
	}
	if err != nil {
		return fmt.Errorf("leer log existente: %w", err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 256*1024), 256*1024) // entradas de hasta 256 KiB
	var lastLine []byte
	for sc.Scan() {
		if b := sc.Bytes(); len(b) > 0 {
			lastLine = make([]byte, len(b))
			copy(lastLine, b)
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("escanear log existente: %w", err)
	}
	if len(lastLine) == 0 {
		return nil // fichero vacío — cadena arranca desde cero
	}

	var e Entry
	if err := json.Unmarshal(lastLine, &e); err != nil {
		return fmt.Errorf("parsear última entrada del log: %w", err)
	}
	l.seq = e.Seq
	sum := sha256.Sum256(lastLine)
	l.prevHash = hex.EncodeToString(sum[:])
	return nil
}

// maybeRotate rota el log si supera maxFileSize. Llamar bajo l.mu.
// L2: crea un fichero con sufijo de marca de tiempo y abre uno nuevo.
// La cadena del nuevo fichero arranca desde cero.
func (l *Log) maybeRotate() {
	if l.maxFileSize <= 0 {
		return
	}
	info, err := l.f.Stat()
	if err != nil || info.Size() < l.maxFileSize {
		return
	}
	rotPath := l.path + "." + time.Now().UTC().Format("20060102T150405Z")
	_ = l.f.Close()
	if err := os.Rename(l.path, rotPath); err != nil {
		// Si el rename falla, reabrir el fichero actual y continuar.
		f, e2 := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if e2 == nil {
			l.f = f
		}
		log.Printf("advertencia: rotación de audit log fallida (%v); se continúa en el fichero original", err)
		return
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		log.Printf("advertencia: no se pudo abrir nuevo audit log tras rotación: %v", err)
		return
	}
	l.f = f
	l.seq = 0
	l.prevHash = ""
	log.Printf("audit log rotado: %s → %s", l.path, rotPath)
}

// Append firma y escribe una entrada. Calcula prev_hash/seq y la firma sobre el
// contenido canónico (sin el propio campo Sig).
func (l *Log) Append(e Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// L2: rotar si el fichero ha alcanzado el límite de tamaño.
	l.maybeRotate()

	l.seq++
	e.Seq = l.seq
	e.PrevHash = l.prevHash
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}

	// Firmamos el contenido canónico con Sig vacío; luego rellenamos Sig.
	e.Sig = ""
	payload, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("serializar payload: %w", err)
	}
	sig := ed25519.Sign(l.signKey, payload)
	e.Sig = base64.StdEncoding.EncodeToString(sig)

	line, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("serializar línea: %w", err)
	}
	if _, err := l.f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("escribir log: %w", err)
	}
	if err := l.f.Sync(); err != nil {
		return fmt.Errorf("fsync log: %w", err)
	}

	sum := sha256.Sum256(line)
	l.prevHash = hex.EncodeToString(sum[:])
	return nil
}

// Close cierra el fichero subyacente.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Close()
}
