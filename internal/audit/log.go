// Package audit escribe un registro append-only y a prueba de manipulación de
// cada firma/ejecución: encadena entradas por hash (estilo cadena) y firma cada
// una con una clave de auditoría Ed25519, de modo que no se puede alterar ni
// reordenar el histórico sin detectarlo.
package audit

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

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

	// Campos de integridad (rellenados por Log.Append).
	Seq      uint64 `json:"seq"`
	PrevHash string `json:"prev_hash"`
	Sig      string `json:"sig"`
}

// Log es un escritor de auditoría concurrente que encadena y firma entradas.
type Log struct {
	mu       sync.Mutex
	f        *os.File
	signKey  ed25519.PrivateKey
	prevHash string
	seq      uint64
}

// Open abre (o crea) el fichero de auditoría en append y prepara la firma.
func Open(path string, signKey ed25519.PrivateKey) (*Log, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("abrir log de auditoría: %w", err)
	}
	return &Log{f: f, signKey: signKey}, nil
}

// Append firma y escribe una entrada. Calcula prev_hash/seq y la firma sobre el
// contenido canónico (sin el propio campo Sig).
func (l *Log) Append(e Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()

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
