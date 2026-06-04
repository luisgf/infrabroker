package signer

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/crypto/ssh"
)

// WireRequest es el cuerpo de POST /v1/sign. No incluye Caller: el servicio lo
// deriva del certificado de cliente mTLS (no es asertable por el broker).
type WireRequest struct {
	Host       string `json:"host"`
	Role       string `json:"role"`
	Purpose    string `json:"purpose"`
	Command    string `json:"command,omitempty"`
	TTLSeconds int    `json:"ttl_seconds,omitempty"`
	PublicKey  string `json:"public_key"` // línea authorized_keys de la pubkey efímera

	// Elevación (sudo NOPASSWD).
	Sudo     bool   `json:"sudo,omitempty"`
	SudoUser string `json:"sudo_user,omitempty"` // vacío = root

	// PTY: solicita permit-pty en el certificado.
	PTY bool `json:"pty,omitempty"`
}

// WireResponse es la respuesta del servicio a /v1/sign.
type WireResponse struct {
	Certificate string `json:"certificate"` // línea authorized_keys del cert
	Serial      uint64 `json:"serial"`
	// ElevationPrefix es el prefijo a anteponer en sesiones persistentes.
	// Vacío en one-shot (el prefijo ya está en el force-command del cert).
	ElevationPrefix string `json:"elevation_prefix,omitempty"`
}

// WireHostInfo contiene los datos de conectividad y capacidades de un host,
// tal como los devuelve GET /v1/hosts. No incluye datos de política internos
// (principal, source_address, etc.) — esos son exclusivos del signer.
type WireHostInfo struct {
	Addr    string `json:"addr"`
	User    string `json:"user"`
	HostKey string `json:"host_key"`
	Jump    string `json:"jump,omitempty"`
	// Capacidades: indica al broker (y al modelo) qué operaciones están permitidas.
	AllowSudo bool `json:"allow_sudo,omitempty"`
	AllowPTY  bool `json:"allow_pty,omitempty"`
}

// HostInfo es la representación interna del broker de los datos de
// conectividad y capacidades recibidos del signer.
type HostInfo struct {
	Addr      string
	User      string
	HostKey   string
	Jump      string
	AllowSudo bool
	AllowPTY  bool
}

// Remote delega la firma en el servicio externo por HTTP+mTLS.
type Remote struct {
	client *http.Client
	url    string
}

// NewRemote crea un cliente del servicio de firma.
func NewRemote(url string, tlsCfg *tls.Config, timeout time.Duration) *Remote {
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	return &Remote{
		url:    url,
		client: &http.Client{Timeout: timeout, Transport: &http.Transport{TLSClientConfig: tlsCfg}},
	}
}

// SignIntent implementa Signer contra el servicio remoto.
func (r *Remote) SignIntent(in Intent) (*Issued, error) {
	body, err := json.Marshal(WireRequest{
		Host:       in.Host,
		Role:       in.Role,
		Purpose:    in.Purpose,
		Command:    in.Command,
		TTLSeconds: int(in.RequestedTTL / time.Second),
		PublicKey:  string(ssh.MarshalAuthorizedKey(in.PublicKey)),
		Sudo:       in.Sudo,
		SudoUser:   in.SudoUser,
		PTY:        in.PTY,
	})
	if err != nil {
		return nil, err
	}
	resp, err := r.client.Post(r.url+"/v1/sign", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("contactar servicio de firma: %w", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("firma rechazada (%d): %s", resp.StatusCode, bytes.TrimSpace(rb))
	}

	var wr WireResponse
	if err := json.Unmarshal(rb, &wr); err != nil {
		return nil, fmt.Errorf("respuesta inválida: %w", err)
	}
	cert, err := ParseCertificate(wr.Certificate)
	if err != nil {
		return nil, err
	}
	return &Issued{Certificate: cert, Serial: wr.Serial, ElevationPrefix: wr.ElevationPrefix}, nil
}

// FetchHosts llama a GET /v1/hosts en el signer y devuelve los datos de
// conectividad de todos los hosts configurados. El broker usa esta información
// para construir los hops SSH; la política de firma permanece en el signer.
func (r *Remote) FetchHosts() (map[string]HostInfo, error) {
	resp, err := r.client.Get(r.url + "/v1/hosts")
	if err != nil {
		return nil, fmt.Errorf("obtener lista de hosts: %w", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("signer devolvió %d: %s", resp.StatusCode, bytes.TrimSpace(rb))
	}

	var wire map[string]WireHostInfo
	if err := json.Unmarshal(rb, &wire); err != nil {
		return nil, fmt.Errorf("respuesta /v1/hosts inválida: %w", err)
	}

	hosts := make(map[string]HostInfo, len(wire))
	for name, h := range wire {
		hosts[name] = HostInfo{
			Addr:      h.Addr,
			User:      h.User,
			HostKey:   h.HostKey,
			Jump:      h.Jump,
			AllowSudo: h.AllowSudo,
			AllowPTY:  h.AllowPTY,
		}
	}
	return hosts, nil
}

// ParseCertificate convierte una línea authorized_keys en *ssh.Certificate.
func ParseCertificate(authorizedLine string) (*ssh.Certificate, error) {
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedLine))
	if err != nil {
		return nil, fmt.Errorf("parsear certificado: %w", err)
	}
	cert, ok := pk.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("la clave devuelta no es un certificado")
	}
	return cert, nil
}

// ParsePublicKey convierte una línea authorized_keys en ssh.PublicKey.
func ParsePublicKey(authorizedLine string) (ssh.PublicKey, error) {
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedLine))
	if err != nil {
		return nil, fmt.Errorf("parsear pubkey: %w", err)
	}
	return pk, nil
}
