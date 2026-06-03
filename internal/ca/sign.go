// Package ca contiene las primitivas de bajo nivel de la CA SSH: generación del
// par efímero (lado broker) y construcción+firma del certificado (lado firmante).
//
// El firmado es nativo (golang.org/x/crypto/ssh): la clave de CA se consume a
// través de un ssh.Signer, que puede estar respaldado por un crypto.Signer de
// HSM/KMS/Secure Enclave (clave no exportable).
package ca

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
)

// Constraints son los límites que el firmante graba en el certificado. Los deriva
// la política del firmante a partir de la intención; el broker no los elige.
type Constraints struct {
	// Principal es el valor que sshd mapea a una cuenta local (p. ej. "host:web01").
	Principal string
	// TTL es la ventana de validez. Debe ser de minutos.
	TTL time.Duration
	// SourceAddress (CIDR o IP) fija desde dónde es usable el cert. Para destinos
	// tras un bastión debe ser la IP de egreso del bastión.
	SourceAddress string
	// ForceCommand ata el cert a ejecutar solo ese comando (one-shot). Vacío en
	// conexiones de sesión.
	ForceCommand string
	// AllowPortForwarding añade permit-port-forwarding (solo hops bastión).
	AllowPortForwarding bool
	// AllowPTY añade permit-pty al certificado. Necesario para sesiones
	// interactivas (mode=pty) y comandos one-shot que requieran TTY.
	AllowPTY bool
	// KeyID es la identidad para el log de sshd.
	KeyID string
}

// GenerateEphemeralKey crea el par efímero del cliente. La clave privada se queda
// en el broker (hace la conexión SSH); solo la pública viaja al firmante.
func GenerateEphemeralKey() (ed25519.PrivateKey, ssh.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generar par efímero: %w", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, nil, fmt.Errorf("envolver pubkey: %w", err)
	}
	return priv, sshPub, nil
}

// LoadCAFromPEM carga la clave de CA desde PEM (uso de laboratorio). En producción,
// sustituir por un ssh.Signer respaldado por crypto.Signer de HSM/KMS.
func LoadCAFromPEM(pem []byte) (ssh.Signer, error) {
	s, err := ssh.ParsePrivateKey(pem)
	if err != nil {
		return nil, fmt.Errorf("parsear clave de CA: %w", err)
	}
	return s, nil
}

// BuildAndSign construye un certificado de usuario acotado sobre pub y lo firma con
// la clave de CA. Devuelve el cert y su número de serie único.
func BuildAndSign(caKey ssh.Signer, pub ssh.PublicKey, c Constraints) (*ssh.Certificate, uint64, error) {
	if c.Principal == "" {
		return nil, 0, fmt.Errorf("principal es obligatorio")
	}
	if c.TTL <= 0 || c.TTL > 15*time.Minute {
		return nil, 0, fmt.Errorf("TTL debe estar en (0, 15m]; recibido %s", c.TTL)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, 0, err
	}

	now := time.Now()
	cert := &ssh.Certificate{
		Key:             pub,
		Serial:          serial,
		CertType:        ssh.UserCert,
		KeyId:           c.KeyID,
		ValidPrincipals: []string{c.Principal},
		// Margen de 30s hacia atrás para tolerar desfase de reloj.
		ValidAfter:  uint64(now.Add(-30 * time.Second).Unix()),
		ValidBefore: uint64(now.Add(c.TTL).Unix()),
		Permissions: ssh.Permissions{
			CriticalOptions: map[string]string{},
			Extensions:      map[string]string{}, // vacío: sin agent/X11 forwarding
		},
	}
	if c.SourceAddress != "" {
		cert.Permissions.CriticalOptions["source-address"] = c.SourceAddress
	}
	if c.ForceCommand != "" {
		cert.Permissions.CriticalOptions["force-command"] = c.ForceCommand
	}
	if c.AllowPortForwarding {
		cert.Permissions.Extensions["permit-port-forwarding"] = ""
	}
	if c.AllowPTY {
		cert.Permissions.Extensions["permit-pty"] = ""
	}

	if err := cert.SignCert(rand.Reader, caKey); err != nil {
		return nil, 0, fmt.Errorf("firmar certificado: %w", err)
	}
	return cert, serial, nil
}

func randomSerial() (uint64, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, fmt.Errorf("serial aleatorio: %w", err)
	}
	return binary.BigEndian.Uint64(b[:]), nil
}
