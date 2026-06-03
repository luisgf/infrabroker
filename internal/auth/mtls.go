// Package auth construye la configuración TLS del broker: exige certificado de
// cliente (mTLS) firmado por una CA de confianza. Así solo agentes autorizados
// pueden pedir ejecuciones, y el CN del cliente queda asociado a cada entrada de
// auditoría (no repudio del llamante).
package auth

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
)

// ServerTLSConfig devuelve un *tls.Config que exige mTLS con clientes firmados
// por clientCAFile, presentando el par (serverCertFile, serverKeyFile).
func ServerTLSConfig(serverCertFile, serverKeyFile, clientCAFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(serverCertFile, serverKeyFile)
	if err != nil {
		return nil, fmt.Errorf("cargar cert de servidor: %w", err)
	}
	caPEM, err := os.ReadFile(clientCAFile)
	if err != nil {
		return nil, fmt.Errorf("leer CA de clientes: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("CA de clientes inválida: %s", clientCAFile)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// ClientTLSConfig construye la config TLS de un cliente mTLS: presenta
// (certFile, keyFile) y verifica al servidor contra serverCAFile. La usa el
// broker para hablar con el servicio de firma.
func ClientTLSConfig(certFile, keyFile, serverCAFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("cargar cert de cliente: %w", err)
	}
	caPEM, err := os.ReadFile(serverCAFile)
	if err != nil {
		return nil, fmt.Errorf("leer CA del servidor: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("CA del servidor inválida: %s", serverCAFile)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// CallerCN extrae el Common Name del certificado de cliente verificado.
// Asume que el TLS handshake ya validó la cadena (RequireAndVerifyClientCert).
func CallerCN(r *http.Request) (string, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", fmt.Errorf("sin certificado de cliente")
	}
	return r.TLS.PeerCertificates[0].Subject.CommonName, nil
}
