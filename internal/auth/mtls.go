// Package auth builds the TLS configuration for the broker: it requires a
// client certificate (mTLS) signed by a trusted CA. This ensures only
// authorised agents can request executions, and the client CN is associated
// with each audit entry (caller non-repudiation).
package auth

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"unicode"
)

// ServerTLSConfig returns a *tls.Config that requires mTLS with clients signed
// by clientCAFile, presenting the (serverCertFile, serverKeyFile) pair.
func ServerTLSConfig(serverCertFile, serverKeyFile, clientCAFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(serverCertFile, serverKeyFile)
	if err != nil {
		return nil, fmt.Errorf("loading server cert: %w", err)
	}
	caPEM, err := os.ReadFile(clientCAFile)
	if err != nil {
		return nil, fmt.Errorf("reading client CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("invalid client CA: %s", clientCAFile)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// ServerTLSConfigNoClientAuth returns a *tls.Config for an HTTPS server that
// presents (serverCertFile, serverKeyFile) but does NOT require a client
// certificate. Used by the HTTP+OAuth MCP frontend: caller authentication is
// provided by the bearer token (OIDC), not mTLS.
func ServerTLSConfigNoClientAuth(serverCertFile, serverKeyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(serverCertFile, serverKeyFile)
	if err != nil {
		return nil, fmt.Errorf("loading server cert: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// ClientTLSConfig builds the TLS config for an mTLS client: presents
// (certFile, keyFile) and verifies the server against serverCAFile. Used by
// the broker to talk to the signing service.
func ClientTLSConfig(certFile, keyFile, serverCAFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("loading client cert: %w", err)
	}
	caPEM, err := os.ReadFile(serverCAFile)
	if err != nil {
		return nil, fmt.Errorf("reading server CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("invalid server CA: %s", serverCAFile)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// CallerCN extracts the Common Name from the verified client certificate.
// Assumes the TLS handshake has already validated the chain
// (RequireAndVerifyClientCert). The leaf must carry the clientAuth EKU
// (#399): the client CA may also issue non-client certs (server, broker-ctl,
// operator tooling), and CN-based RBAC would otherwise be satisfied by any
// cert of the same CA with a colliding CN — a server cert is not a caller
// identity.
func CallerCN(r *http.Request) (string, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", fmt.Errorf("no client certificate")
	}
	cert := r.TLS.PeerCertificates[0]
	if !hasClientAuthEKU(cert) {
		return "", fmt.Errorf("client certificate lacks the clientAuth extended key usage")
	}
	cn := cert.Subject.CommonName
	// Fail closed on an empty or malformed CN: with the default-open caller
	// tables an empty CN would otherwise be accepted as an (unlisted) identity
	// and inherit broad access; control characters could also corrupt audit
	// lines or RBAC keys.
	if cn == "" {
		return "", fmt.Errorf("client certificate has an empty common name")
	}
	for _, c := range cn {
		if unicode.IsControl(c) {
			return "", fmt.Errorf("client certificate common name contains a control character")
		}
	}
	return cn, nil
}

// hasClientAuthEKU reports whether the certificate is valid for TLS client
// authentication: it has no EKU extension (any usage, per RFC 5280) or it
// includes ExtKeyUsageClientAuth. A certificate restricted to serverAuth (a
// server cert from the same CA) is not a caller identity, no matter what CN
// it carries.
func hasClientAuthEKU(cert *x509.Certificate) bool {
	if len(cert.ExtKeyUsage) == 0 {
		return true
	}
	for _, ku := range cert.ExtKeyUsage {
		if ku == x509.ExtKeyUsageClientAuth {
			return true
		}
	}
	return false
}
