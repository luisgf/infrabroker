package auth

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http/httptest"
	"testing"
)

func TestCallerCN(t *testing.T) {
	t.Parallel()
	req := func(cn string) (string, error) {
		r := httptest.NewRequest("GET", "/", nil)
		r.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: cn}}},
		}
		return CallerCN(r)
	}

	if cn, err := req("broker-1"); err != nil || cn != "broker-1" {
		t.Errorf("valid CN: got cn=%q err=%v", cn, err)
	}
	// Fail closed on an empty CN (would otherwise be an unlisted, default-open caller).
	if _, err := req(""); err == nil {
		t.Error("empty CN must be rejected")
	}
	// Reject control characters (audit-line / RBAC-key integrity).
	if _, err := req("bad\nname"); err == nil {
		t.Error("CN with a control character must be rejected")
	}
	// No client certificate at all.
	if _, err := CallerCN(httptest.NewRequest("GET", "/", nil)); err == nil {
		t.Error("missing client certificate must be rejected")
	}
}

// TestCallerCNRequiresClientAuthEKU pins #399: the client CA can issue certs
// for other purposes (serverAuth, code signing...), and CN-based RBAC must
// not be satisfied by such a cert with a colliding CN. A leaf with no EKU
// extension is unconstrained (RFC 5280) and still accepted; a leaf restricted
// to serverAuth is rejected even with a valid CN.
func TestCallerCNRequiresClientAuthEKU(t *testing.T) {
	t.Parallel()
	req := func(eku []x509.ExtKeyUsage) (string, error) {
		r := httptest.NewRequest("GET", "/", nil)
		r.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{{
				Subject:     pkix.Name{CommonName: "broker-1"},
				ExtKeyUsage: eku,
			}},
		}
		return CallerCN(r)
	}

	if cn, err := req(nil); err != nil || cn != "broker-1" {
		t.Errorf("no EKU extension (any usage): got cn=%q err=%v", cn, err)
	}
	if cn, err := req([]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}); err != nil || cn != "broker-1" {
		t.Errorf("clientAuth among EKUs: got cn=%q err=%v", cn, err)
	}
	if _, err := req([]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}); err == nil {
		t.Error("a serverAuth-only cert must be rejected as a caller identity")
	}
	if _, err := req([]x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}); err == nil {
		t.Error("a codeSigning-only cert must be rejected as a caller identity")
	}
}
