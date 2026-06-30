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
