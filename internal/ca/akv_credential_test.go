package ca

import (
	"strings"
	"testing"
)

// TestAKVCredentialPartialServicePrincipalIsAnError locks in #751: a
// service-principal block with only some of tenant_id / client_id /
// client_secret_env set must fail the CA load naming the missing field(s),
// never fall back to DefaultAzureCredential and sign as whatever identity that
// finds. All three set with the secret present still builds the SP credential.
func TestAKVCredentialPartialServicePrincipalIsAnError(t *testing.T) {
	t.Setenv("INFRABROKER_TEST_AKV_SECRET", "s3cret")
	cases := []struct {
		name    string
		cfg     CAKeyConfig
		missing string
	}{
		{"tenant_only", CAKeyConfig{TenantID: "t"}, "client_id, client_secret_env"},
		{"tenant_client_no_secret_env", CAKeyConfig{TenantID: "t", ClientID: "c"}, "client_secret_env"},
		{"secret_env_only", CAKeyConfig{ClientSecretEnv: "INFRABROKER_TEST_AKV_SECRET"}, "tenant_id, client_id"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cred, err := akvCredential(c.cfg)
			if err == nil || cred != nil {
				t.Fatalf("partial SP block must be an error, got cred=%v err=%v", cred, err)
			}
			if !strings.Contains(err.Error(), "missing "+c.missing) {
				t.Errorf("error must name the missing field(s) %q: %v", c.missing, err)
			}
		})
	}
	t.Run("complete", func(t *testing.T) {
		cred, err := akvCredential(CAKeyConfig{TenantID: "t", ClientID: "c", ClientSecretEnv: "INFRABROKER_TEST_AKV_SECRET"})
		if err != nil || cred == nil {
			t.Fatalf("complete SP block must build a credential, got cred=%v err=%v", cred, err)
		}
	})
	t.Run("complete_but_env_empty", func(t *testing.T) {
		t.Setenv("INFRABROKER_TEST_AKV_EMPTY", "")
		if _, err := akvCredential(CAKeyConfig{TenantID: "t", ClientID: "c", ClientSecretEnv: "INFRABROKER_TEST_AKV_EMPTY"}); err == nil {
			t.Fatal("an empty secret env var must still be an error")
		}
	})
}
