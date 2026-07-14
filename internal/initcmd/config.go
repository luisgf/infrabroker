package initcmd

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/luisgf/infrabroker/internal/signer"
)

// localGroup is the RBAC group tying the broker caller to the starter host: the
// broker-local caller's allowed_groups and the host's groups must intersect or
// the v2.0.0 default-deny callers table hides the host.
const localGroup = "local"

// signerURL is the localhost mTLS endpoint the broker dials.
const signerURL = "https://127.0.0.1:9443"

// starterHost is an optional first host written into signer.json.
type starterHost struct {
	name, addr, user, hostKey string
}

// signerJSON is the exact wire shape of the emitted signer.json. Sub-structures
// reuse the real exported types (signer.CallerPolicy / signer.CommandPolicy) so
// they cannot drift from the schema the signer loads.
type signerJSON struct {
	Listen               string                          `json:"listen"`
	ServerCert           string                          `json:"server_cert"`
	ServerKey            string                          `json:"server_key"`
	ClientCA             string                          `json:"client_ca"`
	CAKey                string                          `json:"ca_key"`
	AuditLog             string                          `json:"audit_log"`
	AuditKey             string                          `json:"audit_key"`
	AuditFailMode        string                          `json:"audit_fail_mode"`
	MaxTTLSeconds        int                             `json:"max_ttl_seconds"`
	MonitorListen        string                          `json:"monitor_listen"`
	ReloadCallers        []string                        `json:"reload_callers"`
	Callers              map[string]signer.CallerPolicy  `json:"callers"`
	CommandPolicies      map[string]signer.CommandPolicy `json:"command_policies"`
	GroupCommandPolicies map[string][]string             `json:"group_command_policies"`
	Hosts                map[string]hostJSON             `json:"hosts"`
}

// hostJSON is the subset of the host entry init emits (a functional connectable
// host); it round-trips into signer.HostPolicy.
type hostJSON struct {
	Addr      string   `json:"addr"`
	User      string   `json:"user"`
	HostKey   string   `json:"host_key"`
	Principal string   `json:"principal"`
	Groups    []string `json:"groups"`
}

// brokerJSON is the lean remote/stdio broker config: it points at the signer and
// holds NO CA key and NO host list (hosts are fetched via GET /v1/hosts).
type brokerJSON struct {
	Signer                signerClientJSON `json:"signer"`
	AuditLog              string           `json:"audit_log"`
	AuditKey              string           `json:"audit_key"`
	AuditFailMode         string           `json:"audit_fail_mode"`
	MaxTTLSeconds         int              `json:"max_ttl_seconds"`
	HostsRefreshSeconds   int              `json:"hosts_refresh_seconds"`
	RevocationPollSeconds int              `json:"revocation_poll_seconds"`
	SessionIdleSeconds    int              `json:"session_idle_seconds"`
	SessionMaxSeconds     int              `json:"session_max_seconds"`
	MonitorListen         string           `json:"monitor_listen"`
}

type signerClientJSON struct {
	URL        string `json:"url"`
	ClientCert string `json:"client_cert"`
	ClientKey  string `json:"client_key"`
	CA         string `json:"ca"`
}

// buildSignerJSON assembles the signer config: CA custody + a default-deny
// starter policy on the reserved _default group + the broker-local caller + the
// imported/starter hosts. Every PKI/audit path is ABSOLUTE (rooted at absRoot):
// the broker's config.json is launched by the MCP client from an arbitrary CWD
// (`--register-mcp`), and the broker/signer resolve config paths against the
// process CWD, so relative paths would break a registered server (#271).
func buildSignerJSON(hosts []starterHost, absRoot string) signerJSON {
	allow := "^uptime$"
	s := signerJSON{
		Listen:        ":9443",
		ServerCert:    filepath.Join(absRoot, "pki", "signer.crt"),
		ServerKey:     filepath.Join(absRoot, "pki", "signer.key"),
		ClientCA:      filepath.Join(absRoot, "pki", "mtls_ca.crt"),
		CAKey:         filepath.Join(absRoot, "pki", "ssh_ca"),
		AuditLog:      filepath.Join(absRoot, "signer_audit.log"),
		AuditKey:      filepath.Join(absRoot, "pki", "signer_audit.seed"),
		AuditFailMode: "closed",
		MaxTTLSeconds: 300,
		MonitorListen: "127.0.0.1:9160",
		// broker-local doubles as the reload/admin CN (broker-ctl uses pki/broker.*).
		ReloadCallers: []string{brokerCN},
		Callers: map[string]signer.CallerPolicy{
			brokerCN: {AllowedGroups: []string{localGroup}},
		},
		// Default-deny: an allowlist matching only `uptime`; everything else is
		// denied. Attached to _default so it covers every host, now and future.
		CommandPolicies: map[string]signer.CommandPolicy{
			"starter-deny": {Mode: signer.CmdPolicyAllowlist, Allow: []string{allow}},
		},
		GroupCommandPolicies: map[string][]string{
			// "_default" is the reserved group that applies to every host.
			"_default": {"starter-deny"},
		},
		Hosts: map[string]hostJSON{},
	}
	for _, host := range hosts {
		s.Hosts[host.name] = hostJSON{
			Addr:      host.addr,
			User:      host.user,
			HostKey:   host.hostKey,
			Principal: "host:" + host.name,
			Groups:    []string{localGroup},
		}
	}
	return s
}

// buildBrokerJSON assembles the remote-mode broker config (custody-separated: no
// CA key). Its client cert CN (broker-local) is the caller in signer.json. Every
// path is ABSOLUTE (rooted at absRoot) so the config works when the MCP client
// launches `infrabroker serve-mcp` from its own CWD, not the init dir (#271).
func buildBrokerJSON(absRoot string) brokerJSON {
	return brokerJSON{
		Signer: signerClientJSON{
			URL:        signerURL,
			ClientCert: filepath.Join(absRoot, "pki", "broker.crt"),
			ClientKey:  filepath.Join(absRoot, "pki", "broker.key"),
			CA:         filepath.Join(absRoot, "pki", "mtls_ca.crt"),
		},
		AuditLog:              filepath.Join(absRoot, "audit.log"),
		AuditKey:              filepath.Join(absRoot, "pki", "audit.seed"),
		AuditFailMode:         "closed",
		MaxTTLSeconds:         300,
		HostsRefreshSeconds:   30,
		RevocationPollSeconds: 10,
		SessionIdleSeconds:    300,
		SessionMaxSeconds:     1800,
		MonitorListen:         "127.0.0.1:9180",
	}
}

// writeJSONConfig marshals v (indented) and writes it at 0640.
func writeJSONConfig(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(path, b, 0o640)
}
