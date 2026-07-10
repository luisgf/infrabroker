package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/luisgf/infrabroker/internal/audit"
	"github.com/luisgf/infrabroker/internal/auth"
	"github.com/luisgf/infrabroker/internal/confcheck"
	"github.com/luisgf/infrabroker/internal/signer"
)

var (
	errHostNotFound = errors.New("unknown host")
	errNoChange     = errors.New("no change")
)

type allowReq struct {
	Pattern string `json:"pattern"`
}

// handlePolicyAllow adds (POST) or removes (DELETE) a single allowlist regex from
// a host's command_policy. Auth is mTLS + the reload_callers allowlist (same
// trust tier as POST /v1/reload — "may change policy"). The edit is validated by
// building the new state (CompileHostPolicies + CA load) BEFORE it is persisted
// or applied: a bad regex, an unknown host, or a config that would not compile is
// rejected and nothing changes. On success the file is written atomically and the
// in-memory policy is swapped, so disk and the running policy stay consistent.
// Every attempt is recorded in the signed audit log.
func (s *server) handlePolicyAllow(w http.ResponseWriter, r *http.Request) {
	add := r.Method == http.MethodPost
	if !add && r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	caller, err := auth.CallerCN(r)
	if err != nil {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	s.mu.RLock()
	_, allowed := s.reloadCN[caller]
	s.mu.RUnlock()
	if !allowed {
		s.auditPolicy(caller, "", "", add, "policy-denied", errors.New("caller not authorised"))
		http.Error(w, "not authorised to change policy", http.StatusForbidden)
		return
	}
	host := r.PathValue("host")
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	var req allowReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Pattern == "" {
		http.Error(w, `invalid request: need {"pattern": "..."}`, http.StatusBadRequest)
		return
	}
	if _, err := regexp.Compile(req.Pattern); err != nil {
		s.auditPolicy(caller, host, req.Pattern, add, "policy-failed", err)
		http.Error(w, "invalid regex: "+err.Error(), http.StatusBadRequest)
		return
	}

	n, err := s.mutateAllow(host, req.Pattern, add)
	if err != nil {
		s.auditPolicy(caller, host, req.Pattern, add, "policy-failed", err)
		http.Error(w, err.Error(), policyErrStatus(err))
		return
	}
	s.auditPolicy(caller, host, req.Pattern, add, "policy-changed", nil)
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "host": host, "hosts": n})
}

func policyErrStatus(err error) int {
	switch {
	case errors.Is(err, errHostNotFound):
		return http.StatusNotFound
	case errors.Is(err, errNoChange):
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}

// mutateAllow edits the host's command_policy allowlist in signer.json and
// applies it. writeMu serialises mutations (read-modify-write of the file);
// buildState runs outside the state lock (it may load CA keys), and only the
// final swap takes s.mu — mirroring reload().
func (s *server) mutateAllow(host, pattern string, add bool) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	orig, err := os.ReadFile(s.cfgPath)
	if err != nil {
		return 0, err
	}
	newBytes, err := editAllow(orig, host, pattern, add)
	if err != nil {
		return 0, err
	}
	cfg, err := parseConfig(newBytes)
	if err != nil {
		return 0, fmt.Errorf("invalid config after edit: %w", err)
	}
	local, err := buildState(context.Background(), cfg, s.grants)
	if err != nil {
		return 0, err // bad regex / would-not-compile: nothing persisted or applied
	}
	if err := atomicWrite(s.cfgPath, newBytes); err != nil {
		return 0, err
	}
	s.mu.Lock()
	s.local = local
	s.hosts = cfg.Hosts
	s.callers = cfg.Callers
	s.reloadCN = reloadSet(cfg.ReloadCallers)
	s.forwarders = reloadSet(cfg.TrustedForwarders)
	s.mu.Unlock()
	return len(cfg.Hosts), nil
}

// jsonPtrEscape escapes a JSON Pointer reference token (RFC 6901): "~"→"~0",
// "/"→"~1", so a host name is a valid pointer segment.
func jsonPtrEscape(s string) string {
	s = strings.ReplaceAll(s, "~", "~0")
	s = strings.ReplaceAll(s, "/", "~1")
	return s
}

// editAllow edits one host's command_policy allowlist in the raw JSONC config
// and returns the new bytes, PRESERVING every other byte — comments, key order,
// formatting — via a format-preserving JSON Patch (confcheck.Patch). It reads
// the current shape from a standardized copy, then applies the minimal patch:
// create command_policy / allow when absent, append or remove the pattern, and
// (on add) flip an off/empty mode to allowlist — matching the previous
// parse→marshal behaviour byte-for-byte in value, but without losing comments.
func editAllow(orig []byte, host, pattern string, add bool) ([]byte, error) {
	std, err := confcheck.Standardize(orig)
	if err != nil {
		return nil, err
	}
	var top struct {
		Hosts map[string]json.RawMessage `json:"hosts"`
	}
	if err := json.Unmarshal(std, &top); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	hraw, ok := top.Hosts[host]
	if !ok {
		return nil, fmt.Errorf("%w: %q", errHostNotFound, host)
	}
	var hostObj map[string]json.RawMessage
	if err := json.Unmarshal(hraw, &hostObj); err != nil {
		return nil, fmt.Errorf("parsing host %q: %w", host, err)
	}
	cpRaw, hasCP := hostObj["command_policy"]
	var cp signer.CommandPolicy
	allowExists := false
	if hasCP {
		if err := json.Unmarshal(cpRaw, &cp); err != nil {
			return nil, fmt.Errorf("parsing host %q command_policy: %w", host, err)
		}
		var cpObj map[string]json.RawMessage
		_ = json.Unmarshal(cpRaw, &cpObj)
		_, allowExists = cpObj["allow"]
	}

	type patchOp struct {
		Op    string `json:"op"`
		Path  string `json:"path"`
		Value any    `json:"value,omitempty"`
	}
	base := "/hosts/" + jsonPtrEscape(host) + "/command_policy"
	var ops []patchOp
	if add {
		if slices.Contains(cp.Allow, pattern) {
			return nil, fmt.Errorf("%w: pattern already in the allowlist", errNoChange)
		}
		setMode := cp.Mode == "" || cp.Mode == signer.CmdPolicyOff
		switch {
		case !hasCP:
			ops = append(ops, patchOp{"add", base, map[string]any{
				"mode": signer.CmdPolicyAllowlist, "allow": []string{pattern},
			}})
		case !allowExists:
			ops = append(ops, patchOp{"add", base + "/allow", []string{pattern}})
			if setMode {
				ops = append(ops, patchOp{"add", base + "/mode", signer.CmdPolicyAllowlist})
			}
		default:
			ops = append(ops, patchOp{"add", base + "/allow/-", pattern})
			if setMode {
				ops = append(ops, patchOp{"add", base + "/mode", signer.CmdPolicyAllowlist})
			}
		}
	} else {
		i := slices.Index(cp.Allow, pattern)
		if i < 0 {
			return nil, fmt.Errorf("%w: pattern not in the allowlist", errNoChange)
		}
		ops = append(ops, patchOp{Op: "remove", Path: fmt.Sprintf("%s/allow/%d", base, i)})
	}
	patch, err := json.Marshal(ops)
	if err != nil {
		return nil, err
	}
	return confcheck.Patch(orig, patch)
}

// atomicWrite writes b to path via a temp file + rename, preserving the existing
// file's permissions.
func atomicWrite(path string, b []byte) error {
	mode := os.FileMode(0o600)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// auditPolicy records a policy mutation attempt in the signed audit log.
func (s *server) auditPolicy(caller, host, pattern string, add bool, outcome string, err error) {
	op := "policy-allow-remove"
	if add {
		op = "policy-allow-add"
	}
	// The pattern is a caller-supplied regex that legitimately contains spaces
	// (e.g. "^systemctl restart nginx$"), so it must NOT go into Command — the
	// project's space-separated key=value token stream — where it could splice
	// forged attribution tokens (user=/elev=/role=). It is recorded in the
	// discrete, labeled PolicyRule field instead (shown as "[rule: ...]").
	e := audit.Entry{Caller: caller, Host: host, Command: op, Outcome: outcome}
	if pattern != "" {
		e.PolicyRule = "allow:" + pattern
	}
	if err != nil {
		e.Err = err.Error()
	}
	if aerr := s.audit.Append(e); aerr != nil {
		log.Printf("warning: error writing signer audit log: %v", aerr)
	}
}

// handlePolicyHostsRead serves the full host-policy table (GET /v1/policy/hosts).
// Auth is mTLS + reload_callers — the same "may change policy" tier as the
// mutation APIs above, because the response carries every internal policy field
// (principal, source_address, TTLs, allowed_callers, command_policy) that
// GET /v1/hosts deliberately withholds from brokers. It serves the current
// in-memory table, so it reflects hot-reloads and runtime mutations without a
// restart. Successful reads and denied attempts are both recorded in the audit
// log: a full policy dump is security-sensitive. No X-On-Behalf-Of handling —
// the admin tier is direct-CN only, exactly like /v1/reload.
func (s *server) handlePolicyHostsRead(w http.ResponseWriter, r *http.Request) {
	caller, authd, authz := s.policyAdmin(r)
	if !authd {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	if !authz {
		s.auditPolicyRead(caller, 0, "policy-read-denied", errors.New("caller not authorised"))
		http.Error(w, "not authorised to read policy", http.StatusForbidden)
		return
	}
	_, hosts, _, _ := s.snapshot()
	if hosts == nil {
		hosts = signer.PolicyTable{}
	}
	s.auditPolicyRead(caller, len(hosts), "policy-read", nil)
	writeJSON(w, http.StatusOK, hosts)
}

// auditPolicyRead records a full host-policy read attempt in the signed audit log.
func (s *server) auditPolicyRead(caller string, hosts int, outcome string, err error) {
	e := audit.Entry{
		Caller:  caller,
		Command: fmt.Sprintf("policy-hosts-read hosts=%d", hosts),
		Outcome: outcome,
	}
	if err != nil {
		e.Err = err.Error()
	}
	if aerr := s.audit.Append(e); aerr != nil {
		log.Printf("warning: error writing signer audit log: %v", aerr)
	}
}
