package main

import (
	"fmt"
	"net/http"

	"github.com/luisgf/ssh-broker/internal/audit"
	"github.com/luisgf/ssh-broker/internal/auth"
	"github.com/luisgf/ssh-broker/internal/signer"
)

// handleSignK8s is the Kubernetes branch of /v1/sign. The generic gates
// (rate limit, body decode, identity token-char checks, caller resolution,
// forwarder/approved) already ran in handleSign; here we do the k8s-specific
// group authorization, build the k8s intent, sign (mint a bound token), and
// audit with the canonical action.
func (s *server) handleSignK8s(w http.ResponseWriter, r *http.Request, caller string, req signer.WireRequest, isForwarder, effectiveApproved bool, local localSigner, callers signer.CallerTable) {
	clusters := local.Clusters()
	if _, ok := clusters[req.Host]; !ok {
		s.auditK8s(caller, req, 0, "denied", nil, fmt.Errorf("no policy for cluster %q", req.Host))
		http.Error(w, "unknown cluster", http.StatusForbidden)
		return
	}
	// Per-caller group RBAC over the cluster table (mirrors HostSetForCaller).
	if set, restricted := signer.ClusterSetForCaller(caller, clusters, callers); restricted {
		if _, ok := set[req.Host]; !ok {
			s.auditK8s(caller, req, 0, "denied", nil, fmt.Errorf("cluster %q outside group for %q", req.Host, caller))
			http.Error(w, "cluster not authorised", http.StatusForbidden)
			return
		}
	}

	action := signer.K8sAction{
		Verb:      req.K8sVerb,
		Resource:  req.K8sResource,
		Group:     req.K8sGroup,
		Namespace: req.K8sNamespace,
		Name:      req.K8sName,
	}
	in := signer.Intent{
		Caller:        caller,
		Host:          req.Host,
		TargetType:    signer.TargetTypeK8s,
		K8s:           &action,
		Role:          signer.RoleTarget,
		Purpose:       signer.PurposeOneshot,
		Command:       req.Command,
		DryRun:        req.DryRun,
		Preflight:     req.Preflight,
		Approved:      effectiveApproved,
		EndUser:       req.EndUser,
		EndUserGroups: req.EndUserGroups,
	}
	issued, err := local.SignIntent(r.Context(), in)
	if err != nil {
		s.auditK8s(caller, req, 0, "denied", nil, err)
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if isForwarder && req.LearnTTLSeconds > 0 {
		s.maybeLearnWaiver(caller, req, issued)
	}
	s.respondSignK8s(w, caller, req, issued)
}

// respondSignK8s audits and writes the response for the three k8s cases:
// dry-run, approval-required, and token issued.
func (s *server) respondSignK8s(w http.ResponseWriter, caller string, req signer.WireRequest, issued *signer.Issued) {
	if req.DryRun {
		outcome := "dry_run_allowed"
		if issued.Decision != nil && !issued.Decision.Allowed {
			outcome = "dry_run_denied"
		}
		s.auditK8s(caller, req, 0, outcome, issued.Decision, nil)
		writeJSON(w, http.StatusOK, signer.WireResponse{Decision: issued.Decision})
		return
	}
	if issued.K8sToken == "" {
		s.auditK8s(caller, req, 0, "approval-required", issued.Decision, nil)
		writeJSON(w, http.StatusOK, signer.WireResponse{Decision: issued.Decision})
		return
	}
	s.auditK8s(caller, req, issued.Serial, "issued", issued.Decision, nil)
	writeJSON(w, http.StatusOK, signer.WireResponse{
		K8sToken:       issued.K8sToken,
		K8sTokenExpiry: issued.K8sTokenExpiry,
		Serial:         issued.Serial,
		Decision:       issued.Decision,
	})
}

// auditK8s records a k8s issuance decision. The canonical action is the
// Command; the api_server is the audited Host. A k8s_apply manifest is never
// logged verbatim (it can carry a Secret) — its sha256 rides in body_sha256,
// added by the broker's execution entry, not here.
func (s *server) auditK8s(caller string, req signer.WireRequest, serial uint64, outcome string, dec *signer.DecisionInfo, err error) {
	signRequestsTotal.With(outcome).Inc()
	host := req.Host
	if cp, ok := s.currentClusters()[req.Host]; ok {
		host = cp.APIServer
	}
	cmd := "target=k8s action=" + req.Command
	if req.EndUser != "" {
		cmd += " user=" + req.EndUser
	}
	e := audit.Entry{
		Caller:     caller,
		Host:       host,
		Command:    cmd,
		Serial:     serial,
		Outcome:    outcome,
		TargetType: signer.TargetTypeK8s,
	}
	if dec != nil {
		e.PolicyRule = dec.MatchedRule
		e.Warning = dec.Warning
	}
	if err != nil {
		e.Err = err.Error()
	}
	s.appendAudit(e)
}

// currentClusters returns the compiled cluster table under RLock.
func (s *server) currentClusters() signer.ClusterTable {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.local.Clusters()
}

// handleClusters serves GET /v1/clusters: the connectivity data for the
// clusters accessible to the caller (group-filtered like /v1/hosts, and
// gated by per-cluster allowed_callers). Internal policy — token_file, SA
// bindings, rules — is never exposed.
func (s *server) handleClusters(w http.ResponseWriter, r *http.Request) {
	caller, err := auth.CallerCN(r)
	if err != nil {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	s.mu.RLock()
	clusters := s.local.Clusters()
	callers := s.callers
	forwarders := s.forwarders
	s.mu.RUnlock()

	caller, ok := resolveCaller(caller, r.Header.Get(signer.HeaderOnBehalfOf), forwarders)
	if !ok {
		http.Error(w, "on_behalf_of not allowed for this caller", http.StatusForbidden)
		return
	}

	result := make(map[string]signer.WireClusterInfo, len(clusters))
	for name, cp := range clusters {
		if !cp.AllowsCaller(caller) {
			continue
		}
		wire := signer.WireClusterInfo{
			APIServer: cp.APIServer,
			CACertPEM: string(cp.CAPEM),
			Groups:    cp.Groups,
		}
		for _, rd := range cp.ExtraResources {
			wire.ExtraResources = append(wire.ExtraResources, signer.ResourceDef{
				Resource: rd.Resource, Group: rd.Group, Version: rd.Version,
				Kind: rd.Kind, Namespaced: rd.Namespaced,
			})
		}
		result[name] = wire
	}
	if set, restricted := signer.ClusterSetForCaller(caller, clusters, callers); restricted {
		for name := range result {
			if _, ok := set[name]; !ok {
				delete(result, name)
			}
		}
	}
	writeJSON(w, http.StatusOK, result)
}
