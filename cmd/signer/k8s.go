package main

import (
	"fmt"
	"net/http"

	"github.com/luisgf/infrabroker/internal/audit"
	"github.com/luisgf/infrabroker/internal/auth"
	"github.com/luisgf/infrabroker/internal/signer"
)

// handleSignK8s is the Kubernetes branch of /v1/sign. The generic gates
// (rate limit, body decode, identity token-char checks, caller resolution,
// forwarder/approved) already ran in handleSign; here we do the k8s-specific
// group authorization, build the k8s intent, sign (mint a bound token), and
// audit with the canonical action.
func (s *server) handleSignK8s(w http.ResponseWriter, r *http.Request, caller string, req signer.WireRequest, isForwarder, effectiveApproved bool, local localSigner, callers signer.CallerTable) {
	clusters := local.Clusters()
	if _, ok := clusters[req.Host]; !ok {
		if aerr := s.auditK8s(caller, req, 0, "denied", nil, fmt.Errorf("no policy for cluster %q", req.Host)); aerr != nil {
			writeAuditUnavailable(w)
			return
		}
		http.Error(w, "unknown cluster", http.StatusForbidden)
		return
	}
	// Per-caller group RBAC over the cluster table (mirrors HostSetForCaller).
	if set, restricted := signer.ClusterSetForCaller(caller, clusters, callers); restricted {
		if _, ok := set[req.Host]; !ok {
			if aerr := s.auditK8s(caller, req, 0, "denied", nil, fmt.Errorf("cluster %q outside group for %q", req.Host, caller)); aerr != nil {
				writeAuditUnavailable(w)
				return
			}
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
		if aerr := s.auditK8s(caller, req, 0, "denied", nil, err); aerr != nil {
			writeAuditUnavailable(w)
			return
		}
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	// Persist the token result FIRST; mint the approve-and-learn waiver only after
	// respondSignK8s confirms the bound token was issued AND its "issued" record
	// committed, so a fail-closed audit denial cannot leave a durable, restart-
	// surviving waiver behind (#222, k8s sibling of the SSH path).
	if !s.respondSignK8s(w, caller, req, issued) {
		return
	}
	if isForwarder && req.LearnTTLSeconds > 0 {
		s.maybeLearnWaiver(caller, req, issued)
	}
}

// respondSignK8s audits and writes the response for the three k8s cases:
// dry-run, approval-required, and token issued. It returns true only in the last
// case AND only once the "issued" record has committed, so the caller can gate
// the approve-and-learn waiver on an issuance that actually happened.
func (s *server) respondSignK8s(w http.ResponseWriter, caller string, req signer.WireRequest, issued *signer.Issued) bool {
	if req.DryRun {
		outcome := "dry_run_allowed"
		if issued.Decision != nil && !issued.Decision.Allowed {
			outcome = "dry_run_denied"
		}
		if aerr := s.auditK8s(caller, req, 0, outcome, issued.Decision, nil); aerr != nil {
			writeAuditUnavailable(w)
			return false
		}
		writeJSON(w, http.StatusOK, signer.WireResponse{Decision: issued.Decision})
		return false
	}
	if issued.K8sToken == "" {
		if aerr := s.auditK8s(caller, req, 0, "approval-required", issued.Decision, nil); aerr != nil {
			writeAuditUnavailable(w)
			return false
		}
		writeJSON(w, http.StatusOK, signer.WireResponse{Decision: issued.Decision})
		return false
	}
	// Issuance gate: no durable "issued" record, no bound token in the response.
	if aerr := s.auditK8s(caller, req, issued.Serial, "issued", issued.Decision, nil); aerr != nil {
		writeAuditUnavailable(w)
		return false
	}
	writeJSON(w, http.StatusOK, signer.WireResponse{
		K8sToken:       issued.K8sToken,
		K8sTokenExpiry: issued.K8sTokenExpiry,
		Serial:         issued.Serial,
		Decision:       issued.Decision,
	})
	return true
}

// auditK8s records a k8s issuance decision. The api_server is the audited
// Host. The action is written from the STRUCTURED, token-safe req.K8s* fields
// (validated in handleSign) rather than the free-form req.Command, so a
// crafted command cannot splice forged key=value tokens into the signed,
// space-separated token stream on the denial paths (where req.Command has not
// yet been checked against the canonical). A k8s_apply manifest is never
// logged verbatim (it can carry a Secret) — its sha256 rides in body_sha256,
// added by the broker's execution entry, not here.
// auditK8s is the single audit funnel for the /v1/sign Kubernetes branch. Like
// auditEmission it returns an error in fail-closed mode so the caller denies the
// request (no bound token leaves the signer) when the log cannot be written.
func (s *server) auditK8s(caller string, req signer.WireRequest, serial uint64, outcome string, dec *signer.DecisionInfo, err error) error {
	signRequestsTotal.With(outcome).Inc()
	host := req.Host
	if cp, ok := s.currentClusters()[req.Host]; ok {
		host = cp.APIServer
	}
	resource := req.K8sResource
	if req.K8sGroup != "" {
		resource += "." + req.K8sGroup
	}
	ns, name := req.K8sNamespace, req.K8sName
	if ns == "" {
		ns = "-"
	}
	if name == "" {
		name = "-"
	}
	cmd := "target=k8s verb=" + req.K8sVerb + " resource=" + resource + " ns=" + ns + " name=" + name
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
	return s.appendAudit(e)
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

	peerCN := caller
	caller, ok := resolveCaller(caller, r.Header.Get(signer.HeaderOnBehalfOf), forwarders)
	if !ok {
		http.Error(w, "on_behalf_of not allowed for this caller", http.StatusForbidden)
		return
	}

	// Kill switch (#203): a frozen caller learns no cluster connectivity, even
	// though /v1/clusters mints no token (info-disclosure only — api_server,
	// inlined CA PEM, groups). Tests the raw peer CN too, since a forwarder's
	// traffic is always on_behalf_of.
	if _, frozen := s.frozenSubject(peerCN, caller, ""); frozen {
		http.Error(w, "subject is frozen", http.StatusForbidden)
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
