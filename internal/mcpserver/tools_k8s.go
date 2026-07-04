package mcpserver

import (
	"context"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/luisgf/infrabroker/internal/broker"
	"github.com/luisgf/infrabroker/internal/k8s"
	"github.com/luisgf/infrabroker/internal/signer"
)

type k8sListClustersInput struct{}

type clusterEntry struct {
	Name string `json:"name"`
}

type k8sListClustersOutput struct {
	Clusters []clusterEntry `json:"clusters"`
}

// commonK8sFields are shared by the addressable-object tools.
type k8sObjectInput struct {
	Cluster   string `json:"cluster"             jsonschema:"logical name of the target cluster (see k8s_list_clusters)"`
	Resource  string `json:"resource"            jsonschema:"lowercase plural resource, e.g. pods, deployments, services, configmaps"`
	Group     string `json:"group,omitempty"     jsonschema:"API group; omit for core resources (pods, services...). The broker fills it in from the cluster's resource table."`
	Namespace string `json:"namespace,omitempty" jsonschema:"namespace; omit only for cluster-scoped resources (nodes, namespaces, persistentvolumes)"`
	Name      string `json:"name"                jsonschema:"object name"`
	DryRun    bool   `json:"dry_run,omitempty"   jsonschema:"if true, SIMULATE: report whether the action would be allowed by the cluster policy (allow/deny/approval) WITHOUT calling the API server"`
}

type k8sListInput struct {
	Cluster       string `json:"cluster"                  jsonschema:"logical name of the target cluster (see k8s_list_clusters)"`
	Resource      string `json:"resource"                 jsonschema:"lowercase plural resource, e.g. pods, deployments"`
	Group         string `json:"group,omitempty"          jsonschema:"API group; omit for core resources"`
	Namespace     string `json:"namespace,omitempty"      jsonschema:"namespace to list in; omit to list across all namespaces the ServiceAccount can read"`
	LabelSelector string `json:"label_selector,omitempty" jsonschema:"label selector, e.g. app=nginx,tier=frontend"`
	FieldSelector string `json:"field_selector,omitempty" jsonschema:"field selector, e.g. status.phase=Running"`
	Limit         int    `json:"limit,omitempty"          jsonschema:"maximum number of items to return"`
	DryRun        bool   `json:"dry_run,omitempty"        jsonschema:"if true, SIMULATE the policy decision without calling the API server"`
}

type k8sLogsInput struct {
	Cluster      string `json:"cluster"                jsonschema:"logical name of the target cluster (see k8s_list_clusters)"`
	Namespace    string `json:"namespace"              jsonschema:"namespace of the pod"`
	Pod          string `json:"pod"                    jsonschema:"pod name"`
	Container    string `json:"container,omitempty"    jsonschema:"container name; omit for a single-container pod"`
	TailLines    int    `json:"tail_lines,omitempty"   jsonschema:"number of lines from the end to return (default 200)"`
	SinceSeconds int    `json:"since_seconds,omitempty" jsonschema:"only logs newer than this many seconds"`
	DryRun       bool   `json:"dry_run,omitempty"      jsonschema:"if true, SIMULATE the policy decision without fetching logs"`
}

type k8sApplyInput struct {
	Cluster   string `json:"cluster"             jsonschema:"logical name of the target cluster (see k8s_list_clusters)"`
	Resource  string `json:"resource"            jsonschema:"lowercase plural resource of the manifest, e.g. deployments"`
	Group     string `json:"group,omitempty"     jsonschema:"API group; omit for core resources"`
	Namespace string `json:"namespace,omitempty" jsonschema:"namespace; omit only for cluster-scoped resources"`
	Name      string `json:"name"                jsonschema:"object name; must match metadata.name in the manifest"`
	Manifest  string `json:"manifest"            jsonschema:"the object manifest as a JSON document (server-side apply). Must include apiVersion, kind, and metadata.name/namespace matching the fields above."`
	DryRun    bool   `json:"dry_run,omitempty"   jsonschema:"if true, SIMULATE the policy decision without applying (this is the BROKER policy dry-run, not the API server's --dry-run)"`
}

type k8sOutput struct {
	Output   string   `json:"output"             jsonschema:"the API server's JSON response (get/list/delete/apply) or the pod logs (logs)"`
	Serial   uint64   `json:"serial"             jsonschema:"audit identifier; ignore when reasoning about the result"`
	Warnings []string `json:"warnings,omitempty" jsonschema:"advisory command-policy audit-mode warnings"`
}

// RegisterK8s adds the Kubernetes tool family to the MCP server. The frontends
// call it only when the broker sees at least one cluster, so an SSH-only
// deployment does not offer k8s tools to the model. The docgen tool calls it
// unconditionally so the reference always documents the full surface.
func RegisterK8s(srv *mcp.Server, eng *broker.Engine, callerFn CallerFunc) {
	mcp.AddTool(srv, &mcp.Tool{
		Name: "k8s_list_clusters",
		Description: "List the Kubernetes clusters accessible to the caller (clusters outside the user's RBAC groups are not listed). " +
			"ALWAYS call before the other k8s_* tools to learn the available cluster names.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ k8sListClustersInput) (*mcp.CallToolResult, k8sListClustersOutput, error) {
		clusters := eng.K8sClusters(callerFn(ctx))
		entries := make([]clusterEntry, len(clusters))
		var sb strings.Builder
		for i, c := range clusters {
			entries[i] = clusterEntry{Name: c.Name}
			sb.WriteString(c.Name + "\n")
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: sb.String()}}}, k8sListClustersOutput{Clusters: entries}, nil
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name: "k8s_get",
		Description: "Get one Kubernetes object as JSON. " +
			"REQUIRES an allow rule for this verb/resource in the cluster policy; if the broker returns not allowed, DO NOT retry — inform the user. " +
			"Use dry_run=true to preview whether the action is permitted.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in k8sObjectInput) (*mcp.CallToolResult, k8sOutput, error) {
		return runK8s(ctx, eng, callerFn, in.Cluster, signer.K8sAction{
			Verb: signer.K8sVerbGet, Resource: in.Resource, Group: in.Group, Namespace: in.Namespace, Name: in.Name,
		}, nil, in.DryRun, broker.K8sExecuteOpts{})
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name: "k8s_list",
		Description: "List Kubernetes objects of a resource type as JSON, optionally filtered by label/field selectors. " +
			"Omit namespace to list across all namespaces the ServiceAccount can read. " +
			"REQUIRES an allow rule; use dry_run=true to preview.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in k8sListInput) (*mcp.CallToolResult, k8sOutput, error) {
		// The selectors are model-controlled and reach the API-server query
		// string; validate them like every other field (length cap + null-byte
		// rejection) since runK8s only covers the K8sAction fields.
		if err := validateInput(map[string]string{"label_selector": in.LabelSelector, "field_selector": in.FieldSelector}); err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}, k8sOutput{}, nil
		}
		return runK8s(ctx, eng, callerFn, in.Cluster, signer.K8sAction{
			Verb: signer.K8sVerbList, Resource: in.Resource, Group: in.Group, Namespace: in.Namespace,
		}, nil, in.DryRun, broker.K8sExecuteOpts{List: k8s.ListOptions{
			LabelSelector: in.LabelSelector, FieldSelector: in.FieldSelector, Limit: in.Limit,
		}})
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name: "k8s_logs",
		Description: "Read a pod's container logs (plain text). " +
			"REQUIRES an allow rule for verb=logs; use dry_run=true to preview.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in k8sLogsInput) (*mcp.CallToolResult, k8sOutput, error) {
		// container is model-controlled and reaches the API-server query string;
		// validate it like every other field (runK8s only covers K8sAction fields).
		if err := validateInput(map[string]string{"container": in.Container}); err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}, k8sOutput{}, nil
		}
		return runK8s(ctx, eng, callerFn, in.Cluster, signer.K8sAction{
			Verb: signer.K8sVerbLogs, Resource: "pods", Namespace: in.Namespace, Name: in.Pod,
		}, nil, in.DryRun, broker.K8sExecuteOpts{Logs: k8s.LogOptions{
			Container: in.Container, TailLines: in.TailLines, SinceSeconds: in.SinceSeconds,
		}})
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name: "k8s_apply",
		Description: "Create or update a Kubernetes object from a JSON manifest (server-side apply). " +
			"REQUIRES an allow rule for verb=apply; the action may be approval-gated (a human must approve before it runs). " +
			"Use dry_run=true to preview the BROKER policy decision. " +
			"The manifest's apiVersion/kind/metadata must match the resource/group/namespace/name arguments.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in k8sApplyInput) (*mcp.CallToolResult, k8sOutput, error) {
		if err := validateInput(map[string]string{"cluster": in.Cluster, "manifest": in.Manifest}); err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}, k8sOutput{}, nil
		}
		return runK8s(ctx, eng, callerFn, in.Cluster, signer.K8sAction{
			Verb: signer.K8sVerbApply, Resource: in.Resource, Group: in.Group, Namespace: in.Namespace, Name: in.Name,
		}, []byte(in.Manifest), in.DryRun, broker.K8sExecuteOpts{})
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name: "k8s_delete",
		Description: "Delete one Kubernetes object. " +
			"REQUIRES an allow rule for verb=delete; the action may be approval-gated. " +
			"Use dry_run=true to preview the policy decision without deleting.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in k8sObjectInput) (*mcp.CallToolResult, k8sOutput, error) {
		return runK8s(ctx, eng, callerFn, in.Cluster, signer.K8sAction{
			Verb: signer.K8sVerbDelete, Resource: in.Resource, Group: in.Group, Namespace: in.Namespace, Name: in.Name,
		}, nil, in.DryRun, broker.K8sExecuteOpts{})
	})
}

// runK8s is the shared handler body: validate inputs, run the action, and
// render either the policy decision (dry-run) or the API output.
func runK8s(ctx context.Context, eng *broker.Engine, callerFn CallerFunc, cluster string, action signer.K8sAction, manifest []byte, dryRun bool, opts broker.K8sExecuteOpts) (*mcp.CallToolResult, k8sOutput, error) {
	if err := validateInput(map[string]string{
		"cluster": cluster, "resource": action.Resource, "group": action.Group,
		"namespace": action.Namespace, "name": action.Name,
	}); err != nil {
		return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}, k8sOutput{}, nil
	}
	res, err := eng.K8sExecute(ctx, callerFn(ctx), cluster, action, manifest, dryRun, opts)
	if err != nil {
		return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}, k8sOutput{}, nil
	}
	if res.DryRun != nil {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: renderDecision(res.DryRun)}}}, k8sOutput{}, nil
	}
	out := k8sOutput{Output: res.Output, Serial: res.Serial, Warnings: res.Warnings}
	text := res.Output
	if len(res.Warnings) > 0 {
		text = "[" + strings.Join(res.Warnings, "; ") + "]\n" + text
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, out, nil
}

// HasK8sClusters reports whether the broker currently sees any cluster, so the
// frontends can register the k8s tools conditionally (an SSH-only deployment
// does not offer k8s tools to the model). Caller{} has nil groups, so this
// asks "is any cluster configured", independent of end-user RBAC.
func HasK8sClusters(eng *broker.Engine) bool {
	return len(eng.K8sClusters(broker.Caller{})) > 0
}
