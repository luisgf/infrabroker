package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
)

// cmdCluster dispatches the `cluster` subcommands.
func cmdCluster(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: broker-ctl cluster list --remote")
		os.Exit(1)
	}
	switch args[0] {
	case "list":
		cmdClusterList(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown cluster subcommand: %q\n", args[0])
		os.Exit(1)
	}
}

// wireClusterInfo mirrors signer.WireClusterInfo for decoding GET /v1/clusters
// without importing the signer package here.
type wireClusterInfo struct {
	APIServer      string   `json:"api_server"`
	CACertPEM      string   `json:"ca_cert_pem"`
	Groups         []string `json:"groups,omitempty"`
	ExtraResources []struct {
		Resource string `json:"resource"`
	} `json:"extra_resources,omitempty"`
}

// cmdClusterList reads the Kubernetes clusters the caller may reach from the
// signer's GET /v1/clusters (mTLS) and renders them. The recommended
// post-deploy check for a k8s target — the endpoint is caller-scoped, so a
// non-200 is a hard failure (no silent fallback).
func cmdClusterList(args []string) {
	fs := flag.NewFlagSet("cluster list", flag.ExitOnError)
	remote := fs.Bool("remote", false, "read the live cluster list from the signer over mTLS (required)")
	urlFlag, cert, key, ca := signerFlags(fs)
	must(fs.Parse(args))
	if !*remote {
		fatalf("cluster list requires --remote (clusters live only in the signer, not the local config)")
	}
	resolveSignerTarget(fs)
	client, base := policyHTTP(*urlFlag, *cert, *key, *ca)

	var clusters map[string]wireClusterInfo
	doJSON(client, http.MethodGet, base+"/v1/clusters", nil, &clusters)
	if len(clusters) == 0 {
		fmt.Println("(no kubernetes clusters configured or visible to this caller)")
		return
	}
	names := make([]string, 0, len(clusters))
	for n := range clusters {
		names = append(names, n)
	}
	sort.Strings(names)

	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tAPI SERVER\tGROUPS\tEXTRA RESOURCES")
	for _, n := range names {
		c := clusters[n]
		extra := make([]string, 0, len(c.ExtraResources))
		for _, r := range c.ExtraResources {
			extra = append(extra, r.Resource)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", n, c.APIServer,
			joinOrDash(c.Groups), joinOrDash(extra))
	}
	tw.Flush()
}

func joinOrDash(s []string) string {
	if len(s) == 0 {
		return "-"
	}
	return strings.Join(s, ",")
}
