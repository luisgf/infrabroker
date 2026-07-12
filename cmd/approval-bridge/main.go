// Command approval-bridge presents infrabroker approval requests on a chat
// platform (Slack, via Socket Mode) and relays Allow/Deny back to the control
// plane (#120). It is outbound-only: it polls the control plane's mTLS approval
// API and connects out to Slack, so nothing with approval authority becomes
// internet-facing.
//
// It is a convenience, not a new trust root — the control plane still enforces
// consumed-once and four-eyes. See docs/OPERATIONS.md and docs/THREAT_MODEL.md.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/luisgf/infrabroker/internal/auth"
	"github.com/luisgf/infrabroker/internal/bridge"
	"github.com/luisgf/infrabroker/internal/version"
)

func main() {
	cpURL := flag.String("cp-url", envOr("BRIDGE_CP_URL", ""), "control plane host:port (mTLS)")
	cert := flag.String("cert", envOr("BRIDGE_CERT", "./pki/approver.crt"), "approver client cert (CN must be in the control plane's approval.callers)")
	key := flag.String("key", envOr("BRIDGE_KEY", "./pki/approver.key"), "approver client key")
	ca := flag.String("ca", envOr("BRIDGE_CA", "./pki/mtls_ca.crt"), "mTLS CA for the control plane")
	channel := flag.String("slack-channel", envOr("SLACK_CHANNEL", ""), "Slack channel id to post approvals to")
	identityMapPath := flag.String("identity-map", envOr("BRIDGE_IDENTITY_MAP", ""), "path to a JSON {platform_user_id: end_user_identity} map; when set, the bridge refuses an approval whose clicker maps to the request's originator (four-eyes, #214)")
	poll := flag.Duration("poll", 5*time.Second, "how often to poll the control plane for pending approvals")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		version.Print(false)
		return
	}
	if *cpURL == "" {
		log.Fatalf("--cp-url (or BRIDGE_CP_URL) is required")
	}

	identityMap, err := loadIdentityMap(*identityMapPath)
	if err != nil {
		log.Fatalf("identity map: %v", err)
	}

	// Secrets come from the environment, never flags: bot token (xoxb-) and the
	// app-level token (xapp-) that enables Socket Mode.
	botToken, appToken := os.Getenv("SLACK_BOT_TOKEN"), os.Getenv("SLACK_APP_TOKEN")

	tlsCfg, err := auth.ClientTLSConfig(*cert, *key, *ca)
	if err != nil {
		log.Fatalf("approver mTLS: %v", err)
	}
	cp := bridge.NewHTTPControlPlane(*cpURL, tlsCfg)

	adapter, err := bridge.NewSlackAdapter(botToken, appToken, *channel)
	if err != nil {
		log.Fatalf("slack: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	guard := "OFF (documented residual; set --identity-map to enable)"
	if len(identityMap) > 0 {
		guard = "on"
	}
	log.Printf("approval-bridge: polling %s every %s, presenting on slack; self-approval guard %s", *cpURL, *poll, guard)
	if err := bridge.New(cp, adapter, *poll, identityMap).Run(ctx); err != nil && err != context.Canceled {
		log.Fatalf("approval-bridge: %v", err)
	}
	log.Printf("approval-bridge: stopped")
}

// loadIdentityMap reads a JSON {platform_user_id: end_user_identity} object from
// path. An empty path returns a nil map, leaving the bridge's self-approval guard
// off (the documented residual). An empty JSON object is rejected: configuring an
// empty map is almost certainly a mistake that would silently disable the guard.
func loadIdentityMap(path string) (map[string]string, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	if len(m) == 0 {
		return nil, fmt.Errorf("identity map %q is empty; omit --identity-map to run without the self-approval guard", path)
	}
	return m, nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
