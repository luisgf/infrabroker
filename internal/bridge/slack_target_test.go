package bridge

import (
	"strings"
	"testing"

	"github.com/slack-go/slack"

	"github.com/luisgf/infrabroker/internal/control"
	"github.com/luisgf/infrabroker/internal/signer"
)

// TestSlackApprovalLabelsCluster: a k8s approval's card names a cluster, not
// a host; an SSH card is unchanged (#664).
func TestSlackApprovalLabelsCluster(t *testing.T) {
	text := func(ap control.Approval) string {
		for _, blk := range buildApprovalBlocks(ap) {
			if sb, ok := blk.(*slack.SectionBlock); ok && sb.Text != nil && sb.Text.Type == slack.PlainTextType {
				return sb.Text.Text
			}
		}
		t.Fatal("no plain_text section")
		return ""
	}
	k8s := control.Approval{ID: "ap1", Caller: "brk1", Host: "prod-aks", Command: "delete pods prod/web-1", TargetType: signer.TargetTypeK8s}
	if got := text(k8s); !strings.HasPrefix(got, "run delete pods prod/web-1 on cluster prod-aks\n") {
		t.Errorf("k8s card must name the cluster, got %q", got)
	}
	ssh := control.Approval{ID: "ap2", Caller: "brk1", Host: "web01", Command: "uptime"}
	if got := text(ssh); got != "run uptime on web01\ncaller brk1" {
		t.Errorf("SSH card must be unchanged, got %q", got)
	}
}
