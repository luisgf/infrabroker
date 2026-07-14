// Command broker is a thin, DEPRECATED compatibility wrapper for
// `infrabroker serve-http` — the broker engine over HTTP+mTLS (POST /v1/ssh_run).
// Prefer the unified `infrabroker` binary; this name is kept so existing deploy
// units, scripts and client configs keep working unchanged. Same flags, same
// behaviour.
package main

import (
	"os"

	"github.com/luisgf/infrabroker/internal/brokermain"
)

func main() { brokermain.RunHTTP(os.Args[1:]) }
