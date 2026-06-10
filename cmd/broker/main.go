// Command broker exposes the broker engine over HTTP+mTLS: an authorised agent
// (client certificate) POSTs /v1/ssh_run and receives only the command output.
// The ephemeral SSH credential never leaves the process.
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/luisgf/ssh-broker/internal/auth"
	"github.com/luisgf/ssh-broker/internal/broker"
	"github.com/luisgf/ssh-broker/internal/httpserve"
)

type runRequest struct {
	Host       string `json:"host"`
	Command    string `json:"command"`
	TTLSeconds int    `json:"ttl_seconds"`
	// Elevation NOPASSWD.
	Sudo     bool   `json:"sudo,omitempty"`
	SudoUser string `json:"sudo_user,omitempty"`
	// PTY.
	PTY bool `json:"pty,omitempty"`
}

type runResponse struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exit_code"`
	Serial   uint64 `json:"serial"`
}

func main() {
	cfgPath := flag.String("config", "config.json", "path to JSON configuration file")
	flag.Parse()

	cfg, err := broker.LoadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	eng, err := broker.NewEngine(cfg)
	if err != nil {
		log.Fatalf("initialising broker: %v", err)
	}
	defer eng.Close()

	tlsCfg, err := auth.ServerTLSConfig(cfg.ServerCert, cfg.ServerKey, cfg.ClientCA)
	if err != nil {
		log.Fatalf("tls: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/ssh_run", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		caller, err := auth.CallerCN(r)
		if err != nil {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		// A2: limit the request body to prevent OOM from oversized payloads.
		r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
		var req runRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		res, err := eng.Execute(r.Context(), broker.Caller{ID: caller}, req.Host, req.Command, req.TTLSeconds,
			broker.ExecOptions{Sudo: req.Sudo, SudoUser: req.SudoUser, PTY: req.PTY})
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		writeJSON(w, http.StatusOK, runResponse{
			Stdout: res.Stdout, Stderr: res.Stderr, ExitCode: res.ExitCode, Serial: res.Serial,
		})
	})

	// A1: timeouts to prevent connection exhaustion (slowloris and hung
	// connections). WriteTimeout deliberately not set: the response is written
	// only after the remote command completes, which may take up to the SSH
	// execution timeout (10 min) — same rationale as cmd/mcp-broker-http.
	httpSrv := &http.Server{
		Addr:        cfg.Listen,
		Handler:     mux,
		TLSConfig:   tlsCfg,
		ReadTimeout: 15 * time.Second,
		IdleTimeout: 120 * time.Second,
	}
	log.Printf("broker HTTP (mTLS) on %s", cfg.Listen)
	httpserve.RunTLS(httpSrv, "broker", 10*time.Second)
}

// writeJSON serialises v as JSON with the given HTTP status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("writeJSON: %v", err)
	}
}
