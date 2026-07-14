package brokermain

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/luisgf/infrabroker/internal/auth"
	"github.com/luisgf/infrabroker/internal/broker"
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
	Stdout   string   `json:"stdout"`
	Stderr   string   `json:"stderr"`
	ExitCode int      `json:"exit_code"`
	Serial   uint64   `json:"serial"`
	Warnings []string `json:"warnings,omitempty"`
}

// RunHTTP serves the broker engine over HTTP+mTLS — the `serve-http` transport
// (legacy binary `broker`): an authorised agent (client certificate) POSTs
// /v1/ssh_run and receives only the command output. The ephemeral SSH credential
// never leaves the process.
func RunHTTP(args []string) {
	cfgPath, done := parseCommonFlags("broker", args)
	if done {
		return
	}
	eng, cfg := Boot("broker", cfgPath)
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
			status, msg := classifyError(err)
			http.Error(w, msg, status)
			return
		}
		writeJSON(w, http.StatusOK, runResponse{
			Stdout: res.Stdout, Stderr: res.Stderr, ExitCode: res.ExitCode, Serial: res.Serial, Warnings: res.Warnings,
		})
	})

	log.Printf("broker HTTP (mTLS) on %s", cfg.Listen)
	serveHTTP(cfg, tlsCfg, mux, "broker")
}

// classifyError maps an engine error to an HTTP status and a client-facing
// message. Policy/authorization denials are 403 and keep their (useful) text;
// malformed requests are 400; an unknown host is 404; infrastructure failures
// are 502 with a generic message, so internal addresses from dial errors are
// not leaked to the client (the full error is still audited engine-side).
func classifyError(err error) (int, string) {
	switch {
	case errors.Is(err, broker.ErrBadRequest):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, broker.ErrUnknownHost):
		return http.StatusNotFound, err.Error()
	case errors.Is(err, broker.ErrUpstream):
		return http.StatusBadGateway, "upstream failure"
	case errors.Is(err, broker.ErrAuditUnavailable):
		// Fail-closed audit: the action's result is withheld because it could not
		// be durably recorded. 500 (a broker-side availability failure), not 403.
		return http.StatusInternalServerError, "audit unavailable"
	default:
		return http.StatusForbidden, err.Error()
	}
}

// writeJSON serialises v as JSON with the given HTTP status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("writeJSON: %v", err)
	}
}
