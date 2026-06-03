// Command broker expone el motor del broker por HTTP+mTLS: un agente autorizado
// (cert de cliente) hace POST /v1/ssh_run y recibe solo la salida del comando.
// La credencial SSH efímera nunca sale del proceso.
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"

	"github.com/luisgf/ssh-broker/internal/auth"
	"github.com/luisgf/ssh-broker/internal/broker"
)

type runRequest struct {
	Host       string `json:"host"`
	Command    string `json:"command"`
	TTLSeconds int    `json:"ttl_seconds"`
	// Elevación NOPASSWD.
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
	cfgPath := flag.String("config", "config.json", "ruta al fichero de configuración JSON")
	flag.Parse()

	cfg, err := broker.LoadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	eng, err := broker.NewEngine(cfg)
	if err != nil {
		log.Fatalf("inicializar broker: %v", err)
	}
	defer eng.Close()

	tlsCfg, err := auth.ServerTLSConfig(cfg.ServerCert, cfg.ServerKey, cfg.ClientCA)
	if err != nil {
		log.Fatalf("tls: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/ssh_run", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "método no permitido", http.StatusMethodNotAllowed)
			return
		}
		caller, err := auth.CallerCN(r)
		if err != nil {
			http.Error(w, "no autenticado", http.StatusUnauthorized)
			return
		}
		var req runRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "petición inválida", http.StatusBadRequest)
			return
		}
		res, err := eng.Execute(caller, req.Host, req.Command, req.TTLSeconds,
			broker.ExecOptions{Sudo: req.Sudo, SudoUser: req.SudoUser, PTY: req.PTY})
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(runResponse{
			Stdout: res.Stdout, Stderr: res.Stderr, ExitCode: res.ExitCode, Serial: res.Serial,
		})
	})

	httpSrv := &http.Server{Addr: cfg.Listen, Handler: mux, TLSConfig: tlsCfg}
	log.Printf("broker HTTP (mTLS) en %s", cfg.Listen)
	log.Fatal(httpSrv.ListenAndServeTLS("", ""))
}
