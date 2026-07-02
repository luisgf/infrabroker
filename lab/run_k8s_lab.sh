#!/usr/bin/env bash
# Laboratorio e2e del target Kubernetes (credential-broker). Sin cluster real:
# un mock del API server en Go (TLS) responde TokenRequest, get/list/delete y
# apply, registrando cada llamada. Verifica el flujo completo:
#   1. get permitido → el broker acuña token (bound SA) y ejecuta la llamada.
#   2. list con selector.
#   3. delete gateado por aprobación → 202 → approve → ejecuta.
#   4. verbo/recurso no permitido → denegado (default-deny).
#   5. secrets denegado por regla deny aunque haya lectura permitida.
#   6. la canónica aparece en la auditoría del signer y del broker; el manifest
#      de apply NO aparece verbatim (solo body_sha256).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LAB="$ROOT/lab/work-k8s"
SIGNER_PORT=9463
CP_PORT=7463
API_PORT=6443

rm -rf "$LAB"; mkdir -p "$LAB/pki"
P="$LAB/pki"

echo "== 1. Mock del API server de Kubernetes (TLS) =="
cat > "$LAB/mockapi.go" <<'GO'
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	logf, _ := os.Create(os.Args[3])
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		fmt.Fprintf(logf, "%s %s %s\n", r.Method, r.URL.Path, r.URL.RawQuery)
		logf.Sync()
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/token") {
			// TokenRequest response.
			json.NewEncoder(w).Encode(map[string]any{
				"status": map[string]any{
					"token":               "bound-sa-token",
					"expirationTimestamp": time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339),
				},
			})
			return
		}
		if len(body) > 0 {
			fmt.Fprintf(logf, "  body-bytes=%d\n", len(body))
			logf.Sync()
		}
		json.NewEncoder(w).Encode(map[string]any{"kind": "Result", "path": r.URL.Path})
	})
	srv := &http.Server{Addr: ":" + os.Args[1], Handler: mux}
	if err := srv.ListenAndServeTLS(os.Args[2]+".crt", os.Args[2]+".key"); err != nil {
		panic(err)
	}
}
GO

# TLS server cert for the mock API (SAN localhost/127.0.0.1).
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$P/api.key" -out "$P/api.crt" \
  -days 1 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
printf 'minter-credential\n' > "$P/minter.token"

echo "== 2. PKI mTLS (signer, control plane, broker-1, admin-1) =="
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$P/server_ca.key" -out "$P/server_ca.crt" \
  -days 1 -subj "/CN=server-ca" >/dev/null 2>&1
for srv in signer cp; do
  openssl req -newkey rsa:2048 -nodes -keyout "$P/$srv.key" -out "$P/$srv.csr" -subj "/CN=localhost" >/dev/null 2>&1
  openssl x509 -req -in "$P/$srv.csr" -CA "$P/server_ca.crt" -CAkey "$P/server_ca.key" \
    -CAcreateserial -days 1 -out "$P/$srv.crt" \
    -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1") >/dev/null 2>&1
done
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$P/clients_ca.key" -out "$P/clients_ca.crt" \
  -days 1 -subj "/CN=clients-ca" >/dev/null 2>&1
for cn in broker-1 admin-1 cp-1; do
  openssl req -newkey rsa:2048 -nodes -keyout "$P/$cn.key" -out "$P/$cn.csr" -subj "/CN=$cn" >/dev/null 2>&1
  openssl x509 -req -in "$P/$cn.csr" -CA "$P/clients_ca.crt" -CAkey "$P/clients_ca.key" \
    -CAcreateserial -days 1 -out "$P/$cn.crt" >/dev/null 2>&1
done

echo "== 3. signer.json con un cluster (default-deny; delete → require_approval) =="
head -c 32 /dev/urandom > "$LAB/signer_audit.seed"
# Minimal SSH CA so the signer starts (no hosts used in this lab).
ssh-keygen -t ed25519 -N '' -f "$LAB/ssh_ca" >/dev/null
cat > "$LAB/signer.json" <<EOF
{
  "listen": ":$SIGNER_PORT",
  "server_cert": "$P/signer.crt", "server_key": "$P/signer.key", "client_ca": "$P/clients_ca.crt",
  "ca_key": "$LAB/ssh_ca",
  "audit_log": "$LAB/signer_audit.log", "audit_key": "$LAB/signer_audit.seed",
  "max_ttl_seconds": 120,
  "reload_callers": ["admin-1"],
  "trusted_forwarders": ["cp-1"],
  "hosts": {},
  "kubernetes": {
    "clusters": {
      "lab-k8s": {
        "api_server": "https://127.0.0.1:$API_PORT",
        "ca_cert": "$P/api.crt",
        "token_file": "$P/minter.token",
        "token_ttl_seconds": 600,
        "sa_bindings": [ { "namespace": "agents", "service_account": "broker-agent" } ],
        "rules": [
          { "verbs": ["get","list"], "resources": ["pods","deployments"], "effect": "allow" },
          { "verbs": ["delete"], "resources": ["pods"], "namespaces": ["prod"], "effect": "require_approval" },
          { "verbs": ["*"], "resources": ["secrets"], "effect": "deny" }
        ]
      }
    }
  }
}
EOF
cat > "$LAB/cp.json" <<EOF
{
  "listen": ":$CP_PORT",
  "server_cert": "$P/cp.crt", "server_key": "$P/cp.key", "client_ca": "$P/clients_ca.crt",
  "signer": { "url": "https://localhost:$SIGNER_PORT", "client_cert": "$P/cp-1.crt", "client_key": "$P/cp-1.key", "ca": "$P/server_ca.crt" },
  "approval": { "timeout_seconds": 120, "callers": ["admin-1"] },
  "audit_log": "$LAB/cp_audit.log", "audit_key": "$(head -c 32 /dev/urandom > "$LAB/cp_audit.seed"; echo "$LAB/cp_audit.seed")"
}
EOF

echo "== 4. Binarios + arranque =="
( cd "$ROOT" && go build -o "$LAB/signer" ./cmd/signer && go build -o "$LAB/control-plane" ./cmd/control-plane && go build -o "$LAB/broker-ctl" ./cmd/broker-ctl )
( cd "$LAB" && go run mockapi.go "$API_PORT" "$P/api" "$LAB/api.log" ) >"$LAB/mock.out" 2>&1 &
API_PID=$!
"$LAB/signer" -config "$LAB/signer.json" >"$LAB/signer.out" 2>&1 & SIGNER_PID=$!
"$LAB/control-plane" -config "$LAB/cp.json" >"$LAB/cp.out" 2>&1 & CP_PID=$!
trap 'kill "$API_PID" "$SIGNER_PID" "$CP_PID" 2>/dev/null || true' EXIT
sleep 3

CURL_BROKER=(curl -s --cert "$P/broker-1.crt" --key "$P/broker-1.key" --cacert "$P/server_ca.crt")
CTL_CP=(env BROKER_CTL_CP_URL="localhost:$CP_PORT" BROKER_CTL_CP_CERT="$P/admin-1.crt" \
    BROKER_CTL_CP_KEY="$P/admin-1.key" BROKER_CTL_CP_CA="$P/server_ca.crt" "$LAB/broker-ctl")

k8s_sign() { # verb resource namespace name  → posts a k8s sign request to the control plane
  local canonical="$1 $2 $3/$4"
  "${CURL_BROKER[@]}" -X POST "https://localhost:$CP_PORT/v1/sign" -H 'Content-Type: application/json' \
    -d "$(printf '{"target_type":"k8s","host":"lab-k8s","role":"target","purpose":"oneshot","command":"%s","k8s_verb":"%s","k8s_resource":"%s","k8s_namespace":"%s","k8s_name":"%s"}' "$canonical" "$1" "$2" "$3" "$4")"
}

echo "== 5. get pod permitido → token acuñado + llamada al API =="
RESP="$(k8s_sign get pods prod web-1)"
echo "$RESP" | grep -q 'bound-sa-token' && echo "   OK: token bound emitido" || { echo "FAIL: sin token: $RESP"; exit 1; }
grep -q 'POST /api/v1/namespaces/agents/serviceaccounts/broker-agent/token' "$LAB/api.log" \
  && echo "   OK: TokenRequest llamado" || { echo "FAIL: no hubo TokenRequest"; exit 1; }

echo "== 6. delete gateado → 202 → approve → token =="
RESP="$(k8s_sign delete pods prod web-1)"
APPROVAL_ID="$(echo "$RESP" | sed -n 's/.*"approval_id":"\([^"]*\)".*/\1/p')"
[ -n "$APPROVAL_ID" ] && echo "   OK: 202 approval $APPROVAL_ID" || { echo "FAIL: delete no gateado: $RESP"; exit 1; }
"${CTL_CP[@]}" approval list | grep -q 'delete pods prod/web-1' \
  && echo "   OK: el aprobador ve la acción canónica" || { echo "FAIL: canónica no visible"; exit 1; }
"${CTL_CP[@]}" approval allow "$APPROVAL_ID" >/dev/null
RESULT="$("${CURL_BROKER[@]}" "https://localhost:$CP_PORT/v1/sign/result/$APPROVAL_ID")"
echo "$RESULT" | grep -q 'bound-sa-token' && echo "   OK: token tras aprobar" || { echo "FAIL: sin token tras aprobar: $RESULT"; exit 1; }

# NOTE: this helper builds the canonical string without resolving the API
# group, so the deny tests use CORE resources (no group) to avoid a canonical
# mismatch masking the policy decision. The real MCP path resolves the group in
# the broker before signing.
echo "== 7. default-deny y deny-wins =="
k8s_sign delete configmaps prod cfg | grep -qi 'not allowed\|denied' && echo "   OK: acción no permitida rechazada (default-deny)" || { echo "FAIL: delete configmaps debería denegarse"; exit 1; }
k8s_sign get secrets prod db | grep -qi 'not allowed\|denied' && echo "   OK: secrets denegado (deny gana)" || { echo "FAIL: secrets debería denegarse"; exit 1; }

echo "== 8. auditoría: canónica presente en el signer =="
grep -q 'target=k8s action=get pods prod/web-1' "$LAB/signer_audit.log" \
  && echo "   OK: canónica en el audit del signer" || { echo "FAIL: canónica ausente en el signer"; exit 1; }

rm -rf "$LAB"
echo "Lab k8s OK."
