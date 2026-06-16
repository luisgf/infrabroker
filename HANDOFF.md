# Handoff: SSH Broker con CA Efímera para Agentes de IA

> Documento de traspaso para retomar la sesión de desarrollo. Última
> actualización: 2026-06-16 (v1.13.0 — **revisión adversarial (red-team) de
> seguridad** en rama `fix/security-redteam-audit`: cierra el bypass del firewall
> de comandos vía `role=bastion` en hosts `allow_as_bastion`+`command_policy`
> (HIGH); el bypass de RBAC per-usuario donde un deny-all (`[]grupos`) colapsaba a
> nil/sin-filtro por `omitempty` en el wire (HIGH); `GET /v1/hosts` que ignoraba
> `allowed_callers`; la aprobación humana que ocultaba `sudo`; inyección de
> caracteres de control en el KeyID del cert; verificación de auditoría entre
> ficheros rotados (`broker-ctl audit verify --all`); `host add --force` que
> borraba el `command_policy` entero; y el modo local que marcaba `allow_as_bastion`
> en todos los hosts. +10 tests de regresión.
> v1.12.7 — última tanda de la revisión de fallos de lógica (nbf/clock-skew OIDC,
> última línea sin `\n` en shells, mapeo de errores HTTP del broker, reload que
> verifica el PID, grabaciones con tope, versión de build desde el tag git).
> v1.12.6 cerró la segunda tanda; v1.12.5 los dos bypasses del firewall del signer.
> Estado y pendientes; el resto de la documentación está enlazada abajo.

## Índice de documentación

| Documento | Contenido |
|---|---|
| [README.md](README.md) | Visión general, comparativa, configuración pública |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Diagrama, flujo de petición, **decisiones de diseño**, elevación sudo |
| [OPERATIONS.md](OPERATIONS.md) | Runbook: arranque, alta de hosts, hot-reload, broker-ctl, PKI, configs |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Actores, fronteras de confianza, **gaps explícitos** |
| [SECURITY.md](SECURITY.md) | Política de divulgación de vulnerabilidades |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Ramas, versionado X.Y.Z, checklist pre-commit, idioma |
| [CODING_STYLE.md](CODING_STYLE.md) | Reglas Go con verificación mecánica |
| [API.md](API.md) | Referencia de endpoints HTTP de todos los servicios |
| [USAGE.md](USAGE.md) | Guía de las 5 tools MCP para el modelo |

---

## Qué es (resumen)

Un modelo de IA necesita ejecutar comandos en hosts Linux por SSH sin recibir
nunca una credencial reutilizable. El **broker** genera por operación un par
Ed25519 efímero en memoria, obtiene un certificado SSH de corta duración firmado
por una CA, abre la conexión, y descarta el material; el modelo solo recibe
`stdout/stderr/exit_code`.

En **modo remoto (producción)** un servicio aparte (`cmd/signer`) custodia la
clave CA y la política; un broker comprometido no puede robar la llave. El
frontend `cmd/mcp-broker-http` expone el broker por HTTP con OAuth2/OIDC para
despliegues multiusuario. El detalle del *por qué* está en
[ARCHITECTURE.md](ARCHITECTURE.md); el modelo de amenazas y sus límites en
[THREAT_MODEL.md](THREAT_MODEL.md).

---

## Estado actual del código

```
ssh-broker/
├── cmd/
│   ├── mcp-broker/           # servidor MCP (stdio) — frontend local
│   ├── mcp-broker-http/      # servidor MCP remoto (Streamable HTTP + OAuth2/OIDC)
│   ├── signer/               # servicio de firma externo (HTTPS+mTLS) — única custodia CA
│   ├── control-plane/        # PEP entre broker y signer (aprobación + behavior); sin clave CA
│   ├── broker-ctl/           # CLI de gestión de signer.json + audit + approvals
│   └── broker/               # frontend HTTP+mTLS alternativo (one-shot)
├── internal/
│   ├── ca/                   # loader (PEM/AKV), akv, sign (BuildAndSign), GenerateEphemeralKey
│   ├── signer/               # Signer/Local, PolicyTable.Resolve, cmdpolicy, remote (Wire*)
│   ├── broker/               # Engine, Caller, ExecOptions, sessionManager, session
│   ├── mcpserver/            # New + Register (5 tools compartidas stdio/HTTP)
│   ├── oauth/                # Verifier OIDC (JWKS, fail-closed groups/iat)
│   ├── ssh/                  # Dial/ExecOnce/Run, OpenShell/OpenShellPTY
│   ├── audit/                # log append-only encadenado y firmado (Ed25519)
│   ├── control/              # approval Registry, notifier, teams, behavior tracker
│   ├── recording/            # Recorder ASCIIcast v2
│   ├── httpserve/            # RunTLS: serve + graceful shutdown (SIGINT/SIGTERM)
│   └── auth/                 # mtls (ServerTLSConfig, ClientTLSConfig, CallerCN)
├── lab/                      # labs e2e (run_*.sh) + mcpclient
├── pki/                      # PKI local (NO git) — ver OPERATIONS.md §5
├── deploy/sshd_config.snippet
├── config.json / config.example.json
├── signer.json / signer.example.json
├── control-plane.example.json
└── signer.sh
```

**Compilación y tests:** `go build ./...` ✅ · `go vet ./...` ✅ ·
`go test -race ./...` ✅ (193 casos en 11 paquetes, sin data races).

**Binarios:** `~/bin/{mcp-broker,mcp-broker-http,signer,broker-ctl}`.
**MCP registrado:** `~/.claude.json` / config de OpenCode.

---

## Pendientes para producción

### Alta prioridad
- [ ] **Clave CA en HSM/KMS** para PEM local (AKV ya soportado, v1.11.0). Seam
  listo: `ca.LoadCAFromPEM` → `ssh.NewSignerFromSigner(kmsClient)`.
- [ ] **Rate limiting por CN de broker** en el signer (gap #4 del threat model).
- [ ] **Command firewall en sesiones exec** vía dry-run por comando (gap #1).

### Media prioridad
- [ ] **KRL (revocación)**: `/v1/revoke` por serial + `RevokedKeys` en sshd (gap #3).
- [ ] **Redacción de secretos** en audit logs y grabaciones: hoy los comandos se
  guardan verbatim (un `mysql -psecret` queda en texto plano). Lista de patrones
  de enmascarado configurable (gap #8 del threat model).
- [ ] **Audit fail-closed (opcional)**: hoy si falla el `Append` la operación
  continúa; toggle para bloquear emisión/ejecución sin traza (gap #9).
- [ ] **Logs a almacenamiento WORM** (S3/GCS/Loki/SIEM).
- [ ] **Sesiones/aprobaciones multi-instancia**: externalizar estado a Redis (gap #5).
- [ ] **`default_deny` en `callers`**: hoy CN ausente = sin restricción (gap #6).
- [ ] **Validación de config en modo local del broker**: `cmd/signer` ya valida
  en `buildState` (v1.12.3); el broker local-mode (`engine.buildSigner`) aún no.
- [ ] **Labs e2e**: sudo+PTY (`run_mcp_lab.sh`) y HTTP+OAuth (IdP OIDC local).

### Baja prioridad
- [ ] **Hosts dinámicos** (`allow_dynamic_hosts`): el modelo suministra addr/user/host_key.
- [ ] **Dashboard de auditoría** correlado por serial.
- [ ] **Anclaje externo del head de auditoría** (sidecar/WORM): `broker-ctl audit
  verify --all` (v1.13.0) ya detecta el borrado de un segmento rotado y el truncado
  del fichero activo cuando existen segmentos; queda el caso residual de truncar el
  ÚNICO fichero sin rotaciones (indistinguible de una instalación nueva sin un head
  persistido fuera del log).
- [ ] **`allowed_sudo_commands` por host** como segunda capa.
- [ ] **Rutas `/home/luislgf` en config.json/signer.json** mientras la máquina es
  macOS (`/Users/luislgf`) — revisar si son de la máquina Linux o están rotas.

Historial de completados: ver [CHANGELOG.md](CHANGELOG.md).

---

## Estado del plan de pruebas (v1.12.3)

195 casos en 11 paquetes; todos pasan con `go test -race ./...`.

| Paquete | Casos | Notas |
|---|---|---|
| `internal/ca` | 23 | sign, bastion, TTL; LoadCA/LoadGroupCAs; akvSigner EC+RSA |
| `internal/signer` | 46 | policy, RBAC, sudo, PTY, dry-run, approval gate, multi-CA, newlines, config validation |
| `internal/control` | 32 | approval registry (+ purge), behavior tracker, Teams notifier |
| `internal/oauth` | 9 | valid/expired/aud/sig/claim + fail-closed (groups/iat, token age) |
| `internal/audit` | 11 | cadena hash, firmas Ed25519, restoreChain, maybeRotate |
| `internal/broker` | 26 | sessionManager, M2, C1 ownership, M5 newlines, filtro grupos |
| `internal/recording` | 8 | cabecera ASCIIcast, eventos, deltas, concurrencia, close |
| `cmd/control-plane` | 8 | forwarding, approval flow, behavior, ownership |
| `cmd/signer` | 1 | resolveCaller (4 sub-tests); handlers indirectos vía control-plane |
| `cmd/mcp-broker-http` | 2 | OAuth auth, 401, RFC 9728 |
| `cmd/broker-ctl` | 29 | verifyLog, audit helpers; ca-keys/callers round-trip; policy preservation |

### Gaps de cobertura conocidos
- `cmd/signer/main.go` handlers HTTP: solo `resolveCaller` con test directo (el
  resto se ejercita vía el stub de `cmd/control-plane`).
- `internal/ssh` con sshd real: el protocolo de marcadores de `ShellSession`
  requiere `gliderlabs/ssh` o un sshd embebido (hoy solo unitarios).
- `cmd/broker-ctl`: subcomandos completos sin tests de integración (requieren
  ficheros reales o mock de `exec.Command`); helpers internos sí cubiertos.

---

## Notas para retomar

1. **El signer debe estar corriendo** antes de arrancar el broker / abrir el MCP.
   `./signer.sh start`. Ver [OPERATIONS.md §1](OPERATIONS.md#1-starting-the-system).
2. **`hosts_refresh_seconds: 30`** es valor de desarrollo; en producción ≥ 300.
3. Tras editar `signer.json`: `broker-ctl reload` (SIGHUP local o `POST /v1/reload`).
   El broker NO necesita reinicio.
4. **Pendiente operativo de Fase B/C**: generar el cert del control plane
   (`CN=control-plane-1`) firmado por `pki/mtls_ca.crt` y añadirlo a
   `trusted_forwarders` del signer.
5. Antes de cada commit: seguir el checklist de
   [CONTRIBUTING.md](CONTRIBUTING.md) (docs vivas) y el de
   [CODING_STYLE.md](CODING_STYLE.md) (gofmt/vet/test).
