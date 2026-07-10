# Handoff: infrabroker — broker de acceso a infraestructura para agentes de IA

> Documento de traspaso para retomar la sesión de desarrollo. Última
> actualización: 2026-07-10 (v2.0.0, secure-by-default: tres defaults fail-open volteados).
>
> Estado reciente:
> - **v2.0.0** (primer major): **secure-by-default** — se voltean a fail-closed
>   los tres defaults fail-open que un operador podía confundir con protección,
>   cada uno con su opt-out documentado: (1) la tabla `callers` no vacía es
>   autoritativa y **default-deny** (un CN no listado no ve/firma ningún host;
>   escape: `_default` con grupos, o tabla vacía = sin RBAC) [#184]; (2) el
>   **audit append es fail-closed** vía `audit_fail_mode` (default `closed`): sin
>   registro durable no hay acción — el signer no devuelve cert (gate real,
>   cubre exec/sesiones/file-transfer) y el broker retiene el resultado; métrica
>   `audit_blocked_total`; escape: `"open"` [#184, cierra #133]; (3) un **freeze
>   volátil** (signer sin `state_db`) se **rechaza** con 409 salvo
>   `allow_volatile`/`--volatile` [#184]. Acompañan: kill switch/revocación
>   (#117), aprobaciones in-conversation (#118), approval-bridge multiplataforma
>   (#120), identidad IdP por agente (#121), custodia de CA en ssh-agent (#122),
>   configs JSONC (#183) y `doctor --security` (#134). Tres commits `!`.
> - **v1.38.0**: pasada de auditoría de seguridad/correctitud (6 hallazgos: 5
>   fixes low + `broker-ctl audit repair`). El signer sigue fail-closed ante un
>   registro final de auditoría truncado; `audit repair` es la ruta explícita de
>   recuperación del operador (dry-run por defecto, `--apply` pone en cuarentena
>   el tail corrupto y trunca al último registro válido). Fixes: validación de
>   selectores/container en tools k8s, doble conteo en policy recommend, chequeo
>   de `max_ttl_seconds` global en carga, borrado de código muerto, gitignore de
>   `control-plane.json`. `server.json` en 1.38.0, publicado en el MCP Registry
>   automáticamente por `release.yml` (job `mcp-registry`, auth GitHub OIDC, corre
>   tras subir la imagen a ghcr) — ya no es un paso manual post-release.
> - **v1.37.0**: release de distribución. goreleaser (archives por plataforma
>   con los 6 binarios; el tarball del installer se conserva vía
>   `release.extra_files`), imagen OCI multi-arch `ghcr.io/luisgf/infrabroker`
>   (distroless/static, nonroot, entrypoint `mcp-broker`, label
>   `io.modelcontextprotocol.server.name` para el MCP Registry), demo compose
>   en `examples/compose/` (`make demo`; signer + sshd de juguete + broker,
>   PKI autoprovisionada, verificada e2e con auditoría correlada) y
>   `docs/CONTAINERS.md`. k8s como runtime del broker: APLAZADO a propósito
>   (decisión 2026-07-04; solo k8s como target). Homebrew tap: descartado por
>   ahora. Post-release manual: hacer público el package en ghcr (one-time) y
>   publicar en el MCP Registry con `mcp-publisher` (server.json ya en 1.37.0).
> - **v1.36.0**: renombrado del proyecto **ssh-broker → infrabroker** (module
>   path, dist, CI, docs site, unidades systemd, usuarios de sistema y rutas
>   de instalación; el repo de GitHub redirige). Sin cambios funcionales. Se
>   conservan los nombres de binarios (nunca llevaron el nombre del proyecto)
>   y el CHANGELOG histórico; el campo del header de grabaciones pasa a
>   `infrabroker` (las grabaciones antiguas mantienen `ssh_broker`; los
>   players ignoran campos desconocidos). Migración manual de despliegues
>   previos: deploy/README.md §"Upgrading from ssh-broker". Incluye manifest
>   `server.json` (MCP registry). El plan de campaña de visibilidad se
>   mantiene fuera del repo (planificación local).
> - **v1.35.0**: separación de privilegios en el deploy de referencia: un
>   usuario de sistema por servicio (`infrabroker-signer` /
>   `infrabroker-control-plane` / `infrabroker-mcp-http`; el grupo compartido
>   `infrabroker` queda solo para atravesar `/etc/infrabroker` y leer la CA mTLS
>   pública). PKI por subdirectorio de servicio (`pki/<svc>/`, clave legible
>   solo por su servicio), material del CLI admin en `pki/admin/` (solo root),
>   configs de /etc con grupo por servicio. `install.sh` migra installs
>   ≤ v1.34 (re-own idempotente + aviso de claves planas en `pki/`). Un broker
>   comprometido ya no puede leer la clave CA `pem`, la policy, `state.db`, la
>   semilla de audit ni suplantar a otro servicio. Además: protección de rama
>   en main (build/govulncheck/check requeridos), gate anti-drift cierra el
>   hueco de ficheros no trackeados, y `make verify` como gate local completo.
> - **v1.34.0**: target Kubernetes (credential-broker). El signer acuña bound
>   ServiceAccount tokens (TokenRequest) para acciones autorizadas; el agente
>   nunca ve credencial de cluster. ActionPolicy estructurada por cluster
>   (default-deny) compilada sobre la string canónica `<verb> <resource[.group]>
>   <ns>/<name>` → reutiliza `PolicySet` (grants/waivers/recommend gratis).
>   6 tools MCP (`k8s_list_clusters/get/list/logs/apply/delete`, registro
>   condicional), cliente REST sin client-go (`internal/k8s`), `kubernetes.clusters`
>   en signer.json (nombres disjuntos de hosts), `GET /v1/clusters`,
>   `broker-ctl cluster list --remote`. `audit.Entry` += `target_type`/`body_sha256`
>   (el manifest de apply nunca verbatim). Gap #10 del threat model: el token da
>   todo el RBAC de la SA durante su TTL, no una sola llamada. Lab `run_k8s_lab.sh`.
> - **v1.33.0**: `state_db` opt-in (SQLite puro-Go, `internal/statedb`):
>   grants/waivers del signer y approvals del control plane sobreviven
>   restarts (write-through; el mapa in-memory sigue siendo el único estado
>   del decision path). Revocación de grants con delete durable obligatorio
>   (no resucitan); `issuing` no se persiste (consumible exactamente una vez
>   tras restart); baselines de behavior y sesiones vivas siguen in-memory por
>   diseño. Lab `lab/run_state_lab.sh`.
> - **v1.32.0**: redacción de secretos opt-in (gap #8): bloque `redact` en los
>   tres servicios; `internal/redact` (reglas RE2 con nombre, defaults +
>   patrones de operador) aplicado en choke-points — `audit.Log` (campos de
>   texto libre, antes de firmar: la cadena cubre el contenido ya redactado),
>   `recording.Recorder` (eventos ASCIIcast) y el notifier de aprobaciones
>   (log/webhook/Teams). El decision path y la approval UI mTLS ven siempre el
>   comando original.
> - **post-v1.23.5**: los waivers approve-and-learn quedan acotados al broker y
>   `end_user` aprobados; el lector de sesiones `shell`/`pty` limita líneas sin
>   newline antes de bufferizarlas; `broker-ctl reload` solo envía SIGHUP si el
>   basename del proceso es exactamente `signer`.
> - **v1.23.5**: endurecimiento de sesiones persistentes: el marcador de
>   `mode=shell`/`mode=pty` ya no depende de un `printf()` redefinible por la
>   sesión, y `ssh_session_exec` rechaza sesiones abiertas si cambió la ruta
>   física del host (`addr`/`user`/`host_key`/`jump`). El handoff deja de fijar
>   conteos de tests para evitar drift documental.
> - **v1.23.4**: `ssh_session_exec` preflight propaga el bit `PTY`, de modo
>   que una recarga de política que deshabilita `allow_pty` corta también sesiones
>   `mode=pty` ya abiertas en el siguiente comando. Documentación de aprobación
>   actualizada: `approval.timeout_seconds` cubre tanto solicitudes pendientes
>   desde creación como aprobadas-no-recogidas desde decisión.
> - **v1.23.3**: cada `ssh_session_exec` se revalida contra la política vigente
>   del signer (`dry_run=true`, `preflight=true`); sesiones `exec` aplican la
>   política nueva en el siguiente comando y `shell`/`pty` se bloquean si aparece
>   `command_policy`. Las aprobaciones concedidas expiran si el broker no las
>   recoge dentro del TTL.
> - **v1.23.2**: las aprobaciones ya no se queman ante fallos transitorios del
>   signer; se consumen solo al recibir certificado o decisión usable. El frontend
>   HTTP del broker devuelve warnings de `command_policy.enforcement=audit`.
> - **v1.23.1**: los preflights ejecutables pasan por guardrails de comportamiento;
>   dry-runs puros siguen sin consumir rate-limit. El modo audit quedó documentado
>   como mecanismo de baseline.
> - **v1.23.0**: `command_policy.enforcement` añade `audit` y el firewall de
>   comandos se extiende a sesiones `mode=exec` mediante preflight por comando.
> - **v1.19.0**: relicencia a GPL-3.0 y documentación en GitHub Pages con pipeline
>   anti-drift: `docs/` como fuente única, `tools/docgen` para referencia generada,
>   `internal/confcheck` sobre `*.example.json`, `mkdocs --strict` y espejo
>   opcional a GitHub Wiki.
> - **v1.18.0**: política dinámica: grants `allow` con TTL y approve-and-learn
>   mediante waivers de aprobación, siempre operator/control-plane scoped.
> - **v1.17.0-v1.13.0**: recomendador de políticas, auto-reload, mutación validada
>   de allow rules, políticas componibles por grupo, endurecimientos de RBAC,
>   `allowed_callers`, aprobación con sudo visible y defensa contra uso de
>   `command_policy` como bastion.
>
> Estado y pendientes; el resto de la documentación está enlazada abajo.

## Índice de documentación

| Documento | Contenido |
|---|---|
| [README.md](../README.md) | Visión general, comparativa, configuración pública |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Diagrama, flujo de petición, **decisiones de diseño**, elevación sudo |
| [OPERATIONS.md](OPERATIONS.md) | Runbook: arranque, alta de hosts, hot-reload, broker-ctl, PKI, configs |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Actores, fronteras de confianza, **gaps explícitos** |
| [SECURITY.md](SECURITY.md) | Política de divulgación de vulnerabilidades |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Ramas, versionado X.Y.Z, checklist pre-commit, idioma |
| [CODING_STYLE.md](CODING_STYLE.md) | Reglas Go con verificación mecánica |
| [API.md](API.md) | Referencia de endpoints HTTP de todos los servicios |
| [USAGE.md](USAGE.md) | Guía de las tools MCP para el modelo (7 SSH + 6 Kubernetes) |

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
infrabroker/
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
│   ├── mcpserver/            # New + Register (7 SSH + RegisterK8s 6, compartidas stdio/HTTP)
│   ├── oauth/                # Verifier OIDC (JWKS, fail-closed groups/iat)
│   ├── ssh/                  # Dial/ExecOnce/Run, OpenShell/OpenShellPTY
│   ├── audit/                # log append-only encadenado y firmado (Ed25519)
│   ├── control/              # approval Registry, notifier, teams, behavior tracker
│   ├── recording/            # Recorder ASCIIcast v2
│   ├── httpserve/            # RunTLS: serve + graceful shutdown (SIGINT/SIGTERM)
│   ├── auth/                 # mtls (ServerTLSConfig, ClientTLSConfig, CallerCN)
│   ├── confcheck/            # validación estricta de los *.example.json (DisallowUnknownFields)
│   ├── policyrec/            # motor de broker-ctl policy recommend (minería del audit log)
│   └── version/              # versión embebida en build (git describe via Makefile)
├── lab/                      # labs e2e (run_*.sh) + mcpclient
├── pki/                      # PKI local (NO git) — ver OPERATIONS.md §5
├── deploy/sshd_config.snippet
├── config.json / config.example.json
├── signer.json / signer.example.json
├── control-plane.example.json
└── signer.sh
```

**Compilación y tests:** validado en esta actualización con `go test ./...`,
`go vet ./...`, `go test -race ./...` y `govulncheck ./...` (sin vulnerabilidades
conocidas). La suite de tests cubre los paquetes con lógica de seguridad,
política, transporte, auditoría, CLI y documentación generada.

**Binarios:** `~/bin/{mcp-broker,mcp-broker-http,signer,broker-ctl,broker,control-plane}`.
**MCP registrado:** `~/.claude.json` / config de OpenCode.

---

## Pendientes para producción

### Alta prioridad
- [ ] **Clave CA en HSM/KMS** para PEM local (AKV ya soportado, v1.11.0). Punto
  de extensión listo: `ca.LoadCAFromPEM` → `ssh.NewSignerFromSigner(kmsClient)`.
- [x] **Rate limiting por CN de broker** en el signer (v1.25.0, gap #4): token
  bucket por CN mTLS en `POST /v1/sign` (`sign_rate_limit_per_min`, hot-reload),
  429 + Retry-After, comprobado antes de parsear el body y sin auditar cada
  rechazo (el log no debe ser el amplificador del flooding).
- [x] **Command firewall en sesiones exec** vía dry-run por comando: `mode=exec`
  preflighted por `ssh_session_exec`; el preflight lleva `session_mode`, comando,
  sudo/sudo_user y PTY, y revalida tanto el target como cada bastion de la cadena.
  Antes de ejecutar, el broker compara además la ruta SSH física actual
  (`addr`/`user`/`host_key`/`jump`) con la usada al abrir la sesión; si cambió,
  rechaza el comando y exige una sesión nueva. `shell`/`pty` siguen rechazados en
  hosts con `command_policy`. Pendiente como gap fuerte: enforcement host-side.

### Media prioridad
- [ ] **KRL (revocación)**: `/v1/revoke` por serial + `RevokedKeys` en sshd (gap #3).
- [x] **Redacción de secretos** (v1.32.0): bloque `redact` opt-in en los tres
  servicios; enmascara en audit (antes de firmar la entrada), grabaciones y
  notificaciones. Residual: best-effort por regex, no DLP (gap #8).
- [ ] **Audit fail-closed (opcional)**: hoy si falla el `Append` la operación
  continúa; toggle para bloquear emisión/ejecución sin traza (gap #9). Desde
  v1.26.0 el fallo es observable: contador `audit_append_failures_total` en
  `/metrics` (`monitor_listen`) — alertar sobre cualquier incremento.
- [ ] **Logs a almacenamiento WORM** (S3/GCS/Loki/SIEM).
- [ ] **Sesiones/aprobaciones multi-instancia**: externalizar estado a Redis (gap #5).
- [x] **`default_deny` en `callers`** (v2.0.0): una tabla `callers` no vacía es
  autoritativa y default-deny — un CN no listado no ve ningún host. `_default` con
  grupos concede una base a los CN no listados; omitir `callers` deja todo abierto.
- [x] **Validación de config en modo local del broker** (v1.14.0): `engine.buildSigner`
  ahora compila y valida vía `signer.CompileHostPolicies` (regex de `command_policy`,
  modos, refs de grupo, jumps, exclusión bastión), igual que `cmd/signer` en `buildState`.
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

## Backlog de rendimiento y mantenibilidad

Hallazgos de la auditoría de rendimiento/mantenibilidad (v1.16.0) **diferidos**
para evaluación posterior. Los ítems de alta/media prioridad de esa auditoría
(BehaviorTracker acotado, evaluador único de command_policy, cache de host keys,
`shellQuote` O(n²), pool del parser, ciclo de vida de la goroutine de refresh) ya
están implementados en v1.16.0; lo que queda es esto:

- [ ] **P3 — `audit.Append` hace `fsync` bajo el mutex** (`internal/audit/log.go:174-205`),
  en la ruta síncrona de cada petición: serializa todas las peticiones auditadas
  tras un sync de disco (techo de throughput del sistema). **Enfoque preferido:
  solo micro-optimizar** (no cambiar el modelo de durabilidad): quitar el `Stat()`
  por-append rastreando el tamaño en memoria (`log.go:144,178`) y hacer un único
  `json.Marshal` por entrada (hoy son dos, `log.go:189,196`). Mantener el `fsync`
  síncrono. No introducir modo async salvo decisión explícita.
- [ ] **M1b — `buildHops`/`buildHopsWithPrefix` duplicados** (~50 líneas casi
  idénticas, `internal/broker/engine.go`): `buildHops` puede ser un wrapper fino
  sobre `buildHopsWithPrefix` (descartando el prefijo). Riesgo de drift en la
  construcción de la cadena de certs.
- [ ] **M3 — Contexto en firmantes HSM/KMS**: `SessionExec` ya propaga el ctx del
  llamante al preflight y a la ejecución SSH (`internal/broker/session.go`), de
  modo que una desconexión puede cancelar comandos en vuelo. Queda el límite de
  `ca.BuildAndSign`: comprueba `ctx` antes de firmar, pero `ssh.Certificate`
  delega en `crypto.Signer`, cuya `Sign` no acepta contexto. El signer AKV aplica
  su propio timeout fijo de 10s (`internal/ca/akv.go:101`); para cancelación
  estricta habría que introducir una interfaz de firma con contexto o mantener el
  contrato documentado como timeout interno.
- [ ] **M4 — Capa de validación de config + god-structs**: `LoadConfig` no valida
  combinaciones mutuamente excluyentes (`CAKey`/`CAKeys` vs `Signer`; `CommandPolicy`
  inline vs `Policies` compilado), que fallan tarde dentro de `buildSigner`. Añadir
  `Validate()` temprano. `broker.Config` (~25 campos) y `signer.HostPolicy` (~20,
  con `MaxTTL`/`MaxTTLSeconds` redundantes) mezclan conexión/emisión/cache: valorar
  dividir por responsabilidad.
- [ ] **M5 — Limpiezas menores**: `elevationLabelFromPrefix` es código muerto
  (solo lo usa un test en `internal/broker/session.go`); extraer
  `internal/shellutil` para el quoting hoy duplicado entre `broker` y `signer`;
  helper para construir `audit.Entry` (boilerplate repetido); constantes operativas
  hardcoded (límites de sesión, geometría de grabación) → config; `newSessionID`
  descarta el error de `rand.Read` apoyándose en la semántica de Go 1.24+
  (`internal/broker/session.go`).
- [ ] **Normalización ES→EN amplia**: nombres de tests y comentarios en español
  por todo el repo (el código de producción de `cmdpolicy.go` ya está en inglés;
  el inglés debe prevalecer en lo nuevo).
- [ ] **Estado multi-instancia (HA)**: el registro de aprobaciones y el
  BehaviorTracker viven en memoria (una sola instancia de control-plane). Sembrar
  una interfaz (memoria ahora, Redis después) para despliegues HA.

---

## Estado del plan de pruebas (2026-06-30, post-v1.23.5)

Validaciones ejecutadas en esta actualización:

```bash
gofmt -l .
go vet ./...
go build ./...
go test -race ./...
make docs-check
```

Resultado: todo pasa.
Cobertura relevante: CA/AKV/multi-CA, signer policy/RBAC/sudo/PTY/dry-run,
command-policy composition/audit/approval/grants, control-plane approvals y
behavior guardrails, broker sessions/ownership/preflight, OAuth fail-closed,
audit chain/rotation, session recording, CLI helpers y config example strictness.

### Gaps de cobertura conocidos
- `cmd/signer/main.go` handlers HTTP: cobertura directa parcial (`resolveCaller`,
  filtro `allowed_callers` de `/v1/hosts`, propagación de `preflight` en
  `/v1/sign`); el resto se ejercita sobre todo vía el stub de `cmd/control-plane`.
- `internal/ssh` con sshd real: el protocolo de marcadores de `ShellSession`
  requiere `gliderlabs/ssh` o un sshd embebido (hoy solo unitarios).
- `cmd/broker-ctl`: subcomandos completos sin tests de integración (requieren
  ficheros reales o mock de `exec.Command`); helpers internos sí cubiertos.

---

## Notas para retomar

1. **El signer debe estar corriendo** antes de arrancar el broker / abrir el MCP.
   `./signer.sh start`. Ver [OPERATIONS.md §1](OPERATIONS.md#1-starting-the-system).
2. **`hosts_refresh_seconds`** es opcional; por defecto 300s (5 min) si se omite
   o es `0` — ya apropiado para producción (no aparece en los ejemplos). Bájalo
   (p. ej. `30`) solo en desarrollo.
3. Tras editar `signer.json`: `broker-ctl reload` (SIGHUP local o `POST /v1/reload`).
   El broker NO necesita reinicio.
4. **Pendiente operativo de Fase B/C**: generar el cert del control plane
   (`CN=control-plane-1`) firmado por `pki/mtls_ca.crt` y añadirlo a
   `trusted_forwarders` del signer.
5. Antes de cada commit: seguir el checklist de
   [CONTRIBUTING.md](CONTRIBUTING.md) (docs vivas) y el de
   [CODING_STYLE.md](CODING_STYLE.md) (gofmt/vet/test).
6. **Auditoría de seguridad recurrente**: skill `/audit`
   (`.agents/skills/audit/`) — bucle find→fix→close por categoría, con
   `audit-issue.sh` para el formato uniforme de las issues (audit-id, dedupe,
   ledger, report derivados de GitHub).
