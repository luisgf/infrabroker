# Handoff: SSH Broker con CA Efímera para Agentes de IA

> Documento de traspaso para retomar la sesión de desarrollo. Última
> actualización: 2026-06-30 (post-v1.23.5 audit hardening).
>
> Estado reciente:
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

**Compilación y tests:** validado en esta actualización con `go test ./...`,
`go vet ./...`, `go test -race ./...` y `govulncheck ./...` (sin vulnerabilidades
conocidas). La suite de tests cubre los paquetes con lógica de seguridad,
política, transporte, auditoría, CLI y documentación generada.

**Binarios:** `~/bin/{mcp-broker,mcp-broker-http,signer,broker-ctl}`.
**MCP registrado:** `~/.claude.json` / config de OpenCode.

---

## Pendientes para producción

### Alta prioridad
- [ ] **Clave CA en HSM/KMS** para PEM local (AKV ya soportado, v1.11.0). Punto
  de extensión listo: `ca.LoadCAFromPEM` → `ssh.NewSignerFromSigner(kmsClient)`.
- [ ] **Rate limiting por CN de broker** en el signer (gap #4 del threat model).
- [x] **Command firewall en sesiones exec** vía dry-run por comando: `mode=exec`
  preflighted por `ssh_session_exec`; el preflight lleva `session_mode`, comando,
  sudo/sudo_user y PTY, y revalida tanto el target como cada bastion de la cadena.
  Antes de ejecutar, el broker compara además la ruta SSH física actual
  (`addr`/`user`/`host_key`/`jump`) con la usada al abrir la sesión; si cambió,
  rechaza el comando y exige una sesión nueva. `shell`/`pty` siguen rechazados en
  hosts con `command_policy`. Pendiente como gap fuerte: enforcement host-side.

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
2. **`hosts_refresh_seconds: 30`** es valor de desarrollo; en producción ≥ 300.
3. Tras editar `signer.json`: `broker-ctl reload` (SIGHUP local o `POST /v1/reload`).
   El broker NO necesita reinicio.
4. **Pendiente operativo de Fase B/C**: generar el cert del control plane
   (`CN=control-plane-1`) firmado por `pki/mtls_ca.crt` y añadirlo a
   `trusted_forwarders` del signer.
5. Antes de cada commit: seguir el checklist de
   [CONTRIBUTING.md](CONTRIBUTING.md) (docs vivas) y el de
   [CODING_STYLE.md](CODING_STYLE.md) (gofmt/vet/test).
