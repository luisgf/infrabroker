// Package signer abstrae la emisión de certificados. El broker pide una intención
// y recibe un certificado firmado, sin construir él los constraints de seguridad
// ni custodiar la clave de CA.
//
//   - Local:  firma en proceso (modo single-binary, o el núcleo del servicio).
//   - Remote: delega en el servicio de firma externo por HTTP+mTLS.
//
// La política (host → principal/source-address/TTL/forwarding + autorización por
// llamante) vive aquí y la aplican tanto Local como el servicio.
package signer

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/luisgf/ssh-broker/internal/ca"
)

// Role distingue el papel del hop en la cadena.
const (
	RoleTarget  = "target"
	RoleBastion = "bastion"
)

// Purpose distingue el uso de la conexión.
const (
	PurposeOneshot = "oneshot"
	PurposeSession = "session"
)

// reValidUser acepta solo nombres de usuario Unix seguros (sin flags ni metacaracteres).
var reValidUser = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,31}$`)

// Intent es lo que el broker pide firmar. No contiene constraints de seguridad:
// los deriva la política del firmante.
type Intent struct {
	Caller       string // identidad del solicitante (CN mTLS en remoto; "local" en local)
	Host         string // nombre lógico del host
	Role         string // RoleTarget | RoleBastion
	Purpose      string // PurposeOneshot | PurposeSession
	Command      string // solo relevante para one-shot en el destino (force-command)
	RequestedTTL time.Duration
	PublicKey    ssh.PublicKey // pubkey efímera del broker

	// Elevación (NOPASSWD).
	Sudo     bool   // solicita elevación de privilegio
	SudoUser string // usuario destino para sudo; "" = root

	// PTY: solicita permit-pty en el certificado.
	PTY bool

	// DryRun: si es true, el firmante resuelve la política y devuelve la decisión
	// (DecisionInfo) SIN emitir un certificado usable. Permite al modelo previsualizar
	// si un comando sería permitido / requeriría aprobación antes de ejecutarlo.
	DryRun bool

	// Approved indica que una operación que requiere aprobación humana ya fue
	// aprobada. El signer solo lo honra si proviene de un forwarder de confianza
	// (el control plane); un broker no puede auto-aprobarse. Hace que la aprobación
	// sea inevadible: sin approved, un comando con require_approval no se emite.
	Approved bool

	// OnBehalfOf es el CN del broker en cuyo nombre actúa un forwarder de confianza
	// (el control plane). El signer lo usa como Caller efectivo para RBAC SOLO si el
	// CN mTLS real está en trusted_forwarders; en otro caso la petición se rechaza.
	// Vacío en peticiones directas broker→signer (se usa el CN mTLS).
	OnBehalfOf string

	// EndUser es la identidad del usuario final que originó la petición (p. ej. el
	// sub/preferred_username de un token OIDC en el frontend HTTP). Vacío cuando la
	// petición no porta identidad de usuario (stdio local o frontend mTLS). Se usa
	// para trazabilidad (KeyID/auditoría); no sustituye a Caller (la identidad del
	// broker frente al signer).
	EndUser string
	// EndUserGroups son los grupos RBAC aseverados para el usuario final. Si no es
	// nil, activa la autorización por usuario: el host solicitado debe pertenecer a
	// alguno de estos grupos. Si es nil, no se aplica filtro por usuario (compat).
	EndUserGroups []string
}

// Issued es el resultado de firmar.
type Issued struct {
	Certificate *ssh.Certificate
	Serial      uint64
	// ElevationPrefix es el prefijo exacto a anteponer a cada comando en sesiones
	// persistentes (p. ej. "sudo -n" o "sudo -n -u deploy"). Vacío si no hay
	// elevación o si el propósito es one-shot (el prefijo ya va en ForceCommand).
	ElevationPrefix string
	// Decision resume la decisión de política. En dry-run, Certificate es nil y solo
	// se rellena Decision. En emisión normal se rellena para trazabilidad/auditoría.
	Decision *DecisionInfo
}

// DecisionInfo resume la decisión de política para dry-run y auditoría, sin
// exponer la clave ni el certificado. Sirve también como tipo de transporte
// (campo decision de WireResponse).
type DecisionInfo struct {
	// Allowed indica si el comando sería autorizado (false en dry-run de denegación).
	Allowed bool `json:"allowed"`
	// Reason explica una denegación (vacío si Allowed).
	Reason string `json:"reason,omitempty"`
	// RequireApproval indica que el comando requiere aprobación humana out-of-band.
	RequireApproval bool `json:"require_approval,omitempty"`
	// MatchedRule es la regla de command_policy que motivó la decisión.
	MatchedRule string `json:"matched_rule,omitempty"`
	// ForceCommand es el force-command que se hornearía en el cert (incluye sudo).
	ForceCommand string `json:"force_command,omitempty"`
	// TTLSeconds es el TTL que tendría el cert emitido.
	TTLSeconds int `json:"ttl_seconds,omitempty"`
	// Elevation es el prefijo de elevación que se aplicaría (sesiones).
	Elevation string `json:"elevation,omitempty"`
}

// Decision es el resultado de PolicyTable.Resolve: los constraints del cert más
// metadatos de la decisión de política.
type Decision struct {
	Constraints     ca.Constraints
	ElevationPrefix string
	// RequireApproval lo surface el signer pero lo ACTÚA el control plane (el signer
	// no tiene maquinaria de aprobación; permanece sin estado).
	RequireApproval bool
	// MatchedRule es la regla de command_policy que casó (auditoría/dry-run).
	MatchedRule string
}

// Signer emite un certificado a partir de una intención.
type Signer interface {
	SignIntent(Intent) (*Issued, error)
}

// HostPolicy es la política de emisión para un host, y también la fuente de
// verdad para los datos de conectividad. El signer es el único lugar donde se
// declara un host: el broker obtiene addr/user/host_key/jump vía /v1/hosts.
type HostPolicy struct {
	// Conectividad — expuesta al broker por /v1/hosts.
	Addr    string `json:"addr"`           // host:puerto
	User    string `json:"user"`           // cuenta remota SSH
	HostKey string `json:"host_key"`       // línea authorized_keys de la host key
	Jump    string `json:"jump,omitempty"` // nombre lógico del bastión previo

	// Política de emisión — interna, nunca se expone al broker.
	Principal      string        `json:"principal"`
	SourceAddress  string        `json:"source_address,omitempty"`
	MaxTTL         time.Duration `json:"-"`
	MaxTTLSeconds  int           `json:"max_ttl_seconds,omitempty"`
	AllowAsBastion bool          `json:"allow_as_bastion,omitempty"`
	// AllowedCallers restringe qué CN pueden pedir este host. Vacío = cualquiera
	// autenticado.
	AllowedCallers []string `json:"allowed_callers,omitempty"`

	// Elevación (sudo NOPASSWD).
	// AllowSudo habilita la elevación de privilegio para este host.
	AllowSudo bool `json:"allow_sudo,omitempty"`
	// AllowedSudoUsers lista los usuarios destino permitidos (p. ej. ["root","deploy"]).
	// Vacío = solo root. El valor "root" siempre está implícito si AllowSudo=true.
	AllowedSudoUsers []string `json:"allowed_sudo_users,omitempty"`

	// AllowPTY autoriza la extensión permit-pty en los certificados de este host.
	// Si es false las peticiones PTY son rechazadas.
	AllowPTY bool `json:"allow_pty,omitempty"`

	// Groups enumera los grupos RBAC a los que pertenece este host.
	// Un caller restringido por grupos solo puede acceder a hosts que compartan
	// al menos uno de sus allowed_groups. Vacío = el host no pertenece a ningún grupo.
	Groups []string `json:"groups,omitempty"`

	// CommandPolicy restringe qué comandos pueden ejecutarse en este host
	// (AI-action firewall). Vacía/off = sin restricción de comando. Si tiene
	// reglas, las sesiones quedan deshabilitadas (el comando no es verificable).
	CommandPolicy CommandPolicy `json:"command_policy,omitempty"`
}

// PolicyTable mapea nombre de host → política.
type PolicyTable map[string]HostPolicy

// Resolve deriva los constraints del certificado a partir de la intención,
// aplicando autorización y topes. Devuelve un Decision con los constraints, el
// ElevationPrefix para sesiones persistentes (vacío en one-shot, donde el prefijo
// va en ForceCommand) y los metadatos de la decisión (command policy).
func (p PolicyTable) Resolve(in Intent, defaultMaxTTL time.Duration) (Decision, error) {
	hp, ok := p[in.Host]
	if !ok {
		return Decision{}, fmt.Errorf("host sin política: %q", in.Host)
	}
	if !callerAllowed(hp.AllowedCallers, in.Caller) {
		return Decision{}, fmt.Errorf("llamante %q no autorizado para %q", in.Caller, in.Host)
	}
	// RBAC por usuario final: si la petición porta grupos del usuario (frontend
	// OIDC), el host debe pertenecer a alguno de ellos. Si EndUserGroups es nil no
	// se aplica filtro (peticiones sin identidad de usuario: stdio/mTLS).
	if in.EndUserGroups != nil && !groupsIntersect(hp.Groups, in.EndUserGroups) {
		return Decision{}, fmt.Errorf("usuario %q no autorizado para %q (grupos)", in.EndUser, in.Host)
	}
	if in.Role == RoleBastion && !hp.AllowAsBastion {
		return Decision{}, fmt.Errorf("host %q no permitido como bastión", in.Host)
	}

	// Validar y construir prefijo de elevación.
	elevationPrefix, err := resolveElevation(hp, in)
	if err != nil {
		return Decision{}, err
	}

	// Validar PTY.
	if in.PTY && !hp.AllowPTY {
		return Decision{}, fmt.Errorf("host %q no permite PTY (allow_pty=false)", in.Host)
	}

	// Command policy (AI-action firewall): autoritativa para one-shot en el destino.
	// Las sesiones no son verificables (el comando no llega al firmante al firmar),
	// así que se rechazan en hosts con cualquier regla de comando.
	var requireApproval bool
	var matchedRule string
	if in.Role == RoleTarget && hp.CommandPolicy.Restricts() {
		if in.Purpose == PurposeSession {
			return Decision{}, fmt.Errorf("host %q tiene command_policy: las sesiones no están permitidas (el comando no es verificable al firmar)", in.Host)
		}
		allowed, needsApproval, rule, cerr := hp.CommandPolicy.Decide(in.Command)
		if cerr != nil {
			return Decision{}, fmt.Errorf("command_policy de %q: %w", in.Host, cerr)
		}
		if !allowed {
			return Decision{}, fmt.Errorf("comando no permitido en %q por command_policy (%s)", in.Host, rule)
		}
		requireApproval = needsApproval
		matchedRule = rule
	}

	maxTTL := hp.MaxTTL
	if maxTTL <= 0 {
		maxTTL = defaultMaxTTL
	}
	ttl := in.RequestedTTL
	if ttl <= 0 || ttl > maxTTL {
		ttl = maxTTL
	}

	// Construir etiquetas para KeyID (trazabilidad en sshd).
	keyIDParts := []string{
		fmt.Sprintf("agent=%s", in.Caller),
		fmt.Sprintf("host=%s", in.Host),
		fmt.Sprintf("role=%s", in.Role),
		fmt.Sprintf("t=%d", time.Now().Unix()),
	}
	if in.EndUser != "" {
		keyIDParts = append(keyIDParts, fmt.Sprintf("user=%s", in.EndUser))
	}
	if elevationPrefix != "" {
		keyIDParts = append(keyIDParts, fmt.Sprintf("elev=%s", elevationPrefix))
	}
	if in.PTY {
		keyIDParts = append(keyIDParts, "pty=1")
	}

	c := ca.Constraints{
		Principal:           hp.Principal,
		TTL:                 ttl,
		SourceAddress:       hp.SourceAddress,
		AllowPortForwarding: in.Role == RoleBastion,
		AllowPTY:            in.PTY,
		KeyID:               strings.Join(keyIDParts, " "),
	}

	// force-command solo para one-shot en el destino.
	if in.Purpose == PurposeOneshot && in.Role == RoleTarget {
		cmd := in.Command
		if elevationPrefix != "" {
			cmd = buildElevatedCommand(elevationPrefix, in.Command)
		}
		c.ForceCommand = cmd
		// En one-shot el prefijo va en ForceCommand; no se devuelve como prefix.
		elevationPrefix = ""
	}

	return Decision{
		Constraints:     c,
		ElevationPrefix: elevationPrefix,
		RequireApproval: requireApproval,
		MatchedRule:     matchedRule,
	}, nil
}

// resolveElevation valida la solicitud de elevación contra la política del host
// y devuelve el prefijo sudo a usar (p. ej. "sudo -n" o "sudo -n -u deploy").
// Devuelve "" si no hay elevación.
func resolveElevation(hp HostPolicy, in Intent) (string, error) {
	if !in.Sudo {
		return "", nil
	}
	// La elevación solo aplica al hop target; bastiones no la necesitan.
	if in.Role != RoleTarget {
		return "", nil
	}
	if !hp.AllowSudo {
		return "", fmt.Errorf("host %q no permite elevación (allow_sudo=false)", in.Host)
	}

	sudoUser := in.SudoUser
	if sudoUser == "" {
		sudoUser = "root"
	}

	// Validar formato del usuario destino contra expresión regular segura.
	if !reValidUser.MatchString(sudoUser) {
		return "", fmt.Errorf("sudo_user %q contiene caracteres no permitidos", sudoUser)
	}

	// Validar contra whitelist de la política.
	if !sudoUserAllowed(hp.AllowedSudoUsers, sudoUser) {
		return "", fmt.Errorf("sudo_user %q no está en la lista de usuarios permitidos para %q", sudoUser, in.Host)
	}

	if sudoUser == "root" {
		return "sudo -n", nil
	}
	return fmt.Sprintf("sudo -n -u %s", sudoUser), nil
}

// buildElevatedCommand envuelve command con prefix de forma segura:
// prefix + " -- /bin/sh -c " + shellQuote(command).
// El doble guion separa las opciones de sudo del argumento, y /bin/sh -c permite
// pipelines, redirecciones y variables (igual que sin elevación).
func buildElevatedCommand(prefix, command string) string {
	return fmt.Sprintf("%s -- /bin/sh -c %s", prefix, shellQuote(command))
}

// shellQuote envuelve s en comillas simples escapando las comillas simples internas
// (reemplaza ' por '\”).
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// sudoUserAllowed comprueba si user está en la lista. Vacía → solo root.
func sudoUserAllowed(allowed []string, user string) bool {
	if len(allowed) == 0 {
		return user == "root"
	}
	for _, a := range allowed {
		if a == user {
			return true
		}
	}
	return false
}

// groupsIntersect indica si hostGroups y userGroups comparten al menos un grupo.
// Un host sin grupos no es accesible por RBAC de usuario.
func groupsIntersect(hostGroups, userGroups []string) bool {
	for _, hg := range hostGroups {
		for _, ug := range userGroups {
			if hg == ug {
				return true
			}
		}
	}
	return false
}

func callerAllowed(allowed []string, caller string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, a := range allowed {
		if a == caller {
			return true
		}
	}
	return false
}

// CallerPolicy define los grupos a los que tiene acceso un caller identificado
// por el CN de su certificado mTLS.
// Ausente en CallerTable = sin restricción de grupo (backward compatible).
// Presente con AllowedGroups vacío = denegación total por grupos.
type CallerPolicy struct {
	AllowedGroups []string `json:"allowed_groups"`
}

// CallerTable mapea CN del cert mTLS → CallerPolicy.
type CallerTable map[string]CallerPolicy

// HostSetForCaller calcula el conjunto de hosts accesibles a un caller según
// la pertenencia a grupos. Un host es accesible si alguno de sus Groups
// intersecta con los AllowedGroups del caller.
// Devuelve (set, true) si el caller tiene restricción de grupo,
// (nil, false) si el caller no está en CallerTable (sin restricción).
func HostSetForCaller(callerCN string, policy PolicyTable, callers CallerTable) (map[string]struct{}, bool) {
	cp, ok := callers[callerCN]
	if !ok {
		return nil, false
	}
	allowed := make(map[string]struct{}, len(cp.AllowedGroups))
	for _, g := range cp.AllowedGroups {
		allowed[g] = struct{}{}
	}
	set := make(map[string]struct{})
	for hostName, hp := range policy {
		for _, g := range hp.Groups {
			if _, ok := allowed[g]; ok {
				set[hostName] = struct{}{}
				break
			}
		}
	}
	return set, true
}

// Local firma en proceso: resuelve política y construye+firma con la clave de CA.
type Local struct {
	caKey      ssh.Signer
	policy     PolicyTable
	defaultTTL time.Duration
}

// NewLocal crea un firmante local.
func NewLocal(caKey ssh.Signer, policy PolicyTable, defaultTTL time.Duration) *Local {
	return &Local{caKey: caKey, policy: policy, defaultTTL: defaultTTL}
}

// SignIntent implementa Signer.
//
// En dry-run no se emite certificado: se resuelve la política y se devuelve la
// decisión. Una denegación de política en dry-run es un resultado (Allowed=false),
// no un error; solo los fallos de configuración (regex inválida) devuelven error.
func (l *Local) SignIntent(in Intent) (*Issued, error) {
	d, err := l.policy.Resolve(in, l.defaultTTL)
	if in.DryRun {
		if err != nil {
			return &Issued{Decision: &DecisionInfo{Allowed: false, Reason: err.Error()}}, nil
		}
		return &Issued{Decision: decisionInfo(d, true)}, nil
	}
	if err != nil {
		return nil, err
	}
	// Gate de aprobación: si la política exige aprobación humana y no se ha
	// concedido, no se emite certificado. Se devuelve la decisión (cert nil) para
	// que el control plane orqueste la aprobación. La aprobación es inevadible: un
	// broker directo no puede poner Approved (solo forwarders de confianza).
	if d.RequireApproval && !in.Approved {
		return &Issued{Decision: decisionInfo(d, true)}, nil
	}
	cert, serial, err := ca.BuildAndSign(l.caKey, in.PublicKey, d.Constraints)
	if err != nil {
		return nil, err
	}
	return &Issued{Certificate: cert, Serial: serial, ElevationPrefix: d.ElevationPrefix, Decision: decisionInfo(d, true)}, nil
}

// decisionInfo proyecta un Decision a DecisionInfo (transporte/auditoría).
func decisionInfo(d Decision, allowed bool) *DecisionInfo {
	return &DecisionInfo{
		Allowed:         allowed,
		RequireApproval: d.RequireApproval,
		MatchedRule:     d.MatchedRule,
		ForceCommand:    d.Constraints.ForceCommand,
		TTLSeconds:      int(d.Constraints.TTL / time.Second),
		Elevation:       d.ElevationPrefix,
	}
}
