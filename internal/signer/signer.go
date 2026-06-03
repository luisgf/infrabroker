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
}

// Issued es el resultado de firmar.
type Issued struct {
	Certificate *ssh.Certificate
	Serial      uint64
	// ElevationPrefix es el prefijo exacto a anteponer a cada comando en sesiones
	// persistentes (p. ej. "sudo -n" o "sudo -n -u deploy"). Vacío si no hay
	// elevación o si el propósito es one-shot (el prefijo ya va en ForceCommand).
	ElevationPrefix string
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
}

// PolicyTable mapea nombre de host → política.
type PolicyTable map[string]HostPolicy

// Resolve deriva los constraints del certificado a partir de la intención,
// aplicando autorización y topes. Devuelve también el ElevationPrefix para
// sesiones persistentes (vacío en one-shot, donde el prefijo va en ForceCommand).
func (p PolicyTable) Resolve(in Intent, defaultMaxTTL time.Duration) (ca.Constraints, string, error) {
	hp, ok := p[in.Host]
	if !ok {
		return ca.Constraints{}, "", fmt.Errorf("host sin política: %q", in.Host)
	}
	if !callerAllowed(hp.AllowedCallers, in.Caller) {
		return ca.Constraints{}, "", fmt.Errorf("llamante %q no autorizado para %q", in.Caller, in.Host)
	}
	if in.Role == RoleBastion && !hp.AllowAsBastion {
		return ca.Constraints{}, "", fmt.Errorf("host %q no permitido como bastión", in.Host)
	}

	// Validar y construir prefijo de elevación.
	elevationPrefix, err := resolveElevation(hp, in)
	if err != nil {
		return ca.Constraints{}, "", err
	}

	// Validar PTY.
	if in.PTY && !hp.AllowPTY {
		return ca.Constraints{}, "", fmt.Errorf("host %q no permite PTY (allow_pty=false)", in.Host)
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

	return c, elevationPrefix, nil
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
// (reemplaza ' por '\'').
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
func (l *Local) SignIntent(in Intent) (*Issued, error) {
	c, elevPrefix, err := l.policy.Resolve(in, l.defaultTTL)
	if err != nil {
		return nil, err
	}
	cert, serial, err := ca.BuildAndSign(l.caKey, in.PublicKey, c)
	if err != nil {
		return nil, err
	}
	return &Issued{Certificate: cert, Serial: serial, ElevationPrefix: elevPrefix}, nil
}
