package signer

import "fmt"

// PolicySet is a host's effective command policy: the composition of every
// CommandPolicy that applies to it — its own inline command_policy plus the
// named policies attached to each of its groups (see CompileHostPolicies).
//
// Composition is ADDITIVE (union):
//
//   - deny wins: a deny match in ANY denylist policy blocks the command.
//   - allow is a union: if ANY policy is an allowlist, the command must match the
//     union of all allowlists; with no allowlist present, the default is allow.
//   - require_approval is a union: any match requires approval.
//   - shell_parse is OR: any policy with shell_parse parses the command.
//   - enforcement is conservative: enforce wins over audit.
//
// A single-element PolicySet evaluates a lone inline command_policy, so a host
// with one inline policy and no group policies behaves identically to before.
type PolicySet []CommandPolicy

// Active reports whether any member enforces allow/deny.
func (ps PolicySet) Active() bool {
	for _, p := range ps {
		if p.Active() {
			return true
		}
	}
	return false
}

// Restricts reports whether any member imposes a command rule (allow/deny or
// require_approval) — i.e. whether the host needs command-aware session handling.
func (ps PolicySet) Restricts() bool {
	for _, p := range ps {
		if p.Restricts() {
			return true
		}
	}
	return false
}

// Enforcement returns the effective enforcement mode for the composed policy.
// The composition is conservative: any enforcing policy makes the whole set
// enforcing. A host is audit-only only when every restricting member is audit.
func (ps PolicySet) Enforcement() string {
	auditOnly := false
	for _, p := range ps {
		if !p.Restricts() {
			continue
		}
		if p.Enforcement == CmdPolicyAudit {
			auditOnly = true
			continue
		}
		return CmdPolicyEnforce
	}
	if auditOnly {
		return CmdPolicyAudit
	}
	return CmdPolicyEnforce
}

// hasAllowlist reports whether any member enforces an allowlist. It gates
// widen-only grant injection: a runtime allow-grant must only be added to a host
// that is ALREADY allowlist-active. On a default-allow or denylist-only host the
// command is already permitted, and adding an allowlist member would invert the
// host to default-deny (see decideOne step 3) — so injection is suppressed there.
func (ps PolicySet) hasAllowlist() bool {
	for _, p := range ps {
		if p.Mode == CmdPolicyAllowlist {
			return true
		}
	}
	return false
}

// Validate compiles every regex in every member policy.
func (ps PolicySet) Validate() error {
	for _, p := range ps {
		if err := p.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// Decide evaluates command against the composed set. When any member has
// shell_parse=true the command is decomposed once and each simple command is
// evaluated against the whole set.
func (ps PolicySet) Decide(command string) (allowed bool, needsApproval bool, rule string, err error) {
	if len(ps) == 0 {
		return true, false, "", nil
	}
	cmds := []string{command}
	if ps.shellParse() {
		cmds, err = extractCommands(command)
		if err != nil {
			return false, false, "shell-parse:" + err.Error(), err
		}
	}
	for _, cmd := range cmds {
		a, n, r, cerr := ps.decideOne(cmd)
		if cerr != nil || !a {
			return a, n, r, cerr
		}
		if n && !needsApproval {
			needsApproval = true
			rule = r
		} else if !needsApproval {
			rule = r
		}
	}
	return true, needsApproval, rule, nil
}

// shellParse reports whether any member requests POSIX shell parsing.
func (ps PolicySet) shellParse() bool {
	for _, p := range ps {
		if p.ShellParse {
			return true
		}
	}
	return false
}

// decideOne composes the decision for a single simple command across all member
// policies: deny wins, then require_approval (union), then allow (union of every
// allowlist; default-allow when no allowlist applies).
func (ps PolicySet) decideOne(command string) (allowed bool, needsApproval bool, rule string, err error) {
	// 1. deny wins — any denylist match blocks, regardless of allowlists.
	for _, p := range ps {
		if p.Mode != CmdPolicyDenylist {
			continue
		}
		for _, pat := range p.Deny {
			re, e := cachedRegex(pat)
			if e != nil {
				return false, false, "", fmt.Errorf("invalid deny regex %q: %w", pat, e)
			}
			if re.MatchString(command) {
				return false, false, "deny:" + pat, nil
			}
		}
	}
	// 2. require_approval — union across all members.
	for _, p := range ps {
		for _, pat := range p.RequireApproval {
			re, e := cachedRegex(pat)
			if e != nil {
				return false, false, "", fmt.Errorf("invalid require_approval regex %q: %w", pat, e)
			}
			if re.MatchString(command) {
				needsApproval = true
				rule = "require_approval:" + pat
				break
			}
		}
		if needsApproval {
			break
		}
	}
	// 3. allow — union of every allowlist. If none applies, default-allow.
	hasAllowlist := false
	for _, p := range ps {
		if p.Mode != CmdPolicyAllowlist {
			continue
		}
		hasAllowlist = true
		for _, pat := range p.Allow {
			re, e := cachedRegex(pat)
			if e != nil {
				return false, false, "", fmt.Errorf("invalid allow regex %q: %w", pat, e)
			}
			if re.MatchString(command) {
				if rule == "" {
					rule = "allow:" + pat
				}
				return true, needsApproval, rule, nil
			}
		}
	}
	if !hasAllowlist {
		return true, needsApproval, rule, nil
	}
	return false, needsApproval, "allowlist:no-match", nil
}
