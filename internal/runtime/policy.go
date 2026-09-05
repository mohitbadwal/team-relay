package runtime

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

type PolicyMode string

const (
	PolicyReadOnly     PolicyMode = "read_only"
	PolicyGuardedWrite PolicyMode = "guarded_write"
	PolicyCustom       PolicyMode = "custom"
)

// Policy is recipient-owned configuration. Destructive commands are always
// denied by Team Relay; a runtime may only be able to enforce that denial on a
// best-effort basis, which is exposed through Capabilities.
type Policy struct {
	Mode           PolicyMode `json:"mode" yaml:"mode"`
	AllowWrites    bool       `json:"allow_writes" yaml:"allow_writes"`
	AllowShell     bool       `json:"allow_shell" yaml:"allow_shell"`
	AllowNetwork   bool       `json:"allow_network" yaml:"allow_network"`
	AllowMCPs      bool       `json:"allow_mcps" yaml:"allow_mcps"`
	DeniedTools    []string   `json:"denied_tools,omitempty" yaml:"denied_tools,omitempty"`
	DeniedCommands []string   `json:"denied_commands,omitempty" yaml:"denied_commands,omitempty"`
}

// PolicyRequest can only narrow a local Policy. Pointer booleans distinguish
// "not requested" from an explicit false.
type PolicyRequest struct {
	Mode         PolicyMode `json:"mode,omitempty"`
	AllowWrites  *bool      `json:"allow_writes,omitempty"`
	AllowShell   *bool      `json:"allow_shell,omitempty"`
	AllowNetwork *bool      `json:"allow_network,omitempty"`
	AllowMCPs    *bool      `json:"allow_mcps,omitempty"`
}

var baselineDeniedCommands = []string{
	"rm",
	"rmdir",
	"git reset --hard",
	"git clean",
	"git push --force",
	"git push -f",
	"sudo",
	"doas",
	"shutdown",
	"reboot",
	"kubectl delete",
	"terraform destroy",
	"team-relay",
	"team-relay-agent",
	"team-relay-mcp",
}

func DefaultPolicy(mode PolicyMode) (Policy, error) {
	switch mode {
	case PolicyReadOnly:
		return normalizePolicy(Policy{Mode: mode}), nil
	case PolicyGuardedWrite:
		return normalizePolicy(Policy{
			Mode:         mode,
			AllowWrites:  true,
			AllowShell:   true,
			AllowNetwork: true,
			AllowMCPs:    true,
		}), nil
	case PolicyCustom:
		return normalizePolicy(Policy{Mode: mode}), nil
	default:
		return Policy{}, fmt.Errorf("unknown policy mode %q", mode)
	}
}

func ValidatePolicy(policy Policy) (Policy, error) {
	switch policy.Mode {
	case PolicyReadOnly, PolicyGuardedWrite, PolicyCustom:
	default:
		return Policy{}, fmt.Errorf("unknown policy mode %q", policy.Mode)
	}
	return normalizePolicy(policy), nil
}

// EffectivePolicy computes local ∩ requested. A true value in a peer request
// never turns on a capability disabled by the recipient.
func EffectivePolicy(local Policy, requested *PolicyRequest) (Policy, error) {
	local, err := ValidatePolicy(local)
	if err != nil {
		return Policy{}, err
	}
	if requested == nil || (requested.Mode == "" && requested.AllowWrites == nil && requested.AllowShell == nil && requested.AllowNetwork == nil && requested.AllowMCPs == nil) {
		return local, nil
	}

	limit := Policy{
		Mode:         PolicyCustom,
		AllowWrites:  true,
		AllowShell:   true,
		AllowNetwork: true,
		AllowMCPs:    true,
	}
	if requested.Mode != "" {
		var err error
		limit, err = DefaultPolicy(requested.Mode)
		if err != nil {
			return Policy{}, err
		}
	}
	intersectBool := func(current bool, requested *bool) bool {
		if requested == nil {
			return current
		}
		return current && *requested
	}
	limit.AllowWrites = intersectBool(limit.AllowWrites, requested.AllowWrites)
	limit.AllowShell = intersectBool(limit.AllowShell, requested.AllowShell)
	limit.AllowNetwork = intersectBool(limit.AllowNetwork, requested.AllowNetwork)
	limit.AllowMCPs = intersectBool(limit.AllowMCPs, requested.AllowMCPs)

	effective := local
	effective.AllowWrites = local.AllowWrites && limit.AllowWrites
	effective.AllowShell = local.AllowShell && limit.AllowShell
	effective.AllowNetwork = local.AllowNetwork && limit.AllowNetwork
	effective.AllowMCPs = local.AllowMCPs && limit.AllowMCPs
	if !effective.AllowWrites && !effective.AllowShell && !effective.AllowMCPs {
		effective.Mode = PolicyReadOnly
	} else if samePermissions(effective, local) {
		effective.Mode = local.Mode
	} else {
		effective.Mode = PolicyCustom
	}
	return normalizePolicy(effective), nil
}

func samePermissions(left, right Policy) bool {
	return left.AllowWrites == right.AllowWrites &&
		left.AllowShell == right.AllowShell &&
		left.AllowNetwork == right.AllowNetwork &&
		left.AllowMCPs == right.AllowMCPs
}

func normalizePolicy(policy Policy) Policy {
	if policy.Mode == PolicyReadOnly {
		policy.AllowWrites = false
		policy.AllowShell = false
		// An arbitrary MCP can mutate remote state, so MCP use is not part of
		// the provider-neutral read-only guarantee.
		policy.AllowMCPs = false
	}
	policy.DeniedTools = uniqueSorted(append([]string{"team-relay"}, policy.DeniedTools...))
	policy.DeniedCommands = uniqueSorted(append(append([]string(nil), baselineDeniedCommands...), policy.DeniedCommands...))
	return policy
}

func uniqueSorted(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || slices.Contains(result, value) {
			continue
		}
		result = append(result, value)
	}
	slices.Sort(result)
	return result
}

func PolicyFingerprint(policy Policy) string {
	policy = normalizePolicy(policy)
	encoded, _ := json.Marshal(policy)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:16])
}

func WorkDirFingerprint(path string) string {
	sum := sha256.Sum256([]byte(path))
	return hex.EncodeToString(sum[:16])
}

func CompatibleSession(session *SessionRef, runtimeID string, policy Policy, workDir string) bool {
	return session != nil && session.OpaqueID != "" && session.RuntimeID == runtimeID &&
		session.PolicyFingerprint == PolicyFingerprint(policy) &&
		session.WorkDirFingerprint == WorkDirFingerprint(workDir)
}
