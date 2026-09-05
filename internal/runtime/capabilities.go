package runtime

import (
	"fmt"
	"strings"
)

// ValidatePolicySupport fails closed when an adapter cannot enforce a control
// denied by the recipient-owned policy. Best-effort and tool-level controls are
// accepted but remain visible through the capability report; only an explicit
// or unknown/empty unsupported control prevents execution.
func ValidatePolicySupport(capabilities Capabilities, policy Policy) error {
	validated, err := ValidatePolicy(policy)
	if err != nil {
		return err
	}

	missing := make([]string, 0, 6)
	if validated.AllowWrites {
		if !availableEnforcement(capabilities.Policy.GuardedWrite) {
			missing = append(missing, "guarded-write mode")
		}
	} else if !availableEnforcement(capabilities.Policy.ReadOnly) {
		missing = append(missing, "read-only mode")
	}
	if !availableEnforcement(capabilities.Policy.FilesystemIsolation) {
		missing = append(missing, "filesystem isolation")
	}
	if !availableEnforcement(capabilities.Policy.DestructiveCommandDeny) {
		missing = append(missing, "destructive-command denial")
	}
	if !validated.AllowNetwork && !availableEnforcement(capabilities.Policy.NetworkIsolation) {
		missing = append(missing, "network isolation")
	}
	if !validated.AllowShell && !availableEnforcement(capabilities.Policy.ShellControl) {
		missing = append(missing, "shell control")
	}
	if !validated.AllowMCPs && !availableEnforcement(capabilities.Policy.MCPControl) {
		missing = append(missing, "MCP control")
	}
	if len(missing) == 0 {
		return nil
	}
	runtimeID := strings.TrimSpace(capabilities.RuntimeID)
	if runtimeID == "" {
		runtimeID = "unknown"
	}
	return fmt.Errorf("%w: runtime %q does not enforce required controls: %s", ErrUnsupportedPolicy, runtimeID, strings.Join(missing, ", "))
}

func SupportsPolicy(capabilities Capabilities, policy Policy) bool {
	return ValidatePolicySupport(capabilities, policy) == nil
}

func availableEnforcement(value Enforcement) bool {
	switch value {
	case EnforcementNative, EnforcementToolLevel, EnforcementBestEffort:
		return true
	default:
		return false
	}
}
