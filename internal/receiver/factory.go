package receiver

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	appconfig "github.com/mohitbadwal/team-relay/internal/config"
	relayruntime "github.com/mohitbadwal/team-relay/internal/runtime"
	"github.com/mohitbadwal/team-relay/internal/runtime/claude"
	"github.com/mohitbadwal/team-relay/internal/runtime/codex"
	"github.com/mohitbadwal/team-relay/internal/runtime/external"
)

// BuildController selects exactly one recipient-owned profile. Nothing in a
// network request can override the runtime, executable, model, directory, or
// maximum policy chosen here.
func BuildController(config appconfig.Config, sessionFile string) (*Controller, error) {
	profile, ok := config.Profiles[config.Receiver.Profile]
	if !ok {
		return nil, fmt.Errorf("receiver profile %q is not configured", config.Receiver.Profile)
	}
	workDir := profile.WorkDir
	if workDir == "" {
		var err error
		workDir, err = os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("determine working directory: %w", err)
		}
	}
	policy, err := policyFromProfile(profile)
	if err != nil {
		return nil, fmt.Errorf("receiver profile %q: %w", config.Receiver.Profile, err)
	}
	timeout := time.Duration(config.Receiver.RuntimeSecs) * time.Second
	if timeout <= 0 {
		timeout = 15 * time.Minute
	}

	var adapter relayruntime.Adapter
	executable := strings.TrimSpace(profile.Executable)
	if executable == "auto" {
		executable = ""
	}
	switch strings.ToLower(strings.TrimSpace(profile.Runtime)) {
	case "claude", claude.RuntimeID:
		adapter, err = claude.New(claude.Config{
			Executable:           executable,
			PrefixArgs:           stringSliceOption(profile.Options, "args"),
			WorkDir:              workDir,
			Model:                profile.Model,
			EnvironmentAllowlist: profile.EnvironmentAllowlist,
			Policy:               policy,
			Timeout:              timeout,
		})
	case codex.RuntimeID:
		adapter, err = codex.New(codex.Config{
			Executable:           executable,
			PrefixArgs:           stringSliceOption(profile.Options, "args"),
			WorkDir:              workDir,
			Model:                profile.Model,
			Profile:              stringOption(profile.Options, "profile"),
			EnvironmentAllowlist: profile.EnvironmentAllowlist,
			Policy:               policy,
			Timeout:              timeout,
		})
	case "external":
		externalID := stringOption(profile.Options, "id")
		if externalID == "" {
			externalID = "external"
		}
		adapter, err = external.New(external.Config{
			ID:                   externalID,
			Name:                 stringOption(profile.Options, "name"),
			Executable:           executable,
			PrefixArgs:           stringSliceOption(profile.Options, "args"),
			WorkDir:              workDir,
			Model:                profile.Model,
			EnvironmentAllowlist: profile.EnvironmentAllowlist,
			Policy:               policy,
			Timeout:              timeout,
		})
	default:
		return nil, fmt.Errorf("receiver runtime must be claude-code, codex, or external")
	}
	if err != nil {
		return nil, err
	}
	if sessionFile == "" {
		stateDir, stateErr := DefaultStateDir()
		if stateErr != nil {
			return nil, stateErr
		}
		sessionFile = filepath.Join(stateDir, "receiver_sessions.json")
	}
	store, err := NewFileSessionStore(sessionFile)
	if err != nil {
		return nil, err
	}
	return NewController(adapter, store, config.Receiver.MaxConcurrent)
}

func policyFromProfile(profile appconfig.ReceiverProfile) (relayruntime.Policy, error) {
	mode := relayruntime.PolicyMode(strings.TrimSpace(profile.Policy.Mode))
	if mode == "" {
		mode = relayruntime.PolicyReadOnly
	}
	policy, err := relayruntime.DefaultPolicy(mode)
	if err != nil {
		return relayruntime.Policy{}, err
	}
	switch strings.ToLower(strings.TrimSpace(profile.Policy.Network)) {
	case "", "default", "inherit":
	case "allow", "allowed", "on", "true":
		policy.AllowNetwork = true
	case "deny", "denied", "off", "false":
		policy.AllowNetwork = false
	default:
		return relayruntime.Policy{}, fmt.Errorf("policy.network must be allow, deny, or default")
	}
	if profile.Policy.AllowWrites != nil {
		policy.AllowWrites = policy.AllowWrites && *profile.Policy.AllowWrites
		if mode == relayruntime.PolicyCustom {
			policy.AllowWrites = *profile.Policy.AllowWrites
		}
	}
	if profile.Policy.AllowShell != nil {
		policy.AllowShell = policy.AllowShell && *profile.Policy.AllowShell
		if mode == relayruntime.PolicyCustom {
			policy.AllowShell = *profile.Policy.AllowShell
		}
	}
	if profile.Policy.AllowMCPs != nil {
		policy.AllowMCPs = policy.AllowMCPs && *profile.Policy.AllowMCPs
		if mode == relayruntime.PolicyCustom {
			policy.AllowMCPs = *profile.Policy.AllowMCPs
		}
	}
	if profile.Context.InheritMCPs != nil && !*profile.Context.InheritMCPs {
		policy.AllowMCPs = false
	}
	if profile.Policy.DenyNestedRelay != nil && !*profile.Policy.DenyNestedRelay {
		return relayruntime.Policy{}, fmt.Errorf("policy.deny_nested_team_relay cannot be disabled")
	}
	// Provider CLIs currently cannot enforce a portable per-MCP allowlist.
	// Reject it rather than advertising a boundary that can be bypassed.
	if len(profile.Policy.AllowedMCPs) > 0 {
		return relayruntime.Policy{}, fmt.Errorf("policy.allowed_mcps is not supported yet; use context.inherit_mcps for all-or-none MCP access")
	}
	if explicitlyFalse(profile.Context.InheritUserConfig) || explicitlyFalse(profile.Context.InheritProjectInstructions) || explicitlyFalse(profile.Context.InheritSkills) {
		return relayruntime.Policy{}, fmt.Errorf("disabling user config, project instructions, or skills independently is not supported by all runtimes yet")
	}
	policy.DeniedCommands = append(policy.DeniedCommands, profile.Policy.DeniedCommands...)
	return relayruntime.ValidatePolicy(policy)
}

func explicitlyFalse(value *bool) bool { return value != nil && !*value }

func stringOption(options map[string]any, name string) string {
	if value, ok := options[name].(string); ok {
		return strings.TrimSpace(value)
	}
	return ""
}

func stringSliceOption(options map[string]any, name string) []string {
	value, ok := options[name]
	if !ok {
		return nil
	}
	switch values := value.(type) {
	case []string:
		return append([]string(nil), values...)
	case []any:
		result := make([]string, 0, len(values))
		for _, item := range values {
			if text, ok := item.(string); ok && strings.TrimSpace(text) != "" {
				result = append(result, text)
			}
		}
		return result
	default:
		return nil
	}
}

func DefaultStateDir() (string, error) {
	if override := strings.TrimSpace(os.Getenv("TEAM_RELAY_STATE_DIR")); override != "" {
		return filepath.Abs(override)
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve user config directory: %w", err)
	}
	return filepath.Join(base, "team-relay"), nil
}
