// Package config loads local, recipient-owned Team Relay configuration.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/mohitbadwal/team-relay/internal/privatefs"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Version             int                        `yaml:"version"`
	Relay               RelayConfig                `yaml:"relay"`
	Receiver            ReceiverConfig             `yaml:"receiver"`
	Profiles            map[string]ReceiverProfile `yaml:"profiles"`
	Workspaces          map[string]string          `yaml:"workspaces"`
	OutboundAttachments bool                       `yaml:"outbound_attachments"`
}

type RelayConfig struct {
	URL       string `yaml:"url"`
	TokenFile string `yaml:"token_file"`
}

type ReceiverConfig struct {
	Profile       string `yaml:"profile"`
	MaxConcurrent int    `yaml:"max_concurrent"`
	RuntimeSecs   int    `yaml:"runtime_seconds"`
}

type ReceiverProfile struct {
	Runtime              string         `yaml:"runtime"`
	Executable           string         `yaml:"executable"`
	Model                string         `yaml:"model"`
	WorkDir              string         `yaml:"work_dir"`
	EnvironmentAllowlist []string       `yaml:"environment_allowlist,omitempty"`
	Policy               PolicyConfig   `yaml:"policy"`
	Context              ContextConfig  `yaml:"context"`
	Options              map[string]any `yaml:"options"`
}

type PolicyConfig struct {
	Mode            string   `yaml:"mode"`
	Network         string   `yaml:"network"`
	AllowWrites     *bool    `yaml:"allow_writes"`
	AllowShell      *bool    `yaml:"allow_shell"`
	AllowMCPs       *bool    `yaml:"allow_mcps"`
	DeniedCommands  []string `yaml:"denied_commands"`
	AllowedMCPs     []string `yaml:"allowed_mcps"`
	DenyNestedRelay *bool    `yaml:"deny_nested_team_relay"`
}

type ContextConfig struct {
	InheritUserConfig          *bool `yaml:"inherit_user_config"`
	InheritProjectInstructions *bool `yaml:"inherit_project_instructions"`
	InheritSkills              *bool `yaml:"inherit_skills"`
	InheritMCPs                *bool `yaml:"inherit_mcps"`
}

func Load(path string) (Config, error) {
	if strings.TrimSpace(path) == "" {
		var err error
		path, err = DefaultPath()
		if err != nil {
			return Config{}, err
		}
	}
	path, err := expandHome(path)
	if err != nil {
		return Config{}, err
	}
	payload, err := privatefs.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config %s: %w", path, err)
	}
	var cfg Config
	decoder := yaml.NewDecoder(strings.NewReader(string(payload)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := cfg.normalize(); err != nil {
		return Config{}, fmt.Errorf("config %s: %w", path, err)
	}
	return cfg, nil
}

func DefaultPath() (string, error) {
	if override := strings.TrimSpace(os.Getenv("TEAM_RELAY_CONFIG")); override != "" {
		return expandHome(override)
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve user config directory: %w", err)
	}
	return filepath.Join(base, "team-relay", "config.yaml"), nil
}

func (c Config) DeviceToken() (string, error) {
	if token := strings.TrimSpace(os.Getenv("TEAM_RELAY_DEVICE_TOKEN")); token != "" {
		return token, nil
	}
	if strings.TrimSpace(c.Relay.TokenFile) == "" {
		return "", errors.New("relay.token_file or TEAM_RELAY_DEVICE_TOKEN is required")
	}
	path, err := expandHome(c.Relay.TokenFile)
	if err != nil {
		return "", err
	}
	payload, err := privatefs.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read device token: %w", err)
	}
	token := strings.TrimSpace(string(payload))
	if token == "" {
		return "", errors.New("device token file is empty")
	}
	return token, nil
}

func (c *Config) normalize() error {
	if c.Version == 0 {
		c.Version = 1
	}
	if c.Version != 1 {
		return fmt.Errorf("unsupported config version %d", c.Version)
	}
	if value := strings.TrimSpace(os.Getenv("TEAM_RELAY_URL")); value != "" {
		c.Relay.URL = value
	}
	if strings.TrimSpace(c.Relay.URL) == "" {
		return errors.New("relay.url or TEAM_RELAY_URL is required")
	}
	if c.Receiver.Profile == "" {
		c.Receiver.Profile = "default"
	}
	if c.Receiver.MaxConcurrent <= 0 {
		c.Receiver.MaxConcurrent = 1
	}
	if c.Receiver.RuntimeSecs <= 0 {
		c.Receiver.RuntimeSecs = 900
	}
	for alias, root := range c.Workspaces {
		if strings.TrimSpace(alias) == "" || strings.ContainsAny(alias, "/\\") {
			return fmt.Errorf("workspace alias %q is invalid", alias)
		}
		expanded, err := expandHome(root)
		if err != nil {
			return fmt.Errorf("workspace %q: %w", alias, err)
		}
		c.Workspaces[alias] = filepath.Clean(expanded)
	}
	for name, profile := range c.Profiles {
		if strings.TrimSpace(name) == "" {
			return errors.New("receiver profile name cannot be empty")
		}
		if strings.TrimSpace(profile.Runtime) == "" {
			return fmt.Errorf("receiver profile %q requires runtime", name)
		}
		if profile.WorkDir != "" {
			expanded, err := expandHome(profile.WorkDir)
			if err != nil {
				return fmt.Errorf("receiver profile %q work_dir: %w", name, err)
			}
			profile.WorkDir = filepath.Clean(expanded)
		}
		seenEnvironment := make(map[string]struct{}, len(profile.EnvironmentAllowlist))
		for index, variable := range profile.EnvironmentAllowlist {
			variable = strings.TrimSpace(variable)
			if !validEnvironmentName(variable) {
				return fmt.Errorf("receiver profile %q environment_allowlist[%d] is not a portable environment variable name", name, index)
			}
			key := strings.ToUpper(variable)
			if _, exists := seenEnvironment[key]; exists {
				return fmt.Errorf("receiver profile %q repeats environment variable %q", name, variable)
			}
			seenEnvironment[key] = struct{}{}
			profile.EnvironmentAllowlist[index] = variable
		}
		c.Profiles[name] = profile
	}
	if len(c.Profiles) > 0 {
		if _, ok := c.Profiles[c.Receiver.Profile]; !ok {
			return fmt.Errorf("receiver profile %q is not defined", c.Receiver.Profile)
		}
	}
	return nil
}

func validEnvironmentName(value string) bool {
	if value == "" {
		return false
	}
	for index, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || character == '_' ||
			(index > 0 && character >= '0' && character <= '9') {
			continue
		}
		return false
	}
	return true
}

func expandHome(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "~" || strings.HasPrefix(value, "~/") || (runtime.GOOS == "windows" && strings.HasPrefix(value, `~\`)) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve home directory: %w", err)
		}
		if value == "~" {
			return home, nil
		}
		return filepath.Join(home, value[2:]), nil
	}
	return value, nil
}
