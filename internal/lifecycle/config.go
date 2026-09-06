// Package lifecycle manages native Team Relay processes through the current
// user's OS service manager. Every service belongs to one role and config path.
package lifecycle

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	appconfig "github.com/mohitbadwal/team-relay/internal/config"
	"github.com/mohitbadwal/team-relay/internal/privatefs"
	"github.com/mohitbadwal/team-relay/internal/receiver"
	relayruntime "github.com/mohitbadwal/team-relay/internal/runtime"
)

var configKeys = map[string]bool{
	"TEAM_RELAY_SERVER_MODE": true, "TEAM_RELAY_BIND_ADDRESS": true,
	"TEAM_RELAY_PORT": true, "TEAM_RELAY_REDIS_URL": true,
	"TEAM_RELAY_BOOTSTRAP_TOKEN_FILE": true, "TEAM_RELAY_SERVER_EXECUTABLE": true,
	"TEAM_RELAY_RECEIVER_EXECUTABLE": true, "TEAM_RELAY_RECEIVER_CONFIG": true,
	"TEAM_RELAY_RECEIVER_STATE_DIR": true, "TEAM_RELAY_RECEIVER_CONTROL_ADDRESS": true,
}

type configuration struct {
	path   string
	values map[string]string
}

func loadConfig(path string) (configuration, error) {
	if strings.TrimSpace(path) == "" {
		return configuration{}, errors.New("a lifecycle .conf path is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return configuration{}, fmt.Errorf("resolve lifecycle config: %w", err)
	}
	if err := privatefs.ValidateRegularFile(abs); err != nil {
		return configuration{}, fmt.Errorf("lifecycle config must be a private regular file (chmod 600 on Unix): %w", err)
	}
	file, err := os.Open(abs)
	if err != nil {
		return configuration{}, fmt.Errorf("open lifecycle config: %w", err)
	}
	defer file.Close()
	payload, err := io.ReadAll(io.LimitReader(file, 65537))
	if err != nil {
		return configuration{}, fmt.Errorf("read lifecycle config: %w", err)
	}
	if len(payload) > 65536 {
		return configuration{}, errors.New("lifecycle config exceeds 64 KiB")
	}
	values, err := parseConfig(string(payload))
	if err != nil {
		return configuration{}, err
	}
	return configuration{path: filepath.Clean(abs), values: values}, nil
}

func parseConfig(payload string) (map[string]string, error) {
	values := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(payload))
	for line := 1; scanner.Scan(); line++ {
		text := strings.TrimSuffix(scanner.Text(), "\r")
		if strings.TrimSpace(text) == "" || strings.HasPrefix(text, "#") {
			continue
		}
		key, value, ok := strings.Cut(text, "=")
		if !ok || !configKeys[key] {
			return nil, fmt.Errorf("lifecycle config line %d: expected a supported KEY=value setting or # comment", line)
		}
		if _, exists := values[key]; exists {
			return nil, fmt.Errorf("lifecycle config line %d: duplicate %s", line, key)
		}
		if strings.ContainsAny(value, "\x00\r\n") {
			return nil, fmt.Errorf("lifecycle config line %d: control characters are not allowed", line)
		}
		// Values are literal. Quotes, substitutions, exports, and shell statements
		// are neither interpreted nor removed.
		values[key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, errors.New("could not scan lifecycle config")
	}
	return values, nil
}

func (c configuration) value(key, fallback string) string {
	if value := c.values[key]; value != "" {
		return value
	}
	return fallback
}

func (c configuration) resolve(value string) string {
	if filepath.IsAbs(value) {
		return filepath.Clean(value)
	}
	return filepath.Join(filepath.Dir(c.path), value)
}

func serviceID(role, absoluteConfigPath string) string {
	digest := sha256.Sum256([]byte(filepath.Clean(absoluteConfigPath)))
	return "com.team-relay." + role + "." + hex.EncodeToString(digest[:16])
}

type serviceSpec struct {
	id          string
	role        string
	configPath  string
	workingDir  string
	executable  string
	args        []string
	environment map[string]string
}

func makeSpec(c configuration, role, home, commandPath string) (serviceSpec, error) {
	spec := serviceSpec{
		id: serviceID(role, c.path), role: role, configPath: c.path,
		workingDir: filepath.Dir(c.path), environment: map[string]string{},
	}
	switch role {
	case "server":
		bind := c.value("TEAM_RELAY_BIND_ADDRESS", "127.0.0.1")
		if bind != "127.0.0.1" && bind != "0.0.0.0" {
			return serviceSpec{}, errors.New("TEAM_RELAY_BIND_ADDRESS must be 127.0.0.1 or 0.0.0.0")
		}
		port := c.value("TEAM_RELAY_PORT", "8080")
		if !validPort(port) {
			return serviceSpec{}, errors.New("TEAM_RELAY_PORT must be an integer from 1 to 65535")
		}
		redisURL := c.value("TEAM_RELAY_REDIS_URL", "redis://127.0.0.1:6379/0")
		parsed, err := url.Parse(redisURL)
		if err != nil || (parsed.Scheme != "redis" && parsed.Scheme != "rediss") || parsed.Host == "" || parsed.Fragment != "" {
			return serviceSpec{}, errors.New("TEAM_RELAY_REDIS_URL must be a valid redis:// or rediss:// URL")
		}
		spec.executable = c.resolve(c.value("TEAM_RELAY_SERVER_EXECUTABLE", "bin/team-relay-server"))
		spec.environment["REDIS_URL"] = redisURL
		spec.environment["TEAM_RELAY_ADDR"] = net.JoinHostPort(bind, port)
		spec.environment["TEAM_RELAY_BOOTSTRAP_TOKEN_FILE"] = c.resolve(c.value("TEAM_RELAY_BOOTSTRAP_TOKEN_FILE", "secrets/bootstrap-token"))
	case "receiver":
		spec.executable = c.resolve(c.value("TEAM_RELAY_RECEIVER_EXECUTABLE", "bin/team-relay-agent"))
		configPath := c.values["TEAM_RELAY_RECEIVER_CONFIG"]
		if configPath == "" {
			var err error
			configPath, err = appconfig.DefaultPath()
			if err != nil {
				return serviceSpec{}, err
			}
			configPath, err = filepath.Abs(configPath)
			if err != nil {
				return serviceSpec{}, err
			}
		} else {
			configPath = c.resolve(configPath)
		}
		stateDir := c.values["TEAM_RELAY_RECEIVER_STATE_DIR"]
		if stateDir == "" {
			var err error
			stateDir, err = receiver.DefaultStateDir()
			if err != nil {
				return serviceSpec{}, err
			}
		} else {
			stateDir = c.resolve(stateDir)
		}
		control := c.value("TEAM_RELAY_RECEIVER_CONTROL_ADDRESS", "127.0.0.1:8787")
		host, port, err := net.SplitHostPort(control)
		if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() || !validPort(port) {
			return serviceSpec{}, errors.New("TEAM_RELAY_RECEIVER_CONTROL_ADDRESS must be a loopback IP and port from 1 to 65535")
		}
		spec.args = []string{"--config", configPath, "--state-dir", stateDir, "--control-address", control, "run"}
		// Runtime CLIs need the user's tool search path and home for existing
		// subscriptions/config. Never snapshot the rest of the shell environment.
		spec.environment["HOME"] = home
		spec.environment["PATH"] = commandPath
	default:
		return serviceSpec{}, errors.New("lifecycle role must be server or receiver")
	}
	for _, value := range append(append([]string{spec.executable, spec.workingDir}, spec.args...), mapValues(spec.environment)...) {
		if strings.ContainsAny(value, "\x00\r\n") {
			return serviceSpec{}, errors.New("service paths and environment values cannot contain control characters")
		}
	}
	return spec, nil
}

func mapValues(values map[string]string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	return result
}

// A service manager does not inherit the interactive shell that enrolled the
// receiver. Capture only the selected recipient profile's explicitly allowed
// variables, and apply the same authority exclusions as the runtime boundary.
// These values are stored only in the private generated service definition.
func inheritReceiverEnvironment(spec *serviceSpec, environment []string) error {
	if spec.role != "receiver" {
		return nil
	}
	cfg, err := appconfig.Load(spec.args[1])
	if err != nil {
		return errors.New("could not load private receiver config to select its environment allowlist; check the enrollment config")
	}
	profile, ok := cfg.Profiles[cfg.Receiver.Profile]
	if !ok {
		return errors.New("the selected receiver profile is not configured")
	}
	allowed := make(map[string]bool, len(profile.EnvironmentAllowlist))
	for _, name := range profile.EnvironmentAllowlist {
		allowed[strings.ToUpper(strings.TrimSpace(name))] = true
	}
	selected := make([]string, 0, len(allowed))
	for _, entry := range environment {
		name, _, found := strings.Cut(entry, "=")
		if found && allowed[strings.ToUpper(name)] {
			selected = append(selected, entry)
		}
	}
	for _, entry := range relayruntime.SanitizedEnvironment(selected, profile.EnvironmentAllowlist) {
		name, value, _ := strings.Cut(entry, "=")
		if strings.ContainsAny(value, "\x00\r\n") {
			return fmt.Errorf("allowed environment variable %s contains unsupported control characters", name)
		}
		spec.environment[name] = value
	}
	return nil
}

func validPort(value string) bool {
	if value == "" || strings.Trim(value, "0123456789") != "" {
		return false
	}
	port, err := strconv.Atoi(value)
	return err == nil && port > 0 && port <= 65535
}
