package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

type CommandSpec struct {
	Executable           string
	Args                 []string
	Directory            string
	Stdin                string
	EnvironmentAllowlist []string
	// Environment contains trusted, adapter-owned values added after host
	// environment sanitization. Relay authority variables remain forbidden.
	Environment map[string]string
}

// ExecuteJSONLines starts a fixed local executable without invoking a shell.
// It drains stderr but exposes only a bounded, redacted diagnostic on failure.
func ExecuteJSONLines(ctx context.Context, spec CommandSpec, onLine func(json.RawMessage) error) error {
	cmd := exec.CommandContext(ctx, spec.Executable, spec.Args...)
	cmd.Dir = spec.Directory
	cmd.Stdin = strings.NewReader(spec.Stdin)
	environment, err := trustedEnvironment(SanitizedEnvironment(os.Environ(), spec.EnvironmentAllowlist), spec.Environment)
	if err != nil {
		return fmt.Errorf("runtime environment: %w", err)
	}
	cmd.Env = environment
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("stderr pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start runtime: %w", err)
	}
	stderrDone := make(chan []byte, 1)
	go func() {
		var buffer bytes.Buffer
		_, _ = io.CopyN(&buffer, stderr, MaxDiagnosticBytes)
		_, _ = io.Copy(io.Discard, stderr)
		stderrDone <- buffer.Bytes()
	}()
	scanErr := ScanJSONLines(stdout, onLine)
	if scanErr != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	waitErr := cmd.Wait()
	diagnostic := Diagnostic(<-stderrDone)
	if scanErr != nil {
		return fmt.Errorf("read runtime output: %w", scanErr)
	}
	if waitErr != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if diagnostic != "" {
			return fmt.Errorf("runtime exited: %w (%s)", waitErr, diagnostic)
		}
		return fmt.Errorf("runtime exited: %w", waitErr)
	}
	return nil
}

func trustedEnvironment(base []string, extra map[string]string) ([]string, error) {
	result := append([]string(nil), base...)
	if len(extra) == 0 {
		return result, nil
	}
	names := make([]string, 0, len(extra))
	for name, value := range extra {
		upper := strings.ToUpper(name)
		if name == "" || strings.ContainsAny(name, "=\x00") || strings.ContainsRune(value, '\x00') {
			return nil, fmt.Errorf("invalid environment override name %q", name)
		}
		if relayAuthorityVariable(upper) {
			return nil, fmt.Errorf("relay authority environment variable %q is forbidden", name)
		}
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		upper := strings.ToUpper(name)
		filtered := result[:0]
		for _, item := range result {
			current, _, found := strings.Cut(item, "=")
			if !found || strings.ToUpper(current) != upper {
				filtered = append(filtered, item)
			}
		}
		result = append(filtered, name+"="+extra[name])
	}
	return result, nil
}

// SanitizedEnvironment starts from a small operational allowlist. Additional
// names are recipient-owned configuration for runtimes or MCPs that require an
// environment variable. Relay authority is denied even if explicitly listed.
func SanitizedEnvironment(environment, additionalAllowed []string) []string {
	allowed := map[string]struct{}{
		"ALL_PROXY": {}, "APPDATA": {}, "CLAUDE_CONFIG_DIR": {}, "CODEX_HOME": {},
		"COLORTERM": {}, "COMSPEC": {}, "CURL_CA_BUNDLE": {}, "HOME": {},
		"HTTPS_PROXY": {}, "HTTP_PROXY": {}, "LANG": {}, "LANGUAGE": {},
		"LOCALAPPDATA": {}, "LOGNAME": {}, "NODE_EXTRA_CA_CERTS": {}, "NO_COLOR": {},
		"NO_PROXY": {}, "PATH": {}, "PATHEXT": {}, "PROGRAMDATA": {},
		"REQUESTS_CA_BUNDLE": {}, "SHELL": {}, "SSL_CERT_DIR": {}, "SSL_CERT_FILE": {},
		"SYSTEMROOT": {}, "TEMP": {}, "TERM": {}, "TMP": {}, "TMPDIR": {},
		"USER": {}, "USERPROFILE": {}, "WINDIR": {}, "XDG_CACHE_HOME": {},
		"XDG_CONFIG_HOME": {}, "XDG_DATA_HOME": {}, "XDG_STATE_HOME": {},
	}
	for _, name := range additionalAllowed {
		name = strings.ToUpper(strings.TrimSpace(name))
		if name != "" && !relayAuthorityVariable(name) {
			allowed[name] = struct{}{}
		}
	}
	result := make([]string, 0, len(environment))
	for _, item := range environment {
		name, _, found := strings.Cut(item, "=")
		if !found {
			continue
		}
		upper := strings.ToUpper(name)
		if relayAuthorityVariable(upper) {
			continue
		}
		if _, ok := allowed[upper]; !ok && !strings.HasPrefix(upper, "LC_") {
			continue
		}
		result = append(result, item)
	}
	return result
}

func relayAuthorityVariable(upper string) bool {
	return strings.HasPrefix(upper, "TEAM_RELAY_")
}

func ProbeCommand(ctx context.Context, executable string, prefixArgs, environmentAllowlist []string, versionArgs ...string) (string, error) {
	if _, err := exec.LookPath(executable); err != nil {
		return "", fmt.Errorf("%w: %s", ErrUnavailable, executable)
	}
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	args := append(append([]string(nil), prefixArgs...), versionArgs...)
	command := exec.CommandContext(probeCtx, executable, args...)
	command.Env = SanitizedEnvironment(os.Environ(), environmentAllowlist)
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("probe runtime: %w", err)
	}
	return SafeSummary(string(output)), nil
}
