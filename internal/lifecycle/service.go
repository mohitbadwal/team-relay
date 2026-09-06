package lifecycle

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/mohitbadwal/team-relay/internal/privatefs"
)

type serviceLayout struct {
	directory string
	unit      string
	entry     string
	log       string
}

func layoutFor(platform, home, configBase, id string) serviceLayout {
	directory := filepath.Join(configBase, "team-relay", "services", id)
	if platform == "darwin" {
		name := id + ".plist"
		return serviceLayout{directory, filepath.Join(directory, name), filepath.Join(home, "Library", "LaunchAgents", name), filepath.Join(directory, "service.log")}
	}
	name := id + ".service"
	return serviceLayout{directory, filepath.Join(directory, name), filepath.Join(configBase, "systemd", "user", name), ""}
}

func validateExecutable(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("service executable is unavailable at %s; run ./install-native first: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("service executable %s is not an executable regular file", path)
	}
	return nil
}

func validateSpec(spec serviceSpec) error {
	if err := validateExecutable(spec.executable); err != nil {
		return err
	}
	if spec.role == "server" {
		if _, err := privatefs.ReadFile(spec.environment["TEAM_RELAY_BOOTSTRAP_TOKEN_FILE"]); err != nil {
			return fmt.Errorf("read private bootstrap token file before starting server: %w", err)
		}
	} else {
		if _, err := privatefs.ReadFile(spec.args[1]); err != nil {
			return fmt.Errorf("read private receiver config before starting service; enroll with team-relay setup first: %w", err)
		}
		if err := privatefs.EnsureDirectory(spec.args[3]); err != nil {
			return fmt.Errorf("prepare private receiver state: %w", err)
		}
	}
	return nil
}

// Service definitions contain only this receiver's selected environment, and
// may contain a Redis password. Keep them private rather than placing their
// contents directly in the shared service-manager configuration directory.
func installDefinition(platform string, spec serviceSpec, layout serviceLayout) error {
	if err := privatefs.EnsureDirectory(layout.directory); err != nil {
		return fmt.Errorf("prepare private service directory: %w", err)
	}
	if err := checkEntry(layout); err != nil {
		return err
	}
	var payload []byte
	if platform == "darwin" {
		if err := ensurePrivateLog(layout.log); err != nil {
			return err
		}
		payload = launchAgent(spec, layout.log)
	} else {
		payload = systemdUnit(spec)
	}
	if info, err := os.Lstat(layout.unit); err == nil {
		if !info.Mode().IsRegular() {
			return errors.New("refusing to replace a non-regular service definition")
		}
		if err := privatefs.ValidateRegularFile(layout.unit); err != nil {
			return fmt.Errorf("existing service definition is not private: %w", err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := privatefs.AtomicWriteFile(layout.unit, payload, 0o600); err != nil {
		return fmt.Errorf("write service definition: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(layout.entry), 0o755); err != nil {
		return fmt.Errorf("create service-manager directory: %w", err)
	}
	if _, err := os.Lstat(layout.entry); errors.Is(err, fs.ErrNotExist) {
		if err := os.Symlink(layout.unit, layout.entry); err != nil {
			return fmt.Errorf("link scoped service definition: %w", err)
		}
	} else if err != nil {
		return err
	}
	return nil
}

func checkEntry(layout serviceLayout) error {
	info, err := os.Lstat(layout.entry)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return fmt.Errorf("refusing to replace an existing service-manager entry at %s", layout.entry)
	}
	target, err := os.Readlink(layout.entry)
	if err != nil {
		return err
	}
	if target != layout.unit {
		return fmt.Errorf("service-manager entry %s belongs to a different definition", layout.entry)
	}
	return nil
}

func removeEntry(layout serviceLayout) error {
	if err := checkEntry(layout); err != nil {
		return err
	}
	if err := os.Remove(layout.entry); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove scoped service link: %w", err)
	}
	return nil
}

func ensurePrivateLog(path string) error {
	if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
		if err := privatefs.WriteNewFile(path, nil, 0o600); err != nil {
			return fmt.Errorf("create private service log: %w", err)
		}
	} else if err != nil {
		return err
	}
	if err := privatefs.ValidateRegularFile(path); err != nil {
		return fmt.Errorf("service log is not a private regular file: %w", err)
	}
	return nil
}

func xmlText(value string) string {
	var out bytes.Buffer
	_ = xml.EscapeText(&out, []byte(value))
	return out.String()
}

func sortedKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func launchAgent(spec serviceSpec, logPath string) []byte {
	var out strings.Builder
	out.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n")
	fmt.Fprintf(&out, "<key>Label</key><string>%s</string>\n", xmlText(spec.id))
	out.WriteString("<key>ProgramArguments</key><array>\n")
	for _, argument := range append([]string{spec.executable}, spec.args...) {
		fmt.Fprintf(&out, "<string>%s</string>\n", xmlText(argument))
	}
	out.WriteString("</array>\n<key>EnvironmentVariables</key><dict>\n")
	for _, key := range sortedKeys(spec.environment) {
		fmt.Fprintf(&out, "<key>%s</key><string>%s</string>\n", xmlText(key), xmlText(spec.environment[key]))
	}
	out.WriteString("</dict>\n")
	fmt.Fprintf(&out, "<key>WorkingDirectory</key><string>%s</string>\n", xmlText(spec.workingDir))
	fmt.Fprintf(&out, "<key>StandardOutPath</key><string>%s</string>\n<key>StandardErrorPath</key><string>%s</string>\n", xmlText(logPath), xmlText(logPath))
	out.WriteString("<key>RunAtLoad</key><true/>\n<key>KeepAlive</key><true/>\n<key>ThrottleInterval</key><integer>10</integer>\n<key>Umask</key><integer>63</integer>\n</dict></plist>\n")
	return []byte(out.String())
}

// systemd performs specifier expansion for unit values and additionally dollar
// expansion for ExecStart. Quoting alone does not turn off those expansions.
func systemdQuote(value string, execArgument bool) string {
	value = strings.ReplaceAll(value, "%", "%%")
	if execArgument {
		value = strings.ReplaceAll(value, "$", "$$")
	}
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\"", "\\\"")
	value = strings.ReplaceAll(value, "\t", "\\t")
	return "\"" + value + "\""
}

func systemdUnit(spec serviceSpec) []byte {
	var out strings.Builder
	fmt.Fprintf(&out, "[Unit]\nDescription=Team Relay %s (%s)\n\n[Service]\nType=simple\n", spec.role, spec.id)
	fmt.Fprintf(&out, "WorkingDirectory=%s\n", systemdQuote(spec.workingDir, false))
	out.WriteString("ExecStart=")
	for index, argument := range append([]string{spec.executable}, spec.args...) {
		if index > 0 {
			out.WriteByte(' ')
		}
		out.WriteString(systemdQuote(argument, true))
	}
	out.WriteByte('\n')
	for _, key := range sortedKeys(spec.environment) {
		fmt.Fprintf(&out, "Environment=%s\n", systemdQuote(key+"="+spec.environment[key], false))
	}
	out.WriteString("Restart=always\nRestartSec=10\nUMask=0077\nStandardOutput=journal\nStandardError=journal\n\n[Install]\nWantedBy=default.target\n")
	return []byte(out.String())
}
