package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/mohitbadwal/team-relay/internal/privatefs"
)

type executor interface {
	output(context.Context, string, ...string) ([]byte, error)
	stream(context.Context, io.Writer, io.Writer, string, ...string) error
}

type osExecutor struct{}

func (osExecutor) output(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

func (osExecutor) stream(ctx context.Context, out, errOut io.Writer, name string, args ...string) error {
	command := exec.CommandContext(ctx, name, args...)
	command.Stdout, command.Stderr = out, errOut
	return command.Run()
}

type manager struct {
	platform   string
	home       string
	configBase string
	uid        string
	path       string
	self       string
	commands   executor
	pause      func(context.Context, time.Duration) error
}

// Run manages one native server or receiver service. The service identity is
// derived from role plus the absolute lifecycle .conf path, never a process
// name or port. Docker servers are delegated to the checkout's shell entrypoint.
// Start is idempotent; restart reloads the current config; stop disables the
// scoped service at login while keeping its definition and logs for diagnosis.
func Run(ctx context.Context, role, action, configPath string, follow bool, out, errOut io.Writer) error {
	if out == nil {
		out = io.Discard
	}
	if errOut == nil {
		errOut = io.Discard
	}
	if err := validateRequest(role, action, follow); err != nil {
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("resolve home directory: %w", err)
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return fmt.Errorf("resolve user config directory: %w", err)
	}
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate lifecycle command: %w", err)
	}
	m := manager{platform: runtime.GOOS, home: home, configBase: base, uid: strconv.Itoa(os.Getuid()), path: os.Getenv("PATH"), self: self, commands: osExecutor{}}
	return m.run(ctx, role, action, configPath, follow, out, errOut)
}

func validateRequest(role, action string, follow bool) error {
	if role != "server" && role != "receiver" {
		return errors.New("role must be server or receiver")
	}
	switch action {
	case "start", "stop", "restart", "status", "logs":
	default:
		return errors.New("action must be start, stop, restart, status, or logs")
	}
	if follow && action != "logs" {
		return errors.New("--follow is only valid for logs")
	}
	return nil
}

func (m manager) run(ctx context.Context, role, action, configPath string, follow bool, out, errOut io.Writer) error {
	if err := validateRequest(role, action, follow); err != nil {
		return err
	}
	cfg, err := loadConfig(configPath)
	if err != nil {
		return err
	}
	mode := cfg.value("TEAM_RELAY_SERVER_MODE", "docker")
	if mode != "docker" && mode != "native" {
		return errors.New("TEAM_RELAY_SERVER_MODE must be docker or native")
	}
	if role == "server" && mode == "docker" {
		return m.docker(ctx, action, cfg.path, follow, out, errOut)
	}
	if m.platform != "darwin" && m.platform != "linux" {
		return fmt.Errorf("native background services are unsupported on %s; use macOS launchctl or Linux systemd --user (including WSL with systemd)", m.platform)
	}
	id := serviceID(role, cfg.path)
	layout := layoutFor(m.platform, m.home, m.configBase, id)
	if err := checkEntry(layout); err != nil {
		return err
	}
	if action == "logs" {
		return m.logs(ctx, id, layout, follow, out, errOut)
	}
	if m.platform == "darwin" {
		// Check the domain separately so a missing login session is never
		// misreported as a stopped service. Do not print this environment dump.
		if _, err := m.commands.output(ctx, "launchctl", "print", "gui/"+m.uid); err != nil {
			return errors.New("the current user's launchctl GUI session is unavailable; run from that user's logged-in macOS session")
		}
	}
	state, err := m.inspect(ctx, id)
	if err != nil {
		return err
	}
	if action == "status" {
		fmt.Fprintf(out, "%s: %s\n", id, state.summary)
		return nil
	}
	if action == "stop" {
		if err := m.stop(ctx, id, layout, state); err != nil {
			return err
		}
		fmt.Fprintf(out, "%s: stopped\n", id)
		return nil
	}
	if action == "start" && state.running {
		fmt.Fprintf(out, "%s: already running; use restart to reload configuration\n", id)
		return nil
	}
	// Only activation requires the executable and runtime credentials. Status,
	// stop, and logs continue to work if an installation file went missing.
	spec, err := makeSpec(cfg, role, m.home, m.path)
	if err != nil {
		return err
	}
	if err := validateSpec(spec); err != nil {
		return err
	}
	if err := inheritReceiverEnvironment(&spec, os.Environ()); err != nil {
		return err
	}
	// Validate and publish the replacement definition before stopping a working
	// launchd job. An unwritable/unsafe artifact must not interrupt that process.
	if err := installDefinition(m.platform, spec, layout); err != nil {
		return err
	}
	if m.platform == "darwin" && state.loaded {
		if err := m.unloadLaunchAgent(ctx, id); err != nil {
			return err
		}
	}
	if m.platform == "darwin" {
		if err := m.command(ctx, "launchctl", "enable", "gui/"+m.uid+"/"+id); err != nil {
			return err
		}
		if err := m.command(ctx, "launchctl", "bootstrap", "gui/"+m.uid, layout.entry); err != nil {
			return err
		}
	} else {
		if err := m.command(ctx, "systemctl", "--user", "daemon-reload"); err != nil {
			return err
		}
		if err := m.command(ctx, "systemctl", "--user", "enable", id+".service"); err != nil {
			return err
		}
		verb := "start"
		if action == "restart" {
			verb = "restart"
		}
		if err := m.command(ctx, "systemctl", "--user", verb, id+".service"); err != nil {
			return err
		}
	}
	fmt.Fprintf(out, "%s: %s submitted to the user service manager\n", id, action)
	fmt.Fprintln(out, "Use status to inspect the process and logs to diagnose startup.")
	return nil
}

type serviceState struct {
	loaded  bool
	running bool
	summary string
}

func (m manager) inspect(ctx context.Context, id string) (serviceState, error) {
	if m.platform == "darwin" {
		payload, err := m.commands.output(ctx, "launchctl", "print", "gui/"+m.uid+"/"+id)
		if err != nil {
			message := strings.ToLower(string(payload))
			if strings.Contains(message, "could not find service") || strings.Contains(message, "could not find specified service") {
				return serviceState{summary: "stopped (not registered)"}, nil
			}
			return serviceState{}, fmt.Errorf("could not inspect scoped launchctl service: %w", err)
		}
		// launchctl print includes the entire service environment. Display only
		// process-state fields so Redis credentials cannot appear in status.
		fields := map[string]string{}
		for _, line := range strings.Split(string(payload), "\n") {
			key, value, ok := strings.Cut(strings.TrimSpace(line), " = ")
			if ok && (key == "state" || key == "pid" || key == "last exit code") {
				if _, exists := fields[key]; !exists {
					fields[key] = strings.TrimSpace(value)
				}
			}
		}
		summary := fields["state"]
		if summary == "" {
			summary = "registered"
		}
		for _, key := range []string{"pid", "last exit code"} {
			if fields[key] != "" {
				summary += ", " + key + "=" + fields[key]
			}
		}
		return serviceState{loaded: true, running: fields["state"] == "running", summary: summary}, nil
	}
	payload, err := m.commands.output(ctx, "systemctl", "--user", "show", id+".service", "--property=LoadState,ActiveState,SubState,MainPID,ExecMainStatus", "--no-pager")
	fields := map[string]string{}
	for _, line := range strings.Split(string(payload), "\n") {
		if key, value, ok := strings.Cut(line, "="); ok {
			fields[key] = value
		}
	}
	if fields["LoadState"] == "not-found" {
		return serviceState{summary: "stopped (not registered)"}, nil
	}
	if err != nil || fields["LoadState"] == "" {
		return serviceState{}, errors.New("could not inspect systemd user service; ensure systemd --user is available for the current user")
	}
	summary := fields["ActiveState"] + " (" + fields["SubState"] + ")"
	if fields["MainPID"] != "" && fields["MainPID"] != "0" {
		summary += ", pid=" + fields["MainPID"]
	}
	if fields["ExecMainStatus"] != "" {
		summary += ", last exit code=" + fields["ExecMainStatus"]
	}
	return serviceState{loaded: true, running: fields["ActiveState"] == "active" || fields["ActiveState"] == "activating", summary: summary}, nil
}

func (m manager) stop(ctx context.Context, id string, layout serviceLayout, state serviceState) error {
	if m.platform == "darwin" {
		if state.loaded {
			if err := m.unloadLaunchAgent(ctx, id); err != nil {
				return err
			}
		}
		return removeEntry(layout)
	}
	if state.loaded {
		if err := m.command(ctx, "systemctl", "--user", "disable", "--now", id+".service"); err != nil {
			return err
		}
	}
	if err := removeEntry(layout); err != nil {
		return err
	}
	return m.command(ctx, "systemctl", "--user", "daemon-reload")
}

func (m manager) unloadLaunchAgent(ctx context.Context, id string) error {
	if err := m.command(ctx, "launchctl", "bootout", "gui/"+m.uid+"/"+id); err != nil {
		return err
	}
	// bootout can finish before launchd releases the registration. Immediate
	// bootstrap then fails with a misleading generic I/O error. Wait only for
	// this exact service to disappear, and confirm absence across two polls;
	// never retry an arbitrary bootstrap/permission failure.
	absent := 0
	for attempt := 0; attempt < 60; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		state, err := m.inspect(ctx, id)
		if err != nil {
			return err
		}
		if state.loaded {
			absent = 0
		} else {
			absent++
			if absent == 2 {
				return nil
			}
		}
		if attempt < 59 {
			if err := m.wait(ctx, 250*time.Millisecond); err != nil {
				return err
			}
		}
	}
	return fmt.Errorf("launchctl service %s did not finish deregistering within 15 seconds; inspect status/logs before retrying", id)
}

func (m manager) wait(ctx context.Context, delay time.Duration) error {
	if m.pause != nil {
		return m.pause(ctx, delay)
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (m manager) command(ctx context.Context, name string, args ...string) error {
	// Do not echo captured manager output: it can include service environment
	// values. Arguments here contain only our scoped ID or private file path.
	if _, err := m.commands.output(ctx, name, args...); err != nil {
		return fmt.Errorf("%s %s failed: %w; inspect this service with status/logs", name, strings.Join(args, " "), err)
	}
	return nil
}

func (m manager) logs(ctx context.Context, id string, layout serviceLayout, follow bool, out, errOut io.Writer) error {
	if m.platform == "linux" {
		args := []string{"--user", "--unit", id + ".service", "--no-pager", "--lines=100"}
		if follow {
			args = append(args, "--follow")
		}
		return m.commands.stream(ctx, out, errOut, "journalctl", args...)
	}
	if _, err := os.Lstat(layout.log); errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintln(out, "No service logs yet; start this service first.")
		return nil
	} else if err != nil {
		return err
	}
	if err := privatefs.ValidateRegularFile(layout.log); err != nil {
		return err
	}
	args := []string{"-n", "100"}
	if follow {
		args = append(args, "-F")
	}
	args = append(args, layout.log)
	return m.commands.stream(ctx, out, errOut, "tail", args...)
}

func (m manager) docker(ctx context.Context, action, configPath string, follow bool, out, errOut io.Writer) error {
	candidates := []string{
		filepath.Join(filepath.Dir(configPath), "team-relay"),
		filepath.Join(filepath.Dir(m.self), "..", "team-relay"),
		filepath.Join(filepath.Dir(m.self), "team-relay"),
	}
	for _, candidate := range candidates {
		candidate = filepath.Clean(candidate)
		if err := validateExecutable(candidate); err != nil {
			continue
		}
		// The native command has the same basename. Delegate only to an actual
		// script so an unusual layout cannot recursively spawn this binary.
		file, err := os.Open(candidate)
		if err != nil {
			continue
		}
		var prefix [2]byte
		_, readErr := io.ReadFull(file, prefix[:])
		_ = file.Close()
		if readErr != nil || string(prefix[:]) != "#!" {
			continue
		}
		args := []string{"server", action, "--config", configPath}
		if follow {
			args = append(args, "--follow")
		}
		return m.commands.stream(ctx, out, errOut, candidate, args...)
	}
	return errors.New("Docker server mode requires the checkout's ./team-relay entrypoint; run ./team-relay server " + action + " --config <path>")
}
