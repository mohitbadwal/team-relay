// Package desktop implements the native app's local JSON bridge. It does not
// listen on a network port and never accepts executable names from peer input.
package desktop

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/mohitbadwal/team-relay/internal/client"
	"github.com/mohitbadwal/team-relay/internal/config"
	"github.com/mohitbadwal/team-relay/internal/lifecycle"
	"github.com/mohitbadwal/team-relay/internal/privatefs"
)

type app struct {
	serviceConfig string
	self          string
	settings      lifecycle.ReceiverSettings
}

// ErrReported asks the CLI to exit unsuccessfully without appending text after
// the JSON error already delivered to the desktop (or headless installer).
var ErrReported = errors.New("desktop action failed")

// Run is a private implementation interface for the native app. Invitations
// arrive on stdin, never through process arguments, URLs or environment vars.
func Run(args []string, in io.Reader, out io.Writer) error {
	flags := flag.NewFlagSet("app", flag.ContinueOnError)
	serviceConfig := flags.String("service-config", "", "private service settings path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() < 1 {
		return errors.New("app requires an action")
	}
	settings, err := lifecycle.ResolveReceiver(*serviceConfig)
	if err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	a := app{*serviceConfig, self, settings}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	result, err := a.action(ctx, flags.Args(), in)
	if err != nil {
		if encodeErr := json.NewEncoder(out).Encode(map[string]any{"ok": false, "error": err.Error()}); encodeErr != nil {
			return encodeErr
		}
		return ErrReported
	}
	return json.NewEncoder(out).Encode(map[string]any{"ok": true, "data": result})
}

func (a app) action(ctx context.Context, args []string, in io.Reader) (any, error) {
	switch args[0] {
	case "info":
		return a.info()
	case "join":
		return a.join(ctx, in)
	case "finish":
		return a.finish(ctx)
	case "status":
		var output bytes.Buffer
		err := lifecycle.Run(ctx, "receiver", "status", a.serviceConfig, false, &output, &output)
		own := err == nil && runningSummary(output.String())
		return map[string]any{"service": strings.TrimSpace(output.String()), "running": own && a.healthy(ctx), "detail": errorText(err)}, nil
	case "start", "restart", "stop", "logs":
		if args[0] == "start" || args[0] == "restart" {
			if err := a.checkConnectionOwner(ctx); err != nil {
				return nil, err
			}
		}
		var output bytes.Buffer
		err := lifecycle.Run(ctx, "receiver", args[0], a.serviceConfig, false, &output, &output)
		if err != nil {
			return nil, err
		}
		return map[string]string{"text": output.String()}, nil
	case "doctor", "pending", "inspect", "approve", "deny", "approval-grants", "revoke-approval-grant":
		cliArgs := []string{"--config", a.settings.ConfigPath, "--state-dir", a.settings.StateDir, "--control-address", a.settings.ControlAddress}
		payload, err := command(ctx, nil, a.settings.Executable, append(cliArgs, args...)...)
		if err != nil {
			return nil, err
		}
		var value any
		if json.Unmarshal(payload, &value) == nil {
			return value, nil
		}
		return map[string]string{"text": string(payload)}, nil
	case "teammates":
		cfg, err := config.Load(a.settings.ConfigPath)
		if err != nil {
			return nil, err
		}
		token, err := cfg.DeviceToken()
		if err != nil {
			return nil, err
		}
		relay, err := client.New(cfg.Relay.URL, token, nil)
		if err != nil {
			return nil, err
		}
		return relay.ListAgents(ctx, client.AgentQuery{Limit: 50})
	default:
		return nil, errors.New("unknown desktop action")
	}
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func (a app) info() (any, error) {
	hostname, _ := os.Hostname()
	name := ""
	if current, err := user.Current(); err == nil {
		name = current.Name
		if name == "" {
			name = current.Username
		}
	}
	runtimes := []map[string]string{}
	for _, id := range []string{"claude-code", "codex"} {
		path, _ := runtimePath(id)
		runtimes = append(runtimes, map[string]string{"id": id, "executable": path})
	}
	result := map[string]any{"name": name, "device": hostname, "runtimes": runtimes, "enrolled": false}
	cfg, err := config.Load(a.settings.ConfigPath)
	if errors.Is(err, os.ErrNotExist) {
		return result, nil
	}
	if err != nil {
		return nil, err
	}
	profile := cfg.Profiles[cfg.Receiver.Profile]
	result["enrolled"], result["server"], result["runtime"] = true, cfg.Relay.URL, profile.Runtime
	result["work_dir"], result["permission"], result["model"] = profile.WorkDir, profile.Policy.Mode, profile.Model
	return result, nil
}

type joinInput struct {
	Server     string `json:"server"`
	Invite     string `json:"invite"`
	Name       string `json:"name"`
	Runtime    string `json:"runtime"`
	WorkDir    string `json:"work_dir"`
	Permission string `json:"permission"`
	Model      string `json:"model"`
	ShareFiles bool   `json:"share_files"`
}

func validateJoin(input *joinInput) error {
	input.Server, input.Invite = strings.TrimSpace(input.Server), strings.TrimSpace(input.Invite)
	if input.Server == "" || input.Invite == "" || strings.TrimSpace(input.Name) == "" {
		return errors.New("enter the relay address, invitation token and your name")
	}
	if input.Runtime != "claude-code" && input.Runtime != "codex" {
		return errors.New("choose Claude Code or Codex")
	}
	if input.Permission != "read_only" && input.Permission != "guarded_write" {
		return errors.New("choose a tool permission level")
	}
	if input.Runtime == "codex" && input.Permission == "read_only" {
		return errors.New("Codex does not support the shell-disabled read-only profile; choose Claude Code for read-only, or explicitly select guarded tools")
	}
	if !filepath.IsAbs(input.WorkDir) {
		return errors.New("choose an absolute working folder")
	}
	info, err := os.Stat(input.WorkDir)
	if err != nil || !info.IsDir() {
		return errors.New("the working folder does not exist; choose a folder on this machine")
	}
	if _, err := client.New(input.Server, "validation-only", nil); err != nil {
		return err
	}
	return nil
}

func (a app) join(ctx context.Context, in io.Reader) (any, error) {
	var input joinInput
	decoder := json.NewDecoder(io.LimitReader(in, 16385))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return nil, errors.New("invalid setup form")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, errors.New("setup accepts one form only")
	}
	if err := validateJoin(&input); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(a.settings.ConfigPath); err == nil {
		return nil, errors.New("this machine is already enrolled; use Finish setup instead of spending another invitation")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	path, err := runtimePath(input.Runtime)
	if err != nil {
		return nil, err
	}
	if err := a.checkConnectionOwner(ctx); err != nil {
		return nil, err
	}
	// Preflight MCP conflicts before using the single-use invitation.
	if err := a.checkMCP(ctx, input.Runtime); err != nil {
		return nil, err
	}
	args := []string{"setup", "--server", input.Server, "--invite-stdin", "--name", input.Name,
		"--runtime", input.Runtime, "--executable", path, "--work-dir", input.WorkDir,
		"--permission", input.Permission, "--config", a.settings.ConfigPath, "--model", input.Model,
		"--workspace", "workspace=" + input.WorkDir}
	if input.ShareFiles {
		args = append(args, "--outbound-attachments")
	}
	if _, err := command(ctx, strings.NewReader(input.Invite), a.self, args...); err != nil {
		return nil, errors.New(strings.ReplaceAll(err.Error(), input.Invite, "[invitation hidden]"))
	}
	return a.finish(ctx)
}

func (a app) finish(ctx context.Context) (any, error) {
	if err := a.checkConnectionOwner(ctx); err != nil {
		return nil, err
	}
	cfg, err := config.Load(a.settings.ConfigPath)
	if err != nil {
		return nil, err
	}
	id := cfg.Profiles[cfg.Receiver.Profile].Runtime
	if err := a.installIntegration(ctx, id); err != nil {
		return nil, fmt.Errorf("enrollment saved. Agent integration needs attention: %w. Use Finish setup to retry without a new invitation", err)
	}
	if _, err := command(ctx, nil, a.settings.Executable, "--config", a.settings.ConfigPath, "--state-dir", a.settings.StateDir, "doctor"); err != nil {
		return nil, fmt.Errorf("MCP and skills installed. The receiving agent is not ready: %w. Fix this, then choose Finish setup", err)
	}
	var output bytes.Buffer
	if err := lifecycle.Run(ctx, "receiver", "start", a.serviceConfig, false, &output, &output); err != nil {
		return nil, fmt.Errorf("integration installed; could not start your connection: %w", err)
	}
	for attempt := 0; attempt < 20; attempt++ {
		if a.healthy(ctx) {
			return map[string]any{"ready": true, "message": "MCP and skills installed. Your connection is running. Start a new chat in your agent to load Team Relay."}, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	return nil, errors.New("MCP and skills installed, but the connection did not become ready. Open Logs or Check setup in the menu, then retry")
}

func runningSummary(value string) bool {
	_, summary, ok := strings.Cut(strings.TrimSpace(value), ": ")
	return ok && (strings.HasPrefix(summary, "running") || strings.HasPrefix(summary, "active (") || strings.HasPrefix(summary, "activating ("))
}

func (a app) checkConnectionOwner(ctx context.Context) error {
	var status bytes.Buffer
	if err := lifecycle.Run(ctx, "receiver", "status", a.serviceConfig, false, &status, &status); err != nil {
		return err
	}
	if runningSummary(status.String()) {
		return nil
	}
	connection, err := net.DialTimeout("tcp", a.settings.ControlAddress, time.Second)
	if err == nil {
		connection.Close()
		return errors.New("another installation already uses the local connection port. Stop its connection from the old installation before starting this one; it has not been interrupted")
	}
	return nil
}

func (a app) healthy(ctx context.Context) bool {
	token, err := privatefs.ReadFile(filepath.Join(a.settings.StateDir, "control.token"))
	if err != nil {
		return false
	}
	req, err := http.NewRequestWithContext(ctx, "GET", "http://"+a.settings.ControlAddress+"/health", nil)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	local := http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer local.CloseIdleConnections()
	response, err := local.Do(req)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	return response.StatusCode == http.StatusOK
}

func command(ctx context.Context, in io.Reader, executable string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Stdin = in
	// Ignore stale relay overrides: desktop actions must manage the selected
	// enrollment, never a token or relay inherited from a developer's shell.
	cmd.Env = desktopEnvironment()
	payload, err := cmd.CombinedOutput()
	if err != nil {
		if len(bytes.TrimSpace(payload)) == 0 {
			return nil, fmt.Errorf("could not run %s: %w", filepath.Base(executable), err)
		}
		return nil, fmt.Errorf("%s: %s", filepath.Base(executable), strings.TrimSpace(string(payload)))
	}
	return payload, nil
}

func desktopEnvironment() []string {
	result := []string{}
	for _, value := range os.Environ() {
		key, _, _ := strings.Cut(value, "=")
		if !strings.HasPrefix(key, "TEAM_RELAY_") {
			result = append(result, value)
		}
	}
	return result
}
