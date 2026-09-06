package desktop

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"time"

	mcpclient "github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"
	relayruntime "github.com/mohitbadwal/team-relay/internal/runtime"

	"github.com/mohitbadwal/team-relay/skills"
)

const mcpName = "team-relay"

func runtimePath(id string) (string, error) {
	name := "claude"
	if id == "codex" {
		name = "codex"
	} else if id != "claude-code" {
		return "", errors.New("automatic integration supports Claude Code and Codex; external adapters use the headless setup")
	}
	if path, err := exec.LookPath(name); err == nil {
		return filepath.Abs(path)
	}
	home, _ := os.UserHomeDir()
	candidates := []string{filepath.Join(home, ".local", "bin", name), "/opt/homebrew/bin/" + name, "/usr/local/bin/" + name}
	if id == "codex" && runtime.GOOS == "darwin" {
		candidates = append(candidates, "/Applications/ChatGPT.app/Contents/Resources/codex", "/Applications/Codex.app/Contents/Resources/codex")
	}
	for _, path := range candidates {
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() && info.Mode()&0111 != 0 {
			return path, nil
		}
	}
	return "", fmt.Errorf("%s is not installed or not on PATH. Install and sign into that agent first, then reopen Team Relay", name)
}

type mcpRegistration struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Type    string            `json:"type"`
	URL     string            `json:"url"`
	Env     map[string]string `json:"env"`
	Enabled *bool             `json:"enabled"`
}

func (a app) desiredMCP() mcpRegistration {
	suffix := ""
	if runtime.GOOS == "windows" {
		suffix = ".exe"
	}
	directory := filepath.Dir(a.self)
	if a.settings.Executable != "" {
		directory = filepath.Dir(a.settings.Executable)
	}
	return mcpRegistration{Command: filepath.Join(directory, "team-relay-mcp"+suffix), Args: []string{"--config", a.settings.ConfigPath}}
}

// Read only this entry; never print a client's full configuration or other MCP
// credentials. Unknown/invalid configuration errors are not treated as absent.
func existingMCP(ctx context.Context, id string) (*mcpRegistration, error) {
	if id == "claude-code" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		path := filepath.Join(home, ".claude.json")
		if dir := os.Getenv("CLAUDE_CONFIG_DIR"); dir != "" {
			path = filepath.Join(dir, ".claude.json")
		}
		payload, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		if err != nil {
			return nil, errors.New("cannot read Claude's user configuration")
		}
		var cfg struct {
			Servers map[string]mcpRegistration `json:"mcpServers"`
		}
		if json.Unmarshal(payload, &cfg) != nil {
			return nil, errors.New("Claude's user configuration is invalid; repair it before installing Team Relay")
		}
		entry, ok := cfg.Servers[mcpName]
		if !ok {
			return nil, nil
		}
		return &entry, nil
	}
	path, err := runtimePath(id)
	if err != nil {
		return nil, err
	}
	payload, err := command(ctx, nil, path, "mcp", "get", mcpName, "--json")
	if err != nil {
		if strings.Contains(err.Error(), "No MCP server named '"+mcpName+"' found") {
			return nil, nil
		}
		return nil, errors.New("cannot inspect Codex's MCP configuration; run Codex once and resolve its configuration error, then retry")
	}
	var cfg struct {
		Transport mcpRegistration `json:"transport"`
		Enabled   *bool           `json:"enabled"`
	}
	if json.Unmarshal(payload, &cfg) != nil {
		return nil, errors.New("Codex returned an unrecognized MCP configuration")
	}
	cfg.Transport.Enabled = cfg.Enabled
	return &cfg.Transport, nil
}

func (a app) checkMCP(ctx context.Context, id string) error {
	existing, err := existingMCP(ctx, id)
	if err != nil {
		return err
	}
	if existing == nil {
		return nil
	}
	desired := a.desiredMCP()
	if existing.URL != "" || existing.Command != desired.Command || !reflect.DeepEqual(existing.Args, desired.Args) || len(existing.Env) != 0 || (existing.Enabled != nil && !*existing.Enabled) {
		return errors.New("an existing team-relay MCP points to a different installation or is disabled. It was not overwritten. Remove or rename that entry in your agent's MCP settings, then choose Finish setup (or Connect for a new enrollment)")
	}
	return nil
}

func (a app) installIntegration(ctx context.Context, id string) error {
	path, err := runtimePath(id)
	if err != nil {
		return err
	}
	if err := a.checkMCP(ctx, id); err != nil {
		return err
	}
	desired := a.desiredMCP()
	if info, err := os.Stat(desired.Command); err != nil || !info.Mode().IsRegular() {
		return errors.New("Team Relay MCP executable is missing; rerun the installer")
	}
	entry, err := existingMCP(ctx, id)
	if err != nil {
		return err
	}
	if entry == nil {
		args := []string{"mcp", "add"}
		if id == "claude-code" {
			args = append(args, "--scope", "user", "--transport", "stdio")
		}
		args = append(args, mcpName, "--", desired.Command)
		args = append(args, desired.Args...)
		if _, err := command(ctx, nil, path, args...); err != nil {
			return err
		}
	}
	if err := a.checkMCP(ctx, id); err != nil {
		return err
	}
	entry, err = existingMCP(ctx, id)
	if err != nil {
		return err
	}
	if entry == nil {
		return errors.New("the agent did not save its MCP entry")
	}
	if err := installSkills(id); err != nil {
		return err
	}
	return a.checkMCPHandshake(ctx)
}

// Don't report setup success merely because a configuration file was written.
// Start the exact MCP command and verify its real tool inventory. This does
// not send a prompt, invoke a model or execute any teammate request.
func (a app) checkMCPHandshake(parent context.Context) error {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	desired := a.desiredMCP()
	stdio := transport.NewStdioWithOptions(desired.Command, nil, desired.Args,
		transport.WithCommandFunc(func(ctx context.Context, name string, env []string, args []string) (*exec.Cmd, error) {
			cmd := exec.CommandContext(ctx, name, args...)
			cmd.Env = desktopEnvironment()
			return cmd, nil
		}))
	connection := mcpclient.NewClient(stdio)
	if err := connection.Start(ctx); err != nil {
		return errors.New("the Team Relay MCP could not start")
	}
	defer connection.Close()
	var diagnostic diagnosticBuffer
	if stderr, ok := mcpclient.GetStderr(connection); ok {
		go io.Copy(&diagnostic, stderr)
	}
	request := mcp.InitializeRequest{}
	request.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	request.Params.ClientInfo = mcp.Implementation{Name: "team-relay-setup", Version: "1"}
	if _, err := connection.Initialize(ctx, request); err != nil {
		return fmt.Errorf("the Team Relay MCP could not initialize: %s (%v)", diagnostic.summary(), err)
	}
	result, err := connection.ListTools(ctx, mcp.ListToolsRequest{})
	if err != nil {
		return errors.New("could not read Team Relay's tools")
	}
	required := map[string]bool{"find_teammates": false, "request_teammate_help": false, "get_request_status": false}
	for _, tool := range result.Tools {
		if _, ok := required[tool.Name]; ok {
			required[tool.Name] = true
		}
	}
	for name, present := range required {
		if !present {
			return fmt.Errorf("the MCP is missing %s; rerun the installer", name)
		}
	}
	return nil
}

type diagnosticBuffer struct {
	sync.Mutex
	data []byte
}

func (b *diagnosticBuffer) Write(value []byte) (int, error) {
	b.Lock()
	defer b.Unlock()
	b.data = append(b.data, value...)
	if len(b.data) > 4096 {
		b.data = b.data[len(b.data)-4096:]
	}
	return len(value), nil
}
func (b *diagnosticBuffer) summary() string {
	b.Lock()
	defer b.Unlock()
	return relayruntime.SafeSummary(string(b.data))
}

func installSkills(id string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	root := filepath.Join(home, ".claude", "skills")
	if id == "codex" {
		root = filepath.Join(home, ".codex", "skills")
		if configured := os.Getenv("CODEX_HOME"); configured != "" {
			root = filepath.Join(configured, "skills")
		}
	} else if configured := os.Getenv("CLAUDE_CONFIG_DIR"); configured != "" {
		root = filepath.Join(configured, "skills")
	}
	for _, role := range []string{"requester", "recipient"} {
		dir := filepath.Join(root, "team-relay-"+role)
		if info, err := os.Lstat(dir); err == nil && (!info.IsDir() || info.Mode()&os.ModeSymlink != 0) {
			return errors.New("a Team Relay skill directory is a symlink or non-directory; it was left untouched")
		}
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
		path := filepath.Join(dir, "SKILL.md")
		if info, err := os.Lstat(path); err == nil {
			if !info.Mode().IsRegular() || info.Size() == 0 {
				return errors.New("an existing Team Relay skill is empty or not a regular file; it was left untouched")
			}
			continue // Preserve customized instructions; no opt-in prompt.
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		payload, err := skills.Files.ReadFile(role + "/SKILL.md")
		if err != nil {
			return err
		}
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
		if err != nil {
			return err
		}
		_, writeErr := file.Write(payload)
		closeErr := file.Close()
		if writeErr != nil {
			return writeErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}
