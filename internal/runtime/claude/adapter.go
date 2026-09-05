// Package claude implements the recipient runtime adapter for Claude Code.
package claude

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mohitbadwal/team-relay/internal/privatefs"
	relayruntime "github.com/mohitbadwal/team-relay/internal/runtime"
)

const RuntimeID = "claude-code"

const (
	recipientRunEnvironment = "AGENT_RELAY_RECIPIENT_RUN"
	maxClaudeConfigBytes    = 16 << 20
	temporaryNameAttempts   = 100
)

type Config struct {
	Executable           string
	PrefixArgs           []string
	WorkDir              string
	Model                string
	EnvironmentAllowlist []string
	Policy               relayruntime.Policy
	Timeout              time.Duration
}

type Adapter struct {
	executable           string
	prefixArgs           []string
	workDir              string
	model                string
	environmentAllowlist []string
	policy               relayruntime.Policy
	timeout              time.Duration

	mcpOnce    sync.Once
	mcpServers map[string]json.RawMessage
	mcpErr     error
}

func New(config Config) (*Adapter, error) {
	if err := validateClaudePrefixArgs(config.PrefixArgs); err != nil {
		return nil, err
	}
	workDir, err := relayruntime.ValidateWorkDir(config.WorkDir)
	if err != nil {
		return nil, err
	}
	policy, err := relayruntime.ValidatePolicy(config.Policy)
	if err != nil {
		return nil, err
	}
	if config.Executable == "" {
		config.Executable = "claude"
	}
	if config.Timeout <= 0 {
		config.Timeout = 30 * time.Minute
	}
	adapter := &Adapter{
		executable:           config.Executable,
		prefixArgs:           append([]string(nil), config.PrefixArgs...),
		workDir:              workDir,
		model:                config.Model,
		environmentAllowlist: append([]string(nil), config.EnvironmentAllowlist...),
		policy:               policy,
		timeout:              config.Timeout,
	}
	if err := validateClaudePolicy(adapter.policy, adapter.capabilities()); err != nil {
		return nil, err
	}
	return adapter, nil
}

func validateClaudePrefixArgs(args []string) error {
	for _, argument := range args {
		name, _, _ := strings.Cut(strings.TrimSpace(argument), "=")
		if name == "--mcp-config" || name == "--strict-mcp-config" {
			return errors.New("Claude prefix arguments cannot override adapter-owned MCP configuration")
		}
	}
	return nil
}

func (a *Adapter) ID() string { return RuntimeID }

func (a *Adapter) ConfiguredPolicy() relayruntime.Policy { return a.policy }

func (a *Adapter) WorkDirFingerprint() string {
	return relayruntime.WorkDirFingerprint(a.workDir)
}

func (a *Adapter) ApprovalFingerprint() (string, error) {
	servers, err := a.frozenRecipientMCPServers()
	if err != nil {
		return "", fmt.Errorf("freeze Claude Code MCP inventory: %w", err)
	}
	return relayruntime.ApprovalConfigFingerprint(struct {
		Version              int                        `json:"version"`
		RuntimeID            string                     `json:"runtime_id"`
		Executable           string                     `json:"executable"`
		PrefixArgs           []string                   `json:"prefix_args"`
		WorkDir              string                     `json:"work_dir"`
		Model                string                     `json:"model"`
		EnvironmentAllowlist []string                   `json:"environment_allowlist"`
		Policy               relayruntime.Policy        `json:"policy"`
		Timeout              time.Duration              `json:"timeout"`
		MCPServers           map[string]json.RawMessage `json:"mcp_servers"`
	}{
		Version: 1, RuntimeID: RuntimeID, Executable: a.executable,
		PrefixArgs: append([]string(nil), a.prefixArgs...), WorkDir: a.workDir,
		Model: a.model, EnvironmentAllowlist: relayruntime.CanonicalEnvironmentAllowlist(a.environmentAllowlist),
		Policy: a.policy, Timeout: a.timeout, MCPServers: servers,
	})
}

func (a *Adapter) capabilities() relayruntime.Capabilities {
	return relayruntime.Capabilities{
		RuntimeID:              RuntimeID,
		DisplayName:            "Claude Code",
		SupportsResume:         true,
		SupportsStreaming:      true,
		SupportsModelSelection: true,
		PreservesLocalContext:  true,
		LoadsLocalMCPs:         a.policy.AllowMCPs,
		Policy: relayruntime.PolicyCapabilities{
			ReadOnly:               relayruntime.EnforcementToolLevel,
			GuardedWrite:           relayruntime.EnforcementBestEffort,
			FilesystemIsolation:    relayruntime.EnforcementBestEffort,
			NetworkIsolation:       relayruntime.EnforcementBestEffort,
			ShellControl:           relayruntime.EnforcementToolLevel,
			MCPControl:             relayruntime.EnforcementToolLevel,
			DestructiveCommandDeny: relayruntime.EnforcementBestEffort,
		},
	}
}

func (a *Adapter) Probe(ctx context.Context) (relayruntime.Capabilities, error) {
	capabilities := a.capabilities()
	if err := validateClaudePolicy(a.policy, capabilities); err != nil {
		capabilities.Detail = err.Error()
		return capabilities, err
	}
	version, err := relayruntime.ProbeCommand(ctx, a.executable, a.prefixArgs, a.environmentAllowlist, "--version")
	if err != nil {
		capabilities.Detail = err.Error()
		if errors.Is(err, relayruntime.ErrUnavailable) {
			return capabilities, nil
		}
		return capabilities, err
	}
	capabilities.Available = true
	capabilities.Version = version
	return capabilities, nil
}

func (a *Adapter) Run(ctx context.Context, request relayruntime.RunRequest, sink relayruntime.EventSink) (relayruntime.RunResult, error) {
	if err := relayruntime.ValidateRunRequest(request); err != nil {
		return relayruntime.RunResult{}, err
	}
	effective, err := relayruntime.EffectivePolicy(a.policy, request.RequestedPolicy)
	if err != nil {
		return relayruntime.RunResult{}, err
	}
	if err := validateClaudePolicy(effective, a.capabilities()); err != nil {
		return relayruntime.RunResult{}, err
	}
	request = relayruntime.ConstrainRequest(request, effective)

	runCtx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()
	mcpConfigPath, cleanupMCPConfig, err := a.prepareMCPConfig(effective)
	if err != nil {
		return relayruntime.RunResult{}, fmt.Errorf("prepare Claude Code MCP policy: %w", err)
	}
	defer cleanupMCPConfig()
	args, session := a.commandArgs(request, effective, mcpConfigPath)
	if request.Session != nil && session == nil {
		if err := relayruntime.Emit(runCtx, sink, relayruntime.Event{Type: relayruntime.EventWarning, Summary: "Previous session was not resumed because its runtime, directory, or permission profile changed"}); err != nil {
			return relayruntime.RunResult{}, err
		}
	}
	if err := relayruntime.Emit(runCtx, sink, relayruntime.Event{Type: relayruntime.EventStarting, Summary: "Starting Claude Code"}); err != nil {
		return relayruntime.RunResult{}, err
	}

	prompt := relayruntime.BuildPrompt(request, relayruntime.RecipientResponseContract) + relayruntime.PolicyInstructions(effective)
	result := relayruntime.RunResult{EffectivePolicy: effective, Session: session}
	var providerError bool
	toolNames := make(map[string]string)
	err = relayruntime.ExecuteJSONLines(runCtx, relayruntime.CommandSpec{
		Executable:           a.executable,
		Args:                 args,
		Directory:            a.workDir,
		Stdin:                prompt,
		EnvironmentAllowlist: a.environmentAllowlist,
		Environment:          map[string]string{recipientRunEnvironment: "1"},
	}, func(raw json.RawMessage) error {
		var event claudeEvent
		if err := json.Unmarshal(raw, &event); err != nil {
			return nil
		}
		if event.SessionID != "" && (result.Session == nil || result.Session.OpaqueID != event.SessionID) {
			result.Session = a.sessionRef(event.SessionID, effective)
			if err := relayruntime.Emit(runCtx, sink, relayruntime.Event{Type: relayruntime.EventSession, Summary: "Claude Code session connected", Session: result.Session}); err != nil {
				return err
			}
		}
		switch event.Type {
		case "assistant":
			for _, content := range event.Message.Content {
				switch content.Type {
				case "text":
					if strings.TrimSpace(content.Text) != "" {
						if len(content.Text) > relayruntime.MaxFinalTextBytes {
							return fmt.Errorf("Claude Code answer exceeds local size limit")
						}
						result.FinalText = content.Text
						if err := relayruntime.Emit(runCtx, sink, relayruntime.Event{Type: relayruntime.EventProgress, Summary: "Claude Code produced response text"}); err != nil {
							return err
						}
					}
				case "tool_use":
					name := relayruntime.SafeSummary(content.Name)
					if content.ID != "" {
						toolNames[content.ID] = name
					}
					summary := toolSummary(content.Name)
					if err := relayruntime.Emit(runCtx, sink, relayruntime.Event{Type: relayruntime.EventToolStarted, Tool: name, Summary: summary}); err != nil {
						return err
					}
				}
			}
		case "user":
			for _, content := range event.Message.Content {
				if content.Type != "tool_result" {
					continue
				}
				name := toolNames[content.ToolUseID]
				if name == "" {
					name = "Tool"
				}
				status := "completed"
				if content.IsError {
					status = "failed"
				}
				if err := relayruntime.Emit(runCtx, sink, relayruntime.Event{Type: relayruntime.EventToolFinished, Tool: name, Summary: name + " " + status}); err != nil {
					return err
				}
			}
		case "result":
			if strings.TrimSpace(event.Result) != "" {
				if len(event.Result) > relayruntime.MaxFinalTextBytes {
					return fmt.Errorf("Claude Code answer exceeds local size limit")
				}
				result.FinalText = event.Result
			}
			providerError = event.IsError
			result.Usage.CostUSD = event.TotalCostUSD
			result.Usage.Duration = time.Duration(event.DurationMS) * time.Millisecond
			if err := relayruntime.Emit(runCtx, sink, relayruntime.Event{Type: relayruntime.EventFinishing, Summary: "Claude Code finished; returning result", Usage: &result.Usage}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return relayruntime.RunResult{}, fmt.Errorf("Claude Code: %w", err)
	}
	if providerError {
		return relayruntime.RunResult{}, fmt.Errorf("Claude Code reported an error")
	}
	if strings.TrimSpace(result.FinalText) == "" {
		return relayruntime.RunResult{}, fmt.Errorf("Claude Code: %w", relayruntime.ErrNoFinalAnswer)
	}
	if err := relayruntime.Emit(runCtx, sink, relayruntime.Event{Type: relayruntime.EventCompleted, Summary: "Claude Code response ready", Session: result.Session, Usage: &result.Usage}); err != nil {
		return relayruntime.RunResult{}, err
	}
	return result, nil
}

func validateClaudePolicy(policy relayruntime.Policy, capabilities relayruntime.Capabilities) error {
	if err := relayruntime.ValidatePolicySupport(capabilities, policy); err != nil {
		return err
	}
	// Claude Code can omit Bash entirely, but it cannot make Bash read-only.
	// Allowing Bash while merely denying Edit/Write would still permit shell
	// redirection and arbitrary programs to mutate the filesystem.
	if !policy.AllowWrites && policy.AllowShell {
		return fmt.Errorf("%w: runtime %q cannot allow Bash while denying writes; set allow_shell=false or allow_writes=true", relayruntime.ErrUnsupportedPolicy, RuntimeID)
	}
	return nil
}

func (a *Adapter) commandArgs(request relayruntime.RunRequest, policy relayruntime.Policy, mcpConfigPath string) ([]string, *relayruntime.SessionRef) {
	args := append([]string(nil), a.prefixArgs...)
	args = append(args, "-p", "--output-format", "stream-json", "--verbose")
	// Keep normal memories, skills, and settings, but prevent a
	// repository/user/plugin SessionStart or tool hook from executing outside
	// the provider tool permission boundary. Managed hooks remain controlled by
	// the recipient's organization and cannot be overridden by CLI settings.
	args = append(args, "--settings", `{"disableAllHooks":true}`)
	if a.model != "" {
		args = append(args, "--model", a.model)
	}
	if policy.Mode == relayruntime.PolicyReadOnly {
		allowed := []string{"Read", "Glob", "Grep"}
		if policy.AllowNetwork {
			allowed = append(allowed, "WebFetch", "WebSearch")
		}
		args = append(args, "--permission-mode", "dontAsk", "--tools", strings.Join(allowed, ","))
	} else {
		args = append(args, "--permission-mode", "auto", "--tools", "default")
		denied := claudeDeniedTools(policy)
		if len(denied) > 0 {
			args = append(args, "--disallowedTools", strings.Join(denied, ","))
		}
	}
	// Strict mode is unconditional: repository .mcp.json files, plugins, and
	// other implicit sources must never add a server after recipient policy has
	// been resolved. The adapter-owned file contains only recipient-private
	// user/local entries that survived filtering, or an empty server map when
	// MCP access is disabled. Its potentially credential-bearing JSON never
	// appears in process arguments.
	args = append(args, "--strict-mcp-config", "--mcp-config", mcpConfigPath)
	// Appending preserves normal CLAUDE.md, auto-memory, skills, settings, and
	// other non-MCP local context.
	args = append(args, "--append-system-prompt", relayruntime.RecipientResponseContract)
	for _, path := range additionalDirectories(request) {
		args = append(args, "--add-dir", path)
	}
	var session *relayruntime.SessionRef
	if relayruntime.CompatibleSession(request.Session, RuntimeID, policy, a.workDir) {
		session = request.Session
		args = append(args, "--resume", session.OpaqueID)
	}
	return args, session
}

type claudeConfig struct {
	MCPServers map[string]json.RawMessage    `json:"mcpServers"`
	Projects   map[string]claudeProjectState `json:"projects"`
}

type claudeProjectState struct {
	MCPServers         map[string]json.RawMessage `json:"mcpServers"`
	DisabledMCPServers []string                   `json:"disabledMcpServers"`
}

type claudeMCPFile struct {
	MCPServers map[string]json.RawMessage `json:"mcpServers"`
}

type claudeMCPIdentity struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
	URL     string   `json:"url"`
}

func (a *Adapter) prepareMCPConfig(policy relayruntime.Policy) (string, func(), error) {
	configured, err := a.frozenRecipientMCPServers()
	if err != nil {
		return "", func() {}, err
	}
	servers := make(map[string]json.RawMessage)
	if policy.AllowMCPs {
		servers = configured
	}
	payload, err := json.Marshal(claudeMCPFile{MCPServers: servers})
	if err != nil {
		return "", func() {}, fmt.Errorf("encode private MCP configuration: %w", err)
	}
	return writePrivateMCPConfig(payload)
}

func (a *Adapter) frozenRecipientMCPServers() (map[string]json.RawMessage, error) {
	a.mcpOnce.Do(func() {
		// Preserve the existing guarantee that an MCP-disabled profile does not
		// read Claude state at all. Its effective inventory is permanently empty.
		if !a.policy.AllowMCPs {
			a.mcpServers = map[string]json.RawMessage{}
			return
		}
		a.mcpServers, a.mcpErr = a.recipientMCPServers()
		if a.mcpErr == nil {
			a.mcpServers = cloneMCPServers(a.mcpServers)
		}
	})
	if a.mcpErr != nil {
		return nil, a.mcpErr
	}
	return cloneMCPServers(a.mcpServers), nil
}

func (a *Adapter) recipientMCPServers() (map[string]json.RawMessage, error) {
	path, err := claudeConfigPath()
	if err != nil {
		return nil, err
	}
	payload, err := readBoundedRegularFile(path, maxClaudeConfigBytes)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]json.RawMessage{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read recipient Claude configuration: %w", err)
	}
	var configured claudeConfig
	if err := json.Unmarshal(payload, &configured); err != nil {
		return nil, fmt.Errorf("decode recipient Claude configuration: %w", err)
	}

	servers := cloneMCPServers(configured.MCPServers)
	project := matchingClaudeProject(configured.Projects, a.workDir)
	for name, server := range project.MCPServers {
		servers[name] = append(json.RawMessage(nil), server...)
	}
	for _, name := range project.DisabledMCPServers {
		delete(servers, name)
	}
	for name, server := range servers {
		blocked, err := isTeamRelayMCPServer(name, server)
		if err != nil {
			return nil, err
		}
		if blocked {
			delete(servers, name)
		}
	}
	return servers, nil
}

func claudeConfigPath() (string, error) {
	if directory := strings.TrimSpace(os.Getenv("CLAUDE_CONFIG_DIR")); directory != "" {
		absolute, err := filepath.Abs(directory)
		if err != nil {
			return "", fmt.Errorf("resolve CLAUDE_CONFIG_DIR: %w", err)
		}
		return filepath.Join(absolute, ".claude.json"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve Claude configuration home: %w", err)
	}
	return filepath.Join(home, ".claude.json"), nil
}

func readBoundedRegularFile(path string, limit int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, errors.New("recipient Claude configuration is not a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		_ = file.Close()
		return nil, errors.New("recipient Claude configuration changed while it was opened")
	}
	payload, readErr := io.ReadAll(io.LimitReader(file, limit+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return nil, errors.Join(readErr, closeErr)
	}
	if int64(len(payload)) > limit {
		return nil, fmt.Errorf("recipient Claude configuration exceeds %d bytes", limit)
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) {
		return nil, errors.New("recipient Claude configuration changed while it was read")
	}
	return payload, nil
}

func cloneMCPServers(source map[string]json.RawMessage) map[string]json.RawMessage {
	result := make(map[string]json.RawMessage, len(source))
	for name, server := range source {
		result[name] = append(json.RawMessage(nil), server...)
	}
	return result
}

func matchingClaudeProject(projects map[string]claudeProjectState, workDir string) claudeProjectState {
	root := claudeProjectRoot(workDir)
	if project, ok := projects[root]; ok {
		return project
	}
	rootInfo, err := os.Stat(root)
	if err != nil {
		return claudeProjectState{}
	}
	// Claude stores local-scope MCPs against its canonical project root. Match
	// an equivalent path (for example /tmp versus /private/tmp on macOS)
	// without treating an arbitrary ancestor's project state as inherited.
	paths := make([]string, 0, len(projects))
	for path := range projects {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		info, statErr := os.Stat(path)
		if statErr == nil && os.SameFile(rootInfo, info) {
			return projects[path]
		}
	}
	return claudeProjectState{}
}

func claudeProjectRoot(workDir string) string {
	current := filepath.Clean(workDir)
	for {
		if info, err := os.Lstat(filepath.Join(current, ".git")); err == nil &&
			(info.IsDir() || info.Mode().IsRegular()) {
			return current
		}
		parent := filepath.Dir(current)
		if parent == current {
			return workDir
		}
		current = parent
	}
}

func isTeamRelayMCPServer(name string, raw json.RawMessage) (bool, error) {
	alias := strings.ToLower(strings.TrimSpace(name))
	alias = strings.NewReplacer("_", "-", " ", "-").Replace(alias)
	if alias == "team-relay" || alias == "team-relay-mcp" {
		return true, nil
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '{' {
		return false, errors.New("recipient MCP server has an invalid configuration")
	}
	var identity claudeMCPIdentity
	if err := json.Unmarshal(raw, &identity); err != nil {
		return false, fmt.Errorf("decode recipient MCP server identity: %w", err)
	}
	values := append([]string{identity.Command, identity.URL}, identity.Args...)
	for _, value := range values {
		normalized := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), "_", "-"))
		normalized = strings.ReplaceAll(normalized, "\\", "/")
		base := filepath.Base(normalized)
		if base == "team-relay-mcp" || base == "team-relay-mcp.exe" ||
			strings.Contains(normalized, "team-relay-mcp") ||
			strings.Contains(normalized, "team-relay/team-relay") ||
			strings.Contains(normalized, "/team-relay/") {
			return true, nil
		}
	}
	return false, nil
}

func writePrivateMCPConfig(payload []byte) (string, func(), error) {
	for range temporaryNameAttempts {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return "", func() {}, fmt.Errorf("generate private MCP directory name: %w", err)
		}
		directory := filepath.Join(os.TempDir(), "team-relay-claude-mcp-"+hex.EncodeToString(random[:]))
		if err := privatefs.CreateDirectory(directory); err != nil {
			if errors.Is(err, os.ErrExist) {
				continue
			}
			return "", func() {}, fmt.Errorf("create private MCP directory: %w", err)
		}
		path := filepath.Join(directory, "mcp.json")
		if err := privatefs.WriteNewFile(path, payload, 0o600); err != nil {
			_ = os.Remove(directory)
			return "", func() {}, fmt.Errorf("write private MCP configuration: %w", err)
		}
		cleanup := func() {
			_ = os.Remove(path)
			_ = os.Remove(directory)
		}
		return path, cleanup, nil
	}
	return "", func() {}, errors.New("could not allocate a private MCP directory")
}

func (a *Adapter) sessionRef(id string, policy relayruntime.Policy) *relayruntime.SessionRef {
	return &relayruntime.SessionRef{
		RuntimeID:          RuntimeID,
		OpaqueID:           id,
		PolicyFingerprint:  relayruntime.PolicyFingerprint(policy),
		WorkDirFingerprint: relayruntime.WorkDirFingerprint(a.workDir),
	}
}

func additionalDirectories(request relayruntime.RunRequest) []string {
	seen := make(map[string]struct{})
	for _, workspace := range request.Workspaces {
		seen[workspace.Path] = struct{}{}
	}
	for _, attachment := range request.Attachments {
		seen[filepath.Dir(attachment)] = struct{}{}
	}
	if request.ReturnDirectory != "" {
		seen[request.ReturnDirectory] = struct{}{}
	}
	paths := make([]string, 0, len(seen))
	for path := range seen {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

func claudeDeniedTools(policy relayruntime.Policy) []string {
	denied := append([]string(nil), policy.DeniedTools...)
	// A recipient runtime may answer a relay request but can never recursively
	// create another relay request using the recipient's MCP credentials. Claude
	// does not support wildcard MCP tool patterns, so deny the conventional
	// aliases exactly. A renamed local Team Relay binary is independently
	// blocked by the adapter-owned recipient-run environment marker.
	teamRelayTools := []string{
		"find_teammates",
		"request_teammate_help",
		"get_request_status",
		"continue_teammate_conversation",
		"cancel_request",
		"download_teammate_file",
	}
	for _, alias := range []string{"team-relay", "team_relay"} {
		denied = append(denied, "mcp__"+alias)
		for _, tool := range teamRelayTools {
			denied = append(denied, "mcp__"+alias+"__"+tool)
		}
	}
	if !policy.AllowShell {
		denied = append(denied, "Bash")
	}
	if !policy.AllowWrites {
		denied = append(denied, "Edit", "Write", "NotebookEdit")
	}
	if !policy.AllowNetwork {
		denied = append(denied, "WebFetch", "WebSearch")
	}
	for _, command := range policy.DeniedCommands {
		denied = append(denied, "Bash("+command+" *)")
	}
	sort.Strings(denied)
	return compact(denied)
}

func compact(values []string) []string {
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}

func toolSummary(name string) string {
	name = relayruntime.SafeSummary(name)
	return "Running " + name
}

type claudeEvent struct {
	Type         string  `json:"type"`
	SessionID    string  `json:"session_id"`
	Result       string  `json:"result"`
	IsError      bool    `json:"is_error"`
	DurationMS   int64   `json:"duration_ms"`
	TotalCostUSD float64 `json:"total_cost_usd"`
	Message      struct {
		Content []struct {
			ID        string          `json:"id"`
			Type      string          `json:"type"`
			Text      string          `json:"text"`
			Name      string          `json:"name"`
			Input     json.RawMessage `json:"input"`
			ToolUseID string          `json:"tool_use_id"`
			IsError   bool            `json:"is_error"`
		} `json:"content"`
	} `json:"message"`
}
