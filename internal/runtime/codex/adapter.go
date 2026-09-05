// Package codex implements the recipient runtime adapter for the Codex CLI.
package codex

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	relayruntime "github.com/mohitbadwal/team-relay/internal/runtime"
)

const RuntimeID = "codex"

const (
	recipientRunEnvironment  = "AGENT_RELAY_RECIPIENT_RUN"
	containmentProbeTimeout  = 5 * time.Second
	maxContainmentProbeBytes = 1 << 20
)

var codexIntegrationFeatures = []string{
	"plugins",
	"remote_plugin",
	"apps",
	"enable_mcp_apps",
	"external_migration",
	"skill_mcp_dependency_install",
	"tool_suggest",
	"hooks",
}

type Config struct {
	Executable           string
	PrefixArgs           []string
	WorkDir              string
	Model                string
	Profile              string
	EnvironmentAllowlist []string
	Policy               relayruntime.Policy
	Timeout              time.Duration
}

type Adapter struct {
	executable           string
	prefixArgs           []string
	workDir              string
	model                string
	profile              string
	environmentAllowlist []string
	policy               relayruntime.Policy
	timeout              time.Duration
}

func New(config Config) (*Adapter, error) {
	workDir, err := relayruntime.ValidateWorkDir(config.WorkDir)
	if err != nil {
		return nil, err
	}
	policy, err := relayruntime.ValidatePolicy(config.Policy)
	if err != nil {
		return nil, err
	}
	if config.Executable == "" {
		config.Executable = "codex"
	}
	if config.Timeout <= 0 {
		config.Timeout = 30 * time.Minute
	}
	if strings.TrimSpace(config.Profile) != "" {
		return nil, fmt.Errorf("Codex profiles cannot be loaded for recipient requests because they can restore mutable MCP configuration; configure the receiver model explicitly instead")
	}
	if err := validateCodexPrefixArgs(config.PrefixArgs); err != nil {
		return nil, err
	}
	return &Adapter{
		executable:           config.Executable,
		prefixArgs:           append([]string(nil), config.PrefixArgs...),
		workDir:              workDir,
		model:                config.Model,
		profile:              config.Profile,
		environmentAllowlist: append([]string(nil), config.EnvironmentAllowlist...),
		policy:               policy,
		timeout:              config.Timeout,
	}, nil
}

func (a *Adapter) ID() string { return RuntimeID }

func (a *Adapter) ConfiguredPolicy() relayruntime.Policy { return a.policy }

func (a *Adapter) WorkDirFingerprint() string {
	return relayruntime.WorkDirFingerprint(a.workDir)
}

func (a *Adapter) ApprovalFingerprint() (string, error) {
	if err := requireIsolatedCodexMCPPolicy(a.policy); err != nil {
		return "", err
	}
	if err := a.preflightNoResidualMCP(context.Background()); err != nil {
		return "", err
	}
	return relayruntime.ApprovalConfigFingerprint(struct {
		Version                     int                 `json:"version"`
		RuntimeID                   string              `json:"runtime_id"`
		Executable                  string              `json:"executable"`
		PrefixArgs                  []string            `json:"prefix_args"`
		WorkDir                     string              `json:"work_dir"`
		Model                       string              `json:"model"`
		Profile                     string              `json:"profile"`
		EnvironmentAllowlist        []string            `json:"environment_allowlist"`
		Policy                      relayruntime.Policy `json:"policy"`
		Timeout                     time.Duration       `json:"timeout"`
		MCPIsolation                string              `json:"mcp_isolation"`
		DisabledIntegrationFeatures []string            `json:"disabled_integration_features"`
		MCPServers                  []string            `json:"mcp_servers"`
	}{
		Version: 3, RuntimeID: RuntimeID, Executable: a.executable,
		PrefixArgs: append([]string(nil), a.prefixArgs...), WorkDir: a.workDir,
		Model: a.model, Profile: a.profile,
		EnvironmentAllowlist:        relayruntime.CanonicalEnvironmentAllowlist(a.environmentAllowlist),
		Policy:                      a.policy,
		Timeout:                     a.timeout,
		MCPIsolation:                "empty-home-preflight-and-ignore-user-config",
		DisabledIntegrationFeatures: canonicalCodexIntegrationFeatures(),
		MCPServers:                  []string{},
	})
}

func (a *Adapter) capabilities() relayruntime.Capabilities {
	return relayruntime.Capabilities{
		RuntimeID:              RuntimeID,
		DisplayName:            "Codex",
		SupportsResume:         true,
		SupportsStreaming:      true,
		SupportsModelSelection: true,
		PreservesLocalContext:  true,
		LoadsLocalMCPs:         false,
		Policy: relayruntime.PolicyCapabilities{
			ReadOnly:               relayruntime.EnforcementNative,
			GuardedWrite:           relayruntime.EnforcementNative,
			FilesystemIsolation:    relayruntime.EnforcementBestEffort,
			NetworkIsolation:       relayruntime.EnforcementNative,
			ShellControl:           relayruntime.EnforcementUnsupported,
			MCPControl:             relayruntime.EnforcementNative,
			DestructiveCommandDeny: relayruntime.EnforcementBestEffort,
		},
	}
}

func (a *Adapter) Probe(ctx context.Context) (relayruntime.Capabilities, error) {
	capabilities := a.capabilities()
	version, err := relayruntime.ProbeCommand(ctx, a.executable, a.prefixArgs, a.environmentAllowlist, "--version")
	if err != nil {
		capabilities.Detail = err.Error()
		if errors.Is(err, relayruntime.ErrUnavailable) {
			return capabilities, nil
		}
		return capabilities, err
	}
	if err := a.validateContainmentSupport(ctx); err != nil {
		capabilities.Detail = err.Error()
		return capabilities, err
	}
	if err := a.preflightNoResidualMCP(ctx); err != nil {
		capabilities.Detail = err.Error()
		return capabilities, err
	}
	if err := requireIsolatedCodexMCPPolicy(a.policy); err != nil {
		capabilities.Detail = err.Error()
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
	if err := requireIsolatedCodexMCPPolicy(effective); err != nil {
		return relayruntime.RunResult{}, err
	}
	if err := relayruntime.ValidatePolicySupport(a.capabilities(), effective); err != nil {
		return relayruntime.RunResult{}, err
	}
	request = relayruntime.ConstrainRequest(request, effective)

	runCtx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()
	args, session := a.commandArgs(request, effective)
	if request.Session != nil && session == nil {
		if err := relayruntime.Emit(runCtx, sink, relayruntime.Event{Type: relayruntime.EventWarning, Summary: "Previous session was not resumed because its runtime, directory, or permission profile changed"}); err != nil {
			return relayruntime.RunResult{}, err
		}
	}
	if err := relayruntime.Emit(runCtx, sink, relayruntime.Event{Type: relayruntime.EventStarting, Summary: "Starting Codex"}); err != nil {
		return relayruntime.RunResult{}, err
	}

	result := relayruntime.RunResult{EffectivePolicy: effective, Session: session}
	var providerError string
	prompt := relayruntime.BuildPrompt(request, relayruntime.RecipientResponseContract) + relayruntime.PolicyInstructions(effective)
	// This is intentionally the last adapter-controlled operation before process
	// launch. It closes the user-config replacement window while rejecting any
	// system/managed MCP that remains after every supported integration switch is
	// disabled. A privileged administrator changing managed config between this
	// check and exec is outside the local recipient threat model.
	if err := a.preflightNoResidualMCP(runCtx); err != nil {
		return relayruntime.RunResult{}, err
	}
	err = relayruntime.ExecuteJSONLines(runCtx, relayruntime.CommandSpec{
		Executable:           a.executable,
		Args:                 args,
		Directory:            a.workDir,
		Stdin:                prompt,
		EnvironmentAllowlist: a.environmentAllowlist,
		Environment:          map[string]string{recipientRunEnvironment: "1"},
	}, func(raw json.RawMessage) error {
		var event codexEvent
		if err := json.Unmarshal(raw, &event); err != nil {
			return nil
		}
		switch event.Type {
		case "thread.started":
			if event.ThreadID != "" {
				result.Session = a.sessionRef(event.ThreadID, effective)
				if err := relayruntime.Emit(runCtx, sink, relayruntime.Event{Type: relayruntime.EventSession, Summary: "Codex session connected", Session: result.Session}); err != nil {
					return err
				}
			}
		case "item.started", "item.updated", "item.completed":
			if err := a.handleItem(runCtx, sink, event, &result); err != nil {
				return err
			}
		case "turn.completed":
			result.Usage.InputTokens = event.Usage.InputTokens
			result.Usage.OutputTokens = event.Usage.OutputTokens
			result.Usage.CachedTokens = event.Usage.CachedInputTokens
			if err := relayruntime.Emit(runCtx, sink, relayruntime.Event{Type: relayruntime.EventFinishing, Summary: "Codex finished; returning result", Usage: &result.Usage}); err != nil {
				return err
			}
		case "turn.failed", "error":
			providerError = event.Error.Message
			if providerError == "" {
				providerError = event.Message
			}
		}
		return nil
	})
	if err != nil {
		return relayruntime.RunResult{}, fmt.Errorf("Codex: %w", err)
	}
	if providerError != "" {
		return relayruntime.RunResult{}, fmt.Errorf("Codex reported an error: %s", relayruntime.SafeSummary(providerError))
	}
	if strings.TrimSpace(result.FinalText) == "" {
		return relayruntime.RunResult{}, fmt.Errorf("Codex: %w", relayruntime.ErrNoFinalAnswer)
	}
	if err := relayruntime.Emit(runCtx, sink, relayruntime.Event{Type: relayruntime.EventCompleted, Summary: "Codex response ready", Session: result.Session, Usage: &result.Usage}); err != nil {
		return relayruntime.RunResult{}, err
	}
	return result, nil
}

func (a *Adapter) commandArgs(request relayruntime.RunRequest, policy relayruntime.Policy) ([]string, *relayruntime.SessionRef) {
	args := append([]string(nil), a.prefixArgs...)
	writableDirectories := codexWritableDirectories(request, policy)
	var session *relayruntime.SessionRef
	if relayruntime.CompatibleSession(request.Session, RuntimeID, policy, a.workDir) {
		session = request.Session
		args = append(args, "exec", "resume")
		args = append(args, codexConfigIsolationArgs()...)
		args = append(args, "--json")
		if a.model != "" {
			args = append(args, "--model", a.model)
		}
		args = append(args, codexPolicyConfig(policy, writableDirectories, a.workDir)...)
		args = append(args, "--skip-git-repo-check", session.OpaqueID, "-")
		return args, session
	}

	args = append(args, "exec")
	args = append(args, codexConfigIsolationArgs()...)
	args = append(args, "--json", "--color", "never", "--cd", a.workDir, "--skip-git-repo-check")
	if a.model != "" {
		args = append(args, "--model", a.model)
	}
	if policy.AllowWrites {
		args = append(args, "--sandbox", "workspace-write")
	} else {
		args = append(args, "--sandbox", "read-only")
	}
	args = append(args, codexPolicyConfig(policy, writableDirectories, a.workDir)...)
	for _, path := range writableDirectories {
		args = append(args, "--add-dir", path)
	}
	args = append(args, "-")
	return args, nil
}

func codexPolicyConfig(policy relayruntime.Policy, writableDirectories []string, workDir string) []string {
	sandboxMode := "read-only"
	if policy.AllowWrites {
		sandboxMode = "workspace-write"
	}
	args := []string{
		"--config", "sandbox_mode=" + strconv.Quote(sandboxMode),
		"--config", fmt.Sprintf("sandbox_workspace_write.network_access=%t", policy.AllowNetwork),
		// Keep provider authentication in the Codex process while preventing
		// model-generated shell commands from inheriting arbitrary secret-named
		// variables from that process.
		"--config", `shell_environment_policy.inherit="core"`,
		"--config", "shell_environment_policy.ignore_default_excludes=false",
	}
	// Do not let a repository reintroduce configuration after the user config was
	// excluded. Cover every ancestor because Codex may identify a parent directory
	// as the project root when the recipient work directory is a nested folder.
	args = append(args, codexUntrustedProjectConfig(workDir)...)
	if policy.AllowWrites {
		quoted := make([]string, 0, len(writableDirectories))
		for _, directory := range writableDirectories {
			quoted = append(quoted, strconv.Quote(directory))
		}
		args = append(args, "--config", "sandbox_workspace_write.writable_roots=["+strings.Join(quoted, ",")+"]")
	}
	return args
}

func codexConfigIsolationArgs() []string {
	args := []string{
		// Keep CODEX_HOME itself so Codex can still use recipient authentication,
		// session state, memories, and instructions. Only its mutable user config
		// is excluded from this child process.
		"--ignore-user-config",
	}
	return append(args, codexIntegrationDisableArgs()...)
}

func codexIntegrationDisableArgs() []string {
	args := make([]string, 0, len(codexIntegrationFeatures)*2)
	for _, feature := range codexIntegrationFeatures {
		args = append(args, "--config", "features."+feature+"=false")
	}
	return args
}

func canonicalCodexIntegrationFeatures() []string {
	features := append([]string(nil), codexIntegrationFeatures...)
	sort.Strings(features)
	return features
}

func requireIsolatedCodexMCPPolicy(policy relayruntime.Policy) error {
	if !policy.AllowMCPs {
		return nil
	}
	return fmt.Errorf("%w: Codex cannot load local MCP servers for recipient requests because the current CLI cannot bind a child process to an exact, secret-safe MCP configuration snapshot; disable MCP access", relayruntime.ErrUnsupportedPolicy)
}

func validateCodexPrefixArgs(args []string) error {
	for _, argument := range args {
		flag := argument
		if index := strings.IndexByte(flag, '='); index >= 0 {
			flag = flag[:index]
		}
		switch flag {
		case "--config", "-c", "--profile", "-p", "--enable", "--disable":
			return fmt.Errorf("Codex prefix arguments must not set config, profiles, or feature flags because they can bypass recipient MCP isolation")
		}
		if strings.HasPrefix(argument, "-c") && !strings.HasPrefix(argument, "--") ||
			strings.HasPrefix(argument, "-p") && !strings.HasPrefix(argument, "--") {
			return fmt.Errorf("Codex prefix arguments must not set config or profiles because they can bypass recipient MCP isolation")
		}
	}
	return nil
}

func (a *Adapter) validateContainmentSupport(ctx context.Context) error {
	home, cleanup, err := freshCodexHome()
	if err != nil {
		return errors.New("Codex containment check could not create a private temporary home")
	}
	defer cleanup()

	help, err := a.runMetadataCommand(ctx, home, []string{"exec", "--help"})
	if err != nil {
		return fmt.Errorf("%w: Codex CLI could not validate exec isolation support", relayruntime.ErrUnsupportedPolicy)
	}
	if !bytes.Contains(help, []byte("--ignore-user-config")) {
		return fmt.Errorf("%w: Codex CLI does not support exec --ignore-user-config; upgrade Codex", relayruntime.ErrUnsupportedPolicy)
	}

	args := codexIntegrationDisableArgs()
	args = append(args, "features", "list")
	featuresOutput, err := a.runMetadataCommand(ctx, home, args)
	if err != nil {
		return fmt.Errorf("%w: Codex CLI rejected one or more required integration-disable switches; upgrade Codex", relayruntime.ErrUnsupportedPolicy)
	}
	effective := make(map[string]string)
	for _, line := range strings.Split(string(featuresOutput), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			effective[fields[0]] = fields[len(fields)-1]
		}
	}
	for _, feature := range codexIntegrationFeatures {
		value, ok := effective[feature]
		if !ok {
			return fmt.Errorf("%w: Codex CLI does not report every required integration-disable feature; upgrade Codex", relayruntime.ErrUnsupportedPolicy)
		}
		if value != "false" {
			return fmt.Errorf("%w: Codex CLI did not disable every required integration feature; check managed Codex policy", relayruntime.ErrUnsupportedPolicy)
		}
	}
	return nil
}

// preflightNoResidualMCP uses a brand-new empty CODEX_HOME so user configuration
// is absent while system/managed layers still apply. It intentionally decodes
// only the array shape and entry count: MCP names, transports, headers, and
// environment values are never retained, returned, or written to diagnostics.
func (a *Adapter) preflightNoResidualMCP(ctx context.Context) error {
	home, cleanup, err := freshCodexHome()
	if err != nil {
		return errors.New("Codex MCP isolation preflight could not create a private temporary home")
	}
	defer cleanup()

	preflightCtx, cancel := context.WithTimeout(ctx, containmentProbeTimeout)
	defer cancel()
	args := append([]string(nil), a.prefixArgs...)
	args = append(args, codexIntegrationDisableArgs()...)
	args = append(args, codexUntrustedProjectConfig(a.workDir)...)
	args = append(args, "mcp", "list", "--json")
	command := exec.CommandContext(preflightCtx, a.executable, args...)
	command.Dir = a.workDir
	command.Env = codexCommandEnvironment(a.environmentAllowlist, home)
	command.Stderr = io.Discard
	stdout, err := command.StdoutPipe()
	if err != nil {
		return codexMCPPreflightFailure()
	}
	if err := command.Start(); err != nil {
		return codexMCPPreflightFailure()
	}

	limited := &io.LimitedReader{R: stdout, N: maxContainmentProbeBytes + 1}
	decoder := json.NewDecoder(limited)
	residual := false
	valid := true
	token, decodeErr := decoder.Token()
	if decodeErr != nil || token != json.Delim('[') {
		valid = false
	} else {
		for decoder.More() {
			var entry struct{}
			if err := decoder.Decode(&entry); err != nil {
				valid = false
				break
			}
			residual = true
		}
		if valid {
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim(']') {
				valid = false
			}
		}
		if valid {
			var trailing struct{}
			if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
				valid = false
			}
		}
	}
	_, drainErr := io.Copy(io.Discard, limited)
	tooLarge := limited.N == 0
	if tooLarge {
		_ = command.Process.Kill()
	}
	waitErr := command.Wait()
	if preflightCtx.Err() != nil || waitErr != nil || drainErr != nil || tooLarge || !valid {
		return codexMCPPreflightFailure()
	}
	if residual {
		return fmt.Errorf("%w: system or managed Codex configuration still enables an MCP server after recipient isolation; remove that MCP configuration", relayruntime.ErrUnsupportedPolicy)
	}
	return nil
}

func codexMCPPreflightFailure() error {
	return fmt.Errorf("%w: Codex MCP isolation preflight could not verify an empty effective inventory", relayruntime.ErrUnsupportedPolicy)
}

func (a *Adapter) runMetadataCommand(ctx context.Context, codexHome string, commandArgs []string) ([]byte, error) {
	probeCtx, cancel := context.WithTimeout(ctx, containmentProbeTimeout)
	defer cancel()
	args := append([]string(nil), a.prefixArgs...)
	args = append(args, commandArgs...)
	command := exec.CommandContext(probeCtx, a.executable, args...)
	command.Dir = a.workDir
	command.Env = codexCommandEnvironment(a.environmentAllowlist, codexHome)
	command.Stderr = io.Discard
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := command.Start(); err != nil {
		return nil, err
	}
	limited := &io.LimitedReader{R: stdout, N: maxContainmentProbeBytes + 1}
	output, readErr := io.ReadAll(limited)
	tooLarge := limited.N == 0
	if tooLarge {
		_ = command.Process.Kill()
	}
	waitErr := command.Wait()
	if probeCtx.Err() != nil {
		return nil, probeCtx.Err()
	}
	if readErr != nil || waitErr != nil || tooLarge {
		return nil, errors.New("Codex metadata command failed")
	}
	return output, nil
}

func freshCodexHome() (string, func(), error) {
	path, err := os.MkdirTemp("", "team-relay-codex-preflight-")
	if err != nil {
		return "", nil, err
	}
	return path, func() { _ = os.RemoveAll(path) }, nil
}

func codexCommandEnvironment(additionalAllowed []string, codexHome string) []string {
	environment := relayruntime.SanitizedEnvironment(os.Environ(), additionalAllowed)
	filtered := environment[:0]
	for _, item := range environment {
		name, _, found := strings.Cut(item, "=")
		if found && strings.EqualFold(name, "CODEX_HOME") {
			continue
		}
		filtered = append(filtered, item)
	}
	return append(filtered, "CODEX_HOME="+codexHome)
}

func codexUntrustedProjectConfig(workDir string) []string {
	current := filepath.Clean(workDir)
	var paths []string
	for {
		paths = append(paths, current)
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	args := make([]string, 0, len(paths)*2)
	for _, path := range paths {
		args = append(args, "--config", "projects."+strconv.Quote(path)+`.trust_level="untrusted"`)
	}
	return args
}

func codexWritableDirectories(request relayruntime.RunRequest, policy relayruntime.Policy) []string {
	if !policy.AllowWrites {
		return nil
	}
	seen := make(map[string]struct{})
	for _, workspace := range request.Workspaces {
		if workspace.Mode == relayruntime.WorkspaceWritable {
			seen[workspace.Path] = struct{}{}
		}
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

func (a *Adapter) sessionRef(id string, policy relayruntime.Policy) *relayruntime.SessionRef {
	return &relayruntime.SessionRef{
		RuntimeID:          RuntimeID,
		OpaqueID:           id,
		PolicyFingerprint:  relayruntime.PolicyFingerprint(policy),
		WorkDirFingerprint: relayruntime.WorkDirFingerprint(a.workDir),
	}
}

func (a *Adapter) handleItem(ctx context.Context, sink relayruntime.EventSink, event codexEvent, result *relayruntime.RunResult) error {
	item := event.Item
	switch item.Type {
	case "agent_message":
		if event.Type == "item.completed" && strings.TrimSpace(item.Text) != "" {
			if len(item.Text) > relayruntime.MaxFinalTextBytes {
				return fmt.Errorf("Codex answer exceeds local size limit")
			}
			result.FinalText = item.Text
			return relayruntime.Emit(ctx, sink, relayruntime.Event{Type: relayruntime.EventProgress, Summary: "Codex produced response text"})
		}
	case "command_execution":
		kind := relayruntime.EventToolStarted
		summary := "Running a command"
		if event.Type == "item.completed" {
			kind = relayruntime.EventToolFinished
			summary = "Command completed"
			if item.ExitCode != nil && *item.ExitCode != 0 {
				summary = "Command failed"
			}
		}
		return relayruntime.Emit(ctx, sink, relayruntime.Event{Type: kind, Tool: "shell", Summary: summary})
	case "mcp_tool_call":
		kind := relayruntime.EventToolStarted
		summary := "Running MCP tool"
		if event.Type == "item.completed" {
			kind = relayruntime.EventToolFinished
			summary = "MCP tool completed"
		}
		return relayruntime.Emit(ctx, sink, relayruntime.Event{Type: kind, Tool: item.Name, Summary: summary})
	case "file_change":
		kind := relayruntime.EventToolStarted
		if event.Type == "item.completed" {
			kind = relayruntime.EventToolFinished
		}
		return relayruntime.Emit(ctx, sink, relayruntime.Event{Type: kind, Tool: "file_change", Summary: "Applying approved workspace changes"})
	case "reasoning":
		return relayruntime.Emit(ctx, sink, relayruntime.Event{Type: relayruntime.EventProgress, Summary: "Codex is reasoning"})
	}
	return nil
}

type codexEvent struct {
	Type     string `json:"type"`
	ThreadID string `json:"thread_id"`
	Message  string `json:"message"`
	Error    struct {
		Message string `json:"message"`
	} `json:"error"`
	Usage struct {
		InputTokens       int64 `json:"input_tokens"`
		CachedInputTokens int64 `json:"cached_input_tokens"`
		OutputTokens      int64 `json:"output_tokens"`
	} `json:"usage"`
	Item struct {
		ID       string `json:"id"`
		Type     string `json:"type"`
		Text     string `json:"text"`
		Name     string `json:"name"`
		Status   string `json:"status"`
		ExitCode *int   `json:"exit_code"`
	} `json:"item"`
}
