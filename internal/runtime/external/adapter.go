// Package external implements the versioned protocol for locally installed
// third-party agent runners. It never invokes a shell and the executable plus
// prefix arguments are fixed in recipient-owned configuration.
package external

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	relayruntime "github.com/mohitbadwal/team-relay/internal/runtime"
)

var validRunnerID = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

const recipientRunEnvironment = "AGENT_RELAY_RECIPIENT_RUN"

type Config struct {
	ID                   string
	Name                 string
	Executable           string
	PrefixArgs           []string
	WorkDir              string
	Model                string
	EnvironmentAllowlist []string
	Policy               relayruntime.Policy
	Timeout              time.Duration
}

type Adapter struct {
	id                   string
	name                 string
	executable           string
	prefixArgs           []string
	workDir              string
	model                string
	environmentAllowlist []string
	policy               relayruntime.Policy
	timeout              time.Duration
}

func New(config Config) (*Adapter, error) {
	if !validRunnerID.MatchString(config.ID) {
		return nil, fmt.Errorf("external runtime id must match %s", validRunnerID)
	}
	if strings.TrimSpace(config.Executable) == "" {
		return nil, fmt.Errorf("external runtime executable is required")
	}
	if isShellExecutable(config.Executable) {
		return nil, fmt.Errorf("external runtime executable must implement %s directly; shell interpreters are not allowed", relayruntime.RunnerProtocolV1)
	}
	workDir, err := relayruntime.ValidateWorkDir(config.WorkDir)
	if err != nil {
		return nil, err
	}
	policy, err := relayruntime.ValidatePolicy(config.Policy)
	if err != nil {
		return nil, err
	}
	if config.Name == "" {
		config.Name = config.ID
	}
	if config.Timeout <= 0 {
		config.Timeout = 30 * time.Minute
	}
	return &Adapter{
		id:                   "external:" + config.ID,
		name:                 config.Name,
		executable:           config.Executable,
		prefixArgs:           append([]string(nil), config.PrefixArgs...),
		workDir:              workDir,
		model:                strings.TrimSpace(config.Model),
		environmentAllowlist: append([]string(nil), config.EnvironmentAllowlist...),
		policy:               policy,
		timeout:              config.Timeout,
	}, nil
}

func (a *Adapter) ID() string { return a.id }

func (a *Adapter) ConfiguredPolicy() relayruntime.Policy { return a.policy }

func (a *Adapter) WorkDirFingerprint() string {
	return relayruntime.WorkDirFingerprint(a.workDir)
}

func (a *Adapter) ApprovalFingerprint() (string, error) {
	// External runners receive the complete effective policy over the fixed v1
	// protocol; unlike built-in adapters, Team Relay does not discover a second
	// local MCP configuration source for them.
	return relayruntime.ApprovalConfigFingerprint(struct {
		Version              int                 `json:"version"`
		Protocol             string              `json:"protocol"`
		RuntimeID            string              `json:"runtime_id"`
		Name                 string              `json:"name"`
		Executable           string              `json:"executable"`
		PrefixArgs           []string            `json:"prefix_args"`
		WorkDir              string              `json:"work_dir"`
		Model                string              `json:"model"`
		EnvironmentAllowlist []string            `json:"environment_allowlist"`
		Policy               relayruntime.Policy `json:"policy"`
		Timeout              time.Duration       `json:"timeout"`
	}{
		Version: 1, Protocol: relayruntime.RunnerProtocolV1, RuntimeID: a.id, Name: a.name,
		Executable: a.executable, PrefixArgs: append([]string(nil), a.prefixArgs...), WorkDir: a.workDir,
		Model: a.model, EnvironmentAllowlist: relayruntime.CanonicalEnvironmentAllowlist(a.environmentAllowlist),
		Policy: a.policy, Timeout: a.timeout,
	})
}

func (a *Adapter) Probe(ctx context.Context) (relayruntime.Capabilities, error) {
	base := relayruntime.Capabilities{RuntimeID: a.id, DisplayName: a.name}
	if _, err := exec.LookPath(a.executable); err != nil {
		base.Detail = fmt.Errorf("%w: %s", relayruntime.ErrUnavailable, a.executable).Error()
		return base, nil
	}
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	input, _ := json.Marshal(runnerInput{Protocol: relayruntime.RunnerProtocolV1, Type: "probe"})
	var received bool
	err := relayruntime.ExecuteJSONLines(probeCtx, relayruntime.CommandSpec{
		Executable:           a.executable,
		Args:                 a.prefixArgs,
		Directory:            a.workDir,
		Stdin:                string(input) + "\n",
		EnvironmentAllowlist: a.environmentAllowlist,
	}, func(raw json.RawMessage) error {
		var envelope runnerOutput
		if err := json.Unmarshal(raw, &envelope); err != nil {
			return nil
		}
		if envelope.Protocol != relayruntime.RunnerProtocolV1 {
			return fmt.Errorf("external runner returned unsupported protocol %q", envelope.Protocol)
		}
		if envelope.Type == "error" {
			return fmt.Errorf("external runner probe: %s", relayruntime.SafeSummary(envelope.Message))
		}
		if envelope.Type != "capabilities" || envelope.Capabilities == nil {
			return nil
		}
		received = true
		base = sanitizeCapabilities(a.id, a.name, a.policy, *envelope.Capabilities)
		base.Available = true
		return nil
	})
	if err != nil {
		return base, err
	}
	if !received {
		return base, fmt.Errorf("external runner returned no capabilities")
	}
	if a.model != "" && !base.SupportsModelSelection {
		return base, fmt.Errorf("external runtime %s does not support the configured recipient model override", a.id)
	}
	return base, nil
}

func (a *Adapter) Run(ctx context.Context, request relayruntime.RunRequest, sink relayruntime.EventSink) (relayruntime.RunResult, error) {
	if err := relayruntime.ValidateRunRequest(request); err != nil {
		return relayruntime.RunResult{}, err
	}
	effective, err := relayruntime.EffectivePolicy(a.policy, request.RequestedPolicy)
	if err != nil {
		return relayruntime.RunResult{}, err
	}
	request = relayruntime.ConstrainRequest(request, effective)
	capabilities, err := a.Probe(ctx)
	if err != nil {
		return relayruntime.RunResult{}, err
	}
	if err := relayruntime.ValidatePolicySupport(capabilities, effective); err != nil {
		return relayruntime.RunResult{}, fmt.Errorf("external runtime %s: %w", a.id, err)
	}
	var session *relayruntime.SessionRef
	if capabilities.SupportsResume && relayruntime.CompatibleSession(request.Session, a.id, effective, a.workDir) {
		session = request.Session
	}
	if request.Session != nil && session == nil {
		if err := relayruntime.Emit(ctx, sink, relayruntime.Event{Type: relayruntime.EventWarning, Summary: "Previous session was not resumed because its runtime, directory, or permission profile changed"}); err != nil {
			return relayruntime.RunResult{}, err
		}
	}

	runCtx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()
	payload := runnerInput{
		Protocol:        relayruntime.RunnerProtocolV1,
		Type:            "run",
		RequestID:       request.RequestID,
		ConversationID:  request.ConversationID,
		Title:           request.Title,
		Requester:       request.Requester,
		Prompt:          relayruntime.BuildPrompt(request, relayruntime.RecipientResponseContract) + relayruntime.PolicyInstructions(effective),
		Model:           a.model,
		WorkDir:         a.workDir,
		Attachments:     request.Attachments,
		Workspaces:      request.Workspaces,
		ReturnDirectory: request.ReturnDirectory,
		Policy:          effective,
	}
	if session != nil {
		payload.SessionID = session.OpaqueID
	}
	input, err := json.Marshal(payload)
	if err != nil {
		return relayruntime.RunResult{}, fmt.Errorf("encode external runner request: %w", err)
	}
	if err := relayruntime.Emit(runCtx, sink, relayruntime.Event{Type: relayruntime.EventStarting, Summary: "Starting " + a.name}); err != nil {
		return relayruntime.RunResult{}, err
	}

	result := relayruntime.RunResult{EffectivePolicy: effective, Session: session}
	var runnerErr string
	err = relayruntime.ExecuteJSONLines(runCtx, relayruntime.CommandSpec{
		Executable:           a.executable,
		Args:                 a.prefixArgs,
		Directory:            a.workDir,
		Stdin:                string(input) + "\n",
		EnvironmentAllowlist: a.environmentAllowlist,
		Environment:          map[string]string{recipientRunEnvironment: "1"},
	}, func(raw json.RawMessage) error {
		var envelope runnerOutput
		if err := json.Unmarshal(raw, &envelope); err != nil {
			return nil
		}
		if envelope.Protocol != relayruntime.RunnerProtocolV1 {
			return fmt.Errorf("external runner returned unsupported protocol %q", envelope.Protocol)
		}
		switch envelope.Type {
		case "started":
			if envelope.SessionID != "" {
				result.Session = a.sessionRef(envelope.SessionID, effective)
				return relayruntime.Emit(runCtx, sink, relayruntime.Event{Type: relayruntime.EventSession, Summary: a.name + " session connected", Session: result.Session})
			}
		case "event":
			if envelope.Event != nil {
				event := genericRunnerEvent(envelope.Event.runtimeEvent())
				// Session references are created locally, never accepted verbatim
				// from a plugin process.
				event.Session = nil
				return relayruntime.Emit(runCtx, sink, event)
			}
		case "result":
			if envelope.Result == nil {
				return fmt.Errorf("external runner returned an empty result envelope")
			}
			if len(envelope.Result.FinalText) > relayruntime.MaxFinalTextBytes {
				return fmt.Errorf("external runner answer exceeds local size limit")
			}
			result.FinalText = envelope.Result.FinalText
			result.Usage = envelope.Result.Usage.runtimeUsage()
			if envelope.Result.SessionID != "" {
				result.Session = a.sessionRef(envelope.Result.SessionID, effective)
			}
		case "error":
			runnerErr = envelope.Message
		}
		return nil
	})
	if err != nil {
		return relayruntime.RunResult{}, fmt.Errorf("external runtime %s: %w", a.id, err)
	}
	if runnerErr != "" {
		return relayruntime.RunResult{}, fmt.Errorf("external runtime %s reported an error: %s", a.id, relayruntime.SafeSummary(runnerErr))
	}
	if strings.TrimSpace(result.FinalText) == "" {
		return relayruntime.RunResult{}, fmt.Errorf("external runtime %s: %w", a.id, relayruntime.ErrNoFinalAnswer)
	}
	if err := relayruntime.Emit(runCtx, sink, relayruntime.Event{Type: relayruntime.EventCompleted, Summary: a.name + " response ready", Session: result.Session, Usage: &result.Usage}); err != nil {
		return relayruntime.RunResult{}, err
	}
	return result, nil
}

func genericRunnerEvent(input relayruntime.Event) relayruntime.Event {
	event := relayruntime.Event{Type: input.Type, Tool: input.Tool, Usage: input.Usage}
	switch input.Type {
	case relayruntime.EventStarting:
		event.Summary = "External runtime started"
	case relayruntime.EventSession:
		event.Summary = "External runtime session connected"
	case relayruntime.EventToolStarted:
		event.Summary = "External runtime tool started"
	case relayruntime.EventToolFinished:
		event.Summary = "External runtime tool finished"
	case relayruntime.EventFinishing:
		event.Summary = "External runtime is finishing"
	case relayruntime.EventCompleted:
		event.Summary = "External runtime response ready"
	case relayruntime.EventWarning:
		event.Summary = "External runtime reported a warning"
	default:
		event.Type = relayruntime.EventProgress
		event.Summary = "External runtime is working"
	}
	return event
}

func (a *Adapter) sessionRef(id string, policy relayruntime.Policy) *relayruntime.SessionRef {
	return &relayruntime.SessionRef{
		RuntimeID:          a.id,
		OpaqueID:           id,
		PolicyFingerprint:  relayruntime.PolicyFingerprint(policy),
		WorkDirFingerprint: relayruntime.WorkDirFingerprint(a.workDir),
	}
}

func sanitizeCapabilities(id, name string, policy relayruntime.Policy, input runnerCapabilities) relayruntime.Capabilities {
	return relayruntime.Capabilities{
		RuntimeID:              id,
		DisplayName:            name,
		Version:                relayruntime.SafeSummary(input.Version),
		SupportsResume:         input.SupportsResume,
		SupportsStreaming:      input.SupportsStreaming,
		SupportsModelSelection: input.SupportsModelSelection,
		PreservesLocalContext:  input.PreservesLocalContext,
		LoadsLocalMCPs:         input.LoadsLocalMCPs && policy.AllowMCPs,
		Policy: relayruntime.PolicyCapabilities{
			ReadOnly:               validEnforcement(input.Policy.ReadOnly),
			GuardedWrite:           validEnforcement(input.Policy.GuardedWrite),
			FilesystemIsolation:    validEnforcement(input.Policy.FilesystemIsolation),
			NetworkIsolation:       validEnforcement(input.Policy.NetworkIsolation),
			ShellControl:           validEnforcement(input.Policy.ShellControl),
			MCPControl:             validEnforcement(input.Policy.MCPControl),
			DestructiveCommandDeny: validEnforcement(input.Policy.DestructiveCommandDeny),
		},
	}
}

func isShellExecutable(executable string) bool {
	name := strings.ToLower(filepath.Base(executable))
	name = strings.TrimSuffix(name, filepath.Ext(name))
	switch name {
	case "sh", "bash", "zsh", "fish", "cmd", "powershell", "pwsh":
		return true
	default:
		return false
	}
}

func validEnforcement(value relayruntime.Enforcement) relayruntime.Enforcement {
	switch value {
	case relayruntime.EnforcementNative, relayruntime.EnforcementToolLevel, relayruntime.EnforcementBestEffort, relayruntime.EnforcementUnsupported:
		return value
	default:
		return relayruntime.EnforcementUnsupported
	}
}

type runnerInput struct {
	Protocol        string                   `json:"protocol"`
	Type            string                   `json:"type"`
	RequestID       string                   `json:"request_id,omitempty"`
	ConversationID  string                   `json:"conversation_id,omitempty"`
	Title           string                   `json:"title,omitempty"`
	Requester       string                   `json:"requester,omitempty"`
	Prompt          string                   `json:"prompt,omitempty"`
	Model           string                   `json:"model,omitempty"`
	WorkDir         string                   `json:"work_dir,omitempty"`
	Attachments     []string                 `json:"attachments,omitempty"`
	Workspaces      []relayruntime.Workspace `json:"workspaces,omitempty"`
	ReturnDirectory string                   `json:"return_directory,omitempty"`
	Policy          relayruntime.Policy      `json:"policy,omitempty"`
	SessionID       string                   `json:"session_id,omitempty"`
}

type runnerOutput struct {
	Protocol     string              `json:"protocol"`
	Type         string              `json:"type"`
	Message      string              `json:"message,omitempty"`
	SessionID    string              `json:"session_id,omitempty"`
	Capabilities *runnerCapabilities `json:"capabilities,omitempty"`
	Event        *runnerEvent        `json:"event,omitempty"`
	Result       *runnerResult       `json:"result,omitempty"`
}

type runnerCapabilities struct {
	Version                string                          `json:"version,omitempty"`
	SupportsResume         bool                            `json:"supports_resume"`
	SupportsStreaming      bool                            `json:"supports_streaming"`
	SupportsModelSelection bool                            `json:"supports_model_selection"`
	PreservesLocalContext  bool                            `json:"preserves_local_context"`
	LoadsLocalMCPs         bool                            `json:"loads_local_mcps"`
	Policy                 relayruntime.PolicyCapabilities `json:"policy"`
}

type runnerResult struct {
	FinalText string      `json:"final_text"`
	SessionID string      `json:"session_id,omitempty"`
	Usage     runnerUsage `json:"usage,omitempty"`
}

type runnerEvent struct {
	Type    relayruntime.EventType `json:"type"`
	Summary string                 `json:"summary,omitempty"`
	Tool    string                 `json:"tool,omitempty"`
	Usage   *runnerUsage           `json:"usage,omitempty"`
}

type runnerUsage struct {
	InputTokens  int64   `json:"input_tokens,omitempty"`
	OutputTokens int64   `json:"output_tokens,omitempty"`
	CachedTokens int64   `json:"cached_tokens,omitempty"`
	CostUSD      float64 `json:"cost_usd,omitempty"`
	DurationMS   int64   `json:"duration_ms,omitempty"`
}

func (u runnerUsage) runtimeUsage() relayruntime.Usage {
	return relayruntime.Usage{
		InputTokens: u.InputTokens, OutputTokens: u.OutputTokens, CachedTokens: u.CachedTokens,
		CostUSD: u.CostUSD, Duration: time.Duration(u.DurationMS) * time.Millisecond,
	}
}

func (e runnerEvent) runtimeEvent() relayruntime.Event {
	result := relayruntime.Event{Type: e.Type, Summary: e.Summary, Tool: e.Tool}
	if e.Usage != nil {
		usage := e.Usage.runtimeUsage()
		result.Usage = &usage
	}
	return result
}

var _ relayruntime.Adapter = (*Adapter)(nil)
