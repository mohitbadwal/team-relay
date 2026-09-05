// Package runtime defines the provider-neutral contract used by recipient-side
// agent runtimes. Runtime implementations are local: relay requests never get
// to select an executable, model, working directory, or stronger policy.
package runtime

import (
	"context"
	"errors"
	"time"
)

const RunnerProtocolV1 = "team-relay-runner/v1"

var (
	ErrUnavailable       = errors.New("runtime unavailable")
	ErrInvalidRequest    = errors.New("invalid runtime request")
	ErrUnsupportedPolicy = errors.New("runtime cannot enforce the requested policy")
	ErrNoFinalAnswer     = errors.New("runtime returned no final answer")
)

// Adapter is implemented by each local agent runtime.
type Adapter interface {
	ID() string
	ConfiguredPolicy() Policy
	WorkDirFingerprint() string
	// ApprovalFingerprint is a secret-safe digest of the complete recipient-owned
	// runtime configuration used to execute approved requests. Implementations
	// freeze any dynamically discovered authority (such as MCP inventory) before
	// calculating it and reuse that same snapshot for every subsequent Run.
	ApprovalFingerprint() (string, error)
	Probe(context.Context) (Capabilities, error)
	Run(context.Context, RunRequest, EventSink) (RunResult, error)
}

// Enforcement describes how strongly a runtime can apply a policy control.
// Unsupported controls are never silently represented as enforced.
type Enforcement string

const (
	EnforcementNative      Enforcement = "native"
	EnforcementToolLevel   Enforcement = "tool_level"
	EnforcementBestEffort  Enforcement = "best_effort"
	EnforcementUnsupported Enforcement = "unsupported"
)

// PolicyCapabilities makes setup UIs able to explain the actual strength of
// each runtime rather than pretending every CLI has an OS sandbox.
type PolicyCapabilities struct {
	ReadOnly               Enforcement `json:"read_only" yaml:"read_only"`
	GuardedWrite           Enforcement `json:"guarded_write" yaml:"guarded_write"`
	FilesystemIsolation    Enforcement `json:"filesystem_isolation" yaml:"filesystem_isolation"`
	NetworkIsolation       Enforcement `json:"network_isolation" yaml:"network_isolation"`
	ShellControl           Enforcement `json:"shell_control" yaml:"shell_control"`
	MCPControl             Enforcement `json:"mcp_control" yaml:"mcp_control"`
	DestructiveCommandDeny Enforcement `json:"destructive_command_deny" yaml:"destructive_command_deny"`
}

type Capabilities struct {
	RuntimeID              string             `json:"runtime_id" yaml:"runtime_id"`
	DisplayName            string             `json:"display_name" yaml:"display_name"`
	Version                string             `json:"version,omitempty" yaml:"version,omitempty"`
	Available              bool               `json:"available" yaml:"available"`
	Detail                 string             `json:"detail,omitempty" yaml:"detail,omitempty"`
	SupportsResume         bool               `json:"supports_resume" yaml:"supports_resume"`
	SupportsStreaming      bool               `json:"supports_streaming" yaml:"supports_streaming"`
	SupportsModelSelection bool               `json:"supports_model_selection" yaml:"supports_model_selection"`
	PreservesLocalContext  bool               `json:"preserves_local_context" yaml:"preserves_local_context"`
	LoadsLocalMCPs         bool               `json:"loads_local_mcps" yaml:"loads_local_mcps"`
	Policy                 PolicyCapabilities `json:"policy" yaml:"policy"`
}

type Workspace struct {
	// Path is resolved from a recipient-owned alias before it reaches a runtime.
	// The network request must never supply an absolute local path directly.
	Path string        `json:"path"`
	Mode WorkspaceMode `json:"mode"`
}

type WorkspaceMode string

const (
	WorkspaceReadOnly WorkspaceMode = "read_only"
	WorkspaceWritable WorkspaceMode = "writable"
)

// RunRequest contains only request data and recipient-resolved paths. Provider,
// executable, model and maximum permissions intentionally do not appear here.
type RunRequest struct {
	RequestID       string         `json:"request_id"`
	ConversationID  string         `json:"conversation_id"`
	Title           string         `json:"title,omitempty"`
	Requester       string         `json:"requester,omitempty"`
	Prompt          string         `json:"prompt"`
	Attachments     []string       `json:"attachments,omitempty"`
	Workspaces      []Workspace    `json:"workspaces,omitempty"`
	ReturnDirectory string         `json:"return_directory,omitempty"`
	RequestedPolicy *PolicyRequest `json:"requested_policy,omitempty"`
	Session         *SessionRef    `json:"session,omitempty"`
}

type SessionRef struct {
	RuntimeID          string `json:"runtime_id"`
	OpaqueID           string `json:"opaque_id"`
	PolicyFingerprint  string `json:"policy_fingerprint"`
	WorkDirFingerprint string `json:"work_dir_fingerprint"`
}

type Usage struct {
	InputTokens  int64         `json:"input_tokens,omitempty"`
	OutputTokens int64         `json:"output_tokens,omitempty"`
	CachedTokens int64         `json:"cached_tokens,omitempty"`
	CostUSD      float64       `json:"cost_usd,omitempty"`
	Duration     time.Duration `json:"duration,omitempty"`
}

type RunResult struct {
	FinalText       string      `json:"final_text"`
	Session         *SessionRef `json:"session,omitempty"`
	Usage           Usage       `json:"usage,omitempty"`
	EffectivePolicy Policy      `json:"effective_policy"`
}

type EventType string

const (
	EventStarting     EventType = "starting"
	EventSession      EventType = "session"
	EventProgress     EventType = "progress"
	EventToolStarted  EventType = "tool_started"
	EventToolFinished EventType = "tool_finished"
	EventFinishing    EventType = "finishing"
	EventCompleted    EventType = "completed"
	EventWarning      EventType = "warning"
)

// Event is deliberately normalized and bounded. Raw provider output and tool
// inputs can contain prompts, file content, or credentials and are not exposed.
type Event struct {
	Type    EventType   `json:"type"`
	At      time.Time   `json:"at"`
	Summary string      `json:"summary,omitempty"`
	Tool    string      `json:"tool,omitempty"`
	Session *SessionRef `json:"session,omitempty"`
	Usage   *Usage      `json:"usage,omitempty"`
}

type EventSink interface {
	Emit(context.Context, Event) error
}

type EventSinkFunc func(context.Context, Event) error

func (f EventSinkFunc) Emit(ctx context.Context, event Event) error {
	if f == nil {
		return nil
	}
	return f(ctx, event)
}

type discardSink struct{}

func (discardSink) Emit(context.Context, Event) error { return nil }

func SinkOrDiscard(sink EventSink) EventSink {
	if sink == nil {
		return discardSink{}
	}
	return sink
}
