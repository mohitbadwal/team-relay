// Package protocol contains the provider-neutral wire types shared by the
// relay, local receiver, and requester MCP.
package protocol

import "time"

const (
	APIVersion             = "v1"
	MaxNeedBytes           = 200
	MaxAttachments         = 5
	MaxAttachmentBytes     = int64(2 * 1024 * 1024)
	MaxRequestPayloadBytes = int64(2 * 1024 * 1024)
	MaxPromptBytes         = 32 * 1024
	MaxTitleBytes          = 200
)

// PermissionMode is the access requested by a sender or configured by a
// recipient. The recipient-local policy is authoritative: a request may be
// downgraded but can never upgrade that policy.
type PermissionMode string

const (
	PermissionReadOnly     PermissionMode = "read_only"
	PermissionGuardedWrite PermissionMode = "guarded_write"
	PermissionCustom       PermissionMode = "custom"
)

func (m PermissionMode) Valid() bool {
	switch m {
	case PermissionReadOnly, PermissionGuardedWrite, PermissionCustom:
		return true
	default:
		return false
	}
}

type Availability string

const (
	AvailabilityAvailable Availability = "available"
	AvailabilityBusy      Availability = "busy"
	AvailabilityAway      Availability = "away"
	AvailabilityOffline   Availability = "offline"
)

type RuntimeCapabilities struct {
	Resume           bool `json:"resume"`
	StructuredEvents bool `json:"structured_events"`
	Skills           bool `json:"skills"`
	MCP              bool `json:"mcp"`
	ReadOnly         bool `json:"read_only"`
	GuardedWrite     bool `json:"guarded_write"`
	ReturnedFiles    bool `json:"returned_files"`
}

type RuntimeDescriptor struct {
	ID           string              `json:"id"`
	DisplayName  string              `json:"display_name"`
	Version      string              `json:"version,omitempty"`
	Capabilities RuntimeCapabilities `json:"capabilities"`
}

// AgentCard intentionally contains aliases and capabilities, never local paths,
// runtime credentials, private session IDs, or provider configuration.
type AgentCard struct {
	AgentID           string            `json:"agent_id"`
	MemberID          string            `json:"member_id"`
	DisplayName       string            `json:"display_name"`
	DeviceName        string            `json:"device_name,omitempty"`
	Availability      Availability      `json:"availability"`
	AcceptingRequests bool              `json:"accepting_requests"`
	Runtime           RuntimeDescriptor `json:"runtime"`
	PermissionMode    PermissionMode    `json:"permission_mode"`
	Capabilities      []string          `json:"capabilities,omitempty"`
	WorkspaceAliases  []string          `json:"workspace_aliases,omitempty"`
	Online            bool              `json:"online"`
	LastSeen          time.Time         `json:"last_seen"`
}

type AgentHeartbeat struct {
	DisplayName       string            `json:"display_name"`
	DeviceName        string            `json:"device_name,omitempty"`
	Availability      Availability      `json:"availability"`
	AcceptingRequests bool              `json:"accepting_requests"`
	Runtime           RuntimeDescriptor `json:"runtime"`
	PermissionMode    PermissionMode    `json:"permission_mode"`
	Capabilities      []string          `json:"capabilities,omitempty"`
	WorkspaceAliases  []string          `json:"workspace_aliases,omitempty"`
}

type AgentDirectoryResponse struct {
	Agents     []AgentCard `json:"agents"`
	ObservedAt time.Time   `json:"observed_at"`
}

type InboxResponse struct {
	Requests   []RequestNotice `json:"requests"`
	ObservedAt time.Time       `json:"observed_at"`
}

type RequestedAccess struct {
	WorkspaceAlias string         `json:"workspace_alias"`
	Mode           PermissionMode `json:"mode"`
}

// AttachmentInput is accepted only on authenticated request/result calls.
// Content is omitted from event notifications.
type AttachmentInput struct {
	Name          string `json:"name"`
	MIMEType      string `json:"mime_type"`
	Encoding      string `json:"encoding"`
	SizeBytes     int64  `json:"size_bytes"`
	SHA256        string `json:"sha256"`
	ContentBase64 string `json:"content_base64"`
}

type ArtifactDescriptor struct {
	ArtifactID string `json:"artifact_id"`
	Name       string `json:"name"`
	MIMEType   string `json:"mime_type"`
	SizeBytes  int64  `json:"size_bytes"`
	SHA256     string `json:"sha256"`
}

type ArtifactContent struct {
	ArtifactDescriptor
	Encoding      string `json:"encoding"`
	ContentBase64 string `json:"content_base64"`
}

type RequestStatus string

const (
	StatusPreparing        RequestStatus = "preparing"
	StatusAwaitingApproval RequestStatus = "awaiting_approval"
	StatusAccepted         RequestStatus = "accepted"
	StatusRunning          RequestStatus = "running"
	StatusCompleted        RequestStatus = "completed"
	StatusRejected         RequestStatus = "rejected"
	StatusExpired          RequestStatus = "expired"
	StatusCancelled        RequestStatus = "cancelled"
	StatusFailed           RequestStatus = "failed"
)

func (s RequestStatus) Terminal() bool {
	switch s {
	case StatusCompleted, StatusRejected, StatusExpired, StatusCancelled, StatusFailed:
		return true
	default:
		return false
	}
}

type CreateRequest struct {
	TargetAgentID    string            `json:"target_agent_id,omitempty"`
	ConversationID   string            `json:"conversation_id,omitempty"`
	Title            string            `json:"title"`
	Prompt           string            `json:"prompt"`
	RequestedAccess  []RequestedAccess `json:"requested_access,omitempty"`
	Attachments      []AttachmentInput `json:"attachments,omitempty"`
	ExpiresInSeconds int               `json:"expires_in_seconds,omitempty"`
	IdempotencyKey   string            `json:"idempotency_key"`
}

type Request struct {
	APIVersion           string               `json:"api_version"`
	RequestID            string               `json:"request_id"`
	ConversationID       string               `json:"conversation_id"`
	RequesterAgentID     string               `json:"requester_agent_id"`
	RequesterMemberID    string               `json:"requester_member_id,omitempty"`
	RequesterDisplayName string               `json:"requester_display_name"`
	TargetAgentID        string               `json:"target_agent_id"`
	Title                string               `json:"title"`
	Prompt               string               `json:"prompt,omitempty"`
	PromptPreview        string               `json:"prompt_preview"`
	PromptBytes          int64                `json:"prompt_bytes"`
	PromptSHA256         string               `json:"prompt_sha256"`
	RequestedAccess      []RequestedAccess    `json:"requested_access,omitempty"`
	Attachments          []ArtifactDescriptor `json:"attachments,omitempty"`
	ResultFiles          []ArtifactDescriptor `json:"result_files,omitempty"`
	Status               RequestStatus        `json:"status"`
	Answer               string               `json:"answer,omitempty"`
	Error                string               `json:"error,omitempty"`
	CreatedAt            time.Time            `json:"created_at"`
	UpdatedAt            time.Time            `json:"updated_at"`
	ExpiresAt            time.Time            `json:"expires_at"`
	Version              int64                `json:"version"`
}

// RequestNotice is safe for event delivery before approval. The full prompt
// and attachment bytes are deliberately absent.
type RequestNotice struct {
	RequestID            string               `json:"request_id"`
	ConversationID       string               `json:"conversation_id"`
	Status               RequestStatus        `json:"status"`
	RequesterAgentID     string               `json:"requester_agent_id"`
	RequesterMemberID    string               `json:"requester_member_id,omitempty"`
	RequesterDisplayName string               `json:"requester_display_name"`
	Title                string               `json:"title"`
	PromptPreview        string               `json:"prompt_preview"`
	PromptBytes          int64                `json:"prompt_bytes"`
	PromptSHA256         string               `json:"prompt_sha256"`
	RequestedAccess      []RequestedAccess    `json:"requested_access,omitempty"`
	Attachments          []ArtifactDescriptor `json:"attachments,omitempty"`
	CreatedAt            time.Time            `json:"created_at"`
	ExpiresAt            time.Time            `json:"expires_at"`
	ResumesSession       bool                 `json:"resumes_session,omitempty"`
}

type ExecutionPayload struct {
	RequestID            string               `json:"request_id"`
	ConversationID       string               `json:"conversation_id"`
	RequesterAgentID     string               `json:"requester_agent_id"`
	RequesterMemberID    string               `json:"requester_member_id,omitempty"`
	RequesterDisplayName string               `json:"requester_display_name"`
	Title                string               `json:"title"`
	Prompt               string               `json:"prompt"`
	RequestedAccess      []RequestedAccess    `json:"requested_access,omitempty"`
	Attachments          []ArtifactDescriptor `json:"attachments,omitempty"`
	ExpiresAt            time.Time            `json:"expires_at"`
}

// ProposalPayload is available only to the exact target for explicit human
// inspection before approval. It contains no attachment bytes or local paths.
type ProposalPayload struct {
	RequestID            string               `json:"request_id"`
	ConversationID       string               `json:"conversation_id"`
	RequesterAgentID     string               `json:"requester_agent_id"`
	RequesterMemberID    string               `json:"requester_member_id,omitempty"`
	RequesterDisplayName string               `json:"requester_display_name"`
	Title                string               `json:"title"`
	Prompt               string               `json:"prompt"`
	RequestedAccess      []RequestedAccess    `json:"requested_access,omitempty"`
	Attachments          []ArtifactDescriptor `json:"attachments,omitempty"`
	ExpiresAt            time.Time            `json:"expires_at"`
}

type Decision string

const (
	DecisionAllowOnce Decision = "allow_once"
	DecisionDeny      Decision = "deny"
)

type DecisionPayload struct {
	Decision Decision `json:"decision"`
	// DecisionID is generated and durably stored by the recipient before the
	// mutation. It makes an exact Allow Once or Deny retry distinguishable from
	// a second human decision after an ambiguous transport response.
	DecisionID string `json:"decision_id"`
}

// ExecutionClaimPayload identifies one recipient-side attempt to execute an
// approved request. The claim is intentionally absent from request status and
// inbox responses; only the daemon that generated it needs to retain it.
type ExecutionClaimPayload struct {
	ExecutionClaimID string `json:"execution_claim_id"`
}

type ResultPayload struct {
	// ExecutionClaimID also scopes the server-side exact-result digest, so only
	// the winning recipient execution can replay its terminal mutation.
	ExecutionClaimID string            `json:"execution_claim_id"`
	State            RequestStatus     `json:"state"`
	Answer           string            `json:"answer,omitempty"`
	Error            string            `json:"error,omitempty"`
	ResultFiles      []AttachmentInput `json:"result_files,omitempty"`
}

type MutationResponse struct {
	RequestID      string        `json:"request_id"`
	ConversationID string        `json:"conversation_id"`
	Status         RequestStatus `json:"status"`
}

type ErrorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code,omitempty"`
}
