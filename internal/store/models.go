package store

import (
	"time"

	"github.com/mohitbadwal/team-relay/internal/auth"
)

type Status string

const (
	StatusActive  Status = "active"
	StatusPending Status = "pending"
	StatusExpired Status = "expired"
	StatusUsed    Status = "used"
	StatusRevoked Status = "revoked"
)

type Organization struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

type Member struct {
	ID             string     `json:"id"`
	OrganizationID string     `json:"organization_id"`
	DisplayName    string     `json:"display_name"`
	Email          string     `json:"email,omitempty"`
	Role           auth.Role  `json:"role"`
	Status         Status     `json:"status"`
	CreatedAt      time.Time  `json:"created_at"`
	RevokedAt      *time.Time `json:"revoked_at,omitempty"`
}

// Device represents a receiver installation. AgentID is the stable identifier
// exposed to the collaboration protocol; Device.ID is the administration ID.
type Device struct {
	ID                string     `json:"id"`
	OrganizationID    string     `json:"organization_id"`
	MemberID          string     `json:"member_id"`
	AgentID           string     `json:"agent_id"`
	Name              string     `json:"name"`
	Runtime           string     `json:"runtime,omitempty"`
	PermissionProfile string     `json:"permission_profile,omitempty"`
	Status            Status     `json:"status"`
	CreatedAt         time.Time  `json:"created_at"`
	LastSeenAt        *time.Time `json:"last_seen_at,omitempty"`
	RevokedAt         *time.Time `json:"revoked_at,omitempty"`
}

type Invite struct {
	ID             string     `json:"id"`
	OrganizationID string     `json:"organization_id"`
	CreatedBy      string     `json:"created_by"`
	MemberID       string     `json:"member_id,omitempty"`
	DisplayName    string     `json:"display_name,omitempty"`
	Email          string     `json:"email,omitempty"`
	Status         Status     `json:"status"`
	CreatedAt      time.Time  `json:"created_at"`
	ExpiresAt      time.Time  `json:"expires_at"`
	UsedAt         *time.Time `json:"used_at,omitempty"`
	UsedByMemberID string     `json:"used_by_member_id,omitempty"`
	RevokedAt      *time.Time `json:"revoked_at,omitempty"`
}

type AuditEvent struct {
	ID             string         `json:"id"`
	OrganizationID string         `json:"organization_id"`
	ActorMemberID  string         `json:"actor_member_id,omitempty"`
	ActorDeviceID  string         `json:"actor_device_id,omitempty"`
	Action         string         `json:"action"`
	TargetType     string         `json:"target_type,omitempty"`
	TargetID       string         `json:"target_id,omitempty"`
	OccurredAt     time.Time      `json:"occurred_at"`
	Metadata       map[string]any `json:"metadata,omitempty"`
}

type BootstrapInput struct {
	OrganizationName string
	AdminDisplayName string
	AdminEmail       string
	AdminTokenHash   string
	IdempotencyHash  string
	Now              time.Time
}

type BootstrapResult struct {
	Organization Organization
	Admin        Member
}

type RotateAdminCredentialInput struct {
	NewTokenHash    string
	IdempotencyHash string
	Now             time.Time
}

type RotateAdminCredentialResult struct {
	RotatedAt time.Time `json:"rotated_at"`
	Replayed  bool      `json:"replayed"`
}

// RevocationResult identifies collaboration agents whose presence and live
// subscriptions must be evicted after the authoritative credential revocation
// commits. Agent IDs are random, non-reusable device identities.
type RevocationResult struct {
	OrganizationID string
	AgentIDs       []string
}

type CreateInviteInput struct {
	DisplayName      string
	Email            string
	ExistingMemberID string
	ExpiresAt        time.Time
	InviteTokenHash  string
	Now              time.Time
}

type EnrollInput struct {
	DisplayName        string
	DeviceName         string
	Runtime            string
	PermissionProfile  string
	DeviceTokenHash    string
	IdempotencyKeyHash string
	Now                time.Time
}

type EnrollResult struct {
	Organization Organization `json:"organization"`
	Member       Member       `json:"member"`
	Device       Device       `json:"device"`
}
