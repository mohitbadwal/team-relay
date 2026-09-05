package auth

import "time"

type Role string

const (
	RoleAdmin  Role = "admin"
	RoleMember Role = "member"
)

// Principal is derived exclusively from a bearer credential stored by the
// relay. HTTP headers asserted by reverse proxies are never authoritative.
type Principal struct {
	OrganizationID string    `json:"organization_id"`
	MemberID       string    `json:"member_id"`
	DeviceID       string    `json:"device_id,omitempty"`
	AgentID        string    `json:"agent_id,omitempty"`
	DisplayName    string    `json:"display_name,omitempty"`
	DeviceName     string    `json:"device_name,omitempty"`
	Runtime        string    `json:"runtime,omitempty"`
	PermissionMode string    `json:"permission_mode,omitempty"`
	CredentialHash string    `json:"-"`
	Role           Role      `json:"role"`
	TokenKind      TokenKind `json:"token_kind"`
	IssuedAt       time.Time `json:"issued_at"`
}

func (p Principal) IsAdmin() bool {
	return p.Role == RoleAdmin && p.TokenKind == TokenAdmin
}
