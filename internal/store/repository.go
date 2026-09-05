package store

import (
	"context"

	"github.com/mohitbadwal/team-relay/internal/auth"
)

// Repository is intentionally small and Redis-compatible. A relay can use
// Redis or Valkey without changing any HTTP or authentication behavior.
type Repository interface {
	Ping(context.Context) error
	IsBootstrapped(context.Context) (bool, error)
	Bootstrap(context.Context, BootstrapInput) (BootstrapResult, error)
	Authenticate(context.Context, string) (auth.Principal, error)
	RotateAdminCredential(context.Context, auth.Principal, RotateAdminCredentialInput) (RotateAdminCredentialResult, error)

	CreateInvite(context.Context, auth.Principal, CreateInviteInput) (Invite, error)
	ListInvites(context.Context, auth.Principal) ([]Invite, error)
	RevokeInvite(context.Context, auth.Principal, string) error
	Enroll(context.Context, string, EnrollInput) (EnrollResult, error)

	ListMembers(context.Context, auth.Principal) ([]Member, error)
	RevokeMember(context.Context, auth.Principal, string) (RevocationResult, error)
	ListDevices(context.Context, auth.Principal, string) ([]Device, error)
	RevokeDevice(context.Context, auth.Principal, string) (RevocationResult, error)
	ListAuditEvents(context.Context, auth.Principal, int) ([]AuditEvent, error)
}
