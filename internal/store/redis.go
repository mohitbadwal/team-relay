package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/mohitbadwal/team-relay/internal/auth"
	"github.com/mohitbadwal/team-relay/internal/keyspace"
	"github.com/redis/go-redis/v9"
)

const (
	keyPrefix            = "team-relay:v1:"
	bootstrapCompleteKey = keyPrefix + "bootstrap:complete"
	bootstrapRecordKey   = keyPrefix + "bootstrap:record"
	maximumAuditEvents   = 10_000
)

type credential struct {
	Kind           auth.TokenKind `json:"kind"`
	OrganizationID string         `json:"organization_id"`
	MemberID       string         `json:"member_id"`
	DeviceID       string         `json:"device_id,omitempty"`
	IssuedAt       time.Time      `json:"issued_at"`
}

type inviteReference struct {
	OrganizationID string `json:"organization_id"`
	InviteID       string `json:"invite_id"`
}

type enrollmentRecord struct {
	InviteTokenHash string       `json:"invite_token_hash"`
	RequestHash     string       `json:"request_hash"`
	DeviceTokenHash string       `json:"device_token_hash"`
	Result          EnrollResult `json:"result"`
}

type bootstrapRecord struct {
	IdempotencyHash string          `json:"idempotency_hash"`
	RequestHash     string          `json:"request_hash"`
	AdminTokenHash  string          `json:"admin_token_hash"`
	Result          BootstrapResult `json:"result"`
}

type adminRotationRecord struct {
	OrganizationID  string    `json:"organization_id"`
	MemberID        string    `json:"member_id"`
	IdempotencyHash string    `json:"idempotency_hash"`
	RequestHash     string    `json:"request_hash"`
	OldTokenHash    string    `json:"old_token_hash"`
	NewTokenHash    string    `json:"new_token_hash"`
	RotatedAt       time.Time `json:"rotated_at"`
}

var errExactReplay = errors.New("exact idempotent replay")

type RedisStore struct {
	rdb *redis.Client
}

func NewRedis(rdb *redis.Client) *RedisStore {
	return &RedisStore{rdb: rdb}
}

func (s *RedisStore) Ping(ctx context.Context) error {
	return s.rdb.Ping(ctx).Err()
}

func (s *RedisStore) IsBootstrapped(ctx context.Context) (bool, error) {
	count, err := s.rdb.Exists(ctx, bootstrapCompleteKey).Result()
	return count == 1, err
}

func (s *RedisStore) Bootstrap(ctx context.Context, in BootstrapInput) (BootstrapResult, error) {
	in.OrganizationName = clean(in.OrganizationName)
	in.AdminDisplayName = clean(in.AdminDisplayName)
	in.AdminEmail = normalizeEmail(in.AdminEmail)
	in.AdminTokenHash = strings.ToLower(in.AdminTokenHash)
	in.IdempotencyHash = strings.ToLower(in.IdempotencyHash)
	in.Now = normalizedTime(in.Now)
	if !validLabel(in.OrganizationName, 120) || !validLabel(in.AdminDisplayName, 100) ||
		!validEmail(in.AdminEmail) || !validHash(in.AdminTokenHash) || !validHash(in.IdempotencyHash) {
		return BootstrapResult{}, ErrInvalid
	}
	requestHash := digestJSON(struct {
		OrganizationName string `json:"organization_name"`
		AdminDisplayName string `json:"admin_display_name"`
		AdminEmail       string `json:"admin_email"`
		AdminTokenHash   string `json:"admin_token_hash"`
	}{in.OrganizationName, in.AdminDisplayName, in.AdminEmail, in.AdminTokenHash})

	organization := Organization{
		ID:        randomID("org_"),
		Name:      in.OrganizationName,
		CreatedAt: in.Now,
	}
	member := Member{
		ID:             randomID("mem_"),
		OrganizationID: organization.ID,
		DisplayName:    in.AdminDisplayName,
		Email:          in.AdminEmail,
		Role:           auth.RoleAdmin,
		Status:         StatusActive,
		CreatedAt:      in.Now,
	}
	adminCredential := credential{
		Kind:           auth.TokenAdmin,
		OrganizationID: organization.ID,
		MemberID:       member.ID,
		IssuedAt:       in.Now,
	}
	audit := AuditEvent{
		ID:             randomID("aud_"),
		OrganizationID: organization.ID,
		ActorMemberID:  member.ID,
		Action:         "organization.bootstrapped",
		TargetType:     "organization",
		TargetID:       organization.ID,
		OccurredAt:     in.Now,
	}

	organizationJSON, _ := json.Marshal(organization)
	memberJSON, _ := json.Marshal(member)
	credentialJSON, _ := json.Marshal(adminCredential)
	auditJSON, _ := json.Marshal(audit)
	result := BootstrapResult{Organization: organization, Admin: member}
	bootstrapJSON, _ := json.Marshal(bootstrapRecord{
		IdempotencyHash: in.IdempotencyHash,
		RequestHash:     requestHash,
		AdminTokenHash:  in.AdminTokenHash,
		Result:          result,
	})

	for attempt := 0; attempt < 5; attempt++ {
		var replay BootstrapResult
		err := s.rdb.Watch(ctx, func(tx *redis.Tx) error {
			exists, err := tx.Exists(ctx, bootstrapCompleteKey).Result()
			if err != nil {
				return err
			}
			if exists != 0 {
				record, readErr := readJSON[bootstrapRecord](ctx, tx, bootstrapRecordKey)
				if readErr != nil || record.IdempotencyHash != in.IdempotencyHash ||
					record.RequestHash != requestHash || record.AdminTokenHash != in.AdminTokenHash {
					return ErrAlreadyBootstrapped
				}
				current, readErr := readJSON[credential](ctx, tx, credentialKey(record.AdminTokenHash))
				if readErr != nil {
					if !errors.Is(readErr, ErrNotFound) {
						return readErr
					}
					return ErrConflict
				}
				if current.Kind != auth.TokenAdmin ||
					current.OrganizationID != record.Result.Organization.ID || current.MemberID != record.Result.Admin.ID {
					return ErrConflict
				}
				member, readErr := readJSON[Member](ctx, tx, memberKey(record.Result.Organization.ID, record.Result.Admin.ID))
				if readErr != nil {
					if !errors.Is(readErr, ErrNotFound) {
						return readErr
					}
					return ErrConflict
				}
				if member.Status != StatusActive || member.Role != auth.RoleAdmin {
					return ErrConflict
				}
				replay = record.Result
				return errExactReplay
			}
			credentialExists, err := tx.Exists(ctx, credentialKey(in.AdminTokenHash)).Result()
			if err != nil {
				return err
			}
			if credentialExists != 0 {
				// The bootstrap transaction may have committed between the two
				// reads above. Retry so the durable idempotency record is observed.
				return redis.TxFailedErr
			}
			_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.Set(ctx, bootstrapCompleteKey, organization.ID, 0)
				pipe.Set(ctx, bootstrapRecordKey, bootstrapJSON, 0)
				pipe.Set(ctx, organizationKey(organization.ID), organizationJSON, 0)
				pipe.Set(ctx, memberKey(organization.ID, member.ID), memberJSON, 0)
				pipe.SAdd(ctx, membersKey(organization.ID), member.ID)
				pipe.Set(ctx, credentialKey(in.AdminTokenHash), credentialJSON, 0)
				pipe.SAdd(ctx, memberCredentialsKey(organization.ID, member.ID), in.AdminTokenHash)
				pipe.LPush(ctx, auditKey(organization.ID), auditJSON)
				pipe.LTrim(ctx, auditKey(organization.ID), 0, maximumAuditEvents-1)
				return nil
			})
			return err
		}, bootstrapCompleteKey, bootstrapRecordKey, credentialKey(in.AdminTokenHash))
		if errors.Is(err, errExactReplay) {
			return replay, nil
		}
		if errors.Is(err, redis.TxFailedErr) {
			continue
		}
		if err != nil {
			return BootstrapResult{}, err
		}
		return result, nil
	}
	return BootstrapResult{}, fmt.Errorf("bootstrap after concurrent updates: %w", redis.TxFailedErr)
}

func (s *RedisStore) Authenticate(ctx context.Context, rawToken string) (auth.Principal, error) {
	kind, err := auth.Kind(rawToken)
	if err != nil || (kind != auth.TokenAdmin && kind != auth.TokenDevice) {
		return auth.Principal{}, ErrUnauthorized
	}
	raw, err := s.rdb.Get(ctx, credentialKey(auth.Hash(rawToken))).Bytes()
	if errors.Is(err, redis.Nil) {
		return auth.Principal{}, ErrUnauthorized
	}
	if err != nil {
		return auth.Principal{}, err
	}
	var record credential
	if json.Unmarshal(raw, &record) != nil || record.Kind != kind || !validID(record.OrganizationID, "org_") || !validID(record.MemberID, "mem_") {
		return auth.Principal{}, ErrUnauthorized
	}
	member, err := s.readMember(ctx, record.OrganizationID, record.MemberID)
	if err != nil || member.Status != StatusActive {
		if err != nil && !errors.Is(err, ErrNotFound) {
			return auth.Principal{}, err
		}
		return auth.Principal{}, ErrUnauthorized
	}
	principal := auth.Principal{
		OrganizationID: record.OrganizationID,
		MemberID:       record.MemberID,
		CredentialHash: auth.Hash(rawToken),
		Role:           member.Role,
		TokenKind:      record.Kind,
		IssuedAt:       record.IssuedAt,
	}
	if kind == auth.TokenAdmin {
		if member.Role != auth.RoleAdmin || record.DeviceID != "" {
			return auth.Principal{}, ErrUnauthorized
		}
		return principal, nil
	}
	if !validID(record.DeviceID, "dev_") {
		return auth.Principal{}, ErrUnauthorized
	}
	device, err := s.readDevice(ctx, record.OrganizationID, record.DeviceID)
	if err != nil || device.Status != StatusActive || device.MemberID != member.ID {
		if err != nil && !errors.Is(err, ErrNotFound) {
			return auth.Principal{}, err
		}
		return auth.Principal{}, ErrUnauthorized
	}
	principal.DeviceID = device.ID
	principal.AgentID = device.AgentID
	principal.DisplayName = member.DisplayName
	principal.DeviceName = device.Name
	principal.Runtime = device.Runtime
	principal.PermissionMode = device.PermissionProfile
	return principal, nil
}

// RotateAdminCredential atomically installs a new administrator credential and
// invalidates the credential authenticating this request. Raw tokens never
// enter the repository.
func (s *RedisStore) RotateAdminCredential(ctx context.Context, principal auth.Principal, in RotateAdminCredentialInput) (RotateAdminCredentialResult, error) {
	if err := s.requireAdmin(ctx, principal); err != nil {
		return RotateAdminCredentialResult{}, err
	}
	in.Now = normalizedTime(in.Now)
	in.NewTokenHash = strings.ToLower(in.NewTokenHash)
	in.IdempotencyHash = strings.ToLower(in.IdempotencyHash)
	if !validHash(principal.CredentialHash) || !validHash(in.NewTokenHash) || !validHash(in.IdempotencyHash) {
		return RotateAdminCredentialResult{}, ErrInvalid
	}
	oldKey := credentialKey(principal.CredentialHash)
	newKey := credentialKey(in.NewTokenHash)
	rotationKey := adminRotationKey(in.IdempotencyHash)
	requestHash := digestJSON(struct {
		OrganizationID string `json:"organization_id"`
		MemberID       string `json:"member_id"`
		NewTokenHash   string `json:"new_token_hash"`
	}{principal.OrganizationID, principal.MemberID, in.NewTokenHash})
	newCredential, _ := json.Marshal(credential{
		Kind: auth.TokenAdmin, OrganizationID: principal.OrganizationID,
		MemberID: principal.MemberID, IssuedAt: in.Now,
	})
	audit, _ := json.Marshal(AuditEvent{
		ID: randomID("aud_"), OrganizationID: principal.OrganizationID,
		ActorMemberID: principal.MemberID, Action: "admin.credential_rotated",
		TargetType: "member", TargetID: principal.MemberID, OccurredAt: in.Now,
	})
	for attempt := 0; attempt < 5; attempt++ {
		var result RotateAdminCredentialResult
		err := s.rdb.Watch(ctx, func(tx *redis.Tx) error {
			existing, readErr := readJSON[adminRotationRecord](ctx, tx, rotationKey)
			if readErr == nil {
				if existing.OrganizationID != principal.OrganizationID || existing.MemberID != principal.MemberID ||
					existing.IdempotencyHash != in.IdempotencyHash || existing.RequestHash != requestHash ||
					existing.NewTokenHash != in.NewTokenHash {
					return fmt.Errorf("%w: admin rotation idempotency key was used for different content", ErrConflict)
				}
				// A lost-response retry authenticates with the locally staged new
				// credential. The old hash is accepted only for an HTTP request that
				// authenticated before the concurrent rotation committed; a future
				// request cannot authenticate with the deleted old credential.
				if principal.CredentialHash != existing.NewTokenHash && principal.CredentialHash != existing.OldTokenHash {
					return ErrUnauthorized
				}
				result = RotateAdminCredentialResult{RotatedAt: existing.RotatedAt, Replayed: true}
				return errExactReplay
			}
			if !errors.Is(readErr, ErrNotFound) {
				return readErr
			}
			if principal.CredentialHash == in.NewTokenHash {
				return ErrInvalid
			}
			current, err := readJSON[credential](ctx, tx, oldKey)
			if err != nil || current.Kind != auth.TokenAdmin || current.OrganizationID != principal.OrganizationID || current.MemberID != principal.MemberID {
				if err != nil && !errors.Is(err, ErrNotFound) {
					return err
				}
				// A concurrent exact rotation can delete the old credential after
				// the idempotency-record read above. Retry that read before deciding
				// this principal is stale.
				return redis.TxFailedErr
			}
			exists, err := tx.Exists(ctx, newKey).Result()
			if err != nil {
				return err
			}
			if exists != 0 {
				return redis.TxFailedErr
			}
			rotation, _ := json.Marshal(adminRotationRecord{
				OrganizationID: principal.OrganizationID, MemberID: principal.MemberID,
				IdempotencyHash: in.IdempotencyHash, RequestHash: requestHash,
				OldTokenHash: principal.CredentialHash, NewTokenHash: in.NewTokenHash, RotatedAt: in.Now,
			})
			_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.Set(ctx, newKey, newCredential, 0)
				pipe.Del(ctx, oldKey)
				pipe.Set(ctx, rotationKey, rotation, 0)
				pipe.SAdd(ctx, memberCredentialsKey(principal.OrganizationID, principal.MemberID), in.NewTokenHash)
				pipe.SRem(ctx, memberCredentialsKey(principal.OrganizationID, principal.MemberID), principal.CredentialHash)
				pipe.LPush(ctx, auditKey(principal.OrganizationID), audit)
				pipe.LTrim(ctx, auditKey(principal.OrganizationID), 0, maximumAuditEvents-1)
				return nil
			})
			result = RotateAdminCredentialResult{RotatedAt: in.Now}
			return err
		}, oldKey, newKey, rotationKey)
		if errors.Is(err, errExactReplay) {
			return result, nil
		}
		if errors.Is(err, redis.TxFailedErr) {
			continue
		}
		return result, err
	}
	return RotateAdminCredentialResult{}, fmt.Errorf("rotate admin credential after concurrent updates: %w", redis.TxFailedErr)
}

func (s *RedisStore) CreateInvite(ctx context.Context, principal auth.Principal, in CreateInviteInput) (Invite, error) {
	if err := s.requireAdmin(ctx, principal); err != nil {
		return Invite{}, err
	}
	in.DisplayName = clean(in.DisplayName)
	in.Email = normalizeEmail(in.Email)
	in.ExistingMemberID = clean(in.ExistingMemberID)
	in.Now = normalizedTime(in.Now)
	in.ExpiresAt = in.ExpiresAt.UTC()
	if !validHash(in.InviteTokenHash) || !in.ExpiresAt.After(in.Now) ||
		(in.DisplayName != "" && !validLabel(in.DisplayName, 100)) ||
		(in.Email != "" && !validEmail(in.Email)) {
		return Invite{}, ErrInvalid
	}
	if in.ExistingMemberID == "" && in.DisplayName == "" && in.Email == "" {
		return Invite{}, ErrInvalid
	}
	if in.ExistingMemberID != "" {
		if !validID(in.ExistingMemberID, "mem_") {
			return Invite{}, ErrInvalid
		}
		member, err := s.readMember(ctx, principal.OrganizationID, in.ExistingMemberID)
		if err != nil {
			return Invite{}, err
		}
		if member.Status != StatusActive {
			return Invite{}, ErrConflict
		}
	}

	invite := Invite{
		ID:             randomID("inv_"),
		OrganizationID: principal.OrganizationID,
		CreatedBy:      principal.MemberID,
		MemberID:       in.ExistingMemberID,
		DisplayName:    in.DisplayName,
		Email:          in.Email,
		Status:         StatusPending,
		CreatedAt:      in.Now,
		ExpiresAt:      in.ExpiresAt,
	}
	reference := inviteReference{OrganizationID: invite.OrganizationID, InviteID: invite.ID}
	audit := AuditEvent{
		ID:             randomID("aud_"),
		OrganizationID: invite.OrganizationID,
		ActorMemberID:  principal.MemberID,
		ActorDeviceID:  principal.DeviceID,
		Action:         "invite.created",
		TargetType:     "invite",
		TargetID:       invite.ID,
		OccurredAt:     in.Now,
		Metadata:       map[string]any{"expires_at": invite.ExpiresAt},
	}
	inviteJSON, _ := json.Marshal(invite)
	referenceJSON, _ := json.Marshal(reference)
	auditJSON, _ := json.Marshal(audit)
	retention := invite.ExpiresAt.Add(24 * time.Hour).Sub(in.Now)
	if retention <= 0 {
		retention = 24 * time.Hour
	}
	_, err := s.rdb.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
		pipe.Set(ctx, inviteKey(invite.OrganizationID, invite.ID), inviteJSON, 0)
		pipe.SAdd(ctx, invitesKey(invite.OrganizationID), invite.ID)
		pipe.Set(ctx, inviteTokenKey(in.InviteTokenHash), referenceJSON, retention)
		pipe.Set(ctx, inviteCredentialKey(invite.OrganizationID, invite.ID), in.InviteTokenHash, retention)
		pipe.LPush(ctx, auditKey(invite.OrganizationID), auditJSON)
		pipe.LTrim(ctx, auditKey(invite.OrganizationID), 0, maximumAuditEvents-1)
		return nil
	})
	if err != nil {
		return Invite{}, err
	}
	return invite, nil
}

func (s *RedisStore) ListInvites(ctx context.Context, principal auth.Principal) ([]Invite, error) {
	if err := s.requireAdmin(ctx, principal); err != nil {
		return nil, err
	}
	ids, err := s.rdb.SMembers(ctx, invitesKey(principal.OrganizationID)).Result()
	if err != nil {
		return nil, err
	}
	invites := make([]Invite, 0, len(ids))
	for _, id := range ids {
		invite, err := s.readInvite(ctx, principal.OrganizationID, id)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if invite.Status == StatusPending && !invite.ExpiresAt.After(time.Now().UTC()) {
			invite.Status = StatusExpired
		}
		invites = append(invites, invite)
	}
	sort.Slice(invites, func(i, j int) bool { return invites[i].CreatedAt.After(invites[j].CreatedAt) })
	return invites, nil
}

func (s *RedisStore) RevokeInvite(ctx context.Context, principal auth.Principal, inviteID string) error {
	if err := s.requireAdmin(ctx, principal); err != nil {
		return err
	}
	if !validID(inviteID, "inv_") {
		return ErrNotFound
	}
	key := inviteKey(principal.OrganizationID, inviteID)
	for attempt := 0; attempt < 5; attempt++ {
		err := s.rdb.Watch(ctx, func(tx *redis.Tx) error {
			invite, err := readJSON[Invite](ctx, tx, key)
			if err != nil {
				return err
			}
			if invite.Status == StatusRevoked {
				return nil
			}
			if invite.Status == StatusUsed {
				return ErrConflict
			}
			now := time.Now().UTC()
			invite.Status = StatusRevoked
			invite.RevokedAt = &now
			inviteJSON, _ := json.Marshal(invite)
			auditJSON, _ := json.Marshal(AuditEvent{
				ID: randomID("aud_"), OrganizationID: principal.OrganizationID,
				ActorMemberID: principal.MemberID, ActorDeviceID: principal.DeviceID,
				Action: "invite.revoked", TargetType: "invite", TargetID: invite.ID, OccurredAt: now,
			})
			_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.Set(ctx, key, inviteJSON, 0)
				pipe.Del(ctx, inviteCredentialKey(principal.OrganizationID, invite.ID))
				pipe.LPush(ctx, auditKey(principal.OrganizationID), auditJSON)
				pipe.LTrim(ctx, auditKey(principal.OrganizationID), 0, maximumAuditEvents-1)
				return nil
			})
			return err
		}, key)
		if errors.Is(err, redis.TxFailedErr) {
			continue
		}
		return err
	}
	return fmt.Errorf("revoke invite after concurrent updates: %w", redis.TxFailedErr)
}

func (s *RedisStore) Enroll(ctx context.Context, rawInviteToken string, in EnrollInput) (EnrollResult, error) {
	if kind, err := auth.Kind(rawInviteToken); err != nil || kind != auth.TokenInvite {
		return EnrollResult{}, ErrUnauthorized
	}
	in.DisplayName = clean(in.DisplayName)
	in.DeviceName = clean(in.DeviceName)
	in.Runtime = clean(in.Runtime)
	in.PermissionProfile = clean(in.PermissionProfile)
	in.DeviceTokenHash = strings.ToLower(clean(in.DeviceTokenHash))
	in.IdempotencyKeyHash = strings.ToLower(clean(in.IdempotencyKeyHash))
	in.Now = normalizedTime(in.Now)
	if in.PermissionProfile == "" {
		in.PermissionProfile = "read_only"
	}
	if !validLabel(in.DeviceName, 100) || !validLabel(in.Runtime, 128) ||
		!validPermissionProfile(in.PermissionProfile) || !validHash(in.DeviceTokenHash) || !validHash(in.IdempotencyKeyHash) ||
		(in.DisplayName != "" && !validLabel(in.DisplayName, 100)) {
		return EnrollResult{}, ErrInvalid
	}

	inviteHash := auth.Hash(rawInviteToken)
	requestHash := enrollmentRequestHash(inviteHash, in)
	idempotencyKeyName := enrollmentIdempotencyKey(in.IdempotencyKeyHash)
	if result, found, err := readEnrollmentRecord(ctx, s.rdb, idempotencyKeyName, inviteHash, requestHash); err != nil {
		return EnrollResult{}, err
	} else if found {
		return result, nil
	}
	refRaw, err := s.rdb.Get(ctx, inviteTokenKey(inviteHash)).Bytes()
	if errors.Is(err, redis.Nil) {
		if result, found, retryErr := readEnrollmentRecord(ctx, s.rdb, idempotencyKeyName, inviteHash, requestHash); retryErr != nil {
			return EnrollResult{}, retryErr
		} else if found {
			return result, nil
		}
		return EnrollResult{}, ErrUnauthorized
	}
	if err != nil {
		return EnrollResult{}, err
	}
	var reference inviteReference
	if json.Unmarshal(refRaw, &reference) != nil || !validID(reference.OrganizationID, "org_") || !validID(reference.InviteID, "inv_") {
		return EnrollResult{}, ErrUnauthorized
	}

	inviteKeyName := inviteKey(reference.OrganizationID, reference.InviteID)
	memberID := randomID("mem_")
	deviceID := randomID("dev_")
	agentID := randomID("agent_")
	for attempt := 0; attempt < 5; attempt++ {
		var result EnrollResult
		err := s.rdb.Watch(ctx, func(tx *redis.Tx) error {
			if existing, found, err := readEnrollmentRecord(ctx, tx, idempotencyKeyName, inviteHash, requestHash); err != nil {
				return err
			} else if found {
				result = existing
				return nil
			}
			currentRef, err := tx.Get(ctx, inviteTokenKey(inviteHash)).Bytes()
			if errors.Is(err, redis.Nil) {
				return ErrUnauthorized
			}
			if err != nil {
				return err
			}
			if string(currentRef) != string(refRaw) {
				return ErrUnauthorized
			}
			invite, err := readJSON[Invite](ctx, tx, inviteKeyName)
			if err != nil {
				return err
			}
			switch invite.Status {
			case StatusUsed:
				return ErrInviteUsed
			case StatusRevoked:
				return ErrInviteRevoked
			case StatusPending:
			default:
				return ErrUnauthorized
			}
			if !invite.ExpiresAt.After(in.Now) {
				return ErrInviteExpired
			}
			credentialExists, err := tx.Exists(ctx, credentialKey(in.DeviceTokenHash)).Result()
			if err != nil {
				return err
			}
			if credentialExists != 0 {
				return ErrConflict
			}

			organization, err := readJSON[Organization](ctx, tx, organizationKey(invite.OrganizationID))
			if err != nil {
				return err
			}
			member := Member{
				ID: memberID, OrganizationID: invite.OrganizationID,
				DisplayName: invite.DisplayName, Email: invite.Email,
				Role: auth.RoleMember, Status: StatusActive, CreatedAt: in.Now,
			}
			newMember := invite.MemberID == ""
			if !newMember {
				member, err = readJSON[Member](ctx, tx, memberKey(invite.OrganizationID, invite.MemberID))
				if err != nil {
					return err
				}
				if member.Status != StatusActive {
					return ErrConflict
				}
			} else if member.DisplayName == "" {
				member.DisplayName = in.DisplayName
			}
			if !validLabel(member.DisplayName, 100) {
				return ErrInvalid
			}
			device := Device{
				ID: deviceID, OrganizationID: invite.OrganizationID, MemberID: member.ID,
				AgentID: agentID, Name: in.DeviceName, Runtime: in.Runtime,
				PermissionProfile: in.PermissionProfile, Status: StatusActive, CreatedAt: in.Now,
			}
			deviceCredential := credential{
				Kind: auth.TokenDevice, OrganizationID: invite.OrganizationID,
				MemberID: member.ID, DeviceID: device.ID, IssuedAt: in.Now,
			}
			invite.Status = StatusUsed
			invite.UsedAt = &in.Now
			invite.UsedByMemberID = member.ID
			inviteJSON, _ := json.Marshal(invite)
			memberJSON, _ := json.Marshal(member)
			deviceJSON, _ := json.Marshal(device)
			credentialJSON, _ := json.Marshal(deviceCredential)
			result = EnrollResult{Organization: organization, Member: member, Device: device}
			enrollmentJSON, _ := json.Marshal(enrollmentRecord{
				InviteTokenHash: inviteHash,
				RequestHash:     requestHash,
				DeviceTokenHash: in.DeviceTokenHash,
				Result:          result,
			})
			auditJSON, _ := json.Marshal(AuditEvent{
				ID: randomID("aud_"), OrganizationID: invite.OrganizationID,
				ActorMemberID: member.ID, ActorDeviceID: device.ID,
				Action: "device.enrolled", TargetType: "device", TargetID: device.ID,
				OccurredAt: in.Now, Metadata: map[string]any{"runtime": device.Runtime, "permission_profile": device.PermissionProfile},
			})
			_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.Set(ctx, inviteKeyName, inviteJSON, 0)
				pipe.Del(ctx, inviteCredentialKey(invite.OrganizationID, invite.ID))
				if newMember {
					pipe.Set(ctx, memberKey(invite.OrganizationID, member.ID), memberJSON, 0)
					pipe.SAdd(ctx, membersKey(invite.OrganizationID), member.ID)
				}
				pipe.Set(ctx, deviceKey(invite.OrganizationID, device.ID), deviceJSON, 0)
				pipe.SAdd(ctx, devicesKey(invite.OrganizationID), device.ID)
				pipe.SAdd(ctx, memberDevicesKey(invite.OrganizationID, member.ID), device.ID)
				pipe.Set(ctx, credentialKey(in.DeviceTokenHash), credentialJSON, 0)
				pipe.Set(ctx, deviceCredentialKey(invite.OrganizationID, device.ID), in.DeviceTokenHash, 0)
				pipe.SAdd(ctx, memberCredentialsKey(invite.OrganizationID, member.ID), in.DeviceTokenHash)
				pipe.Set(ctx, idempotencyKeyName, enrollmentJSON, 0)
				pipe.LPush(ctx, auditKey(invite.OrganizationID), auditJSON)
				pipe.LTrim(ctx, auditKey(invite.OrganizationID), 0, maximumAuditEvents-1)
				return nil
			})
			return err
		}, inviteTokenKey(inviteHash), inviteKeyName, idempotencyKeyName, credentialKey(in.DeviceTokenHash))
		if errors.Is(err, redis.TxFailedErr) {
			continue
		}
		if errors.Is(err, ErrInviteUsed) || errors.Is(err, ErrConflict) {
			if existing, found, retryErr := readEnrollmentRecord(ctx, s.rdb, idempotencyKeyName, inviteHash, requestHash); retryErr != nil {
				return EnrollResult{}, retryErr
			} else if found {
				return existing, nil
			}
		}
		if err != nil {
			return EnrollResult{}, err
		}
		return result, nil
	}
	return EnrollResult{}, fmt.Errorf("enroll after concurrent updates: %w", redis.TxFailedErr)
}

func enrollmentRequestHash(inviteTokenHash string, in EnrollInput) string {
	payload, _ := json.Marshal(struct {
		InviteTokenHash   string `json:"invite_token_hash"`
		DisplayName       string `json:"display_name"`
		DeviceName        string `json:"device_name"`
		Runtime           string `json:"runtime"`
		PermissionProfile string `json:"permission_profile"`
		DeviceTokenHash   string `json:"device_token_hash"`
	}{
		InviteTokenHash: inviteTokenHash, DisplayName: in.DisplayName, DeviceName: in.DeviceName,
		Runtime: in.Runtime, PermissionProfile: in.PermissionProfile, DeviceTokenHash: in.DeviceTokenHash,
	})
	return auth.Hash(string(payload))
}

func readEnrollmentRecord(ctx context.Context, getter redisGetter, key, inviteHash, requestHash string) (EnrollResult, bool, error) {
	record, err := readJSON[enrollmentRecord](ctx, getter, key)
	if errors.Is(err, ErrNotFound) {
		return EnrollResult{}, false, nil
	}
	if err != nil {
		return EnrollResult{}, false, err
	}
	if !validHash(record.InviteTokenHash) || !validHash(record.RequestHash) || !validHash(record.DeviceTokenHash) ||
		!validID(record.Result.Organization.ID, "org_") || !validID(record.Result.Member.ID, "mem_") ||
		!validID(record.Result.Device.ID, "dev_") {
		return EnrollResult{}, false, errors.New("stored enrollment idempotency record is invalid")
	}
	if record.InviteTokenHash != inviteHash || record.RequestHash != requestHash {
		return EnrollResult{}, false, ErrConflict
	}
	member, err := readJSON[Member](ctx, getter, memberKey(record.Result.Organization.ID, record.Result.Member.ID))
	if err != nil || member.Status != StatusActive {
		if err != nil && !errors.Is(err, ErrNotFound) {
			return EnrollResult{}, false, err
		}
		return EnrollResult{}, false, ErrConflict
	}
	device, err := readJSON[Device](ctx, getter, deviceKey(record.Result.Organization.ID, record.Result.Device.ID))
	if err != nil || device.Status != StatusActive || device.MemberID != member.ID {
		if err != nil && !errors.Is(err, ErrNotFound) {
			return EnrollResult{}, false, err
		}
		return EnrollResult{}, false, ErrConflict
	}
	deviceHash, err := getter.Get(ctx, deviceCredentialKey(record.Result.Organization.ID, device.ID)).Result()
	if err != nil || deviceHash != record.DeviceTokenHash {
		if err != nil && !errors.Is(err, redis.Nil) {
			return EnrollResult{}, false, err
		}
		return EnrollResult{}, false, ErrConflict
	}
	storedCredential, err := readJSON[credential](ctx, getter, credentialKey(record.DeviceTokenHash))
	if err != nil || storedCredential.Kind != auth.TokenDevice || storedCredential.OrganizationID != record.Result.Organization.ID ||
		storedCredential.MemberID != member.ID || storedCredential.DeviceID != device.ID {
		if err != nil && !errors.Is(err, ErrNotFound) {
			return EnrollResult{}, false, err
		}
		return EnrollResult{}, false, ErrConflict
	}
	return record.Result, true, nil
}

func (s *RedisStore) ListMembers(ctx context.Context, principal auth.Principal) ([]Member, error) {
	if err := s.requireAdmin(ctx, principal); err != nil {
		return nil, err
	}
	ids, err := s.rdb.SMembers(ctx, membersKey(principal.OrganizationID)).Result()
	if err != nil {
		return nil, err
	}
	members := make([]Member, 0, len(ids))
	for _, id := range ids {
		member, err := s.readMember(ctx, principal.OrganizationID, id)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		members = append(members, member)
	}
	sort.Slice(members, func(i, j int) bool { return members[i].CreatedAt.Before(members[j].CreatedAt) })
	return members, nil
}

func (s *RedisStore) RevokeMember(ctx context.Context, principal auth.Principal, memberID string) (RevocationResult, error) {
	if err := s.requireAdmin(ctx, principal); err != nil {
		return RevocationResult{}, err
	}
	if !validID(memberID, "mem_") {
		return RevocationResult{}, ErrNotFound
	}
	if memberID == principal.MemberID {
		return RevocationResult{}, ErrConflict
	}
	key := memberKey(principal.OrganizationID, memberID)
	for attempt := 0; attempt < 5; attempt++ {
		result := RevocationResult{OrganizationID: principal.OrganizationID}
		err := s.rdb.Watch(ctx, func(tx *redis.Tx) error {
			member, err := readJSON[Member](ctx, tx, key)
			if err != nil {
				return err
			}
			deviceIDs, err := tx.SMembers(ctx, memberDevicesKey(principal.OrganizationID, memberID)).Result()
			if err != nil {
				return err
			}
			credentialHashes, err := tx.SMembers(ctx, memberCredentialsKey(principal.OrganizationID, memberID)).Result()
			if err != nil {
				return err
			}
			devices := make([]Device, 0, len(deviceIDs))
			for _, deviceID := range deviceIDs {
				device, readErr := readJSON[Device](ctx, tx, deviceKey(principal.OrganizationID, deviceID))
				if errors.Is(readErr, ErrNotFound) {
					continue
				}
				if readErr != nil {
					return readErr
				}
				devices = append(devices, device)
			}
			result.AgentIDs = agentIDsFromDevices(devices)
			if member.Status == StatusRevoked {
				_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
					addRevokedAgentTombstones(ctx, pipe, principal.OrganizationID, result.AgentIDs)
					return nil
				})
				return err
			}
			now := time.Now().UTC()
			member.Status = StatusRevoked
			member.RevokedAt = &now
			for index := range devices {
				devices[index].Status = StatusRevoked
				devices[index].RevokedAt = &now
			}
			memberJSON, _ := json.Marshal(member)
			auditJSON, _ := json.Marshal(AuditEvent{
				ID: randomID("aud_"), OrganizationID: principal.OrganizationID,
				ActorMemberID: principal.MemberID, ActorDeviceID: principal.DeviceID,
				Action: "member.revoked", TargetType: "member", TargetID: member.ID, OccurredAt: now,
			})
			_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.Set(ctx, key, memberJSON, 0)
				addRevokedAgentTombstones(ctx, pipe, principal.OrganizationID, result.AgentIDs)
				for _, hash := range credentialHashes {
					pipe.Del(ctx, credentialKey(hash))
				}
				for _, device := range devices {
					encoded, _ := json.Marshal(device)
					pipe.Set(ctx, deviceKey(principal.OrganizationID, device.ID), encoded, 0)
					pipe.Del(ctx, deviceCredentialKey(principal.OrganizationID, device.ID))
				}
				pipe.Del(ctx, memberCredentialsKey(principal.OrganizationID, memberID))
				pipe.LPush(ctx, auditKey(principal.OrganizationID), auditJSON)
				pipe.LTrim(ctx, auditKey(principal.OrganizationID), 0, maximumAuditEvents-1)
				return nil
			})
			return err
		}, key)
		if errors.Is(err, redis.TxFailedErr) {
			continue
		}
		return result, err
	}
	return RevocationResult{}, fmt.Errorf("revoke member after concurrent updates: %w", redis.TxFailedErr)
}

func (s *RedisStore) ListDevices(ctx context.Context, principal auth.Principal, memberID string) ([]Device, error) {
	if err := s.requireAdmin(ctx, principal); err != nil {
		return nil, err
	}
	var ids []string
	var err error
	if memberID == "" {
		ids, err = s.rdb.SMembers(ctx, devicesKey(principal.OrganizationID)).Result()
	} else {
		if !validID(memberID, "mem_") {
			return nil, ErrInvalid
		}
		ids, err = s.rdb.SMembers(ctx, memberDevicesKey(principal.OrganizationID, memberID)).Result()
	}
	if err != nil {
		return nil, err
	}
	devices := make([]Device, 0, len(ids))
	for _, id := range ids {
		device, err := s.readDevice(ctx, principal.OrganizationID, id)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		devices = append(devices, device)
	}
	sort.Slice(devices, func(i, j int) bool { return devices[i].CreatedAt.Before(devices[j].CreatedAt) })
	return devices, nil
}

func (s *RedisStore) RevokeDevice(ctx context.Context, principal auth.Principal, deviceID string) (RevocationResult, error) {
	if err := s.requireAdmin(ctx, principal); err != nil {
		return RevocationResult{}, err
	}
	if !validID(deviceID, "dev_") {
		return RevocationResult{}, ErrNotFound
	}
	key := deviceKey(principal.OrganizationID, deviceID)
	for attempt := 0; attempt < 5; attempt++ {
		result := RevocationResult{OrganizationID: principal.OrganizationID}
		err := s.rdb.Watch(ctx, func(tx *redis.Tx) error {
			device, err := readJSON[Device](ctx, tx, key)
			if err != nil {
				return err
			}
			result.AgentIDs = []string{device.AgentID}
			if device.Status == StatusRevoked {
				_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
					addRevokedAgentTombstones(ctx, pipe, principal.OrganizationID, result.AgentIDs)
					return nil
				})
				return err
			}
			now := time.Now().UTC()
			device.Status = StatusRevoked
			device.RevokedAt = &now
			hash, err := tx.Get(ctx, deviceCredentialKey(principal.OrganizationID, device.ID)).Result()
			if err != nil && !errors.Is(err, redis.Nil) {
				return err
			}
			deviceJSON, _ := json.Marshal(device)
			auditJSON, _ := json.Marshal(AuditEvent{
				ID: randomID("aud_"), OrganizationID: principal.OrganizationID,
				ActorMemberID: principal.MemberID, ActorDeviceID: principal.DeviceID,
				Action: "device.revoked", TargetType: "device", TargetID: device.ID, OccurredAt: now,
			})
			_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.Set(ctx, key, deviceJSON, 0)
				addRevokedAgentTombstones(ctx, pipe, principal.OrganizationID, result.AgentIDs)
				if hash != "" {
					pipe.Del(ctx, credentialKey(hash))
					pipe.SRem(ctx, memberCredentialsKey(principal.OrganizationID, device.MemberID), hash)
				}
				pipe.Del(ctx, deviceCredentialKey(principal.OrganizationID, device.ID))
				pipe.LPush(ctx, auditKey(principal.OrganizationID), auditJSON)
				pipe.LTrim(ctx, auditKey(principal.OrganizationID), 0, maximumAuditEvents-1)
				return nil
			})
			return err
		}, key, deviceCredentialKey(principal.OrganizationID, deviceID))
		if errors.Is(err, redis.TxFailedErr) {
			continue
		}
		return result, err
	}
	return RevocationResult{}, fmt.Errorf("revoke device after concurrent updates: %w", redis.TxFailedErr)
}

func agentIDsFromDevices(devices []Device) []string {
	unique := make(map[string]struct{}, len(devices))
	for _, device := range devices {
		if device.AgentID != "" {
			unique[device.AgentID] = struct{}{}
		}
	}
	result := make([]string, 0, len(unique))
	for agentID := range unique {
		result = append(result, agentID)
	}
	sort.Strings(result)
	return result
}

func addRevokedAgentTombstones(ctx context.Context, pipe redis.Pipeliner, organizationID string, agentIDs []string) {
	for _, agentID := range agentIDs {
		if strings.TrimSpace(agentID) != "" {
			pipe.SAdd(ctx, keyspace.CollaborationRevokedAgents(organizationID), agentID)
		}
	}
}

func (s *RedisStore) ListAuditEvents(ctx context.Context, principal auth.Principal, limit int) ([]AuditEvent, error) {
	if err := s.requireAdmin(ctx, principal); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	values, err := s.rdb.LRange(ctx, auditKey(principal.OrganizationID), 0, int64(limit-1)).Result()
	if err != nil {
		return nil, err
	}
	events := make([]AuditEvent, 0, len(values))
	for _, value := range values {
		var event AuditEvent
		if json.Unmarshal([]byte(value), &event) == nil && event.OrganizationID == principal.OrganizationID {
			events = append(events, event)
		}
	}
	return events, nil
}

func (s *RedisStore) requireAdmin(ctx context.Context, principal auth.Principal) error {
	if !principal.IsAdmin() || !validID(principal.OrganizationID, "org_") || !validID(principal.MemberID, "mem_") {
		return ErrForbidden
	}
	member, err := s.readMember(ctx, principal.OrganizationID, principal.MemberID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return ErrForbidden
		}
		return err
	}
	if member.Status != StatusActive || member.Role != auth.RoleAdmin {
		return ErrForbidden
	}
	return nil
}

func (s *RedisStore) readMember(ctx context.Context, organizationID, memberID string) (Member, error) {
	return readJSON[Member](ctx, s.rdb, memberKey(organizationID, memberID))
}

func (s *RedisStore) readDevice(ctx context.Context, organizationID, deviceID string) (Device, error) {
	return readJSON[Device](ctx, s.rdb, deviceKey(organizationID, deviceID))
}

func (s *RedisStore) readInvite(ctx context.Context, organizationID, inviteID string) (Invite, error) {
	return readJSON[Invite](ctx, s.rdb, inviteKey(organizationID, inviteID))
}

type redisGetter interface {
	Get(context.Context, string) *redis.StringCmd
}

func readJSON[T any](ctx context.Context, getter redisGetter, key string) (T, error) {
	var result T
	raw, err := getter.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return result, ErrNotFound
	}
	if err != nil {
		return result, err
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return result, fmt.Errorf("decode stored record: %w", err)
	}
	return result, nil
}

func normalizedTime(value time.Time) time.Time {
	if value.IsZero() {
		return time.Now().UTC()
	}
	return value.UTC()
}

func clean(value string) string {
	return strings.TrimSpace(value)
}

func normalizeEmail(value string) string {
	return strings.ToLower(clean(value))
}

func validEmail(value string) bool {
	return value != "" && len(value) <= 254 && strings.Contains(value, "@") && !hasControl(value)
}

func validLabel(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && !hasControl(value)
}

func validPermissionProfile(value string) bool {
	switch value {
	case "read_only", "guarded_write", "custom":
		return true
	default:
		return false
	}
}

func hasControl(value string) bool {
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}

func validHash(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func digestJSON(value any) string {
	payload, err := json.Marshal(value)
	if err != nil {
		panic("marshal internal digest input: " + err.Error())
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}

func validID(value, prefix string) bool {
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+32 {
		return false
	}
	_, err := hex.DecodeString(value[len(prefix):])
	return err == nil
}

func randomID(prefix string) string {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return prefix + hex.EncodeToString(value)
}

func organizationKey(organizationID string) string {
	return keyPrefix + "org:" + organizationID + ":record"
}
func membersKey(organizationID string) string {
	return keyPrefix + "org:" + organizationID + ":members"
}
func memberKey(organizationID, memberID string) string {
	return keyPrefix + "org:" + organizationID + ":member:" + memberID
}
func devicesKey(organizationID string) string {
	return keyPrefix + "org:" + organizationID + ":devices"
}
func deviceKey(organizationID, deviceID string) string {
	return keyPrefix + "org:" + organizationID + ":device:" + deviceID
}
func memberDevicesKey(organizationID, memberID string) string {
	return keyPrefix + "org:" + organizationID + ":member:" + memberID + ":devices"
}
func invitesKey(organizationID string) string {
	return keyPrefix + "org:" + organizationID + ":invites"
}
func inviteKey(organizationID, inviteID string) string {
	return keyPrefix + "org:" + organizationID + ":invite:" + inviteID
}
func memberCredentialsKey(organizationID, memberID string) string {
	return keyPrefix + "org:" + organizationID + ":member:" + memberID + ":credential_hashes"
}
func deviceCredentialKey(organizationID, deviceID string) string {
	return keyPrefix + "org:" + organizationID + ":device:" + deviceID + ":credential_hash"
}
func inviteCredentialKey(organizationID, inviteID string) string {
	return keyPrefix + "org:" + organizationID + ":invite:" + inviteID + ":credential_hash"
}
func auditKey(organizationID string) string {
	return keyPrefix + "org:" + organizationID + ":audit"
}
func credentialKey(hash string) string {
	return keyPrefix + "credential:" + hash
}
func inviteTokenKey(hash string) string {
	return keyPrefix + "invite_token:" + hash
}
func enrollmentIdempotencyKey(hash string) string {
	return keyPrefix + "enrollment_idempotency:" + hash
}
func adminRotationKey(hash string) string {
	return keyPrefix + "admin_rotation:" + hash
}
