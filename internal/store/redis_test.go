package store

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/mohitbadwal/team-relay/internal/auth"
	"github.com/mohitbadwal/team-relay/internal/keyspace"
	"github.com/redis/go-redis/v9"
)

func testRedisStore(t *testing.T) (*miniredis.Miniredis, *RedisStore) {
	t.Helper()
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return server, NewRedis(client)
}

func bootstrapTestOrganization(t *testing.T, repository *RedisStore, now time.Time) (string, BootstrapResult, auth.Principal) {
	t.Helper()
	token, err := auth.NewToken(auth.TokenAdmin)
	if err != nil {
		t.Fatal(err)
	}
	result, err := repository.Bootstrap(context.Background(), BootstrapInput{
		OrganizationName: "Example Engineering",
		AdminDisplayName: "Relay Admin",
		AdminEmail:       "admin@example.com",
		AdminTokenHash:   auth.Hash(token),
		IdempotencyHash:  auth.Hash("bootstrap-test"),
		Now:              now,
	})
	if err != nil {
		t.Fatal(err)
	}
	principal, err := repository.Authenticate(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	return token, result, principal
}

func TestBootstrapIsOneTimeAndStoresOnlyAdminTokenHash(t *testing.T) {
	redisServer, repository := testRedisStore(t)
	now := time.Date(2026, time.September, 5, 12, 0, 0, 0, time.UTC)
	token, result, principal := bootstrapTestOrganization(t, repository, now)
	if !principal.IsAdmin() || principal.OrganizationID != result.Organization.ID || principal.MemberID != result.Admin.ID {
		t.Fatalf("unexpected principal: %+v", principal)
	}
	if redisServer.Exists(credentialKey(token)) {
		t.Fatal("raw admin credential was used as a Redis key")
	}
	if !redisServer.Exists(credentialKey(auth.Hash(token))) {
		t.Fatal("hashed admin credential index is missing")
	}
	if strings.Contains(redisServer.Dump(), token) {
		t.Fatal("raw admin credential was persisted in Redis")
	}
	if strings.Contains(redisServer.Dump(), "bootstrap-test") {
		t.Fatal("raw bootstrap idempotency key was persisted in Redis")
	}
	retry, err := repository.Bootstrap(context.Background(), BootstrapInput{
		OrganizationName: "Example Engineering", AdminDisplayName: "Relay Admin", AdminEmail: "admin@example.com",
		AdminTokenHash: auth.Hash(token), IdempotencyHash: auth.Hash("bootstrap-test"), Now: now.Add(time.Minute),
	})
	if err != nil || retry.Organization.ID != result.Organization.ID || retry.Admin.ID != result.Admin.ID {
		t.Fatalf("exact bootstrap retry = %+v, %v", retry, err)
	}
	_, err = repository.Bootstrap(context.Background(), BootstrapInput{
		OrganizationName: "Other",
		AdminDisplayName: "Other Admin",
		AdminEmail:       "other@example.com",
		AdminTokenHash:   auth.Hash(token),
		IdempotencyHash:  auth.Hash("different-bootstrap"),
		Now:              now,
	})
	if !errors.Is(err, ErrAlreadyBootstrapped) {
		t.Fatalf("second bootstrap error = %v", err)
	}
}

func TestConcurrentExactBootstrapRetriesCreateOneOrganization(t *testing.T) {
	_, repository := testRedisStore(t)
	token, _ := auth.NewToken(auth.TokenAdmin)
	input := BootstrapInput{
		OrganizationName: "Concurrent Team", AdminDisplayName: "Admin", AdminEmail: "admin@example.test",
		AdminTokenHash: auth.Hash(token), IdempotencyHash: auth.Hash("same-bootstrap-attempt"), Now: time.Now().UTC(),
	}
	const callers = 4
	start := make(chan struct{})
	results := make(chan BootstrapResult, callers)
	errorsCh := make(chan error, callers)
	var wait sync.WaitGroup
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			result, err := repository.Bootstrap(context.Background(), input)
			results <- result
			errorsCh <- err
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatalf("concurrent bootstrap retry: %v", err)
		}
	}
	var organizationID, memberID string
	for result := range results {
		if organizationID == "" {
			organizationID, memberID = result.Organization.ID, result.Admin.ID
		}
		if result.Organization.ID != organizationID || result.Admin.ID != memberID {
			t.Fatalf("concurrent bootstrap returned different identities: %+v", result)
		}
	}
}

func TestAdminCredentialRotationIsAtomicAndAudited(t *testing.T) {
	redisServer, repository := testRedisStore(t)
	ctx := context.Background()
	now := time.Date(2026, time.September, 5, 12, 0, 0, 0, time.UTC)
	oldToken, _, principal := bootstrapTestOrganization(t, repository, now)
	newToken, err := auth.NewToken(auth.TokenAdmin)
	if err != nil {
		t.Fatal(err)
	}
	input := RotateAdminCredentialInput{
		NewTokenHash: auth.Hash(newToken), IdempotencyHash: auth.Hash("rotate-test"), Now: now.Add(time.Minute),
	}
	if result, err := repository.RotateAdminCredential(ctx, principal, input); err != nil || result.Replayed {
		t.Fatalf("initial rotation = %+v, %v", result, err)
	}
	if _, err := repository.Authenticate(ctx, oldToken); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("old admin credential remained valid: %v", err)
	}
	rotated, err := repository.Authenticate(ctx, newToken)
	if err != nil || !rotated.IsAdmin() || rotated.MemberID != principal.MemberID {
		t.Fatalf("replacement credential did not authenticate: %+v, %v", rotated, err)
	}
	input.Now = now.Add(10 * time.Minute)
	replayed, err := repository.RotateAdminCredential(ctx, rotated, input)
	if err != nil || !replayed.Replayed || !replayed.RotatedAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("lost-response replay = %+v, %v", replayed, err)
	}
	if dump := redisServer.Dump(); strings.Contains(dump, newToken) || strings.Contains(dump, "rotate-test") {
		t.Fatal("raw replacement token or rotation idempotency key was persisted")
	}
	differentToken, _ := auth.NewToken(auth.TokenAdmin)
	mismatched := input
	mismatched.NewTokenHash = auth.Hash(differentToken)
	if _, err := repository.RotateAdminCredential(ctx, rotated, mismatched); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed rotation idempotency replay error = %v", err)
	}
	events, err := repository.ListAuditEvents(ctx, rotated, 10)
	if err != nil || len(events) == 0 || events[0].Action != "admin.credential_rotated" {
		t.Fatalf("rotation audit event = %+v, %v", events, err)
	}
}

func TestConcurrentExactAdminRotationsCommitOnce(t *testing.T) {
	_, repository := testRedisStore(t)
	ctx := context.Background()
	oldToken, _, principal := bootstrapTestOrganization(t, repository, time.Now().UTC())
	newToken, _ := auth.NewToken(auth.TokenAdmin)
	input := RotateAdminCredentialInput{
		NewTokenHash: auth.Hash(newToken), IdempotencyHash: auth.Hash("same-rotation-attempt"), Now: time.Now().UTC(),
	}
	const callers = 4
	start := make(chan struct{})
	errorsCh := make(chan error, callers)
	var wait sync.WaitGroup
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, err := repository.RotateAdminCredential(ctx, principal, input)
			errorsCh <- err
		}()
	}
	close(start)
	wait.Wait()
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatalf("concurrent rotation retry: %v", err)
		}
	}
	if _, err := repository.Authenticate(ctx, oldToken); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("old token authenticated after concurrent rotation: %v", err)
	}
	newPrincipal, err := repository.Authenticate(ctx, newToken)
	if err != nil {
		t.Fatal(err)
	}
	events, err := repository.ListAuditEvents(ctx, newPrincipal, 20)
	if err != nil {
		t.Fatal(err)
	}
	rotations := 0
	for _, event := range events {
		if event.Action == "admin.credential_rotated" {
			rotations++
		}
	}
	if rotations != 1 {
		t.Fatalf("rotation audit event count = %d", rotations)
	}
}

func TestInviteEnrollIsSingleUseAndDeviceIsRevocable(t *testing.T) {
	_, repository := testRedisStore(t)
	ctx := context.Background()
	now := time.Date(2026, time.September, 5, 12, 0, 0, 0, time.UTC)
	_, _, admin := bootstrapTestOrganization(t, repository, now)
	inviteToken, _ := auth.NewToken(auth.TokenInvite)
	invite, err := repository.CreateInvite(ctx, admin, CreateInviteInput{
		DisplayName: "Alice", Email: "alice@example.com",
		ExpiresAt: now.Add(time.Hour), InviteTokenHash: auth.Hash(inviteToken), Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	deviceToken, _ := auth.NewToken(auth.TokenDevice)
	enrollment, err := repository.Enroll(ctx, inviteToken, EnrollInput{
		DeviceName: "Alice laptop", Runtime: "codex", PermissionProfile: "read_only",
		DeviceTokenHash: auth.Hash(deviceToken), IdempotencyKeyHash: auth.Hash("enroll-alice"), Now: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if enrollment.Member.DisplayName != "Alice" || enrollment.Device.AgentID == "" || enrollment.Device.PermissionProfile != "read_only" {
		t.Fatalf("unexpected enrollment: %+v", enrollment)
	}
	principal, err := repository.Authenticate(ctx, deviceToken)
	if err != nil {
		t.Fatal(err)
	}
	if principal.DeviceID != enrollment.Device.ID || principal.AgentID != enrollment.Device.AgentID || principal.Role != auth.RoleMember {
		t.Fatalf("unexpected device principal: %+v", principal)
	}
	secondToken, _ := auth.NewToken(auth.TokenDevice)
	if _, err := repository.Enroll(ctx, inviteToken, EnrollInput{
		DeviceName: "Replay", Runtime: "claude-code", PermissionProfile: "guarded_write",
		DeviceTokenHash: auth.Hash(secondToken), IdempotencyKeyHash: auth.Hash("enroll-replay"), Now: now.Add(2 * time.Minute),
	}); !errors.Is(err, ErrInviteUsed) {
		t.Fatalf("invite replay error = %v", err)
	}
	invites, err := repository.ListInvites(ctx, admin)
	if err != nil || len(invites) != 1 || invites[0].ID != invite.ID || invites[0].Status != StatusUsed {
		t.Fatalf("invites = %+v, err = %v", invites, err)
	}
	if _, err := repository.RevokeDevice(ctx, admin, enrollment.Device.ID); err != nil {
		t.Fatal(err)
	}
	revokedKey := keyspace.CollaborationRevokedAgents(admin.OrganizationID)
	if revoked, err := repository.rdb.SIsMember(ctx, revokedKey, enrollment.Device.AgentID).Result(); err != nil || !revoked {
		t.Fatalf("device revocation tombstone = %t, %v", revoked, err)
	}
	if _, err := repository.Authenticate(ctx, deviceToken); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked device authentication error = %v", err)
	}
	// An exact retry repairs a tombstone that an older deployment or operator
	// may have removed, without reviving the device or duplicating its audit.
	if err := repository.rdb.Del(ctx, revokedKey).Err(); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.RevokeDevice(ctx, admin, enrollment.Device.ID); err != nil {
		t.Fatal(err)
	}
	if revoked, err := repository.rdb.SIsMember(ctx, revokedKey, enrollment.Device.AgentID).Result(); err != nil || !revoked {
		t.Fatalf("device revocation retry did not repair tombstone: %t, %v", revoked, err)
	}
}

func TestEnrollmentExactRetryIsIdempotentHashOnlyAndRejectsMismatchOrRevocation(t *testing.T) {
	redisServer, repository := testRedisStore(t)
	ctx := context.Background()
	now := time.Date(2026, time.September, 5, 12, 0, 0, 0, time.UTC)
	_, _, admin := bootstrapTestOrganization(t, repository, now)
	inviteToken, _ := auth.NewToken(auth.TokenInvite)
	_, err := repository.CreateInvite(ctx, admin, CreateInviteInput{
		DisplayName: "Alice", ExpiresAt: now.Add(time.Hour), InviteTokenHash: auth.Hash(inviteToken), Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	deviceToken, _ := auth.NewToken(auth.TokenDevice)
	idempotencyKey := "tr_enroll_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	input := EnrollInput{
		DeviceName: "Alice laptop", Runtime: "codex", PermissionProfile: "read_only",
		DeviceTokenHash:    strings.ToUpper(auth.Hash(deviceToken)),
		IdempotencyKeyHash: strings.ToUpper(auth.Hash(idempotencyKey)), Now: now.Add(time.Minute),
	}
	first, err := repository.Enroll(ctx, inviteToken, input)
	if err != nil {
		t.Fatal(err)
	}
	input.Now = now.Add(10 * time.Minute)
	second, err := repository.Enroll(ctx, inviteToken, input)
	if err != nil {
		t.Fatal(err)
	}
	if first.Organization.ID != second.Organization.ID || first.Member.ID != second.Member.ID || first.Device.ID != second.Device.ID || first.Device.AgentID != second.Device.AgentID {
		t.Fatalf("exact retry changed enrollment: first=%+v second=%+v", first, second)
	}
	devices, err := repository.ListDevices(ctx, admin, "")
	if err != nil || len(devices) != 1 {
		t.Fatalf("devices after exact retry = %+v, %v", devices, err)
	}
	if !redisServer.Exists(credentialKey(auth.Hash(deviceToken))) || redisServer.Exists(credentialKey(strings.ToUpper(auth.Hash(deviceToken)))) {
		t.Fatal("device token hash was not canonicalized before indexing")
	}
	dump := redisServer.Dump()
	if strings.Contains(dump, deviceToken) || strings.Contains(dump, idempotencyKey) {
		t.Fatal("raw device token or idempotency key was persisted")
	}

	mismatched := input
	mismatched.DeviceName = "different laptop"
	if _, err := repository.Enroll(ctx, inviteToken, mismatched); !errors.Is(err, ErrConflict) {
		t.Fatalf("mismatched idempotency reuse error = %v", err)
	}
	if _, err := repository.RevokeDevice(ctx, admin, first.Device.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Enroll(ctx, inviteToken, input); !errors.Is(err, ErrConflict) {
		t.Fatalf("retry after device revocation error = %v", err)
	}
}

func TestConcurrentExactEnrollmentRetriesCreateOneDevice(t *testing.T) {
	_, repository := testRedisStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	_, _, admin := bootstrapTestOrganization(t, repository, now)
	inviteToken, _ := auth.NewToken(auth.TokenInvite)
	_, err := repository.CreateInvite(ctx, admin, CreateInviteInput{
		DisplayName: "Concurrent", ExpiresAt: now.Add(time.Hour), InviteTokenHash: auth.Hash(inviteToken), Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	deviceToken, _ := auth.NewToken(auth.TokenDevice)
	input := EnrollInput{
		DeviceName: "shared laptop", Runtime: "codex", PermissionProfile: "read_only",
		DeviceTokenHash: auth.Hash(deviceToken), IdempotencyKeyHash: auth.Hash("concurrent-enrollment"), Now: now,
	}
	const callers = 4
	start := make(chan struct{})
	results := make(chan EnrollResult, callers)
	errorsCh := make(chan error, callers)
	var wait sync.WaitGroup
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			result, err := repository.Enroll(ctx, inviteToken, input)
			results <- result
			errorsCh <- err
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatalf("concurrent exact retry failed: %v", err)
		}
	}
	var deviceID string
	for result := range results {
		if deviceID == "" {
			deviceID = result.Device.ID
		}
		if result.Device.ID != deviceID {
			t.Fatalf("concurrent retry returned device %q; want %q", result.Device.ID, deviceID)
		}
	}
	devices, err := repository.ListDevices(ctx, admin, "")
	if err != nil || len(devices) != 1 {
		t.Fatalf("devices after concurrent retries = %+v, %v", devices, err)
	}
}

func TestExpiredAndRevokedInvitationsCannotEnroll(t *testing.T) {
	_, repository := testRedisStore(t)
	ctx := context.Background()
	now := time.Date(2026, time.September, 5, 12, 0, 0, 0, time.UTC)
	_, _, admin := bootstrapTestOrganization(t, repository, now)

	expiredToken, _ := auth.NewToken(auth.TokenInvite)
	_, err := repository.CreateInvite(ctx, admin, CreateInviteInput{
		DisplayName: "Expired", ExpiresAt: now.Add(time.Minute),
		InviteTokenHash: auth.Hash(expiredToken), Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	deviceToken, _ := auth.NewToken(auth.TokenDevice)
	_, err = repository.Enroll(ctx, expiredToken, EnrollInput{
		DeviceName: "laptop", Runtime: "codex", PermissionProfile: "read_only",
		DeviceTokenHash: auth.Hash(deviceToken), IdempotencyKeyHash: auth.Hash("enroll-expired"), Now: now.Add(2 * time.Minute),
	})
	if !errors.Is(err, ErrInviteExpired) {
		t.Fatalf("expired invitation error = %v", err)
	}

	revokedToken, _ := auth.NewToken(auth.TokenInvite)
	revoked, err := repository.CreateInvite(ctx, admin, CreateInviteInput{
		DisplayName: "Revoked", ExpiresAt: now.Add(time.Hour),
		InviteTokenHash: auth.Hash(revokedToken), Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.RevokeInvite(ctx, admin, revoked.ID); err != nil {
		t.Fatal(err)
	}
	_, err = repository.Enroll(ctx, revokedToken, EnrollInput{
		DeviceName: "laptop", Runtime: "codex", PermissionProfile: "read_only",
		DeviceTokenHash: auth.Hash(deviceToken), IdempotencyKeyHash: auth.Hash("enroll-revoked"), Now: now.Add(time.Minute),
	})
	if !errors.Is(err, ErrInviteRevoked) {
		t.Fatalf("revoked invitation error = %v", err)
	}
}

func TestMemberRevocationInvalidatesEveryDeviceCredential(t *testing.T) {
	_, repository := testRedisStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	_, _, admin := bootstrapTestOrganization(t, repository, now)

	firstInviteToken, _ := auth.NewToken(auth.TokenInvite)
	_, err := repository.CreateInvite(ctx, admin, CreateInviteInput{
		DisplayName: "Bob", ExpiresAt: now.Add(time.Hour), InviteTokenHash: auth.Hash(firstInviteToken), Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	firstDeviceToken, _ := auth.NewToken(auth.TokenDevice)
	firstEnrollmentInput := EnrollInput{
		DeviceName: "one", Runtime: "claude-code", PermissionProfile: "guarded_write",
		DeviceTokenHash: auth.Hash(firstDeviceToken), IdempotencyKeyHash: auth.Hash("enroll-first"), Now: now,
	}
	first, err := repository.Enroll(ctx, firstInviteToken, firstEnrollmentInput)
	if err != nil {
		t.Fatal(err)
	}

	secondInviteToken, _ := auth.NewToken(auth.TokenInvite)
	_, err = repository.CreateInvite(ctx, admin, CreateInviteInput{
		ExistingMemberID: first.Member.ID, ExpiresAt: now.Add(time.Hour),
		InviteTokenHash: auth.Hash(secondInviteToken), Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	secondDeviceToken, _ := auth.NewToken(auth.TokenDevice)
	second, err := repository.Enroll(ctx, secondInviteToken, EnrollInput{
		DeviceName: "two", Runtime: "codex", PermissionProfile: "read_only",
		DeviceTokenHash: auth.Hash(secondDeviceToken), IdempotencyKeyHash: auth.Hash("enroll-second"), Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}

	revocation, err := repository.RevokeMember(ctx, admin, first.Member.ID)
	if err != nil {
		t.Fatal(err)
	}
	revokedAgents := make(map[string]bool, len(revocation.AgentIDs))
	for _, agentID := range revocation.AgentIDs {
		revokedAgents[agentID] = true
	}
	if len(revokedAgents) != 2 || !revokedAgents[first.Device.AgentID] || !revokedAgents[second.Device.AgentID] {
		t.Fatalf("member revocation agents = %#v", revocation.AgentIDs)
	}
	revokedKey := keyspace.CollaborationRevokedAgents(admin.OrganizationID)
	for _, agentID := range revocation.AgentIDs {
		if revoked, err := repository.rdb.SIsMember(ctx, revokedKey, agentID).Result(); err != nil || !revoked {
			t.Fatalf("member revocation tombstone for %q = %t, %v", agentID, revoked, err)
		}
	}
	for _, token := range []string{firstDeviceToken, secondDeviceToken} {
		if _, err := repository.Authenticate(ctx, token); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("revoked member device authenticated: %v", err)
		}
	}
	if _, err := repository.Enroll(ctx, firstInviteToken, firstEnrollmentInput); !errors.Is(err, ErrConflict) {
		t.Fatalf("exact enrollment retry after member revocation error = %v", err)
	}
	if err := repository.rdb.Del(ctx, revokedKey).Err(); err != nil {
		t.Fatal(err)
	}
	replayed, err := repository.RevokeMember(ctx, admin, first.Member.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, agentID := range replayed.AgentIDs {
		if revoked, err := repository.rdb.SIsMember(ctx, revokedKey, agentID).Result(); err != nil || !revoked {
			t.Fatalf("member revocation retry did not repair tombstone for %q: %t, %v", agentID, revoked, err)
		}
	}
	if _, err := repository.RevokeMember(ctx, admin, admin.MemberID); !errors.Is(err, ErrConflict) {
		t.Fatalf("self-revocation error = %v", err)
	}
}

func TestOrganizationScopeCannotBeSelectedByCaller(t *testing.T) {
	_, repository := testRedisStore(t)
	now := time.Now().UTC()
	_, _, admin := bootstrapTestOrganization(t, repository, now)
	forged := admin
	forged.OrganizationID = "org_00000000000000000000000000000000"
	_, err := repository.ListMembers(context.Background(), forged)
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("cross-organization principal error = %v", err)
	}
}
