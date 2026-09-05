package receiver

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mohitbadwal/team-relay/internal/privatefs"
	"github.com/mohitbadwal/team-relay/internal/protocol"
)

func TestApprovalLevelsAndAskAlwaysIsNotPersisted(t *testing.T) {
	t.Parallel()
	for _, level := range []ApprovalLevel{
		ApprovalLevelAskAlways,
		ApprovalLevelConversation30m,
		ApprovalLevelTeammateAlways,
		ApprovalLevelAllAlways,
	} {
		if !level.Valid() {
			t.Fatalf("expected level %q to be valid", level)
		}
	}
	if ApprovalLevel("forever_without_consent").Valid() {
		t.Fatal("unknown approval level was accepted")
	}

	store, path := newTestApprovalStore(t)
	grant, err := store.Upsert(testApprovalAuthority(), ApprovalLevelAskAlways, ApprovalCandidate{})
	if err != nil {
		t.Fatal(err)
	}
	if grant.GrantID != "" || grant.Level != "" || len(grant.AccessCeiling.RequestedAccess) != 0 || grant.AccessCeiling.MaxAttachmentCount != 0 || grant.AccessCeiling.MaxAttachmentBytes != 0 {
		t.Fatalf("ask_always returned a persisted grant: %#v", grant)
	}
	grants, err := store.List(testApprovalAuthority())
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 0 {
		t.Fatalf("ask_always persisted %d grants", len(grants))
	}
	if err := privatefs.ValidateDirectory(filepath.Dir(path)); err != nil {
		t.Fatalf("approval directory is not private: %v", err)
	}
	if err := privatefs.ValidateRegularFile(path); err != nil {
		t.Fatalf("approval file is not private: %v", err)
	}
}

func TestApprovalStoreMatchesMostSpecificGrantAndUsesFixedExpiry(t *testing.T) {
	t.Parallel()
	store, _ := newTestApprovalStore(t)
	authority := testApprovalAuthority()
	candidate := testApprovalCandidate()
	createdAt := time.Date(2030, 4, 5, 6, 7, 8, 900, time.UTC)
	current := createdAt
	store.now = func() time.Time { return current }

	all, err := store.Upsert(authority, ApprovalLevelAllAlways, candidate)
	if err != nil {
		t.Fatal(err)
	}
	teammate, err := store.Upsert(authority, ApprovalLevelTeammateAlways, candidate)
	if err != nil {
		t.Fatal(err)
	}
	conversation, err := store.Upsert(authority, ApprovalLevelConversation30m, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if all.GrantID == teammate.GrantID || all.GrantID == conversation.GrantID || teammate.GrantID == conversation.GrantID {
		t.Fatal("different scopes received the same stable grant ID")
	}
	if conversation.ExpiresAt == nil || !conversation.ExpiresAt.Equal(createdAt.Add(ApprovalConversationWindow)) {
		t.Fatalf("conversation expiry = %v, want %v", conversation.ExpiresAt, createdAt.Add(ApprovalConversationWindow))
	}

	matched, ok, err := store.Match(authority, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || matched.GrantID != conversation.GrantID {
		t.Fatalf("matched grant = %#v, present=%t; want conversation", matched, ok)
	}

	current = createdAt.Add(10 * time.Minute)
	replayed, err := store.Upsert(authority, ApprovalLevelConversation30m, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if replayed.GrantID != conversation.GrantID || !replayed.CreatedAt.Equal(conversation.CreatedAt) || replayed.ExpiresAt == nil || !replayed.ExpiresAt.Equal(*conversation.ExpiresAt) {
		t.Fatalf("idempotent upsert extended or replaced the fixed grant: original=%#v replay=%#v", conversation, replayed)
	}

	current = createdAt.Add(ApprovalConversationWindow)
	matched, ok, err = store.Match(authority, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || matched.GrantID != teammate.GrantID {
		t.Fatalf("post-expiry match = %#v, present=%t; want teammate fallback", matched, ok)
	}
	grants, err := store.List(authority)
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 2 || grants[0].Level != ApprovalLevelTeammateAlways || grants[1].Level != ApprovalLevelAllAlways {
		t.Fatalf("post-expiry grants = %#v", grants)
	}

	current = current.Add(time.Second)
	recreated, err := store.Upsert(authority, ApprovalLevelConversation30m, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if recreated.GrantID != conversation.GrantID {
		t.Fatalf("recreated stable ID = %q, want %q", recreated.GrantID, conversation.GrantID)
	}
	if !recreated.CreatedAt.Equal(current) || recreated.ExpiresAt == nil || !recreated.ExpiresAt.Equal(current.Add(ApprovalConversationWindow)) {
		t.Fatalf("recreated grant has wrong new fixed window: %#v", recreated)
	}
}

func TestApprovalStoreScopesByConversationAndStableMemberIdentity(t *testing.T) {
	t.Parallel()
	store, _ := newTestApprovalStore(t)
	authority := testApprovalAuthority()
	candidate := testApprovalCandidate()
	conversation, err := store.Upsert(authority, ApprovalLevelConversation30m, candidate)
	if err != nil {
		t.Fatal(err)
	}

	differentConversation := candidate
	differentConversation.ConversationID = "conv_other"
	if _, ok, err := store.Match(authority, differentConversation); err != nil || ok {
		t.Fatalf("conversation grant matched a different conversation: present=%t err=%v", ok, err)
	}
	differentMember := candidate
	differentMember.RequesterMemberID = "mem_other"
	if _, ok, err := store.Match(authority, differentMember); err != nil || ok {
		t.Fatalf("conversation grant matched a different member: present=%t err=%v", ok, err)
	}

	teammate, err := store.Upsert(authority, ApprovalLevelTeammateAlways, candidate)
	if err != nil {
		t.Fatal(err)
	}
	matched, ok, err := store.Match(authority, differentConversation)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || matched.GrantID != teammate.GrantID || matched.GrantID == conversation.GrantID {
		t.Fatalf("member-scoped match = %#v, present=%t", matched, ok)
	}

	// A display name is only a label. Changing it must not change authorization.
	renamed := differentConversation
	renamed.RequesterDisplayName = "Alice Renamed"
	matched, ok, err = store.Match(authority, renamed)
	if err != nil || !ok || matched.GrantID != teammate.GrantID {
		t.Fatalf("display-name change affected member match: %#v, present=%t err=%v", matched, ok, err)
	}
}

func TestStandingApprovalScopeAllowsOnlySameOrNarrowerResourceAccess(t *testing.T) {
	t.Parallel()
	for _, level := range []ApprovalLevel{
		ApprovalLevelConversation30m,
		ApprovalLevelTeammateAlways,
		ApprovalLevelAllAlways,
	} {
		t.Run(string(level), func(t *testing.T) {
			t.Parallel()
			store, _ := newTestApprovalStore(t)
			authority := testApprovalAuthority()
			approved := testApprovalCandidate()
			approved.AccessScope = ApprovalAccessScope{
				RequestedAccess: []protocol.RequestedAccess{
					{WorkspaceAlias: "repo-write", Mode: protocol.PermissionGuardedWrite},
					{WorkspaceAlias: "repo-read", Mode: protocol.PermissionReadOnly},
				},
				MaxAttachmentCount: 2,
				MaxAttachmentBytes: 512,
			}
			grant, err := store.Upsert(authority, level, approved)
			if err != nil {
				t.Fatal(err)
			}

			narrower := approved
			narrower.AccessScope = ApprovalAccessScope{
				RequestedAccess:    []protocol.RequestedAccess{{WorkspaceAlias: "repo-write", Mode: protocol.PermissionReadOnly}},
				MaxAttachmentCount: 1,
				MaxAttachmentBytes: 128,
			}
			matched, ok, err := store.Match(authority, narrower)
			if err != nil || !ok || matched.GrantID != grant.GrantID {
				t.Fatalf("same-or-narrower request did not match: grant=%#v present=%t err=%v", matched, ok, err)
			}

			for _, broadened := range []ApprovalCandidate{
				withApprovalScope(approved, ApprovalAccessScope{RequestedAccess: []protocol.RequestedAccess{
					{WorkspaceAlias: "repo-read", Mode: protocol.PermissionReadOnly},
					{WorkspaceAlias: "new-repo", Mode: protocol.PermissionReadOnly},
				}}),
				withApprovalScope(approved, ApprovalAccessScope{RequestedAccess: []protocol.RequestedAccess{
					{WorkspaceAlias: "repo-read", Mode: protocol.PermissionGuardedWrite},
				}}),
				withApprovalScope(approved, ApprovalAccessScope{MaxAttachmentCount: 3, MaxAttachmentBytes: 512}),
				withApprovalScope(approved, ApprovalAccessScope{MaxAttachmentCount: 2, MaxAttachmentBytes: 513}),
			} {
				if _, ok, err := store.Match(authority, broadened); err != nil || ok {
					t.Fatalf("broader resource scope matched level %q: scope=%#v present=%t err=%v", level, broadened.AccessScope, ok, err)
				}
			}
		})
	}
}

func TestStandingApprovalCreatedWithoutAttachmentsCannotApproveAttachmentLater(t *testing.T) {
	t.Parallel()
	store, _ := newTestApprovalStore(t)
	authority := testApprovalAuthority()
	approved := testApprovalCandidate()
	if _, err := store.Upsert(authority, ApprovalLevelConversation30m, approved); err != nil {
		t.Fatal(err)
	}
	withAttachment := approved
	withAttachment.AccessScope = ApprovalAccessScope{MaxAttachmentCount: 1, MaxAttachmentBytes: 1}
	if _, ok, err := store.Match(authority, withAttachment); err != nil || ok {
		t.Fatalf("attachment was introduced through a no-attachment grant: present=%t err=%v", ok, err)
	}
}

func TestApprovalStoreAllStillRequiresTrustedRequesterMemberID(t *testing.T) {
	t.Parallel()
	store, _ := newTestApprovalStore(t)
	authority := testApprovalAuthority()
	candidate := testApprovalCandidate()
	global, err := store.Upsert(authority, ApprovalLevelAllAlways, candidate)
	if err != nil {
		t.Fatal(err)
	}

	other := ApprovalCandidate{RequesterMemberID: "mem_other", RequesterDisplayName: "Bob", ConversationID: "conv_other"}
	matched, ok, err := store.Match(authority, other)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || matched.GrantID != global.GrantID {
		t.Fatalf("all-teammates grant did not match a trusted member: %#v, present=%t", matched, ok)
	}

	missingMember := ApprovalCandidate{RequesterDisplayName: "Bob", ConversationID: "conv_other"}
	if _, ok, err := store.Match(authority, missingMember); err != nil || ok {
		t.Fatalf("all-teammates grant matched without member identity: present=%t err=%v", ok, err)
	}
	invalidMember := ApprovalCandidate{RequesterMemberID: "mem invalid", ConversationID: "conv_other"}
	if _, ok, err := store.Match(authority, invalidMember); err == nil || ok {
		t.Fatalf("invalid member identity did not fail closed: present=%t err=%v", ok, err)
	}
}

func TestApprovalStorePrunesAuthorityAndRecipientMismatches(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name      string
		authority ApprovalAuthority
	}{
		{name: "authority changed", authority: ApprovalAuthority{Fingerprint: "authority_b", RecipientAgentID: "agent_recipient"}},
		{name: "recipient changed", authority: ApprovalAuthority{Fingerprint: "authority_a", RecipientAgentID: "agent_other"}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			store, path := newTestApprovalStore(t)
			if _, err := store.Upsert(testApprovalAuthority(), ApprovalLevelAllAlways, testApprovalCandidate()); err != nil {
				t.Fatal(err)
			}
			removed, err := store.Prune(testCase.authority)
			if err != nil {
				t.Fatal(err)
			}
			if removed != 1 {
				t.Fatalf("pruned %d grants, want 1", removed)
			}
			reopened, err := NewApprovalStore(path)
			if err != nil {
				t.Fatal(err)
			}
			grants, err := reopened.List(testCase.authority)
			if err != nil {
				t.Fatal(err)
			}
			if len(grants) != 0 {
				t.Fatalf("mismatched grant survived pruning: %#v", grants)
			}
		})
	}
}

func TestRevocationTombstoneSurvivesAuthorityRoundTrip(t *testing.T) {
	t.Parallel()
	store, path := newTestApprovalStore(t)
	original := testApprovalAuthority()
	candidate := testApprovalCandidate()
	grant, err := store.Upsert(original, ApprovalLevelTeammateAlways, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if revoked, err := store.Revoke(original, grant.GrantID); err != nil || !revoked {
		t.Fatalf("revoke result = %t, %v", revoked, err)
	}

	changed := ApprovalAuthority{Fingerprint: "authority_changed", RecipientAgentID: "agent_changed"}
	if _, err := store.List(changed); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewApprovalStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.RestorePrepared(original, ApprovalLevelTeammateAlways, candidate, grant.CreatedAt); !errors.Is(err, ErrApprovalGrantRevoked) {
		t.Fatalf("authority round trip erased revocation tombstone: %v", err)
	}
}

func TestApprovalStorePersistsStableIDsAndRevocation(t *testing.T) {
	t.Parallel()
	store, path := newTestApprovalStore(t)
	authority := testApprovalAuthority()
	candidate := testApprovalCandidate()
	grant, err := store.Upsert(authority, ApprovalLevelTeammateAlways, candidate)
	if err != nil {
		t.Fatal(err)
	}

	reopened, err := NewApprovalStore(path)
	if err != nil {
		t.Fatal(err)
	}
	matched, ok, err := reopened.Match(authority, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || matched.GrantID != grant.GrantID {
		t.Fatalf("persisted grant = %#v, present=%t", matched, ok)
	}
	replayed, err := reopened.Upsert(authority, ApprovalLevelTeammateAlways, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if replayed.GrantID != grant.GrantID || !replayed.CreatedAt.Equal(grant.CreatedAt) {
		t.Fatalf("upsert did not preserve stable grant: original=%#v replay=%#v", grant, replayed)
	}

	revoked, err := reopened.Revoke(authority, grant.GrantID)
	if err != nil || !revoked {
		t.Fatalf("revoke result = %t, %v", revoked, err)
	}
	revoked, err = reopened.Revoke(authority, grant.GrantID)
	if err != nil || revoked {
		t.Fatalf("idempotent revoke result = %t, %v", revoked, err)
	}
	final, err := NewApprovalStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := final.Match(authority, candidate); err != nil || ok {
		t.Fatalf("revoked grant survived restart: present=%t err=%v", ok, err)
	}
	if _, err := final.RestorePrepared(authority, ApprovalLevelTeammateAlways, candidate, grant.CreatedAt); !errors.Is(err, ErrApprovalGrantRevoked) {
		t.Fatalf("crash recovery recreated a revoked grant: %v", err)
	}

	// A new, explicit recipient choice is allowed to re-authorize the same
	// stable scope and clears the tombstone deliberately.
	reauthorized, err := final.Upsert(authority, ApprovalLevelTeammateAlways, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if reauthorized.GrantID != grant.GrantID {
		t.Fatalf("re-authorized grant ID = %q, want %q", reauthorized.GrantID, grant.GrantID)
	}
	if _, ok, err := final.Match(authority, candidate); err != nil || !ok {
		t.Fatalf("explicit re-authorization did not clear tombstone: present=%t err=%v", ok, err)
	}
}

func TestConversationCrashRecoveryNeverRestartsTheThirtyMinuteClock(t *testing.T) {
	t.Parallel()
	store, _ := newTestApprovalStore(t)
	authority := testApprovalAuthority()
	candidate := testApprovalCandidate()
	grantedAt := time.Date(2030, 4, 5, 6, 7, 8, 0, time.UTC)
	current := grantedAt.Add(ApprovalConversationWindow)
	store.now = func() time.Time { return current }

	if _, err := store.RestorePrepared(authority, ApprovalLevelConversation30m, candidate, grantedAt); !errors.Is(err, ErrApprovalGrantWindowExpired) {
		t.Fatalf("expired prepared conversation approval was restored with a new clock: %v", err)
	}
	grants, err := store.List(authority)
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 0 {
		t.Fatalf("expired recovery created grants: %#v", grants)
	}
}

func TestStandingApprovalCrashRecoveryRestoresExplicitCeilingExpansion(t *testing.T) {
	t.Parallel()
	store, path := newTestApprovalStore(t)
	authority := testApprovalAuthority()
	grantedAt := time.Date(2030, 4, 5, 6, 7, 8, 0, time.UTC)
	current := grantedAt
	store.now = func() time.Time { return current }

	narrow := testApprovalCandidate()
	narrow.AccessScope = ApprovalAccessScope{
		RequestedAccess: []protocol.RequestedAccess{{WorkspaceAlias: "repo-read", Mode: protocol.PermissionReadOnly}},
	}
	original, err := store.Upsert(authority, ApprovalLevelConversation30m, narrow)
	if err != nil {
		t.Fatal(err)
	}
	if original.ExpiresAt == nil {
		t.Fatal("conversation grant has no expiry")
	}

	broader := narrow
	broader.AccessScope = ApprovalAccessScope{
		RequestedAccess: []protocol.RequestedAccess{
			{WorkspaceAlias: "repo-read", Mode: protocol.PermissionGuardedWrite},
			{WorkspaceAlias: "repo-extra", Mode: protocol.PermissionReadOnly},
		},
		MaxAttachmentCount: 2,
		MaxAttachmentBytes: 512,
	}
	current = grantedAt.Add(10 * time.Minute)
	restored, err := store.RestorePrepared(authority, ApprovalLevelConversation30m, broader, current)
	if err != nil {
		t.Fatal(err)
	}
	if !approvalScopeCovers(restored.AccessCeiling, broader.AccessScope) {
		t.Fatalf("recovered grant did not restore explicit ceiling expansion: %#v", restored.AccessCeiling)
	}
	if !restored.CreatedAt.Equal(original.CreatedAt) || restored.ExpiresAt == nil || !restored.ExpiresAt.Equal(*original.ExpiresAt) {
		t.Fatalf("recovered expansion changed the fixed approval window: original=%#v restored=%#v", original, restored)
	}

	reopened, err := NewApprovalStore(path)
	if err != nil {
		t.Fatal(err)
	}
	reopened.now = func() time.Time { return current }
	matched, ok, err := reopened.Match(authority, broader)
	if err != nil || !ok || matched.GrantID != original.GrantID {
		t.Fatalf("expanded ceiling was not durable: grant=%#v present=%t err=%v", matched, ok, err)
	}
}

func TestApprovalStoreMigratesScopedVersionWithoutBroadening(t *testing.T) {
	t.Parallel()
	_, path := newTestApprovalStore(t)
	authority := testApprovalAuthority()
	candidate := testApprovalCandidate()
	grant := newApprovalGrant(authority, ApprovalLevelTeammateAlways, candidate, time.Now().UTC())
	previous := approvalSnapshot{
		Version: scopedApprovalStoreVersion, UpdatedAt: time.Now().UTC(),
		Grants: map[string]ApprovalGrant{grant.GrantID: grant},
	}
	payload, err := json.MarshalIndent(previous, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := privatefs.AtomicWriteFile(path, append(payload, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewApprovalStore(path)
	if err != nil {
		t.Fatal(err)
	}
	matched, ok, err := reopened.Match(authority, candidate)
	if err != nil || !ok || matched.GrantID != grant.GrantID {
		t.Fatalf("version 2 scoped grant was not preserved: grant=%#v present=%t err=%v", matched, ok, err)
	}
	upgradedPayload, err := privatefs.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var upgraded approvalSnapshot
	if err := json.Unmarshal(upgradedPayload, &upgraded); err != nil {
		t.Fatal(err)
	}
	if upgraded.Version != approvalStoreVersion || upgraded.Revocations == nil {
		t.Fatalf("version 2 store was not migrated to tombstone format: %#v", upgraded)
	}
}

func TestApprovalStoreReloadSeesGrantWrittenAfterConstruction(t *testing.T) {
	t.Parallel()
	first, path := newTestApprovalStore(t)
	stale, err := NewApprovalStore(path)
	if err != nil {
		t.Fatal(err)
	}
	want, err := first.Upsert(testApprovalAuthority(), ApprovalLevelTeammateAlways, testApprovalCandidate())
	if err != nil {
		t.Fatal(err)
	}
	if err := stale.Reload(); err != nil {
		t.Fatal(err)
	}
	got, ok, err := stale.Match(testApprovalAuthority(), testApprovalCandidate())
	if err != nil || !ok || got.GrantID != want.GrantID {
		t.Fatalf("reloaded grant = %#v, present=%t err=%v", got, ok, err)
	}
}

func TestApprovalStoreRejectsInvalidPersistedGrant(t *testing.T) {
	t.Parallel()
	_, path := newTestApprovalStore(t)
	authority := testApprovalAuthority()
	candidate := testApprovalCandidate()
	invalid := ApprovalGrant{
		Level: ApprovalLevelAskAlways, AuthorityFingerprint: authority.Fingerprint,
		RecipientAgentID: authority.RecipientAgentID, CreatedAt: time.Now().UTC(),
	}
	invalid.GrantID = stableApprovalGrantID(authority, invalid.Level, candidate)
	snapshot := approvalSnapshot{
		Version: approvalStoreVersion, UpdatedAt: time.Now().UTC(),
		Grants: map[string]ApprovalGrant{invalid.GrantID: invalid},
	}
	payload, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	payload = append(payload, '\n')
	if err := privatefs.AtomicWriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewApprovalStore(path); err == nil || !strings.Contains(err.Error(), "invalid grant") {
		t.Fatalf("invalid persisted ask_always grant error = %v", err)
	}
}

func TestApprovalStoreDropsLegacyGrantsWithoutResourceCeilings(t *testing.T) {
	t.Parallel()
	_, path := newTestApprovalStore(t)
	legacy := approvalSnapshot{
		Version: legacyApprovalStoreVersion, UpdatedAt: time.Now().UTC(),
		Grants: map[string]ApprovalGrant{
			"grant_legacy": {
				GrantID: "grant_legacy", Level: ApprovalLevelAllAlways,
				AuthorityFingerprint: "old-authority", RecipientAgentID: "old-agent", CreatedAt: time.Now().UTC(),
			},
		},
	}
	payload, err := json.MarshalIndent(legacy, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := privatefs.AtomicWriteFile(path, append(payload, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewApprovalStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(reopened.grants) != 0 {
		t.Fatalf("legacy wildcard grants survived migration: %#v", reopened.grants)
	}
	upgradedPayload, err := privatefs.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var upgraded approvalSnapshot
	if err := json.Unmarshal(upgradedPayload, &upgraded); err != nil {
		t.Fatal(err)
	}
	if upgraded.Version != approvalStoreVersion || len(upgraded.Grants) != 0 {
		t.Fatalf("legacy approval snapshot was not replaced safely: %#v", upgraded)
	}
}

func newTestApprovalStore(t *testing.T) (*ApprovalStore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state", "approval_grants.json")
	store, err := NewApprovalStore(path)
	if err != nil {
		t.Fatal(err)
	}
	return store, path
}

func testApprovalAuthority() ApprovalAuthority {
	return ApprovalAuthority{Fingerprint: "authority_a", RecipientAgentID: "agent_recipient"}
}

func testApprovalCandidate() ApprovalCandidate {
	return ApprovalCandidate{
		RequesterMemberID: "mem_alice", RequesterDisplayName: "Alice", ConversationID: "conv_question",
	}
}

func withApprovalScope(candidate ApprovalCandidate, scope ApprovalAccessScope) ApprovalCandidate {
	candidate.AccessScope = scope
	return candidate
}
