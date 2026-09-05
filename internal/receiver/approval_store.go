package receiver

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/mohitbadwal/team-relay/internal/privatefs"
	"github.com/mohitbadwal/team-relay/internal/protocol"
)

const (
	approvalStoreVersion       = 3
	scopedApprovalStoreVersion = 2
	legacyApprovalStoreVersion = 1
	ApprovalConversationWindow = 30 * time.Minute
)

var (
	ErrApprovalGrantRevoked       = errors.New("standing approval grant was revoked")
	ErrApprovalGrantWindowExpired = errors.New("standing approval grant window expired")
)

// ApprovalLevel is a recipient-owned choice about how often Team Relay should
// ask before approving a request. AskAlways is the absence of a standing grant
// and is therefore valid input but is never persisted.
type ApprovalLevel string

const (
	ApprovalLevelAskAlways       ApprovalLevel = "ask_always"
	ApprovalLevelConversation30m ApprovalLevel = "conversation_30m"
	ApprovalLevelTeammateAlways  ApprovalLevel = "teammate_always"
	ApprovalLevelAllAlways       ApprovalLevel = "all_always"
)

func (l ApprovalLevel) Valid() bool {
	switch l {
	case ApprovalLevelAskAlways, ApprovalLevelConversation30m, ApprovalLevelTeammateAlways, ApprovalLevelAllAlways:
		return true
	default:
		return false
	}
}

func (l ApprovalLevel) standing() bool {
	return l.Valid() && l != ApprovalLevelAskAlways
}

// ApprovalAuthority binds grants to one relay enrollment and one recipient
// agent. The fingerprint should be a stable, one-way namespace derived by the
// caller from the enrollment authority (for example, relay origin plus device
// credential). An old grant must not carry into a different enrollment.
type ApprovalAuthority struct {
	Fingerprint      string `json:"authority_fingerprint"`
	RecipientAgentID string `json:"recipient_agent_id"`
}

// ApprovalCandidate contains only trusted identity metadata derived from a
// pending request. DisplayName is a UI label and never participates in matching.
type ApprovalCandidate struct {
	RequesterMemberID    string              `json:"requester_member_id"`
	RequesterDisplayName string              `json:"requester_display_name,omitempty"`
	ConversationID       string              `json:"conversation_id,omitempty"`
	AccessScope          ApprovalAccessScope `json:"access_scope"`
}

// ApprovalAccessScope is the maximum resource access covered by one standing
// approval. Workspace aliases are recipient-owned names, sorted and unique.
// A future request may omit aliases or request a weaker mode, but it may not
// introduce a new alias or strengthen a mode. Attachment limits deliberately
// capture presence as well as bounded volume: a grant created without an
// attachment can never silently approve a later request containing one.
//
// Shell, network and MCP permissions are part of ApprovalAuthority instead of
// this request scope because the wire protocol does not let a requester vary
// them per request. Changing any of those effective permissions changes the
// authority fingerprint and invalidates the entire grant.
type ApprovalAccessScope struct {
	RequestedAccess    []protocol.RequestedAccess `json:"requested_access,omitempty"`
	MaxAttachmentCount int                        `json:"max_attachment_count,omitempty"`
	MaxAttachmentBytes int64                      `json:"max_attachment_bytes,omitempty"`
}

// ApprovalGrant is recipient-local policy. The relay never owns or evaluates
// these records; a match merely authorizes the receiver to issue the existing
// per-request Allow Once decision.
type ApprovalGrant struct {
	GrantID              string              `json:"grant_id"`
	Level                ApprovalLevel       `json:"level"`
	AuthorityFingerprint string              `json:"authority_fingerprint"`
	RecipientAgentID     string              `json:"recipient_agent_id"`
	RequesterMemberID    string              `json:"requester_member_id,omitempty"`
	RequesterDisplayName string              `json:"requester_display_name,omitempty"`
	ConversationID       string              `json:"conversation_id,omitempty"`
	AccessCeiling        ApprovalAccessScope `json:"access_ceiling"`
	CreatedAt            time.Time           `json:"created_at"`
	ExpiresAt            *time.Time          `json:"expires_at,omitempty"`
}

// ApprovalRevocation is a durable tombstone. It prevents crash recovery from
// recreating a grant that was successfully written, shown to the user and then
// revoked before the request journal could record ApprovalGrantPersisted.
// A later explicit approval may intentionally clear the tombstone.
type ApprovalRevocation struct {
	AuthorityFingerprint string    `json:"authority_fingerprint"`
	RecipientAgentID     string    `json:"recipient_agent_id"`
	RevokedAt            time.Time `json:"revoked_at"`
}

type approvalSnapshot struct {
	Version     int                           `json:"version"`
	UpdatedAt   time.Time                     `json:"updated_at"`
	Grants      map[string]ApprovalGrant      `json:"grants"`
	Revocations map[string]ApprovalRevocation `json:"revocations"`
}

// ApprovalStore persists standing approval grants in a private, atomically
// replaced JSON file. All public operations prune grants belonging to a stale
// authority/recipient before returning anything to the caller.
type ApprovalStore struct {
	mu          sync.RWMutex
	path        string
	grants      map[string]ApprovalGrant
	revocations map[string]ApprovalRevocation
	now         func() time.Time
}

func NewApprovalStore(path string) (*ApprovalStore, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("approval store path is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve approval store path: %w", err)
	}
	if err := privatefs.EnsureDirectory(filepath.Dir(abs)); err != nil {
		return nil, fmt.Errorf("prepare approval store directory: %w", err)
	}
	store := &ApprovalStore{
		path: abs, grants: make(map[string]ApprovalGrant), revocations: make(map[string]ApprovalRevocation), now: time.Now,
	}
	if err := store.load(); err != nil {
		return nil, err
	}
	return store, nil
}

// Reload refreshes the in-memory snapshot after the receiver process acquires
// exclusive ownership of its state directory. This prevents a grant written by
// the previous daemon between construction and lock acquisition from being
// lost to a stale in-memory snapshot.
func (s *ApprovalStore) Reload() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.load()
}

// List returns only grants bound to authority. Expired and stale-enrollment
// records are removed before the result is returned.
func (s *ApprovalStore) List(authority ApprovalAuthority) ([]ApprovalGrant, error) {
	authority, err := normalizeApprovalAuthority(authority)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.pruneAndPersistLocked(authority, s.now().UTC()); err != nil {
		return nil, err
	}
	result := make([]ApprovalGrant, 0, len(s.grants))
	for _, grant := range s.grants {
		result = append(result, cloneApprovalGrant(grant))
	}
	sort.Slice(result, func(i, j int) bool {
		left, right := approvalPrecedence(result[i].Level), approvalPrecedence(result[j].Level)
		if left != right {
			return left < right
		}
		if !result[i].CreatedAt.Equal(result[j].CreatedAt) {
			return result[i].CreatedAt.Before(result[j].CreatedAt)
		}
		return result[i].GrantID < result[j].GrantID
	})
	return result, nil
}

// Upsert creates a standing grant for a trusted pending request. Repeating an
// upsert returns the original record, including its original absolute expiry;
// it never turns the 30-minute conversation window into a sliding window.
// AskAlways returns a zero grant after pruning and writes no ask-always record.
func (s *ApprovalStore) Upsert(authority ApprovalAuthority, level ApprovalLevel, candidate ApprovalCandidate) (ApprovalGrant, error) {
	authority, err := normalizeApprovalAuthority(authority)
	if err != nil {
		return ApprovalGrant{}, err
	}
	if !level.Valid() {
		return ApprovalGrant{}, fmt.Errorf("approval level %q is invalid", level)
	}
	if level.standing() {
		candidate, err = normalizeApprovalCandidate(candidate, true)
		if err != nil {
			return ApprovalGrant{}, err
		}
		if level == ApprovalLevelConversation30m && candidate.ConversationID == "" {
			return ApprovalGrant{}, errors.New("conversation approval requires conversation_id")
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	before := cloneApprovalGrants(s.grants)
	beforeRevocations := cloneApprovalRevocations(s.revocations)
	now := s.now().UTC()
	changed := s.pruneLocked(authority, now) > 0
	if level == ApprovalLevelAskAlways {
		if changed {
			if err := s.writeLocked(); err != nil {
				s.grants = before
				s.revocations = beforeRevocations
				return ApprovalGrant{}, err
			}
		}
		return ApprovalGrant{}, nil
	}

	grant := newApprovalGrant(authority, level, candidate, now)
	// This is a fresh, explicit recipient choice. Re-authorizing the same scope
	// is the only operation allowed to clear its revocation tombstone.
	if _, revoked := s.revocations[grant.GrantID]; revoked {
		delete(s.revocations, grant.GrantID)
		changed = true
	}
	if existing, ok := s.grants[grant.GrantID]; ok {
		// An explicit approval can replace an incomparable or narrower ceiling,
		// but an idempotent retry and a later same-or-narrower approval preserve
		// the original grant and the fixed conversation expiry.
		if !approvalScopeCovers(existing.AccessCeiling, candidate.AccessScope) {
			existing.AccessCeiling = candidate.AccessScope
			existing.RequesterDisplayName = grant.RequesterDisplayName
			s.grants[grant.GrantID] = existing
			changed = true
		}
		if changed {
			if err := s.writeLocked(); err != nil {
				s.grants = before
				s.revocations = beforeRevocations
				return ApprovalGrant{}, err
			}
		}
		return cloneApprovalGrant(existing), nil
	}
	s.grants[grant.GrantID] = grant
	if err := s.writeLocked(); err != nil {
		s.grants = before
		s.revocations = beforeRevocations
		return ApprovalGrant{}, err
	}
	return cloneApprovalGrant(grant), nil
}

// RestorePrepared recreates a standing grant only for crash recovery. Unlike
// Upsert, it never clears a revocation tombstone or restarts a fixed 30-minute
// window: a completed local revoke and the original approval time remain
// authoritative even if the receiver crashed before updating its journal.
func (s *ApprovalStore) RestorePrepared(authority ApprovalAuthority, level ApprovalLevel, candidate ApprovalCandidate, grantedAt time.Time) (ApprovalGrant, error) {
	authority, err := normalizeApprovalAuthority(authority)
	if err != nil {
		return ApprovalGrant{}, err
	}
	if !level.standing() {
		return ApprovalGrant{}, fmt.Errorf("approval level %q is not a standing approval", level)
	}
	candidate, err = normalizeApprovalCandidate(candidate, true)
	if err != nil {
		return ApprovalGrant{}, err
	}
	if level == ApprovalLevelConversation30m && candidate.ConversationID == "" {
		return ApprovalGrant{}, errors.New("conversation approval requires conversation_id")
	}
	if grantedAt.IsZero() {
		return ApprovalGrant{}, errors.New("prepared approval time is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	before := cloneApprovalGrants(s.grants)
	beforeRevocations := cloneApprovalRevocations(s.revocations)
	now := s.now().UTC()
	grantedAt = grantedAt.UTC()
	// A wall-clock correction must never extend a recovered approval into the
	// future. Clamp an apparently future journal timestamp to the current time.
	if grantedAt.After(now) {
		grantedAt = now
	}
	changed := s.pruneLocked(authority, now) > 0
	grant := newApprovalGrant(authority, level, candidate, grantedAt)
	if _, revoked := s.revocations[grant.GrantID]; revoked {
		if changed {
			if err := s.writeLocked(); err != nil {
				s.grants = before
				s.revocations = beforeRevocations
				return ApprovalGrant{}, err
			}
		}
		return ApprovalGrant{}, fmt.Errorf("%w: %s", ErrApprovalGrantRevoked, grant.GrantID)
	}
	if approvalGrantExpired(grant, now) {
		if changed {
			if err := s.writeLocked(); err != nil {
				s.grants = before
				s.revocations = beforeRevocations
				return ApprovalGrant{}, err
			}
		}
		return ApprovalGrant{}, fmt.Errorf("%w: %s", ErrApprovalGrantWindowExpired, grant.GrantID)
	}
	if existing, ok := s.grants[grant.GrantID]; ok {
		// The prepared mutation records an explicit recipient choice. If a
		// narrower (or otherwise incomparable) copy of the same stable grant was
		// already present, restore the exact approved ceiling just as Upsert did
		// before the crash. Preserve the original timestamps so a conversation
		// grant can never acquire a fresh or sliding 30-minute window.
		if !approvalScopeCovers(existing.AccessCeiling, candidate.AccessScope) {
			existing.AccessCeiling = candidate.AccessScope
			existing.RequesterDisplayName = grant.RequesterDisplayName
			s.grants[grant.GrantID] = existing
			changed = true
		}
		if changed {
			if err := s.writeLocked(); err != nil {
				s.grants = before
				s.revocations = beforeRevocations
				return ApprovalGrant{}, err
			}
		}
		return cloneApprovalGrant(existing), nil
	}
	s.grants[grant.GrantID] = grant
	if err := s.writeLocked(); err != nil {
		s.grants = before
		s.revocations = beforeRevocations
		return ApprovalGrant{}, err
	}
	return cloneApprovalGrant(grant), nil
}

// Revoke removes one grant in the current authority namespace. The boolean is
// false when the grant was already absent. Stale authority records are pruned.
func (s *ApprovalStore) Revoke(authority ApprovalAuthority, grantID string) (bool, error) {
	authority, err := normalizeApprovalAuthority(authority)
	if err != nil {
		return false, err
	}
	grantID = strings.TrimSpace(grantID)
	if !validApprovalGrantID(grantID) {
		return false, errors.New("approval grant_id is invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	before := cloneApprovalGrants(s.grants)
	beforeRevocations := cloneApprovalRevocations(s.revocations)
	changed := s.pruneLocked(authority, s.now().UTC()) > 0
	_, existed := s.grants[grantID]
	if existed {
		delete(s.grants, grantID)
		s.revocations[grantID] = ApprovalRevocation{
			AuthorityFingerprint: authority.Fingerprint,
			RecipientAgentID:     authority.RecipientAgentID,
			RevokedAt:            s.now().UTC(),
		}
		changed = true
	}
	if changed {
		if err := s.writeLocked(); err != nil {
			s.grants = before
			s.revocations = beforeRevocations
			return false, err
		}
	}
	return existed, nil
}

// Prune removes expired grants and grants bound to any authority or recipient
// other than the supplied current enrollment.
func (s *ApprovalStore) Prune(authority ApprovalAuthority) (int, error) {
	authority, err := normalizeApprovalAuthority(authority)
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pruneAndPersistLocked(authority, s.now().UTC())
}

// Match returns the most specific active grant for candidate. A missing member
// identity fails closed even when an all-teammates grant exists.
func (s *ApprovalStore) Match(authority ApprovalAuthority, candidate ApprovalCandidate) (ApprovalGrant, bool, error) {
	authority, err := normalizeApprovalAuthority(authority)
	if err != nil {
		return ApprovalGrant{}, false, err
	}
	candidate, err = normalizeApprovalCandidate(candidate, false)
	if err != nil {
		return ApprovalGrant{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.pruneAndPersistLocked(authority, s.now().UTC()); err != nil {
		return ApprovalGrant{}, false, err
	}
	if candidate.RequesterMemberID == "" {
		return ApprovalGrant{}, false, nil
	}
	levels := []ApprovalLevel{ApprovalLevelConversation30m, ApprovalLevelTeammateAlways, ApprovalLevelAllAlways}
	for _, level := range levels {
		if level == ApprovalLevelConversation30m && candidate.ConversationID == "" {
			continue
		}
		id := stableApprovalGrantID(authority, level, candidate)
		if grant, ok := s.grants[id]; ok {
			if approvalScopeCovers(grant.AccessCeiling, candidate.AccessScope) {
				return cloneApprovalGrant(grant), true, nil
			}
		}
	}
	return ApprovalGrant{}, false, nil
}

func (s *ApprovalStore) load() error {
	payload, err := privatefs.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return s.writeLocked()
	}
	if err != nil {
		return fmt.Errorf("read approval store: %w", err)
	}
	var snapshot approvalSnapshot
	if err := json.Unmarshal(payload, &snapshot); err != nil {
		return fmt.Errorf("parse approval store: %w", err)
	}
	if snapshot.Version == legacyApprovalStoreVersion {
		// Version 1 grants had no resource ceiling. Treating that omission as a
		// wildcard would broaden authority, so upgrade by dropping every legacy
		// grant and requiring the recipient to make a fresh explicit choice.
		s.grants = make(map[string]ApprovalGrant)
		s.revocations = make(map[string]ApprovalRevocation)
		return s.writeLocked()
	}
	if snapshot.Version != approvalStoreVersion && snapshot.Version != scopedApprovalStoreVersion {
		return fmt.Errorf("unsupported approval store version %d", snapshot.Version)
	}
	grants := make(map[string]ApprovalGrant, len(snapshot.Grants))
	for grantID, grant := range snapshot.Grants {
		if grantID == "" || grantID != grant.GrantID {
			return errors.New("approval store contains an invalid grant identity")
		}
		if err := validateApprovalGrant(grant); err != nil {
			return fmt.Errorf("approval store contains an invalid grant %q: %w", grantID, err)
		}
		if approvalGrantExpired(grant, s.now().UTC()) {
			continue
		}
		grants[grantID] = cloneApprovalGrant(grant)
	}
	revocations := make(map[string]ApprovalRevocation, len(snapshot.Revocations))
	for grantID, revocation := range snapshot.Revocations {
		if !validApprovalGrantID(grantID) || revocation.RevokedAt.IsZero() {
			return fmt.Errorf("approval store contains an invalid revocation %q", grantID)
		}
		authority, authorityErr := normalizeApprovalAuthority(ApprovalAuthority{
			Fingerprint: revocation.AuthorityFingerprint, RecipientAgentID: revocation.RecipientAgentID,
		})
		if authorityErr != nil || authority.Fingerprint != revocation.AuthorityFingerprint || authority.RecipientAgentID != revocation.RecipientAgentID {
			return fmt.Errorf("approval store contains an invalid revocation authority for %q", grantID)
		}
		if _, exists := grants[grantID]; exists {
			return fmt.Errorf("approval store contains both a grant and revocation for %q", grantID)
		}
		revocations[grantID] = revocation
	}
	expiredRemoved := len(grants) != len(snapshot.Grants)
	s.grants = grants
	s.revocations = revocations
	if expiredRemoved || snapshot.Version == scopedApprovalStoreVersion {
		return s.writeLocked()
	}
	return nil
}

func (s *ApprovalStore) pruneAndPersistLocked(authority ApprovalAuthority, now time.Time) (int, error) {
	before := cloneApprovalGrants(s.grants)
	beforeRevocations := cloneApprovalRevocations(s.revocations)
	removed := s.pruneLocked(authority, now)
	if removed == 0 {
		return 0, nil
	}
	if err := s.writeLocked(); err != nil {
		s.grants = before
		s.revocations = beforeRevocations
		return 0, err
	}
	return removed, nil
}

func (s *ApprovalStore) pruneLocked(authority ApprovalAuthority, now time.Time) int {
	removed := 0
	for grantID, grant := range s.grants {
		if grant.AuthorityFingerprint != authority.Fingerprint || grant.RecipientAgentID != authority.RecipientAgentID || approvalGrantExpired(grant, now) {
			delete(s.grants, grantID)
			removed++
		}
	}
	// Revocation tombstones intentionally survive authority switches. Their
	// stable grant IDs already include the old authority, so they cannot affect
	// matching under the new one. Deleting them here could resurrect a revoked
	// grant if an old prepared mutation is later reopened under its original
	// authority.
	return removed
}

func (s *ApprovalStore) writeLocked() error {
	snapshot := approvalSnapshot{
		Version: approvalStoreVersion, UpdatedAt: s.now().UTC(),
		Grants: cloneApprovalGrants(s.grants), Revocations: cloneApprovalRevocations(s.revocations),
	}
	payload, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return fmt.Errorf("encode approval store: %w", err)
	}
	if err := privatefs.AtomicWriteFile(s.path, append(payload, '\n'), 0o600); err != nil {
		return fmt.Errorf("persist approval store: %w", err)
	}
	return nil
}

func newApprovalGrant(authority ApprovalAuthority, level ApprovalLevel, candidate ApprovalCandidate, now time.Time) ApprovalGrant {
	grant := ApprovalGrant{
		Level: level, AuthorityFingerprint: authority.Fingerprint, RecipientAgentID: authority.RecipientAgentID,
		AccessCeiling: candidate.AccessScope, CreatedAt: now,
	}
	switch level {
	case ApprovalLevelConversation30m:
		grant.RequesterMemberID = candidate.RequesterMemberID
		grant.RequesterDisplayName = candidate.RequesterDisplayName
		grant.ConversationID = candidate.ConversationID
		expiresAt := now.Add(ApprovalConversationWindow)
		grant.ExpiresAt = &expiresAt
	case ApprovalLevelTeammateAlways:
		grant.RequesterMemberID = candidate.RequesterMemberID
		grant.RequesterDisplayName = candidate.RequesterDisplayName
	case ApprovalLevelAllAlways:
	}
	grant.GrantID = stableApprovalGrantID(authority, level, candidate)
	return grant
}

func stableApprovalGrantID(authority ApprovalAuthority, level ApprovalLevel, candidate ApprovalCandidate) string {
	memberID, conversationID := "", ""
	switch level {
	case ApprovalLevelConversation30m:
		memberID, conversationID = candidate.RequesterMemberID, candidate.ConversationID
	case ApprovalLevelTeammateAlways:
		memberID = candidate.RequesterMemberID
	}
	payload := strings.Join([]string{
		"team-relay-approval-grant/v2", authority.Fingerprint, authority.RecipientAgentID,
		string(level), memberID, conversationID,
	}, "\x00")
	digest := sha256.Sum256([]byte(payload))
	return "grant_" + hex.EncodeToString(digest[:])
}

func validateApprovalGrant(grant ApprovalGrant) error {
	authority, err := normalizeApprovalAuthority(ApprovalAuthority{Fingerprint: grant.AuthorityFingerprint, RecipientAgentID: grant.RecipientAgentID})
	if err != nil || authority.Fingerprint != grant.AuthorityFingerprint || authority.RecipientAgentID != grant.RecipientAgentID {
		return errors.New("grant authority is invalid")
	}
	if !grant.Level.standing() || grant.CreatedAt.IsZero() {
		return errors.New("grant level and created_at are required")
	}
	candidate, err := normalizeApprovalCandidate(ApprovalCandidate{
		RequesterMemberID: grant.RequesterMemberID, RequesterDisplayName: grant.RequesterDisplayName, ConversationID: grant.ConversationID,
		AccessScope: grant.AccessCeiling,
	}, grant.Level != ApprovalLevelAllAlways)
	if err != nil || candidate.RequesterMemberID != grant.RequesterMemberID || candidate.RequesterDisplayName != grant.RequesterDisplayName || candidate.ConversationID != grant.ConversationID ||
		!sameApprovalAccessScope(candidate.AccessScope, grant.AccessCeiling) {
		return errors.New("grant subject is invalid")
	}
	switch grant.Level {
	case ApprovalLevelConversation30m:
		if candidate.RequesterMemberID == "" || candidate.ConversationID == "" || grant.ExpiresAt == nil || !grant.ExpiresAt.Equal(grant.CreatedAt.Add(ApprovalConversationWindow)) {
			return errors.New("conversation grant must contain one fixed 30-minute member conversation window")
		}
	case ApprovalLevelTeammateAlways:
		if candidate.RequesterMemberID == "" || candidate.ConversationID != "" || grant.ExpiresAt != nil {
			return errors.New("teammate grant contains inconsistent scope fields")
		}
	case ApprovalLevelAllAlways:
		if candidate.RequesterMemberID != "" || candidate.RequesterDisplayName != "" || candidate.ConversationID != "" || grant.ExpiresAt != nil {
			return errors.New("all-teammates grant contains inconsistent scope fields")
		}
	}
	wantID := stableApprovalGrantID(authority, grant.Level, candidate)
	if grant.GrantID != wantID || !validApprovalGrantID(grant.GrantID) {
		return errors.New("grant_id does not match its authority and scope")
	}
	return nil
}

func normalizeApprovalAuthority(authority ApprovalAuthority) (ApprovalAuthority, error) {
	authority.Fingerprint = strings.TrimSpace(authority.Fingerprint)
	authority.RecipientAgentID = strings.TrimSpace(authority.RecipientAgentID)
	if !validApprovalValue(authority.Fingerprint, 256, false) {
		return ApprovalAuthority{}, errors.New("approval authority fingerprint is required and must be valid")
	}
	if !validApprovalValue(authority.RecipientAgentID, 200, false) {
		return ApprovalAuthority{}, errors.New("approval recipient agent_id is required and must be valid")
	}
	return authority, nil
}

func normalizeApprovalCandidate(candidate ApprovalCandidate, requireMember bool) (ApprovalCandidate, error) {
	candidate.RequesterMemberID = strings.TrimSpace(candidate.RequesterMemberID)
	candidate.RequesterDisplayName = strings.TrimSpace(candidate.RequesterDisplayName)
	candidate.ConversationID = strings.TrimSpace(candidate.ConversationID)
	if requireMember && !validApprovalValue(candidate.RequesterMemberID, 200, false) {
		return ApprovalCandidate{}, errors.New("approval requester member_id is required and must be valid")
	}
	if candidate.RequesterMemberID != "" && !validApprovalValue(candidate.RequesterMemberID, 200, false) {
		return ApprovalCandidate{}, errors.New("approval requester member_id is invalid")
	}
	if candidate.ConversationID != "" && !validApprovalValue(candidate.ConversationID, 200, false) {
		return ApprovalCandidate{}, errors.New("approval conversation_id is invalid")
	}
	if candidate.RequesterDisplayName != "" && !validApprovalValue(candidate.RequesterDisplayName, 200, true) {
		return ApprovalCandidate{}, errors.New("approval requester display name is invalid")
	}
	var err error
	candidate.AccessScope, err = normalizeApprovalAccessScope(candidate.AccessScope)
	if err != nil {
		return ApprovalCandidate{}, err
	}
	return candidate, nil
}

func normalizeApprovalAccessScope(scope ApprovalAccessScope) (ApprovalAccessScope, error) {
	if scope.MaxAttachmentCount < 0 || scope.MaxAttachmentCount > protocol.MaxAttachments {
		return ApprovalAccessScope{}, errors.New("approval attachment count ceiling is invalid")
	}
	if scope.MaxAttachmentBytes < 0 || scope.MaxAttachmentBytes > protocol.MaxRequestPayloadBytes {
		return ApprovalAccessScope{}, errors.New("approval attachment byte ceiling is invalid")
	}
	if scope.MaxAttachmentCount == 0 && scope.MaxAttachmentBytes != 0 {
		return ApprovalAccessScope{}, errors.New("approval attachment byte ceiling requires attachment presence")
	}

	normalized := ApprovalAccessScope{
		RequestedAccess:    append([]protocol.RequestedAccess(nil), scope.RequestedAccess...),
		MaxAttachmentCount: scope.MaxAttachmentCount,
		MaxAttachmentBytes: scope.MaxAttachmentBytes,
	}
	seen := make(map[string]struct{}, len(normalized.RequestedAccess))
	for index := range normalized.RequestedAccess {
		access := &normalized.RequestedAccess[index]
		access.WorkspaceAlias = strings.TrimSpace(access.WorkspaceAlias)
		if !validApprovalValue(access.WorkspaceAlias, 200, false) || strings.ContainsAny(access.WorkspaceAlias, `/\\`) {
			return ApprovalAccessScope{}, errors.New("approval workspace alias is invalid")
		}
		if access.Mode != protocol.PermissionReadOnly && access.Mode != protocol.PermissionGuardedWrite {
			return ApprovalAccessScope{}, errors.New("approval workspace permission is invalid")
		}
		if _, ok := seen[access.WorkspaceAlias]; ok {
			return ApprovalAccessScope{}, fmt.Errorf("approval workspace alias %q appears more than once", access.WorkspaceAlias)
		}
		seen[access.WorkspaceAlias] = struct{}{}
	}
	sort.Slice(normalized.RequestedAccess, func(i, j int) bool {
		return normalized.RequestedAccess[i].WorkspaceAlias < normalized.RequestedAccess[j].WorkspaceAlias
	})
	return normalized, nil
}

func approvalScopeCovers(ceiling, requested ApprovalAccessScope) bool {
	ceiling, ceilingErr := normalizeApprovalAccessScope(ceiling)
	requested, requestedErr := normalizeApprovalAccessScope(requested)
	if ceilingErr != nil || requestedErr != nil ||
		requested.MaxAttachmentCount > ceiling.MaxAttachmentCount ||
		requested.MaxAttachmentBytes > ceiling.MaxAttachmentBytes {
		return false
	}
	allowed := make(map[string]protocol.PermissionMode, len(ceiling.RequestedAccess))
	for _, access := range ceiling.RequestedAccess {
		allowed[access.WorkspaceAlias] = access.Mode
	}
	for _, access := range requested.RequestedAccess {
		ceilingMode, ok := allowed[access.WorkspaceAlias]
		if !ok || approvalPermissionRank(access.Mode) > approvalPermissionRank(ceilingMode) {
			return false
		}
	}
	return true
}

func approvalPermissionRank(mode protocol.PermissionMode) int {
	if mode == protocol.PermissionGuardedWrite {
		return 1
	}
	return 0
}

func sameApprovalAccessScope(left, right ApprovalAccessScope) bool {
	if left.MaxAttachmentCount != right.MaxAttachmentCount || left.MaxAttachmentBytes != right.MaxAttachmentBytes || len(left.RequestedAccess) != len(right.RequestedAccess) {
		return false
	}
	for index := range left.RequestedAccess {
		if left.RequestedAccess[index] != right.RequestedAccess[index] {
			return false
		}
	}
	return true
}

func validApprovalValue(value string, maximum int, allowSpaces bool) bool {
	if value == "" || len([]byte(value)) > maximum {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || (!allowSpaces && unicode.IsSpace(character)) {
			return false
		}
	}
	return true
}

func validApprovalGrantID(value string) bool {
	const prefix = "grant_"
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+64 {
		return false
	}
	_, err := hex.DecodeString(value[len(prefix):])
	return err == nil
}

func approvalGrantExpired(grant ApprovalGrant, now time.Time) bool {
	return grant.ExpiresAt != nil && !now.Before(*grant.ExpiresAt)
}

func approvalPrecedence(level ApprovalLevel) int {
	switch level {
	case ApprovalLevelConversation30m:
		return 0
	case ApprovalLevelTeammateAlways:
		return 1
	case ApprovalLevelAllAlways:
		return 2
	default:
		return 3
	}
}

func cloneApprovalGrant(grant ApprovalGrant) ApprovalGrant {
	grant.AccessCeiling.RequestedAccess = append([]protocol.RequestedAccess(nil), grant.AccessCeiling.RequestedAccess...)
	if grant.ExpiresAt != nil {
		expiresAt := *grant.ExpiresAt
		grant.ExpiresAt = &expiresAt
	}
	return grant
}

func cloneApprovalGrants(grants map[string]ApprovalGrant) map[string]ApprovalGrant {
	result := make(map[string]ApprovalGrant, len(grants))
	for grantID, grant := range grants {
		result[grantID] = cloneApprovalGrant(grant)
	}
	return result
}

func cloneApprovalRevocations(revocations map[string]ApprovalRevocation) map[string]ApprovalRevocation {
	result := make(map[string]ApprovalRevocation, len(revocations))
	for grantID, revocation := range revocations {
		result[grantID] = revocation
	}
	return result
}
