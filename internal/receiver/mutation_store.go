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

	"github.com/mohitbadwal/team-relay/internal/privatefs"
	"github.com/mohitbadwal/team-relay/internal/protocol"
)

const (
	mutationStoreVersion               = 3
	legacyMutationStoreVersion         = 1
	authorityBoundMutationStoreVersion = 2
	approvedNoticeBindingVersion       = 1
)

type mutationPhase string

const (
	mutationDecisionPrepared mutationPhase = "decision_prepared"
	mutationClaimPrepared    mutationPhase = "claim_prepared"
	mutationRuntimeStarted   mutationPhase = "runtime_started"
	mutationResultPrepared   mutationPhase = "result_prepared"
)

// mutationRecord is the receiver's write-ahead record for network mutations.
// Every value needed for an exact retry is synced before the corresponding
// relay mutation or local runtime execution begins.
type mutationRecord struct {
	RequestID              string            `json:"request_id"`
	ConversationID         string            `json:"conversation_id,omitempty"`
	DecisionID             string            `json:"decision_id,omitempty"`
	Decision               protocol.Decision `json:"decision,omitempty"`
	ApprovalLevel          ApprovalLevel     `json:"approval_level,omitempty"`
	ApprovalGrantID        string            `json:"approval_grant_id,omitempty"`
	ApprovalGrantPersisted bool              `json:"approval_grant_persisted,omitempty"`
	// Every allow is bound before the relay mutation to the exact effective
	// enrollment, recipient agent, policy and work directory represented by
	// ApprovalAuthority. Legacy records may be loaded without these fields only
	// so recovery can refuse them safely; new allow records cannot omit them.
	ApprovalAuthorityFingerprint string `json:"approval_authority_fingerprint,omitempty"`
	ApprovalRecipientAgentID     string `json:"approval_recipient_agent_id,omitempty"`
	// ApprovedNotice is the immutable, approval-safe request metadata that the
	// recipient authorized. It deliberately stores only the prompt byte count
	// and SHA-256 digest, never the prompt itself. The current inbox notice and
	// the post-approval execution payload must both match this record before the
	// relay can be marked running.
	ApprovedNotice   *approvedNoticeBinding  `json:"approved_notice,omitempty"`
	ExecutionClaimID string                  `json:"execution_claim_id,omitempty"`
	Phase            mutationPhase           `json:"phase"`
	Result           *protocol.ResultPayload `json:"result,omitempty"`
	UpdatedAt        time.Time               `json:"updated_at"`
}

// approvedNoticeBinding is safe to persist beside PendingStore: it contains
// the same approval metadata and only a cryptographic commitment to the prompt.
// Slice order is intentional because the recipient approves the requested
// workspace and attachment sequence exactly as presented.
type approvedNoticeBinding struct {
	Version              int                           `json:"version"`
	RequestID            string                        `json:"request_id"`
	ConversationID       string                        `json:"conversation_id"`
	RequesterAgentID     string                        `json:"requester_agent_id"`
	RequesterMemberID    string                        `json:"requester_member_id,omitempty"`
	RequesterDisplayName string                        `json:"requester_display_name"`
	Title                string                        `json:"title"`
	ExpiresAt            time.Time                     `json:"expires_at"`
	RequestedAccess      []protocol.RequestedAccess    `json:"requested_access,omitempty"`
	Attachments          []protocol.ArtifactDescriptor `json:"attachments,omitempty"`
	PromptBytes          int64                         `json:"prompt_bytes"`
	PromptSHA256         string                        `json:"prompt_sha256"`
}

type mutationSnapshot struct {
	Version   int                       `json:"version"`
	UpdatedAt time.Time                 `json:"updated_at"`
	Records   map[string]mutationRecord `json:"records"`
}

type mutationStore struct {
	mu      sync.RWMutex
	path    string
	records map[string]mutationRecord
}

func newMutationStore(path string) (*mutationStore, error) {
	if path == "" {
		return nil, errors.New("receiver mutation store path is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve receiver mutation store: %w", err)
	}
	if err := privatefs.EnsureDirectory(filepath.Dir(abs)); err != nil {
		return nil, fmt.Errorf("prepare receiver mutation store directory: %w", err)
	}
	store := &mutationStore{path: abs, records: make(map[string]mutationRecord)}
	if err := store.Reload(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *mutationStore) Get(requestID string) (mutationRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.records[requestID]
	return cloneMutationRecord(record), ok
}

func (s *mutationStore) List() []mutationRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]mutationRecord, 0, len(s.records))
	for _, record := range s.records {
		result = append(result, cloneMutationRecord(record))
	}
	sort.Slice(result, func(i, j int) bool { return result[i].RequestID < result[j].RequestID })
	return result
}

func (s *mutationStore) Put(record mutationRecord) error {
	if err := validateMutationRecord(record); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record.UpdatedAt = time.Now().UTC()
	previous, existed := s.records[record.RequestID]
	s.records[record.RequestID] = cloneMutationRecord(record)
	if err := s.writeLocked(); err != nil {
		if existed {
			s.records[record.RequestID] = previous
		} else {
			delete(s.records, record.RequestID)
		}
		return err
	}
	return nil
}

func (s *mutationStore) Update(requestID string, update func(*mutationRecord) error) (mutationRecord, error) {
	if update == nil {
		return mutationRecord{}, errors.New("receiver mutation update is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.records[requestID]
	if !ok {
		return mutationRecord{}, fmt.Errorf("receiver mutation for request %q is missing", requestID)
	}
	previous := cloneMutationRecord(current)
	current = cloneMutationRecord(current)
	if err := update(&current); err != nil {
		return mutationRecord{}, err
	}
	if current.RequestID != requestID {
		return mutationRecord{}, errors.New("receiver mutation update changed request_id")
	}
	if err := validateMutationRecord(current); err != nil {
		return mutationRecord{}, err
	}
	current.UpdatedAt = time.Now().UTC()
	s.records[requestID] = cloneMutationRecord(current)
	if err := s.writeLocked(); err != nil {
		s.records[requestID] = previous
		return mutationRecord{}, err
	}
	return cloneMutationRecord(current), nil
}

func (s *mutationStore) Remove(requestID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	previous, ok := s.records[requestID]
	if !ok {
		return nil
	}
	delete(s.records, requestID)
	if err := s.writeLocked(); err != nil {
		s.records[requestID] = previous
		return err
	}
	return nil
}

// Reload refreshes the in-memory snapshot after this process has acquired the
// exclusive receiver-state lock. This matters when a Service was constructed
// while an older daemon still owned and updated the same state directory.
func (s *mutationStore) Reload() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reloadLocked()
}

func (s *mutationStore) reloadLocked() error {
	payload, err := privatefs.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		s.records = make(map[string]mutationRecord)
		return s.writeLocked()
	}
	if err != nil {
		return fmt.Errorf("read receiver mutation store: %w", err)
	}
	var snapshot mutationSnapshot
	if err := json.Unmarshal(payload, &snapshot); err != nil {
		return fmt.Errorf("parse receiver mutation store: %w", err)
	}
	if snapshot.Version != mutationStoreVersion &&
		snapshot.Version != authorityBoundMutationStoreVersion &&
		snapshot.Version != legacyMutationStoreVersion {
		return fmt.Errorf("unsupported receiver mutation store version %d", snapshot.Version)
	}
	records := make(map[string]mutationRecord, len(snapshot.Records))
	for requestID, record := range snapshot.Records {
		if requestID == "" || requestID != record.RequestID {
			return errors.New("receiver mutation store contains an invalid record")
		}
		if err := validateMutationRecordForLoad(record); err != nil {
			return fmt.Errorf("receiver mutation store contains an invalid record for %q: %w", requestID, err)
		}
		records[requestID] = cloneMutationRecord(record)
	}
	s.records = records
	return nil
}

func (s *mutationStore) writeLocked() error {
	snapshot := mutationSnapshot{
		Version: mutationStoreVersion, UpdatedAt: time.Now().UTC(),
		Records: make(map[string]mutationRecord, len(s.records)),
	}
	for requestID, record := range s.records {
		snapshot.Records[requestID] = cloneMutationRecord(record)
	}
	payload, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return fmt.Errorf("encode receiver mutation store: %w", err)
	}
	if err := privatefs.AtomicWriteFile(s.path, append(payload, '\n'), 0o600); err != nil {
		return fmt.Errorf("persist receiver mutation store: %w", err)
	}
	return nil
}

func cloneMutationRecord(record mutationRecord) mutationRecord {
	if record.ApprovedNotice != nil {
		binding := *record.ApprovedNotice
		binding.RequestedAccess = append([]protocol.RequestedAccess(nil), record.ApprovedNotice.RequestedAccess...)
		binding.Attachments = append([]protocol.ArtifactDescriptor(nil), record.ApprovedNotice.Attachments...)
		record.ApprovedNotice = &binding
	}
	if record.Result != nil {
		copy := *record.Result
		copy.ResultFiles = append([]protocol.AttachmentInput(nil), record.Result.ResultFiles...)
		record.Result = &copy
	}
	return record
}

func validateMutationRecord(record mutationRecord) error {
	return validateMutationRecordWithLegacy(record, false, false)
}

// validateMutationRecordForLoad accepts a complete historical record whose
// allow predates authority binding. Service recovery treats that record as
// untrusted and never executes it. All newly written allow records use the
// strict validator above.
func validateMutationRecordForLoad(record mutationRecord) error {
	return validateMutationRecordWithLegacy(record, true, true)
}

func validateMutationRecordWithLegacy(record mutationRecord, allowLegacyAuthority, allowLegacyNotice bool) error {
	if record.RequestID == "" || record.Phase == "" {
		return errors.New("receiver mutation request_id and phase are required")
	}
	validDecision := record.Decision == protocol.DecisionAllowOnce || record.Decision == protocol.DecisionDeny
	if record.DecisionID != "" && (!validDecision || !validLocalOpaqueID(record.DecisionID, "decision_")) {
		return errors.New("receiver mutation contains an invalid decision identity")
	}
	if record.ExecutionClaimID != "" && !validLocalOpaqueID(record.ExecutionClaimID, "claim_") {
		return errors.New("receiver mutation contains an invalid execution claim")
	}
	hasAuthorityFingerprint := record.ApprovalAuthorityFingerprint != ""
	hasRecipientAgent := record.ApprovalRecipientAgentID != ""
	if hasAuthorityFingerprint != hasRecipientAgent {
		return errors.New("receiver mutation contains an incomplete approval authority")
	}
	if hasAuthorityFingerprint {
		authority, err := normalizeApprovalAuthority(ApprovalAuthority{
			Fingerprint: record.ApprovalAuthorityFingerprint, RecipientAgentID: record.ApprovalRecipientAgentID,
		})
		if err != nil || authority.Fingerprint != record.ApprovalAuthorityFingerprint || authority.RecipientAgentID != record.ApprovalRecipientAgentID {
			return errors.New("receiver mutation contains an invalid approval authority")
		}
	}
	if record.Decision == protocol.DecisionDeny && (record.ApprovalLevel != "" || record.ApprovalGrantID != "" || record.ApprovalGrantPersisted) {
		return errors.New("Deny decision unexpectedly contains approval-grant intent")
	}
	if record.Decision == protocol.DecisionDeny && hasAuthorityFingerprint {
		return errors.New("Deny decision unexpectedly contains an approval authority")
	}
	if record.Decision == protocol.DecisionDeny && record.ApprovedNotice != nil {
		return errors.New("Deny decision unexpectedly contains an approved notice")
	}
	if record.Decision == protocol.DecisionAllowOnce && !hasAuthorityFingerprint && !allowLegacyAuthority {
		return errors.New("Allow Once decision has no bound approval authority")
	}
	if record.ApprovedNotice != nil {
		if err := validateApprovedNoticeBinding(*record.ApprovedNotice, record.RequestID); err != nil {
			return fmt.Errorf("receiver mutation contains an invalid approved notice: %w", err)
		}
	}
	if record.Decision == protocol.DecisionAllowOnce && record.ApprovedNotice == nil && !allowLegacyNotice {
		return errors.New("Allow Once decision has no bound approved notice")
	}
	if record.Decision == protocol.DecisionAllowOnce && record.ApprovalLevel != "" {
		if !record.ApprovalLevel.Valid() {
			return errors.New("receiver mutation contains an invalid approval level")
		}
		if record.ApprovalLevel.standing() {
			if !validApprovalGrantID(record.ApprovalGrantID) {
				return errors.New("standing approval mutation contains an invalid grant identity")
			}
		} else if record.ApprovalGrantID != "" || record.ApprovalGrantPersisted {
			return errors.New("ask-always mutation unexpectedly contains a standing grant")
		}
	} else if record.ApprovalGrantID != "" || record.ApprovalGrantPersisted {
		return errors.New("receiver mutation contains approval-grant state without an approval level")
	}
	switch record.Phase {
	case mutationDecisionPrepared:
		if record.DecisionID == "" || !validDecision || record.Result != nil {
			return errors.New("prepared decision record is incomplete")
		}
		if record.Decision == protocol.DecisionAllowOnce && record.ExecutionClaimID == "" {
			return errors.New("Allow Once decision has no prepared execution claim")
		}
		if record.Decision == protocol.DecisionDeny && record.ExecutionClaimID != "" {
			return errors.New("Deny decision unexpectedly has an execution claim")
		}
	case mutationClaimPrepared, mutationRuntimeStarted:
		if record.ExecutionClaimID == "" || record.Result != nil || (record.DecisionID != "" && record.Decision != protocol.DecisionAllowOnce) {
			return errors.New("execution mutation record is inconsistent")
		}
	case mutationResultPrepared:
		if record.ExecutionClaimID == "" || record.Result == nil || record.Result.ExecutionClaimID != record.ExecutionClaimID {
			return errors.New("prepared result record is incomplete")
		}
		if record.Result.State != protocol.StatusCompleted && record.Result.State != protocol.StatusFailed && record.Result.State != protocol.StatusCancelled {
			return errors.New("prepared result has an invalid terminal state")
		}
	default:
		return fmt.Errorf("receiver mutation phase %q is invalid", record.Phase)
	}
	return nil
}

func validLocalOpaqueID(value, prefix string) bool {
	if len(value) != len(prefix)+64 || value[:len(prefix)] != prefix {
		return false
	}
	_, err := hex.DecodeString(value[len(prefix):])
	return err == nil
}

func validateApprovedNoticeBinding(binding approvedNoticeBinding, requestID string) error {
	if binding.Version != approvedNoticeBindingVersion {
		return fmt.Errorf("approved notice binding version %d is unsupported", binding.Version)
	}
	if binding.RequestID == "" || binding.RequestID != requestID {
		return errors.New("approved notice binding has a mismatched request_id")
	}
	if binding.PromptBytes < 0 {
		return errors.New("approved notice binding has a negative prompt byte count")
	}
	if digest := strings.TrimSpace(binding.PromptSHA256); digest != "" {
		decoded, err := hex.DecodeString(digest)
		if err != nil || len(decoded) != sha256.Size {
			return errors.New("approved notice binding has an invalid prompt SHA-256")
		}
	}
	return nil
}
