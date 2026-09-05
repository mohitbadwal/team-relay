package receiver

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mohitbadwal/team-relay/internal/artifact"
	"github.com/mohitbadwal/team-relay/internal/client"
	"github.com/mohitbadwal/team-relay/internal/protocol"
	relayruntime "github.com/mohitbadwal/team-relay/internal/runtime"
)

type RelayClient interface {
	Heartbeat(context.Context, protocol.AgentHeartbeat) (*protocol.AgentCard, error)
	Inbox(context.Context) (*protocol.InboxResponse, error)
	StreamEvents(context.Context, func(client.Event) error) error
	GetRequest(context.Context, string) (*protocol.Request, error)
	Decide(context.Context, string, protocol.DecisionPayload) (*protocol.MutationResponse, error)
	InspectProposal(context.Context, string) (*protocol.ProposalPayload, error)
	FetchExecution(context.Context, string) (*protocol.ExecutionPayload, error)
	MarkRunning(context.Context, string, string) (*protocol.MutationResponse, error)
	SubmitResult(context.Context, string, protocol.ResultPayload) (*protocol.MutationResponse, error)
	FetchArtifact(context.Context, string) (*protocol.ArtifactContent, error)
}

type ServiceConfig struct {
	Client     RelayClient
	Controller *Controller
	Pending    *PendingStore
	Approvals  *ApprovalStore
	Artifacts  *artifact.Manager
	// ApprovalAuthorityFingerprint is a one-way, stable digest of the local
	// relay enrollment and effective receiver configuration. Standing grants
	// are invalidated when this value or the heartbeat's recipient agent ID
	// changes.
	ApprovalAuthorityFingerprint string
	DisplayName                  string
	DeviceName                   string
	AcceptingRequests            bool
	Workspaces                   map[string]string
	Capabilities                 []string
	HeartbeatInterval            time.Duration
	Logger                       *slog.Logger
}

type Service struct {
	client     RelayClient
	controller *Controller
	pending    *PendingStore
	approvals  *ApprovalStore
	mutations  *mutationStore
	artifacts  *artifact.Manager
	workspaces map[string]string
	heartbeat  protocol.AgentHeartbeat
	interval   time.Duration
	logger     *slog.Logger

	approvalMu          sync.RWMutex
	approvalDecisionMu  sync.Mutex
	approvalAuthority   ApprovalAuthority
	approvalFingerprint string

	mutationMu  sync.Mutex
	reconcileMu sync.Mutex
	runMu       sync.RWMutex
	runCtx      context.Context
	running     bool
	active      map[string]context.CancelFunc
	activeWG    sync.WaitGroup
}

const (
	initialReconnectDelay = time.Second
	maximumReconnectDelay = 30 * time.Second
)

var errReceiverBusy = errors.New("wait for the current teammate execution to finish before approving another request")

// ApprovalResult describes the exact local choice applied to a request. A
// standing grant is returned after the private grant snapshot has been durably
// updated.
type ApprovalResult struct {
	RequestID string                 `json:"request_id"`
	Status    protocol.RequestStatus `json:"status"`
	Level     ApprovalLevel          `json:"level"`
	Grant     *ApprovalGrant         `json:"grant,omitempty"`
}

type reconnectBackoff struct {
	current time.Duration
}

func (b *reconnectBackoff) next(healthy bool) time.Duration {
	if b.current <= 0 || healthy {
		b.current = initialReconnectDelay
	}
	delay := b.current
	if !healthy {
		if b.current >= maximumReconnectDelay/2 {
			b.current = maximumReconnectDelay
		} else {
			b.current *= 2
		}
	}
	return delay
}

func NewService(config ServiceConfig) (*Service, error) {
	if config.Client == nil || config.Controller == nil || config.Pending == nil {
		return nil, fmt.Errorf("relay client, runtime controller, and pending store are required")
	}
	if config.DisplayName == "" || config.DeviceName == "" {
		return nil, fmt.Errorf("display name and device name are required")
	}
	if config.HeartbeatInterval <= 0 {
		config.HeartbeatInterval = 25 * time.Second
	}
	if config.Logger == nil {
		config.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	workspaces, err := resolveConfiguredWorkspaces(config.Workspaces)
	if err != nil {
		return nil, err
	}
	aliases := make([]string, 0, len(workspaces))
	for alias := range workspaces {
		aliases = append(aliases, alias)
	}
	sort.Strings(aliases)
	mutations, err := newMutationStore(filepath.Join(filepath.Dir(config.Pending.path), "receiver_mutations.json"))
	if err != nil {
		return nil, err
	}
	approvals := config.Approvals
	if approvals == nil {
		approvals, err = NewApprovalStore(filepath.Join(filepath.Dir(config.Pending.path), "approval_grants.json"))
		if err != nil {
			return nil, err
		}
	}
	effectiveFingerprint, err := effectiveApprovalPolicyFingerprint(config.Controller, workspaces, config.DisplayName, config.DeviceName)
	if err != nil {
		return nil, err
	}
	approvalFingerprint := effectiveFingerprint
	if enrollmentFingerprint := strings.TrimSpace(config.ApprovalAuthorityFingerprint); enrollmentFingerprint != "" {
		digest := sha256.Sum256([]byte("team-relay-approval-authority/v2\x00" + enrollmentFingerprint + "\x00" + effectiveFingerprint))
		approvalFingerprint = hex.EncodeToString(digest[:])
	}
	return &Service{
		client:     config.Client,
		controller: config.Controller,
		pending:    config.Pending,
		approvals:  approvals,
		mutations:  mutations,
		artifacts:  config.Artifacts,
		workspaces: workspaces,
		heartbeat: protocol.AgentHeartbeat{
			DisplayName:       config.DisplayName,
			DeviceName:        config.DeviceName,
			Availability:      protocol.AvailabilityAvailable,
			AcceptingRequests: config.AcceptingRequests,
			PermissionMode:    protocol.PermissionMode(config.Controller.ConfiguredPolicy().Mode),
			Capabilities:      append([]string(nil), config.Capabilities...),
			WorkspaceAliases:  aliases,
		},
		interval:            config.HeartbeatInterval,
		logger:              config.Logger,
		active:              make(map[string]context.CancelFunc),
		approvalFingerprint: approvalFingerprint,
	}, nil
}

func (s *Service) Run(ctx context.Context) error {
	s.runMu.Lock()
	if s.running {
		s.runMu.Unlock()
		return fmt.Errorf("receiver service is already running")
	}
	stateLock, err := acquireReceiverProcessLock(filepath.Join(filepath.Dir(s.mutations.path), "receiver.lock"))
	if err != nil {
		s.runMu.Unlock()
		return fmt.Errorf("acquire receiver state ownership: %w", err)
	}
	// NewService may have loaded this snapshot while an older process still
	// owned the directory. Reload only after exclusive ownership is established.
	if err := s.mutations.Reload(); err != nil {
		_ = stateLock.Close()
		s.runMu.Unlock()
		return fmt.Errorf("reload receiver mutation state: %w", err)
	}
	if err := s.approvals.Reload(); err != nil {
		_ = stateLock.Close()
		s.runMu.Unlock()
		return fmt.Errorf("reload standing approval state: %w", err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	var backgroundWG sync.WaitGroup
	s.runCtx = runCtx
	s.running = true
	s.runMu.Unlock()
	defer func() {
		if err := stateLock.Close(); err != nil {
			s.logger.Warn("release receiver state ownership failed", "error", relayruntime.SafeSummary(err.Error()))
		}
	}()
	defer func() {
		s.runMu.Lock()
		s.running = false
		s.runCtx = nil
		cancels := make([]context.CancelFunc, 0, len(s.active))
		for _, activeCancel := range s.active {
			cancels = append(cancels, activeCancel)
		}
		s.runMu.Unlock()

		cancel()
		for _, activeCancel := range cancels {
			activeCancel()
		}
		s.activeWG.Wait()
		backgroundWG.Wait()
	}()

	capabilities, err := s.controller.Probe(runCtx)
	if err != nil {
		return fmt.Errorf("probe recipient runtime: %w", err)
	}
	if !capabilities.Available {
		return fmt.Errorf("recipient runtime %q is unavailable: %s", capabilities.RuntimeID, capabilities.Detail)
	}
	s.heartbeat.Runtime = protocol.RuntimeDescriptor{
		ID:          capabilities.RuntimeID,
		DisplayName: capabilities.DisplayName,
		Version:     capabilities.Version,
		Capabilities: protocol.RuntimeCapabilities{
			Resume:           capabilities.SupportsResume,
			StructuredEvents: capabilities.SupportsStreaming,
			Skills:           capabilities.PreservesLocalContext,
			MCP:              capabilities.LoadsLocalMCPs,
			ReadOnly:         supportsDefaultPolicy(capabilities, relayruntime.PolicyReadOnly),
			GuardedWrite:     supportsDefaultPolicy(capabilities, relayruntime.PolicyGuardedWrite),
			ReturnedFiles:    s.artifacts != nil && s.controller.ConfiguredPolicy().AllowWrites,
		},
	}
	card, err := s.client.Heartbeat(runCtx, s.heartbeat)
	if err != nil {
		return fmt.Errorf("publish initial heartbeat: %w", err)
	}
	if err := s.activateApprovalAuthority(card); err != nil {
		return fmt.Errorf("initialize standing approval authority: %w", err)
	}
	if err := s.reconcile(runCtx); err != nil {
		return fmt.Errorf("reconcile recipient inbox: %w", err)
	}
	backgroundWG.Add(1)
	go func() {
		defer backgroundWG.Done()
		s.heartbeatLoop(runCtx)
	}()

	var backoff reconnectBackoff
	for runCtx.Err() == nil {
		streamErr, reconcileErr, healthy := s.eventStreamAttempt(runCtx)
		if runCtx.Err() != nil {
			break
		}
		retryIn := backoff.next(healthy)
		if streamErr != nil {
			s.logger.Warn("relay event stream disconnected", "error", relayruntime.SafeSummary(streamErr.Error()), "retry_in", retryIn)
		}
		if reconcileErr != nil {
			s.logger.Warn("relay inbox reconciliation failed", "error", relayruntime.SafeSummary(reconcileErr.Error()))
		}
		timer := time.NewTimer(retryIn)
		select {
		case <-runCtx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
	return nil
}

// eventStreamAttempt reconciles the durable inbox after every disconnected
// stream. Receiving the relay's ready event proves a complete SSE handshake;
// a successful inbox read independently proves the durable path is healthy.
// Either signal resets reconnect backoff for the next attempt.
func (s *Service) eventStreamAttempt(ctx context.Context) (streamErr, reconcileErr error, healthy bool) {
	ready := false
	streamErr = s.client.StreamEvents(ctx, func(event client.Event) error {
		if event.Type == "ready" {
			ready = true
		}
		return s.handleEvent(event)
	})
	if ctx.Err() != nil {
		return streamErr, nil, ready
	}
	reconcileErr = s.reconcile(ctx)
	return streamErr, reconcileErr, ready || reconcileErr == nil
}

func supportsDefaultPolicy(capabilities relayruntime.Capabilities, mode relayruntime.PolicyMode) bool {
	policy, err := relayruntime.DefaultPolicy(mode)
	return err == nil && relayruntime.SupportsPolicy(capabilities, policy)
}

func effectiveApprovalPolicyFingerprint(controller *Controller, workspaces map[string]string, displayName, deviceName string) (string, error) {
	runtimeConfigFingerprint, err := controller.RuntimeApprovalFingerprint()
	if err != nil {
		return "", fmt.Errorf("derive runtime approval fingerprint: %w", err)
	}
	payload, err := json.Marshal(struct {
		Version                  int                 `json:"version"`
		RuntimeID                string              `json:"runtime_id"`
		RuntimeConfigFingerprint string              `json:"runtime_config_fingerprint"`
		Policy                   relayruntime.Policy `json:"policy"`
		WorkDirFingerprint       string              `json:"work_dir_fingerprint"`
		Workspaces               map[string]string   `json:"workspaces"`
		DisplayName              string              `json:"display_name"`
		DeviceName               string              `json:"device_name"`
	}{
		Version: 2, RuntimeID: controller.RuntimeID(), RuntimeConfigFingerprint: runtimeConfigFingerprint,
		Policy:             controller.ConfiguredPolicy(),
		WorkDirFingerprint: controller.WorkDirFingerprint(), Workspaces: workspaces,
		DisplayName: displayName, DeviceName: deviceName,
	})
	if err != nil {
		return "", fmt.Errorf("derive effective approval policy fingerprint: %w", err)
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]), nil
}

func (s *Service) activateApprovalAuthority(card *protocol.AgentCard) error {
	if card == nil || strings.TrimSpace(card.AgentID) == "" {
		return errors.New("relay heartbeat did not return the recipient agent_id")
	}
	s.approvalDecisionMu.Lock()
	defer s.approvalDecisionMu.Unlock()
	authority := ApprovalAuthority{
		Fingerprint:      s.approvalFingerprint,
		RecipientAgentID: strings.TrimSpace(card.AgentID),
	}
	s.approvalMu.RLock()
	current := s.approvalAuthority
	s.approvalMu.RUnlock()
	if current.RecipientAgentID != "" && current != authority {
		s.approvalMu.Lock()
		s.approvalAuthority = ApprovalAuthority{}
		s.approvalMu.Unlock()
		_, _ = s.approvals.Prune(authority)
		return errors.New("relay heartbeat changed the recipient approval identity; standing approvals were disabled")
	}
	removed, err := s.approvals.Prune(authority)
	if err != nil {
		return err
	}
	s.approvalMu.Lock()
	s.approvalAuthority = authority
	s.approvalMu.Unlock()
	if removed > 0 {
		s.logger.Info("pruned stale standing approval grants", "count", removed)
	}
	return nil
}

func (s *Service) currentApprovalAuthority() (ApprovalAuthority, error) {
	s.approvalMu.RLock()
	authority := s.approvalAuthority
	s.approvalMu.RUnlock()
	if strings.TrimSpace(authority.Fingerprint) == "" || strings.TrimSpace(authority.RecipientAgentID) == "" {
		return ApprovalAuthority{}, errors.New("approval identity is unavailable until the receiver connects to the relay")
	}
	return authority, nil
}

func approvalAuthorityFromMutation(operation mutationRecord) (ApprovalAuthority, error) {
	if strings.TrimSpace(operation.ApprovalAuthorityFingerprint) == "" || strings.TrimSpace(operation.ApprovalRecipientAgentID) == "" {
		return ApprovalAuthority{}, errors.New("durable allow has no bound approval authority")
	}
	authority, err := normalizeApprovalAuthority(ApprovalAuthority{
		Fingerprint:      operation.ApprovalAuthorityFingerprint,
		RecipientAgentID: operation.ApprovalRecipientAgentID,
	})
	if err != nil {
		return ApprovalAuthority{}, errors.New("durable allow has an invalid approval authority")
	}
	return authority, nil
}

func (s *Service) requireCurrentApprovalAuthority(operation mutationRecord) error {
	recorded, err := approvalAuthorityFromMutation(operation)
	if err != nil {
		return fmt.Errorf("request %q cannot use an unbound durable allow: %w", operation.RequestID, err)
	}
	current, err := s.currentApprovalAuthority()
	if err != nil {
		return fmt.Errorf("request %q cannot verify its durable allow: %w", operation.RequestID, err)
	}
	if recorded != current {
		return fmt.Errorf("request %q durable allow belongs to a different approval authority", operation.RequestID)
	}
	return nil
}

// requireCurrentApprovedNotice verifies that mutable inbox state still
// represents the exact request metadata durably authorized before the relay
// decision. Status and local session-affinity decoration are intentionally not
// part of the binding because they legitimately change after approval.
func (s *Service) requireCurrentApprovedNotice(operation mutationRecord) (PendingRecord, error) {
	if operation.ApprovedNotice == nil {
		return PendingRecord{}, fmt.Errorf("request %q durable allow has no bound approved notice", operation.RequestID)
	}
	if err := validateApprovedNoticeBinding(*operation.ApprovedNotice, operation.RequestID); err != nil {
		return PendingRecord{}, fmt.Errorf("request %q durable allow has an invalid approved notice: %w", operation.RequestID, err)
	}
	record, ok := s.pending.Get(operation.RequestID)
	if !ok {
		return PendingRecord{}, fmt.Errorf("request %q is missing its locally approved pending notice", operation.RequestID)
	}
	if err := validateNoticeAgainstApprovedBinding(record.Notice, *operation.ApprovedNotice); err != nil {
		return PendingRecord{}, err
	}
	return record, nil
}

func (s *Service) Pending() []PendingRecord { return s.pending.List() }

// InspectProposal retrieves the full prompt for an explicit local approval
// decision. The proposal is neither persisted nor passed to the runtime, and
// inspecting it does not approve the request.
func (s *Service) InspectProposal(ctx context.Context, requestID string) (*protocol.ProposalPayload, error) {
	requestID = strings.TrimSpace(requestID)
	if requestID == "" {
		return nil, errors.New("request_id is required")
	}
	record, ok := s.pending.Get(requestID)
	if !ok {
		return nil, fmt.Errorf("request %q is not pending", requestID)
	}
	if record.Notice.Status != protocol.StatusAwaitingApproval {
		return nil, fmt.Errorf("request %q is %s and can no longer be inspected for approval", requestID, record.Notice.Status)
	}
	proposal, err := s.client.InspectProposal(ctx, requestID)
	if err != nil {
		return nil, fmt.Errorf("inspect request proposal: %w", err)
	}
	if proposal == nil {
		return nil, errors.New("relay returned an empty proposal")
	}
	if err := validateProposal(record.Notice, *proposal); err != nil {
		return nil, err
	}
	return proposal, nil
}

func (s *Service) AllowOnce(ctx context.Context, requestID string) error {
	s.approvalDecisionMu.Lock()
	defer s.approvalDecisionMu.Unlock()
	return s.allowOnce(ctx, requestID)
}

func (s *Service) allowOnce(ctx context.Context, requestID string) error {
	_, err := s.allowOnceWithApproval(ctx, requestID, ApprovalLevelAskAlways, "", false)
	return err
}

func (s *Service) allowOnceWithApproval(ctx context.Context, requestID string, level ApprovalLevel, grantID string, grantPersisted bool) (protocol.RequestStatus, error) {
	return s.allowOnceWithApprovalForNotice(ctx, requestID, level, grantID, grantPersisted, nil)
}

// allowOnceWithApprovalForNotice carries the exact notice that matched a
// standing grant into the approval path. This prevents a replacement inbox
// record from borrowing a grant that covered only an earlier, narrower request.
func (s *Service) allowOnceWithApprovalForNotice(ctx context.Context, requestID string, level ApprovalLevel, grantID string, grantPersisted bool, matchedNotice *protocol.RequestNotice) (protocol.RequestStatus, error) {
	requestID = strings.TrimSpace(requestID)
	if requestID == "" {
		return "", errors.New("request_id is required")
	}
	record, ok := s.pending.Get(requestID)
	if !ok {
		return "", fmt.Errorf("request %q is not pending", requestID)
	}
	if record.Notice.Status != protocol.StatusAwaitingApproval && record.Notice.Status != protocol.StatusAccepted && record.Notice.Status != protocol.StatusRunning {
		return "", fmt.Errorf("request %q is %s and cannot be approved", requestID, record.Notice.Status)
	}
	if err := s.validateNotice(record.Notice); err != nil {
		return "", err
	}
	if matchedNotice != nil {
		matchedBinding, err := approvedNoticeBindingFor(*matchedNotice)
		if err != nil {
			return "", fmt.Errorf("validate notice matched by standing approval: %w", err)
		}
		currentBinding, err := approvedNoticeBindingFor(record.Notice)
		if err != nil {
			return "", fmt.Errorf("validate current standing-approval notice: %w", err)
		}
		if !sameApprovedNoticeBinding(*matchedBinding, *currentBinding) {
			return "", fmt.Errorf("request %q changed after its standing approval was matched", requestID)
		}
		authority, err := s.currentApprovalAuthority()
		if err != nil {
			return "", err
		}
		candidate, err := approvalCandidateForNotice(record.Notice)
		if err != nil {
			return "", err
		}
		currentGrant, stillMatched, err := s.approvals.Match(authority, candidate)
		if err != nil {
			return "", fmt.Errorf("recheck standing approval for request %q: %w", requestID, err)
		}
		if !stillMatched || currentGrant.GrantID != grantID || currentGrant.Level != level {
			return "", fmt.Errorf("request %q is no longer covered by the matched standing approval", requestID)
		}
	}
	// An accepted/running notice means a decision already committed at the
	// relay. Recover its durable claim instead of inventing another decision ID,
	// which the relay must (and does) reject as a conflicting retry.
	if record.Notice.Status != protocol.StatusAwaitingApproval {
		operation, exists := s.mutations.Get(requestID)
		if !exists {
			return record.Notice.Status, fmt.Errorf("request %q was accepted without a locally bound approval; refusing runtime recovery", requestID)
		}
		if operation.Phase == mutationDecisionPrepared || operation.Phase == mutationClaimPrepared {
			if err := s.requireCurrentApprovalAuthority(operation); err != nil {
				return record.Notice.Status, err
			}
		}
		return record.Notice.Status, s.recoverOperationLocked(ctx, requestID, record.Notice.ConversationID, record.Notice.Status)
	}
	_, hasPreparedOperation := s.mutations.Get(requestID)
	if !hasPreparedOperation && s.hasActiveExecution() {
		return protocol.StatusAwaitingApproval, errReceiverBusy
	}
	operation, _, err := s.prepareDecision(record.Notice, protocol.DecisionAllowOnce, level, grantID, grantPersisted)
	if err != nil {
		return "", err
	}
	return s.commitAllowOnce(ctx, requestID, operation)
}

func (s *Service) commitAllowOnce(ctx context.Context, requestID string, operation mutationRecord) (protocol.RequestStatus, error) {
	if err := s.requireCurrentApprovalAuthority(operation); err != nil {
		return "", err
	}
	if _, err := s.requireCurrentApprovedNotice(operation); err != nil {
		return "", err
	}
	mutation, err := s.client.Decide(ctx, requestID, protocol.DecisionPayload{Decision: operation.Decision, DecisionID: operation.DecisionID})
	if err != nil {
		return "", fmt.Errorf("record allow-once decision: %w", err)
	}
	status, err := mutationStatus(mutation, requestID)
	if err != nil {
		return "", err
	}
	return status, s.handleDecisionMutation(ctx, requestID, operation, status)
}

// Approve applies one of the recipient's four prompting choices. AskAlways is
// the existing one-turn Allow Once behavior. A standing grant is derived only
// from authenticated metadata already in the recipient's pending inbox. The
// selected local intent and grant are persisted before the per-request relay
// decision so a lost response cannot silently change the recipient's choice.
func (s *Service) Approve(ctx context.Context, requestID string, level ApprovalLevel) (ApprovalResult, error) {
	requestID = strings.TrimSpace(requestID)
	if requestID == "" {
		return ApprovalResult{}, errors.New("request_id is required")
	}
	if !level.Valid() {
		return ApprovalResult{}, fmt.Errorf("approval level %q is invalid", level)
	}
	s.approvalDecisionMu.Lock()
	defer s.approvalDecisionMu.Unlock()
	record, ok := s.pending.Get(requestID)
	if !ok {
		return ApprovalResult{}, fmt.Errorf("request %q is not pending", requestID)
	}
	result := ApprovalResult{RequestID: requestID, Status: protocol.StatusAccepted, Level: level}
	if level == ApprovalLevelAskAlways {
		status, err := s.allowOnceWithApproval(ctx, requestID, ApprovalLevelAskAlways, "", false)
		if err != nil {
			return ApprovalResult{}, err
		}
		result.Status = status
		return result, nil
	}
	if record.Notice.Status != protocol.StatusAwaitingApproval {
		return ApprovalResult{}, fmt.Errorf("request %q is %s and cannot create a standing approval", requestID, record.Notice.Status)
	}
	// Do not let an executing teammate runtime use the same-user loopback
	// control surface to broaden approval for a different pending request. This
	// is defense in depth for the preview; complete protection still requires
	// child-process identity/filesystem isolation.
	if s.hasActiveExecution() && !s.hasActiveRequest(requestID) {
		return ApprovalResult{}, errReceiverBusy
	}
	if err := s.validateNotice(record.Notice); err != nil {
		return ApprovalResult{}, err
	}
	candidate, err := approvalCandidateForNotice(record.Notice)
	if err != nil {
		return ApprovalResult{}, err
	}
	authority, err := s.currentApprovalAuthority()
	if err != nil {
		return ApprovalResult{}, err
	}
	plannedGrantID := stableApprovalGrantID(authority, level, candidate)
	operation, _, err := s.prepareDecision(record.Notice, protocol.DecisionAllowOnce, level, plannedGrantID, false)
	if err != nil {
		return ApprovalResult{}, err
	}
	var grant *ApprovalGrant
	if !operation.ApprovalGrantPersisted {
		saved, saveErr := s.approvals.Upsert(authority, level, candidate)
		if saveErr != nil {
			return ApprovalResult{}, fmt.Errorf("save standing approval before accepting request %q: %w", requestID, saveErr)
		}
		operation, err = s.mutations.Update(requestID, func(current *mutationRecord) error {
			if current.DecisionID != operation.DecisionID || current.ApprovalLevel != level || current.ApprovalGrantID != saved.GrantID {
				return fmt.Errorf("request %q durable approval intent changed while saving its grant", requestID)
			}
			current.ApprovalGrantPersisted = true
			return nil
		})
		if err != nil {
			return ApprovalResult{}, fmt.Errorf("confirm durable standing approval for request %q: %w", requestID, err)
		}
		grant = &saved
		s.logger.Info("standing approval grant saved", "request_id", requestID, "grant_id", saved.GrantID, "level", saved.Level)
	} else {
		grants, listErr := s.approvals.List(authority)
		if listErr != nil {
			return ApprovalResult{}, listErr
		}
		for index := range grants {
			if grants[index].GrantID == operation.ApprovalGrantID {
				copy := grants[index]
				grant = &copy
				break
			}
		}
	}
	result.Grant = grant
	status, err := s.commitAllowOnce(ctx, requestID, operation)
	if err != nil {
		return result, fmt.Errorf("standing approval %q was saved, but request %q was not confirmed accepted: %w", operation.ApprovalGrantID, requestID, err)
	}
	result.Status = status
	return result, nil
}

func (s *Service) ApprovalGrants() ([]ApprovalGrant, error) {
	s.approvalDecisionMu.Lock()
	defer s.approvalDecisionMu.Unlock()
	authority, err := s.currentApprovalAuthority()
	if err != nil {
		return nil, err
	}
	return s.approvals.List(authority)
}

func (s *Service) RevokeApprovalGrant(grantID string) error {
	s.approvalDecisionMu.Lock()
	defer s.approvalDecisionMu.Unlock()
	authority, err := s.currentApprovalAuthority()
	if err != nil {
		return err
	}
	revoked, err := s.approvals.Revoke(authority, grantID)
	if err != nil {
		return err
	}
	if !revoked {
		return fmt.Errorf("standing approval grant %q was not found", strings.TrimSpace(grantID))
	}
	s.logger.Info("standing approval grant revoked", "grant_id", strings.TrimSpace(grantID))
	return nil
}

func approvalCandidateForNotice(notice protocol.RequestNotice) (ApprovalCandidate, error) {
	var attachmentBytes int64
	for _, descriptor := range notice.Attachments {
		attachmentBytes += descriptor.SizeBytes
	}
	candidate := ApprovalCandidate{
		RequesterMemberID:    strings.TrimSpace(notice.RequesterMemberID),
		RequesterDisplayName: strings.TrimSpace(notice.RequesterDisplayName),
		ConversationID:       strings.TrimSpace(notice.ConversationID),
		AccessScope: ApprovalAccessScope{
			RequestedAccess:    append([]protocol.RequestedAccess(nil), notice.RequestedAccess...),
			MaxAttachmentCount: len(notice.Attachments),
			MaxAttachmentBytes: attachmentBytes,
		},
	}
	if candidate.RequesterMemberID == "" {
		return ApprovalCandidate{}, errors.New("standing approvals require a relay-authenticated requester member_id; approve this legacy request with ask_always")
	}
	if candidate.ConversationID == "" {
		return ApprovalCandidate{}, errors.New("standing approvals require conversation_id")
	}
	return candidate, nil
}

// ensurePreparedStandingGrant closes the crash window between journaling a
// recipient's standing-approval choice and replacing the private grant file.
// Once the journal says the grant was persisted, a later local revocation is
// authoritative and recovery must never recreate it.
func (s *Service) ensurePreparedStandingGrant(requestID string, operation mutationRecord) (mutationRecord, error) {
	if !operation.ApprovalLevel.standing() || operation.ApprovalGrantPersisted {
		return operation, nil
	}
	if err := s.requireCurrentApprovalAuthority(operation); err != nil {
		return mutationRecord{}, err
	}
	record, err := s.requireCurrentApprovedNotice(operation)
	if err != nil {
		return mutationRecord{}, err
	}
	candidate, err := approvalCandidateForNotice(record.Notice)
	if err != nil {
		return mutationRecord{}, err
	}
	authority, err := s.currentApprovalAuthority()
	if err != nil {
		return mutationRecord{}, err
	}
	if expected := stableApprovalGrantID(authority, operation.ApprovalLevel, candidate); expected != operation.ApprovalGrantID {
		return mutationRecord{}, fmt.Errorf("request %q standing approval no longer matches the current authority", requestID)
	}
	restoredGrant, err := s.approvals.RestorePrepared(authority, operation.ApprovalLevel, candidate, operation.UpdatedAt)
	grantWasNotRestored := errors.Is(err, ErrApprovalGrantRevoked) || errors.Is(err, ErrApprovalGrantWindowExpired)
	inactiveGrantReason := ""
	if grantWasNotRestored {
		inactiveGrantReason = relayruntime.SafeSummary(err.Error())
	}
	if err != nil && !grantWasNotRestored {
		return mutationRecord{}, fmt.Errorf("recover standing approval for request %q: %w", requestID, err)
	}
	if !grantWasNotRestored && restoredGrant.GrantID != operation.ApprovalGrantID {
		return mutationRecord{}, fmt.Errorf("recover standing approval for request %q returned a different grant identity", requestID)
	}
	operation, err = s.mutations.Update(requestID, func(current *mutationRecord) error {
		if current.DecisionID != operation.DecisionID || current.ApprovalLevel != operation.ApprovalLevel || current.ApprovalGrantID != operation.ApprovalGrantID {
			return fmt.Errorf("request %q durable approval intent changed during recovery", requestID)
		}
		current.ApprovalGrantPersisted = true
		return nil
	})
	if err != nil {
		return mutationRecord{}, err
	}
	if grantWasNotRestored {
		// A tombstone proves the standing grant was revoked; an elapsed fixed
		// conversation window is equally ineligible for restoration. Preserve the
		// already prepared one-request decision, but never recreate future access.
		s.logger.Info("kept current request approval without restoring inactive standing grant", "request_id", requestID, "grant_id", operation.ApprovalGrantID, "reason", inactiveGrantReason)
	}
	return operation, nil
}

func (s *Service) maybeAutoApprove(ctx context.Context, notice protocol.RequestNotice) {
	if notice.Status != protocol.StatusAwaitingApproval || strings.TrimSpace(notice.RequesterMemberID) == "" {
		return
	}
	s.approvalDecisionMu.Lock()
	defer s.approvalDecisionMu.Unlock()
	authority, err := s.currentApprovalAuthority()
	if err != nil {
		return
	}
	// Re-read under the approval decision lock instead of trusting the event or
	// reconciliation snapshot supplied by the caller. A later replacement is
	// also detected by allowOnceWithApprovalForNotice and commitAllowOnce.
	current, ok := s.pending.Get(notice.RequestID)
	if !ok || current.Notice.Status != protocol.StatusAwaitingApproval {
		return
	}
	candidate, err := approvalCandidateForNotice(current.Notice)
	if err != nil {
		s.logger.Warn("standing approval candidate was invalid", "request_id", notice.RequestID, "error", relayruntime.SafeSummary(err.Error()))
		return
	}
	grant, matched, err := s.approvals.Match(authority, candidate)
	if err != nil {
		s.logger.Warn("match standing approval grant failed", "request_id", notice.RequestID, "error", relayruntime.SafeSummary(err.Error()))
		return
	}
	if !matched {
		return
	}
	_, err = s.allowOnceWithApprovalForNotice(ctx, current.Notice.RequestID, grant.Level, grant.GrantID, true, &current.Notice)
	if err != nil {
		if errors.Is(err, errReceiverBusy) {
			s.logger.Info("standing approval deferred while another teammate request runs", "request_id", notice.RequestID, "grant_id", grant.GrantID, "level", grant.Level)
			return
		}
		s.logger.Warn("standing approval could not accept request", "request_id", notice.RequestID, "grant_id", grant.GrantID, "level", grant.Level, "error", relayruntime.SafeSummary(err.Error()))
		return
	}
	s.logger.Info("request accepted from standing approval grant", "request_id", notice.RequestID, "grant_id", grant.GrantID, "level", grant.Level)
}

func (s *Service) hasActiveExecution() bool {
	s.runMu.RLock()
	defer s.runMu.RUnlock()
	return len(s.active) > 0
}

func (s *Service) hasActiveRequest(requestID string) bool {
	s.runMu.RLock()
	defer s.runMu.RUnlock()
	_, ok := s.active[requestID]
	return ok
}

func (s *Service) Deny(ctx context.Context, requestID string) error {
	s.approvalDecisionMu.Lock()
	defer s.approvalDecisionMu.Unlock()
	record, ok := s.pending.Get(requestID)
	if !ok {
		return fmt.Errorf("request %q is not pending", requestID)
	}
	if record.Notice.Status != protocol.StatusAwaitingApproval {
		return fmt.Errorf("request %q is %s and can no longer be denied", requestID, record.Notice.Status)
	}
	operation, _, err := s.prepareDecision(record.Notice, protocol.DecisionDeny, "", "", false)
	if err != nil {
		return err
	}
	mutation, err := s.client.Decide(ctx, requestID, protocol.DecisionPayload{Decision: operation.Decision, DecisionID: operation.DecisionID})
	if err != nil {
		return fmt.Errorf("record deny decision: %w", err)
	}
	status, err := mutationStatus(mutation, requestID)
	if err != nil {
		return err
	}
	if status != protocol.StatusRejected && status != protocol.StatusExpired && status != protocol.StatusCancelled {
		return fmt.Errorf("relay returned unexpected decision state %q", status)
	}
	if err := s.pending.Remove(requestID); err != nil {
		return err
	}
	return s.mutations.Remove(requestID)
}

func (s *Service) prepareDecision(notice protocol.RequestNotice, decision protocol.Decision, level ApprovalLevel, grantID string, grantPersisted bool) (mutationRecord, bool, error) {
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	var authority ApprovalAuthority
	var approvedNotice *approvedNoticeBinding
	var err error
	if decision == protocol.DecisionAllowOnce {
		authority, err = s.currentApprovalAuthority()
		if err != nil {
			return mutationRecord{}, false, err
		}
		approvedNotice, err = approvedNoticeBindingFor(notice)
		if err != nil {
			return mutationRecord{}, false, fmt.Errorf("bind approved request %q: %w", notice.RequestID, err)
		}
	}
	if existing, ok := s.mutations.Get(notice.RequestID); ok {
		existingLevel := existing.ApprovalLevel
		if existingLevel == "" && existing.Decision == protocol.DecisionAllowOnce {
			existingLevel = ApprovalLevelAskAlways
		}
		if existing.ConversationID != notice.ConversationID || existing.Decision != decision || existing.DecisionID == "" ||
			existingLevel != level || existing.ApprovalGrantID != grantID {
			return mutationRecord{}, true, fmt.Errorf("request %q already has a different durable receiver operation", notice.RequestID)
		}
		if decision == protocol.DecisionAllowOnce {
			existingAuthority, authorityErr := approvalAuthorityFromMutation(existing)
			if authorityErr != nil || existingAuthority != authority {
				return mutationRecord{}, true, fmt.Errorf("request %q durable allow belongs to a different approval authority", notice.RequestID)
			}
			if existing.ApprovedNotice == nil || !sameApprovedNoticeBinding(*existing.ApprovedNotice, *approvedNotice) {
				return mutationRecord{}, true, fmt.Errorf("request %q durable allow belongs to a different approved notice", notice.RequestID)
			}
		}
		return existing, true, nil
	}
	decisionID, err := newOpaqueID("decision_")
	if err != nil {
		return mutationRecord{}, false, err
	}
	operation := mutationRecord{
		RequestID: notice.RequestID, ConversationID: notice.ConversationID,
		DecisionID: decisionID, Decision: decision, ApprovalLevel: level,
		ApprovalGrantID: grantID, ApprovalGrantPersisted: grantPersisted,
		Phase: mutationDecisionPrepared,
	}
	if decision == protocol.DecisionAllowOnce {
		operation.ApprovalAuthorityFingerprint = authority.Fingerprint
		operation.ApprovalRecipientAgentID = authority.RecipientAgentID
		operation.ApprovedNotice = approvedNotice
		operation.ExecutionClaimID, err = newExecutionClaimID()
		if err != nil {
			return mutationRecord{}, false, err
		}
	}
	if err := s.mutations.Put(operation); err != nil {
		return mutationRecord{}, false, fmt.Errorf("persist receiver decision before relay mutation: %w", err)
	}
	return operation, false, nil
}

func (s *Service) handleDecisionMutation(ctx context.Context, requestID string, operation mutationRecord, status protocol.RequestStatus) error {
	switch status {
	case protocol.StatusAccepted, protocol.StatusRunning:
		if operation.Decision != protocol.DecisionAllowOnce || operation.ExecutionClaimID == "" {
			return fmt.Errorf("relay accepted request %q without a durable allow-once claim", requestID)
		}
		if err := s.requireCurrentApprovalAuthority(operation); err != nil {
			return err
		}
		if _, err := s.requireCurrentApprovedNotice(operation); err != nil {
			return err
		}
		current, err := s.mutations.Update(requestID, func(current *mutationRecord) error {
			if current.DecisionID != operation.DecisionID || current.Decision != operation.Decision || current.ExecutionClaimID != operation.ExecutionClaimID {
				return fmt.Errorf("request %q durable decision identity changed during retry", requestID)
			}
			if current.Phase == mutationDecisionPrepared {
				current.Phase = mutationClaimPrepared
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("persist execution claim before runtime mutation: %w", err)
		}
		operation = current
		switch operation.Phase {
		case mutationClaimPrepared:
		case mutationResultPrepared:
			if status != protocol.StatusRunning {
				return fmt.Errorf("request %q has a prepared result but relay state regressed to %q", requestID, status)
			}
		case mutationRuntimeStarted:
			if err := s.pending.UpdateStatus(requestID, status); err != nil {
				return err
			}
			if !s.hasActiveRequest(requestID) {
				s.logUnsafeReplayRefusal(requestID)
			}
			return nil
		default:
			return fmt.Errorf("request %q has invalid durable receiver phase %q", requestID, operation.Phase)
		}
		if err := s.pending.UpdateStatus(requestID, status); err != nil {
			return err
		}
		return s.startExecution(requestID, status)
	case protocol.StatusCompleted, protocol.StatusFailed, protocol.StatusCancelled:
		s.cancelExecution(requestID)
		if operation.Phase == mutationResultPrepared && operation.Result != nil && operation.Result.State == status {
			return s.replayPreparedResult(ctx, operation)
		}
		if err := s.pending.Remove(requestID); err != nil {
			return err
		}
		return s.mutations.Remove(requestID)
	case protocol.StatusExpired:
		if err := s.pending.Remove(requestID); err != nil {
			return err
		}
		return s.mutations.Remove(requestID)
	default:
		return fmt.Errorf("relay returned unexpected decision state %q", status)
	}
}

func (s *Service) handleEvent(event client.Event) error {
	switch event.Type {
	case "ready":
		return nil
	case "peer_request":
		var notice protocol.RequestNotice
		if err := json.Unmarshal(event.Payload, &notice); err != nil {
			return fmt.Errorf("decode peer request notice: %w", err)
		}
		if notice.Status == "" {
			notice.Status = protocol.StatusAwaitingApproval
		}
		resumes, err := s.controller.ResumesConversation(notice.ConversationID)
		if err != nil {
			return fmt.Errorf("check local session affinity: %w", err)
		}
		notice.ResumesSession = resumes
		if err := s.pending.Upsert(notice); err != nil {
			return err
		}
		if notice.Status == protocol.StatusAccepted || notice.Status == protocol.StatusRunning {
			runCtx := s.currentRunContext()
			if runCtx == nil {
				return fmt.Errorf("cannot recover request %q while receiver service is stopped", notice.RequestID)
			}
			return s.recoverOperation(runCtx, notice.RequestID, notice.ConversationID, notice.Status)
		}
		if notice.Status == protocol.StatusAwaitingApproval {
			runCtx := s.currentRunContext()
			if runCtx != nil {
				s.maybeAutoApprove(runCtx, notice)
			}
		}
		return nil
	case "peer_cancelled":
		var payload struct {
			RequestID string `json:"request_id"`
		}
		if err := json.Unmarshal(event.Payload, &payload); err != nil {
			return fmt.Errorf("decode cancellation notice: %w", err)
		}
		s.cancelExecution(payload.RequestID)
		if err := s.pending.Remove(payload.RequestID); err != nil {
			return err
		}
		return s.mutations.Remove(payload.RequestID)
	default:
		return nil
	}
}

func (s *Service) currentRunContext() context.Context {
	s.runMu.RLock()
	defer s.runMu.RUnlock()
	return s.runCtx
}

func (s *Service) reconcile(ctx context.Context) error {
	s.reconcileMu.Lock()
	defer s.reconcileMu.Unlock()
	inbox, err := s.client.Inbox(ctx)
	if err != nil {
		return err
	}
	for index := range inbox.Requests {
		resumes, resumeErr := s.controller.ResumesConversation(inbox.Requests[index].ConversationID)
		if resumeErr != nil {
			return resumeErr
		}
		inbox.Requests[index].ResumesSession = resumes
	}
	if err := s.pending.Replace(inbox.Requests); err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(inbox.Requests))
	for _, notice := range inbox.Requests {
		seen[notice.RequestID] = struct{}{}
		if err := s.recoverOperation(ctx, notice.RequestID, notice.ConversationID, notice.Status); err != nil {
			return err
		}
		if record, ok := s.pending.Get(notice.RequestID); ok && record.Notice.Status == protocol.StatusAwaitingApproval {
			s.maybeAutoApprove(ctx, record.Notice)
		}
	}
	// Terminal requests are intentionally absent from the inbox. Consult their
	// status when a locally durable mutation still needs an exact replay.
	for _, operation := range s.mutations.List() {
		if _, ok := seen[operation.RequestID]; ok {
			continue
		}
		request, err := s.client.GetRequest(ctx, operation.RequestID)
		if err != nil {
			if relayResourceNotFound(err) {
				s.cancelExecution(operation.RequestID)
				if removeErr := s.pending.Remove(operation.RequestID); removeErr != nil {
					return removeErr
				}
				if removeErr := s.mutations.Remove(operation.RequestID); removeErr != nil {
					return removeErr
				}
				s.logger.Warn("discarded orphaned receiver mutation no longer retained by relay", "request_id", operation.RequestID)
				continue
			}
			return fmt.Errorf("recover durable receiver operation %q: %w", operation.RequestID, err)
		}
		if request == nil || request.RequestID != operation.RequestID {
			return fmt.Errorf("recover durable receiver operation %q: relay returned mismatched request", operation.RequestID)
		}
		if operation.ConversationID != "" && request.ConversationID != operation.ConversationID {
			return fmt.Errorf("recover durable receiver operation %q: conversation mismatch", operation.RequestID)
		}
		if err := s.recoverOperation(ctx, operation.RequestID, request.ConversationID, request.Status); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) recoverOperation(ctx context.Context, requestID, conversationID string, status protocol.RequestStatus) error {
	s.approvalDecisionMu.Lock()
	defer s.approvalDecisionMu.Unlock()
	return s.recoverOperationLocked(ctx, requestID, conversationID, status)
}

func (s *Service) recoverOperationLocked(ctx context.Context, requestID, conversationID string, status protocol.RequestStatus) error {
	operation, ok := s.mutations.Get(requestID)
	switch status {
	case protocol.StatusAwaitingApproval:
		if !ok {
			return nil
		}
		if operation.Phase != mutationDecisionPrepared || operation.DecisionID == "" {
			return fmt.Errorf("request %q is awaiting approval but has inconsistent durable receiver state %q", requestID, operation.Phase)
		}
		if operation.Decision == protocol.DecisionAllowOnce && s.hasActiveExecution() && !s.hasActiveRequest(requestID) {
			return nil
		}
		if operation.Decision == protocol.DecisionAllowOnce {
			if authorityErr := s.requireCurrentApprovalAuthority(operation); authorityErr != nil {
				// The relay still says no decision committed, so it is safe to
				// discard the stale local intent and ask the recipient again.
				if err := s.mutations.Remove(requestID); err != nil {
					return err
				}
				s.logger.Warn("discarded stale prepared allow and restored Ask always", "request_id", requestID, "error", relayruntime.SafeSummary(authorityErr.Error()))
				return nil
			}
			if _, noticeErr := s.requireCurrentApprovedNotice(operation); noticeErr != nil {
				// No relay decision committed, so a changed or legacy-unbound
				// notice can safely return to explicit approval.
				if err := s.mutations.Remove(requestID); err != nil {
					return err
				}
				s.logger.Warn("discarded stale prepared allow and restored Ask always", "request_id", requestID, "error", relayruntime.SafeSummary(noticeErr.Error()))
				return nil
			}
		}
		var err error
		operation, err = s.ensurePreparedStandingGrant(requestID, operation)
		if err != nil {
			return err
		}
		mutation, err := s.client.Decide(ctx, requestID, protocol.DecisionPayload{Decision: operation.Decision, DecisionID: operation.DecisionID})
		if err != nil {
			return fmt.Errorf("replay durable recipient decision for %q: %w", requestID, err)
		}
		mutationState, err := mutationStatus(mutation, requestID)
		if err != nil {
			return err
		}
		return s.handleDecisionMutation(ctx, requestID, operation, mutationState)
	case protocol.StatusAccepted:
		if !ok {
			s.logUnboundApprovalRefusal(requestID)
			return nil
		}
		if operation.Phase == mutationDecisionPrepared {
			if err := s.requireCurrentApprovalAuthority(operation); err != nil {
				s.logApprovalAuthorityRefusal(requestID, err)
				return nil
			}
			if _, err := s.requireCurrentApprovedNotice(operation); err != nil {
				s.logApprovedNoticeRefusal(requestID, err)
				return nil
			}
			var err error
			operation, err = s.ensurePreparedStandingGrant(requestID, operation)
			if err != nil {
				return err
			}
			mutation, err := s.client.Decide(ctx, requestID, protocol.DecisionPayload{Decision: operation.Decision, DecisionID: operation.DecisionID})
			if err != nil {
				return fmt.Errorf("confirm durable recipient decision for %q: %w", requestID, err)
			}
			mutationState, err := mutationStatus(mutation, requestID)
			if err != nil {
				return err
			}
			return s.handleDecisionMutation(ctx, requestID, operation, mutationState)
		}
		if operation.Phase == mutationRuntimeStarted {
			if !s.hasActiveRequest(requestID) {
				s.logUnsafeReplayRefusal(requestID)
			}
			return nil
		}
		if operation.Phase != mutationClaimPrepared {
			return fmt.Errorf("accepted request %q has inconsistent durable receiver phase %q", requestID, operation.Phase)
		}
		if err := s.requireCurrentApprovalAuthority(operation); err != nil {
			s.logApprovalAuthorityRefusal(requestID, err)
			return nil
		}
		if _, err := s.requireCurrentApprovedNotice(operation); err != nil {
			s.logApprovedNoticeRefusal(requestID, err)
			return nil
		}
		return s.startExecution(requestID, status)
	case protocol.StatusRunning:
		if !ok {
			s.logUnsafeReplayRefusal(requestID)
			return nil
		}
		switch operation.Phase {
		case mutationDecisionPrepared:
			if err := s.requireCurrentApprovalAuthority(operation); err != nil {
				s.logApprovalAuthorityRefusal(requestID, err)
				return nil
			}
			if _, err := s.requireCurrentApprovedNotice(operation); err != nil {
				s.logApprovedNoticeRefusal(requestID, err)
				return nil
			}
			var err error
			operation, err = s.ensurePreparedStandingGrant(requestID, operation)
			if err != nil {
				return err
			}
			mutation, err := s.client.Decide(ctx, requestID, protocol.DecisionPayload{Decision: operation.Decision, DecisionID: operation.DecisionID})
			if err != nil {
				return fmt.Errorf("confirm durable recipient decision for running request %q: %w", requestID, err)
			}
			mutationState, err := mutationStatus(mutation, requestID)
			if err != nil {
				return err
			}
			return s.handleDecisionMutation(ctx, requestID, operation, mutationState)
		case mutationClaimPrepared:
			if err := s.requireCurrentApprovalAuthority(operation); err != nil {
				s.logApprovalAuthorityRefusal(requestID, err)
				return nil
			}
			if _, err := s.requireCurrentApprovedNotice(operation); err != nil {
				s.logApprovedNoticeRefusal(requestID, err)
				return nil
			}
			return s.startExecution(requestID, status)
		case mutationResultPrepared:
			return s.startExecution(requestID, status)
		case mutationRuntimeStarted:
			if !s.hasActiveRequest(requestID) {
				s.logUnsafeReplayRefusal(requestID)
			}
			return nil
		default:
			return fmt.Errorf("request %q has invalid durable receiver phase %q", requestID, operation.Phase)
		}
	case protocol.StatusCompleted, protocol.StatusFailed, protocol.StatusCancelled:
		s.cancelExecution(requestID)
		if ok && operation.Phase == mutationResultPrepared && operation.Result != nil {
			if operation.Result.State == status {
				return s.replayPreparedResult(ctx, operation)
			}
			s.logger.Warn("relay reached a different terminal state before prepared result replay", "request_id", requestID, "relay_status", status, "prepared_status", operation.Result.State)
		}
		if err := s.pending.Remove(requestID); err != nil {
			return err
		}
		return s.mutations.Remove(requestID)
	case protocol.StatusRejected, protocol.StatusExpired:
		s.cancelExecution(requestID)
		if err := s.pending.Remove(requestID); err != nil {
			return err
		}
		return s.mutations.Remove(requestID)
	default:
		return fmt.Errorf("request %q has unsupported recovery state %q", requestID, status)
	}
}

func relayResourceNotFound(err error) bool {
	var relayErr *client.Error
	return errors.As(err, &relayErr) && relayErr.StatusCode == 404
}

func (s *Service) logUnsafeReplayRefusal(requestID string) {
	s.logger.Warn("request may have started before receiver restart; refusing automatic runtime replay", "request_id", requestID, "recovery", "manual resolution required")
}

func (s *Service) logUnboundApprovalRefusal(requestID string) {
	s.logger.Warn("request was accepted without a locally bound approval; refusing runtime recovery", "request_id", requestID, "recovery", "manual resolution required")
}

func (s *Service) logApprovalAuthorityRefusal(requestID string, err error) {
	s.logger.Warn("durable approval authority changed; refusing runtime recovery", "request_id", requestID, "error", relayruntime.SafeSummary(err.Error()), "recovery", "manual resolution required")
}

func (s *Service) logApprovedNoticeRefusal(requestID string, err error) {
	s.logger.Warn("durably approved request metadata is missing or changed; refusing runtime recovery", "request_id", requestID, "error", relayruntime.SafeSummary(err.Error()), "recovery", "manual resolution required")
}

func (s *Service) startExecution(requestID string, status protocol.RequestStatus) error {
	if status != protocol.StatusAccepted && status != protocol.StatusRunning {
		return fmt.Errorf("request %q cannot execute from relay state %q", requestID, status)
	}
	operation, ok := s.mutations.Get(requestID)
	if !ok {
		return fmt.Errorf("request %q has no durable execution claim", requestID)
	}
	if operation.Phase == mutationRuntimeStarted {
		if !s.hasActiveRequest(requestID) {
			s.logUnsafeReplayRefusal(requestID)
		}
		return nil
	}
	if operation.Phase != mutationClaimPrepared && operation.Phase != mutationResultPrepared {
		return fmt.Errorf("request %q cannot execute from durable phase %q", requestID, operation.Phase)
	}
	if status == protocol.StatusAccepted && operation.Phase != mutationClaimPrepared {
		return fmt.Errorf("accepted request %q cannot use durable phase %q", requestID, operation.Phase)
	}
	if operation.Phase == mutationClaimPrepared {
		if err := s.requireCurrentApprovalAuthority(operation); err != nil {
			return err
		}
		if _, err := s.requireCurrentApprovedNotice(operation); err != nil {
			return err
		}
	}
	s.runMu.Lock()
	if !s.running || s.runCtx == nil {
		s.runMu.Unlock()
		return fmt.Errorf("receiver service is not running")
	}
	if _, exists := s.active[requestID]; exists {
		s.runMu.Unlock()
		return nil
	}
	executionCtx, cancel := context.WithCancel(s.runCtx)
	s.active[requestID] = cancel
	s.activeWG.Add(1)
	s.runMu.Unlock()
	go func() {
		defer s.activeWG.Done()
		defer func() {
			s.runMu.Lock()
			delete(s.active, requestID)
			s.runMu.Unlock()
		}()
		s.execute(executionCtx, requestID)
	}()
	return nil
}

func (s *Service) execute(ctx context.Context, requestID string) {
	operation, ok := s.mutations.Get(requestID)
	if !ok {
		s.logger.Error("load durable execution claim failed", "request_id", requestID, "error", "operation is missing")
		return
	}
	if operation.Phase == mutationResultPrepared {
		if err := s.replayPreparedResult(ctx, operation); err != nil {
			s.logger.Error("replay prepared runtime result failed", "request_id", requestID, "error", relayruntime.SafeSummary(err.Error()))
		}
		return
	}
	if operation.Phase != mutationClaimPrepared || operation.ExecutionClaimID == "" {
		s.logUnsafeReplayRefusal(requestID)
		return
	}
	if err := s.requireCurrentApprovalAuthority(operation); err != nil {
		s.logApprovalAuthorityRefusal(requestID, err)
		return
	}
	_, err := s.requireCurrentApprovedNotice(operation)
	if err != nil {
		s.logApprovedNoticeRefusal(requestID, err)
		return
	}
	executionClaimID := operation.ExecutionClaimID
	payload, err := s.client.FetchExecution(ctx, requestID)
	if err != nil {
		s.logger.Error("fetch approved execution failed", "request_id", requestID, "error", relayruntime.SafeSummary(err.Error()))
		return
	}
	if payload == nil {
		s.logger.Error("validate approved execution payload failed", "request_id", requestID, "error", "relay returned an empty execution payload")
		return
	}
	if err := validateExecutionPayloadAgainstApprovedBinding(*operation.ApprovedNotice, *payload); err != nil {
		s.logger.Error("validate approved execution payload failed", "request_id", requestID, "error", relayruntime.SafeSummary(err.Error()))
		return
	}
	mutation, err := s.client.MarkRunning(ctx, requestID, executionClaimID)
	if err != nil {
		s.logger.Error("mark request running failed", "request_id", requestID, "error", relayruntime.SafeSummary(err.Error()))
		return
	}
	mutationState, mutationErr := mutationStatus(mutation, requestID)
	if mutationErr != nil || mutationState != protocol.StatusRunning {
		s.logger.Error("mark request running returned unexpected state", "request_id", requestID)
		return
	}
	// This synced phase is the at-most-once boundary. Once it exists, a
	// receiver restart must never spawn the runtime again because external tool
	// effects cannot be rolled back or proven absent.
	operation, err = s.mutations.Update(requestID, func(current *mutationRecord) error {
		if current.ExecutionClaimID != executionClaimID || current.Phase != mutationClaimPrepared {
			return fmt.Errorf("durable claim changed before the runtime-start boundary")
		}
		current.Phase = mutationRuntimeStarted
		return nil
	})
	if err != nil {
		s.logger.Error("persist runtime-start boundary failed", "request_id", requestID, "error", relayruntime.SafeSummary(err.Error()))
		return
	}
	_ = s.pending.UpdateStatus(requestID, protocol.StatusRunning)

	var sandbox *artifact.Sandbox
	if s.artifacts != nil {
		sandbox, err = s.artifacts.Materialize(ctx, payload.Attachments, s.client)
		if err != nil {
			s.submitFailure(ctx, requestID, executionClaimID, err)
			return
		}
		defer func() {
			if cleanupErr := s.artifacts.Cleanup(sandbox); cleanupErr != nil {
				s.logger.Warn("clean recipient artifact sandbox failed", "request_id", requestID, "error", relayruntime.SafeSummary(cleanupErr.Error()))
			}
		}()
	} else if len(payload.Attachments) > 0 {
		s.submitFailure(ctx, requestID, executionClaimID, errors.New("approved request has attachments but recipient artifact support is unavailable"))
		return
	}
	workspaces, err := s.resolveRequestedWorkspaces(payload.RequestedAccess)
	if err != nil {
		s.submitFailure(ctx, requestID, executionClaimID, err)
		return
	}
	request := relayruntime.RunRequest{
		RequestID:      payload.RequestID,
		ConversationID: payload.ConversationID,
		Title:          payload.Title,
		Requester:      payload.RequesterDisplayName,
		Prompt:         payload.Prompt,
		Workspaces:     workspaces,
	}
	if sandbox != nil {
		request.Attachments = append([]string(nil), sandbox.Attachments...)
		if s.controller.ConfiguredPolicy().AllowWrites {
			request.ReturnDirectory = sandbox.ReturnDirectory
		}
	}
	result, err := s.controller.Execute(ctx, request, relayruntime.EventSinkFunc(func(_ context.Context, event relayruntime.Event) error {
		s.logger.Info("recipient runtime progress", "request_id", requestID, "event", event.Type, "tool", event.Tool, "summary", event.Summary)
		return nil
	}))
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return
		}
		s.submitFailure(ctx, requestID, executionClaimID, err)
		return
	}
	var resultFiles []protocol.AttachmentInput
	if sandbox != nil && request.ReturnDirectory != "" {
		resultFiles, err = s.artifacts.CollectResults(sandbox)
		if err != nil {
			s.submitFailure(ctx, requestID, executionClaimID, err)
			return
		}
	}
	answer := relayruntime.RedactSensitiveText(result.FinalText)
	if answer != result.FinalText {
		s.logger.Warn("recipient result contained credential-shaped text and was redacted", "request_id", requestID)
	}
	resultPayload := protocol.ResultPayload{ExecutionClaimID: executionClaimID, State: protocol.StatusCompleted, Answer: answer, ResultFiles: resultFiles}
	if err := s.prepareAndSubmitResult(ctx, operation, resultPayload); err != nil {
		s.logger.Error("submit runtime result failed", "request_id", requestID, "error", relayruntime.SafeSummary(err.Error()))
	}
}

func (s *Service) submitFailure(ctx context.Context, requestID, executionClaimID string, executionErr error) {
	diagnostic := relayruntime.SafeSummary(executionErr.Error())
	operation, ok := s.mutations.Get(requestID)
	if !ok || operation.ExecutionClaimID != executionClaimID {
		s.logger.Error("prepare runtime failure result failed", "request_id", requestID, "error", "durable execution claim is unavailable")
		return
	}
	if err := s.prepareAndSubmitResult(ctx, operation, protocol.ResultPayload{ExecutionClaimID: executionClaimID, State: protocol.StatusFailed, Error: diagnostic}); err != nil {
		s.logger.Error("submit runtime failure failed", "request_id", requestID, "error", relayruntime.SafeSummary(err.Error()))
	}
}

func (s *Service) prepareAndSubmitResult(ctx context.Context, operation mutationRecord, result protocol.ResultPayload) error {
	if operation.Phase != mutationRuntimeStarted || operation.ExecutionClaimID != result.ExecutionClaimID {
		return fmt.Errorf("request %q is not at its durable result boundary", operation.RequestID)
	}
	resultCopy := result
	resultCopy.ResultFiles = append([]protocol.AttachmentInput(nil), result.ResultFiles...)
	operation, err := s.mutations.Update(operation.RequestID, func(current *mutationRecord) error {
		if current.ExecutionClaimID != result.ExecutionClaimID {
			return errors.New("durable execution claim changed before result preparation")
		}
		switch current.Phase {
		case mutationRuntimeStarted:
			current.Phase = mutationResultPrepared
			current.Result = &resultCopy
			return nil
		case mutationResultPrepared:
			if current.Result == nil || !samePreparedResult(*current.Result, resultCopy) {
				return errors.New("a different result is already prepared for this request")
			}
			return nil
		default:
			return fmt.Errorf("request is in durable phase %q", current.Phase)
		}
	})
	if err != nil {
		return fmt.Errorf("persist exact result before relay mutation: %w", err)
	}
	return s.replayPreparedResult(ctx, operation)
}

func (s *Service) replayPreparedResult(ctx context.Context, operation mutationRecord) error {
	if operation.Phase != mutationResultPrepared || operation.Result == nil || operation.Result.ExecutionClaimID != operation.ExecutionClaimID {
		return fmt.Errorf("request %q has no valid prepared result", operation.RequestID)
	}
	mutation, err := s.client.SubmitResult(ctx, operation.RequestID, *operation.Result)
	if err != nil {
		return err
	}
	mutationState, mutationErr := mutationStatus(mutation, operation.RequestID)
	if mutationErr != nil || mutationState != operation.Result.State {
		return fmt.Errorf("relay returned unexpected result state for request %q", operation.RequestID)
	}
	if err := s.pending.Remove(operation.RequestID); err != nil {
		return err
	}
	return s.mutations.Remove(operation.RequestID)
}

func mutationStatus(response *protocol.MutationResponse, requestID string) (protocol.RequestStatus, error) {
	if response == nil || response.RequestID != requestID || response.Status == "" {
		return "", fmt.Errorf("relay returned a mismatched mutation response for request %q", requestID)
	}
	return response.Status, nil
}

func samePreparedResult(left, right protocol.ResultPayload) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && string(leftJSON) == string(rightJSON)
}

func newExecutionClaimID() (string, error) {
	return newOpaqueID("claim_")
}

func newOpaqueID(prefix string) (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("read cryptographic randomness: %w", err)
	}
	return prefix + hex.EncodeToString(value), nil
}

func (s *Service) heartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if card, err := s.client.Heartbeat(ctx, s.heartbeat); err != nil && ctx.Err() == nil {
				s.logger.Warn("publish heartbeat failed", "error", relayruntime.SafeSummary(err.Error()))
			} else if err == nil {
				if identityErr := s.activateApprovalAuthority(card); identityErr != nil {
					s.logger.Error("standing approval identity check failed", "error", relayruntime.SafeSummary(identityErr.Error()))
				}
			}
			// Poll the durable inbox as well as consuming SSE. This bounds recovery
			// time when a mutation response was lost but the event stream itself
			// stayed healthy, so accepted claims and prepared results do not require
			// a daemon restart or another button press.
			if err := s.reconcile(ctx); err != nil && ctx.Err() == nil {
				s.logger.Warn("periodic receiver reconciliation failed", "error", relayruntime.SafeSummary(err.Error()))
			}
		}
	}
}

func (s *Service) cancelExecution(requestID string) {
	s.runMu.RLock()
	cancel := s.active[requestID]
	s.runMu.RUnlock()
	if cancel != nil {
		cancel()
	}
}

func (s *Service) validateNotice(notice protocol.RequestNotice) error {
	if len(notice.Attachments) > 0 && s.artifacts == nil {
		return fmt.Errorf("request %q has attachments but recipient artifact support is unavailable", notice.RequestID)
	}
	if len(notice.Attachments) > protocol.MaxAttachments {
		return fmt.Errorf("request %q exceeds the attachment count limit", notice.RequestID)
	}
	var total int64
	for _, descriptor := range notice.Attachments {
		if strings.TrimSpace(descriptor.ArtifactID) == "" || strings.TrimSpace(descriptor.Name) == "" || descriptor.SizeBytes < 0 || descriptor.SizeBytes > protocol.MaxAttachmentBytes {
			return fmt.Errorf("request %q has invalid attachment metadata", notice.RequestID)
		}
		total += descriptor.SizeBytes
	}
	if total > protocol.MaxRequestPayloadBytes {
		return fmt.Errorf("request %q exceeds the attachment byte limit", notice.RequestID)
	}
	_, err := s.resolveRequestedWorkspaces(notice.RequestedAccess)
	return err
}

func (s *Service) resolveRequestedWorkspaces(requested []protocol.RequestedAccess) ([]relayruntime.Workspace, error) {
	result := make([]relayruntime.Workspace, 0, len(requested))
	seen := make(map[string]struct{}, len(requested))
	for _, access := range requested {
		alias := strings.TrimSpace(access.WorkspaceAlias)
		root, ok := s.workspaces[alias]
		if !ok {
			return nil, fmt.Errorf("workspace alias %q is not configured by this recipient", alias)
		}
		if _, exists := seen[alias]; exists {
			return nil, fmt.Errorf("workspace alias %q was requested more than once", alias)
		}
		seen[alias] = struct{}{}
		if access.Mode == protocol.PermissionReadOnly && s.controller.ConfiguredPolicy().AllowWrites {
			return nil, fmt.Errorf("workspace alias %q requests read_only access, which this runtime cannot enforce while the recipient policy allows writes", alias)
		}
		mode := relayruntime.WorkspaceReadOnly
		if access.Mode == protocol.PermissionGuardedWrite && s.controller.ConfiguredPolicy().AllowWrites {
			mode = relayruntime.WorkspaceWritable
		} else if access.Mode != protocol.PermissionReadOnly && access.Mode != protocol.PermissionGuardedWrite {
			return nil, fmt.Errorf("workspace alias %q has invalid requested access %q", alias, access.Mode)
		}
		result = append(result, relayruntime.Workspace{Path: root, Mode: mode})
	}
	return result, nil
}

func validateProposal(notice protocol.RequestNotice, proposal protocol.ProposalPayload) error {
	if proposal.RequestID != notice.RequestID ||
		proposal.ConversationID != notice.ConversationID ||
		proposal.RequesterAgentID != notice.RequesterAgentID ||
		proposal.RequesterMemberID != notice.RequesterMemberID ||
		proposal.RequesterDisplayName != notice.RequesterDisplayName ||
		proposal.Title != notice.Title ||
		!proposal.ExpiresAt.Equal(notice.ExpiresAt) ||
		!sameRequestedAccess(proposal.RequestedAccess, notice.RequestedAccess) ||
		!sameArtifactDescriptors(proposal.Attachments, notice.Attachments) {
		return fmt.Errorf("relay proposal metadata does not match pending request %q", notice.RequestID)
	}
	if notice.PromptBytes != 0 || notice.PromptSHA256 != "" {
		if int64(len([]byte(proposal.Prompt))) != notice.PromptBytes {
			return fmt.Errorf("relay proposal prompt does not match pending request %q", notice.RequestID)
		}
		if notice.PromptSHA256 != "" {
			digest := fmt.Sprintf("%x", sha256.Sum256([]byte(proposal.Prompt)))
			if !strings.EqualFold(digest, notice.PromptSHA256) {
				return fmt.Errorf("relay proposal prompt does not match pending request %q", notice.RequestID)
			}
		}
	}
	return nil
}

func approvedNoticeBindingFor(notice protocol.RequestNotice) (*approvedNoticeBinding, error) {
	binding := &approvedNoticeBinding{
		Version:              approvedNoticeBindingVersion,
		RequestID:            notice.RequestID,
		ConversationID:       notice.ConversationID,
		RequesterAgentID:     notice.RequesterAgentID,
		RequesterMemberID:    notice.RequesterMemberID,
		RequesterDisplayName: notice.RequesterDisplayName,
		Title:                notice.Title,
		ExpiresAt:            notice.ExpiresAt.UTC(),
		RequestedAccess:      append([]protocol.RequestedAccess(nil), notice.RequestedAccess...),
		Attachments:          append([]protocol.ArtifactDescriptor(nil), notice.Attachments...),
		PromptBytes:          notice.PromptBytes,
		PromptSHA256:         strings.ToLower(strings.TrimSpace(notice.PromptSHA256)),
	}
	if err := validateApprovedNoticeBinding(*binding, notice.RequestID); err != nil {
		return nil, err
	}
	return binding, nil
}

func sameApprovedNoticeBinding(left, right approvedNoticeBinding) bool {
	return left.Version == right.Version &&
		left.RequestID == right.RequestID &&
		left.ConversationID == right.ConversationID &&
		left.RequesterAgentID == right.RequesterAgentID &&
		left.RequesterMemberID == right.RequesterMemberID &&
		left.RequesterDisplayName == right.RequesterDisplayName &&
		left.Title == right.Title &&
		left.ExpiresAt.Equal(right.ExpiresAt) &&
		sameRequestedAccess(left.RequestedAccess, right.RequestedAccess) &&
		sameArtifactDescriptors(left.Attachments, right.Attachments) &&
		left.PromptBytes == right.PromptBytes &&
		strings.EqualFold(strings.TrimSpace(left.PromptSHA256), strings.TrimSpace(right.PromptSHA256))
}

func validateNoticeAgainstApprovedBinding(notice protocol.RequestNotice, binding approvedNoticeBinding) error {
	candidate, err := approvedNoticeBindingFor(notice)
	if err != nil {
		return fmt.Errorf("current pending notice for request %q is invalid: %w", binding.RequestID, err)
	}
	if !sameApprovedNoticeBinding(binding, *candidate) {
		return fmt.Errorf("current pending notice for request %q no longer matches the durably approved notice", binding.RequestID)
	}
	return nil
}

// validateExecutionPayload binds the full post-approval payload to the exact
// metadata represented by a notice. Production execution uses the durable
// approvedNoticeBinding overload below so mutable PendingStore state can never
// redefine what was approved.
func validateExecutionPayload(notice protocol.RequestNotice, payload protocol.ExecutionPayload) error {
	binding, err := approvedNoticeBindingFor(notice)
	if err != nil {
		return err
	}
	return validateExecutionPayloadAgainstApprovedBinding(*binding, payload)
}

// validateExecutionPayloadAgainstApprovedBinding checks the second relay read
// against immutable approval metadata before MarkRunning. Prompt contents are
// never persisted locally; byte count plus SHA-256 commit to the exact bytes.
func validateExecutionPayloadAgainstApprovedBinding(binding approvedNoticeBinding, payload protocol.ExecutionPayload) error {
	requestID := binding.RequestID
	if payload.RequestID != requestID {
		return fmt.Errorf("approved execution payload does not match pending request %q: request_id changed", requestID)
	}
	if payload.ConversationID != binding.ConversationID {
		return fmt.Errorf("approved execution payload does not match pending request %q: conversation_id changed", requestID)
	}
	if payload.RequesterAgentID != binding.RequesterAgentID {
		return fmt.Errorf("approved execution payload does not match pending request %q: requester_agent_id changed", requestID)
	}
	if payload.RequesterMemberID != binding.RequesterMemberID {
		return fmt.Errorf("approved execution payload does not match pending request %q: authenticated requester member_id changed", requestID)
	}
	if payload.RequesterDisplayName != binding.RequesterDisplayName {
		return fmt.Errorf("approved execution payload does not match pending request %q: requester display name changed", requestID)
	}
	if payload.Title != binding.Title {
		return fmt.Errorf("approved execution payload does not match pending request %q: title changed", requestID)
	}
	if !payload.ExpiresAt.Equal(binding.ExpiresAt) {
		return fmt.Errorf("approved execution payload does not match pending request %q: expiry changed", requestID)
	}
	if !sameRequestedAccess(payload.RequestedAccess, binding.RequestedAccess) {
		return fmt.Errorf("approved execution payload does not match pending request %q: requested access changed", requestID)
	}
	if !sameArtifactDescriptors(payload.Attachments, binding.Attachments) {
		return fmt.Errorf("approved execution payload does not match pending request %q: attachment descriptors changed", requestID)
	}
	if binding.PromptBytes < 0 || int64(len([]byte(payload.Prompt))) != binding.PromptBytes {
		return fmt.Errorf("approved execution payload does not match pending request %q: prompt byte count changed", requestID)
	}
	wantDigest := strings.TrimSpace(binding.PromptSHA256)
	decodedDigest, err := hex.DecodeString(wantDigest)
	if err != nil || len(decodedDigest) != sha256.Size {
		return fmt.Errorf("approved execution payload cannot be verified for pending request %q: pending prompt SHA-256 is missing or invalid", requestID)
	}
	gotDigest := sha256.Sum256([]byte(payload.Prompt))
	if !strings.EqualFold(hex.EncodeToString(gotDigest[:]), wantDigest) {
		return fmt.Errorf("approved execution payload does not match pending request %q: prompt SHA-256 changed", requestID)
	}
	return nil
}

func sameRequestedAccess(left, right []protocol.RequestedAccess) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func sameArtifactDescriptors(left, right []protocol.ArtifactDescriptor) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func resolveConfiguredWorkspaces(configured map[string]string) (map[string]string, error) {
	resolved := make(map[string]string, len(configured))
	for rawAlias, rawPath := range configured {
		alias := strings.TrimSpace(rawAlias)
		if alias == "" || strings.ContainsAny(alias, `/\\`) {
			return nil, fmt.Errorf("workspace alias %q is invalid", rawAlias)
		}
		absolute, err := filepath.Abs(rawPath)
		if err != nil {
			return nil, fmt.Errorf("resolve workspace %q: %w", alias, err)
		}
		canonical, err := filepath.EvalSymlinks(absolute)
		if err != nil {
			return nil, fmt.Errorf("resolve workspace %q links: %w", alias, err)
		}
		info, err := os.Stat(canonical)
		if err != nil || !info.IsDir() {
			return nil, fmt.Errorf("workspace %q is not an available directory", alias)
		}
		resolved[alias] = filepath.Clean(canonical)
	}
	return resolved, nil
}
