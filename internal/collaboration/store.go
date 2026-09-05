package collaboration

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/mohitbadwal/team-relay/internal/auth"
	"github.com/mohitbadwal/team-relay/internal/keyspace"
	"github.com/mohitbadwal/team-relay/internal/protocol"
	"github.com/redis/go-redis/v9"
)

var (
	ErrUnauthorized = errors.New("unauthorized")
	ErrForbidden    = errors.New("forbidden")
	ErrNotFound     = errors.New("not found")
	ErrInvalid      = errors.New("invalid request")
	ErrConflict     = errors.New("request state conflict")
)

const (
	prefix             = "team-relay:v1:collab:"
	agentTTL           = 75 * time.Second
	requestRetention   = 7 * 24 * time.Hour
	conversationTTL    = 30 * 24 * time.Hour
	maximumAnswerBytes = 128 * 1024
	maximumErrorBytes  = 4 * 1024
)

type AgentQuery struct {
	Need             string
	Capabilities     []string
	WorkspaceAliases []string
	OnlineOnly       bool
	AcceptingOnly    bool
	Limit            int
}

type RedisStore struct {
	rdb *redis.Client
	now func() time.Time
}

func NewRedisStore(rdb *redis.Client) *RedisStore {
	return &RedisStore{rdb: rdb, now: time.Now}
}

func (s *RedisStore) Heartbeat(ctx context.Context, principal auth.Principal, heartbeat protocol.AgentHeartbeat) (protocol.AgentCard, error) {
	if err := requireDevice(principal); err != nil {
		return protocol.AgentCard{}, err
	}
	if err := validateHeartbeat(heartbeat); err != nil {
		return protocol.AgentCard{}, err
	}
	// Runtime and permission mode are chosen during local enrollment. Bind the
	// advertised directory card to that authenticated device record so a
	// modified client cannot claim a more capable runtime or policy.
	if strings.TrimSpace(principal.Runtime) == "" || strings.TrimSpace(principal.PermissionMode) == "" ||
		strings.TrimSpace(heartbeat.Runtime.ID) != principal.Runtime || string(heartbeat.PermissionMode) != principal.PermissionMode {
		return protocol.AgentCard{}, ErrForbidden
	}
	now := s.now().UTC()
	card := protocol.AgentCard{
		AgentID:           principal.AgentID,
		MemberID:          principal.MemberID,
		DisplayName:       principal.DisplayName,
		DeviceName:        principal.DeviceName,
		Availability:      heartbeat.Availability,
		AcceptingRequests: heartbeat.AcceptingRequests,
		Runtime:           heartbeat.Runtime,
		PermissionMode:    heartbeat.PermissionMode,
		Capabilities:      cleanUnique(heartbeat.Capabilities, 20),
		WorkspaceAliases:  cleanUnique(heartbeat.WorkspaceAliases, 20),
		Online:            true,
		LastSeen:          now,
	}
	payload, err := json.Marshal(card)
	if err != nil {
		return protocol.AgentCard{}, err
	}
	for attempt := 0; attempt < 5; attempt++ {
		err = s.rdb.Watch(ctx, func(tx *redis.Tx) error {
			revoked, checkErr := tx.SIsMember(ctx, revokedAgentsKey(principal.OrganizationID), principal.AgentID).Result()
			if checkErr != nil {
				return checkErr
			}
			if revoked {
				return ErrForbidden
			}
			_, transactionErr := tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.Set(ctx, agentKey(principal.OrganizationID, principal.AgentID), payload, agentTTL)
				pipe.SAdd(ctx, agentsKey(principal.OrganizationID), principal.AgentID)
				return nil
			})
			return transactionErr
		}, revokedAgentsKey(principal.OrganizationID))
		if errors.Is(err, redis.TxFailedErr) {
			continue
		}
		return card, err
	}
	return protocol.AgentCard{}, fmt.Errorf("publish heartbeat after concurrent revocation: %w", redis.TxFailedErr)
}

func (s *RedisStore) ListAgents(ctx context.Context, principal auth.Principal, query AgentQuery) (protocol.AgentDirectoryResponse, error) {
	if err := requireDevice(principal); err != nil {
		return protocol.AgentDirectoryResponse{}, err
	}
	ids, err := s.rdb.SMembers(ctx, agentsKey(principal.OrganizationID)).Result()
	if err != nil {
		return protocol.AgentDirectoryResponse{}, err
	}
	result := protocol.AgentDirectoryResponse{Agents: make([]protocol.AgentCard, 0, len(ids)), ObservedAt: s.now().UTC()}
	revokedIDs, err := s.rdb.SMembers(ctx, revokedAgentsKey(principal.OrganizationID)).Result()
	if err != nil {
		return protocol.AgentDirectoryResponse{}, err
	}
	revoked := make(map[string]struct{}, len(revokedIDs))
	for _, id := range revokedIDs {
		revoked[id] = struct{}{}
	}
	for _, id := range ids {
		if _, isRevoked := revoked[id]; isRevoked {
			_ = s.rdb.SRem(ctx, agentsKey(principal.OrganizationID), id).Err()
			_ = s.rdb.Del(ctx, agentKey(principal.OrganizationID, id)).Err()
			continue
		}
		payload, err := s.rdb.Get(ctx, agentKey(principal.OrganizationID, id)).Bytes()
		if errors.Is(err, redis.Nil) {
			_ = s.rdb.SRem(ctx, agentsKey(principal.OrganizationID), id).Err()
			continue
		}
		if err != nil {
			return protocol.AgentDirectoryResponse{}, err
		}
		var card protocol.AgentCard
		if json.Unmarshal(payload, &card) != nil || card.AgentID != id {
			continue
		}
		// A teammate is a different member, not merely a different device.
		// Excluding every device owned by the caller prevents a cross-device
		// self-loop from consuming an approval and spawning another local agent.
		if card.MemberID == principal.MemberID {
			continue
		}
		card.Online = true
		if query.AcceptingOnly && !card.AcceptingRequests {
			continue
		}
		if !matchesAgent(card, query) {
			continue
		}
		result.Agents = append(result.Agents, card)
	}
	sort.Slice(result.Agents, func(i, j int) bool {
		if result.Agents[i].DisplayName == result.Agents[j].DisplayName {
			return result.Agents[i].AgentID < result.Agents[j].AgentID
		}
		return result.Agents[i].DisplayName < result.Agents[j].DisplayName
	})
	if query.Limit > 0 && len(result.Agents) > query.Limit {
		result.Agents = result.Agents[:query.Limit]
	}
	return result, nil
}

type storedRequest struct {
	Request             protocol.Request  `json:"request"`
	Prompt              string            `json:"prompt"`
	IdempotencyRedisKey string            `json:"idempotency_redis_key,omitempty"`
	DecisionID          string            `json:"decision_id,omitempty"`
	Decision            protocol.Decision `json:"decision,omitempty"`
	ExecutionClaimID    string            `json:"execution_claim_id,omitempty"`
	ResultDigest        string            `json:"result_digest,omitempty"`
}

type conversation struct {
	ID               string `json:"id"`
	OrganizationID   string `json:"organization_id"`
	RequesterAgentID string `json:"requester_agent_id"`
	TargetAgentID    string `json:"target_agent_id"`
}

type storedArtifact struct {
	Descriptor       protocol.ArtifactDescriptor `json:"descriptor"`
	Encoding         string                      `json:"encoding"`
	ContentBase64    string                      `json:"content_base64"`
	RequestID        string                      `json:"request_id"`
	RequesterAgentID string                      `json:"requester_agent_id"`
	TargetAgentID    string                      `json:"target_agent_id"`
	Direction        string                      `json:"direction"`
}

type idempotencyRecord struct {
	RequestID string `json:"request_id"`
	Digest    string `json:"digest"`
}

func (s *RedisStore) CreateRequest(ctx context.Context, principal auth.Principal, input protocol.CreateRequest) (protocol.MutationResponse, protocol.RequestNotice, bool, error) {
	if err := requireDevice(principal); err != nil {
		return protocol.MutationResponse{}, protocol.RequestNotice{}, false, err
	}
	if err := validateCreate(input); err != nil {
		return protocol.MutationResponse{}, protocol.RequestNotice{}, false, err
	}
	digest, err := requestDigest(input)
	if err != nil {
		return protocol.MutationResponse{}, protocol.RequestNotice{}, false, err
	}
	idempotencyRedisKey := idempotencyKey(principal.OrganizationID, principal.AgentID, input.IdempotencyKey)
	if existingRaw, lookupErr := s.rdb.Get(ctx, idempotencyRedisKey).Bytes(); lookupErr == nil {
		var existing idempotencyRecord
		if json.Unmarshal(existingRaw, &existing) != nil || existing.Digest != digest {
			return protocol.MutationResponse{}, protocol.RequestNotice{}, false, fmt.Errorf("%w: idempotency key was already used for different content", ErrConflict)
		}
		previous, readErr := s.readStoredRequest(ctx, principal.OrganizationID, existing.RequestID)
		if readErr != nil {
			return protocol.MutationResponse{}, protocol.RequestNotice{}, false, readErr
		}
		return mutation(previous.Request), notice(previous.Request), false, nil
	} else if !errors.Is(lookupErr, redis.Nil) {
		return protocol.MutationResponse{}, protocol.RequestNotice{}, false, lookupErr
	}

	var conv conversation
	newConversation := strings.TrimSpace(input.ConversationID) == ""
	if newConversation {
		conv = conversation{
			ID:               randomID("conv_"),
			OrganizationID:   principal.OrganizationID,
			RequesterAgentID: principal.AgentID,
			TargetAgentID:    strings.TrimSpace(input.TargetAgentID),
		}
	} else {
		conv, err = s.readConversation(ctx, principal.OrganizationID, strings.TrimSpace(input.ConversationID))
		if err != nil {
			return protocol.MutationResponse{}, protocol.RequestNotice{}, false, err
		}
		if conv.RequesterAgentID != principal.AgentID {
			return protocol.MutationResponse{}, protocol.RequestNotice{}, false, ErrForbidden
		}
		if input.TargetAgentID != "" && strings.TrimSpace(input.TargetAgentID) != conv.TargetAgentID {
			return protocol.MutationResponse{}, protocol.RequestNotice{}, false, fmt.Errorf("%w: target_agent_id does not match conversation", ErrInvalid)
		}
	}
	if conv.TargetAgentID == principal.AgentID {
		return protocol.MutationResponse{}, protocol.RequestNotice{}, false, fmt.Errorf("%w: an agent cannot request itself", ErrInvalid)
	}
	target, err := s.readAgent(ctx, principal.OrganizationID, conv.TargetAgentID)
	if err != nil {
		return protocol.MutationResponse{}, protocol.RequestNotice{}, false, fmt.Errorf("target agent is unavailable: %w", err)
	}
	if target.MemberID == principal.MemberID {
		return protocol.MutationResponse{}, protocol.RequestNotice{}, false, fmt.Errorf("%w: an agent cannot request another device owned by the same member", ErrInvalid)
	}
	if !target.AcceptingRequests {
		return protocol.MutationResponse{}, protocol.RequestNotice{}, false, fmt.Errorf("%w: target agent is not accepting requests", ErrConflict)
	}
	requester, err := s.readAgent(ctx, principal.OrganizationID, principal.AgentID)
	if err != nil {
		return protocol.MutationResponse{}, protocol.RequestNotice{}, false, fmt.Errorf("caller must publish a heartbeat before sending: %w", err)
	}

	now := s.now().UTC()
	expiresAt := now.Add(time.Duration(input.ExpiresInSeconds) * time.Second)
	requestID := randomID("req_")
	descriptors, artifacts, err := prepareArtifacts(input.Attachments, requestID, principal.AgentID, conv.TargetAgentID, "input")
	if err != nil {
		return protocol.MutationResponse{}, protocol.RequestNotice{}, false, err
	}
	promptDigest := sha256.Sum256([]byte(input.Prompt))
	request := protocol.Request{
		APIVersion:           protocol.APIVersion,
		RequestID:            requestID,
		ConversationID:       conv.ID,
		RequesterAgentID:     principal.AgentID,
		RequesterMemberID:    principal.MemberID,
		RequesterDisplayName: requester.DisplayName,
		TargetAgentID:        conv.TargetAgentID,
		Title:                strings.TrimSpace(input.Title),
		PromptPreview:        preview(input.Prompt, 240),
		PromptBytes:          int64(len([]byte(input.Prompt))),
		PromptSHA256:         hex.EncodeToString(promptDigest[:]),
		RequestedAccess:      input.RequestedAccess,
		Attachments:          descriptors,
		Status:               protocol.StatusAwaitingApproval,
		CreatedAt:            now,
		UpdatedAt:            now,
		ExpiresAt:            expiresAt,
		Version:              1,
	}
	stored := storedRequest{Request: request, Prompt: input.Prompt, IdempotencyRedisKey: idempotencyRedisKey}
	storedJSON, _ := json.Marshal(stored)
	convJSON, _ := json.Marshal(conv)
	identifier := idempotencyRecord{RequestID: requestID, Digest: digest}
	idempotencyJSON, _ := json.Marshal(identifier)

	for attempts := 0; attempts < 5; attempts++ {
		err = s.rdb.Watch(ctx, func(tx *redis.Tx) error {
			existingRaw, getErr := tx.Get(ctx, idempotencyRedisKey).Bytes()
			if getErr == nil {
				var existing idempotencyRecord
				if json.Unmarshal(existingRaw, &existing) != nil || existing.Digest != digest {
					return fmt.Errorf("%w: idempotency key was already used for different content", ErrConflict)
				}
				previous, readErr := s.readStoredRequestWith(ctx, tx, principal.OrganizationID, existing.RequestID)
				if readErr != nil {
					return readErr
				}
				request = previous.Request
				return errExistingRequest
			}
			if !errors.Is(getErr, redis.Nil) {
				return getErr
			}
			_, txErr := tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.Set(ctx, requestKey(principal.OrganizationID, requestID), storedJSON, requestRetention)
				pipe.Set(ctx, idempotencyRedisKey, idempotencyJSON, requestRetention)
				pipe.SAdd(ctx, inboxKey(principal.OrganizationID, conv.TargetAgentID), requestID)
				pipe.Expire(ctx, inboxKey(principal.OrganizationID, conv.TargetAgentID), requestRetention)
				if newConversation {
					pipe.Set(ctx, conversationKey(principal.OrganizationID, conv.ID), convJSON, conversationTTL)
				}
				for _, artifact := range artifacts {
					payload, _ := json.Marshal(artifact)
					pipe.Set(ctx, artifactKey(principal.OrganizationID, artifact.Descriptor.ArtifactID), payload, requestRetention)
				}
				return nil
			})
			return txErr
		}, idempotencyRedisKey)
		if errors.Is(err, errExistingRequest) {
			return mutation(request), notice(request), false, nil
		}
		if errors.Is(err, redis.TxFailedErr) {
			continue
		}
		if err != nil {
			return protocol.MutationResponse{}, protocol.RequestNotice{}, false, err
		}
		return mutation(request), notice(request), true, nil
	}
	return protocol.MutationResponse{}, protocol.RequestNotice{}, false, fmt.Errorf("create request after concurrent updates: %w", redis.TxFailedErr)
}

var errExistingRequest = errors.New("existing idempotent request")

func (s *RedisStore) GetRequest(ctx context.Context, principal auth.Principal, requestID string) (protocol.Request, error) {
	if err := requireDevice(principal); err != nil {
		return protocol.Request{}, err
	}
	stored, err := s.readStoredRequest(ctx, principal.OrganizationID, requestID)
	if err != nil {
		return protocol.Request{}, err
	}
	if principal.AgentID != stored.Request.RequesterAgentID && principal.AgentID != stored.Request.TargetAgentID {
		return protocol.Request{}, ErrForbidden
	}
	request := stored.Request
	request.Prompt = ""
	return request, nil
}

func (s *RedisStore) Inbox(ctx context.Context, principal auth.Principal) ([]protocol.RequestNotice, error) {
	if err := requireDevice(principal); err != nil {
		return nil, err
	}
	revoked, err := s.rdb.SIsMember(ctx, revokedAgentsKey(principal.OrganizationID), principal.AgentID).Result()
	if err != nil {
		return nil, err
	}
	if revoked {
		return nil, ErrForbidden
	}
	ids, err := s.rdb.SMembers(ctx, inboxKey(principal.OrganizationID, principal.AgentID)).Result()
	if err != nil {
		return nil, err
	}
	result := make([]protocol.RequestNotice, 0, len(ids))
	for _, id := range ids {
		stored, err := s.readStoredRequest(ctx, principal.OrganizationID, id)
		if errors.Is(err, ErrNotFound) {
			_ = s.rdb.SRem(ctx, inboxKey(principal.OrganizationID, principal.AgentID), id).Err()
			continue
		}
		if err != nil {
			return nil, err
		}
		if stored.Request.Status.Terminal() {
			_ = s.rdb.SRem(ctx, inboxKey(principal.OrganizationID, principal.AgentID), id).Err()
			continue
		}
		if stored.Request.Status == protocol.StatusAwaitingApproval && !s.now().UTC().Before(stored.Request.ExpiresAt) {
			expired, expireErr := s.expireAwaiting(ctx, principal, id)
			if expireErr != nil {
				return nil, expireErr
			}
			if expired {
				_ = s.rdb.SRem(ctx, inboxKey(principal.OrganizationID, principal.AgentID), id).Err()
				continue
			}
			// Approval or another lifecycle transition won the race after the
			// initial inbox read. Re-read the authoritative state rather than
			// returning the stale awaiting-approval notice.
			stored, err = s.readStoredRequest(ctx, principal.OrganizationID, id)
			if errors.Is(err, ErrNotFound) {
				_ = s.rdb.SRem(ctx, inboxKey(principal.OrganizationID, principal.AgentID), id).Err()
				continue
			}
			if err != nil {
				return nil, err
			}
			if stored.Request.Status.Terminal() {
				_ = s.rdb.SRem(ctx, inboxKey(principal.OrganizationID, principal.AgentID), id).Err()
				continue
			}
		}
		result = append(result, notice(stored.Request))
	}
	sort.Slice(result, func(i, j int) bool { return result[i].CreatedAt.Before(result[j].CreatedAt) })
	return result, nil
}

var errNotAwaitingExpiry = errors.New("request is not awaiting expiry")

// expireAwaiting rechecks both lifecycle state and deadline inside the Redis
// WATCH transaction. An Allow Once decision that wins after Inbox's initial
// read therefore cannot be overwritten by a stale expiry transition.
func (s *RedisStore) expireAwaiting(ctx context.Context, principal auth.Principal, requestID string) (bool, error) {
	expired := false
	_, err := s.transition(ctx, principal, requestID, func(request *protocol.Request) error {
		expired = false
		if request.TargetAgentID != principal.AgentID {
			return ErrForbidden
		}
		if request.Status != protocol.StatusAwaitingApproval || s.now().UTC().Before(request.ExpiresAt) {
			return errNotAwaitingExpiry
		}
		request.Status = protocol.StatusExpired
		expired = true
		return nil
	})
	if errors.Is(err, errNotAwaitingExpiry) {
		return false, nil
	}
	return expired, err
}

func (s *RedisStore) Decide(ctx context.Context, principal auth.Principal, requestID string, input protocol.DecisionPayload) (protocol.MutationResponse, error) {
	if input.Decision != protocol.DecisionAllowOnce && input.Decision != protocol.DecisionDeny {
		return protocol.MutationResponse{}, fmt.Errorf("%w: invalid decision", ErrInvalid)
	}
	if !validDecisionID(input.DecisionID) {
		return protocol.MutationResponse{}, fmt.Errorf("%w: invalid decision identity", ErrInvalid)
	}
	revocationsKey := revokedAgentsKey(principal.OrganizationID)
	return s.transitionStoredWatching(ctx, principal, requestID, []string{revocationsKey}, func(tx *redis.Tx, stored *storedRequest) error {
		request := &stored.Request
		if request.TargetAgentID != principal.AgentID {
			return ErrForbidden
		}
		if stored.DecisionID != "" {
			if !opaqueIDMatches(stored.DecisionID, input.DecisionID) || stored.Decision != input.Decision {
				return fmt.Errorf("%w: request already has a different recipient decision", ErrConflict)
			}
			// An exact replay returns the current request state. This remains
			// idempotent even when claiming or result submission advanced the
			// request after the original decision response was lost.
			return nil
		}
		if request.Status != protocol.StatusAwaitingApproval {
			return ErrConflict
		}
		if !s.now().UTC().Before(request.ExpiresAt) {
			stored.DecisionID = input.DecisionID
			stored.Decision = input.Decision
			request.Status = protocol.StatusExpired
			return nil
		}
		if input.Decision == protocol.DecisionAllowOnce {
			revoked, err := tx.SIsMember(ctx, revocationsKey, request.RequesterAgentID).Result()
			if err != nil {
				return err
			}
			if revoked {
				// A queued request cannot execute after its requester is revoked.
				// Commit a terminal state under the recipient's exact decision ID
				// so lost-response retries cleanly converge instead of leaving an
				// automatically approved request in an endless 403 retry loop.
				stored.DecisionID = input.DecisionID
				stored.Decision = input.Decision
				request.Status = protocol.StatusCancelled
				return nil
			}
		}
		stored.DecisionID = input.DecisionID
		stored.Decision = input.Decision
		if input.Decision == protocol.DecisionDeny {
			request.Status = protocol.StatusRejected
		} else {
			request.Status = protocol.StatusAccepted
		}
		return nil
	})
}

func (s *RedisStore) FetchExecution(ctx context.Context, principal auth.Principal, requestID string) (protocol.ExecutionPayload, error) {
	if err := requireDevice(principal); err != nil {
		return protocol.ExecutionPayload{}, err
	}
	stored, err := s.readStoredRequest(ctx, principal.OrganizationID, requestID)
	if err != nil {
		return protocol.ExecutionPayload{}, err
	}
	if stored.Request.TargetAgentID != principal.AgentID {
		return protocol.ExecutionPayload{}, ErrForbidden
	}
	if stored.Request.Status != protocol.StatusAccepted && stored.Request.Status != protocol.StatusRunning {
		return protocol.ExecutionPayload{}, ErrConflict
	}
	return protocol.ExecutionPayload{
		RequestID:            stored.Request.RequestID,
		ConversationID:       stored.Request.ConversationID,
		RequesterAgentID:     stored.Request.RequesterAgentID,
		RequesterMemberID:    stored.Request.RequesterMemberID,
		RequesterDisplayName: stored.Request.RequesterDisplayName,
		Title:                stored.Request.Title,
		Prompt:               stored.Prompt,
		RequestedAccess:      stored.Request.RequestedAccess,
		Attachments:          stored.Request.Attachments,
		ExpiresAt:            stored.Request.ExpiresAt,
	}, nil
}

func (s *RedisStore) InspectProposal(ctx context.Context, principal auth.Principal, requestID string) (protocol.ProposalPayload, error) {
	if err := requireDevice(principal); err != nil {
		return protocol.ProposalPayload{}, err
	}
	stored, err := s.readStoredRequest(ctx, principal.OrganizationID, requestID)
	if err != nil {
		return protocol.ProposalPayload{}, err
	}
	if stored.Request.TargetAgentID != principal.AgentID {
		return protocol.ProposalPayload{}, ErrForbidden
	}
	if stored.Request.Status != protocol.StatusAwaitingApproval || !s.now().UTC().Before(stored.Request.ExpiresAt) {
		return protocol.ProposalPayload{}, ErrConflict
	}
	return protocol.ProposalPayload{
		RequestID: stored.Request.RequestID, ConversationID: stored.Request.ConversationID,
		RequesterAgentID: stored.Request.RequesterAgentID, RequesterMemberID: stored.Request.RequesterMemberID,
		RequesterDisplayName: stored.Request.RequesterDisplayName,
		Title:                stored.Request.Title, Prompt: stored.Prompt, RequestedAccess: stored.Request.RequestedAccess,
		Attachments: stored.Request.Attachments, ExpiresAt: stored.Request.ExpiresAt,
	}, nil
}

// MarkRunning atomically claims an accepted request before a local runtime is
// spawned. A second claim is rejected so two daemons using the same device
// credential cannot execute one Allow Once decision twice.
func (s *RedisStore) MarkRunning(ctx context.Context, principal auth.Principal, requestID, executionClaimID string) (protocol.MutationResponse, error) {
	if !validExecutionClaimID(executionClaimID) {
		return protocol.MutationResponse{}, fmt.Errorf("%w: invalid execution claim", ErrInvalid)
	}
	return s.transitionStored(ctx, principal, requestID, func(stored *storedRequest) error {
		if stored.Request.TargetAgentID != principal.AgentID {
			return ErrForbidden
		}
		switch stored.Request.Status {
		case protocol.StatusAccepted:
			stored.ExecutionClaimID = executionClaimID
			stored.Request.Status = protocol.StatusRunning
			return nil
		case protocol.StatusRunning:
			if executionClaimMatches(stored.ExecutionClaimID, executionClaimID) {
				return nil
			}
			return ErrConflict
		default:
			return ErrConflict
		}
	})
}

func (s *RedisStore) SubmitResult(ctx context.Context, principal auth.Principal, requestID string, result protocol.ResultPayload) (protocol.MutationResponse, error) {
	if err := requireDevice(principal); err != nil {
		return protocol.MutationResponse{}, err
	}
	if result.State != protocol.StatusCompleted && result.State != protocol.StatusFailed && result.State != protocol.StatusCancelled {
		return protocol.MutationResponse{}, fmt.Errorf("%w: invalid terminal result state", ErrInvalid)
	}
	if !validExecutionClaimID(result.ExecutionClaimID) {
		return protocol.MutationResponse{}, fmt.Errorf("%w: invalid execution claim", ErrInvalid)
	}
	if len([]byte(result.Answer)) > maximumAnswerBytes || len([]byte(result.Error)) > maximumErrorBytes || len(result.ResultFiles) > protocol.MaxAttachments {
		return protocol.MutationResponse{}, ErrInvalid
	}
	switch result.State {
	case protocol.StatusCompleted:
		if result.Error != "" {
			return protocol.MutationResponse{}, fmt.Errorf("%w: completed results cannot include an error", ErrInvalid)
		}
	case protocol.StatusFailed, protocol.StatusCancelled:
		if result.Answer != "" || len(result.ResultFiles) > 0 {
			return protocol.MutationResponse{}, fmt.Errorf("%w: failed or cancelled results cannot include an answer or files", ErrInvalid)
		}
	}
	resultDigest, err := digestResult(result)
	if err != nil {
		return protocol.MutationResponse{}, err
	}
	current, err := s.readStoredRequest(ctx, principal.OrganizationID, requestID)
	if err != nil {
		return protocol.MutationResponse{}, err
	}
	if current.Request.TargetAgentID != principal.AgentID {
		return protocol.MutationResponse{}, ErrForbidden
	}
	if current.Request.Status.Terminal() {
		if exactResultReplay(current, result, resultDigest) {
			return mutation(current.Request), nil
		}
		return protocol.MutationResponse{}, ErrConflict
	}
	// Validate the durable lifecycle state before allocating result artifacts.
	// The transition below repeats this check atomically to cover races.
	if current.Request.Status != protocol.StatusRunning || !executionClaimMatches(current.ExecutionClaimID, result.ExecutionClaimID) {
		return protocol.MutationResponse{}, ErrConflict
	}
	descriptors, artifacts, err := prepareArtifacts(result.ResultFiles, requestID, current.Request.RequesterAgentID, current.Request.TargetAgentID, "result")
	if err != nil {
		return protocol.MutationResponse{}, err
	}
	// Persist result artifacts before publishing their descriptors in terminal
	// request state. A failed state transition can leave only bounded TTL-backed
	// orphans; a successful transition can never reference missing bytes.
	for _, artifact := range artifacts {
		payload, _ := json.Marshal(artifact)
		if err := s.rdb.Set(ctx, artifactKey(principal.OrganizationID, artifact.Descriptor.ArtifactID), payload, requestRetention).Err(); err != nil {
			return protocol.MutationResponse{}, err
		}
	}
	response, err := s.transitionStored(ctx, principal, requestID, func(stored *storedRequest) error {
		if stored.Request.TargetAgentID != principal.AgentID {
			return ErrForbidden
		}
		if stored.Request.Status.Terminal() {
			if exactResultReplay(*stored, result, resultDigest) {
				return nil
			}
			return ErrConflict
		}
		if stored.Request.Status != protocol.StatusRunning || !executionClaimMatches(stored.ExecutionClaimID, result.ExecutionClaimID) {
			return ErrConflict
		}
		stored.Request.Status = result.State
		stored.Request.Answer = result.Answer
		stored.Request.Error = result.Error
		stored.Request.ResultFiles = descriptors
		stored.ResultDigest = resultDigest
		return nil
	})
	if err != nil {
		return protocol.MutationResponse{}, err
	}
	_ = s.rdb.SRem(ctx, inboxKey(principal.OrganizationID, principal.AgentID), requestID).Err()
	return response, nil
}

func (s *RedisStore) Cancel(ctx context.Context, principal auth.Principal, requestID string) (protocol.MutationResponse, bool, error) {
	changed := false
	response, err := s.transition(ctx, principal, requestID, func(request *protocol.Request) error {
		changed = false
		if request.RequesterAgentID != principal.AgentID {
			return ErrForbidden
		}
		if request.Status == protocol.StatusCancelled {
			return nil
		}
		if request.Status.Terminal() {
			return ErrConflict
		}
		request.Status = protocol.StatusCancelled
		changed = true
		return nil
	})
	return response, changed, err
}

func (s *RedisStore) FetchArtifact(ctx context.Context, principal auth.Principal, artifactID string) (protocol.ArtifactContent, error) {
	if err := requireDevice(principal); err != nil {
		return protocol.ArtifactContent{}, err
	}
	raw, err := s.rdb.Get(ctx, artifactKey(principal.OrganizationID, strings.TrimSpace(artifactID))).Bytes()
	if errors.Is(err, redis.Nil) {
		return protocol.ArtifactContent{}, ErrNotFound
	}
	if err != nil {
		return protocol.ArtifactContent{}, err
	}
	var artifact storedArtifact
	if json.Unmarshal(raw, &artifact) != nil {
		return protocol.ArtifactContent{}, ErrNotFound
	}
	request, err := s.readStoredRequest(ctx, principal.OrganizationID, artifact.RequestID)
	if err != nil {
		return protocol.ArtifactContent{}, err
	}
	switch artifact.Direction {
	case "input":
		if principal.AgentID != artifact.TargetAgentID || request.Request.TargetAgentID != principal.AgentID {
			return protocol.ArtifactContent{}, ErrForbidden
		}
		// Input bytes are disclosed only for the one approved execution window.
		// Proposal inspection deliberately exposes descriptors, never content.
		if (request.Request.Status != protocol.StatusAccepted && request.Request.Status != protocol.StatusRunning) ||
			!containsArtifact(request.Request.Attachments, artifact.Descriptor.ArtifactID) {
			return protocol.ArtifactContent{}, ErrConflict
		}
	case "result":
		if principal.AgentID != artifact.RequesterAgentID || request.Request.RequesterAgentID != principal.AgentID {
			return protocol.ArtifactContent{}, ErrForbidden
		}
		if request.Request.Status != protocol.StatusCompleted || !containsArtifact(request.Request.ResultFiles, artifact.Descriptor.ArtifactID) {
			return protocol.ArtifactContent{}, ErrConflict
		}
	default:
		return protocol.ArtifactContent{}, ErrNotFound
	}
	return protocol.ArtifactContent{ArtifactDescriptor: artifact.Descriptor, Encoding: artifact.Encoding, ContentBase64: artifact.ContentBase64}, nil
}

func containsArtifact(descriptors []protocol.ArtifactDescriptor, artifactID string) bool {
	for _, descriptor := range descriptors {
		if descriptor.ArtifactID == artifactID {
			return true
		}
	}
	return false
}

func (s *RedisStore) transition(ctx context.Context, principal auth.Principal, requestID string, update func(*protocol.Request) error) (protocol.MutationResponse, error) {
	return s.transitionStored(ctx, principal, requestID, func(stored *storedRequest) error {
		return update(&stored.Request)
	})
}

func (s *RedisStore) transitionStored(ctx context.Context, principal auth.Principal, requestID string, update func(*storedRequest) error) (protocol.MutationResponse, error) {
	return s.transitionStoredWatching(ctx, principal, requestID, nil, func(_ *redis.Tx, stored *storedRequest) error {
		return update(stored)
	})
}

func (s *RedisStore) transitionStoredWatching(ctx context.Context, principal auth.Principal, requestID string, additionalWatchKeys []string, update func(*redis.Tx, *storedRequest) error) (protocol.MutationResponse, error) {
	if err := requireDevice(principal); err != nil {
		return protocol.MutationResponse{}, err
	}
	key := requestKey(principal.OrganizationID, strings.TrimSpace(requestID))
	watchKeys := make([]string, 1, 1+len(additionalWatchKeys))
	watchKeys[0] = key
	watchKeys = append(watchKeys, additionalWatchKeys...)
	var updated protocol.Request
	for attempt := 0; attempt < 5; attempt++ {
		err := s.rdb.Watch(ctx, func(tx *redis.Tx) error {
			stored, err := s.readStoredRequestWith(ctx, tx, principal.OrganizationID, requestID)
			if err != nil {
				return err
			}
			previous, marshalErr := json.Marshal(stored)
			if marshalErr != nil {
				return marshalErr
			}
			if err := update(tx, &stored); err != nil {
				return err
			}
			current, marshalErr := json.Marshal(stored)
			if marshalErr != nil {
				return marshalErr
			}
			if subtle.ConstantTimeCompare(previous, current) == 1 {
				updated = stored.Request
				return nil
			}
			stored.Request.Version++
			stored.Request.UpdatedAt = s.now().UTC()
			payload, _ := json.Marshal(stored)
			if _, err := tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.Set(ctx, key, payload, requestRetention)
				// A lifecycle change extends request retention. Keep the original
				// create-idempotency binding alive for exactly the same window so
				// an old ambiguous CreateRequest retry cannot create a second task.
				if stored.IdempotencyRedisKey != "" {
					pipe.Expire(ctx, stored.IdempotencyRedisKey, requestRetention)
				}
				return nil
			}); err != nil {
				return err
			}
			updated = stored.Request
			return nil
		}, watchKeys...)
		if errors.Is(err, redis.TxFailedErr) {
			continue
		}
		if err != nil {
			return protocol.MutationResponse{}, err
		}
		return mutation(updated), nil
	}
	return protocol.MutationResponse{}, fmt.Errorf("update request after concurrent changes: %w", redis.TxFailedErr)
}

func (s *RedisStore) readAgent(ctx context.Context, organizationID, agentID string) (protocol.AgentCard, error) {
	revoked, err := s.rdb.SIsMember(ctx, revokedAgentsKey(organizationID), agentID).Result()
	if err != nil {
		return protocol.AgentCard{}, err
	}
	if revoked {
		return protocol.AgentCard{}, ErrNotFound
	}
	raw, err := s.rdb.Get(ctx, agentKey(organizationID, agentID)).Bytes()
	if errors.Is(err, redis.Nil) {
		return protocol.AgentCard{}, ErrNotFound
	}
	if err != nil {
		return protocol.AgentCard{}, err
	}
	var card protocol.AgentCard
	if json.Unmarshal(raw, &card) != nil || card.AgentID != agentID {
		return protocol.AgentCard{}, ErrNotFound
	}
	return card, nil
}

func (s *RedisStore) readConversation(ctx context.Context, organizationID, conversationID string) (conversation, error) {
	raw, err := s.rdb.Get(ctx, conversationKey(organizationID, conversationID)).Bytes()
	if errors.Is(err, redis.Nil) {
		return conversation{}, ErrNotFound
	}
	if err != nil {
		return conversation{}, err
	}
	var value conversation
	if json.Unmarshal(raw, &value) != nil || value.OrganizationID != organizationID || value.ID != conversationID {
		return conversation{}, ErrNotFound
	}
	return value, nil
}

type redisGetter interface {
	Get(context.Context, string) *redis.StringCmd
}

func (s *RedisStore) readStoredRequest(ctx context.Context, organizationID, requestID string) (storedRequest, error) {
	return s.readStoredRequestWith(ctx, s.rdb, organizationID, requestID)
}

func (s *RedisStore) readStoredRequestWith(ctx context.Context, getter redisGetter, organizationID, requestID string) (storedRequest, error) {
	raw, err := getter.Get(ctx, requestKey(organizationID, strings.TrimSpace(requestID))).Bytes()
	if errors.Is(err, redis.Nil) {
		return storedRequest{}, ErrNotFound
	}
	if err != nil {
		return storedRequest{}, err
	}
	var stored storedRequest
	if json.Unmarshal(raw, &stored) != nil || stored.Request.RequestID != strings.TrimSpace(requestID) {
		return storedRequest{}, ErrNotFound
	}
	return stored, nil
}

func validateHeartbeat(value protocol.AgentHeartbeat) error {
	if !validLabel(value.DisplayName, 100) || !validLabel(value.Runtime.ID, 128) || !validLabel(value.Runtime.DisplayName, 100) {
		return ErrInvalid
	}
	if value.Availability != protocol.AvailabilityAvailable && value.Availability != protocol.AvailabilityBusy && value.Availability != protocol.AvailabilityAway {
		return ErrInvalid
	}
	if !value.PermissionMode.Valid() {
		return ErrInvalid
	}
	if len(value.Capabilities) > 20 || len(value.WorkspaceAliases) > 20 {
		return ErrInvalid
	}
	return nil
}

func validateCreate(input protocol.CreateRequest) error {
	if strings.TrimSpace(input.ConversationID) == "" && strings.TrimSpace(input.TargetAgentID) == "" {
		return fmt.Errorf("%w: target_agent_id is required for a new conversation", ErrInvalid)
	}
	if !validLabel(input.Title, protocol.MaxTitleBytes) || strings.TrimSpace(input.Prompt) == "" || len([]byte(input.Prompt)) > protocol.MaxPromptBytes {
		return ErrInvalid
	}
	if !validIdentifier(input.IdempotencyKey, 128) || input.ExpiresInSeconds < 60 || input.ExpiresInSeconds > 86400 {
		return ErrInvalid
	}
	if input.TargetAgentID != "" && !validIdentifier(input.TargetAgentID, 100) {
		return ErrInvalid
	}
	if input.ConversationID != "" && !validIdentifier(input.ConversationID, 100) {
		return ErrInvalid
	}
	if len(input.RequestedAccess) > 10 || len(input.Attachments) > protocol.MaxAttachments {
		return ErrInvalid
	}
	seenAccess := make(map[string]struct{}, len(input.RequestedAccess))
	for _, access := range input.RequestedAccess {
		if !validLabel(access.WorkspaceAlias, 100) || (access.Mode != protocol.PermissionReadOnly && access.Mode != protocol.PermissionGuardedWrite) {
			return ErrInvalid
		}
		key := strings.ToLower(strings.TrimSpace(access.WorkspaceAlias))
		if _, exists := seenAccess[key]; exists {
			return ErrInvalid
		}
		seenAccess[key] = struct{}{}
	}
	return nil
}

func prepareArtifacts(inputs []protocol.AttachmentInput, requestID, requesterAgentID, targetAgentID, direction string) ([]protocol.ArtifactDescriptor, []storedArtifact, error) {
	descriptors := make([]protocol.ArtifactDescriptor, 0, len(inputs))
	artifacts := make([]storedArtifact, 0, len(inputs))
	seen := map[string]struct{}{}
	var total int64
	for _, input := range inputs {
		if !validArtifactName(input.Name) || !validMIMEType(input.MIMEType) || input.Encoding != "base64" || input.SizeBytes < 0 || input.SizeBytes > protocol.MaxAttachmentBytes {
			return nil, nil, ErrInvalid
		}
		key := strings.ToLower(input.Name)
		if _, exists := seen[key]; exists {
			return nil, nil, ErrInvalid
		}
		seen[key] = struct{}{}
		decoded, err := base64.StdEncoding.DecodeString(input.ContentBase64)
		if err != nil || int64(len(decoded)) != input.SizeBytes {
			return nil, nil, ErrInvalid
		}
		total += input.SizeBytes
		if total > protocol.MaxRequestPayloadBytes {
			return nil, nil, ErrInvalid
		}
		digest := sha256.Sum256(decoded)
		computed := hex.EncodeToString(digest[:])
		if !strings.EqualFold(computed, input.SHA256) {
			return nil, nil, ErrInvalid
		}
		descriptor := protocol.ArtifactDescriptor{
			ArtifactID: randomID("art_"), Name: input.Name, MIMEType: input.MIMEType,
			SizeBytes: input.SizeBytes, SHA256: computed,
		}
		descriptors = append(descriptors, descriptor)
		artifacts = append(artifacts, storedArtifact{
			Descriptor: descriptor, Encoding: "base64", ContentBase64: input.ContentBase64,
			RequestID: requestID, RequesterAgentID: requesterAgentID, TargetAgentID: targetAgentID, Direction: direction,
		})
	}
	return descriptors, artifacts, nil
}

func matchesAgent(card protocol.AgentCard, query AgentQuery) bool {
	if query.OnlineOnly && !card.Online {
		return false
	}
	if !containsAllFold(card.Capabilities, query.Capabilities) || !containsAllFold(card.WorkspaceAliases, query.WorkspaceAliases) {
		return false
	}
	need := strings.ToLower(strings.TrimSpace(query.Need))
	if need == "" {
		return true
	}
	haystack := []string{card.DisplayName, card.DeviceName, card.Runtime.ID, card.Runtime.DisplayName}
	haystack = append(haystack, card.Capabilities...)
	haystack = append(haystack, card.WorkspaceAliases...)
	for _, value := range haystack {
		if strings.Contains(strings.ToLower(value), need) {
			return true
		}
	}
	return false
}

func containsAllFold(values, wanted []string) bool {
	for _, candidate := range wanted {
		found := false
		for _, value := range values {
			if strings.EqualFold(strings.TrimSpace(value), strings.TrimSpace(candidate)) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func cleanUnique(values []string, limit int) []string {
	result := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		key := strings.ToLower(value)
		if value == "" || len(value) > 100 {
			continue
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, value)
		if len(result) == limit {
			break
		}
	}
	return result
}

func requireDevice(principal auth.Principal) error {
	if principal.TokenKind != auth.TokenDevice || principal.OrganizationID == "" || principal.MemberID == "" || principal.AgentID == "" {
		return ErrUnauthorized
	}
	return nil
}

func requestDigest(input protocol.CreateRequest) (string, error) {
	payload, err := json.Marshal(input)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]), nil
}

func mutation(request protocol.Request) protocol.MutationResponse {
	return protocol.MutationResponse{RequestID: request.RequestID, ConversationID: request.ConversationID, Status: request.Status}
}

func notice(request protocol.Request) protocol.RequestNotice {
	return protocol.RequestNotice{
		RequestID: request.RequestID, ConversationID: request.ConversationID,
		Status:           request.Status,
		RequesterAgentID: request.RequesterAgentID, RequesterMemberID: request.RequesterMemberID,
		RequesterDisplayName: request.RequesterDisplayName,
		Title:                request.Title, PromptPreview: request.PromptPreview, PromptBytes: request.PromptBytes,
		PromptSHA256: request.PromptSHA256, RequestedAccess: request.RequestedAccess,
		Attachments: request.Attachments, CreatedAt: request.CreatedAt, ExpiresAt: request.ExpiresAt,
	}
}

func preview(value string, runes int) string {
	if utf8.RuneCountInString(value) <= runes {
		return value
	}
	characters := []rune(value)
	return string(characters[:runes])
}

func validLabel(value string, max int) bool {
	value = strings.TrimSpace(value)
	if value == "" || len([]byte(value)) > max {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validArtifactName(value string) bool {
	if protocol.ValidatePortableFilename(value) != nil || !validLabel(value, 255) {
		return false
	}
	lower := strings.ToLower(value)
	switch lower {
	case ".env", ".netrc", ".npmrc", ".pypirc", ".gitconfig", ".git-credentials",
		"credentials", "credentials.json", "id_rsa", "id_ed25519", "known_hosts", "authorized_keys":
		return false
	}
	if strings.HasPrefix(lower, ".env.") {
		return false
	}
	for _, suffix := range []string{".pem", ".key", ".p12", ".pfx", ".kdbx"} {
		if strings.HasSuffix(lower, suffix) {
			return false
		}
	}
	return true
}

func validMIMEType(value string) bool {
	if value != strings.TrimSpace(value) || len(value) > 255 || !validLabel(value, 255) {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(value)
	return err == nil && mediaType != ""
}

func validIdentifier(value string, max int) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > max {
		return false
	}
	for _, r := range value {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}

func validExecutionClaimID(value string) bool {
	return validOpaqueID(value, "claim_")
}

func validDecisionID(value string) bool {
	return validOpaqueID(value, "decision_")
}

func validOpaqueID(value, prefixValue string) bool {
	if len(value) != len(prefixValue)+64 || !strings.HasPrefix(value, prefixValue) {
		return false
	}
	_, err := hex.DecodeString(value[len(prefixValue):])
	return err == nil
}

func executionClaimMatches(stored, presented string) bool {
	return opaqueIDMatches(stored, presented)
}

func opaqueIDMatches(stored, presented string) bool {
	if len(stored) != len(presented) || stored == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(stored), []byte(presented)) == 1
}

func digestResult(result protocol.ResultPayload) (string, error) {
	payload, err := json.Marshal(result)
	if err != nil {
		return "", fmt.Errorf("encode result retry identity: %w", err)
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]), nil
}

func exactResultReplay(stored storedRequest, result protocol.ResultPayload, digest string) bool {
	return stored.Request.Status == result.State &&
		executionClaimMatches(stored.ExecutionClaimID, result.ExecutionClaimID) &&
		opaqueIDMatches(stored.ResultDigest, digest)
}

func randomID(prefixValue string) string {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return prefixValue + hex.EncodeToString(value)
}

func escaped(value string) string {
	return hex.EncodeToString([]byte(value))
}

func agentKey(org, agent string) string  { return prefix + escaped(org) + ":agent:" + escaped(agent) }
func agentsKey(org string) string        { return prefix + escaped(org) + ":agents" }
func revokedAgentsKey(org string) string { return keyspace.CollaborationRevokedAgents(org) }
func requestKey(org, request string) string {
	return prefix + escaped(org) + ":request:" + escaped(request)
}
func inboxKey(org, agent string) string { return prefix + escaped(org) + ":inbox:" + escaped(agent) }
func conversationKey(org, conv string) string {
	return prefix + escaped(org) + ":conversation:" + escaped(conv)
}
func artifactKey(org, artifact string) string {
	return prefix + escaped(org) + ":artifact:" + escaped(artifact)
}
func idempotencyKey(org, agent, key string) string {
	digest := sha256.Sum256([]byte(key))
	return prefix + escaped(org) + ":idempotency:" + escaped(agent) + ":" + hex.EncodeToString(digest[:])
}
