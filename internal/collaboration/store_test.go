package collaboration

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/mohitbadwal/team-relay/internal/auth"
	"github.com/mohitbadwal/team-relay/internal/protocol"
	"github.com/redis/go-redis/v9"
)

const (
	testExecutionClaimA = "claim_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testExecutionClaimB = "claim_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testDecisionAllow   = "decision_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testDecisionDeny    = "decision_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func decisionPayload(decision protocol.Decision) protocol.DecisionPayload {
	id := testDecisionAllow
	if decision == protocol.DecisionDeny {
		id = testDecisionDeny
	}
	return protocol.DecisionPayload{Decision: decision, DecisionID: id}
}

func TestRequestRequiresDifferentLiveTargetAndApproval(t *testing.T) {
	t.Parallel()

	mini := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	store := NewRedisStore(rdb)
	fixed := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return fixed }
	requester := devicePrincipal("org_1", "mem_1", "dev_1", "agent_1", "Requester", "codex", protocol.PermissionReadOnly)
	target := devicePrincipal("org_1", "mem_2", "dev_2", "agent_2", "Target", "claude-code", protocol.PermissionReadOnly)
	heartbeat := func(display, runtimeID string) protocol.AgentHeartbeat {
		return protocol.AgentHeartbeat{
			DisplayName: display, Availability: protocol.AvailabilityAvailable, AcceptingRequests: true,
			Runtime:        protocol.RuntimeDescriptor{ID: runtimeID, DisplayName: runtimeID},
			PermissionMode: protocol.PermissionReadOnly,
		}
	}
	if _, err := store.Heartbeat(context.Background(), requester, heartbeat("Requester", "codex")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Heartbeat(context.Background(), target, heartbeat("Target", "claude-code")); err != nil {
		t.Fatal(err)
	}

	input := protocol.CreateRequest{
		TargetAgentID: "agent_2", Title: "Review", Prompt: "Inspect the parser",
		ExpiresInSeconds: 600, IdempotencyKey: "idem_1",
		RequestedAccess: []protocol.RequestedAccess{{WorkspaceAlias: "repo", Mode: protocol.PermissionReadOnly}},
	}
	created, createdNotice, wasCreated, err := store.CreateRequest(context.Background(), requester, input)
	if err != nil {
		t.Fatal(err)
	}
	if !wasCreated {
		t.Fatal("first request was reported as an idempotent retry")
	}
	if created.Status != protocol.StatusAwaitingApproval || createdNotice.PromptPreview == "" {
		t.Fatalf("unexpected create response: %#v %#v", created, createdNotice)
	}
	if createdNotice.RequesterMemberID != requester.MemberID {
		t.Fatalf("notice requester member = %q, want authenticated member %q", createdNotice.RequesterMemberID, requester.MemberID)
	}
	status, err := store.GetRequest(context.Background(), target, created.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	if status.RequesterMemberID != requester.MemberID {
		t.Fatalf("request status requester member = %q, want authenticated member %q", status.RequesterMemberID, requester.MemberID)
	}
	if status.Prompt != "" {
		t.Fatal("status endpoint must not disclose the full prompt")
	}
	proposal, err := store.InspectProposal(context.Background(), target, created.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	if proposal.Prompt != input.Prompt || proposal.RequestID != created.RequestID ||
		proposal.RequesterMemberID != requester.MemberID || len(proposal.RequestedAccess) != 1 {
		t.Fatalf("unexpected inspectable proposal: %#v", proposal)
	}
	if _, err := store.InspectProposal(context.Background(), requester, created.RequestID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("requester inspected target-only proposal: %v", err)
	}
	if _, err := store.FetchExecution(context.Background(), target, created.RequestID); err == nil {
		t.Fatal("execution payload must be unavailable before approval")
	}
	if _, err := store.Decide(context.Background(), target, created.RequestID, decisionPayload(protocol.DecisionAllowOnce)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.InspectProposal(context.Background(), target, created.RequestID); !errors.Is(err, ErrConflict) {
		t.Fatalf("proposal remained inspectable after approval: %v", err)
	}
	execution, err := store.FetchExecution(context.Background(), target, created.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	if execution.Prompt != input.Prompt || execution.RequesterMemberID != requester.MemberID {
		t.Fatalf("unexpected execution payload: %#v", execution)
	}
	if _, err := store.MarkRunning(context.Background(), target, created.RequestID, ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing execution claim error = %v, want %v", err, ErrInvalid)
	}
	if _, err := store.MarkRunning(context.Background(), target, created.RequestID, testExecutionClaimA); err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkRunning(context.Background(), target, created.RequestID, testExecutionClaimA); err != nil {
		t.Fatalf("idempotent execution claim retry failed: %v", err)
	}
	if _, err := store.MarkRunning(context.Background(), target, created.RequestID, testExecutionClaimB); !errors.Is(err, ErrConflict) {
		t.Fatalf("competing execution claim error = %v, want %v", err, ErrConflict)
	}
	if _, err := store.SubmitResult(context.Background(), target, created.RequestID, protocol.ResultPayload{State: protocol.StatusCompleted, Answer: "Missing owner"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing result claim error = %v, want %v", err, ErrInvalid)
	}
	if _, err := store.SubmitResult(context.Background(), target, created.RequestID, protocol.ResultPayload{ExecutionClaimID: testExecutionClaimB, State: protocol.StatusCompleted, Answer: "Wrong owner"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("competing result claim error = %v, want %v", err, ErrConflict)
	}
	if _, err := store.SubmitResult(context.Background(), target, created.RequestID, protocol.ResultPayload{ExecutionClaimID: testExecutionClaimA, State: protocol.StatusCompleted, Answer: "Looks good"}); err != nil {
		t.Fatal(err)
	}
	completed, err := store.GetRequest(context.Background(), requester, created.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	if completed.Status != protocol.StatusCompleted || completed.Answer != "Looks good" {
		t.Fatalf("unexpected terminal request: %#v", completed)
	}
	retried, retryNotice, retryCreated, err := store.CreateRequest(context.Background(), requester, input)
	if err != nil {
		t.Fatal(err)
	}
	if retryCreated || retried.RequestID != created.RequestID || retried.Status != protocol.StatusCompleted ||
		retryNotice.Status != protocol.StatusCompleted || retryNotice.RequesterMemberID != requester.MemberID {
		t.Fatalf("terminal idempotent retry was not returned as existing: %#v %#v created=%t", retried, retryNotice, retryCreated)
	}
}

func TestConcurrentExecutionClaimsHaveOneOwner(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, requester, target, _ := artifactTestStore(t)
	created, _, _, err := store.CreateRequest(ctx, requester, protocol.CreateRequest{
		TargetAgentID: target.AgentID, Title: "Race", Prompt: "Execute once",
		ExpiresInSeconds: 600, IdempotencyKey: "concurrent_claim",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Decide(ctx, target, created.RequestID, decisionPayload(protocol.DecisionAllowOnce)); err != nil {
		t.Fatal(err)
	}

	type outcome struct {
		claimID string
		err     error
	}
	start := make(chan struct{})
	outcomes := make(chan outcome, 2)
	var wg sync.WaitGroup
	for _, claimID := range []string{testExecutionClaimA, testExecutionClaimB} {
		wg.Add(1)
		go func(claimID string) {
			defer wg.Done()
			<-start
			_, err := store.MarkRunning(ctx, target, created.RequestID, claimID)
			outcomes <- outcome{claimID: claimID, err: err}
		}(claimID)
	}
	close(start)
	wg.Wait()
	close(outcomes)

	var winner string
	conflicts := 0
	for result := range outcomes {
		switch {
		case result.err == nil:
			if winner != "" {
				t.Fatalf("multiple execution claims succeeded: %q and %q", winner, result.claimID)
			}
			winner = result.claimID
		case errors.Is(result.err, ErrConflict):
			conflicts++
		default:
			t.Fatalf("unexpected claim error for %q: %v", result.claimID, result.err)
		}
	}
	if winner == "" || conflicts != 1 {
		t.Fatalf("claim outcomes: winner=%q conflicts=%d", winner, conflicts)
	}
	if _, err := store.MarkRunning(ctx, target, created.RequestID, winner); err != nil {
		t.Fatalf("winning claim was not idempotent: %v", err)
	}
}

func TestRequestTransitionExtendsCreateIdempotencyRetention(t *testing.T) {
	t.Parallel()

	mini := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	store := NewRedisStore(rdb)
	requester := devicePrincipal("org_idem_ttl", "mem_1", "dev_1", "agent_1", "Requester", "codex", protocol.PermissionReadOnly)
	target := devicePrincipal("org_idem_ttl", "mem_2", "dev_2", "agent_2", "Target", "claude-code", protocol.PermissionReadOnly)
	for _, peer := range []auth.Principal{requester, target} {
		if _, err := store.Heartbeat(context.Background(), peer, protocol.AgentHeartbeat{
			DisplayName: peer.DisplayName, Availability: protocol.AvailabilityAvailable, AcceptingRequests: true,
			Runtime: protocol.RuntimeDescriptor{ID: peer.Runtime, DisplayName: peer.Runtime}, PermissionMode: protocol.PermissionReadOnly,
		}); err != nil {
			t.Fatal(err)
		}
	}
	input := protocol.CreateRequest{
		TargetAgentID: target.AgentID, Title: "Durable retry", Prompt: "Run once",
		ExpiresInSeconds: 600, IdempotencyKey: "retain_create_identity",
	}
	created, _, wasCreated, err := store.CreateRequest(context.Background(), requester, input)
	if err != nil || !wasCreated {
		t.Fatalf("create request = %#v, created=%t, err=%v", created, wasCreated, err)
	}
	mini.FastForward(requestRetention - time.Hour)
	if _, changed, err := store.Cancel(context.Background(), requester, created.RequestID); err != nil || !changed {
		t.Fatalf("late request transition changed=%t err=%v", changed, err)
	}
	idemRedisKey := idempotencyKey(requester.OrganizationID, requester.AgentID, input.IdempotencyKey)
	if ttl := mini.TTL(idemRedisKey); ttl < requestRetention-time.Minute {
		t.Fatalf("idempotency TTL after request transition = %s, want approximately %s", ttl, requestRetention)
	}
	mini.FastForward(2 * time.Hour)
	retried, _, retryCreated, err := store.CreateRequest(context.Background(), requester, input)
	if err != nil {
		t.Fatal(err)
	}
	if retryCreated || retried.RequestID != created.RequestID || retried.Status != protocol.StatusCancelled {
		t.Fatalf("old exact retry created another request: %#v created=%t", retried, retryCreated)
	}
}

func TestDecisionAndResultMutationsAreExactReplaySafe(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, requester, target, _ := artifactTestStore(t)
	created, _, _, err := store.CreateRequest(ctx, requester, protocol.CreateRequest{
		TargetAgentID: target.AgentID, Title: "Retry safety", Prompt: "Execute exactly once",
		ExpiresInSeconds: 600, IdempotencyKey: "mutation_replay_safety",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Decide(ctx, target, created.RequestID, protocol.DecisionPayload{Decision: protocol.DecisionAllowOnce}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing decision identity error = %v, want %v", err, ErrInvalid)
	}
	allow := decisionPayload(protocol.DecisionAllowOnce)
	firstDecision, err := store.Decide(ctx, target, created.RequestID, allow)
	if err != nil || firstDecision.Status != protocol.StatusAccepted {
		t.Fatalf("first decision = %#v, %v", firstDecision, err)
	}
	afterDecision, err := store.GetRequest(ctx, target, created.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	replayedDecision, err := store.Decide(ctx, target, created.RequestID, allow)
	if err != nil || replayedDecision.Status != protocol.StatusAccepted {
		t.Fatalf("replayed decision = %#v, %v", replayedDecision, err)
	}
	afterReplay, err := store.GetRequest(ctx, target, created.RequestID)
	if err != nil || afterReplay.Version != afterDecision.Version {
		t.Fatalf("decision replay changed version from %d to %d: %v", afterDecision.Version, afterReplay.Version, err)
	}
	changedID := allow
	changedID.DecisionID = "decision_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	if _, err := store.Decide(ctx, target, created.RequestID, changedID); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed decision identity error = %v, want %v", err, ErrConflict)
	}
	changedPayload := allow
	changedPayload.Decision = protocol.DecisionDeny
	if _, err := store.Decide(ctx, target, created.RequestID, changedPayload); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed decision payload error = %v, want %v", err, ErrConflict)
	}
	if _, err := store.Decide(ctx, requester, created.RequestID, allow); !errors.Is(err, ErrForbidden) {
		t.Fatalf("non-target decision replay error = %v, want %v", err, ErrForbidden)
	}

	if _, err := store.MarkRunning(ctx, target, created.RequestID, testExecutionClaimA); err != nil {
		t.Fatal(err)
	}
	runningDecision, err := store.Decide(ctx, target, created.RequestID, allow)
	if err != nil || runningDecision.Status != protocol.StatusRunning {
		t.Fatalf("decision replay after claim = %#v, %v", runningDecision, err)
	}
	resultFile := attachmentInput("retry-report.md", []byte("same bytes"))
	result := protocol.ResultPayload{
		ExecutionClaimID: testExecutionClaimA, State: protocol.StatusCompleted,
		Answer: "stable answer", ResultFiles: []protocol.AttachmentInput{resultFile},
	}
	firstResult, err := store.SubmitResult(ctx, target, created.RequestID, result)
	if err != nil || firstResult.Status != protocol.StatusCompleted {
		t.Fatalf("first result = %#v, %v", firstResult, err)
	}
	completed, err := store.GetRequest(ctx, requester, created.RequestID)
	if err != nil || len(completed.ResultFiles) != 1 {
		t.Fatalf("completed request = %#v, %v", completed, err)
	}
	artifactID := completed.ResultFiles[0].ArtifactID
	replayedResult, err := store.SubmitResult(ctx, target, created.RequestID, result)
	if err != nil || replayedResult.Status != protocol.StatusCompleted {
		t.Fatalf("replayed result = %#v, %v", replayedResult, err)
	}
	afterResultReplay, err := store.GetRequest(ctx, requester, created.RequestID)
	if err != nil || afterResultReplay.Version != completed.Version || len(afterResultReplay.ResultFiles) != 1 || afterResultReplay.ResultFiles[0].ArtifactID != artifactID {
		t.Fatalf("result replay changed terminal request: before=%#v after=%#v err=%v", completed, afterResultReplay, err)
	}
	changedResult := result
	changedResult.Answer = "different answer"
	if _, err := store.SubmitResult(ctx, target, created.RequestID, changedResult); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed terminal result error = %v, want %v", err, ErrConflict)
	}
	if _, err := store.SubmitResult(ctx, requester, created.RequestID, result); !errors.Is(err, ErrForbidden) {
		t.Fatalf("non-target result replay error = %v, want %v", err, ErrForbidden)
	}
	terminalDecision, err := store.Decide(ctx, target, created.RequestID, allow)
	if err != nil || terminalDecision.Status != protocol.StatusCompleted {
		t.Fatalf("terminal decision replay = %#v, %v", terminalDecision, err)
	}
}

func TestApprovalCancelsRevokedRequesterButAllowsOfflineRequester(t *testing.T) {
	t.Parallel()

	t.Run("revoked requester", func(t *testing.T) {
		ctx := context.Background()
		store, requester, target, _ := artifactTestStore(t)
		created, _, _, err := store.CreateRequest(ctx, requester, protocol.CreateRequest{
			TargetAgentID: target.AgentID, Title: "Queued before revocation", Prompt: "Do not run after revocation",
			ExpiresInSeconds: 600, IdempotencyKey: "revoked_requester_approval",
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := store.rdb.SAdd(ctx, revokedAgentsKey(requester.OrganizationID), requester.AgentID).Err(); err != nil {
			t.Fatal(err)
		}

		decision := decisionPayload(protocol.DecisionAllowOnce)
		cancelled, err := store.Decide(ctx, target, created.RequestID, decision)
		if err != nil || cancelled.Status != protocol.StatusCancelled {
			t.Fatalf("allow queued request after requester revocation = %#v, %v", cancelled, err)
		}
		terminal, err := store.GetRequest(ctx, target, created.RequestID)
		if err != nil {
			t.Fatal(err)
		}
		if terminal.Status != protocol.StatusCancelled {
			t.Fatalf("revoked requester approval left request in state %q", terminal.Status)
		}
		replayed, err := store.Decide(ctx, target, created.RequestID, decision)
		if err != nil || replayed.Status != protocol.StatusCancelled {
			t.Fatalf("revoked requester cancellation replay = %#v, %v", replayed, err)
		}
		if _, err := store.Decide(ctx, target, created.RequestID, decisionPayload(protocol.DecisionDeny)); !errors.Is(err, ErrConflict) {
			t.Fatalf("changed decision after revoked requester cancellation error = %v", err)
		}
	})

	t.Run("offline requester", func(t *testing.T) {
		ctx := context.Background()
		store, requester, target, _ := artifactTestStore(t)
		created, _, _, err := store.CreateRequest(ctx, requester, protocol.CreateRequest{
			TargetAgentID: target.AgentID, Title: "Queued while online", Prompt: "Allow while sender is offline",
			ExpiresInSeconds: 600, IdempotencyKey: "offline_requester_approval",
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := store.rdb.Del(ctx, agentKey(requester.OrganizationID, requester.AgentID)).Err(); err != nil {
			t.Fatal(err)
		}
		if err := store.rdb.SRem(ctx, agentsKey(requester.OrganizationID), requester.AgentID).Err(); err != nil {
			t.Fatal(err)
		}

		approved, err := store.Decide(ctx, target, created.RequestID, decisionPayload(protocol.DecisionAllowOnce))
		if err != nil {
			t.Fatalf("offline non-revoked requester was rejected: %v", err)
		}
		if approved.Status != protocol.StatusAccepted {
			t.Fatalf("offline non-revoked request status = %q, want %q", approved.Status, protocol.StatusAccepted)
		}
	})
}

func TestSelfLoopIsRejected(t *testing.T) {
	t.Parallel()

	mini := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	store := NewRedisStore(rdb)
	principal := devicePrincipal("org_1", "mem_1", "dev_1", "agent_1", "Me", "codex", protocol.PermissionReadOnly)
	_, err := store.Heartbeat(context.Background(), principal, protocol.AgentHeartbeat{
		DisplayName: "Me", Availability: protocol.AvailabilityAvailable, AcceptingRequests: true,
		Runtime: protocol.RuntimeDescriptor{ID: "codex", DisplayName: "Codex"}, PermissionMode: protocol.PermissionReadOnly,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = store.CreateRequest(context.Background(), principal, protocol.CreateRequest{
		TargetAgentID: "agent_1", Title: "Loop", Prompt: "Do not loop", ExpiresInSeconds: 60, IdempotencyKey: "loop_1",
	})
	if err == nil {
		t.Fatal("expected self-loop to be rejected")
	}
	sameMember := devicePrincipal("org_1", "mem_1", "dev_2", "agent_2", "Me elsewhere", "codex", protocol.PermissionReadOnly)
	_, err = store.Heartbeat(context.Background(), sameMember, protocol.AgentHeartbeat{
		DisplayName: "Me elsewhere", Availability: protocol.AvailabilityAvailable, AcceptingRequests: true,
		Runtime: protocol.RuntimeDescriptor{ID: "codex", DisplayName: "Codex"}, PermissionMode: protocol.PermissionReadOnly,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = store.CreateRequest(context.Background(), principal, protocol.CreateRequest{
		TargetAgentID: sameMember.AgentID, Title: "Cross-device loop", Prompt: "Do not loop",
		ExpiresInSeconds: 60, IdempotencyKey: "loop_2",
	})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("same-member target error = %v, want %v", err, ErrInvalid)
	}
}

func TestDirectoryIsOrganizationScopedAndExcludesCaller(t *testing.T) {
	t.Parallel()

	mini := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	store := NewRedisStore(rdb)
	heartbeat := protocol.AgentHeartbeat{
		DisplayName: "Agent", Availability: protocol.AvailabilityAvailable, AcceptingRequests: true,
		Runtime: protocol.RuntimeDescriptor{ID: "codex", DisplayName: "Codex"}, PermissionMode: protocol.PermissionGuardedWrite,
	}
	a := devicePrincipal("org_a", "mem_1", "dev_1", "agent_1", "Agent A", "codex", protocol.PermissionGuardedWrite)
	aSecondDevice := devicePrincipal("org_a", "mem_1", "dev_4", "agent_4", "Agent A second device", "codex", protocol.PermissionGuardedWrite)
	b := devicePrincipal("org_a", "mem_2", "dev_2", "agent_2", "Agent B", "codex", protocol.PermissionGuardedWrite)
	other := devicePrincipal("org_b", "mem_3", "dev_3", "agent_3", "Agent C", "codex", protocol.PermissionGuardedWrite)
	for _, principal := range []auth.Principal{a, aSecondDevice, b, other} {
		if _, err := store.Heartbeat(context.Background(), principal, heartbeat); err != nil {
			t.Fatal(err)
		}
	}
	directory, err := store.ListAgents(context.Background(), a, AgentQuery{OnlineOnly: true, AcceptingOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(directory.Agents) != 1 || directory.Agents[0].AgentID != b.AgentID {
		t.Fatalf("unexpected scoped directory: %#v", directory.Agents)
	}
}

func devicePrincipal(org, member, device, agent, display, runtimeID string, permission protocol.PermissionMode) auth.Principal {
	return auth.Principal{
		OrganizationID: org, MemberID: member, DeviceID: device, AgentID: agent,
		DisplayName: display, DeviceName: device, Runtime: runtimeID, PermissionMode: string(permission),
		Role: auth.RoleMember, TokenKind: auth.TokenDevice,
	}
}

func TestHeartbeatCannotUpgradeEnrolledRuntimeOrPermission(t *testing.T) {
	t.Parallel()

	mini := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	store := NewRedisStore(rdb)
	principal := devicePrincipal("org_1", "mem_1", "dev_1", "agent_1", "Agent", "codex", protocol.PermissionReadOnly)
	base := protocol.AgentHeartbeat{
		DisplayName: "spoofed", DeviceName: "spoofed", Availability: protocol.AvailabilityAvailable, AcceptingRequests: true,
		Runtime: protocol.RuntimeDescriptor{ID: "codex", DisplayName: "Codex"}, PermissionMode: protocol.PermissionReadOnly,
	}
	card, err := store.Heartbeat(context.Background(), principal, base)
	if err != nil {
		t.Fatal(err)
	}
	if card.DisplayName != principal.DisplayName || card.DeviceName != principal.DeviceName {
		t.Fatalf("heartbeat overrode enrolled identity: %#v", card)
	}
	base.PermissionMode = protocol.PermissionGuardedWrite
	if _, err := store.Heartbeat(context.Background(), principal, base); !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected permission upgrade to be forbidden, got %v", err)
	}
	base.PermissionMode = protocol.PermissionReadOnly
	base.Runtime.ID = "claude-code"
	if _, err := store.Heartbeat(context.Background(), principal, base); !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected runtime substitution to be forbidden, got %v", err)
	}
}

func TestInboxExpiryRechecksStateAndDeadlineInsideTransition(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, requester, target, now := artifactTestStore(t)
	accepted, _, _, err := store.CreateRequest(ctx, requester, protocol.CreateRequest{
		TargetAgentID: target.AgentID, Title: "Accepted", Prompt: "Do work",
		ExpiresInSeconds: 60, IdempotencyKey: "accepted_before_expiry",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Decide(ctx, target, accepted.RequestID, decisionPayload(protocol.DecisionAllowOnce)); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(61 * time.Second)
	expired, err := store.expireAwaiting(ctx, target, accepted.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	if expired {
		t.Fatal("accepted request was expired from a stale inbox observation")
	}
	acceptedState, err := store.GetRequest(ctx, target, accepted.RequestID)
	if err != nil || acceptedState.Status != protocol.StatusAccepted {
		t.Fatalf("accepted state = %s, %v", acceptedState.Status, err)
	}

	waiting, _, _, err := store.CreateRequest(ctx, requester, protocol.CreateRequest{
		TargetAgentID: target.AgentID, Title: "Waiting", Prompt: "Do later",
		ExpiresInSeconds: 60, IdempotencyKey: "actually_expired",
	})
	if err != nil {
		t.Fatal(err)
	}
	*now = now.Add(61 * time.Second)
	expired, err = store.expireAwaiting(ctx, target, waiting.RequestID)
	if err != nil || !expired {
		t.Fatalf("expireAwaiting = %t, %v", expired, err)
	}
	expiredState, err := store.GetRequest(ctx, target, waiting.RequestID)
	if err != nil || expiredState.Status != protocol.StatusExpired {
		t.Fatalf("expired state = %s, %v", expiredState.Status, err)
	}
}

func TestCancelIsIdempotentOnlyForExistingCancelledRequest(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, requester, target, _ := artifactTestStore(t)
	created, _, _, err := store.CreateRequest(ctx, requester, protocol.CreateRequest{
		TargetAgentID: target.AgentID, Title: "Cancel", Prompt: "Stop this",
		ExpiresInSeconds: 600, IdempotencyKey: "cancel_idempotent",
	})
	if err != nil {
		t.Fatal(err)
	}
	first, changed, err := store.Cancel(ctx, requester, created.RequestID)
	if err != nil || !changed || first.Status != protocol.StatusCancelled {
		t.Fatalf("first cancel = %#v changed=%t err=%v", first, changed, err)
	}
	beforeRetry, err := store.GetRequest(ctx, requester, created.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	second, changed, err := store.Cancel(ctx, requester, created.RequestID)
	if err != nil || changed || second != first {
		t.Fatalf("repeat cancel = %#v changed=%t err=%v", second, changed, err)
	}
	afterRetry, err := store.GetRequest(ctx, requester, created.RequestID)
	if err != nil || afterRetry.Version != beforeRetry.Version {
		t.Fatalf("repeat cancel changed version from %d to %d: %v", beforeRetry.Version, afterRetry.Version, err)
	}

	rejected, _, _, err := store.CreateRequest(ctx, requester, protocol.CreateRequest{
		TargetAgentID: target.AgentID, Title: "Rejected", Prompt: "Reject this",
		ExpiresInSeconds: 600, IdempotencyKey: "cancel_rejected",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Decide(ctx, target, rejected.RequestID, decisionPayload(protocol.DecisionDeny)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Cancel(ctx, requester, rejected.RequestID); !errors.Is(err, ErrConflict) {
		t.Fatalf("cancel rejected request error = %v, want %v", err, ErrConflict)
	}
}

func TestSubmitResultRejectsIncoherentOrOversizedFields(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, requester, target, _ := artifactTestStore(t)
	created, _, _, err := store.CreateRequest(ctx, requester, protocol.CreateRequest{
		TargetAgentID: target.AgentID, Title: "Result", Prompt: "Return result",
		ExpiresInSeconds: 600, IdempotencyKey: "result_field_validation",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Decide(ctx, target, created.RequestID, decisionPayload(protocol.DecisionAllowOnce)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkRunning(ctx, target, created.RequestID, testExecutionClaimA); err != nil {
		t.Fatal(err)
	}
	file := attachmentInput("report.md", []byte("safe"))
	invalid := []protocol.ResultPayload{
		{ExecutionClaimID: testExecutionClaimA, State: protocol.StatusCompleted, Answer: "done", Error: "also failed"},
		{ExecutionClaimID: testExecutionClaimA, State: protocol.StatusFailed, Answer: "not coherent", Error: "failed"},
		{ExecutionClaimID: testExecutionClaimA, State: protocol.StatusCancelled, Answer: "not coherent"},
		{ExecutionClaimID: testExecutionClaimA, State: protocol.StatusFailed, Error: "failed", ResultFiles: []protocol.AttachmentInput{file}},
		{ExecutionClaimID: testExecutionClaimA, State: protocol.StatusFailed, Error: strings.Repeat("e", maximumErrorBytes+1)},
	}
	for index, result := range invalid {
		if _, err := store.SubmitResult(ctx, target, created.RequestID, result); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid result %d error = %v, want %v", index, err, ErrInvalid)
		}
	}
	state, err := store.GetRequest(ctx, target, created.RequestID)
	if err != nil || state.Status != protocol.StatusRunning {
		t.Fatalf("invalid result mutated state to %s: %v", state.Status, err)
	}
	if _, err := store.SubmitResult(ctx, target, created.RequestID, protocol.ResultPayload{
		ExecutionClaimID: testExecutionClaimA, State: protocol.StatusFailed, Error: strings.Repeat("e", maximumErrorBytes),
	}); err != nil {
		t.Fatalf("valid bounded failure rejected: %v", err)
	}
}

func TestArtifactBytesFollowApprovalAndResultState(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		transition func(context.Context, *RedisStore, auth.Principal, auth.Principal, string, *time.Time) error
		wantError  error
	}{
		{name: "awaiting approval", wantError: ErrConflict},
		{
			name: "rejected",
			transition: func(ctx context.Context, store *RedisStore, _ auth.Principal, target auth.Principal, requestID string, _ *time.Time) error {
				_, err := store.Decide(ctx, target, requestID, decisionPayload(protocol.DecisionDeny))
				return err
			},
			wantError: ErrConflict,
		},
		{
			name: "expired",
			transition: func(ctx context.Context, store *RedisStore, _ auth.Principal, target auth.Principal, requestID string, now *time.Time) error {
				*now = now.Add(61 * time.Second)
				_, err := store.Decide(ctx, target, requestID, decisionPayload(protocol.DecisionAllowOnce))
				return err
			},
			wantError: ErrConflict,
		},
		{
			name: "cancelled",
			transition: func(ctx context.Context, store *RedisStore, requester auth.Principal, _ auth.Principal, requestID string, _ *time.Time) error {
				_, _, err := store.Cancel(ctx, requester, requestID)
				return err
			},
			wantError: ErrConflict,
		},
		{
			name: "accepted",
			transition: func(ctx context.Context, store *RedisStore, _ auth.Principal, target auth.Principal, requestID string, _ *time.Time) error {
				_, err := store.Decide(ctx, target, requestID, decisionPayload(protocol.DecisionAllowOnce))
				return err
			},
		},
		{
			name: "running",
			transition: func(ctx context.Context, store *RedisStore, _ auth.Principal, target auth.Principal, requestID string, _ *time.Time) error {
				if _, err := store.Decide(ctx, target, requestID, decisionPayload(protocol.DecisionAllowOnce)); err != nil {
					return err
				}
				_, err := store.MarkRunning(ctx, target, requestID, testExecutionClaimA)
				return err
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			store, requester, target, now := artifactTestStore(t)
			attachment := attachmentInput("input.txt", []byte("approved bytes only"))
			created, notice, _, err := store.CreateRequest(ctx, requester, protocol.CreateRequest{
				TargetAgentID: target.AgentID, Title: "Inspect", Prompt: "Review the attachment",
				ExpiresInSeconds: 60, IdempotencyKey: "artifact_state",
				Attachments: []protocol.AttachmentInput{attachment},
			})
			if err != nil {
				t.Fatal(err)
			}
			if testCase.transition != nil {
				if err := testCase.transition(ctx, store, requester, target, created.RequestID, now); err != nil {
					t.Fatal(err)
				}
			}
			_, err = store.FetchArtifact(ctx, target, notice.Attachments[0].ArtifactID)
			if !errors.Is(err, testCase.wantError) {
				t.Fatalf("FetchArtifact error = %v, want %v", err, testCase.wantError)
			}
			if _, err := store.FetchArtifact(ctx, requester, notice.Attachments[0].ArtifactID); !errors.Is(err, ErrForbidden) {
				t.Fatalf("requester fetched its input artifact through recipient endpoint: %v", err)
			}
		})
	}
}

func TestResultFilesRequireCompletedStateAndRequesterAccess(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, requester, target, _ := artifactTestStore(t)
	created, _, _, err := store.CreateRequest(ctx, requester, protocol.CreateRequest{
		TargetAgentID: target.AgentID, Title: "Return", Prompt: "Return a short report",
		ExpiresInSeconds: 600, IdempotencyKey: "result_file_state",
	})
	if err != nil {
		t.Fatal(err)
	}
	resultFile := attachmentInput("report.md", []byte("# Review\nEverything looks good.\n"))
	if _, err := store.SubmitResult(ctx, target, created.RequestID, protocol.ResultPayload{
		ExecutionClaimID: testExecutionClaimA, State: protocol.StatusCompleted, Answer: "Too early", ResultFiles: []protocol.AttachmentInput{resultFile},
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("pre-running result error = %v, want %v", err, ErrConflict)
	}
	if _, err := store.Decide(ctx, target, created.RequestID, decisionPayload(protocol.DecisionAllowOnce)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkRunning(ctx, target, created.RequestID, testExecutionClaimA); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SubmitResult(ctx, target, created.RequestID, protocol.ResultPayload{
		ExecutionClaimID: testExecutionClaimA, State: protocol.StatusFailed, Error: "runtime failed", ResultFiles: []protocol.AttachmentInput{resultFile},
	}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("failed result with files error = %v, want %v", err, ErrInvalid)
	}
	if _, err := store.SubmitResult(ctx, target, created.RequestID, protocol.ResultPayload{
		ExecutionClaimID: testExecutionClaimA, State: protocol.StatusCompleted, Answer: "Done", ResultFiles: []protocol.AttachmentInput{resultFile},
	}); err != nil {
		t.Fatal(err)
	}
	completed, err := store.GetRequest(ctx, requester, created.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	if completed.Status != protocol.StatusCompleted || len(completed.ResultFiles) != 1 {
		t.Fatalf("unexpected completed request: %#v", completed)
	}
	artifactID := completed.ResultFiles[0].ArtifactID
	content, err := store.FetchArtifact(ctx, requester, artifactID)
	if err != nil {
		t.Fatal(err)
	}
	if content.ContentBase64 != resultFile.ContentBase64 {
		t.Fatalf("returned content = %q, want %q", content.ContentBase64, resultFile.ContentBase64)
	}
	if _, err := store.FetchArtifact(ctx, target, artifactID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("target fetched its own result artifact: %v", err)
	}
}

func artifactTestStore(t *testing.T) (*RedisStore, auth.Principal, auth.Principal, *time.Time) {
	t.Helper()
	mini := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	store := NewRedisStore(rdb)
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	requester := devicePrincipal("org_artifacts", "mem_1", "dev_1", "agent_1", "Requester", "codex", protocol.PermissionReadOnly)
	target := devicePrincipal("org_artifacts", "mem_2", "dev_2", "agent_2", "Target", "claude-code", protocol.PermissionReadOnly)
	for _, peer := range []auth.Principal{requester, target} {
		if _, err := store.Heartbeat(context.Background(), peer, protocol.AgentHeartbeat{
			DisplayName: peer.DisplayName, Availability: protocol.AvailabilityAvailable, AcceptingRequests: true,
			Runtime: protocol.RuntimeDescriptor{ID: peer.Runtime, DisplayName: peer.Runtime}, PermissionMode: protocol.PermissionReadOnly,
		}); err != nil {
			t.Fatal(err)
		}
	}
	return store, requester, target, &now
}

func attachmentInput(name string, content []byte) protocol.AttachmentInput {
	digest := sha256.Sum256(content)
	return protocol.AttachmentInput{
		Name: name, MIMEType: "text/plain", Encoding: "base64", SizeBytes: int64(len(content)),
		SHA256: hex.EncodeToString(digest[:]), ContentBase64: base64.StdEncoding.EncodeToString(content),
	}
}

func TestValidateCreateRejectsDuplicateWorkspaceAliases(t *testing.T) {
	t.Parallel()

	err := validateCreate(protocol.CreateRequest{
		TargetAgentID: "agent_2", Title: "Review", Prompt: "Review the repository",
		ExpiresInSeconds: 600, IdempotencyKey: "duplicate_workspace",
		RequestedAccess: []protocol.RequestedAccess{
			{WorkspaceAlias: "repo", Mode: protocol.PermissionReadOnly},
			{WorkspaceAlias: "Repo", Mode: protocol.PermissionGuardedWrite},
		},
	})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("duplicate workspace aliases error = %v, want %v", err, ErrInvalid)
	}
}

func TestPrepareArtifactsRejectsUnsafeMetadata(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		mutate func(*protocol.AttachmentInput)
	}{
		{name: "parent traversal", mutate: func(input *protocol.AttachmentInput) { input.Name = "../report.txt" }},
		{name: "absolute path", mutate: func(input *protocol.AttachmentInput) { input.Name = "/tmp/report.txt" }},
		{name: "windows path", mutate: func(input *protocol.AttachmentInput) { input.Name = `C:\\temp\\report.txt` }},
		{name: "alternate data stream", mutate: func(input *protocol.AttachmentInput) { input.Name = "report.txt:secret" }},
		{name: "reserved device", mutate: func(input *protocol.AttachmentInput) { input.Name = "COM1.txt" }},
		{name: "trailing dot", mutate: func(input *protocol.AttachmentInput) { input.Name = "report.txt." }},
		{name: "trailing space", mutate: func(input *protocol.AttachmentInput) { input.Name = "report.txt " }},
		{name: "credential name", mutate: func(input *protocol.AttachmentInput) { input.Name = "credentials.json" }},
		{name: "environment variant", mutate: func(input *protocol.AttachmentInput) { input.Name = ".env.production" }},
		{name: "package registry credential", mutate: func(input *protocol.AttachmentInput) { input.Name = ".npmrc" }},
		{name: "private key extension", mutate: func(input *protocol.AttachmentInput) { input.Name = "client.key" }},
		{name: "invalid MIME type", mutate: func(input *protocol.AttachmentInput) { input.MIMEType = "not a mime type" }},
		{name: "empty MIME type", mutate: func(input *protocol.AttachmentInput) { input.MIMEType = "" }},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			input := attachmentInput("report.txt", []byte("safe content"))
			testCase.mutate(&input)
			if _, _, err := prepareArtifacts([]protocol.AttachmentInput{input}, "req_1", "agent_1", "agent_2", "input"); !errors.Is(err, ErrInvalid) {
				t.Fatalf("prepareArtifacts error = %v, want %v", err, ErrInvalid)
			}
		})
	}
}
