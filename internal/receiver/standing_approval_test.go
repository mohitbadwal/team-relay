package receiver

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mohitbadwal/team-relay/internal/client"
	"github.com/mohitbadwal/team-relay/internal/privatefs"
	"github.com/mohitbadwal/team-relay/internal/protocol"
	relayruntime "github.com/mohitbadwal/team-relay/internal/runtime"
)

func TestConversationGrantAutoApprovesMatchingFutureTurnAndRevocationStopsIt(t *testing.T) {
	policy, _ := relayruntime.DefaultPolicy(relayruntime.PolicyReadOnly)
	relay := &fakeRelayClient{
		heartbeat:     make(chan struct{}, 1),
		heartbeatCard: protocol.AgentCard{AgentID: "agent_recipient"},
		submitted:     make(chan protocol.ResultPayload, 3),
		payload: protocol.ExecutionPayload{
			RequestID: "req_first", ConversationID: "conv_shared", RequesterAgentID: "agent_alice_laptop",
			RequesterMemberID: "member_alice", RequesterDisplayName: "Alice", Prompt: "first",
		},
	}
	streamStarted := make(chan struct{})
	relay.stream = func(ctx context.Context, _ func(client.Event) error) error {
		close(streamStarted)
		<-ctx.Done()
		return ctx.Err()
	}
	controller, err := NewController(&fakeAdapter{
		policy: policy, result: relayruntime.RunResult{FinalText: "done"},
	}, mustSessionStore(t), 1)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := NewPendingStore(filepath.Join(t.TempDir(), "state", "pending.json"))
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(ServiceConfig{
		Client: relay, Controller: controller, Pending: pending,
		ApprovalAuthorityFingerprint: "authority-test", DisplayName: "Recipient", DeviceName: "Laptop",
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), HeartbeatInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Run(ctx) }()
	select {
	case <-streamStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("receiver did not start")
	}

	first := executionNotice(relay.payload, protocol.StatusAwaitingApproval)
	if err := service.handleEvent(peerRequestEvent(t, first)); err != nil {
		t.Fatal(err)
	}
	approved, err := service.Approve(context.Background(), first.RequestID, ApprovalLevelConversation30m)
	if err != nil {
		t.Fatal(err)
	}
	if approved.Grant == nil || approved.Grant.Level != ApprovalLevelConversation30m {
		t.Fatalf("standing approval result = %#v", approved)
	}
	waitForSubmittedResult(t, relay.submitted, first.RequestID)
	waitForReceiverIdle(t, service)

	secondPayload := protocol.ExecutionPayload{
		RequestID: "req_second", ConversationID: "conv_shared", RequesterAgentID: "agent_alice_laptop",
		RequesterMemberID: "member_alice", RequesterDisplayName: "Alice", Prompt: "follow-up",
	}
	relay.mu.Lock()
	relay.payload = secondPayload
	relay.mu.Unlock()
	second := executionNotice(secondPayload, protocol.StatusAwaitingApproval)
	if err := service.handleEvent(peerRequestEvent(t, second)); err != nil {
		t.Fatal(err)
	}
	waitForSubmittedResult(t, relay.submitted, second.RequestID)
	waitForReceiverIdle(t, service)

	relay.mu.Lock()
	decideCalls := relay.decideCalls
	relay.mu.Unlock()
	if decideCalls != 2 {
		t.Fatalf("relay decisions = %d, want one exact decision per request", decideCalls)
	}
	if err := service.RevokeApprovalGrant(approved.Grant.GrantID); err != nil {
		t.Fatal(err)
	}

	third := protocol.RequestNotice{
		RequestID: "req_third", ConversationID: "conv_shared", Status: protocol.StatusAwaitingApproval,
		RequesterAgentID: "agent_alice_laptop", RequesterMemberID: "member_alice", RequesterDisplayName: "Alice",
	}
	if err := service.handleEvent(peerRequestEvent(t, third)); err != nil {
		t.Fatal(err)
	}
	relay.mu.Lock()
	decideCalls = relay.decideCalls
	relay.mu.Unlock()
	if decideCalls != 2 {
		t.Fatalf("revoked grant still approved a request; decisions = %d", decideCalls)
	}
	if record, ok := pending.Get(third.RequestID); !ok || record.Notice.Status != protocol.StatusAwaitingApproval {
		t.Fatalf("request did not return to Ask always after revocation: %#v, present=%t", record, ok)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestStandingApprovalFailsClosedWithoutAuthenticatedMemberIdentity(t *testing.T) {
	policy, _ := relayruntime.DefaultPolicy(relayruntime.PolicyReadOnly)
	relay := &fakeRelayClient{}
	controller, _ := NewController(&fakeAdapter{policy: policy}, mustSessionStore(t), 1)
	pending, _ := NewPendingStore(filepath.Join(t.TempDir(), "state", "pending.json"))
	notice := protocol.RequestNotice{
		RequestID: "req_legacy", ConversationID: "conv_legacy", Status: protocol.StatusAwaitingApproval,
		RequesterAgentID: "agent_legacy", RequesterDisplayName: "Legacy sender",
	}
	if err := pending.Upsert(notice); err != nil {
		t.Fatal(err)
	}
	service, err := NewService(ServiceConfig{
		Client: relay, Controller: controller, Pending: pending,
		DisplayName: "Recipient", DeviceName: "Laptop", ApprovalAuthorityFingerprint: "authority-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	service.approvalAuthority = ApprovalAuthority{Fingerprint: "authority-test", RecipientAgentID: "agent_recipient"}
	if _, err := service.Approve(context.Background(), notice.RequestID, ApprovalLevelAllAlways); err == nil {
		t.Fatal("legacy request without an authenticated member identity created an all-teammates grant")
	}
	grants, err := service.ApprovalGrants()
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 0 {
		t.Fatalf("legacy request persisted grants: %#v", grants)
	}
}

func TestMatchedStandingGrantCannotApproveReplacedBroaderNotice(t *testing.T) {
	policy, _ := relayruntime.DefaultPolicy(relayruntime.PolicyReadOnly)
	relay := &fakeRelayClient{}
	controller, _ := NewController(&fakeAdapter{policy: policy}, mustSessionStore(t), 1)
	pending, _ := NewPendingStore(filepath.Join(t.TempDir(), "state", "pending.json"))
	service, err := NewService(ServiceConfig{
		Client: relay, Controller: controller, Pending: pending,
		DisplayName: "Recipient", DeviceName: "Laptop", Workspaces: map[string]string{"repo": t.TempDir()},
	})
	if err != nil {
		t.Fatal(err)
	}
	service.approvalAuthority = ApprovalAuthority{Fingerprint: service.approvalFingerprint, RecipientAgentID: "agent_recipient"}

	narrow := executionNotice(protocol.ExecutionPayload{
		RequestID: "req_replaced_scope", ConversationID: "conv_replaced_scope",
		RequesterAgentID: "agent_alice", RequesterMemberID: "member_alice", RequesterDisplayName: "Alice",
		Prompt: "inspect without workspace access", ExpiresAt: time.Now().UTC().Add(time.Hour),
	}, protocol.StatusAwaitingApproval)
	candidate, err := approvalCandidateForNotice(narrow)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := service.approvals.Upsert(service.approvalAuthority, ApprovalLevelTeammateAlways, candidate)
	if err != nil {
		t.Fatal(err)
	}

	broaderPayload := protocol.ExecutionPayload{
		RequestID: narrow.RequestID, ConversationID: narrow.ConversationID,
		RequesterAgentID: narrow.RequesterAgentID, RequesterMemberID: narrow.RequesterMemberID, RequesterDisplayName: narrow.RequesterDisplayName,
		Prompt: "modify the repository instead", ExpiresAt: narrow.ExpiresAt,
		RequestedAccess: []protocol.RequestedAccess{{WorkspaceAlias: "repo", Mode: protocol.PermissionGuardedWrite}},
	}
	broader := executionNotice(broaderPayload, protocol.StatusAwaitingApproval)
	if err := pending.Upsert(broader); err != nil {
		t.Fatal(err)
	}

	// Simulate delivery of the earlier narrow event after PendingStore has
	// already been replaced. The old implementation matched the stale event and
	// then approved the broader current record using that narrower grant.
	service.maybeAutoApprove(context.Background(), narrow)
	if _, err := service.allowOnceWithApprovalForNotice(
		context.Background(), narrow.RequestID, grant.Level, grant.GrantID, true, &narrow,
	); err == nil || !strings.Contains(err.Error(), "changed after its standing approval was matched") {
		t.Fatalf("matched narrow notice did not reject its broader replacement: %v", err)
	}

	relay.mu.Lock()
	decisions := relay.decideCalls
	relay.mu.Unlock()
	if decisions != 0 {
		t.Fatalf("narrow grant %q approved a replaced broader request (%d relay decisions)", grant.GrantID, decisions)
	}
	if _, ok := service.mutations.Get(narrow.RequestID); ok {
		t.Fatal("replaced broader notice created a durable allow mutation")
	}
	if record, ok := pending.Get(narrow.RequestID); !ok || record.Notice.Status != protocol.StatusAwaitingApproval {
		t.Fatalf("broader replacement did not remain Ask always: %#v, present=%t", record, ok)
	}
}

func TestApprovalAuthorityChangesWithEffectiveRuntimeWorkDir(t *testing.T) {
	policy, _ := relayruntime.DefaultPolicy(relayruntime.PolicyReadOnly)
	first, err := NewController(&fakeAdapter{policy: policy, workDir: "/recipient/repo-a"}, mustSessionStore(t), 1)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewController(&fakeAdapter{policy: policy, workDir: "/recipient/repo-b"}, mustSessionStore(t), 1)
	if err != nil {
		t.Fatal(err)
	}
	firstFingerprint, err := effectiveApprovalPolicyFingerprint(first, nil, "Recipient", "Laptop")
	if err != nil {
		t.Fatal(err)
	}
	secondFingerprint, err := effectiveApprovalPolicyFingerprint(second, nil, "Recipient", "Laptop")
	if err != nil {
		t.Fatal(err)
	}
	if firstFingerprint == secondFingerprint {
		t.Fatal("standing approval authority survived a changed effective runtime work directory")
	}
}

func TestApprovalAuthorityChangesWithFrozenRuntimeConfiguration(t *testing.T) {
	policy, _ := relayruntime.DefaultPolicy(relayruntime.PolicyReadOnly)
	first, err := NewController(&fakeAdapter{policy: policy, approval: "runtime-config-a"}, mustSessionStore(t), 1)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewController(&fakeAdapter{policy: policy, approval: "runtime-config-b"}, mustSessionStore(t), 1)
	if err != nil {
		t.Fatal(err)
	}
	firstFingerprint, err := effectiveApprovalPolicyFingerprint(first, nil, "Recipient", "Laptop")
	if err != nil {
		t.Fatal(err)
	}
	secondFingerprint, err := effectiveApprovalPolicyFingerprint(second, nil, "Recipient", "Laptop")
	if err != nil {
		t.Fatal(err)
	}
	if firstFingerprint == secondFingerprint {
		t.Fatal("standing approval authority survived a changed frozen runtime configuration")
	}
}

func TestApprovalAuthorityChangesWithEffectiveMCPAndNetworkPolicy(t *testing.T) {
	base, _ := relayruntime.DefaultPolicy(relayruntime.PolicyReadOnly)
	baseController, _ := NewController(&fakeAdapter{policy: base}, mustSessionStore(t), 1)
	baseFingerprint, err := effectiveApprovalPolicyFingerprint(baseController, nil, "Recipient", "Laptop")
	if err != nil {
		t.Fatal(err)
	}
	for _, testCase := range []struct {
		name   string
		policy relayruntime.Policy
	}{
		{name: "network", policy: relayruntime.Policy{Mode: relayruntime.PolicyCustom, AllowNetwork: true}},
		{name: "MCP", policy: relayruntime.Policy{Mode: relayruntime.PolicyCustom, AllowMCPs: true}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			validated, err := relayruntime.ValidatePolicy(testCase.policy)
			if err != nil {
				t.Fatal(err)
			}
			controller, _ := NewController(&fakeAdapter{policy: validated}, mustSessionStore(t), 1)
			fingerprint, err := effectiveApprovalPolicyFingerprint(controller, nil, "Recipient", "Laptop")
			if err != nil {
				t.Fatal(err)
			}
			if fingerprint == baseFingerprint {
				t.Fatalf("standing approval authority survived changed %s permission", testCase.name)
			}
		})
	}
}

func TestRestartRefusesAcceptedAllowPreparedUnderDifferentWorkDir(t *testing.T) {
	policy, _ := relayruntime.DefaultPolicy(relayruntime.PolicyReadOnly)
	stateDir := filepath.Join(t.TempDir(), "state")
	pendingPath := filepath.Join(stateDir, "pending.json")
	notice := protocol.RequestNotice{
		RequestID: "req_changed_authority", ConversationID: "conv_changed_authority", Status: protocol.StatusAwaitingApproval,
		RequesterAgentID: "agent_alice", RequesterMemberID: "member_alice", RequesterDisplayName: "Alice",
	}
	firstPending, err := NewPendingStore(pendingPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := firstPending.Upsert(notice); err != nil {
		t.Fatal(err)
	}
	firstController, _ := NewController(&fakeAdapter{policy: policy, workDir: "/recipient/repo-a"}, mustSessionStore(t), 1)
	firstRelay := &fakeRelayClient{decide: func(string, protocol.DecisionPayload) (*protocol.MutationResponse, error) {
		return nil, errors.New("response lost after relay accepted the request")
	}}
	firstService, err := NewService(ServiceConfig{
		Client: firstRelay, Controller: firstController, Pending: firstPending,
		DisplayName: "Recipient", DeviceName: "Laptop", ApprovalAuthorityFingerprint: "enrollment-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	firstService.approvalAuthority = ApprovalAuthority{
		Fingerprint: firstService.approvalFingerprint, RecipientAgentID: "agent_recipient",
	}
	if _, err := firstService.Approve(context.Background(), notice.RequestID, ApprovalLevelAskAlways); err == nil {
		t.Fatal("ambiguous allow was reported as successful")
	}
	prepared, ok := firstService.mutations.Get(notice.RequestID)
	if !ok || prepared.Phase != mutationDecisionPrepared || prepared.ApprovalAuthorityFingerprint != firstService.approvalFingerprint {
		t.Fatalf("first allow was not durably bound: %#v, present=%t", prepared, ok)
	}

	accepted := notice
	accepted.Status = protocol.StatusAccepted
	streamStarted := make(chan struct{})
	secondRelay := &fakeRelayClient{
		heartbeat: make(chan struct{}, 1), inbox: protocol.InboxResponse{Requests: []protocol.RequestNotice{accepted}},
		stream: func(ctx context.Context, _ func(client.Event) error) error {
			close(streamStarted)
			<-ctx.Done()
			return ctx.Err()
		},
	}
	runCalled := make(chan struct{}, 1)
	secondController, _ := NewController(&fakeAdapter{
		policy: policy, workDir: "/recipient/repo-b", onRun: func() { runCalled <- struct{}{} },
	}, mustSessionStore(t), 1)
	secondPending, err := NewPendingStore(pendingPath)
	if err != nil {
		t.Fatal(err)
	}
	secondService, err := NewService(ServiceConfig{
		Client: secondRelay, Controller: secondController, Pending: secondPending,
		DisplayName: "Recipient", DeviceName: "Laptop", ApprovalAuthorityFingerprint: "enrollment-a",
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), HeartbeatInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if secondService.approvalFingerprint == firstService.approvalFingerprint {
		t.Fatal("test setup did not change effective approval authority")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- secondService.Run(ctx) }()
	select {
	case <-streamStarted:
	case err := <-done:
		t.Fatalf("receiver stopped instead of safely retaining the accepted request: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("receiver did not finish safe recovery")
	}
	select {
	case <-runCalled:
		t.Fatal("accepted request executed after its approval authority changed")
	default:
	}
	secondRelay.mu.Lock()
	decisionCalls := secondRelay.decideCalls
	secondRelay.mu.Unlock()
	if decisionCalls != 0 {
		t.Fatalf("changed authority replayed %d relay decisions", decisionCalls)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestLegacyUnboundPreparedAllowReturnsToAskAlwaysWithoutRelayReplay(t *testing.T) {
	policy, _ := relayruntime.DefaultPolicy(relayruntime.PolicyReadOnly)
	stateDir := filepath.Join(t.TempDir(), "state")
	pending, err := NewPendingStore(filepath.Join(stateDir, "pending.json"))
	if err != nil {
		t.Fatal(err)
	}
	notice := protocol.RequestNotice{
		RequestID: "req_legacy_allow", ConversationID: "conv_legacy_allow", Status: protocol.StatusAwaitingApproval,
		RequesterAgentID: "agent_alice", RequesterMemberID: "member_alice", RequesterDisplayName: "Alice",
	}
	if err := pending.Upsert(notice); err != nil {
		t.Fatal(err)
	}
	legacyOperation := mutationRecord{
		RequestID: notice.RequestID, ConversationID: notice.ConversationID,
		DecisionID: "decision_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Decision:   protocol.DecisionAllowOnce, ApprovalLevel: ApprovalLevelAskAlways,
		ExecutionClaimID: "claim_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Phase:            mutationDecisionPrepared,
	}
	legacySnapshot := mutationSnapshot{
		Version: legacyMutationStoreVersion, UpdatedAt: time.Now().UTC(),
		Records: map[string]mutationRecord{notice.RequestID: legacyOperation},
	}
	payload, err := json.MarshalIndent(legacySnapshot, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := privatefs.AtomicWriteFile(filepath.Join(stateDir, "receiver_mutations.json"), append(payload, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	relay := &fakeRelayClient{}
	controller, _ := NewController(&fakeAdapter{policy: policy}, mustSessionStore(t), 1)
	service, err := NewService(ServiceConfig{
		Client: relay, Controller: controller, Pending: pending, DisplayName: "Recipient", DeviceName: "Laptop",
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	service.approvalAuthority = ApprovalAuthority{Fingerprint: service.approvalFingerprint, RecipientAgentID: "agent_recipient"}
	if err := service.recoverOperation(context.Background(), notice.RequestID, notice.ConversationID, protocol.StatusAwaitingApproval); err != nil {
		t.Fatal(err)
	}
	if operation, ok := service.mutations.Get(notice.RequestID); ok {
		t.Fatalf("legacy unbound allow remained replayable: %#v", operation)
	}
	relay.mu.Lock()
	decisions := relay.decideCalls
	relay.mu.Unlock()
	if decisions != 0 {
		t.Fatalf("legacy unbound allow replayed %d relay decisions", decisions)
	}
	if record, ok := pending.Get(notice.RequestID); !ok || record.Notice.Status != protocol.StatusAwaitingApproval {
		t.Fatalf("legacy request did not remain available for fresh approval: %#v, present=%t", record, ok)
	}
}

func TestStandingGrantIntentSurvivesAmbiguousCurrentDecisionFailure(t *testing.T) {
	policy, _ := relayruntime.DefaultPolicy(relayruntime.PolicyReadOnly)
	relay := &fakeRelayClient{decide: func(string, protocol.DecisionPayload) (*protocol.MutationResponse, error) {
		return nil, errors.New("relay unavailable")
	}}
	controller, _ := NewController(&fakeAdapter{policy: policy}, mustSessionStore(t), 1)
	pending, _ := NewPendingStore(filepath.Join(t.TempDir(), "state", "pending.json"))
	notice := protocol.RequestNotice{
		RequestID: "req_failed", ConversationID: "conv_failed", Status: protocol.StatusAwaitingApproval,
		RequesterAgentID: "agent_alice", RequesterMemberID: "member_alice", RequesterDisplayName: "Alice",
	}
	if err := pending.Upsert(notice); err != nil {
		t.Fatal(err)
	}
	service, err := NewService(ServiceConfig{
		Client: relay, Controller: controller, Pending: pending,
		DisplayName: "Recipient", DeviceName: "Laptop", ApprovalAuthorityFingerprint: "authority-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	service.approvalAuthority = ApprovalAuthority{Fingerprint: "authority-test", RecipientAgentID: "agent_recipient"}
	if _, err := service.Approve(context.Background(), notice.RequestID, ApprovalLevelTeammateAlways); err == nil {
		t.Fatal("failed relay decision was reported as successful")
	}
	grants, err := service.ApprovalGrants()
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 1 || grants[0].Level != ApprovalLevelTeammateAlways || grants[0].RequesterMemberID != "member_alice" {
		t.Fatalf("durable standing intent after ambiguous current decision = %#v", grants)
	}
	operation, ok := service.mutations.Get(notice.RequestID)
	if !ok || operation.ApprovalLevel != ApprovalLevelTeammateAlways || operation.ApprovalGrantID != grants[0].GrantID || !operation.ApprovalGrantPersisted {
		t.Fatalf("durable request approval intent = %#v, present=%t", operation, ok)
	}
}

func TestConcurrentConflictingApprovalChoicesPersistOnlyFirstIntent(t *testing.T) {
	policy, _ := relayruntime.DefaultPolicy(relayruntime.PolicyReadOnly)
	decisionEntered := make(chan struct{})
	releaseDecision := make(chan struct{})
	var entered sync.Once
	relay := &fakeRelayClient{decide: func(string, protocol.DecisionPayload) (*protocol.MutationResponse, error) {
		entered.Do(func() { close(decisionEntered) })
		<-releaseDecision
		return nil, errors.New("relay unavailable")
	}}
	controller, _ := NewController(&fakeAdapter{policy: policy}, mustSessionStore(t), 1)
	pending, _ := NewPendingStore(filepath.Join(t.TempDir(), "state", "pending.json"))
	notice := protocol.RequestNotice{
		RequestID: "req_racing_choices", ConversationID: "conv_racing_choices", Status: protocol.StatusAwaitingApproval,
		RequesterAgentID: "agent_alice", RequesterMemberID: "member_alice", RequesterDisplayName: "Alice",
	}
	if err := pending.Upsert(notice); err != nil {
		t.Fatal(err)
	}
	service, err := NewService(ServiceConfig{
		Client: relay, Controller: controller, Pending: pending,
		DisplayName: "Recipient", DeviceName: "Laptop", ApprovalAuthorityFingerprint: "authority-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	service.approvalAuthority = ApprovalAuthority{Fingerprint: "authority-test", RecipientAgentID: "agent_recipient"}

	firstDone := make(chan error, 1)
	go func() {
		_, approveErr := service.Approve(context.Background(), notice.RequestID, ApprovalLevelTeammateAlways)
		firstDone <- approveErr
	}()
	select {
	case <-decisionEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("first approval did not reach relay")
	}
	secondStarted := make(chan struct{})
	secondDone := make(chan error, 1)
	go func() {
		close(secondStarted)
		_, approveErr := service.Approve(context.Background(), notice.RequestID, ApprovalLevelAllAlways)
		secondDone <- approveErr
	}()
	<-secondStarted
	close(releaseDecision)
	if err := <-firstDone; err == nil {
		t.Fatal("ambiguous first relay decision was reported as successful")
	}
	if err := <-secondDone; err == nil {
		t.Fatal("conflicting second approval choice replaced the first intent")
	}

	grants, err := service.ApprovalGrants()
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 1 || grants[0].Level != ApprovalLevelTeammateAlways {
		t.Fatalf("conflicting clicks persisted grants = %#v", grants)
	}
	relay.mu.Lock()
	decisions := relay.decideCalls
	relay.mu.Unlock()
	if decisions != 1 {
		t.Fatalf("relay decision calls = %d, want only the first durable choice", decisions)
	}
}

func TestActiveRuntimeCannotCreateStandingApprovalForAnotherRequest(t *testing.T) {
	policy, _ := relayruntime.DefaultPolicy(relayruntime.PolicyReadOnly)
	relay := &fakeRelayClient{}
	controller, _ := NewController(&fakeAdapter{policy: policy}, mustSessionStore(t), 1)
	pending, _ := NewPendingStore(filepath.Join(t.TempDir(), "state", "pending.json"))
	notice := protocol.RequestNotice{
		RequestID: "req_waiting", ConversationID: "conv_waiting", Status: protocol.StatusAwaitingApproval,
		RequesterAgentID: "agent_alice", RequesterMemberID: "member_alice", RequesterDisplayName: "Alice",
	}
	if err := pending.Upsert(notice); err != nil {
		t.Fatal(err)
	}
	service, err := NewService(ServiceConfig{
		Client: relay, Controller: controller, Pending: pending,
		DisplayName: "Recipient", DeviceName: "Laptop", ApprovalAuthorityFingerprint: "authority-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	service.approvalAuthority = ApprovalAuthority{Fingerprint: "authority-test", RecipientAgentID: "agent_recipient"}
	service.runMu.Lock()
	service.active["req_running"] = func() {}
	service.runMu.Unlock()

	if _, err := service.Approve(context.Background(), notice.RequestID, ApprovalLevelAllAlways); !errors.Is(err, errReceiverBusy) {
		t.Fatalf("approval while another runtime is active = %v, want receiver busy", err)
	}
	if _, ok := service.mutations.Get(notice.RequestID); ok {
		t.Fatal("active runtime caused a durable approval mutation for another request")
	}
	grants, err := service.approvals.List(service.approvalAuthority)
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 0 {
		t.Fatalf("active runtime persisted standing grants: %#v", grants)
	}
	relay.mu.Lock()
	decisions := relay.decideCalls
	relay.mu.Unlock()
	if decisions != 0 {
		t.Fatalf("active runtime triggered %d relay decisions", decisions)
	}
}

func TestCrashRecoveryDoesNotResurrectLocallyRevokedStandingGrant(t *testing.T) {
	policy, _ := relayruntime.DefaultPolicy(relayruntime.PolicyReadOnly)
	controller, _ := NewController(&fakeAdapter{policy: policy}, mustSessionStore(t), 1)
	pending, _ := NewPendingStore(filepath.Join(t.TempDir(), "state", "pending.json"))
	notice := protocol.RequestNotice{
		RequestID: "req_revoke_crash_window", ConversationID: "conv_revoke_crash_window", Status: protocol.StatusAwaitingApproval,
		RequesterAgentID: "agent_alice", RequesterMemberID: "member_alice", RequesterDisplayName: "Alice",
	}
	if err := pending.Upsert(notice); err != nil {
		t.Fatal(err)
	}
	service, err := NewService(ServiceConfig{
		Client: &fakeRelayClient{}, Controller: controller, Pending: pending,
		DisplayName: "Recipient", DeviceName: "Laptop", ApprovalAuthorityFingerprint: "authority-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	service.approvalAuthority = ApprovalAuthority{Fingerprint: "authority-test", RecipientAgentID: "agent_recipient"}
	candidate, err := approvalCandidateForNotice(notice)
	if err != nil {
		t.Fatal(err)
	}
	grantID := stableApprovalGrantID(service.approvalAuthority, ApprovalLevelTeammateAlways, candidate)
	operation, _, err := service.prepareDecision(notice, protocol.DecisionAllowOnce, ApprovalLevelTeammateAlways, grantID, false)
	if err != nil {
		t.Fatal(err)
	}
	operation, ok := service.mutations.Get(notice.RequestID)
	if !ok {
		t.Fatal("prepared recovery operation was not persisted")
	}
	grant, err := service.approvals.Upsert(service.approvalAuthority, ApprovalLevelTeammateAlways, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if grant.GrantID != grantID {
		t.Fatalf("prepared grant ID = %q, persisted ID = %q", grantID, grant.GrantID)
	}
	if err := service.RevokeApprovalGrant(grantID); err != nil {
		t.Fatal(err)
	}

	recovered, err := service.ensurePreparedStandingGrant(notice.RequestID, operation)
	if err != nil {
		t.Fatal(err)
	}
	if !recovered.ApprovalGrantPersisted {
		t.Fatal("recovery did not acknowledge the durable grant-and-revocation history")
	}
	grants, err := service.ApprovalGrants()
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 0 {
		t.Fatalf("recovery resurrected revoked grants: %#v", grants)
	}
	if _, err := service.approvals.RestorePrepared(service.approvalAuthority, ApprovalLevelTeammateAlways, candidate, operation.UpdatedAt); !errors.Is(err, ErrApprovalGrantRevoked) {
		t.Fatalf("revocation tombstone was not durable after recovery: %v", err)
	}
}

func peerRequestEvent(t *testing.T, notice protocol.RequestNotice) client.Event {
	t.Helper()
	payload, err := json.Marshal(notice)
	if err != nil {
		t.Fatal(err)
	}
	return client.Event{Type: "peer_request", Payload: payload}
}

func waitForSubmittedResult(t *testing.T, results <-chan protocol.ResultPayload, requestID string) {
	t.Helper()
	select {
	case result := <-results:
		if result.State != protocol.StatusCompleted {
			t.Fatalf("request %s result = %#v", requestID, result)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("request %s did not complete", requestID)
	}
}

func waitForReceiverIdle(t *testing.T, service *Service) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for service.hasActiveExecution() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if service.hasActiveExecution() {
		t.Fatal("receiver did not become idle")
	}
}
