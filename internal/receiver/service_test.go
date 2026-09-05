package receiver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mohitbadwal/team-relay/internal/artifact"
	"github.com/mohitbadwal/team-relay/internal/client"
	"github.com/mohitbadwal/team-relay/internal/privatefs"
	"github.com/mohitbadwal/team-relay/internal/protocol"
	relayruntime "github.com/mohitbadwal/team-relay/internal/runtime"
)

type fakeRelayClient struct {
	mu            sync.Mutex
	inbox         protocol.InboxResponse
	payload       protocol.ExecutionPayload
	proposal      protocol.ProposalPayload
	order         []string
	heartbeat     chan struct{}
	heartbeatCard protocol.AgentCard
	submitted     chan protocol.ResultPayload
	artifacts     map[string]*protocol.ArtifactContent
	decideCalls   int
	decisions     []protocol.DecisionPayload
	inspectCalls  int
	markedClaim   string
	inboxErr      error
	stream        func(context.Context, func(client.Event) error) error
	getRequest    func(string) (*protocol.Request, error)
	decide        func(string, protocol.DecisionPayload) (*protocol.MutationResponse, error)
	markRunning   func(string, string) (*protocol.MutationResponse, error)
	submitResult  func(string, protocol.ResultPayload) (*protocol.MutationResponse, error)
}

func (f *fakeRelayClient) record(value string) {
	f.mu.Lock()
	f.order = append(f.order, value)
	f.mu.Unlock()
}

func (f *fakeRelayClient) Heartbeat(_ context.Context, _ protocol.AgentHeartbeat) (*protocol.AgentCard, error) {
	f.record("heartbeat")
	select {
	case f.heartbeat <- struct{}{}:
	default:
	}
	card := f.heartbeatCard
	if card.AgentID == "" {
		card.AgentID = "agent_recipient"
	}
	return &card, nil
}

func (f *fakeRelayClient) Inbox(context.Context) (*protocol.InboxResponse, error) {
	f.record("inbox")
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.inboxErr != nil {
		return nil, f.inboxErr
	}
	copy := f.inbox
	copy.Requests = append([]protocol.RequestNotice(nil), f.inbox.Requests...)
	return &copy, nil
}

func (f *fakeRelayClient) StreamEvents(ctx context.Context, onEvent func(client.Event) error) error {
	if f.stream != nil {
		return f.stream(ctx, onEvent)
	}
	<-ctx.Done()
	return ctx.Err()
}

func (f *fakeRelayClient) GetRequest(_ context.Context, requestID string) (*protocol.Request, error) {
	if f.getRequest != nil {
		return f.getRequest(requestID)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, notice := range f.inbox.Requests {
		if notice.RequestID == requestID {
			return &protocol.Request{RequestID: requestID, ConversationID: notice.ConversationID, Status: notice.Status}, nil
		}
	}
	return nil, fmt.Errorf("request %q is unavailable", requestID)
}

func (f *fakeRelayClient) Decide(_ context.Context, requestID string, decision protocol.DecisionPayload) (*protocol.MutationResponse, error) {
	f.mu.Lock()
	f.decideCalls++
	f.decisions = append(f.decisions, decision)
	f.mu.Unlock()
	f.record("decide:" + string(decision.Decision))
	if f.decide != nil {
		return f.decide(requestID, decision)
	}
	status := protocol.StatusAccepted
	if decision.Decision == protocol.DecisionDeny {
		status = protocol.StatusRejected
	}
	return &protocol.MutationResponse{RequestID: requestID, Status: status}, nil
}

func (f *fakeRelayClient) InspectProposal(_ context.Context, _ string) (*protocol.ProposalPayload, error) {
	f.mu.Lock()
	f.inspectCalls++
	f.mu.Unlock()
	f.record("inspect")
	copy := f.proposal
	copy.RequestedAccess = append([]protocol.RequestedAccess(nil), f.proposal.RequestedAccess...)
	copy.Attachments = append([]protocol.ArtifactDescriptor(nil), f.proposal.Attachments...)
	return &copy, nil
}

func (f *fakeRelayClient) FetchExecution(_ context.Context, _ string) (*protocol.ExecutionPayload, error) {
	f.record("fetch")
	copy := f.payload
	return &copy, nil
}

func TestReconnectBackoffResetsAfterHealthyAttempt(t *testing.T) {
	t.Parallel()

	var backoff reconnectBackoff
	want := []time.Duration{
		initialReconnectDelay,
		2 * initialReconnectDelay,
		4 * initialReconnectDelay,
		initialReconnectDelay,
		initialReconnectDelay,
		2 * initialReconnectDelay,
	}
	healthy := []bool{false, false, false, true, false, false}
	for index := range want {
		if got := backoff.next(healthy[index]); got != want[index] {
			t.Fatalf("attempt %d delay = %s, want %s", index, got, want[index])
		}
	}
	for range 10 {
		_ = backoff.next(false)
	}
	if got := backoff.next(false); got != maximumReconnectDelay {
		t.Fatalf("capped reconnect delay = %s, want %s", got, maximumReconnectDelay)
	}
}

func TestEventStreamAttemptTreatsReadyOrDurableReconciliationAsHealthy(t *testing.T) {
	t.Parallel()

	disconnected := errors.New("stream disconnected")
	inboxUnavailable := errors.New("inbox unavailable")
	for _, testCase := range []struct {
		name        string
		sendReady   bool
		inboxErr    error
		wantHealthy bool
	}{
		{name: "ready event", sendReady: true, inboxErr: inboxUnavailable, wantHealthy: true},
		{name: "durable reconciliation", wantHealthy: true},
		{name: "both paths unhealthy", inboxErr: inboxUnavailable, wantHealthy: false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			policy, _ := relayruntime.DefaultPolicy(relayruntime.PolicyReadOnly)
			relay := &fakeRelayClient{inboxErr: testCase.inboxErr}
			relay.stream = func(_ context.Context, onEvent func(client.Event) error) error {
				if testCase.sendReady {
					if err := onEvent(client.Event{Type: "ready", Payload: json.RawMessage(`{"api_version":"v1"}`)}); err != nil {
						return err
					}
				}
				return disconnected
			}
			controller, err := NewController(&fakeAdapter{policy: policy}, mustSessionStore(t), 1)
			if err != nil {
				t.Fatal(err)
			}
			pending, err := NewPendingStore(filepath.Join(t.TempDir(), "state", "pending.json"))
			if err != nil {
				t.Fatal(err)
			}
			service, err := NewService(ServiceConfig{
				Client: relay, Controller: controller, Pending: pending,
				DisplayName: "Recipient", DeviceName: "Laptop",
			})
			if err != nil {
				t.Fatal(err)
			}
			streamErr, reconcileErr, healthy := service.eventStreamAttempt(context.Background())
			if !errors.Is(streamErr, disconnected) {
				t.Fatalf("stream error = %v", streamErr)
			}
			if !errors.Is(reconcileErr, testCase.inboxErr) {
				t.Fatalf("reconcile error = %v, want %v", reconcileErr, testCase.inboxErr)
			}
			if healthy != testCase.wantHealthy {
				t.Fatalf("healthy = %t, want %t", healthy, testCase.wantHealthy)
			}
		})
	}
}

func TestInspectProposalFetchesFullPromptWithoutApprovingOrPersistingIt(t *testing.T) {
	policy, _ := relayruntime.DefaultPolicy(relayruntime.PolicyReadOnly)
	prompt := "Review the complete private proposal"
	digest := sha256.Sum256([]byte(prompt))
	expiresAt := time.Now().UTC().Add(time.Hour)
	notice := protocol.RequestNotice{
		RequestID: "req_inspect", ConversationID: "conv_inspect", Status: protocol.StatusAwaitingApproval,
		RequesterAgentID: "agent_sender", RequesterDisplayName: "Alice", Title: "Review",
		PromptPreview: "Review...", PromptBytes: int64(len([]byte(prompt))), PromptSHA256: hex.EncodeToString(digest[:]), ExpiresAt: expiresAt,
	}
	relay := &fakeRelayClient{proposal: protocol.ProposalPayload{
		RequestID: notice.RequestID, ConversationID: notice.ConversationID,
		RequesterAgentID: notice.RequesterAgentID, RequesterDisplayName: notice.RequesterDisplayName,
		Title: notice.Title, Prompt: prompt, ExpiresAt: expiresAt,
	}}
	controller, err := NewController(&fakeAdapter{policy: policy}, mustSessionStore(t), 1)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := NewPendingStore(filepath.Join(t.TempDir(), "state", "pending.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := pending.Upsert(notice); err != nil {
		t.Fatal(err)
	}
	service, err := NewService(ServiceConfig{Client: relay, Controller: controller, Pending: pending, DisplayName: "Recipient", DeviceName: "Laptop"})
	if err != nil {
		t.Fatal(err)
	}

	proposal, err := service.InspectProposal(context.Background(), notice.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	if proposal.Prompt != prompt {
		t.Fatalf("proposal prompt = %q", proposal.Prompt)
	}
	record, ok := pending.Get(notice.RequestID)
	if !ok || record.Notice.Status != protocol.StatusAwaitingApproval || record.Notice.PromptPreview != notice.PromptPreview {
		t.Fatalf("inspection mutated pending approval state: %#v, present=%v", record, ok)
	}
	relay.mu.Lock()
	decisions, inspections := relay.decideCalls, relay.inspectCalls
	relay.mu.Unlock()
	if decisions != 0 || inspections != 1 {
		t.Fatalf("inspection calls: decisions=%d inspections=%d", decisions, inspections)
	}

	relay.proposal.Prompt = "different prompt"
	if _, err := service.InspectProposal(context.Background(), notice.RequestID); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched proposal was accepted: %v", err)
	}
}

func (f *fakeRelayClient) MarkRunning(_ context.Context, requestID, executionClaimID string) (*protocol.MutationResponse, error) {
	f.mu.Lock()
	f.markedClaim = executionClaimID
	f.mu.Unlock()
	f.record("running")
	if f.markRunning != nil {
		return f.markRunning(requestID, executionClaimID)
	}
	return &protocol.MutationResponse{RequestID: requestID, Status: protocol.StatusRunning}, nil
}

func (f *fakeRelayClient) SubmitResult(_ context.Context, requestID string, result protocol.ResultPayload) (*protocol.MutationResponse, error) {
	f.record("result")
	if f.submitResult != nil {
		response, err := f.submitResult(requestID, result)
		f.submitted <- result
		return response, err
	}
	f.submitted <- result
	return &protocol.MutationResponse{RequestID: requestID, Status: result.State}, nil
}

func (f *fakeRelayClient) FetchArtifact(_ context.Context, artifactID string) (*protocol.ArtifactContent, error) {
	f.record("artifact:" + artifactID)
	content, ok := f.artifacts[artifactID]
	if !ok {
		return nil, fmt.Errorf("artifact %q is unavailable", artifactID)
	}
	copy := *content
	return &copy, nil
}

func TestAllowOnceRecordsDecisionBeforeStartingRuntime(t *testing.T) {
	policy, _ := relayruntime.DefaultPolicy(relayruntime.PolicyReadOnly)
	relay := &fakeRelayClient{
		heartbeat: make(chan struct{}, 2),
		submitted: make(chan protocol.ResultPayload, 1),
		payload: protocol.ExecutionPayload{
			RequestID: "req_1", ConversationID: "conv_1", RequesterDisplayName: "Alice", Title: "Question", Prompt: "What changed?",
		},
	}
	streamStarted := make(chan struct{})
	relay.stream = func(ctx context.Context, _ func(client.Event) error) error {
		close(streamStarted)
		<-ctx.Done()
		return ctx.Err()
	}
	adapter := &fakeAdapter{policy: policy, result: relayruntime.RunResult{FinalText: "The answer"}, onRun: func() { relay.record("run") }}
	controller, err := NewController(adapter, mustSessionStore(t), 1)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := NewPendingStore(filepath.Join(t.TempDir(), "state", "pending.json"))
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(ServiceConfig{
		Client: relay, Controller: controller, Pending: pending,
		DisplayName: "Recipient", DeviceName: "Laptop", AcceptingRequests: true,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), HeartbeatInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Run(ctx) }()
	select {
	case <-relay.heartbeat:
	case <-time.After(2 * time.Second):
		t.Fatal("service did not start")
	}
	select {
	case <-streamStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("service did not finish its initial reconciliation")
	}
	notice := executionNotice(relay.payload, protocol.StatusAwaitingApproval)
	notice.PromptPreview = "What changed?"
	payload, _ := json.Marshal(notice)
	if err := service.handleEvent(client.Event{Type: "peer_request", Payload: payload}); err != nil {
		t.Fatal(err)
	}
	if len(service.Pending()) != 1 {
		t.Fatal("request was not placed in local pending state")
	}
	if err := service.AllowOnce(context.Background(), "req_1"); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-relay.submitted:
		if result.State != protocol.StatusCompleted || result.Answer != "The answer" {
			t.Fatalf("unexpected submitted result: %#v", result)
		}
		relay.mu.Lock()
		markedClaim := relay.markedClaim
		relay.mu.Unlock()
		if result.ExecutionClaimID == "" || result.ExecutionClaimID != markedClaim {
			t.Fatalf("result claim = %q, marked claim = %q", result.ExecutionClaimID, markedClaim)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runtime result was not submitted")
	}
	relay.mu.Lock()
	order := append([]string(nil), relay.order...)
	relay.mu.Unlock()
	positions := map[string]int{}
	for index, value := range order {
		positions[value] = index
	}
	if !(positions["decide:allow_once"] < positions["fetch"] && positions["fetch"] < positions["running"] && positions["running"] < positions["run"] && positions["run"] < positions["result"]) {
		t.Fatalf("unsafe execution order: %#v", order)
	}
	if len(service.Pending()) != 0 {
		t.Fatal("completed request remained pending")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestExecutionPayloadMustMatchApprovedPendingNoticeBeforeMarkRunning(t *testing.T) {
	expiresAt := time.Date(2026, time.September, 5, 12, 0, 0, 0, time.UTC)
	base := protocol.ExecutionPayload{
		RequestID:            "req_bound_payload",
		ConversationID:       "conv_bound_payload",
		RequesterAgentID:     "agent_alice_laptop",
		RequesterMemberID:    "member_alice",
		RequesterDisplayName: "Alice",
		Title:                "Review change",
		Prompt:               "alpha beta",
		RequestedAccess: []protocol.RequestedAccess{{
			WorkspaceAlias: "repo", Mode: protocol.PermissionReadOnly,
		}},
		Attachments: []protocol.ArtifactDescriptor{{
			ArtifactID: "artifact_1", Name: "context.txt", MIMEType: "text/plain", SizeBytes: 10,
			SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		}},
		ExpiresAt: expiresAt,
	}
	notice := executionNotice(base, protocol.StatusAccepted)
	if err := validateExecutionPayload(notice, base); err != nil {
		t.Fatalf("valid execution payload was rejected: %v", err)
	}

	tests := []struct {
		name   string
		field  string
		mutate func(*protocol.ExecutionPayload)
	}{
		{name: "requester member", field: "authenticated requester member_id", mutate: func(payload *protocol.ExecutionPayload) {
			payload.RequesterMemberID = "member_mallory"
		}},
		{name: "requester agent", field: "requester_agent_id", mutate: func(payload *protocol.ExecutionPayload) {
			payload.RequesterAgentID = "agent_mallory_laptop"
		}},
		{name: "title", field: "title", mutate: func(payload *protocol.ExecutionPayload) {
			payload.Title = "Different task"
		}},
		{name: "prompt digest", field: "prompt SHA-256", mutate: func(payload *protocol.ExecutionPayload) {
			// Same byte length proves validation recomputes the digest instead of
			// relying only on the notice's prompt length.
			payload.Prompt = "alpha zeta"
		}},
		{name: "expiry", field: "expiry", mutate: func(payload *protocol.ExecutionPayload) {
			payload.ExpiresAt = expiresAt.Add(time.Minute)
		}},
		{name: "requested access", field: "requested access", mutate: func(payload *protocol.ExecutionPayload) {
			payload.RequestedAccess = []protocol.RequestedAccess{{WorkspaceAlias: "repo", Mode: protocol.PermissionGuardedWrite}}
		}},
		{name: "attachment descriptor", field: "attachment descriptors", mutate: func(payload *protocol.ExecutionPayload) {
			payload.Attachments = append([]protocol.ArtifactDescriptor(nil), payload.Attachments...)
			payload.Attachments[0].SHA256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		}},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			policy, _ := relayruntime.DefaultPolicy(relayruntime.PolicyReadOnly)
			mutated := base
			mutated.RequestedAccess = append([]protocol.RequestedAccess(nil), base.RequestedAccess...)
			mutated.Attachments = append([]protocol.ArtifactDescriptor(nil), base.Attachments...)
			testCase.mutate(&mutated)

			var logs bytes.Buffer
			relay := &fakeRelayClient{
				payload: mutated, submitted: make(chan protocol.ResultPayload, 1),
			}
			runCalled := false
			controller, err := NewController(&fakeAdapter{policy: policy, onRun: func() { runCalled = true }}, mustSessionStore(t), 1)
			if err != nil {
				t.Fatal(err)
			}
			pending, err := NewPendingStore(filepath.Join(t.TempDir(), "state", "pending.json"))
			if err != nil {
				t.Fatal(err)
			}
			if err := pending.Upsert(notice); err != nil {
				t.Fatal(err)
			}
			service, err := NewService(ServiceConfig{
				Client: relay, Controller: controller, Pending: pending,
				DisplayName: "Recipient", DeviceName: "Laptop",
				Logger: slog.New(slog.NewTextHandler(&logs, nil)),
			})
			if err != nil {
				t.Fatal(err)
			}
			service.approvalAuthority = ApprovalAuthority{
				Fingerprint: service.approvalFingerprint, RecipientAgentID: "agent_recipient",
			}
			putBoundApprovalClaim(t, service, notice, "agent_recipient")

			service.execute(context.Background(), notice.RequestID)

			relay.mu.Lock()
			markedClaim := relay.markedClaim
			order := append([]string(nil), relay.order...)
			relay.mu.Unlock()
			if markedClaim != "" || runCalled {
				t.Fatalf("mutated %s crossed execution boundary: claim=%q run=%t order=%v", testCase.field, markedClaim, runCalled, order)
			}
			if len(order) != 1 || order[0] != "fetch" {
				t.Fatalf("mutated %s caused calls after FetchExecution: %v", testCase.field, order)
			}
			if !strings.Contains(logs.String(), testCase.field) || !strings.Contains(logs.String(), notice.RequestID) {
				t.Fatalf("mutated %s did not produce a clear request-scoped diagnostic: %s", testCase.field, logs.String())
			}
		})
	}
}

func TestExecutionPayloadFailsClosedWithoutPendingPromptDigest(t *testing.T) {
	payload := protocol.ExecutionPayload{
		RequestID: "req_missing_digest", ConversationID: "conv_missing_digest",
		RequesterMemberID: "member_alice", Title: "Review", Prompt: "private prompt",
	}
	notice := executionNotice(payload, protocol.StatusAccepted)
	notice.PromptSHA256 = ""
	if err := validateExecutionPayload(notice, payload); err == nil || !strings.Contains(err.Error(), "missing or invalid") {
		t.Fatalf("payload without an approved prompt digest was accepted: %v", err)
	}
}

func TestApprovedNoticeBindingSurvivesMutablePendingAndPayloadReplacement(t *testing.T) {
	originalPayload := protocol.ExecutionPayload{
		RequestID: "req_colluding_replacement", ConversationID: "conv_original",
		RequesterAgentID: "agent_alice", RequesterMemberID: "member_alice", RequesterDisplayName: "Alice",
		Title: "Review original", Prompt: "original prompt", ExpiresAt: time.Now().UTC().Add(time.Hour),
		RequestedAccess: []protocol.RequestedAccess{{WorkspaceAlias: "repo", Mode: protocol.PermissionReadOnly}},
		Attachments: []protocol.ArtifactDescriptor{{
			ArtifactID: "artifact_original", Name: "original.txt", MIMEType: "text/plain", SizeBytes: 4,
			SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		}},
	}
	originalNotice := executionNotice(originalPayload, protocol.StatusAccepted)
	mutatedPayload := originalPayload
	mutatedPayload.ConversationID = "conv_replacement"
	mutatedPayload.RequesterAgentID = "agent_mallory"
	mutatedPayload.RequesterMemberID = "member_mallory"
	mutatedPayload.RequesterDisplayName = "Mallory"
	mutatedPayload.Title = "Run broader replacement"
	mutatedPayload.Prompt = "replacement prompt"
	mutatedPayload.ExpiresAt = originalPayload.ExpiresAt.Add(time.Hour)
	mutatedPayload.RequestedAccess = []protocol.RequestedAccess{{WorkspaceAlias: "repo", Mode: protocol.PermissionGuardedWrite}}
	mutatedPayload.Attachments = []protocol.ArtifactDescriptor{{
		ArtifactID: "artifact_replacement", Name: "replacement.txt", MIMEType: "text/plain", SizeBytes: 8,
		SHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}}
	mutatedNotice := executionNotice(mutatedPayload, protocol.StatusAccepted)

	policy, _ := relayruntime.DefaultPolicy(relayruntime.PolicyReadOnly)
	relay := &fakeRelayClient{payload: mutatedPayload, submitted: make(chan protocol.ResultPayload, 1)}
	runCalled := false
	controller, _ := NewController(&fakeAdapter{policy: policy, onRun: func() { runCalled = true }}, mustSessionStore(t), 1)
	pending, _ := NewPendingStore(filepath.Join(t.TempDir(), "state", "pending.json"))
	if err := pending.Upsert(originalNotice); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	service, _ := NewService(ServiceConfig{
		Client: relay, Controller: controller, Pending: pending, DisplayName: "Recipient", DeviceName: "Laptop",
		Logger: slog.New(slog.NewTextHandler(&logs, nil)),
	})
	service.approvalAuthority = ApprovalAuthority{Fingerprint: service.approvalFingerprint, RecipientAgentID: "agent_recipient"}
	putBoundApprovalClaim(t, service, originalNotice, "agent_recipient")
	if err := pending.Upsert(mutatedNotice); err != nil {
		t.Fatal(err)
	}

	service.execute(context.Background(), originalNotice.RequestID)

	relay.mu.Lock()
	order := append([]string(nil), relay.order...)
	marked := relay.markedClaim
	relay.mu.Unlock()
	if len(order) != 0 || marked != "" || runCalled {
		t.Fatalf("replacement pending notice and matching payload crossed execution boundary: order=%v claim=%q run=%t", order, marked, runCalled)
	}
	if !strings.Contains(logs.String(), "no longer matches the durably approved notice") {
		t.Fatalf("replacement refusal was not observable: %s", logs.String())
	}
}

func TestLegacyAuthorityBoundMutationWithoutApprovedNoticeNeverExecutes(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	notice := executionNotice(protocol.ExecutionPayload{
		RequestID: "req_legacy_notice", ConversationID: "conv_legacy_notice", Prompt: "do not run",
	}, protocol.StatusAccepted)
	pending, _ := NewPendingStore(filepath.Join(stateDir, "pending.json"))
	if err := pending.Upsert(notice); err != nil {
		t.Fatal(err)
	}
	legacy := mutationSnapshot{Version: authorityBoundMutationStoreVersion, Records: map[string]mutationRecord{
		notice.RequestID: {
			RequestID: notice.RequestID, ConversationID: notice.ConversationID,
			DecisionID: "decision_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Decision:   protocol.DecisionAllowOnce, ApprovalLevel: ApprovalLevelAskAlways,
			ApprovalAuthorityFingerprint: "authority-test", ApprovalRecipientAgentID: "agent_recipient",
			ExecutionClaimID: "claim_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Phase: mutationClaimPrepared,
		},
	}}
	encoded, _ := json.Marshal(legacy)
	if err := privatefs.AtomicWriteFile(filepath.Join(stateDir, "receiver_mutations.json"), append(encoded, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	policy, _ := relayruntime.DefaultPolicy(relayruntime.PolicyReadOnly)
	runCalled := false
	relay := &fakeRelayClient{payload: protocol.ExecutionPayload{RequestID: notice.RequestID}, submitted: make(chan protocol.ResultPayload, 1)}
	controller, _ := NewController(&fakeAdapter{policy: policy, onRun: func() { runCalled = true }}, mustSessionStore(t), 1)
	var logs bytes.Buffer
	service, err := NewService(ServiceConfig{
		Client: relay, Controller: controller, Pending: pending, DisplayName: "Recipient", DeviceName: "Laptop",
		Logger: slog.New(slog.NewTextHandler(&logs, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	service.approvalAuthority = ApprovalAuthority{Fingerprint: "authority-test", RecipientAgentID: "agent_recipient"}
	service.execute(context.Background(), notice.RequestID)
	relay.mu.Lock()
	order := append([]string(nil), relay.order...)
	relay.mu.Unlock()
	if len(order) != 0 || runCalled {
		t.Fatalf("legacy unbound notice executed: order=%v run=%t", order, runCalled)
	}
	if !strings.Contains(logs.String(), "no bound approved notice") {
		t.Fatalf("legacy refusal was not observable: %s", logs.String())
	}
}

func TestAllowOnceReusesDurableDecisionAfterAmbiguousResponse(t *testing.T) {
	policy, _ := relayruntime.DefaultPolicy(relayruntime.PolicyReadOnly)
	relay := &fakeRelayClient{
		heartbeat: make(chan struct{}, 2), submitted: make(chan protocol.ResultPayload, 1),
		payload: protocol.ExecutionPayload{
			RequestID: "req_retry_decision", ConversationID: "conv_retry_decision",
			RequesterDisplayName: "Alice", Title: "Retry", Prompt: "Run once",
		},
	}
	notice := executionNotice(relay.payload, protocol.StatusAwaitingApproval)
	// Keep the fake relay's durable inbox aligned with the local notice. The
	// receiver reconciles on every heartbeat, so inserting only into PendingStore
	// would model an impossible state that a legitimate reconciliation removes.
	relay.inbox.Requests = []protocol.RequestNotice{notice}
	retryStreamStarted := make(chan struct{})
	relay.stream = func(ctx context.Context, _ func(client.Event) error) error {
		close(retryStreamStarted)
		<-ctx.Done()
		return ctx.Err()
	}
	attempts := 0
	relay.decide = func(requestID string, _ protocol.DecisionPayload) (*protocol.MutationResponse, error) {
		attempts++
		if attempts == 1 {
			accepted := notice
			accepted.Status = protocol.StatusAccepted
			relay.mu.Lock()
			relay.inbox.Requests = []protocol.RequestNotice{accepted}
			relay.mu.Unlock()
			return nil, errors.New("response lost after relay commit")
		}
		return &protocol.MutationResponse{RequestID: requestID, Status: protocol.StatusAccepted}, nil
	}
	relay.submitResult = func(requestID string, result protocol.ResultPayload) (*protocol.MutationResponse, error) {
		relay.mu.Lock()
		relay.inbox.Requests = nil
		relay.mu.Unlock()
		return &protocol.MutationResponse{RequestID: requestID, Status: result.State}, nil
	}
	runCalled := make(chan struct{}, 1)
	controller, err := NewController(&fakeAdapter{
		policy: policy, result: relayruntime.RunResult{FinalText: "done"},
		onRun: func() { runCalled <- struct{}{} },
	}, mustSessionStore(t), 1)
	if err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(t.TempDir(), "state")
	pending, err := NewPendingStore(filepath.Join(stateDir, "pending.json"))
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(ServiceConfig{
		Client: relay, Controller: controller, Pending: pending,
		DisplayName: "Recipient", DeviceName: "Laptop", Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		HeartbeatInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Run(ctx) }()
	select {
	case <-relay.heartbeat:
	case <-time.After(2 * time.Second):
		t.Fatal("service did not start")
	}
	select {
	case <-retryStreamStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("service did not finish its initial reconciliation")
	}
	if err := service.AllowOnce(context.Background(), notice.RequestID); err == nil || !strings.Contains(err.Error(), "response lost") {
		t.Fatalf("first Allow Once error = %v", err)
	}
	prepared, ok := service.mutations.Get(notice.RequestID)
	if !ok || prepared.Phase != mutationDecisionPrepared || prepared.DecisionID == "" || prepared.ExecutionClaimID == "" {
		t.Fatalf("decision was not durably prepared: %#v, present=%t", prepared, ok)
	}
	select {
	case <-runCalled:
		t.Fatal("runtime started before the decision response was confirmed")
	default:
	}
	select {
	case <-relay.submitted:
	case <-time.After(2 * time.Second):
		t.Fatal("periodic reconciliation did not recover the ambiguous decision")
	}
	relay.mu.Lock()
	decisions := append([]protocol.DecisionPayload(nil), relay.decisions...)
	relay.mu.Unlock()
	if len(decisions) != 2 || decisions[0] != decisions[1] || decisions[0].DecisionID != prepared.DecisionID {
		t.Fatalf("decision retry identities = %#v", decisions)
	}
	waitForMutationRemoval(t, service, notice.RequestID)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRestartRecoversAmbiguousExecutionClaimWithoutDuplicateRuntime(t *testing.T) {
	policy, _ := relayruntime.DefaultPolicy(relayruntime.PolicyReadOnly)
	stateDir := filepath.Join(t.TempDir(), "state")
	pendingPath := filepath.Join(stateDir, "pending.json")
	payload := protocol.ExecutionPayload{
		RequestID: "req_claim_restart", ConversationID: "conv_claim_restart",
		RequesterDisplayName: "Alice", Title: "Recover", Prompt: "Execute once",
	}
	notice := executionNotice(payload, protocol.StatusAccepted)
	firstMarked := make(chan string, 1)
	firstRelay := &fakeRelayClient{
		heartbeat: make(chan struct{}, 1), submitted: make(chan protocol.ResultPayload, 1),
		inbox: protocol.InboxResponse{Requests: []protocol.RequestNotice{notice}}, payload: payload,
	}
	firstRelay.markRunning = func(_ string, claimID string) (*protocol.MutationResponse, error) {
		firstMarked <- claimID
		return nil, errors.New("running response lost after relay commit")
	}
	firstRun := make(chan struct{}, 1)
	firstController, _ := NewController(&fakeAdapter{policy: policy, onRun: func() { firstRun <- struct{}{} }}, mustSessionStore(t), 1)
	firstPending, err := NewPendingStore(pendingPath)
	if err != nil {
		t.Fatal(err)
	}
	firstService, err := NewService(ServiceConfig{
		Client: firstRelay, Controller: firstController, Pending: firstPending,
		DisplayName: "Recipient", DeviceName: "Laptop", Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	durableClaim := putBoundApprovalClaim(t, firstService, notice, "agent_recipient")
	firstCtx, firstCancel := context.WithCancel(context.Background())
	firstDone := make(chan error, 1)
	go func() { firstDone <- firstService.Run(firstCtx) }()
	select {
	case markedClaim := <-firstMarked:
		if markedClaim != durableClaim {
			t.Fatalf("marked claim = %q, want %q", markedClaim, durableClaim)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first receiver did not attempt its execution claim")
	}
	select {
	case <-firstRun:
		t.Fatal("runtime started after an ambiguous execution-claim response")
	default:
	}
	firstCancel()
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	prepared, ok := firstService.mutations.Get(notice.RequestID)
	if !ok || prepared.Phase != mutationClaimPrepared || prepared.ExecutionClaimID != durableClaim {
		t.Fatalf("claim was not recoverable: %#v, present=%t", prepared, ok)
	}

	runningNotice := notice
	runningNotice.Status = protocol.StatusRunning
	secondMarked := make(chan string, 1)
	secondRelay := &fakeRelayClient{
		heartbeat: make(chan struct{}, 1), submitted: make(chan protocol.ResultPayload, 1),
		inbox: protocol.InboxResponse{Requests: []protocol.RequestNotice{runningNotice}}, payload: payload,
	}
	secondRelay.markRunning = func(requestID, claimID string) (*protocol.MutationResponse, error) {
		secondMarked <- claimID
		return &protocol.MutationResponse{RequestID: requestID, Status: protocol.StatusRunning}, nil
	}
	secondRun := make(chan struct{}, 1)
	secondController, _ := NewController(&fakeAdapter{
		policy: policy, result: relayruntime.RunResult{FinalText: "recovered"},
		onRun: func() { secondRun <- struct{}{} },
	}, mustSessionStore(t), 1)
	secondPending, err := NewPendingStore(pendingPath)
	if err != nil {
		t.Fatal(err)
	}
	secondService, err := NewService(ServiceConfig{
		Client: secondRelay, Controller: secondController, Pending: secondPending,
		DisplayName: "Recipient", DeviceName: "Laptop", Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	secondCtx, secondCancel := context.WithCancel(context.Background())
	secondDone := make(chan error, 1)
	go func() { secondDone <- secondService.Run(secondCtx) }()
	select {
	case recoveredClaim := <-secondMarked:
		if recoveredClaim != durableClaim {
			t.Fatalf("recovered claim = %q, want %q", recoveredClaim, durableClaim)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second receiver did not recover the durable claim")
	}
	select {
	case <-secondRun:
	case <-time.After(2 * time.Second):
		t.Fatal("second receiver did not start the runtime")
	}
	select {
	case result := <-secondRelay.submitted:
		if result.ExecutionClaimID != durableClaim || result.Answer != "recovered" {
			t.Fatalf("recovered result = %#v", result)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second receiver did not submit the result")
	}
	secondCancel()
	if err := <-secondDone; err != nil {
		t.Fatal(err)
	}
}

func TestRestartReplaysExactPreparedResultWithoutRerunningRuntime(t *testing.T) {
	policy, _ := relayruntime.DefaultPolicy(relayruntime.PolicyReadOnly)
	stateDir := filepath.Join(t.TempDir(), "state")
	pendingPath := filepath.Join(stateDir, "pending.json")
	payload := protocol.ExecutionPayload{
		RequestID: "req_result_restart", ConversationID: "conv_result_restart",
		RequesterDisplayName: "Alice", Title: "Recover result", Prompt: "Execute once",
	}
	notice := executionNotice(payload, protocol.StatusAccepted)
	firstRelay := &fakeRelayClient{
		heartbeat: make(chan struct{}, 1), submitted: make(chan protocol.ResultPayload, 1),
		inbox: protocol.InboxResponse{Requests: []protocol.RequestNotice{notice}}, payload: payload,
	}
	firstRelay.submitResult = func(_ string, _ protocol.ResultPayload) (*protocol.MutationResponse, error) {
		return nil, errors.New("result response lost after relay commit")
	}
	firstRun := make(chan struct{}, 1)
	firstController, _ := NewController(&fakeAdapter{
		policy: policy, result: relayruntime.RunResult{FinalText: "durable answer"},
		onRun: func() { firstRun <- struct{}{} },
	}, mustSessionStore(t), 1)
	firstPending, err := NewPendingStore(pendingPath)
	if err != nil {
		t.Fatal(err)
	}
	firstService, err := NewService(ServiceConfig{
		Client: firstRelay, Controller: firstController, Pending: firstPending,
		DisplayName: "Recipient", DeviceName: "Laptop", Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	putBoundApprovalClaim(t, firstService, notice, "agent_recipient")
	firstCtx, firstCancel := context.WithCancel(context.Background())
	firstDone := make(chan error, 1)
	go func() { firstDone <- firstService.Run(firstCtx) }()
	var preparedResult protocol.ResultPayload
	select {
	case preparedResult = <-firstRelay.submitted:
	case <-time.After(2 * time.Second):
		t.Fatal("first receiver did not submit its result")
	}
	firstCancel()
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	operation, ok := firstService.mutations.Get(notice.RequestID)
	if !ok || operation.Phase != mutationResultPrepared || operation.Result == nil {
		t.Fatalf("result was not retained for exact replay: %#v, present=%t", operation, ok)
	}

	secondRelay := &fakeRelayClient{
		heartbeat: make(chan struct{}, 1), submitted: make(chan protocol.ResultPayload, 1),
		getRequest: func(requestID string) (*protocol.Request, error) {
			return &protocol.Request{RequestID: requestID, ConversationID: notice.ConversationID, Status: protocol.StatusCompleted}, nil
		},
	}
	secondRelay.submitResult = func(requestID string, result protocol.ResultPayload) (*protocol.MutationResponse, error) {
		return &protocol.MutationResponse{RequestID: requestID, Status: protocol.StatusCompleted}, nil
	}
	secondRun := make(chan struct{}, 1)
	secondController, _ := NewController(&fakeAdapter{policy: policy, onRun: func() { secondRun <- struct{}{} }}, mustSessionStore(t), 1)
	secondPending, err := NewPendingStore(pendingPath)
	if err != nil {
		t.Fatal(err)
	}
	secondService, err := NewService(ServiceConfig{
		Client: secondRelay, Controller: secondController, Pending: secondPending,
		DisplayName: "Recipient", DeviceName: "Laptop", Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	secondCtx, secondCancel := context.WithCancel(context.Background())
	secondDone := make(chan error, 1)
	go func() { secondDone <- secondService.Run(secondCtx) }()
	select {
	case replayed := <-secondRelay.submitted:
		if !sameResultPayload(replayed, preparedResult) {
			t.Fatalf("replayed result = %#v, want %#v", replayed, preparedResult)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("prepared result was not replayed")
	}
	select {
	case <-secondRun:
		t.Fatal("runtime reran while replaying a prepared result")
	default:
	}
	waitForMutationRemoval(t, secondService, notice.RequestID)
	secondCancel()
	if err := <-secondDone; err != nil {
		t.Fatal(err)
	}
}

func TestReceiverStateLockRejectsSecondDaemon(t *testing.T) {
	policy, _ := relayruntime.DefaultPolicy(relayruntime.PolicyReadOnly)
	stateDir := filepath.Join(t.TempDir(), "state")
	pendingPath := filepath.Join(stateDir, "pending.json")
	firstRelay := &fakeRelayClient{heartbeat: make(chan struct{}, 1), submitted: make(chan protocol.ResultPayload, 1)}
	firstController, _ := NewController(&fakeAdapter{policy: policy}, mustSessionStore(t), 1)
	firstPending, err := NewPendingStore(pendingPath)
	if err != nil {
		t.Fatal(err)
	}
	first, err := NewService(ServiceConfig{
		Client: firstRelay, Controller: firstController, Pending: firstPending,
		DisplayName: "Recipient", DeviceName: "Laptop",
	})
	if err != nil {
		t.Fatal(err)
	}
	firstCtx, firstCancel := context.WithCancel(context.Background())
	firstDone := make(chan error, 1)
	go func() { firstDone <- first.Run(firstCtx) }()
	select {
	case <-firstRelay.heartbeat:
	case <-time.After(2 * time.Second):
		t.Fatal("first receiver did not start")
	}

	secondRelay := &fakeRelayClient{heartbeat: make(chan struct{}, 1), submitted: make(chan protocol.ResultPayload, 1)}
	secondController, _ := NewController(&fakeAdapter{policy: policy}, mustSessionStore(t), 1)
	secondPending, err := NewPendingStore(pendingPath)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewService(ServiceConfig{
		Client: secondRelay, Controller: secondController, Pending: secondPending,
		DisplayName: "Recipient", DeviceName: "Laptop",
	})
	if err != nil {
		t.Fatal(err)
	}
	secondDone := make(chan error, 1)
	go func() { secondDone <- second.Run(context.Background()) }()
	select {
	case err := <-secondDone:
		if !errors.Is(err, errReceiverStateLocked) {
			t.Fatalf("second receiver error = %v, want state ownership conflict", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second receiver was not rejected")
	}
	select {
	case <-secondRelay.heartbeat:
		t.Fatal("second receiver contacted the relay before acquiring state ownership")
	default:
	}

	firstCancel()
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	secondCtx, secondCancel := context.WithCancel(context.Background())
	secondRestarted := make(chan error, 1)
	go func() { secondRestarted <- second.Run(secondCtx) }()
	select {
	case <-secondRelay.heartbeat:
	case err := <-secondRestarted:
		t.Fatalf("second receiver did not acquire released state ownership: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("second receiver did not start after state ownership was released")
	}
	secondCancel()
	if err := <-secondRestarted; err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentAcceptedRecoveryWithoutBoundAllowNeverInventsClaim(t *testing.T) {
	policy, _ := relayruntime.DefaultPolicy(relayruntime.PolicyReadOnly)
	relay := &fakeRelayClient{heartbeat: make(chan struct{}, 1), submitted: make(chan protocol.ResultPayload, 1)}
	controller, _ := NewController(&fakeAdapter{policy: policy}, mustSessionStore(t), 1)
	pending, _ := NewPendingStore(filepath.Join(t.TempDir(), "state", "pending.json"))
	service, _ := NewService(ServiceConfig{
		Client: relay, Controller: controller, Pending: pending, DisplayName: "Recipient", DeviceName: "Laptop",
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	const callers = 32
	start := make(chan struct{})
	errorsChannel := make(chan error, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if err := service.recoverOperation(context.Background(), "req_concurrent_recovery", "conv_concurrent_recovery", protocol.StatusAccepted); err != nil {
				errorsChannel <- err
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		t.Fatal(err)
	}
	if operation, ok := service.mutations.Get("req_concurrent_recovery"); ok {
		t.Fatalf("unbound accepted request invented a durable claim: %#v", operation)
	}
}

func TestAllowOnceRecoversAlreadyAcceptedNoticeWithoutNewDecision(t *testing.T) {
	policy, _ := relayruntime.DefaultPolicy(relayruntime.PolicyReadOnly)
	relay := &fakeRelayClient{heartbeat: make(chan struct{}, 1), submitted: make(chan protocol.ResultPayload, 1)}
	controller, _ := NewController(&fakeAdapter{policy: policy}, mustSessionStore(t), 1)
	pending, _ := NewPendingStore(filepath.Join(t.TempDir(), "state", "pending.json"))
	notice := protocol.RequestNotice{RequestID: "req_already_accepted", ConversationID: "conv_already_accepted", Status: protocol.StatusAccepted}
	if err := pending.Upsert(notice); err != nil {
		t.Fatal(err)
	}
	service, _ := NewService(ServiceConfig{Client: relay, Controller: controller, Pending: pending, DisplayName: "Recipient", DeviceName: "Laptop"})
	if err := service.AllowOnce(context.Background(), notice.RequestID); err == nil || !strings.Contains(err.Error(), "without a locally bound approval") {
		t.Fatalf("accepted recovery while stopped error = %v", err)
	}
	relay.mu.Lock()
	decisions := relay.decideCalls
	relay.mu.Unlock()
	if decisions != 0 {
		t.Fatalf("already accepted request sent %d new decisions", decisions)
	}
	if operation, ok := service.mutations.Get(notice.RequestID); ok {
		t.Fatalf("accepted request invented recovery state = %#v", operation)
	}
}

func TestAllowOnceDoesNotInventDecisionOrReplayAlreadyRunningNotice(t *testing.T) {
	policy, _ := relayruntime.DefaultPolicy(relayruntime.PolicyReadOnly)
	notice := protocol.RequestNotice{
		RequestID: "req_already_running", ConversationID: "conv_already_running", Status: protocol.StatusRunning,
	}
	relay := &fakeRelayClient{
		heartbeat: make(chan struct{}, 1), submitted: make(chan protocol.ResultPayload, 1),
		inbox: protocol.InboxResponse{Requests: []protocol.RequestNotice{notice}},
	}
	streamStarted := make(chan struct{})
	relay.stream = func(ctx context.Context, _ func(client.Event) error) error {
		close(streamStarted)
		<-ctx.Done()
		return ctx.Err()
	}
	runCalled := make(chan struct{}, 1)
	controller, _ := NewController(&fakeAdapter{
		policy: policy,
		onRun:  func() { runCalled <- struct{}{} },
	}, mustSessionStore(t), 1)
	pending, _ := NewPendingStore(filepath.Join(t.TempDir(), "state", "pending.json"))
	service, _ := NewService(ServiceConfig{
		Client: relay, Controller: controller, Pending: pending,
		DisplayName: "Recipient", DeviceName: "Laptop", HeartbeatInterval: time.Hour,
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Run(ctx) }()
	select {
	case <-relay.heartbeat:
	case <-time.After(2 * time.Second):
		t.Fatal("receiver did not start")
	}
	select {
	case <-streamStarted:
	case err := <-done:
		t.Fatalf("receiver exited before reconciliation completed: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("receiver did not finish initial reconciliation")
	}

	if err := service.AllowOnce(context.Background(), notice.RequestID); err == nil || !strings.Contains(err.Error(), "without a locally bound approval") {
		t.Fatalf("running recovery without a bound allow error = %v", err)
	}
	relay.mu.Lock()
	decisions := relay.decideCalls
	relay.mu.Unlock()
	if decisions != 0 {
		t.Fatalf("already running request sent %d new decisions", decisions)
	}
	if _, ok := service.mutations.Get(notice.RequestID); ok {
		t.Fatal("already running request without a journal invented durable state")
	}
	select {
	case <-runCalled:
		t.Fatal("already running request without a journal replayed the runtime")
	default:
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestReconcileCancellationStopsActiveRuntime(t *testing.T) {
	policy, _ := relayruntime.DefaultPolicy(relayruntime.PolicyReadOnly)
	executionPayload := protocol.ExecutionPayload{
		RequestID: "req_cancel_reconcile", ConversationID: "conv_cancel_reconcile",
		RequesterDisplayName: "Alice", Title: "Cancel", Prompt: "Wait",
	}
	notice := executionNotice(executionPayload, protocol.StatusAccepted)
	runGate := make(chan struct{})
	relay := &fakeRelayClient{
		heartbeat: make(chan struct{}, 1), submitted: make(chan protocol.ResultPayload, 1),
		inbox:   protocol.InboxResponse{Requests: []protocol.RequestNotice{notice}},
		payload: executionPayload,
		getRequest: func(requestID string) (*protocol.Request, error) {
			return &protocol.Request{RequestID: requestID, ConversationID: notice.ConversationID, Status: protocol.StatusCancelled}, nil
		},
	}
	controller, _ := NewController(&fakeAdapter{policy: policy, runGate: runGate}, mustSessionStore(t), 1)
	pending, _ := NewPendingStore(filepath.Join(t.TempDir(), "state", "pending.json"))
	service, _ := NewService(ServiceConfig{
		Client: relay, Controller: controller, Pending: pending,
		DisplayName: "Recipient", DeviceName: "Laptop", HeartbeatInterval: time.Hour,
	})
	putBoundApprovalClaim(t, service, notice, "agent_recipient")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Run(ctx) }()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		operation, ok := service.mutations.Get(notice.RequestID)
		if ok && operation.Phase == mutationRuntimeStarted && service.hasActiveRequest(notice.RequestID) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	operation, ok := service.mutations.Get(notice.RequestID)
	if !ok || operation.Phase != mutationRuntimeStarted || !service.hasActiveRequest(notice.RequestID) {
		t.Fatalf("runtime did not reach active boundary: %#v, present=%t", operation, ok)
	}
	relay.mu.Lock()
	relay.inbox.Requests = nil
	relay.mu.Unlock()
	if err := service.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && service.hasActiveRequest(notice.RequestID) {
		time.Sleep(time.Millisecond)
	}
	if service.hasActiveRequest(notice.RequestID) {
		t.Fatal("reconciled cancellation did not stop the active runtime")
	}
	if _, ok := service.mutations.Get(notice.RequestID); ok {
		t.Fatal("cancelled request retained its mutation journal")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestStartupDiscardsJournalForRequestNoLongerRetainedByRelay(t *testing.T) {
	policy, _ := relayruntime.DefaultPolicy(relayruntime.PolicyReadOnly)
	streamStarted := make(chan struct{})
	relay := &fakeRelayClient{
		heartbeat: make(chan struct{}, 1), submitted: make(chan protocol.ResultPayload, 1),
		getRequest: func(string) (*protocol.Request, error) {
			return nil, &client.Error{StatusCode: 404, Code: "not_found", Message: "resource was not found"}
		},
		stream: func(ctx context.Context, _ func(client.Event) error) error {
			close(streamStarted)
			<-ctx.Done()
			return ctx.Err()
		},
	}
	controller, _ := NewController(&fakeAdapter{policy: policy}, mustSessionStore(t), 1)
	pending, _ := NewPendingStore(filepath.Join(t.TempDir(), "state", "pending.json"))
	service, _ := NewService(ServiceConfig{Client: relay, Controller: controller, Pending: pending, DisplayName: "Recipient", DeviceName: "Laptop"})
	if err := service.mutations.Put(mutationRecord{
		RequestID: "req_purged", ConversationID: "conv_purged",
		ExecutionClaimID: "claim_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Phase: mutationRuntimeStarted,
	}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Run(ctx) }()
	select {
	case <-streamStarted:
	case err := <-done:
		t.Fatalf("receiver exited on purged journal: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("receiver did not finish startup reconciliation")
	}
	if _, ok := service.mutations.Get("req_purged"); ok {
		t.Fatal("purged relay request retained its orphaned local journal")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func sameResultPayload(left, right protocol.ResultPayload) bool {
	leftJSON, _ := json.Marshal(left)
	rightJSON, _ := json.Marshal(right)
	return string(leftJSON) == string(rightJSON)
}

func waitForMutationRemoval(t *testing.T, service *Service, requestID string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := service.mutations.Get(requestID); !ok {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("request %q retained its durable mutation after success", requestID)
}

func executionNotice(payload protocol.ExecutionPayload, status protocol.RequestStatus) protocol.RequestNotice {
	digest := sha256.Sum256([]byte(payload.Prompt))
	return protocol.RequestNotice{
		RequestID:            payload.RequestID,
		ConversationID:       payload.ConversationID,
		Status:               status,
		RequesterAgentID:     payload.RequesterAgentID,
		RequesterMemberID:    payload.RequesterMemberID,
		RequesterDisplayName: payload.RequesterDisplayName,
		Title:                payload.Title,
		PromptBytes:          int64(len([]byte(payload.Prompt))),
		PromptSHA256:         hex.EncodeToString(digest[:]),
		RequestedAccess:      append([]protocol.RequestedAccess(nil), payload.RequestedAccess...),
		Attachments:          append([]protocol.ArtifactDescriptor(nil), payload.Attachments...),
		ExpiresAt:            payload.ExpiresAt,
	}
}

func putBoundApprovalClaim(t *testing.T, service *Service, notice protocol.RequestNotice, recipientAgentID string) string {
	t.Helper()
	approvedNotice, err := approvedNoticeBindingFor(notice)
	if err != nil {
		t.Fatal(err)
	}
	decisionID, err := newOpaqueID("decision_")
	if err != nil {
		t.Fatal(err)
	}
	claimID, err := newExecutionClaimID()
	if err != nil {
		t.Fatal(err)
	}
	if err := service.mutations.Put(mutationRecord{
		RequestID: notice.RequestID, ConversationID: notice.ConversationID,
		DecisionID: decisionID, Decision: protocol.DecisionAllowOnce, ApprovalLevel: ApprovalLevelAskAlways,
		ApprovalAuthorityFingerprint: service.approvalFingerprint, ApprovalRecipientAgentID: recipientAgentID,
		ApprovedNotice: approvedNotice, ExecutionClaimID: claimID, Phase: mutationClaimPrepared,
	}); err != nil {
		t.Fatal(err)
	}
	return claimID
}

func TestAttachmentCannotBeApprovedWithoutLocalMaterializer(t *testing.T) {
	policy, _ := relayruntime.DefaultPolicy(relayruntime.PolicyReadOnly)
	relay := &fakeRelayClient{heartbeat: make(chan struct{}, 1), submitted: make(chan protocol.ResultPayload, 1)}
	controller, _ := NewController(&fakeAdapter{policy: policy}, mustSessionStore(t), 1)
	pending, _ := NewPendingStore(filepath.Join(t.TempDir(), "state", "pending.json"))
	service, _ := NewService(ServiceConfig{Client: relay, Controller: controller, Pending: pending, DisplayName: "Recipient", DeviceName: "Laptop"})
	notice := protocol.RequestNotice{
		RequestID: "req_file", ConversationID: "conv_file", Status: protocol.StatusAwaitingApproval,
		Attachments: []protocol.ArtifactDescriptor{{ArtifactID: "art_1", Name: "file.txt"}},
	}
	if err := pending.Upsert(notice); err != nil {
		t.Fatal(err)
	}
	err := service.AllowOnce(context.Background(), "req_file")
	if err == nil {
		t.Fatal("attachment request was approved without materialization support")
	}
	relay.mu.Lock()
	decisions := relay.decideCalls
	relay.mu.Unlock()
	if decisions != 0 {
		t.Fatal("relay decision was recorded before local support validation")
	}
}

func TestReadOnlyWorkspaceGrantIsRejectedBeforeDecisionWhenLocalPolicyAllowsWrites(t *testing.T) {
	policy, _ := relayruntime.DefaultPolicy(relayruntime.PolicyGuardedWrite)
	relay := &fakeRelayClient{heartbeat: make(chan struct{}, 1), submitted: make(chan protocol.ResultPayload, 1)}
	controller, err := NewController(&fakeAdapter{policy: policy}, mustSessionStore(t), 1)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := NewPendingStore(filepath.Join(t.TempDir(), "state", "pending.json"))
	if err != nil {
		t.Fatal(err)
	}
	notice := protocol.RequestNotice{
		RequestID: "req_mixed_access", ConversationID: "conv_mixed_access", Status: protocol.StatusAwaitingApproval,
		RequestedAccess: []protocol.RequestedAccess{{WorkspaceAlias: "repo", Mode: protocol.PermissionReadOnly}},
	}
	if err := pending.Upsert(notice); err != nil {
		t.Fatal(err)
	}
	service, err := NewService(ServiceConfig{
		Client: relay, Controller: controller, Pending: pending,
		DisplayName: "Recipient", DeviceName: "Laptop", Workspaces: map[string]string{"repo": t.TempDir()},
	})
	if err != nil {
		t.Fatal(err)
	}

	err = service.AllowOnce(context.Background(), notice.RequestID)
	if err == nil || !strings.Contains(err.Error(), "cannot enforce") {
		t.Fatalf("mixed workspace policy was accepted: %v", err)
	}
	relay.mu.Lock()
	decisions := relay.decideCalls
	relay.mu.Unlock()
	if decisions != 0 {
		t.Fatal("relay decision was recorded before mixed workspace policy was rejected")
	}
}

func TestApprovedAttachmentWorkspaceAndReturnedFileFlow(t *testing.T) {
	policy, _ := relayruntime.DefaultPolicy(relayruntime.PolicyGuardedWrite)
	input := []byte("review me")
	digest := sha256.Sum256(input)
	descriptor := protocol.ArtifactDescriptor{
		ArtifactID: "art_input", Name: "input.txt", MIMEType: "text/plain",
		SizeBytes: int64(len(input)), SHA256: hex.EncodeToString(digest[:]),
	}
	content := &protocol.ArtifactContent{
		ArtifactDescriptor: descriptor, Encoding: "base64", ContentBase64: base64.StdEncoding.EncodeToString(input),
	}
	workspace := t.TempDir()
	canonicalWorkspace, err := filepath.EvalSymlinks(workspace)
	if err != nil {
		t.Fatal(err)
	}
	relay := &fakeRelayClient{
		heartbeat: make(chan struct{}, 2), submitted: make(chan protocol.ResultPayload, 1),
		artifacts: map[string]*protocol.ArtifactContent{"art_input": content},
		payload: protocol.ExecutionPayload{
			RequestID: "req_file", ConversationID: "conv_file", RequesterDisplayName: "Alice", Title: "Review", Prompt: "Review the attachment",
			Attachments:     []protocol.ArtifactDescriptor{descriptor},
			RequestedAccess: []protocol.RequestedAccess{{WorkspaceAlias: "repo", Mode: protocol.PermissionGuardedWrite}},
		},
	}
	adapter := &fakeAdapter{policy: policy, result: relayruntime.RunResult{FinalText: "Done"}}
	adapter.onRequest = func(request relayruntime.RunRequest) {
		if len(request.Attachments) != 1 || len(request.Workspaces) != 1 || request.Workspaces[0].Path != canonicalWorkspace || request.Workspaces[0].Mode != relayruntime.WorkspaceWritable {
			t.Errorf("runtime request grants = %#v", request)
			return
		}
		payload, err := os.ReadFile(request.Attachments[0])
		if err != nil || string(payload) != string(input) {
			t.Errorf("runtime attachment = %q, %v", payload, err)
			return
		}
		if err := os.WriteFile(filepath.Join(request.ReturnDirectory, "findings.md"), []byte("# Findings\n"), 0o600); err != nil {
			t.Errorf("write returned file: %v", err)
		}
	}
	controller, err := NewController(adapter, mustSessionStore(t), 1)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := NewPendingStore(filepath.Join(t.TempDir(), "state", "pending.json"))
	if err != nil {
		t.Fatal(err)
	}
	artifacts, err := artifact.NewManager(filepath.Join(t.TempDir(), "artifacts"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = artifacts.Close() })
	service, err := NewService(ServiceConfig{
		Client: relay, Controller: controller, Pending: pending, Artifacts: artifacts,
		DisplayName: "Recipient", DeviceName: "Laptop", AcceptingRequests: true,
		Workspaces: map[string]string{"repo": workspace}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), HeartbeatInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Run(ctx) }()
	select {
	case <-relay.heartbeat:
	case <-time.After(2 * time.Second):
		t.Fatal("service did not start")
	}
	notice := executionNotice(relay.payload, protocol.StatusAwaitingApproval)
	encoded, _ := json.Marshal(notice)
	if err := service.handleEvent(client.Event{Type: "peer_request", Payload: encoded}); err != nil {
		t.Fatal(err)
	}
	if err := service.AllowOnce(context.Background(), "req_file"); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-relay.submitted:
		if result.State != protocol.StatusCompleted || result.Answer != "Done" || len(result.ResultFiles) != 1 || result.ResultFiles[0].Name != "findings.md" {
			t.Fatalf("unexpected result: %#v", result)
		}
		relay.mu.Lock()
		markedClaim := relay.markedClaim
		relay.mu.Unlock()
		if result.ExecutionClaimID == "" || result.ExecutionClaimID != markedClaim {
			t.Fatalf("result claim = %q, marked claim = %q", result.ExecutionClaimID, markedClaim)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runtime result was not submitted")
	}
	relay.mu.Lock()
	order := append([]string(nil), relay.order...)
	relay.mu.Unlock()
	positions := map[string]int{}
	for index, value := range order {
		positions[value] = index
	}
	if !(positions["decide:allow_once"] < positions["fetch"] && positions["fetch"] < positions["running"] && positions["running"] < positions["artifact:art_input"]) {
		t.Fatalf("attachment was released before approval/running: %#v", order)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRunningInboxEntryIsNeverAutomaticallyReplayed(t *testing.T) {
	policy, _ := relayruntime.DefaultPolicy(relayruntime.PolicyReadOnly)
	relay := &fakeRelayClient{
		heartbeat: make(chan struct{}, 1), submitted: make(chan protocol.ResultPayload, 1),
		inbox: protocol.InboxResponse{Requests: []protocol.RequestNotice{{RequestID: "req_running", ConversationID: "conv", Status: protocol.StatusRunning}}},
	}
	runCalled := make(chan struct{}, 1)
	controller, _ := NewController(&fakeAdapter{policy: policy, onRun: func() { runCalled <- struct{}{} }}, mustSessionStore(t), 1)
	pending, _ := NewPendingStore(filepath.Join(t.TempDir(), "state", "pending.json"))
	service, _ := NewService(ServiceConfig{Client: relay, Controller: controller, Pending: pending, DisplayName: "Recipient", DeviceName: "Laptop", Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err := service.mutations.Put(mutationRecord{
		RequestID: "req_running", ConversationID: "conv", ExecutionClaimID: "claim_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Phase: mutationRuntimeStarted,
	}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Run(ctx) }()
	select {
	case <-relay.heartbeat:
	case <-time.After(2 * time.Second):
		t.Fatal("service did not start")
	}
	select {
	case <-runCalled:
		t.Fatal("previously running request was replayed")
	case <-time.After(100 * time.Millisecond):
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func mustSessionStore(t *testing.T) *FileSessionStore {
	t.Helper()
	store, err := NewFileSessionStore(filepath.Join(t.TempDir(), "state", "sessions.json"))
	if err != nil {
		t.Fatal(err)
	}
	return store
}
