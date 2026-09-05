package integration_test

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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/mohitbadwal/team-relay/internal/auth"
	"github.com/mohitbadwal/team-relay/internal/client"
	"github.com/mohitbadwal/team-relay/internal/collaboration"
	"github.com/mohitbadwal/team-relay/internal/protocol"
	"github.com/mohitbadwal/team-relay/internal/server"
	"github.com/mohitbadwal/team-relay/internal/store"
	"github.com/redis/go-redis/v9"
)

const (
	integrationClaimA = "claim_1111111111111111111111111111111111111111111111111111111111111111"
	integrationClaimB = "claim_2222222222222222222222222222222222222222222222222222222222222222"
)

func TestHTTPRelayApprovalAttachmentResultAndFollowUp(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	mini := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	bootstrapToken, err := auth.NewToken(auth.TokenBootstrap)
	if err != nil {
		t.Fatal(err)
	}
	repository := store.NewRedis(rdb)
	collaborationStore := collaboration.NewRedisStore(rdb)
	hub := collaboration.NewHub()
	adminHandler := server.NewHandler(repository, server.Config{
		BootstrapToken:    bootstrapToken,
		RevocationEvicter: collaboration.NewRevocationEvicter(collaborationStore, hub),
	}, nil)
	mux := http.NewServeMux()
	adminHandler.RegisterRoutes(mux)
	collaboration.NewHandler(
		collaborationStore,
		adminHandler.AuthenticateRequest,
		hub,
		nil,
	).RegisterRoutes(mux)
	httpServer := httptest.NewServer(server.WithSecurityHeaders(mux))
	t.Cleanup(httpServer.Close)

	adminToken, err := auth.NewToken(auth.TokenAdmin)
	if err != nil {
		t.Fatal(err)
	}
	doJSON(t, httpServer.Client(), http.MethodPost, httpServer.URL+"/v1/bootstrap", bootstrapToken, map[string]any{
		"organization_name":  "Protocol Test Team",
		"admin_display_name": "Test Admin",
		"admin_email":        "admin@example.test",
		"admin_token_hash":   auth.Hash(adminToken),
		"idempotency_key":    "tr_bootstrap_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}, http.StatusCreated, nil)
	requester := enrollDevice(t, httpServer, adminToken, "Requester", "requester@example.test", "Requester laptop", "codex")
	target := enrollDevice(t, httpServer, adminToken, "Recipient", "recipient@example.test", "Recipient laptop", "claude-code")

	requesterClient, err := client.New(httpServer.URL, requester.token, httpServer.Client())
	if err != nil {
		t.Fatal(err)
	}
	targetClient, err := client.New(httpServer.URL, target.token, httpServer.Client())
	if err != nil {
		t.Fatal(err)
	}
	for _, peer := range []struct {
		client  *client.Client
		runtime string
		name    string
	}{
		{client: requesterClient, runtime: "codex", name: "Requester"},
		{client: targetClient, runtime: "claude-code", name: "Recipient"},
	} {
		if _, err := peer.client.Heartbeat(ctx, protocol.AgentHeartbeat{
			DisplayName: peer.name, Availability: protocol.AvailabilityAvailable, AcceptingRequests: true,
			Runtime: protocol.RuntimeDescriptor{
				ID: peer.runtime, DisplayName: peer.runtime,
				Capabilities: protocol.RuntimeCapabilities{ReadOnly: true, ReturnedFiles: true},
			},
			PermissionMode:   protocol.PermissionReadOnly,
			Capabilities:     []string{"code-review"},
			WorkspaceAliases: []string{"sample-repo"},
		}); err != nil {
			t.Fatalf("publish %s heartbeat: %v", peer.name, err)
		}
	}

	directory, err := requesterClient.ListAgents(ctx, client.AgentQuery{
		Capabilities: []string{"code-review"}, WorkspaceAliases: []string{"sample-repo"},
		OnlineOnly: true, AcceptingOnly: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(directory.Agents) != 1 || directory.Agents[0].AgentID != target.agentID {
		t.Fatalf("unexpected teammate discovery: %#v", directory.Agents)
	}

	inputBytes := []byte("package example\n")
	inputAttachment := makeAttachment("sample.go", "text/x-go", inputBytes)
	fullPrompt := "Review the attached Go file and return a concise Markdown report."
	created, err := requesterClient.CreateRequest(ctx, protocol.CreateRequest{
		TargetAgentID: target.agentID,
		Title:         "Review sample",
		Prompt:        fullPrompt,
		RequestedAccess: []protocol.RequestedAccess{{
			WorkspaceAlias: "sample-repo", Mode: protocol.PermissionReadOnly,
		}},
		Attachments:      []protocol.AttachmentInput{inputAttachment},
		ExpiresInSeconds: 600,
		IdempotencyKey:   "http-e2e-initial",
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.Status != protocol.StatusAwaitingApproval {
		t.Fatalf("new request status = %q", created.Status)
	}

	proposal, err := targetClient.InspectProposal(ctx, created.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	if proposal.Prompt != fullPrompt || proposal.ConversationID != created.ConversationID ||
		proposal.RequesterMemberID != requester.memberID || len(proposal.Attachments) != 1 {
		t.Fatalf("unexpected inspectable proposal: %#v", proposal)
	}
	proposalJSON, err := json.Marshal(proposal)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(proposalJSON, []byte(inputAttachment.ContentBase64)) || bytes.Contains(proposalJSON, []byte("content_base64")) {
		t.Fatalf("proposal disclosed attachment bytes: %s", proposalJSON)
	}
	assertRelayError(t, func() error {
		_, err := targetClient.FetchExecution(ctx, created.RequestID)
		return err
	}, http.StatusConflict, "conflict")
	assertRelayError(t, func() error {
		_, err := targetClient.FetchArtifact(ctx, proposal.Attachments[0].ArtifactID)
		return err
	}, http.StatusConflict, "conflict")

	allowDecision := protocol.DecisionPayload{
		Decision:   protocol.DecisionAllowOnce,
		DecisionID: "decision_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	decision, err := targetClient.Decide(ctx, created.RequestID, allowDecision)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Status != protocol.StatusAccepted {
		t.Fatalf("allow-once status = %q", decision.Status)
	}
	execution, err := targetClient.FetchExecution(ctx, created.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	if execution.Prompt != fullPrompt || execution.RequesterMemberID != requester.memberID || len(execution.Attachments) != 1 {
		t.Fatalf("unexpected approved execution: %#v", execution)
	}
	downloadedInput, err := targetClient.FetchArtifact(ctx, execution.Attachments[0].ArtifactID)
	if err != nil {
		t.Fatal(err)
	}
	if downloadedInput.ContentBase64 != inputAttachment.ContentBase64 {
		t.Fatalf("approved input content = %q, want %q", downloadedInput.ContentBase64, inputAttachment.ContentBase64)
	}
	if _, err := targetClient.MarkRunning(ctx, created.RequestID, integrationClaimA); err != nil {
		t.Fatal(err)
	}
	if _, err := targetClient.MarkRunning(ctx, created.RequestID, integrationClaimA); err != nil {
		t.Fatalf("idempotent execution claim retry: %v", err)
	}
	assertRelayError(t, func() error {
		_, err := targetClient.MarkRunning(ctx, created.RequestID, integrationClaimB)
		return err
	}, http.StatusConflict, "conflict")
	replayedDecision, err := targetClient.Decide(ctx, created.RequestID, allowDecision)
	if err != nil || replayedDecision.Status != protocol.StatusRunning {
		t.Fatalf("decision replay after claim = %#v, %v", replayedDecision, err)
	}
	resultBytes := []byte("# Review\n\nThe sample is intentionally small.\n")
	resultAttachment := makeAttachment("review.md", "text/markdown", resultBytes)
	assertRelayError(t, func() error {
		_, err := targetClient.SubmitResult(ctx, created.RequestID, protocol.ResultPayload{
			ExecutionClaimID: integrationClaimB, State: protocol.StatusCompleted, Answer: "Wrong daemon",
		})
		return err
	}, http.StatusConflict, "conflict")
	resultPayload := protocol.ResultPayload{
		ExecutionClaimID: integrationClaimA, State: protocol.StatusCompleted, Answer: "Review complete.",
		ResultFiles: []protocol.AttachmentInput{resultAttachment},
	}
	if _, err := targetClient.SubmitResult(ctx, created.RequestID, resultPayload); err != nil {
		t.Fatal(err)
	}

	completed, err := requesterClient.GetRequest(ctx, created.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	if completed.Status != protocol.StatusCompleted || completed.Answer != "Review complete." || len(completed.ResultFiles) != 1 {
		t.Fatalf("unexpected requester result: %#v", completed)
	}
	resultArtifactID := completed.ResultFiles[0].ArtifactID
	replayedResult, err := targetClient.SubmitResult(ctx, created.RequestID, resultPayload)
	if err != nil || replayedResult.Status != protocol.StatusCompleted {
		t.Fatalf("exact terminal result replay = %#v, %v", replayedResult, err)
	}
	afterResultReplay, err := requesterClient.GetRequest(ctx, created.RequestID)
	if err != nil || afterResultReplay.Version != completed.Version || len(afterResultReplay.ResultFiles) != 1 || afterResultReplay.ResultFiles[0].ArtifactID != resultArtifactID {
		t.Fatalf("terminal result changed after exact replay: before=%#v after=%#v err=%v", completed, afterResultReplay, err)
	}
	downloadedResult, err := requesterClient.FetchArtifact(ctx, completed.ResultFiles[0].ArtifactID)
	if err != nil {
		t.Fatal(err)
	}
	decodedResult, err := base64.StdEncoding.DecodeString(downloadedResult.ContentBase64)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decodedResult, resultBytes) {
		t.Fatalf("returned file = %q, want %q", decodedResult, resultBytes)
	}

	followUpPrompt := "Now summarize the single most important finding."
	followUp, err := requesterClient.CreateRequest(ctx, protocol.CreateRequest{
		ConversationID:   created.ConversationID,
		Title:            "Summarize review",
		Prompt:           followUpPrompt,
		ExpiresInSeconds: 600,
		IdempotencyKey:   "http-e2e-follow-up",
	})
	if err != nil {
		t.Fatal(err)
	}
	if followUp.RequestID == created.RequestID || followUp.Status != protocol.StatusAwaitingApproval {
		t.Fatalf("follow-up did not require a fresh per-request decision: %#v", followUp)
	}
	followUpProposal, err := targetClient.InspectProposal(ctx, followUp.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	if followUpProposal.Prompt != followUpPrompt || followUpProposal.ConversationID != created.ConversationID ||
		followUpProposal.RequesterMemberID != requester.memberID {
		t.Fatalf("unexpected follow-up proposal: %#v", followUpProposal)
	}
	assertRelayError(t, func() error {
		_, err := targetClient.FetchExecution(ctx, followUp.RequestID)
		return err
	}, http.StatusConflict, "conflict")
}

func TestHTTPDeviceRevocationEvictsDirectoryAndClosesSSE(t *testing.T) {
	t.Parallel()
	mini := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	bootstrapToken, _ := auth.NewToken(auth.TokenBootstrap)
	adminToken, _ := auth.NewToken(auth.TokenAdmin)
	repository := store.NewRedis(rdb)
	collaborationStore := collaboration.NewRedisStore(rdb)
	hub := collaboration.NewHub()
	adminHandler := server.NewHandler(repository, server.Config{
		BootstrapToken:    bootstrapToken,
		RevocationEvicter: collaboration.NewRevocationEvicter(collaborationStore, hub),
	}, nil)
	mux := http.NewServeMux()
	adminHandler.RegisterRoutes(mux)
	collaboration.NewHandler(collaborationStore, adminHandler.AuthenticateRequest, hub, nil).RegisterRoutes(mux)
	httpServer := httptest.NewServer(server.WithSecurityHeaders(mux))
	t.Cleanup(httpServer.Close)
	doJSON(t, httpServer.Client(), http.MethodPost, httpServer.URL+"/v1/bootstrap", bootstrapToken, map[string]any{
		"organization_name": "Revocation Team", "admin_display_name": "Admin", "admin_email": "admin@example.test",
		"admin_token_hash": auth.Hash(adminToken),
		"idempotency_key":  "tr_bootstrap_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}, http.StatusCreated, nil)
	requester := enrollDevice(t, httpServer, adminToken, "Requester", "requester@example.test", "Requester laptop", "codex")
	target := enrollDevice(t, httpServer, adminToken, "Target", "target@example.test", "Target laptop", "claude-code")
	requesterClient, err := client.New(httpServer.URL, requester.token, httpServer.Client())
	if err != nil {
		t.Fatal(err)
	}
	targetClient, err := client.New(httpServer.URL, target.token, httpServer.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := targetClient.Heartbeat(context.Background(), protocol.AgentHeartbeat{
		DisplayName: "Target", Availability: protocol.AvailabilityAvailable, AcceptingRequests: true,
		Runtime:        protocol.RuntimeDescriptor{ID: "claude-code", DisplayName: "Claude Code"},
		PermissionMode: protocol.PermissionReadOnly,
	}); err != nil {
		t.Fatal(err)
	}
	streamContext, cancelStream := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelStream()
	streamRequest, err := http.NewRequestWithContext(streamContext, http.MethodGet, httpServer.URL+"/v1/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	streamRequest.Header.Set("Authorization", "Bearer "+target.token)
	streamResponse, err := httpServer.Client().Do(streamRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer streamResponse.Body.Close()
	if streamResponse.StatusCode != http.StatusOK {
		t.Fatalf("event stream status = %d", streamResponse.StatusCode)
	}
	doJSON(t, httpServer.Client(), http.MethodDelete, httpServer.URL+"/v1/admin/devices/"+target.deviceID, adminToken, nil, http.StatusNoContent, nil)
	streamClosed := make(chan []byte, 1)
	go func() {
		payload, _ := io.ReadAll(streamResponse.Body)
		streamClosed <- payload
	}()
	select {
	case payload := <-streamClosed:
		if !bytes.Contains(payload, []byte("event: ready")) {
			t.Fatalf("stream closed without ready event: %q", payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("revoked device SSE subscription remained open")
	}
	directory, err := requesterClient.ListAgents(context.Background(), client.AgentQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(directory.Agents) != 0 {
		t.Fatalf("revoked device remained targetable: %#v", directory.Agents)
	}
	assertRelayError(t, func() error {
		_, err := targetClient.Heartbeat(context.Background(), protocol.AgentHeartbeat{
			DisplayName: "Target", Availability: protocol.AvailabilityAvailable, AcceptingRequests: true,
			Runtime:        protocol.RuntimeDescriptor{ID: "claude-code", DisplayName: "Claude Code"},
			PermissionMode: protocol.PermissionReadOnly,
		})
		return err
	}, http.StatusUnauthorized, "unauthorized")
}

type enrolledDevice struct {
	token    string
	agentID  string
	deviceID string
	memberID string
}

func enrollDevice(t *testing.T, relay *httptest.Server, adminToken, displayName, email, deviceName, runtimeID string) enrolledDevice {
	t.Helper()
	var invitation struct {
		InviteToken string `json:"invite_token"`
	}
	doJSON(t, relay.Client(), http.MethodPost, relay.URL+"/v1/admin/invites", adminToken, map[string]any{
		"display_name": displayName, "email": email, "expires_in_seconds": 3600,
	}, http.StatusCreated, &invitation)
	inviteClient, err := client.New(relay.URL, invitation.InviteToken, relay.Client())
	if err != nil {
		t.Fatal(err)
	}
	deviceToken, err := auth.NewToken(auth.TokenDevice)
	if err != nil {
		t.Fatal(err)
	}
	enrolled, err := inviteClient.Enroll(context.Background(), client.EnrollmentRequest{
		DisplayName: displayName, DeviceName: deviceName, Runtime: runtimeID,
		PermissionProfile: string(protocol.PermissionReadOnly),
		DeviceTokenHash:   auth.Hash(deviceToken), IdempotencyKey: "tr_enroll_" + auth.Hash(invitation.InviteToken),
	})
	if err != nil {
		t.Fatal(err)
	}
	if enrolled.Device.AgentID == "" {
		t.Fatalf("incomplete enrollment response: %#v", enrolled)
	}
	return enrolledDevice{
		token: deviceToken, agentID: enrolled.Device.AgentID,
		deviceID: enrolled.Device.ID, memberID: enrolled.Member.ID,
	}
}

func makeAttachment(name, mimeType string, content []byte) protocol.AttachmentInput {
	digest := sha256.Sum256(content)
	return protocol.AttachmentInput{
		Name: name, MIMEType: mimeType, Encoding: "base64", SizeBytes: int64(len(content)),
		SHA256: hex.EncodeToString(digest[:]), ContentBase64: base64.StdEncoding.EncodeToString(content),
	}
}

func doJSON(t *testing.T, httpClient *http.Client, method, url, token string, input any, wantStatus int, output any) {
	t.Helper()
	var body io.Reader
	if input != nil {
		payload, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		body = bytes.NewReader(payload)
	}
	request, err := http.NewRequestWithContext(context.Background(), method, url, body)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := httpClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != wantStatus {
		t.Fatalf("%s %s status = %d, want %d; body = %s", method, url, response.StatusCode, wantStatus, payload)
	}
	if output != nil {
		if err := json.Unmarshal(payload, output); err != nil {
			t.Fatalf("decode %s %s response: %v; body = %s", method, url, err, payload)
		}
	}
}

func assertRelayError(t *testing.T, operation func() error, status int, code string) {
	t.Helper()
	err := operation()
	var relayError *client.Error
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("HTTP %d", status)) {
		t.Fatalf("relay error = %v, want HTTP %d", err, status)
	}
	if !errorAs(err, &relayError) || relayError.StatusCode != status || relayError.Code != code {
		t.Fatalf("relay error = %#v, want status %d code %q", err, status, code)
	}
}

// errorAs is kept local so the assertion reads clearly at each protocol step.
func errorAs(err error, target any) bool {
	return errors.As(err, target)
}
