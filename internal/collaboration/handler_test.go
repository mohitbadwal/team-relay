package collaboration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mohitbadwal/team-relay/internal/auth"
	"github.com/mohitbadwal/team-relay/internal/protocol"
)

func TestCreateRequestRejectsCallerSuppliedRequesterMemberIdentity(t *testing.T) {
	t.Parallel()

	store, requester, _, _ := artifactTestStore(t)
	handler := NewHandler(store, func(*http.Request) (auth.Principal, error) { return requester, nil }, nil, nil)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	body := `{"target_agent_id":"agent_2","title":"Spoof","prompt":"Try identity spoofing","expires_in_seconds":600,"idempotency_key":"member_spoof","requester_member_id":"mem_spoofed"}`
	request := httptest.NewRequest(http.MethodPost, "/v1/peer-requests", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("caller-supplied requester member identity status = %d, body=%s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "unknown field") {
		t.Fatalf("caller-supplied requester member identity error = %s", response.Body.String())
	}
}

func TestIdempotentTerminalRequestRetryDoesNotRepublishPeerRequest(t *testing.T) {
	t.Parallel()

	store, requester, target, _ := artifactTestStore(t)
	hub := NewHub()
	events, unsubscribe := hub.Subscribe(requester.OrganizationID, target.AgentID)
	defer unsubscribe()
	handler := NewHandler(store, func(*http.Request) (auth.Principal, error) { return requester, nil }, hub, nil)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	input := protocol.CreateRequest{
		TargetAgentID: target.AgentID, Title: "Retry", Prompt: "Execute once",
		ExpiresInSeconds: 600, IdempotencyKey: "terminal_retry_no_event",
	}
	payload, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}

	call := func() *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/v1/peer-requests", bytes.NewReader(payload))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		return response
	}
	if response := call(); response.Code != http.StatusCreated {
		t.Fatalf("initial status = %d, body=%s", response.Code, response.Body.String())
	}
	var first event
	select {
	case first = <-events:
	default:
		t.Fatal("initial request was not published")
	}
	notice, ok := first.Payload.(protocol.RequestNotice)
	if first.Type != "peer_request" || !ok {
		t.Fatalf("initial event = %#v", first)
	}
	if _, err := store.Decide(context.Background(), target, notice.RequestID, decisionPayload(protocol.DecisionDeny)); err != nil {
		t.Fatal(err)
	}
	if response := call(); response.Code != http.StatusCreated {
		t.Fatalf("retry status = %d, body=%s", response.Code, response.Body.String())
	}
	select {
	case duplicate := <-events:
		t.Fatalf("terminal retry republished event: %#v", duplicate)
	default:
	}
}

func TestRepeatedCancelDoesNotRepublishCancellation(t *testing.T) {
	t.Parallel()

	store, requester, target, _ := artifactTestStore(t)
	created, _, _, err := store.CreateRequest(context.Background(), requester, protocol.CreateRequest{
		TargetAgentID: target.AgentID, Title: "Cancel", Prompt: "Stop",
		ExpiresInSeconds: 600, IdempotencyKey: "handler_cancel_retry",
	})
	if err != nil {
		t.Fatal(err)
	}
	hub := NewHub()
	events, unsubscribe := hub.Subscribe(requester.OrganizationID, target.AgentID)
	defer unsubscribe()
	handler := NewHandler(store, func(*http.Request) (auth.Principal, error) { return requester, nil }, hub, nil)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	call := func() *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/v1/peer-requests/"+created.RequestID+"/cancel", nil)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		return response
	}
	if response := call(); response.Code != http.StatusOK {
		t.Fatalf("initial cancel status = %d, body=%s", response.Code, response.Body.String())
	}
	select {
	case cancelled := <-events:
		if cancelled.Type != "peer_cancelled" {
			t.Fatalf("cancel event = %#v", cancelled)
		}
	default:
		t.Fatal("initial cancellation was not published")
	}
	if response := call(); response.Code != http.StatusOK {
		t.Fatalf("repeat cancel status = %d, body=%s", response.Code, response.Body.String())
	}
	select {
	case duplicate := <-events:
		t.Fatalf("repeat cancel republished event: %#v", duplicate)
	default:
	}
}

func TestDecisionEndpointRequiresAndReplaysExactRecipientIdentity(t *testing.T) {
	t.Parallel()

	store, requester, target, _ := artifactTestStore(t)
	created, _, _, err := store.CreateRequest(context.Background(), requester, protocol.CreateRequest{
		TargetAgentID: target.AgentID, Title: "Decision retry", Prompt: "Run once",
		ExpiresInSeconds: 600, IdempotencyKey: "handler_decision_retry",
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(store, func(*http.Request) (auth.Principal, error) { return target, nil }, nil, nil)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	call := func(payload protocol.DecisionPayload) *httptest.ResponseRecorder {
		body, marshalErr := json.Marshal(payload)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		request := httptest.NewRequest(http.MethodPost, "/v1/peer-requests/"+created.RequestID+"/decision", bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		return response
	}
	if response := call(protocol.DecisionPayload{Decision: protocol.DecisionAllowOnce}); response.Code != http.StatusBadRequest {
		t.Fatalf("missing identity status = %d, body=%s", response.Code, response.Body.String())
	}
	allow := decisionPayload(protocol.DecisionAllowOnce)
	if response := call(allow); response.Code != http.StatusOK {
		t.Fatalf("initial decision status = %d, body=%s", response.Code, response.Body.String())
	}
	if response := call(allow); response.Code != http.StatusOK {
		t.Fatalf("exact replay status = %d, body=%s", response.Code, response.Body.String())
	}
	changed := allow
	changed.DecisionID = "decision_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	if response := call(changed); response.Code != http.StatusConflict {
		t.Fatalf("changed replay status = %d, body=%s", response.Code, response.Body.String())
	}
}
