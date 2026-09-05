package client

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mohitbadwal/team-relay/internal/protocol"
)

func TestClientUsesBearerCredential(t *testing.T) {
	t.Parallel()

	httpClient := &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		if got := r.Header.Get("Authorization"); got != "Bearer tr_dev_secret" {
			t.Fatalf("unexpected Authorization header %q", got)
		}
		payload, err := json.Marshal(protocol.AgentDirectoryResponse{Agents: []protocol.AgentCard{}})
		if err != nil {
			t.Fatal(err)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(string(payload))),
			Request:    r,
		}, nil
	})}

	c, err := New("https://relay.example", "tr_dev_secret", httpClient)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ListAgents(context.Background(), AgentQuery{}); err != nil {
		t.Fatal(err)
	}
}

func TestEnrollSendsOnlyClientTokenHashAndIdempotencyKey(t *testing.T) {
	t.Parallel()
	const (
		inviteToken     = "tr_inv_secret"
		deviceTokenHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		idempotencyKey  = "tr_enroll_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	)
	httpClient := &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("Authorization") != "Bearer "+inviteToken {
			t.Fatalf("unexpected enrollment bearer %q", request.Header.Get("Authorization"))
		}
		var payload map[string]any
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if payload["device_token_hash"] != deviceTokenHash || payload["idempotency_key"] != idempotencyKey {
			t.Fatalf("enrollment payload = %+v", payload)
		}
		if _, present := payload["device_token"]; present {
			t.Fatalf("raw device token field was sent: %+v", payload)
		}
		return &http.Response{
			StatusCode: http.StatusCreated, Header: make(http.Header), Request: request,
			Body: io.NopCloser(strings.NewReader(`{"member":{"id":"mem_1"},"device":{"id":"dev_1","agent_id":"agent_1"}}`)),
		}, nil
	})}
	client, err := New("https://relay.example", inviteToken, httpClient)
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Enroll(context.Background(), EnrollmentRequest{
		DeviceName: "laptop", Runtime: "codex", PermissionProfile: "guarded_write",
		DeviceTokenHash: deviceTokenHash, IdempotencyKey: idempotencyKey,
	})
	if err != nil || result.Device.AgentID != "agent_1" {
		t.Fatalf("enroll result = %+v, %v", result, err)
	}
}

func TestMarkRunningSendsExecutionClaim(t *testing.T) {
	t.Parallel()

	const claimID = "claim_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/peer-requests/req_1/running" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		var input protocol.ExecutionClaimPayload
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			t.Fatalf("decode claim payload: %v", err)
		}
		if input.ExecutionClaimID != claimID {
			t.Fatalf("execution claim = %q, want %q", input.ExecutionClaimID, claimID)
		}
		_ = json.NewEncoder(w).Encode(protocol.MutationResponse{RequestID: "req_1", Status: protocol.StatusRunning})
	}))
	defer server.Close()
	c, err := New(server.URL, "tr_dev_secret", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.MarkRunning(context.Background(), "req_1", claimID); err != nil {
		t.Fatal(err)
	}
}

func TestDecideSendsRecipientDecisionIdentity(t *testing.T) {
	t.Parallel()

	const decisionID = "decision_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/peer-requests/req_1/decision" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		var input protocol.DecisionPayload
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			t.Fatalf("decode decision payload: %v", err)
		}
		if input.Decision != protocol.DecisionAllowOnce || input.DecisionID != decisionID {
			t.Fatalf("decision payload = %#v", input)
		}
		_ = json.NewEncoder(w).Encode(protocol.MutationResponse{RequestID: "req_1", Status: protocol.StatusAccepted})
	}))
	defer server.Close()
	c, err := New(server.URL, "tr_dev_secret", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Decide(context.Background(), "req_1", protocol.DecisionPayload{Decision: protocol.DecisionAllowOnce, DecisionID: decisionID}); err != nil {
		t.Fatal(err)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestClientRejectsCredentialInURL(t *testing.T) {
	t.Parallel()

	if _, err := New("https://user:secret@example.com", "token", nil); err == nil {
		t.Fatal("expected URL credentials to be rejected")
	}
}

func TestClientRejectsPlainHTTPOutsideLoopback(t *testing.T) {
	t.Parallel()

	if _, err := New("http://relay.example.test", "token", nil); err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("expected non-loopback HTTP to be rejected, got %v", err)
	}
	for _, value := range []string{"http://localhost:8080", "http://127.0.0.1:8080", "http://[::1]:8080"} {
		if _, err := New(value, "token", nil); err != nil {
			t.Fatalf("loopback URL %q was rejected: %v", value, err)
		}
	}
}

func TestClientDoesNotForwardBearerAcrossRedirect(t *testing.T) {
	t.Parallel()

	redirectTargetCalled := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/agents" {
			http.Redirect(w, r, "/redirect-target", http.StatusTemporaryRedirect)
			return
		}
		redirectTargetCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client, err := New(server.URL, "tr_dev_secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.ListAgents(context.Background(), AgentQuery{}); err == nil {
		t.Fatal("redirect response was treated as success")
	}
	if redirectTargetCalled {
		t.Fatal("client followed a redirect with a bearer credential")
	}
}

func TestStreamEventsDoesNotInheritOrdinaryRequestTimeout(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer tr_dev_secret" {
			t.Errorf("unexpected Authorization header %q", got)
			return
		}
		if got := r.Header.Get("Accept"); got != "text/event-stream" {
			t.Errorf("unexpected Accept header %q", got)
			return
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Error("test server does not support flushing")
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "event: ready\ndata: {}\n\n")
		flusher.Flush()
		time.Sleep(100 * time.Millisecond)
		_, _ = io.WriteString(w, "event: peer_request\ndata: {\"request_id\":\"req_1\"}\n\n")
		flusher.Flush()
	}))
	defer server.Close()

	httpClient := server.Client()
	httpClient.Timeout = 25 * time.Millisecond
	c, err := New(server.URL, "tr_dev_secret", httpClient)
	if err != nil {
		t.Fatal(err)
	}
	stop := errors.New("stop after delayed event")
	var eventTypes []string
	err = c.StreamEvents(context.Background(), func(event Event) error {
		eventTypes = append(eventTypes, event.Type)
		if event.Type == "peer_request" {
			return stop
		}
		return nil
	})
	if !errors.Is(err, stop) {
		t.Fatalf("stream error = %v, want callback sentinel", err)
	}
	if strings.Join(eventTypes, ",") != "ready,peer_request" {
		t.Fatalf("event types = %#v", eventTypes)
	}
}

func TestStreamEventsRetainsBoundedResponseHeaderWait(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(150 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	c, err := New(server.URL, "tr_dev_secret", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	c.streamConnectTTL = 25 * time.Millisecond
	err = c.StreamEvents(context.Background(), func(Event) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "response headers exceeded") {
		t.Fatalf("stream error = %v, want bounded response-header error", err)
	}
}

func TestStreamEventsHonorsCallerCancellationAfterHeaders(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher := w.(http.Flusher)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "event: ready\ndata: {}\n\n")
		flusher.Flush()
		<-r.Context().Done()
	}))
	defer server.Close()
	c, err := New(server.URL, "tr_dev_secret", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	err = c.StreamEvents(ctx, func(event Event) error {
		if event.Type == "ready" {
			cancel()
		}
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("stream error = %v, want context cancellation", err)
	}
}
