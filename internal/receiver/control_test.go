package receiver

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/mohitbadwal/team-relay/internal/privatefs"
	"github.com/mohitbadwal/team-relay/internal/protocol"
)

type fakeApprovalController struct {
	busy      bool
	requests  []PendingRecord
	proposal  protocol.ProposalPayload
	inspected string
	allowed   string
	approved  string
	level     ApprovalLevel
	grants    []ApprovalGrant
	revoked   string
	denied    string
}

func (f *fakeApprovalController) ControlBusy() bool        { return f.busy }
func (f *fakeApprovalController) Pending() []PendingRecord { return f.requests }
func (f *fakeApprovalController) InspectProposal(_ context.Context, requestID string) (*protocol.ProposalPayload, error) {
	f.inspected = requestID
	proposal := f.proposal
	return &proposal, nil
}
func (f *fakeApprovalController) AllowOnce(_ context.Context, requestID string) error {
	f.allowed = requestID
	return nil
}
func (f *fakeApprovalController) Approve(_ context.Context, requestID string, level ApprovalLevel) (ApprovalResult, error) {
	f.approved = requestID
	f.level = level
	return ApprovalResult{RequestID: requestID, Status: protocol.StatusAccepted, Level: level}, nil
}
func (f *fakeApprovalController) ApprovalGrants() ([]ApprovalGrant, error) {
	return append([]ApprovalGrant(nil), f.grants...), nil
}
func (f *fakeApprovalController) RevokeApprovalGrant(grantID string) error {
	f.revoked = grantID
	return nil
}
func (f *fakeApprovalController) Deny(_ context.Context, requestID string) error {
	f.denied = requestID
	return nil
}

func TestControlServerExposesScopedApprovalsAndGrantRevocation(t *testing.T) {
	controller := &fakeApprovalController{grants: []ApprovalGrant{{GrantID: "grant_123", Level: ApprovalLevelTeammateAlways}}}
	control, err := NewControlServer("127.0.0.1:8787", "local-secret", controller)
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "/v1/requests/req_1/approve", bytes.NewBufferString(`{"level":"conversation_30m"}`))
	request.Header.Set("Authorization", "Bearer local-secret")
	response := httptest.NewRecorder()
	control.server.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || controller.approved != "req_1" || controller.level != ApprovalLevelConversation30m {
		t.Fatalf("scoped approve response = %d %s, approved=%q level=%q", response.Code, response.Body.String(), controller.approved, controller.level)
	}

	request = httptest.NewRequest(http.MethodGet, "/v1/approval-grants", nil)
	request.Header.Set("Authorization", "Bearer local-secret")
	response = httptest.NewRecorder()
	control.server.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "grant_123") {
		t.Fatalf("grant list response = %d %s", response.Code, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodDelete, "/v1/approval-grants/grant_123", nil)
	request.Header.Set("Authorization", "Bearer local-secret")
	response = httptest.NewRecorder()
	control.server.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || controller.revoked != "grant_123" {
		t.Fatalf("revoke response = %d %s, revoked=%q", response.Code, response.Body.String(), controller.revoked)
	}

	request = httptest.NewRequest(http.MethodPost, "/v1/requests/req_1/approve", bytes.NewBufferString(`{"level":"forever"}`))
	request.Header.Set("Authorization", "Bearer local-secret")
	response = httptest.NewRecorder()
	control.server.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("invalid level response = %d %s", response.Code, response.Body.String())
	}
}

func TestControlServerRequiresBearerTokenAndExposesMetadataOnly(t *testing.T) {
	controller := &fakeApprovalController{
		requests: []PendingRecord{{Notice: protocol.RequestNotice{RequestID: "req_1", PromptPreview: "preview"}}},
		proposal: protocol.ProposalPayload{RequestID: "req_1", Prompt: "full private prompt"},
	}
	control, err := NewControlServer("127.0.0.1:8787", "local-secret", controller)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/pending", nil)
	response := httptest.NewRecorder()
	control.server.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d", response.Code)
	}

	request = httptest.NewRequest(http.MethodGet, "/v1/pending", nil)
	request.Header.Set("Authorization", "Bearer local-secret")
	response = httptest.NewRecorder()
	control.server.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "req_1") || !strings.Contains(response.Body.String(), "preview") {
		t.Fatalf("pending response = %d %s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "full private prompt") {
		t.Fatal("pending metadata response exposed the full proposal prompt")
	}

	request = httptest.NewRequest(http.MethodGet, "/v1/requests/req_1/proposal", nil)
	request.Header.Set("Authorization", "Bearer local-secret")
	response = httptest.NewRecorder()
	control.server.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || controller.inspected != "req_1" || !strings.Contains(response.Body.String(), "full private prompt") {
		t.Fatalf("inspect response = %d %s, inspected = %q", response.Code, response.Body.String(), controller.inspected)
	}

	request = httptest.NewRequest(http.MethodPost, "/v1/requests/req_1/allow-once", nil)
	request.Header.Set("Authorization", "Bearer local-secret")
	response = httptest.NewRecorder()
	control.server.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || controller.approved != "req_1" || controller.level != ApprovalLevelAskAlways {
		t.Fatalf("allow response = %d, approved = %q, level = %q", response.Code, controller.approved, controller.level)
	}
}

func TestControlServerRejectsNonLoopbackBinding(t *testing.T) {
	if _, err := NewControlServer("0.0.0.0:8787", "secret", &fakeApprovalController{}); err == nil {
		t.Fatal("non-loopback control binding was accepted")
	}
}

func TestControlServerLocksSensitiveEndpointsWhileRuntimeIsActive(t *testing.T) {
	controller := &fakeApprovalController{busy: true}
	control, err := NewControlServer("127.0.0.1:8787", "local-secret", controller)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/v1/pending"},
		{http.MethodGet, "/v1/requests/req_1/proposal"},
		{http.MethodPost, "/v1/requests/req_1/allow-once"},
		{http.MethodPost, "/v1/requests/req_1/approve"},
		{http.MethodPost, "/v1/requests/req_1/deny"},
		{http.MethodGet, "/v1/approval-grants"},
		{http.MethodDelete, "/v1/approval-grants/grant_1"},
	} {
		request := httptest.NewRequest(target.method, target.path, nil)
		request.Header.Set("Authorization", "Bearer local-secret")
		response := httptest.NewRecorder()
		control.server.Handler.ServeHTTP(response, request)
		if response.Code != http.StatusLocked {
			t.Fatalf("%s %s status = %d, want %d", target.method, target.path, response.Code, http.StatusLocked)
		}
	}

	request := httptest.NewRequest(http.MethodGet, "/health", nil)
	request.Header.Set("Authorization", "Bearer local-secret")
	response := httptest.NewRecorder()
	control.server.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("health status while runtime active = %d", response.Code)
	}
}

func TestControlTokenIsPrivateAndStable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "control.token")
	first, err := LoadOrCreateControlToken(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreateControlToken(path)
	if err != nil {
		t.Fatal(err)
	}
	if first == "" || first != second {
		t.Fatalf("control token was not stable")
	}
	if err := privatefs.ValidateRegularFile(path); err != nil {
		t.Fatalf("control token is not private: %v", err)
	}
	if err := privatefs.ValidateDirectory(filepath.Dir(path)); err != nil {
		t.Fatalf("control token directory is not private: %v", err)
	}
}

func TestControlTokenConcurrentCreationReturnsOneStableSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "control.token")
	const workers = 8
	tokens := make(chan string, workers)
	errors := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			token, err := LoadOrCreateControlToken(path)
			if err != nil {
				errors <- err
				return
			}
			tokens <- token
		}()
	}
	wait.Wait()
	close(tokens)
	close(errors)
	for err := range errors {
		t.Fatal(err)
	}
	var want string
	for token := range tokens {
		if want == "" {
			want = token
		}
		if token != want {
			t.Fatalf("concurrent control tokens differ: got %q, want %q", token, want)
		}
	}
	if want == "" {
		t.Fatal("concurrent token creation returned no token")
	}
}
