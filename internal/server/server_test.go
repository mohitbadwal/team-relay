package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/mohitbadwal/team-relay/internal/auth"
	"github.com/mohitbadwal/team-relay/internal/store"
	"github.com/redis/go-redis/v9"
)

type recordingRevocationEvicter struct {
	contextErr error
}

func (e *recordingRevocationEvicter) EvictRevokedAgents(ctx context.Context, _ string, _ []string) error {
	e.contextErr = ctx.Err()
	return nil
}

type testHTTPRelay struct {
	t           *testing.T
	redisServer *miniredis.Miniredis
	redisClient *redis.Client
	server      *httptest.Server
	bootstrap   string
}

func newTestHTTPRelay(t *testing.T) *testHTTPRelay {
	t.Helper()
	redisServer := miniredis.RunT(t)
	redisClient := redis.NewClient(&redis.Options{Addr: redisServer.Addr()})
	bootstrap, err := auth.NewToken(auth.TokenBootstrap)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.September, 5, 12, 0, 0, 0, time.UTC)
	handler := New(store.NewRedis(redisClient), Config{BootstrapToken: bootstrap, Now: func() time.Time { return now }}, nil)
	relay := &testHTTPRelay{
		t: t, redisServer: redisServer, redisClient: redisClient,
		server: httptest.NewServer(handler), bootstrap: bootstrap,
	}
	t.Cleanup(func() {
		relay.server.Close()
		_ = relay.redisClient.Close()
	})
	return relay
}

func (relay *testHTTPRelay) request(method, path, token string, body any) (*http.Response, map[string]any) {
	relay.t.Helper()
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			relay.t.Fatal(err)
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequest(method, relay.server.URL+path, reader)
	if err != nil {
		relay.t.Fatal(err)
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		relay.t.Fatal(err)
	}
	defer response.Body.Close()
	decoded := make(map[string]any)
	if response.StatusCode != http.StatusNoContent {
		if err := json.NewDecoder(response.Body).Decode(&decoded); err != nil {
			relay.t.Fatalf("decode HTTP %d response: %v", response.StatusCode, err)
		}
	}
	return response, decoded
}

func (relay *testHTTPRelay) bootstrapRelay() string {
	relay.t.Helper()
	adminToken, err := auth.NewToken(auth.TokenAdmin)
	if err != nil {
		relay.t.Fatal(err)
	}
	response, body := relay.request(http.MethodPost, "/v1/bootstrap", relay.bootstrap, map[string]any{
		"organization_name":  "Test Team",
		"admin_display_name": "Admin",
		"admin_email":        "admin@example.com",
		"admin_token_hash":   auth.Hash(adminToken),
		"idempotency_key":    "tr_bootstrap_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	})
	if response.StatusCode != http.StatusCreated {
		relay.t.Fatalf("bootstrap status = %d, body = %+v", response.StatusCode, body)
	}
	if _, ok := body["admin_token"]; ok {
		relay.t.Fatalf("bootstrap response exposed a raw admin token: %+v", body)
	}
	return adminToken
}

func TestHealthAndOneTimeBootstrap(t *testing.T) {
	relay := newTestHTTPRelay(t)
	response, body := relay.request(http.MethodGet, "/health/live", "", nil)
	if response.StatusCode != http.StatusOK || body["status"] != "ok" {
		t.Fatalf("live response = %d %+v", response.StatusCode, body)
	}
	response, body = relay.request(http.MethodGet, "/health/ready", "", nil)
	if response.StatusCode != http.StatusOK || body["status"] != "ready" {
		t.Fatalf("ready response = %d %+v", response.StatusCode, body)
	}
	wrong, _ := auth.NewToken(auth.TokenBootstrap)
	response, _ = relay.request(http.MethodPost, "/v1/bootstrap", wrong, map[string]any{
		"organization_name": "Test", "admin_display_name": "Admin", "admin_email": "admin@example.com",
	})
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong bootstrap token status = %d", response.StatusCode)
	}
	adminToken := relay.bootstrapRelay()
	if kind, err := auth.Kind(adminToken); err != nil || kind != auth.TokenAdmin {
		t.Fatalf("admin token kind = %q, %v", kind, err)
	}
	response, body = relay.request(http.MethodPost, "/v1/bootstrap", relay.bootstrap, map[string]any{
		"organization_name": "Test Team", "admin_display_name": "Admin", "admin_email": "admin@example.com",
		"admin_token_hash": auth.Hash(adminToken),
		"idempotency_key":  "tr_bootstrap_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	})
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("exact bootstrap retry response = %d %+v", response.StatusCode, body)
	}
	secondToken, _ := auth.NewToken(auth.TokenAdmin)
	response, body = relay.request(http.MethodPost, "/v1/bootstrap", relay.bootstrap, map[string]any{
		"organization_name": "Second", "admin_display_name": "Admin", "admin_email": "admin@example.com",
		"admin_token_hash": auth.Hash(secondToken),
		"idempotency_key":  "tr_bootstrap_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	})
	if response.StatusCode != http.StatusConflict || errorCode(body) != "already_bootstrapped" {
		t.Fatalf("second bootstrap response = %d %+v", response.StatusCode, body)
	}
}

func TestCommittedRevocationCleanupSurvivesRequestCancellation(t *testing.T) {
	evicter := &recordingRevocationEvicter{}
	handler := &Handler{revocationEvicter: evicter}
	requestContext, cancel := context.WithCancel(context.Background())
	cancel()
	if err := handler.evictRevokedAgents(requestContext, store.RevocationResult{
		OrganizationID: "org_1", AgentIDs: []string{"agent_1"},
	}); err != nil {
		t.Fatal(err)
	}
	if evicter.contextErr != nil {
		t.Fatalf("post-commit eviction inherited cancelled request context: %v", evicter.contextErr)
	}
}

func TestAdminCanRotateCredential(t *testing.T) {
	relay := newTestHTTPRelay(t)
	oldToken := relay.bootstrapRelay()
	newToken, err := auth.NewToken(auth.TokenAdmin)
	if err != nil {
		t.Fatal(err)
	}
	payload := map[string]any{
		"new_token_hash":  auth.Hash(newToken),
		"idempotency_key": "tr_rotate_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	response, body := relay.request(http.MethodPost, "/v1/admin/credential/rotate", oldToken, payload)
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("rotate response = %d %+v", response.StatusCode, body)
	}
	if _, ok := body["admin_token"]; ok {
		t.Fatalf("rotation response exposed a raw token: %+v", body)
	}
	response, _ = relay.request(http.MethodGet, "/v1/admin/members", oldToken, nil)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old token remained valid: %d", response.StatusCode)
	}
	response, body = relay.request(http.MethodGet, "/v1/admin/members", newToken, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("new token response = %d %+v", response.StatusCode, body)
	}
	response, body = relay.request(http.MethodPost, "/v1/admin/credential/rotate", newToken, payload)
	if response.StatusCode != http.StatusCreated || body["replayed"] != true {
		t.Fatalf("lost-response rotation replay = %d %+v", response.StatusCode, body)
	}
}

func TestBearerOnlyAdminInviteEnrollmentAndDeviceRevocation(t *testing.T) {
	relay := newTestHTTPRelay(t)
	adminToken := relay.bootstrapRelay()

	request, err := http.NewRequest(http.MethodGet, relay.server.URL+"/v1/admin/members", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Team-Relay-Principal", "admin@example.com")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("proxy identity header authenticated without bearer token: %d", response.StatusCode)
	}

	response, body := relay.request(http.MethodPost, "/v1/admin/invites", adminToken, map[string]any{
		"display_name":       "Alice",
		"email":              "alice@example.com",
		"expires_in_seconds": 3600,
	})
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("create invite response = %d %+v", response.StatusCode, body)
	}
	inviteToken, ok := body["invite_token"].(string)
	if !ok {
		t.Fatalf("invite token missing: %+v", body)
	}
	deviceToken, err := auth.NewToken(auth.TokenDevice)
	if err != nil {
		t.Fatal(err)
	}
	enrollmentPayload := map[string]any{
		"device_name":        "Alice laptop",
		"runtime":            "codex",
		"permission_profile": "read_only",
		"device_token_hash":  auth.Hash(deviceToken),
		"idempotency_key":    "tr_enroll_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	response, body = relay.request(http.MethodPost, "/v1/enroll", inviteToken, enrollmentPayload)
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("enroll response = %d %+v", response.StatusCode, body)
	}
	if _, ok := body["device_token"]; ok {
		t.Fatalf("server returned a raw device token: %+v", body)
	}
	device := body["device"].(map[string]any)
	deviceID := device["id"].(string)
	response, retryBody := relay.request(http.MethodPost, "/v1/enroll", inviteToken, enrollmentPayload)
	if response.StatusCode != http.StatusCreated || retryBody["device"].(map[string]any)["id"] != deviceID {
		t.Fatalf("exact enrollment retry response = %d %+v", response.StatusCode, retryBody)
	}
	mismatchedPayload := map[string]any{
		"device_name": "Different laptop", "runtime": "codex", "permission_profile": "read_only",
		"device_token_hash": auth.Hash(deviceToken),
		"idempotency_key":   "tr_enroll_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	response, retryBody = relay.request(http.MethodPost, "/v1/enroll", inviteToken, mismatchedPayload)
	if response.StatusCode != http.StatusConflict || errorCode(retryBody) != "conflict" {
		t.Fatalf("mismatched enrollment retry response = %d %+v", response.StatusCode, retryBody)
	}

	response, _ = relay.request(http.MethodPost, "/v1/enroll", inviteToken, map[string]any{
		"device_name": "Replay", "runtime": "codex", "permission_profile": "read_only",
		"device_token_hash": auth.Hash("tr_dev_replay"),
		"idempotency_key":   "tr_enroll_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	})
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("invite replay status = %d", response.StatusCode)
	}
	response, body = relay.request(http.MethodGet, "/v1/me", deviceToken, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("device /me response = %d %+v", response.StatusCode, body)
	}
	response, body = relay.request(http.MethodGet, "/v1/admin/devices", adminToken, nil)
	if response.StatusCode != http.StatusOK || len(body["devices"].([]any)) != 1 {
		t.Fatalf("device listing response = %d %+v", response.StatusCode, body)
	}
	response, body = relay.request(http.MethodDelete, "/v1/admin/devices/"+deviceID, adminToken, nil)
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("device revoke response = %d %+v", response.StatusCode, body)
	}
	response, body = relay.request(http.MethodGet, "/v1/me", deviceToken, nil)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked device /me response = %d %+v", response.StatusCode, body)
	}
	response, body = relay.request(http.MethodPost, "/v1/enroll", inviteToken, enrollmentPayload)
	if response.StatusCode != http.StatusConflict || errorCode(body) != "conflict" {
		t.Fatalf("retry after device revocation response = %d %+v", response.StatusCode, body)
	}
}

func TestEnrollmentRejectsUnknownPermissionProfile(t *testing.T) {
	relay := newTestHTTPRelay(t)
	adminToken := relay.bootstrapRelay()
	response, body := relay.request(http.MethodPost, "/v1/admin/invites", adminToken, map[string]any{
		"display_name": "Alice", "expires_in_seconds": 3600,
	})
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("create invite response = %d %+v", response.StatusCode, body)
	}
	response, body = relay.request(http.MethodPost, "/v1/enroll", body["invite_token"].(string), map[string]any{
		"device_name": "Alice laptop", "runtime": "codex", "permission_profile": "unrestricted-root",
		"device_token_hash": auth.Hash("tr_dev_test"),
		"idempotency_key":   "tr_enroll_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	})
	if response.StatusCode != http.StatusBadRequest || errorCode(body) != "invalid_request" {
		t.Fatalf("unsafe profile response = %d %+v", response.StatusCode, body)
	}
}

func errorCode(body map[string]any) string {
	errorValue, _ := body["error"].(map[string]any)
	code, _ := errorValue["code"].(string)
	return code
}
