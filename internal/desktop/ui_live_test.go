package desktop

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/mohitbadwal/team-relay/internal/auth"
	"github.com/mohitbadwal/team-relay/internal/client"
	"github.com/mohitbadwal/team-relay/internal/collaboration"
	"github.com/mohitbadwal/team-relay/internal/config"
	"github.com/mohitbadwal/team-relay/internal/lifecycle"
	"github.com/mohitbadwal/team-relay/internal/protocol"
	"github.com/mohitbadwal/team-relay/internal/server"
	"github.com/mohitbadwal/team-relay/internal/store"
	"github.com/redis/go-redis/v9"
	"gopkg.in/yaml.v3"
)

// Human/UI-driven smoke: real local relay, two identities, scoped LaunchAgent,
// real native app and control APIs. The receiver uses a fixed-answer fixture,
// NOT Claude/Codex, so approving this test never spends a model subscription or
// inspects user repositories. Use CUA/the UI to deny the first request, then
// approve the next. Only this fixture's service and test data are cleaned up.
func TestDesktopUILive(t *testing.T) {
	if os.Getenv("TEAM_RELAY_TEST_DESKTOP_UI") != "1" || runtime.GOOS != "darwin" {
		t.Skip("opt in on a logged-in Mac for native UI testing")
	}
	root := t.TempDir()
	root, _ = filepath.EvalSymlinks(root)
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	write := func(name string, data []byte, mode os.FileMode) string {
		t.Helper()
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	mini := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	bootstrap, _ := auth.NewToken(auth.TokenBootstrap)
	admin, _ := auth.NewToken(auth.TokenAdmin)
	collab := collaboration.NewRedisStore(rdb)
	hub := collaboration.NewHub()
	handler := server.NewHandler(store.NewRedis(rdb), server.Config{BootstrapToken: bootstrap, RevocationEvicter: collaboration.NewRevocationEvicter(collab, hub)}, nil)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	collaboration.NewHandler(collab, handler.AuthenticateRequest, hub, nil).RegisterRoutes(mux)
	relay := httptest.NewServer(server.WithSecurityHeaders(mux))
	t.Cleanup(relay.Close)
	post := func(path, token string, input any, output any) {
		t.Helper()
		data, _ := json.Marshal(input)
		req, _ := http.NewRequestWithContext(ctx, "POST", relay.URL+path, bytes.NewReader(data))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		res, err := relay.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		if res.StatusCode >= 300 {
			t.Fatalf("fixture API %s: %d", path, res.StatusCode)
		}
		if output != nil {
			if err := json.NewDecoder(res.Body).Decode(output); err != nil {
				t.Fatal(err)
			}
		}
	}
	post("/v1/bootstrap", bootstrap, map[string]any{"organization_name": "UI Test", "admin_display_name": "UI Test Admin", "admin_email": "ui@example.test", "admin_token_hash": auth.Hash(admin), "idempotency_key": "tr_bootstrap_" + auth.Hash(root)}, nil)
	enroll := func(name string) (*client.Client, string, string) {
		t.Helper()
		var invitation struct {
			Token string `json:"invite_token"`
		}
		post("/v1/admin/invites", admin, map[string]any{"display_name": name, "expires_in_seconds": 600}, &invitation)
		c, err := client.New(relay.URL, invitation.Token, relay.Client())
		if err != nil {
			t.Fatal(err)
		}
		token, _ := auth.NewToken(auth.TokenDevice)
		enrollment, err := c.Enroll(ctx, client.EnrollmentRequest{DisplayName: name, DeviceName: "Disposable UI fixture", Runtime: "external:ui-fixture", PermissionProfile: "read_only", DeviceTokenHash: auth.Hash(token), IdempotencyKey: "tr_enroll_" + auth.Hash(token)})
		if err != nil {
			t.Fatal(err)
		}
		c, err = client.New(relay.URL, token, relay.Client())
		if err != nil {
			t.Fatal(err)
		}
		return c, enrollment.Device.AgentID, token
	}
	requester, _, _ := enroll("UI Test Teammate")
	if _, err := requester.Heartbeat(ctx, protocol.AgentHeartbeat{DisplayName: "UI Test Teammate", DeviceName: "Disposable UI requester", Availability: protocol.AvailabilityAvailable, AcceptingRequests: true, Runtime: protocol.RuntimeDescriptor{ID: "external:ui-fixture", DisplayName: "UI fixture", Capabilities: protocol.RuntimeCapabilities{ReadOnly: true}}, PermissionMode: protocol.PermissionReadOnly}); err != nil {
		t.Fatal(err)
	}
	_, recipientID, token := enroll("UI Test Receiver")
	bin := filepath.Join(root, "bin")
	if err := os.Mkdir(bin, 0700); err != nil {
		t.Fatal(err)
	}
	repo, _ := filepath.Abs("../..")
	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd/team-relay", "./cmd/team-relay-agent", "./cmd/team-relay-mcp")
	build.Dir = repo
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %s: %v", output, err)
	}
	runner := write("fixed-answer-runtime", []byte(`#!/bin/sh
IFS= read -r request
case "$request" in
  *'"type":"probe"'*) printf '%s\n' '{"protocol":"team-relay-runner/v1","type":"capabilities","capabilities":{"available":true,"policy":{"read_only":"native","shell_control":"native","mcp_control":"native","filesystem_isolation":"native","network_isolation":"native","destructive_command_deny":"native"}}}' ;;
  *) printf '%s\n' '{"protocol":"team-relay-runner/v1","type":"started","session_id":"ui-fixture"}'
     sleep 5
     printf '%s\n' '{"protocol":"team-relay-runner/v1","type":"result","result":{"final_text":"The native approval reached the receiver and this fixed answer returned to the requester."}}' ;;
esac
`), 0700)
	cfg := config.Config{Version: 1, Relay: config.RelayConfig{URL: relay.URL, TokenFile: write("profile/device.token", []byte(token), 0600)}, Receiver: config.ReceiverConfig{Profile: "default", DisplayName: "UI Test Receiver"}, Profiles: map[string]config.ReceiverProfile{"default": {Runtime: "external", Executable: runner, WorkDir: root, Policy: config.PolicyConfig{Mode: "read_only"}, Options: map[string]any{"id": "ui-fixture"}}}}
	payload, _ := yaml.Marshal(cfg)
	cfgPath := write("profile/config.yaml", payload, 0600)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	control := listener.Addr().String()
	listener.Close()
	conf := write("team-relay.conf", []byte(fmt.Sprintf("TEAM_RELAY_SERVER_MODE=native\nTEAM_RELAY_RECEIVER_EXECUTABLE=%s\nTEAM_RELAY_RECEIVER_CONFIG=%s\nTEAM_RELAY_RECEIVER_STATE_DIR=%s\nTEAM_RELAY_RECEIVER_CONTROL_ADDRESS=%s\n", filepath.Join(bin, "team-relay-agent"), cfgPath, filepath.Join(root, "state"), control)), 0600)
	t.Cleanup(func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer stopCancel()
		var output bytes.Buffer
		if err := lifecycle.Run(stopCtx, "receiver", "stop", conf, false, &output, &output); err != nil {
			t.Errorf("stop owned UI test service: %v", err)
		}
	})
	var output bytes.Buffer
	if err := lifecycle.Run(ctx, "receiver", "start", conf, false, &output, &output); err != nil {
		t.Fatal(err)
	}
	pack := exec.CommandContext(ctx, "sh", filepath.Join(repo, "scripts/build-macos-app.sh"), bin, conf, "io.teamrelay.desktop.uitest")
	if output, err := pack.CombinedOutput(); err != nil {
		t.Fatalf("app build: %s: %v", output, err)
	}
	t.Logf("Open this isolated app in CUA: %s", filepath.Join(bin, "Team Relay.app"))
	for {
		directory, err := requester.ListAgents(ctx, client.AgentQuery{})
		found := false
		if err == nil {
			for _, agent := range directory.Agents {
				if agent.AgentID == recipientID && agent.Online {
					found = true
				}
			}
		}
		if found {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("receiver did not connect")
		case <-time.After(time.Second):
		}
	}
	for _, step := range []struct {
		title  string
		status protocol.RequestStatus
	}{{"UI check: deny this request", protocol.StatusRejected}, {"UI check: allow this request", protocol.StatusCompleted}} {
		request, err := requester.CreateRequest(ctx, protocol.CreateRequest{TargetAgentID: recipientID, Title: step.title, Prompt: "This is an isolated UI smoke test. Please click the requested decision. The receiver uses a fixed-answer fixture; no model, personal files or existing relay is involved.", ExpiresInSeconds: 600, IdempotencyKey: auth.Hash(step.title + root)})
		if err != nil {
			t.Fatal(err)
		}
		t.Log(step.title)
		for {
			result, err := requester.GetRequest(ctx, request.RequestID)
			if err == nil && result.Status.Terminal() {
				if result.Status != step.status {
					t.Fatalf("got %s, want %s", result.Status, step.status)
				}
				if step.status == protocol.StatusCompleted && !strings.Contains(result.Answer, "native approval") {
					t.Fatal("answer did not return")
				}
				break
			}
			select {
			case <-ctx.Done():
				t.Fatal("timed out waiting for a native UI decision")
			case <-time.After(400 * time.Millisecond):
			}
		}
		t.Logf("Verified via requester API: %s", step.status)
	}
}
