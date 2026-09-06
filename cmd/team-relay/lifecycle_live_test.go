package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mohitbadwal/team-relay/internal/client"
	"github.com/mohitbadwal/team-relay/internal/transportpolicy"
)

// Opt in from a logged-in macOS desktop with Docker running:
// TEAM_RELAY_TEST_NATIVE_LIVE=1 go test ./cmd/team-relay -run TestNativeLifecycleLive -count=1 -v
// Add TEAM_RELAY_TEST_LAN_HOST=<this machine's private IPv4 address> to verify
// real LAN HTTP bootstrap, enrollment, receiver heartbeat, and discovery.
// This registers two temporary LaunchAgents and cleans up only those agents.
// Server and receiver are real; the external runtime fixture only answers a
// capability probe. No peer prompt or model execution is requested.
func TestNativeLifecycleLive(t *testing.T) {
	if os.Getenv("TEAM_RELAY_TEST_NATIVE_LIVE") != "1" {
		t.Skip("set TEAM_RELAY_TEST_NATIVE_LIVE=1 to exercise real macOS user services")
	}
	if runtime.GOOS != "darwin" {
		t.Skip("live native integration currently targets macOS launchctl")
	}
	bindAddress, relayHost := "127.0.0.1", "127.0.0.1"
	if selected := os.Getenv("TEAM_RELAY_TEST_LAN_HOST"); selected != "" {
		selectedIP := net.ParseIP(selected)
		if selectedIP == nil || selectedIP.To4() == nil || !selectedIP.IsPrivate() {
			t.Fatal("TEAM_RELAY_TEST_LAN_HOST must be this machine's private IPv4 address")
		}
		addresses, err := net.InterfaceAddrs()
		if err != nil {
			t.Fatal(err)
		}
		local := false
		for _, address := range addresses {
			ip, _, err := net.ParseCIDR(address.String())
			if err == nil && selectedIP.Equal(ip) {
				local = true
			}
		}
		if !local {
			t.Fatal("refusing LAN integration against an IP not assigned to this machine")
		}
		bindAddress, relayHost = "0.0.0.0", selected
		t.Logf("Testing actual LAN HTTP access through %s on a separately allocated port.", relayHost)
	}
	fixture, err := os.MkdirTemp("", "team-relay-native-live-")
	if err != nil {
		t.Fatal(err)
	}
	fixture, err = filepath.EvalSymlinks(fixture)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("Private fixture preserved for diagnosis: %s; do not publish its credentials", fixture)
			return
		}
		if err := os.RemoveAll(fixture); err != nil {
			t.Errorf("remove owned fixture: %v", err)
		}
	})
	writePrivate := func(name, contents string, mode os.FileMode) string {
		t.Helper()
		path := filepath.Join(fixture, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(contents), mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	command := func(ctx context.Context, executable string, arguments ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, executable, arguments...)
		for _, value := range os.Environ() {
			name, _, _ := strings.Cut(value, "=")
			if !strings.HasPrefix(value, "TEAM_RELAY_") && !strings.HasSuffix(strings.ToUpper(name), "_PROXY") {
				cmd.Env = append(cmd.Env, value)
			}
		}
		cmd.Env = append(cmd.Env, "NO_PROXY=*")
		return cmd.CombinedOutput()
	}
	run := func(executable string, arguments ...string) []byte {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		output, err := command(ctx, executable, arguments...)
		if err != nil {
			// Command output may contain fresh invitation material; keep it private.
			writePrivate("last-command-output", string(output), 0o600)
			t.Fatalf("%s failed: %v (output kept in private fixture)", filepath.Base(executable), err)
		}
		return output
	}
	run("docker", "info", "--format", "{{.ServerVersion}}")
	bin := filepath.Join(fixture, "bin")
	if err := os.Mkdir(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	run("go", "-C", repo, "build", "-trimpath", "-o", bin,
		"./cmd/team-relay", "./cmd/team-relay-server", "./cmd/team-relay-agent", "./cmd/team-relay-admin")
	cli := filepath.Join(bin, "team-relay")
	admin := filepath.Join(bin, "team-relay-admin")
	agent := filepath.Join(bin, "team-relay-agent")

	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	container := "team-relay-native-live-" + hex.EncodeToString(random[:])
	if _, err := command(context.Background(), "docker", "inspect", container); err == nil {
		t.Fatal("unexpected fixture container collision")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := command(ctx, "docker", "rm", "--force", container); err != nil {
			t.Errorf("remove owned Valkey fixture %s: %v", container, err)
		} else {
			t.Log("Removed the disposable Valkey fixture container.")
		}
	})
	run("docker", "run", "--detach", "--name", container, "--publish", "127.0.0.1::6379",
		"valkey/valkey:8-alpine", "valkey-server", "--save", "", "--appendonly", "no")
	redisAddress := strings.TrimSpace(string(run("docker", "port", container, "6379/tcp")))
	if !strings.HasPrefix(redisAddress, "127.0.0.1:") {
		t.Fatal("fixture Valkey did not bind exclusively to loopback")
	}
	serverPort := reserveNativeTestPort(t)
	controlPort := reserveNativeTestPort(t)
	if serverPort == controlPort {
		t.Fatal("ephemeral test ports collided; rerun the test")
	}
	serverURL := "http://" + net.JoinHostPort(relayHost, serverPort)
	controlAddress := "127.0.0.1:" + controlPort
	bootstrap := writePrivate("secrets/bootstrap-token", string(run(admin, "generate-bootstrap-token")), 0o600)
	adminToken := filepath.Join(fixture, "secrets", "admin-token")
	receiverConfig := filepath.Join(fixture, "receiver", "config.yaml")
	receiverState := filepath.Join(fixture, "receiver-state")
	runner := writePrivate("probe-only-runtime", `#!/bin/sh
IFS= read -r request
case "$request" in
  *'"type":"probe"'*)
    printf '%s\n' '{"protocol":"team-relay-runner/v1","type":"capabilities","capabilities":{"available":true,"policy":{"read_only":"native","shell_control":"native","mcp_control":"native","filesystem_isolation":"native","network_isolation":"native","destructive_command_deny":"native"}}}'
    ;;
  *) printf '%s\n' 'This lifecycle fixture refuses runtime execution.' >&2; exit 64 ;;
esac
`, 0o700)
	conf := writePrivate("team-relay.conf", fmt.Sprintf("TEAM_RELAY_SERVER_MODE=native\nTEAM_RELAY_BIND_ADDRESS=%s\nTEAM_RELAY_PORT=%s\nTEAM_RELAY_REDIS_URL=redis://%s/0\nTEAM_RELAY_BOOTSTRAP_TOKEN_FILE=%s\nTEAM_RELAY_SERVER_EXECUTABLE=%s\nTEAM_RELAY_RECEIVER_EXECUTABLE=%s\nTEAM_RELAY_RECEIVER_CONFIG=%s\nTEAM_RELAY_RECEIVER_STATE_DIR=%s\nTEAM_RELAY_RECEIVER_CONTROL_ADDRESS=%s\n",
		bindAddress, serverPort, redisAddress, bootstrap, filepath.Join(bin, "team-relay-server"), agent, receiverConfig, receiverState, controlAddress), 0o600)
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	configBase, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(filepath.Clean(conf)))
	for _, role := range []string{"server", "receiver"} {
		id := "com.team-relay." + role + "." + hex.EncodeToString(digest[:16])
		entry := filepath.Join(home, "Library", "LaunchAgents", id+".plist")
		directory := filepath.Join(configBase, "team-relay", "services", id)
		for _, path := range []string{entry, directory} {
			if _, err := os.Lstat(path); !os.IsNotExist(err) {
				t.Fatalf("refusing to touch existing service path %s", path)
			}
		}
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if _, err := command(ctx, cli, role, "stop", "--config", conf); err != nil {
				t.Errorf("stop owned %s service: %v", role, err)
				return // Never delete a definition still in use.
			}
			if _, err := os.Lstat(entry); !os.IsNotExist(err) {
				t.Errorf("owned LaunchAgent link remains after stop: %s", entry)
				return
			}
			if _, err := command(ctx, "launchctl", "print", "gui/"+strconv.Itoa(os.Getuid())+"/"+id); err == nil {
				t.Errorf("owned %s service remains registered after stop", role)
				return
			}
			if t.Failed() {
				if log, err := os.ReadFile(filepath.Join(directory, "service.log")); err == nil {
					if err := os.WriteFile(filepath.Join(fixture, role+".private.log"), log, 0o600); err != nil {
						t.Errorf("retain private fixture log: %v", err)
					}
				}
			}
			if err := os.RemoveAll(directory); err != nil {
				t.Errorf("remove owned private service directory: %v", err)
			} else {
				t.Logf("Removed owned %s LaunchAgent registration, symlink, and private service directory.", role)
			}
		})
	}
	lifecycle := func(role, action string) []byte {
		t.Helper()
		return run(cli, role, action, "--config", conf)
	}
	await := func(label string, condition func() bool) {
		t.Helper()
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			if condition() {
				return
			}
			time.Sleep(200 * time.Millisecond)
		}
		t.Fatalf("timed out waiting for %s", label)
	}
	healthy := func() bool {
		httpClient := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil}}
		response, err := httpClient.Get(serverURL + "/health/ready")
		if err != nil {
			return false
		}
		response.Body.Close()
		return response.StatusCode == http.StatusOK
	}
	lifecycle("server", "start")
	await("native server readiness", healthy)
	bootstrapOutput := run(admin, "bootstrap", "--server", serverURL, "--token-file", bootstrap, "--admin-token-file", adminToken,
		"--organization", "Native Lifecycle Test", "--name", "Fixture Admin", "--email", "native-admin@example.invalid")
	if bindAddress == "0.0.0.0" && !bytes.Contains(bootstrapOutput, []byte(transportpolicy.PrivateLANWarning)) {
		t.Fatal("real LAN administrator bootstrap did not emit the unencrypted transport warning")
	}
	inviteOutput := run(admin, "invite", "create", "--server", serverURL, "--token-file", adminToken,
		"--name", "Fixture Receiver", "--email", "native-receiver@example.invalid")
	invite := regexp.MustCompile(`Invite token \(shown once\): (tr_inv_[[:xdigit:]]+)`).FindSubmatch(inviteOutput)
	if len(invite) != 2 {
		t.Fatal("could not read private fixture invitation")
	}
	inviteFile := writePrivate("secrets/invite-token", string(invite[1])+"\n", 0o600)
	setupOutput := run(cli, "setup", "--server", serverURL, "--invite-file", inviteFile, "--name", "Fixture Receiver", "--device-name", container,
		"--runtime", "external", "--external-id", "lifecycle-probe", "--executable", runner, "--permission", "read_only",
		"--inherit-mcps=false", "--work-dir", fixture, "--config", receiverConfig)
	if bindAddress == "0.0.0.0" && !bytes.Contains(setupOutput, []byte(transportpolicy.PrivateLANWarning)) {
		t.Fatal("real LAN enrollment did not emit the unencrypted transport warning")
	}
	// Discovery intentionally excludes the caller's own member. Enroll a second
	// observer identity, without starting another receiver or requesting work.
	observerOutput := run(admin, "invite", "create", "--server", serverURL, "--token-file", adminToken,
		"--name", "Fixture Observer", "--email", "native-observer@example.invalid")
	observerInvite := regexp.MustCompile(`Invite token \(shown once\): (tr_inv_[[:xdigit:]]+)`).FindSubmatch(observerOutput)
	if len(observerInvite) != 2 {
		t.Fatal("could not read private observer invitation")
	}
	observerInviteFile := writePrivate("secrets/observer-invite", string(observerInvite[1])+"\n", 0o600)
	observerConfig := filepath.Join(fixture, "observer", "config.yaml")
	run(cli, "setup", "--server", serverURL, "--invite-file", observerInviteFile, "--name", "Fixture Observer", "--device-name", container+"-observer",
		"--runtime", "external", "--external-id", "lifecycle-probe", "--executable", runner, "--permission", "read_only",
		"--inherit-mcps=false", "--work-dir", fixture, "--config", observerConfig)
	deviceToken, err := os.ReadFile(filepath.Join(filepath.Dir(observerConfig), "device-token"))
	if err != nil {
		t.Fatal("could not read private fixture device credential")
	}
	relay, err := client.New(serverURL, strings.TrimSpace(string(deviceToken)), &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}})
	if err != nil {
		t.Fatal(err)
	}
	lifecycle("receiver", "start")
	await("receiver registration", func() bool {
		directory, err := relay.ListAgents(context.Background(), client.AgentQuery{OnlineOnly: true})
		return err == nil && len(directory.Agents) == 1 && directory.Agents[0].Runtime.ID == "external:lifecycle-probe"
	})
	checkPending := func() {
		await("authenticated local receiver control", func() bool {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_, err := command(ctx, agent, "--config", receiverConfig, "--state-dir", receiverState, "--control-address", controlAddress, "pending")
			return err == nil
		})
	}
	checkPending()
	t.Log("Real native server is healthy; real receiver authenticated, registered, and serves its authenticated local control API.")
	pidPattern := regexp.MustCompile(`pid=([0-9]+)`)
	for _, role := range []string{"server", "receiver"} {
		before := pidPattern.FindSubmatch(lifecycle(role, "status"))
		if len(before) != 2 {
			t.Fatalf("%s status did not contain a running PID", role)
		}
		lifecycle(role, "start")
		afterStart := pidPattern.FindSubmatch(lifecycle(role, "status"))
		if len(afterStart) != 2 || !bytes.Equal(before[1], afterStart[1]) {
			t.Fatalf("idempotent %s start changed the process", role)
		}
		lifecycle(role, "logs")
		lifecycle(role, "restart")
		await(role+" replacement process", func() bool {
			current := pidPattern.FindSubmatch(lifecycle(role, "status"))
			return len(current) == 2 && !bytes.Equal(before[1], current[1])
		})
		t.Logf("%s: idempotent start, status, logs, and restart verified", role)
	}
	await("restarted native server readiness", healthy)
	checkPending()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	follow := exec.CommandContext(ctx, cli, "server", "logs", "--follow", "--config", conf)
	follow.Cancel = func() error { return follow.Process.Signal(os.Interrupt) }
	follow.WaitDelay = 2 * time.Second
	output, _ := follow.CombinedOutput()
	if !bytes.Contains(output, []byte("team relay server listening")) {
		t.Fatal("followed logs did not include real server startup")
	}
	for _, role := range []string{"receiver", "server"} {
		lifecycle(role, "stop")
		if !bytes.Contains(lifecycle(role, "status"), []byte("stopped")) {
			t.Fatalf("%s did not report stopped", role)
		}
	}
	t.Log("Followed logs and stop/status verified; cleanup removes only the two fixture services and disposable Valkey container. No peer prompts or model calls were sent.")
}

func reserveNativeTestPort(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}
