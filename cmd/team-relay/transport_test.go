package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mohitbadwal/team-relay/internal/client"
	"github.com/mohitbadwal/team-relay/internal/config"
	"github.com/mohitbadwal/team-relay/internal/transportpolicy"
)

func TestSetupAndClientAgreeOnRelayTransport(t *testing.T) {
	for _, test := range []struct {
		url     string
		allowed bool
	}{
		{"http://192.168.1.4:8080", true}, {"http://10.255.255.254", true},
		{"http://172.16.0.1", true}, {"http://172.31.255.254", true},
		{"http://[fc00::1]", true}, {"http://[fdff::1]", true},
		{"http://[::ffff:192.168.1.4]", true},
		{"http://LOCALHOST", true}, {"http://127.1.2.3", true}, {"http://[::1]", true},
		{"https://relay.example", true}, {"https://8.8.8.8", true},
		{"http://172.15.255.255", false}, {"http://172.32.0.0", false},
		{"http://169.254.1.2", false}, {"http://100.64.0.1", false},
		{"http://0.0.0.0", false}, {"http://224.0.0.1", false},
		{"http://[fe80::1]", false}, {"http://[::]", false},
		{"http://[::ffff:8.8.8.8]", false}, {"http://relay.local", false},
		{"http://localhost.evil", false}, {"http://localhost.", false},
		{"http://user:secret@192.168.1.4", false},
		{"http://192.168.1.4?secret=x", false}, {"http://192.168.1.4?", false},
		{"http://192.168.1.4#fragment", false}, {"http://192.168.1.4#", false},
		{"https://user:secret@relay.example", false}, {"https://relay.example?x=1", false},
		{"https://:8080", false}, {"ftp://192.168.1.4", false},
	} {
		t.Run(test.url, func(t *testing.T) {
			setupErr := validateRelayURL(test.url)
			_, clientErr := client.New(test.url, "fixture-token", nil)
			if (setupErr == nil) != test.allowed || (clientErr == nil) != test.allowed {
				t.Errorf("URL=%q allowed=%t setup=%v client=%v", test.url, test.allowed, setupErr, clientErr)
			}
		})
	}
}

func TestLANSetupWarnsAndSavesUsableReceiverConfigWithoutOverride(t *testing.T) {
	t.Setenv("TEAM_RELAY_INVITE_TOKEN", "tr_inv_lan_fixture")
	t.Setenv("TEAM_RELAY_URL", "")
	t.Setenv("TEAM_RELAY_ALLOW_HTTP_HOST", "")
	directory := t.TempDir()
	configPath := filepath.Join(directory, "receiver", "config.yaml")
	warningPath := filepath.Join(directory, "stderr")
	warningFile, err := os.OpenFile(warningPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	originalStderr := os.Stderr
	originalEnroll := enrollRelayDevice
	os.Stderr = warningFile
	t.Cleanup(func() {
		os.Stderr = originalStderr
		enrollRelayDevice = originalEnroll
		_ = warningFile.Close()
	})
	calls := 0
	enrollRelayDevice = func(_ context.Context, serverURL, invite string, _ client.EnrollmentRequest) (*client.EnrollmentResponse, error) {
		calls++
		if serverURL != "http://192.168.1.4:8080" || invite != "tr_inv_lan_fixture" {
			t.Error("setup changed the selected LAN endpoint or invitation")
		}
		if _, err := client.New(serverURL, invite, nil); err != nil {
			t.Fatalf("setup accepted a URL that enrollment client rejects: %v", err)
		}
		warning, err := os.ReadFile(warningPath)
		if err != nil || string(warning) != transportpolicy.PrivateLANWarning+"\n" {
			t.Errorf("cleartext warning was not issued before enrollment: %q (%v)", warning, err)
		}
		response := &client.EnrollmentResponse{}
		response.Member.DisplayName = "LAN fixture teammate"
		response.Device.Name = "test device"
		response.Device.AgentID = "fixture-agent"
		return response, nil
	}
	err = setup([]string{
		"--server", "http://192.168.1.4:8080", "--runtime", "claude-code",
		"--name", "LAN fixture teammate", "--device-name", "test device",
		"--work-dir", directory, "--config", configPath,
	})
	if err != nil || calls != 1 {
		t.Fatalf("LAN setup: calls=%d err=%v", calls, err)
	}
	configuration, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	token, err := configuration.DeviceToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.New(configuration.Relay.URL, token, nil); err != nil {
		t.Fatalf("saved receiver/MCP configuration still needs a transport override: %v", err)
	}
	warning, err := os.ReadFile(warningPath)
	if err != nil || strings.Count(string(warning), "Warning:") != 1 || strings.Contains(string(warning), token) {
		t.Fatal("setup warning duplicated or exposed a credential")
	}
}
