package runtime

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestExecuteJSONLinesAddsTrustedEnvironmentAfterSanitization(t *testing.T) {
	t.Setenv("RUNTIME_PROCESS_HELPER", "1")
	t.Setenv("AGENT_RELAY_RECIPIENT_RUN", "spoofed-host-value")
	t.Setenv("TEAM_RELAY_DEVICE_TOKEN", "must-not-cross-runtime-boundary")
	var received struct {
		RecipientRun string `json:"recipient_run"`
		DeviceToken  string `json:"device_token"`
	}
	err := ExecuteJSONLines(context.Background(), CommandSpec{
		Executable:           os.Args[0],
		Args:                 []string{"-test.run=^TestRuntimeProcessHelper$", "--"},
		EnvironmentAllowlist: []string{"RUNTIME_PROCESS_HELPER", "AGENT_RELAY_RECIPIENT_RUN", "TEAM_RELAY_DEVICE_TOKEN"},
		Environment:          map[string]string{"AGENT_RELAY_RECIPIENT_RUN": "1"},
	}, func(raw json.RawMessage) error {
		return json.Unmarshal(raw, &received)
	})
	if err != nil {
		t.Fatal(err)
	}
	if received.RecipientRun != "1" {
		t.Fatalf("recipient marker = %q, want trusted override", received.RecipientRun)
	}
	if received.DeviceToken != "" {
		t.Fatal("relay authority crossed the runtime boundary")
	}
}

func TestExecuteJSONLinesRejectsAuthorityEnvironmentOverride(t *testing.T) {
	err := ExecuteJSONLines(context.Background(), CommandSpec{
		Executable:  "must-not-start",
		Environment: map[string]string{"TEAM_RELAY_DEVICE_TOKEN": "forbidden"},
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "relay authority environment variable") {
		t.Fatalf("authority override error = %v", err)
	}
}

func TestRuntimeProcessHelper(t *testing.T) {
	if os.Getenv("RUNTIME_PROCESS_HELPER") != "1" {
		return
	}
	encoded, _ := json.Marshal(map[string]string{
		"recipient_run": os.Getenv("AGENT_RELAY_RECIPIENT_RUN"),
		"device_token":  os.Getenv("TEAM_RELAY_DEVICE_TOKEN"),
	})
	_, _ = os.Stdout.Write(append(encoded, '\n'))
}
