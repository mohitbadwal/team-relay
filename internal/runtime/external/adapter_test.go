package external

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	relayruntime "github.com/mohitbadwal/team-relay/internal/runtime"
)

func TestProbeUsesVersionedProtocolAndSanitizesCapabilities(t *testing.T) {
	t.Setenv("RUNTIME_ADAPTER_TEST_EXTERNAL_HELPER", "1")
	policy, _ := relayruntime.DefaultPolicy(relayruntime.PolicyReadOnly)
	adapter, err := New(Config{
		ID:                   "local-agent",
		Name:                 "Local Agent",
		Executable:           os.Args[0],
		PrefixArgs:           []string{"-test.run=TestExternalHelperProcess", "--", "fixed-local-argument"},
		EnvironmentAllowlist: []string{"RUNTIME_ADAPTER_TEST_EXTERNAL_HELPER"},
		WorkDir:              t.TempDir(),
		Policy:               policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	capabilities, err := adapter.Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !capabilities.Available || capabilities.RuntimeID != "external:local-agent" || capabilities.DisplayName != "Local Agent" {
		t.Fatalf("unexpected capabilities: %#v", capabilities)
	}
	if capabilities.Policy.ReadOnly != relayruntime.EnforcementNative {
		t.Fatalf("read-only enforcement = %q", capabilities.Policy.ReadOnly)
	}
	if !capabilities.SupportsModelSelection {
		t.Fatal("external runner model-selection capability was not preserved")
	}
	if capabilities.Policy.ShellControl != relayruntime.EnforcementToolLevel {
		t.Fatalf("shell control enforcement = %q", capabilities.Policy.ShellControl)
	}
	invalid := sanitizeCapabilities("external:test", "Test", policy, runnerCapabilities{
		Policy: relayruntime.PolicyCapabilities{MCPControl: relayruntime.Enforcement("invented")},
	})
	if invalid.Policy.MCPControl != relayruntime.EnforcementUnsupported {
		t.Fatalf("unknown enforcement value was trusted: %q", invalid.Policy.MCPControl)
	}
}

func TestExternalRunnerRejectsShellInterpreter(t *testing.T) {
	policy, _ := relayruntime.DefaultPolicy(relayruntime.PolicyReadOnly)
	if _, err := New(Config{ID: "unsafe", Executable: "sh", WorkDir: t.TempDir(), Policy: policy}); err == nil {
		t.Fatal("shell interpreter was accepted as an external runner")
	}
}

func TestWorkDirFingerprintUsesValidatedRuntimeRoot(t *testing.T) {
	workDir := t.TempDir()
	policy, _ := relayruntime.DefaultPolicy(relayruntime.PolicyReadOnly)
	adapter, err := New(Config{ID: "fingerprint", Executable: "runner", WorkDir: workDir, Policy: policy})
	if err != nil {
		t.Fatal(err)
	}
	validated, err := relayruntime.ValidateWorkDir(workDir)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := adapter.WorkDirFingerprint(), relayruntime.WorkDirFingerprint(validated); got != want {
		t.Fatalf("work directory fingerprint = %q, want %q", got, want)
	}
}

func TestApprovalFingerprintBindsStaticExternalExecutionConfiguration(t *testing.T) {
	policy, _ := relayruntime.DefaultPolicy(relayruntime.PolicyGuardedWrite)
	workDir := t.TempDir()
	newAdapter := func(model string, args []string) *Adapter {
		adapter, err := New(Config{
			ID: "fingerprint", Name: "External", Executable: "runner", PrefixArgs: args,
			WorkDir: workDir, Model: model, EnvironmentAllowlist: []string{"token", "PATH"},
			Policy: policy, Timeout: 3 * time.Minute,
		})
		if err != nil {
			t.Fatal(err)
		}
		return adapter
	}
	base := newAdapter("", []string{"--fixed"})
	same := newAdapter("", []string{"--fixed"})
	changed := newAdapter("recipient-model", []string{"--fixed", "--new-authority"})
	baseDigest, err := base.ApprovalFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	sameDigest, err := same.ApprovalFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	changedDigest, err := changed.ApprovalFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if baseDigest != sameDigest {
		t.Fatalf("same external runtime configuration was unstable: %q != %q", baseDigest, sameDigest)
	}
	if baseDigest == changedDigest {
		t.Fatal("external runtime authority change did not change approval fingerprint")
	}
}

func TestProbeRejectsUnsupportedConfiguredModelOverride(t *testing.T) {
	t.Setenv("RUNTIME_ADAPTER_TEST_EXTERNAL_HELPER", "1")
	t.Setenv("RUNTIME_ADAPTER_TEST_NO_MODEL_SELECTION", "1")
	policy, _ := relayruntime.DefaultPolicy(relayruntime.PolicyReadOnly)
	newAdapter := func(model string) *Adapter {
		adapter, err := New(Config{
			ID: "fixed-model", Executable: os.Args[0],
			PrefixArgs: []string{"-test.run=TestExternalHelperProcess", "--", "fixed-local-argument"},
			EnvironmentAllowlist: []string{
				"RUNTIME_ADAPTER_TEST_EXTERNAL_HELPER",
				"RUNTIME_ADAPTER_TEST_NO_MODEL_SELECTION",
			},
			WorkDir: t.TempDir(), Model: model, Policy: policy,
		})
		if err != nil {
			t.Fatal(err)
		}
		return adapter
	}

	if _, err := newAdapter("recipient-override").Probe(context.Background()); err == nil || !strings.Contains(err.Error(), "does not support the configured recipient model override") {
		t.Fatalf("unsupported model override error = %v", err)
	}
	capabilities, err := newAdapter("").Probe(context.Background())
	if err != nil {
		t.Fatalf("blank model should preserve the runner default: %v", err)
	}
	if capabilities.SupportsModelSelection {
		t.Fatal("fixed-model runner unexpectedly advertised model selection")
	}
}

func TestRunUsesFixedExecutableAndNDJSONStdin(t *testing.T) {
	capturePath := filepath.Join(t.TempDir(), "capture.json")
	t.Setenv("RUNTIME_ADAPTER_TEST_EXTERNAL_HELPER", "1")
	t.Setenv("RUNTIME_ADAPTER_TEST_CAPTURE", capturePath)
	t.Setenv("TEAM_RELAY_DEVICE_TOKEN", "tr_dev_must-not-reach-runner")
	local, _ := relayruntime.DefaultPolicy(relayruntime.PolicyGuardedWrite)
	adapter, err := New(Config{
		ID:                   "third-party",
		Name:                 "Third Party",
		Executable:           os.Args[0],
		PrefixArgs:           []string{"-test.run=TestExternalHelperProcess", "--", "fixed-local-argument"},
		EnvironmentAllowlist: []string{"RUNTIME_ADAPTER_TEST_EXTERNAL_HELPER", "RUNTIME_ADAPTER_TEST_CAPTURE"},
		WorkDir:              t.TempDir(),
		Model:                "recipient-model",
		Policy:               local,
		Timeout:              5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := relayruntime.RunRequest{
		RequestID:       "req_external",
		ConversationID:  "conv_external",
		Prompt:          "Review TOKEN=peer-secret",
		ReturnDirectory: filepath.Join(t.TempDir(), "return"),
		Workspaces: []relayruntime.Workspace{{
			Path: filepath.Join(t.TempDir(), "repo"), Mode: relayruntime.WorkspaceWritable,
		}},
		RequestedPolicy: &relayruntime.PolicyRequest{Mode: relayruntime.PolicyReadOnly},
	}
	var events []relayruntime.Event
	result, err := adapter.Run(context.Background(), request, relayruntime.EventSinkFunc(func(_ context.Context, event relayruntime.Event) error {
		events = append(events, event)
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if result.FinalText != "External result" || result.Session == nil || result.Session.RuntimeID != "external:third-party" {
		t.Fatalf("unexpected result: %#v", result)
	}
	if result.EffectivePolicy.Mode != relayruntime.PolicyReadOnly || result.EffectivePolicy.AllowWrites {
		t.Fatalf("peer upgraded effective policy: %#v", result.EffectivePolicy)
	}
	for _, event := range events {
		if strings.Contains(event.Summary, "peer-secret") {
			t.Fatalf("external event leaked credential: %#v", event)
		}
	}

	data, err := os.ReadFile(capturePath)
	if err != nil {
		t.Fatal(err)
	}
	var capture struct {
		Args         []string    `json:"args"`
		Input        runnerInput `json:"input"`
		DeviceToken  string      `json:"device_token"`
		RecipientRun string      `json:"recipient_run"`
	}
	if err := json.Unmarshal(data, &capture); err != nil {
		t.Fatal(err)
	}
	if capture.Input.Protocol != relayruntime.RunnerProtocolV1 || capture.Input.Type != "run" {
		t.Fatalf("unexpected runner envelope: %#v", capture.Input)
	}
	if capture.Input.Model != "recipient-model" {
		t.Fatalf("recipient-selected model was not delivered to the runner: %#v", capture.Input)
	}
	if !strings.Contains(capture.Input.Prompt, "peer-secret") {
		t.Fatal("prompt was not delivered through NDJSON stdin")
	}
	if capture.Input.ReturnDirectory != "" || capture.Input.Workspaces[0].Mode != relayruntime.WorkspaceReadOnly {
		t.Fatalf("read-only request retained writable path grants: %#v", capture.Input)
	}
	joined := strings.Join(capture.Args, " ")
	if !strings.Contains(joined, "fixed-local-argument") || strings.Contains(joined, "peer-secret") {
		t.Fatalf("executable arguments were not fixed locally: %#v", capture.Args)
	}
	if strings.Contains(string(data), `"executable"`) {
		t.Fatalf("runner request exposed an executable selector: %s", data)
	}
	if capture.DeviceToken != "" {
		t.Fatal("relay device token was inherited by external runner")
	}
	if capture.RecipientRun != "1" {
		t.Fatalf("recipient runtime marker = %q, want 1", capture.RecipientRun)
	}
}

func TestExternalHelperProcess(t *testing.T) {
	if os.Getenv("RUNTIME_ADAPTER_TEST_EXTERNAL_HELPER") != "1" {
		return
	}
	stdin, _ := io.ReadAll(os.Stdin)
	var input runnerInput
	_ = json.Unmarshal([]byte(strings.TrimSpace(string(stdin))), &input)
	if path := os.Getenv("RUNTIME_ADAPTER_TEST_CAPTURE"); path != "" {
		capture, _ := json.Marshal(map[string]any{"args": os.Args, "input": input, "device_token": os.Getenv("TEAM_RELAY_DEVICE_TOKEN"), "recipient_run": os.Getenv("AGENT_RELAY_RECIPIENT_RUN")})
		_ = os.WriteFile(path, capture, 0o600)
	}
	if input.Type == "probe" {
		capabilities := `{"protocol":"team-relay-runner/v1","type":"capabilities","capabilities":{"version":"1.0","supports_resume":true,"supports_streaming":true,"supports_model_selection":true,"preserves_local_context":true,"loads_local_mcps":true,"policy":{"read_only":"native","guarded_write":"best_effort","filesystem_isolation":"native","network_isolation":"native","shell_control":"tool_level","mcp_control":"tool_level","destructive_command_deny":"best_effort"}}}`
		if os.Getenv("RUNTIME_ADAPTER_TEST_NO_MODEL_SELECTION") == "1" {
			capabilities = strings.Replace(capabilities, `"supports_model_selection":true`, `"supports_model_selection":false`, 1)
		}
		fmt.Println(capabilities)
		return
	}
	fmt.Println(`{"protocol":"team-relay-runner/v1","type":"started","session_id":"external-session-1"}`)
	fmt.Println(`{"protocol":"team-relay-runner/v1","type":"event","event":{"type":"progress","summary":"Handling TOKEN=peer-secret"}}`)
	fmt.Println(`{"protocol":"team-relay-runner/v1","type":"result","result":{"final_text":"External result","session_id":"external-session-1","usage":{"input_tokens":10,"output_tokens":3}}}`)
}

func TestSupportsPolicyRejectsMissingRequiredControls(t *testing.T) {
	t.Parallel()

	readOnly, _ := relayruntime.DefaultPolicy(relayruntime.PolicyReadOnly)
	complete := relayruntime.Capabilities{Policy: relayruntime.PolicyCapabilities{
		ReadOnly:               relayruntime.EnforcementNative,
		GuardedWrite:           relayruntime.EnforcementBestEffort,
		FilesystemIsolation:    relayruntime.EnforcementNative,
		NetworkIsolation:       relayruntime.EnforcementNative,
		ShellControl:           relayruntime.EnforcementToolLevel,
		MCPControl:             relayruntime.EnforcementToolLevel,
		DestructiveCommandDeny: relayruntime.EnforcementBestEffort,
	}}
	if !relayruntime.SupportsPolicy(complete, readOnly) {
		t.Fatal("complete read-only controls were rejected")
	}

	testCases := []struct {
		name   string
		mutate func(*relayruntime.PolicyCapabilities)
	}{
		{name: "filesystem", mutate: func(policy *relayruntime.PolicyCapabilities) {
			policy.FilesystemIsolation = relayruntime.EnforcementUnsupported
		}},
		{name: "network", mutate: func(policy *relayruntime.PolicyCapabilities) {
			policy.NetworkIsolation = relayruntime.EnforcementUnsupported
		}},
		{name: "shell", mutate: func(policy *relayruntime.PolicyCapabilities) {
			policy.ShellControl = relayruntime.EnforcementUnsupported
		}},
		{name: "MCP", mutate: func(policy *relayruntime.PolicyCapabilities) { policy.MCPControl = relayruntime.EnforcementUnsupported }},
		{name: "destructive-command", mutate: func(policy *relayruntime.PolicyCapabilities) {
			policy.DestructiveCommandDeny = relayruntime.EnforcementUnsupported
		}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			capabilities := complete
			testCase.mutate(&capabilities.Policy)
			if relayruntime.SupportsPolicy(capabilities, readOnly) {
				t.Fatalf("policy was accepted without %s enforcement", testCase.name)
			}
			if err := relayruntime.ValidatePolicySupport(capabilities, readOnly); err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(testCase.name)) {
				t.Fatalf("policy error = %v, want missing %s control", err, testCase.name)
			}
		})
	}
}
