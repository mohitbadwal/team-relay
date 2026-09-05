package claude

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/mohitbadwal/team-relay/internal/privatefs"
	relayruntime "github.com/mohitbadwal/team-relay/internal/runtime"
)

type claudeHelperCapture struct {
	Args                []string `json:"args"`
	Stdin               string   `json:"stdin"`
	RecipientRun        string   `json:"recipient_run"`
	MCPConfigPath       string   `json:"mcp_config_path"`
	MCPConfigNames      []string `json:"mcp_config_names"`
	MCPConfigPrivate    bool     `json:"mcp_config_private"`
	MCPConfigHasSecret  bool     `json:"mcp_config_has_secret"`
	MCPConfigLocalValue string   `json:"mcp_config_local_value"`
}

func TestCommandArgsKeepPromptOutOfArgvAndPreserveLocalContext(t *testing.T) {
	policy, _ := relayruntime.DefaultPolicy(relayruntime.PolicyGuardedWrite)
	adapter, err := New(Config{WorkDir: t.TempDir(), Policy: policy, Model: "opus"})
	if err != nil {
		t.Fatal(err)
	}
	request := relayruntime.RunRequest{
		Prompt:          "TOKEN=do-not-put-in-argv",
		Workspaces:      []relayruntime.Workspace{{Path: "/approved/repo", Mode: relayruntime.WorkspaceWritable}},
		ReturnDirectory: "/request/return",
	}
	session := adapter.sessionRef("session_1", policy)
	request.Session = session
	args, resumed := adapter.commandArgs(request, policy, "/private/runtime/mcp.json")
	joined := strings.Join(args, " ")
	for _, required := range []string{
		"-p", "--output-format stream-json", "--verbose", "--model opus",
		`--settings {"disableAllHooks":true}`,
		"--permission-mode auto", "--tools default", "--append-system-prompt",
		"--strict-mcp-config", "--mcp-config /private/runtime/mcp.json",
		"--disallowedTools", "Bash(rm *)", "mcp__team-relay",
		"mcp__team-relay__find_teammates", "mcp__team-relay__request_teammate_help",
		"mcp__team-relay__get_request_status", "mcp__team-relay__continue_teammate_conversation",
		"mcp__team-relay__cancel_request", "mcp__team-relay__download_teammate_file",
		"--add-dir /approved/repo",
		"--resume session_1",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("arguments missing %q: %#v", required, args)
		}
	}
	for _, forbidden := range []string{"do-not-put-in-argv", "--dangerously-skip-permissions", "--safe-mode", "--disable-slash-commands"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("arguments contain forbidden value %q: %#v", forbidden, args)
		}
	}
	if strings.Contains(joined, "mcp__*") {
		t.Fatalf("arguments rely on unsupported wildcard MCP matching: %#v", args)
	}
	if resumed == nil || resumed.OpaqueID != "session_1" {
		t.Fatalf("compatible session was not resumed: %#v", resumed)
	}
}

func TestWorkDirFingerprintUsesValidatedRuntimeRoot(t *testing.T) {
	workDir := t.TempDir()
	policy, _ := relayruntime.DefaultPolicy(relayruntime.PolicyGuardedWrite)
	adapter, err := New(Config{WorkDir: workDir, Policy: policy})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := adapter.WorkDirFingerprint(), relayruntime.WorkDirFingerprint(adapter.workDir); got != want {
		t.Fatalf("work directory fingerprint = %q, want %q", got, want)
	}
}

func TestReadOnlyCommandUsesReadOnlyToolAllowlistAndDropsIncompatibleSession(t *testing.T) {
	local, _ := relayruntime.DefaultPolicy(relayruntime.PolicyGuardedWrite)
	readOnly, _ := relayruntime.DefaultPolicy(relayruntime.PolicyReadOnly)
	adapter, err := New(Config{WorkDir: t.TempDir(), Policy: local})
	if err != nil {
		t.Fatal(err)
	}
	request := relayruntime.RunRequest{Session: adapter.sessionRef("write-session", local)}
	args, resumed := adapter.commandArgs(request, readOnly, "/private/runtime/empty-mcp.json")
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, `--settings {"disableAllHooks":true}`) || !strings.Contains(joined, "--permission-mode dontAsk") || !strings.Contains(joined, "--tools Read,Glob,Grep") || !strings.Contains(joined, "--strict-mcp-config --mcp-config /private/runtime/empty-mcp.json") {
		t.Fatalf("read-only arguments are not restricted: %#v", args)
	}
	if slices.Contains(args, "--model") {
		t.Fatalf("blank recipient model should preserve the runtime's local default: %#v", args)
	}
	for _, forbidden := range []string{"Bash", "Edit", "Write", "WebFetch", "WebSearch", "--resume"} {
		if slices.Contains(args, forbidden) || strings.Contains(joined, "--resume "+forbidden) {
			t.Fatalf("read-only arguments contain %q: %#v", forbidden, args)
		}
	}
	if resumed != nil {
		t.Fatalf("stronger session was resumed under read-only policy: %#v", resumed)
	}
}

func TestNewRejectsShellWhenWritesAreDenied(t *testing.T) {
	t.Parallel()

	adapter, err := New(Config{
		WorkDir: t.TempDir(),
		Policy: relayruntime.Policy{
			Mode:       relayruntime.PolicyCustom,
			AllowShell: true,
		},
	})
	if adapter != nil || !errors.Is(err, relayruntime.ErrUnsupportedPolicy) || !strings.Contains(err.Error(), "Bash") {
		t.Fatalf("adapter = %#v, error = %v; want fail-closed Bash/write policy error", adapter, err)
	}
}

func TestNewRejectsPrefixMCPOverridesWithoutEchoingTheirValue(t *testing.T) {
	t.Parallel()

	policy, _ := relayruntime.DefaultPolicy(relayruntime.PolicyGuardedWrite)
	adapter, err := New(Config{
		PrefixArgs: []string{`--mcp-config={"mcpServers":{"unsafe":{"env":{"TOKEN":"credential-sentinel"}}}}`},
		WorkDir:    t.TempDir(),
		Policy:     policy,
	})
	if adapter != nil || err == nil {
		t.Fatalf("adapter = %#v, error = %v; want prefix MCP override rejection", adapter, err)
	}
	if strings.Contains(err.Error(), "credential-sentinel") {
		t.Fatal("prefix MCP rejection exposed the credential-bearing argument")
	}
}

func TestRunRejectsNarrowedWritePolicyThatStillAllowsShell(t *testing.T) {
	t.Parallel()

	policy, _ := relayruntime.DefaultPolicy(relayruntime.PolicyGuardedWrite)
	adapter, err := New(Config{
		Executable: "must-not-run",
		WorkDir:    t.TempDir(),
		Policy:     policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	allowWrites := false
	_, err = adapter.Run(context.Background(), relayruntime.RunRequest{
		RequestID:      "req_policy",
		ConversationID: "conv_policy",
		Prompt:         "inspect safely",
		RequestedPolicy: &relayruntime.PolicyRequest{
			AllowWrites: &allowWrites,
		},
	}, nil)
	if !errors.Is(err, relayruntime.ErrUnsupportedPolicy) || !strings.Contains(err.Error(), "Bash") {
		t.Fatalf("run error = %v, want fail-closed Bash/write policy error", err)
	}
}

func TestRunParsesClaudeStreamAndSendsPromptOnlyOnStdin(t *testing.T) {
	capturePath := filepath.Join(t.TempDir(), "capture.json")
	configDir := t.TempDir()
	t.Setenv("RUNTIME_ADAPTER_TEST_CLAUDE_HELPER", "1")
	t.Setenv("RUNTIME_ADAPTER_TEST_CAPTURE", capturePath)
	t.Setenv("CLAUDE_CONFIG_DIR", configDir)
	policy, _ := relayruntime.DefaultPolicy(relayruntime.PolicyGuardedWrite)
	workDir := t.TempDir()
	adapter, err := New(Config{
		Executable:           os.Args[0],
		PrefixArgs:           []string{"-test.run=TestClaudeHelperProcess", "--"},
		EnvironmentAllowlist: []string{"RUNTIME_ADAPTER_TEST_CLAUDE_HELPER", "RUNTIME_ADAPTER_TEST_CAPTURE"},
		WorkDir:              workDir,
		Policy:               policy,
		Timeout:              5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(adapter.workDir, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	claudeConfigPayload, err := json.Marshal(map[string]any{
		"mcpServers": map[string]any{
			"user-server": map[string]any{"type": "http", "url": "https://user.example.test/mcp", "headers": map[string]string{"Authorization": "Bearer credential-sentinel"}},
			"overridden":  map[string]any{"type": "http", "url": "https://user.example.test/mcp"},
			"disabled":    map[string]any{"type": "http", "url": "https://disabled.example.test/mcp"},
			"team_relay":  map[string]any{"type": "stdio", "command": "innocent-wrapper"},
			"renamed":     map[string]any{"type": "stdio", "command": "/opt/bin/team-relay-mcp"},
		},
		"projects": map[string]any{
			adapter.workDir: map[string]any{
				"mcpServers": map[string]any{
					"overridden":   map[string]any{"type": "http", "url": "https://local.example.test/mcp"},
					"local-server": map[string]any{"type": "stdio", "command": "local-mcp"},
					"remote-relay": map[string]any{"type": "http", "url": "https://relay.example.test/team-relay/mcp"},
					"go-run-relay": map[string]any{"type": "stdio", "command": "go", "args": []string{"run", "github.com/mohitbadwal/team-relay/cmd/team-relay-mcp"}},
				},
				"disabledMcpServers": []string{"disabled"},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, ".claude.json"), claudeConfigPayload, 0o600); err != nil {
		t.Fatal(err)
	}
	projectPayload, err := json.Marshal(map[string]any{
		"mcpServers": map[string]any{
			"project-injected": map[string]any{"type": "stdio", "command": "must-not-load"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(adapter.workDir, ".mcp.json"), projectPayload, 0o600); err != nil {
		t.Fatal(err)
	}
	returnDir := filepath.Join(t.TempDir(), "return")
	request := relayruntime.RunRequest{
		RequestID:       "req_1",
		ConversationID:  "conv_1",
		Title:           "Inspect code",
		Requester:       "Alice",
		Prompt:          "Inspect TOKEN=top-secret-value",
		ReturnDirectory: returnDir,
	}
	var events []relayruntime.Event
	result, err := adapter.Run(context.Background(), request, relayruntime.EventSinkFunc(func(_ context.Context, event relayruntime.Event) error {
		events = append(events, event)
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if result.FinalText != "Completed review" || result.Session == nil || result.Session.OpaqueID != "claude-session-1" {
		t.Fatalf("unexpected result: %#v", result)
	}
	if result.EffectivePolicy.Mode != relayruntime.PolicyGuardedWrite || result.Usage.Duration != 1250*time.Millisecond {
		t.Fatalf("missing policy or usage: %#v", result)
	}
	if len(events) < 5 || events[0].Type != relayruntime.EventStarting || events[len(events)-1].Type != relayruntime.EventCompleted {
		t.Fatalf("unexpected normalized events: %#v", events)
	}
	for _, event := range events {
		if strings.Contains(event.Summary, "Reviewing files") || strings.Contains(event.Summary, "Inspect repository") {
			t.Fatalf("normalized event leaked assistant text or tool input: %#v", event)
		}
	}

	data, err := os.ReadFile(capturePath)
	if err != nil {
		t.Fatal(err)
	}
	var capture claudeHelperCapture
	if err := json.Unmarshal(data, &capture); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(capture.Stdin, "top-secret-value") || !strings.Contains(capture.Stdin, "permission-approved request") {
		t.Fatalf("stdin does not contain the request and contract: %q", capture.Stdin)
	}
	if strings.Contains(strings.Join(capture.Args, " "), "top-secret-value") {
		t.Fatalf("request leaked into argv: %#v", capture.Args)
	}
	joinedArgs := strings.Join(capture.Args, " ")
	if strings.Count(joinedArgs, "--strict-mcp-config") != 1 || strings.Count(joinedArgs, "--mcp-config") != 1 {
		t.Fatalf("Claude invocation did not use exactly one strict MCP config: %#v", capture.Args)
	}
	if strings.Contains(joinedArgs, "credential-sentinel") || strings.Contains(joinedArgs, `"mcpServers"`) {
		t.Fatalf("credential-bearing MCP JSON leaked into argv: %#v", capture.Args)
	}
	if !capture.MCPConfigPrivate || !capture.MCPConfigHasSecret {
		t.Fatalf("Claude did not receive the expected private file-backed MCP config")
	}
	wantMCPNames := []string{"local-server", "overridden", "user-server"}
	if !slices.Equal(capture.MCPConfigNames, wantMCPNames) {
		t.Fatalf("filtered MCP aliases = %#v, want %#v", capture.MCPConfigNames, wantMCPNames)
	}
	if capture.MCPConfigLocalValue != "https://local.example.test/mcp" {
		t.Fatalf("local MCP did not override the same user-scoped alias")
	}
	if _, err := os.Stat(capture.MCPConfigPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("private MCP config was not removed after Claude exited")
	}
	if capture.RecipientRun != "1" {
		t.Fatalf("recipient runtime marker = %q, want 1", capture.RecipientRun)
	}
}

func TestDisabledMCPPolicyWritesEmptyPrivateConfigWithoutReadingClaudeState(t *testing.T) {
	configDir := t.TempDir()
	t.Setenv("CLAUDE_CONFIG_DIR", configDir)
	if err := os.WriteFile(filepath.Join(configDir, ".claude.json"), []byte("not-json credential-sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	policy, _ := relayruntime.DefaultPolicy(relayruntime.PolicyReadOnly)
	adapter, err := New(Config{WorkDir: t.TempDir(), Policy: policy})
	if err != nil {
		t.Fatal(err)
	}
	path, cleanup, err := adapter.prepareMCPConfig(policy)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if err := privatefs.ValidateDirectory(filepath.Dir(path)); err != nil {
		t.Fatalf("MCP config directory is not private: %v", err)
	}
	if err := privatefs.ValidateRegularFile(path); err != nil {
		t.Fatalf("MCP config file is not private: %v", err)
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var configured claudeMCPFile
	if err := json.Unmarshal(payload, &configured); err != nil {
		t.Fatal(err)
	}
	if len(configured.MCPServers) != 0 {
		t.Fatalf("MCP-disabled policy wrote %d servers, want zero", len(configured.MCPServers))
	}
}

func TestApprovalFingerprintFreezesFilteredMCPInventoryForAdapterLifetime(t *testing.T) {
	configDir := t.TempDir()
	t.Setenv("CLAUDE_CONFIG_DIR", configDir)
	configPath := filepath.Join(configDir, ".claude.json")
	writeConfig := func(url string) {
		t.Helper()
		payload, err := json.Marshal(map[string]any{"mcpServers": map[string]any{
			"docs":       map[string]any{"type": "http", "url": url, "headers": map[string]string{"Authorization": "credential-sentinel"}},
			"team-relay": map[string]any{"type": "stdio", "command": "innocent-wrapper"},
		}})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(configPath, payload, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeConfig("https://first.example.test/mcp")
	policy, _ := relayruntime.DefaultPolicy(relayruntime.PolicyGuardedWrite)
	workDir := t.TempDir()
	newAdapter := func() *Adapter {
		adapter, err := New(Config{
			Executable: "claude", PrefixArgs: []string{"--fixed"}, WorkDir: workDir,
			Model: "opus", EnvironmentAllowlist: []string{"TOKEN", "path"}, Policy: policy,
			Timeout: 17 * time.Minute,
		})
		if err != nil {
			t.Fatal(err)
		}
		return adapter
	}

	first := newAdapter()
	firstDigest, err := first.ApprovalFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	writeConfig("https://second.example.test/mcp")
	stillFirstDigest, err := first.ApprovalFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if stillFirstDigest != firstDigest {
		t.Fatalf("live adapter fingerprint changed after Claude config mutation: %q != %q", stillFirstDigest, firstDigest)
	}
	servers, err := first.frozenRecipientMCPServers()
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 1 || !strings.Contains(string(servers["docs"]), "first.example.test") {
		t.Fatalf("live adapter did not retain the filtered first snapshot: %#v", servers)
	}
	if _, exists := servers["team-relay"]; exists {
		t.Fatal("Team Relay survived the frozen Claude MCP filter")
	}

	second := newAdapter()
	secondDigest, err := second.ApprovalFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if secondDigest == firstDigest {
		t.Fatal("a restarted adapter did not bind the changed Claude MCP inventory")
	}
	if strings.Contains(firstDigest, "credential-sentinel") || strings.Contains(secondDigest, "credential-sentinel") {
		t.Fatal("approval fingerprint exposed an MCP credential")
	}
}

func TestApprovalFingerprintChangesWithClaudeExecutionConfiguration(t *testing.T) {
	configDir := t.TempDir()
	t.Setenv("CLAUDE_CONFIG_DIR", configDir)
	policy, _ := relayruntime.DefaultPolicy(relayruntime.PolicyReadOnly)
	workDir := t.TempDir()
	base, err := New(Config{Executable: "claude", WorkDir: workDir, Policy: policy, Timeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	changed, err := New(Config{Executable: "claude-wrapper", WorkDir: workDir, Model: "opus", Policy: policy, Timeout: 2 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	baseDigest, err := base.ApprovalFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	changedDigest, err := changed.ApprovalFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if baseDigest == changedDigest {
		t.Fatal("Claude execution configuration change did not change approval fingerprint")
	}
}

func TestTeamRelayMCPIdentityFiltering(t *testing.T) {
	tests := []struct {
		name   string
		alias  string
		config string
		want   bool
	}{
		{name: "hyphen alias", alias: "team-relay", config: `{"type":"stdio","command":"wrapper"}`, want: true},
		{name: "underscore alias", alias: "TEAM_RELAY", config: `{"type":"stdio","command":"wrapper"}`, want: true},
		{name: "binary", alias: "custom", config: `{"type":"stdio","command":"C:\\\\tools\\\\team_relay_mcp.exe"}`, want: true},
		{name: "go module", alias: "custom", config: `{"type":"stdio","command":"go","args":["run","github.com/mohitbadwal/team-relay/cmd/team-relay-mcp"]}`, want: true},
		{name: "remote", alias: "custom", config: `{"type":"http","url":"https://example.test/team-relay/mcp"}`, want: true},
		{name: "unrelated", alias: "relay-notes", config: `{"type":"stdio","command":"github-mcp"}`, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := isTeamRelayMCPServer(test.alias, json.RawMessage(test.config))
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("isTeamRelayMCPServer() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestClaudeHelperProcess(t *testing.T) {
	if os.Getenv("RUNTIME_ADAPTER_TEST_CLAUDE_HELPER") != "1" {
		return
	}
	stdin, _ := io.ReadAll(os.Stdin)
	captured := claudeHelperCapture{
		Args:         os.Args,
		Stdin:        string(stdin),
		RecipientRun: os.Getenv("AGENT_RELAY_RECIPIENT_RUN"),
	}
	for index, argument := range os.Args {
		if argument != "--mcp-config" || index+1 >= len(os.Args) {
			continue
		}
		captured.MCPConfigPath = os.Args[index+1]
		if privatefs.ValidateDirectory(filepath.Dir(captured.MCPConfigPath)) == nil && privatefs.ValidateRegularFile(captured.MCPConfigPath) == nil {
			captured.MCPConfigPrivate = true
		}
		payload, err := os.ReadFile(captured.MCPConfigPath)
		if err != nil {
			continue
		}
		captured.MCPConfigHasSecret = strings.Contains(string(payload), "credential-sentinel")
		var configured claudeMCPFile
		if json.Unmarshal(payload, &configured) != nil {
			continue
		}
		for name, raw := range configured.MCPServers {
			captured.MCPConfigNames = append(captured.MCPConfigNames, name)
			if name == "overridden" {
				var identity claudeMCPIdentity
				if json.Unmarshal(raw, &identity) == nil {
					captured.MCPConfigLocalValue = identity.URL
				}
			}
		}
		sort.Strings(captured.MCPConfigNames)
	}
	capture, _ := json.Marshal(captured)
	if path := os.Getenv("RUNTIME_ADAPTER_TEST_CAPTURE"); path != "" {
		_ = os.WriteFile(path, capture, 0o600)
	}
	fmt.Println(`{"type":"system","subtype":"init","session_id":"claude-session-1"}`)
	fmt.Println(`{"type":"assistant","session_id":"claude-session-1","message":{"content":[{"id":"tool_1","type":"tool_use","name":"Read","input":{"description":"Inspect repository"}},{"type":"text","text":"Reviewing files"}]}}`)
	fmt.Println(`{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"tool_1","is_error":false}]}}`)
	fmt.Println(`{"type":"result","session_id":"claude-session-1","result":"Completed review","duration_ms":1250,"total_cost_usd":0.02,"is_error":false}`)
}
