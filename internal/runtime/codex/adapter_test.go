package codex

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	relayruntime "github.com/mohitbadwal/team-relay/internal/runtime"
)

func codexPolicyWithoutMCPs(t *testing.T) relayruntime.Policy {
	t.Helper()
	policy, err := relayruntime.DefaultPolicy(relayruntime.PolicyGuardedWrite)
	if err != nil {
		t.Fatal(err)
	}
	policy.AllowMCPs = false
	policy, err = relayruntime.ValidatePolicy(policy)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func TestRunRejectsReadOnlyWhenShellControlIsUnavailable(t *testing.T) {
	t.Parallel()
	policy, _ := relayruntime.DefaultPolicy(relayruntime.PolicyReadOnly)
	adapter, err := New(Config{Executable: "must-not-start", WorkDir: t.TempDir(), Policy: policy})
	if err != nil {
		t.Fatal(err)
	}
	_, err = adapter.Run(context.Background(), relayruntime.RunRequest{
		RequestID: "req_read_only", ConversationID: "conv_read_only", Prompt: "inspect",
	}, nil)
	if !errors.Is(err, relayruntime.ErrUnsupportedPolicy) || !strings.Contains(err.Error(), "shell control") {
		t.Fatalf("read-only Codex error = %v, want unsupported shell-control policy", err)
	}
}

func TestNewRunArgumentsUseFailClosedUserConfigIsolation(t *testing.T) {
	policy, _ := relayruntime.DefaultPolicy(relayruntime.PolicyReadOnly)
	workDir := t.TempDir()
	adapter, err := New(Config{WorkDir: workDir, Policy: policy})
	if err != nil {
		t.Fatal(err)
	}
	validatedWorkDir, err := relayruntime.ValidateWorkDir(workDir)
	if err != nil {
		t.Fatal(err)
	}
	request := relayruntime.ConstrainRequest(relayruntime.RunRequest{
		Prompt: "secret prompt", ReturnDirectory: "/ignored/return",
	}, policy)
	args, session := adapter.commandArgs(request, policy)
	joined := strings.Join(args, " ")
	for _, required := range []string{
		"exec --ignore-user-config", "features.plugins=false", "features.remote_plugin=false",
		"features.apps=false", "features.enable_mcp_apps=false",
		"features.external_migration=false", "features.skill_mcp_dependency_install=false", "features.tool_suggest=false",
		"features.hooks=false",
		"--json", "--color never", "--cd " + validatedWorkDir, "--sandbox read-only",
		`sandbox_mode="read-only"`, `shell_environment_policy.inherit="core"`,
		"shell_environment_policy.ignore_default_excludes=false",
		"projects." + strconv.Quote(validatedWorkDir) + `.trust_level="untrusted"`,
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("arguments missing %q: %#v", required, args)
		}
	}
	for _, forbidden := range []string{
		"secret prompt", "--dangerously-bypass-approvals-and-sandbox", "--approve-for-me",
		"--add-dir", "--profile", "mcp_servers.",
	} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("arguments contain forbidden value %q: %#v", forbidden, args)
		}
	}
	if slices.Contains(args, "--model") {
		t.Fatalf("blank recipient model should use the isolated runtime default: %#v", args)
	}
	if session != nil {
		t.Fatalf("unexpected session: %#v", session)
	}
}

func TestGuardedWriteAddsOnlyRecipientApprovedWritableDirectories(t *testing.T) {
	policy := codexPolicyWithoutMCPs(t)
	adapter, err := New(Config{WorkDir: t.TempDir(), Policy: policy, Model: "gpt-test"})
	if err != nil {
		t.Fatal(err)
	}
	request := relayruntime.RunRequest{
		Workspaces: []relayruntime.Workspace{
			{Path: "/approved/read", Mode: relayruntime.WorkspaceReadOnly},
			{Path: "/approved/write", Mode: relayruntime.WorkspaceWritable},
		},
		ReturnDirectory: "/approved/return",
	}
	args, _ := adapter.commandArgs(request, policy)
	joined := strings.Join(args, " ")
	for _, required := range []string{
		"exec --ignore-user-config", "--sandbox workspace-write", "--model gpt-test",
		"--add-dir /approved/write", "--add-dir /approved/return", `sandbox_mode="workspace-write"`,
		`writable_roots=["/approved/return","/approved/write"]`, "network_access=true",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("arguments missing %q: %#v", required, args)
		}
	}
	if strings.Contains(joined, "--add-dir /approved/read") || slices.Contains(args, "--profile") || strings.Contains(joined, "mcp_servers.") {
		t.Fatalf("isolated launch widened recipient authority: %#v", args)
	}
}

func TestResumeUsesOpaqueSessionOnlyWhenPolicyMatchesAndReappliesIsolation(t *testing.T) {
	policy := codexPolicyWithoutMCPs(t)
	adapter, err := New(Config{WorkDir: t.TempDir(), Policy: policy})
	if err != nil {
		t.Fatal(err)
	}
	request := relayruntime.RunRequest{Session: adapter.sessionRef("codex-session-1", policy)}
	args, resumed := adapter.commandArgs(request, policy)
	joined := strings.Join(args, " ")
	if resumed == nil || !strings.Contains(joined, "exec resume --ignore-user-config") || !strings.Contains(joined, "codex-session-1 -") {
		t.Fatalf("session was not resumed through isolated config: %#v", args)
	}
	for _, invalidResumeFlag := range []string{"--cd", "--sandbox", "--profile", "--add-dir"} {
		if slices.Contains(args, invalidResumeFlag) {
			t.Fatalf("resume received unsupported option %q: %#v", invalidResumeFlag, args)
		}
	}
	for _, required := range []string{
		"features.plugins=false", "features.remote_plugin=false", "network_access=true",
		`sandbox_mode="workspace-write"`, "writable_roots=[]",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("resume did not reapply %q: %#v", required, args)
		}
	}

	readOnly, _ := relayruntime.DefaultPolicy(relayruntime.PolicyReadOnly)
	if _, resumed = adapter.commandArgs(request, readOnly); resumed != nil {
		t.Fatal("write-capable session resumed under a different policy")
	}
}

func TestWorkDirFingerprintUsesValidatedRuntimeRoot(t *testing.T) {
	workDir := t.TempDir()
	policy := codexPolicyWithoutMCPs(t)
	adapter, err := New(Config{WorkDir: workDir, Policy: policy})
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

func TestApprovalFingerprintFailsClosedWhenCodexMCPsAreEnabled(t *testing.T) {
	policy, _ := relayruntime.DefaultPolicy(relayruntime.PolicyGuardedWrite)
	adapter, err := New(Config{WorkDir: t.TempDir(), Policy: policy})
	if err != nil {
		t.Fatal(err)
	}
	_, err = adapter.ApprovalFingerprint()
	if !errors.Is(err, relayruntime.ErrUnsupportedPolicy) || !strings.Contains(err.Error(), "exact, secret-safe MCP configuration snapshot") || !strings.Contains(err.Error(), "disable MCP access") {
		t.Fatalf("approval fingerprint error = %v, want fail-closed MCP remediation", err)
	}
	_, err = adapter.Run(context.Background(), relayruntime.RunRequest{
		RequestID: "req_mcp", ConversationID: "conv_mcp", Prompt: "must not start",
	}, nil)
	if !errors.Is(err, relayruntime.ErrUnsupportedPolicy) || !strings.Contains(err.Error(), "disable MCP access") {
		t.Fatalf("run error = %v, want fail-closed MCP remediation", err)
	}
}

func TestApprovalFingerprintChangesWithCodexExecutionConfiguration(t *testing.T) {
	t.Setenv("RUNTIME_ADAPTER_TEST_CODEX_HELPER", "1")
	policy := codexPolicyWithoutMCPs(t)
	workDir := t.TempDir()
	newAdapter := func(model string, timeout time.Duration) *Adapter {
		adapter, err := New(Config{
			Executable: os.Args[0], PrefixArgs: []string{"-test.run=TestCodexHelperProcess", "--"}, WorkDir: workDir,
			Model: model, EnvironmentAllowlist: []string{"TOKEN", "RUNTIME_ADAPTER_TEST_CODEX_HELPER"}, Policy: policy, Timeout: timeout,
		})
		if err != nil {
			t.Fatal(err)
		}
		return adapter
	}
	base := newAdapter("", time.Minute)
	changed := newAdapter("gpt-test", 2*time.Minute)
	baseDigest, err := base.ApprovalFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	changedDigest, err := changed.ApprovalFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if baseDigest == changedDigest {
		t.Fatal("Codex execution configuration change did not change approval fingerprint")
	}
	if strings.Contains(baseDigest, "TOKEN") || strings.Contains(changedDigest, "TOKEN") {
		t.Fatal("approval fingerprint exposed configuration input")
	}
}

func TestNewRejectsConfigAndProfileEscapeHatches(t *testing.T) {
	policy := codexPolicyWithoutMCPs(t)
	for _, testCase := range []struct {
		name       string
		profile    string
		prefixArgs []string
	}{
		{name: "configured profile", profile: "recipient"},
		{name: "long config", prefixArgs: []string{"--config", `mcp_servers.evil.command="evil"`}},
		{name: "short attached config", prefixArgs: []string{`-cmcp_servers.evil.command="evil"`}},
		{name: "long profile", prefixArgs: []string{"--profile=evil"}},
		{name: "short attached profile", prefixArgs: []string{"-pevil"}},
		{name: "enable feature", prefixArgs: []string{"--enable", "plugins"}},
		{name: "disable feature", prefixArgs: []string{"--disable=remote_plugin"}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := New(Config{
				Executable: "codex", PrefixArgs: testCase.prefixArgs, Profile: testCase.profile,
				WorkDir: t.TempDir(), Policy: policy,
			})
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), "mcp") {
				t.Fatalf("New() error = %v, want MCP isolation validation", err)
			}
		})
	}
}

func TestProbeValidatesContainmentControlsAndCleanInventory(t *testing.T) {
	t.Setenv("RUNTIME_ADAPTER_TEST_CODEX_HELPER", "1")
	t.Setenv("RUNTIME_ADAPTER_TEST_CODEX_MODE", "clean")
	policy := codexPolicyWithoutMCPs(t)
	adapter := newCodexHelperAdapter(t, policy)
	capabilities, err := adapter.Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !capabilities.Available || capabilities.Version != "codex-cli 0.153.0-test" || capabilities.LoadsLocalMCPs {
		t.Fatalf("unexpected contained Codex capabilities: %#v", capabilities)
	}
}

func TestProbeRejectsOldCLIAndMissingContainmentFeature(t *testing.T) {
	policy := codexPolicyWithoutMCPs(t)
	for _, testCase := range []struct {
		name string
		mode string
		want string
	}{
		{name: "old CLI lacks ignore-user-config", mode: "old_cli", want: "--ignore-user-config"},
		{name: "feature inventory omits required switch", mode: "missing_feature", want: "integration-disable feature"},
		{name: "CLI rejects required switch", mode: "reject_feature", want: "rejected"},
		{name: "managed policy forces feature on", mode: "forced_feature", want: "did not disable"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Setenv("RUNTIME_ADAPTER_TEST_CODEX_HELPER", "1")
			t.Setenv("RUNTIME_ADAPTER_TEST_CODEX_MODE", testCase.mode)
			adapter := newCodexHelperAdapter(t, policy)
			capabilities, err := adapter.Probe(context.Background())
			if !errors.Is(err, relayruntime.ErrUnsupportedPolicy) || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("Probe() error = %v, want unsupported containment error containing %q", err, testCase.want)
			}
			if capabilities.Available {
				t.Fatalf("unsupported CLI reported available: %#v", capabilities)
			}
		})
	}
}

func TestPreflightRejectsResidualManagedMCPWithoutLeakingItsConfiguration(t *testing.T) {
	t.Setenv("RUNTIME_ADAPTER_TEST_CODEX_HELPER", "1")
	t.Setenv("RUNTIME_ADAPTER_TEST_CODEX_MODE", "residual")
	policy := codexPolicyWithoutMCPs(t)
	adapter := newCodexHelperAdapter(t, policy)
	_, err := adapter.ApprovalFingerprint()
	if !errors.Is(err, relayruntime.ErrUnsupportedPolicy) || !strings.Contains(err.Error(), "system or managed") {
		t.Fatalf("ApprovalFingerprint() error = %v, want residual managed MCP rejection", err)
	}
	for _, forbidden := range []string{"credential-sentinel-managed", "authorization-sentinel", "managed.example"} {
		if strings.Contains(strings.ToLower(err.Error()), strings.ToLower(forbidden)) {
			t.Fatalf("preflight error exposed raw MCP configuration %q: %v", forbidden, err)
		}
	}
}

func TestRunRepeatsMCPPreflightImmediatelyBeforeChildLaunch(t *testing.T) {
	counterPath := filepath.Join(t.TempDir(), "mcp-preflight-count")
	capturePath := filepath.Join(t.TempDir(), "capture.json")
	t.Setenv("RUNTIME_ADAPTER_TEST_CODEX_HELPER", "1")
	t.Setenv("RUNTIME_ADAPTER_TEST_CODEX_MODE", "residual_on_second")
	t.Setenv("RUNTIME_ADAPTER_TEST_MCP_COUNTER", counterPath)
	t.Setenv("RUNTIME_ADAPTER_TEST_CAPTURE", capturePath)
	policy := codexPolicyWithoutMCPs(t)
	adapter := newCodexHelperAdapter(t, policy)
	if _, err := adapter.ApprovalFingerprint(); err != nil {
		t.Fatalf("initial approval preflight failed: %v", err)
	}
	_, err := adapter.Run(context.Background(), relayruntime.RunRequest{
		RequestID: "req_preflight", ConversationID: "conv_preflight", Prompt: "must not launch",
	}, nil)
	if !errors.Is(err, relayruntime.ErrUnsupportedPolicy) || !strings.Contains(err.Error(), "system or managed") {
		t.Fatalf("Run() error = %v, want second preflight rejection", err)
	}
	count, readErr := os.ReadFile(counterPath)
	if readErr != nil || strings.TrimSpace(string(count)) != "2" {
		t.Fatalf("MCP preflight count = %q, err=%v; want 2", count, readErr)
	}
	if _, statErr := os.Stat(capturePath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("Codex child launched despite failed final preflight: %v", statErr)
	}
}

func newCodexHelperAdapter(t *testing.T, policy relayruntime.Policy) *Adapter {
	t.Helper()
	adapter, err := New(Config{
		Executable: os.Args[0], PrefixArgs: []string{"-test.run=TestCodexHelperProcess", "--"},
		EnvironmentAllowlist: []string{
			"RUNTIME_ADAPTER_TEST_CODEX_HELPER", "RUNTIME_ADAPTER_TEST_CODEX_MODE",
			"RUNTIME_ADAPTER_TEST_MCP_COUNTER", "RUNTIME_ADAPTER_TEST_CAPTURE",
		},
		WorkDir: t.TempDir(), Policy: policy, Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return adapter
}

func TestPostApprovalConfigReplacementCannotReachCodexChild(t *testing.T) {
	capturePath := filepath.Join(t.TempDir(), "capture.json")
	codexHome := t.TempDir()
	configPath := filepath.Join(codexHome, "config.toml")
	if err := os.WriteFile(configPath, []byte("[mcp_servers.initial]\ncommand = "+strconv.Quote("credential-sentinel-initial")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CODEX_HOME", codexHome)
	t.Setenv("RUNTIME_ADAPTER_TEST_CODEX_HELPER", "1")
	t.Setenv("RUNTIME_ADAPTER_TEST_CAPTURE", capturePath)
	policy := codexPolicyWithoutMCPs(t)
	adapter, err := New(Config{
		Executable:           os.Args[0],
		PrefixArgs:           []string{"-test.run=TestCodexHelperProcess", "--"},
		EnvironmentAllowlist: []string{"RUNTIME_ADAPTER_TEST_CODEX_HELPER", "RUNTIME_ADAPTER_TEST_CAPTURE"},
		WorkDir:              t.TempDir(),
		Policy:               policy,
		Timeout:              5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.ApprovalFingerprint(); err != nil {
		t.Fatal(err)
	}
	// Adversarial replacement happens after approval binding and immediately
	// before child launch. The child must not consume the new MCP definition.
	if err := os.WriteFile(configPath, []byte("[mcp_servers.after_approval]\ncommand = "+strconv.Quote("credential-sentinel-replacement")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	request := relayruntime.RunRequest{
		RequestID: "req_2", ConversationID: "conv_2", Title: "Count files",
		Requester: "Bob", Prompt: "Count files; TOKEN=private-value",
	}
	var events []relayruntime.Event
	result, err := adapter.Run(context.Background(), request, relayruntime.EventSinkFunc(func(_ context.Context, event relayruntime.Event) error {
		events = append(events, event)
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if result.FinalText != "There are 42 files." || result.Session == nil || result.Session.OpaqueID != "codex-session-1" {
		t.Fatalf("unexpected result: %#v", result)
	}
	if result.Usage.InputTokens != 100 || result.Usage.OutputTokens != 12 || result.Usage.CachedTokens != 20 {
		t.Fatalf("usage was not decoded: %#v", result.Usage)
	}
	for _, event := range events {
		if strings.Contains(event.Summary, "private-value") || strings.Contains(event.Summary, "rm -rf") || strings.Contains(event.Summary, "There are 42 files") {
			t.Fatalf("normalized event leaked raw input: %#v", event)
		}
	}

	data, err := os.ReadFile(capturePath)
	if err != nil {
		t.Fatal(err)
	}
	var capture struct {
		Args              []string `json:"args"`
		Stdin             string   `json:"stdin"`
		RecipientRun      string   `json:"recipient_run"`
		IgnoredUserConfig bool     `json:"ignored_user_config"`
		LoadedUserConfig  string   `json:"loaded_user_config"`
		CodexHome         string   `json:"codex_home"`
	}
	if err := json.Unmarshal(data, &capture); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(capture.Stdin, "private-value") || !strings.Contains(capture.Stdin, "permission-approved request") {
		t.Fatalf("request was not delivered over stdin: %q", capture.Stdin)
	}
	joinedArgs := strings.Join(capture.Args, " ")
	for _, secret := range []string{"private-value", "credential-sentinel-initial", "credential-sentinel-replacement", "after_approval"} {
		if strings.Contains(joinedArgs, secret) {
			t.Fatalf("secret or mutable config leaked into argv: %#v", capture.Args)
		}
	}
	if capture.RecipientRun != "1" || capture.CodexHome != codexHome {
		t.Fatalf("recipient context not preserved: %#v", capture)
	}
	if !capture.IgnoredUserConfig || capture.LoadedUserConfig != "" {
		t.Fatalf("post-approval user config replacement reached child: %#v", capture)
	}
	if !strings.Contains(joinedArgs, "exec --ignore-user-config") || slices.Contains(capture.Args, "--profile") ||
		!strings.Contains(joinedArgs, "features.plugins=false") || !strings.Contains(joinedArgs, "features.remote_plugin=false") ||
		!strings.Contains(joinedArgs, "features.apps=false") ||
		!strings.Contains(joinedArgs, "features.external_migration=false") || !strings.Contains(joinedArgs, "features.hooks=false") {
		t.Fatalf("child launch did not enforce exact empty MCP inventory: %#v", capture.Args)
	}
}

func TestCodexHelperProcess(t *testing.T) {
	if os.Getenv("RUNTIME_ADAPTER_TEST_CODEX_HELPER") != "1" {
		return
	}
	joinedArgs := strings.Join(os.Args, " ")
	mode := os.Getenv("RUNTIME_ADAPTER_TEST_CODEX_MODE")
	if strings.HasSuffix(joinedArgs, " --version") {
		fmt.Println("codex-cli 0.153.0-test")
		os.Exit(0)
	}
	if strings.Contains(joinedArgs, "exec --help") {
		if mode == "old_cli" {
			fmt.Println("Usage: codex exec [OPTIONS]")
		} else {
			fmt.Println("Usage: codex exec [OPTIONS]\n      --ignore-user-config")
		}
		os.Exit(0)
	}
	if strings.Contains(joinedArgs, "features list") {
		if mode == "reject_feature" {
			os.Exit(2)
		}
		for _, feature := range codexIntegrationFeatures {
			if !strings.Contains(joinedArgs, "features."+feature+"=false") {
				os.Exit(2)
			}
			if mode == "missing_feature" && feature == "hooks" {
				continue
			}
			value := "false"
			if mode == "forced_feature" && feature == "plugins" {
				value = "true"
			}
			fmt.Printf("%s stable %s\n", feature, value)
		}
		os.Exit(0)
	}
	if strings.Contains(joinedArgs, "mcp list --json") {
		for _, feature := range codexIntegrationFeatures {
			if !strings.Contains(joinedArgs, "features."+feature+"=false") {
				fmt.Println(`[{}]`)
				os.Exit(0)
			}
		}
		if !strings.Contains(joinedArgs, `.trust_level="untrusted"`) {
			fmt.Println(`[{}]`)
			os.Exit(0)
		}
		if _, err := os.Stat(filepath.Join(os.Getenv("CODEX_HOME"), "config.toml")); err == nil {
			fmt.Println(`[{}]`)
			os.Exit(0)
		}
		invocation := incrementHelperCounter(os.Getenv("RUNTIME_ADAPTER_TEST_MCP_COUNTER"))
		if mode == "residual" || mode == "residual_on_second" && invocation >= 2 {
			fmt.Println(`[{"name":"credential-sentinel-managed","transport":{"type":"streamable_http","url":"https://managed.example/mcp","http_headers":{"Authorization":"authorization-sentinel"}}}]`)
		} else {
			fmt.Println(`[]`)
		}
		os.Exit(0)
	}
	stdin, _ := io.ReadAll(os.Stdin)
	ignoredUserConfig := slices.Contains(os.Args, "--ignore-user-config")
	loadedUserConfig := ""
	if !ignoredUserConfig {
		if value, err := os.ReadFile(filepath.Join(os.Getenv("CODEX_HOME"), "config.toml")); err == nil {
			loadedUserConfig = string(value)
		}
	}
	capture, _ := json.Marshal(map[string]any{
		"args": os.Args, "stdin": string(stdin), "recipient_run": os.Getenv("AGENT_RELAY_RECIPIENT_RUN"),
		"ignored_user_config": ignoredUserConfig, "loaded_user_config": loadedUserConfig,
		"codex_home": os.Getenv("CODEX_HOME"),
	})
	if path := os.Getenv("RUNTIME_ADAPTER_TEST_CAPTURE"); path != "" {
		_ = os.WriteFile(path, capture, 0o600)
	}
	fmt.Println(`{"type":"thread.started","thread_id":"codex-session-1"}`)
	fmt.Println(`{"type":"item.started","item":{"id":"item_1","type":"command_execution","command":"rm -rf TOKEN=private-value","status":"in_progress"}}`)
	fmt.Println(`{"type":"item.completed","item":{"id":"item_1","type":"command_execution","command":"rm -rf TOKEN=private-value","exit_code":0,"status":"completed"}}`)
	fmt.Println(`{"type":"item.completed","item":{"id":"item_2","type":"agent_message","text":"There are 42 files."}}`)
	fmt.Println(`{"type":"turn.completed","usage":{"input_tokens":100,"cached_input_tokens":20,"output_tokens":12}}`)
}

func incrementHelperCounter(path string) int {
	if path == "" {
		return 1
	}
	value, _ := os.ReadFile(path)
	count, _ := strconv.Atoi(strings.TrimSpace(string(value)))
	count++
	_ = os.WriteFile(path, []byte(strconv.Itoa(count)), 0o600)
	return count
}
