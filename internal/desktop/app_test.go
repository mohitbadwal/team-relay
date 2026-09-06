package desktop

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/mohitbadwal/team-relay/internal/lifecycle"
)

func TestJoinRequiresRecipientChoices(t *testing.T) {
	dir := t.TempDir()
	valid := joinInput{Server: "http://192.168.1.4:8080", Invite: "test-invite", Name: "Teammate", Runtime: "claude-code", WorkDir: dir, Permission: "read_only"}
	if err := validateJoin(&valid); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*joinInput){
		func(v *joinInput) { v.Permission = "" },
		func(v *joinInput) { v.Runtime = "codex" },
		func(v *joinInput) { v.WorkDir = "relative" },
		func(v *joinInput) { v.Server = "http://public.example.test" },
		func(v *joinInput) { v.Invite = "" },
	} {
		input := valid
		change(&input)
		if validateJoin(&input) == nil {
			t.Fatalf("accepted missing/unsafe choice: %+v", input)
		}
	}
}

func TestDesktopEnvironmentNeverInheritsRelayOverrides(t *testing.T) {
	t.Setenv("TEAM_RELAY_DEVICE_TOKEN", "do-not-inherit")
	t.Setenv("TEAM_RELAY_INVITE_TOKEN", "do-not-inherit")
	t.Setenv("TEAM_RELAY_URL", "http://other-relay")
	for _, entry := range desktopEnvironment() {
		if strings.HasPrefix(entry, "TEAM_RELAY_") {
			t.Fatal("inherited relay override")
		}
	}
}

func TestSkillsAutomaticIdempotentAndPreserveEdits(t *testing.T) {
	root := t.TempDir()
	t.Setenv("CLAUDE_CONFIG_DIR", root)
	if err := installSkills("claude-code"); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"requester", "recipient"} {
		path := filepath.Join(root, "skills", "team-relay-"+role, "SKILL.md")
		data, err := os.ReadFile(path)
		if err != nil || !strings.Contains(string(data), "Team Relay") {
			t.Fatal("skill not installed", err)
		}
	}
	path := filepath.Join(root, "skills", "team-relay-recipient", "SKILL.md")
	if err := os.WriteFile(path, []byte("custom instructions"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := installSkills("claude-code"); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "custom instructions" {
		t.Fatal("overwrote custom instructions")
	}
}

func TestClaudeConflictDetectedBeforeMutation(t *testing.T) {
	root := t.TempDir()
	t.Setenv("CLAUDE_CONFIG_DIR", root)
	payload := []byte(`{"mcpServers":{"team-relay":{"type":"stdio","command":"/other/relay","args":[]},"keep-me":{"type":"stdio","command":"/other/tool"}}}`)
	path := filepath.Join(root, ".claude.json")
	if err := os.WriteFile(path, payload, 0600); err != nil {
		t.Fatal(err)
	}
	a := app{self: filepath.Join(root, "team-relay"), settings: lifecycle.ReceiverSettings{ConfigPath: filepath.Join(root, "config.yaml")}}
	if err := a.checkMCP(context.Background(), "claude-code"); err == nil {
		t.Fatal("accepted foreign MCP")
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(payload) {
		t.Fatal("changed existing client config")
	}
}

// Exercises the real installed Claude/Codex MCP configuration commands against
// their supported, disposable configuration directories. No user config is
// replaced, no login is performed, and no model or teammate prompt is run.
func TestAgentIntegrationLive(t *testing.T) {
	if os.Getenv("TEAM_RELAY_TEST_AGENT_INTEGRATION") != "1" {
		t.Skip("opt in to real agent CLI integration")
	}
	if runtime.GOOS == "windows" {
		t.Skip("live local check currently targets Unix agent CLIs")
	}
	root := t.TempDir()
	build := exec.Command("go", "build", "-o", filepath.Join(root, "team-relay-mcp"), "../../cmd/team-relay-mcp")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %s: %v", output, err)
	}
	for _, id := range []string{"claude-code", "codex"} {
		t.Run(id, func(t *testing.T) {
			profile := t.TempDir()
			if err := os.Chmod(profile, 0700); err != nil {
				t.Fatal(err)
			}
			// These are each CLI's documented config-location settings, scoped
			// only to this test and its children. The real HOME is not changed.
			t.Setenv("CLAUDE_CONFIG_DIR", filepath.Join(profile, "claude"))
			t.Setenv("CODEX_HOME", filepath.Join(profile, "codex"))
			for _, dir := range []string{"claude", "codex"} {
				if err := os.MkdirAll(filepath.Join(profile, dir), 0700); err != nil {
					t.Fatal(err)
				}
			}
			token := filepath.Join(profile, "device.token")
			if err := os.WriteFile(token, []byte("disposable-handshake-fixture"), 0600); err != nil {
				t.Fatal(err)
			}
			configuration := "version: 1\nrelay:\n  url: http://127.0.0.1:1\n  token_file: " + token + "\n"
			cfgPath := filepath.Join(profile, "config.yaml")
			if err := os.WriteFile(cfgPath, []byte(configuration), 0600); err != nil {
				t.Fatal(err)
			}
			a := app{self: filepath.Join(root, "team-relay"), settings: lifecycle.ReceiverSettings{ConfigPath: cfgPath}}
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			defer cancel()
			if err := a.installIntegration(ctx, id); err != nil {
				t.Fatal(err)
			}
			if err := a.installIntegration(ctx, id); err != nil {
				t.Fatalf("repeat install: %v", err)
			}
			entry, err := existingMCP(ctx, id)
			if err != nil || entry == nil {
				t.Fatal("integration not persisted", err)
			}
			bytes, _ := json.Marshal(entry)
			if strings.Contains(string(bytes), "disposable-handshake-fixture") {
				t.Fatal("token was copied into client config")
			}
			t.Log("Real agent MCP registration, repeat-install preservation, bundled skills and live MCP tool handshake passed; no model call.")
		})
	}
}
