package runtime

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func boolPointer(value bool) *bool { return &value }

func TestEffectivePolicyNeverUpgradesRecipientPolicy(t *testing.T) {
	local, err := DefaultPolicy(PolicyReadOnly)
	if err != nil {
		t.Fatal(err)
	}
	effective, err := EffectivePolicy(local, &PolicyRequest{
		Mode:         PolicyGuardedWrite,
		AllowWrites:  boolPointer(true),
		AllowShell:   boolPointer(true),
		AllowNetwork: boolPointer(true),
		AllowMCPs:    boolPointer(true),
	})
	if err != nil {
		t.Fatal(err)
	}
	if effective.AllowWrites || effective.AllowShell || effective.AllowNetwork || effective.AllowMCPs {
		t.Fatalf("peer upgraded recipient policy: %#v", effective)
	}
	if effective.Mode != PolicyReadOnly {
		t.Fatalf("effective mode = %q, want read_only", effective.Mode)
	}
}

func TestEffectivePolicyCanNarrowGuardedWrite(t *testing.T) {
	local, err := DefaultPolicy(PolicyGuardedWrite)
	if err != nil {
		t.Fatal(err)
	}
	effective, err := EffectivePolicy(local, &PolicyRequest{Mode: PolicyReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	if effective.AllowWrites || effective.AllowShell || effective.AllowNetwork || effective.AllowMCPs {
		t.Fatalf("read-only request was not narrowed: %#v", effective)
	}
	for _, required := range []string{"rm", "git reset --hard", "terraform destroy"} {
		if !slices.Contains(effective.DeniedCommands, required) {
			t.Fatalf("baseline deny %q missing from %#v", required, effective.DeniedCommands)
		}
	}
}

func TestCustomPolicyIntersectionAndStableFingerprint(t *testing.T) {
	local, err := ValidatePolicy(Policy{
		Mode:           PolicyCustom,
		AllowWrites:    true,
		AllowShell:     true,
		AllowNetwork:   false,
		AllowMCPs:      true,
		DeniedCommands: []string{"custom-delete", "rm", "custom-delete"},
	})
	if err != nil {
		t.Fatal(err)
	}
	effective, err := EffectivePolicy(local, &PolicyRequest{
		AllowWrites:  boolPointer(true),
		AllowShell:   boolPointer(false),
		AllowNetwork: boolPointer(true),
		AllowMCPs:    boolPointer(false),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !effective.AllowWrites || effective.AllowShell || effective.AllowNetwork || effective.AllowMCPs {
		t.Fatalf("unexpected custom intersection: %#v", effective)
	}
	if effective.Mode != PolicyCustom {
		t.Fatalf("effective mode = %q, want custom", effective.Mode)
	}
	reordered := local
	reordered.DeniedCommands = []string{"rm", "custom-delete"}
	if PolicyFingerprint(local) != PolicyFingerprint(reordered) {
		t.Fatal("equivalent policies produced different fingerprints")
	}
}

func TestConstrainRequestDowngradesPathsForReadOnly(t *testing.T) {
	request := RunRequest{
		ReturnDirectory: filepath.Join(t.TempDir(), "return"),
		Workspaces:      []Workspace{{Path: filepath.Join(t.TempDir(), "repo"), Mode: WorkspaceWritable}},
	}
	policy, _ := DefaultPolicy(PolicyReadOnly)
	got := ConstrainRequest(request, policy)
	if got.ReturnDirectory != "" {
		t.Fatalf("read-only request retained return directory %q", got.ReturnDirectory)
	}
	if got.Workspaces[0].Mode != WorkspaceReadOnly {
		t.Fatalf("workspace mode = %q", got.Workspaces[0].Mode)
	}
	if request.Workspaces[0].Mode != WorkspaceWritable {
		t.Fatal("input request was mutated")
	}
}

func TestSafeSummaryRedactsAndBoundsProviderOutput(t *testing.T) {
	got := SafeSummary("running TOKEN=tr_dev_supersecret with sk-api-value " + strings.Repeat("界", 400))
	if strings.Contains(got, "supersecret") || strings.Contains(got, "sk-api-value") {
		t.Fatalf("summary leaked a credential: %q", got)
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Fatalf("summary did not show redaction: %q", got)
	}
	if len([]rune(got)) > MaxSummaryRunes+1 {
		t.Fatalf("summary was not bounded: %d runes", len([]rune(got)))
	}
}

func TestRedactSensitiveTextCoversTeamRelayCredentials(t *testing.T) {
	input := "device tr_dev_abcdef bootstrap tr_boot_123456 control trl_987654 and TOKEN=hidden"
	got := RedactSensitiveText(input)
	for _, secret := range []string{"tr_dev_abcdef", "tr_boot_123456", "trl_987654", "hidden"} {
		if strings.Contains(got, secret) {
			t.Fatalf("redaction retained %q in %q", secret, got)
		}
	}
}

func TestValidateRunRequestRejectsNetworkSuppliedStylePaths(t *testing.T) {
	request := RunRequest{RequestID: "req_1", ConversationID: "conv_1", Prompt: "hello", Attachments: []string{"../secret"}}
	if err := ValidateRunRequest(request); err == nil {
		t.Fatal("relative attachment path accepted")
	}
}

func TestSanitizedEnvironmentUsesRecipientAllowlistButNeverPassesRelayAuthority(t *testing.T) {
	input := []string{
		"TEAM_RELAY_DEVICE_TOKEN=tr_dev_secret",
		"TEAM_RELAY_ADMIN_TOKEN=tr_admin_secret",
		"TEAM_RELAY_BOOTSTRAP_SECRET=secret",
		"TEAM_RELAY_CONFIG=/private/team-relay/config.yaml",
		"ANTHROPIC_API_KEY=provider-key",
		"OPENAI_API_KEY=provider-key",
		"DATABASE_PASSWORD=database-secret",
		"PATH=/usr/bin",
		"LC_ALL=en_US.UTF-8",
	}
	got := SanitizedEnvironment(input, []string{"ANTHROPIC_API_KEY", "TEAM_RELAY_DEVICE_TOKEN"})
	joined := strings.Join(got, "\n")
	for _, forbidden := range []string{"TEAM_RELAY_DEVICE_TOKEN", "TEAM_RELAY_ADMIN_TOKEN", "TEAM_RELAY_BOOTSTRAP_SECRET", "TEAM_RELAY_CONFIG", "tr_dev_secret", "tr_admin_secret"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("sanitized environment contains %q: %#v", forbidden, got)
		}
	}
	for _, forbidden := range []string{"OPENAI_API_KEY=provider-key", "DATABASE_PASSWORD=database-secret"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("sanitized environment retained unlisted value %q: %#v", forbidden, got)
		}
	}
	for _, required := range []string{"ANTHROPIC_API_KEY=provider-key", "PATH=/usr/bin", "LC_ALL=en_US.UTF-8"} {
		if !strings.Contains(joined, required) {
			t.Fatalf("sanitized environment dropped %q: %#v", required, got)
		}
	}
}
