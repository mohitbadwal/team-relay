package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mohitbadwal/team-relay/internal/auth"
	"github.com/mohitbadwal/team-relay/internal/client"
	"github.com/mohitbadwal/team-relay/internal/privatefs"
)

func TestConfiguredRuntimeID(t *testing.T) {
	tests := []struct {
		runtime    string
		externalID string
		want       string
		wantError  bool
	}{
		{runtime: "claude-code", externalID: "ignored", want: "claude-code"},
		{runtime: "codex", want: "codex"},
		{runtime: "external", externalID: "local-agent", want: "external:local-agent"},
		{runtime: "external", externalID: "Uppercase", wantError: true},
		{runtime: "external", externalID: "-invalid", wantError: true},
		{runtime: "external", externalID: "", wantError: true},
	}
	for _, test := range tests {
		got, err := configuredRuntimeID(test.runtime, test.externalID)
		if test.wantError {
			if err == nil {
				t.Fatalf("configuredRuntimeID(%q, %q) unexpectedly succeeded with %q", test.runtime, test.externalID, got)
			}
			continue
		}
		if err != nil || got != test.want {
			t.Fatalf("configuredRuntimeID(%q, %q) = %q, %v; want %q", test.runtime, test.externalID, got, err, test.want)
		}
	}
}

func TestSetupRejectsCodexReadOnlyBeforeReadingInvitation(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	err := setup([]string{
		"--server", "http://localhost:8080",
		"--runtime", "codex",
		"--permission", "read_only",
		"--name", "Alice",
		"--device-name", "laptop",
		"--work-dir", directory,
		"--config", filepath.Join(directory, "config.yaml"),
		"--invite-file", filepath.Join(directory, "does-not-exist"),
	})
	if err == nil || !strings.Contains(err.Error(), "Codex cannot run with a shell-disabled policy") {
		t.Fatalf("Codex read_only setup error = %v", err)
	}
}

func TestSetupMCPInheritanceUsesProviderSafeDefaults(t *testing.T) {
	tests := []struct {
		name          string
		runtime       string
		requested     bool
		explicit      bool
		want          bool
		wantErrorText string
	}{
		{name: "Claude default", runtime: "claude-code", requested: true, want: true},
		{name: "Claude explicit deny", runtime: "claude-code", requested: false, explicit: true, want: false},
		{name: "external default", runtime: "external", requested: true, want: true},
		{name: "Codex safe default", runtime: "codex", requested: true, want: false},
		{name: "Codex explicit deny", runtime: "codex", requested: false, explicit: true, want: false},
		{name: "Codex explicit allow", runtime: "codex", requested: true, explicit: true, wantErrorText: "cannot currently inherit local MCP servers safely"},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			got, err := setupMCPInheritance(testCase.runtime, testCase.requested, testCase.explicit)
			if testCase.wantErrorText != "" {
				if err == nil || !strings.Contains(err.Error(), testCase.wantErrorText) {
					t.Fatalf("setupMCPInheritance() error = %v, want %q", err, testCase.wantErrorText)
				}
				return
			}
			if err != nil || got != testCase.want {
				t.Fatalf("setupMCPInheritance() = %t, %v; want %t", got, err, testCase.want)
			}
		})
	}
}

func TestSetupRejectsExplicitCodexMCPInheritanceBeforeReadingInvitation(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	err := setup([]string{
		"--server", "http://localhost:8080",
		"--runtime", "codex",
		"--permission", "guarded_write",
		"--inherit-mcps=true",
		"--name", "Alice",
		"--device-name", "laptop",
		"--work-dir", directory,
		"--config", filepath.Join(directory, "config.yaml"),
		"--invite-file", filepath.Join(directory, "does-not-exist"),
	})
	if err == nil || !strings.Contains(err.Error(), "cannot currently inherit local MCP servers safely") {
		t.Fatalf("Codex MCP setup error = %v", err)
	}
}

func TestWriteSecretRemovesPartialFileOnWriteAndCloseErrors(t *testing.T) {
	tests := []struct {
		name string
		wrap func(*os.File) secretFile
	}{
		{
			name: "write",
			wrap: func(file *os.File) secretFile {
				return &faultingSecretFile{File: file, writeErr: errors.New("disk full")}
			},
		},
		{
			name: "close",
			wrap: func(file *os.File) secretFile {
				return &faultingSecretFile{File: file, closeErr: errors.New("close failed")}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			original := openNewSecretFile
			defer func() { openNewSecretFile = original }()
			openNewSecretFile = func(path string) (secretFile, error) {
				file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
				if err != nil {
					return nil, err
				}
				return test.wrap(file), nil
			}

			path := filepath.Join(t.TempDir(), "secret")
			if err := writeSecret(path, []byte("sensitive payload")); err == nil {
				t.Fatal("writeSecret unexpectedly succeeded")
			}
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("partial secret remains after failure: %v", err)
			}
		})
	}
}

func TestSetupReservesAndStagesDestinationsBeforeEnrollment(t *testing.T) {
	t.Setenv("TEAM_RELAY_INVITE_TOKEN", "tr_inv_test")
	directory := filepath.Join(t.TempDir(), "state")
	configPath := filepath.Join(directory, "config.yaml")
	tokenPath := filepath.Join(directory, "device-token")
	originalEnroll := enrollRelayDevice
	defer func() { enrollRelayDevice = originalEnroll }()
	var enrollmentRequest client.EnrollmentRequest
	enrollRelayDevice = func(_ context.Context, serverURL, invite string, request client.EnrollmentRequest) (*client.EnrollmentResponse, error) {
		if serverURL != "http://localhost:8080" || invite != "tr_inv_test" {
			t.Errorf("enrollment received server=%q invite=%q", serverURL, invite)
		}
		enrollmentRequest = request
		if err := privatefs.ValidateDirectory(directory); err != nil {
			t.Errorf("setup directory is not private during enrollment: %v", err)
		}
		assertFileSize(t, configPath, 0)
		assertPrivateRegularFile(t, configPath)
		token, err := os.ReadFile(tokenPath)
		if err != nil || auth.Hash(string(token)) != request.DeviceTokenHash {
			t.Errorf("complete client-owned token was not durable before enrollment: hash=%q err=%v", auth.Hash(string(token)), err)
		}
		assertPrivateRegularFile(t, tokenPath)
		if !validEnrollmentIdempotencyKey(request.IdempotencyKey) {
			t.Errorf("invalid enrollment idempotency key %q", request.IdempotencyKey)
		}
		attempts, _ := filepath.Glob(filepath.Join(directory, "config.yaml.enrollment-attempt"))
		if len(attempts) != 1 {
			t.Errorf("durable enrollment attempt files = %v; want one", attempts)
		} else {
			assertPrivateRegularFile(t, attempts[0])
		}
		configStages, _ := filepath.Glob(filepath.Join(directory, ".config.yaml.setup-*"))
		if len(configStages) != 1 {
			t.Errorf("enrollment saw config stages %v; want one", configStages)
		} else {
			assertPrivateRegularFile(t, configStages[0])
			configInfo, configErr := os.Stat(configStages[0])
			if configErr != nil || configInfo.Size() == 0 {
				t.Errorf("config was not completely staged before enrollment: info=%v err=%v", configInfo, configErr)
			}
		}
		response := &client.EnrollmentResponse{}
		response.Member.DisplayName = "Alice"
		response.Device.AgentID = "agent_1"
		response.Device.Name = "laptop"
		return response, nil
	}

	err := setup([]string{
		"--server", "http://localhost:8080",
		"--runtime", "claude-code",
		"--name", "Alice",
		"--device-name", "laptop",
		"--work-dir", directory,
		"--config", configPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	token, err := os.ReadFile(tokenPath)
	if err != nil || auth.Hash(string(token)) != enrollmentRequest.DeviceTokenHash {
		t.Fatalf("published token hash = %q, %v; want %q", auth.Hash(string(token)), err, enrollmentRequest.DeviceTokenHash)
	}
	configPayload, err := os.ReadFile(configPath)
	if err != nil || !strings.Contains(string(configPayload), tokenPath) {
		t.Fatalf("published config does not reference token path: %q, %v", configPayload, err)
	}
	stages, _ := filepath.Glob(filepath.Join(directory, ".*.setup-*"))
	if len(stages) != 0 {
		t.Fatalf("successful setup left staging files: %v", stages)
	}
}

func TestSetupRetainsCompleteRecoveryConfigWhenPublicationFailsAfterEnrollment(t *testing.T) {
	t.Setenv("TEAM_RELAY_INVITE_TOKEN", "tr_inv_test")
	directory := filepath.Join(t.TempDir(), "state")
	configPath := filepath.Join(directory, "config.yaml")
	tokenPath := filepath.Join(directory, "device-token")
	originalEnroll := enrollRelayDevice
	defer func() { enrollRelayDevice = originalEnroll }()
	var enrollmentRequest client.EnrollmentRequest
	enrollRelayDevice = func(_ context.Context, _ string, _ string, request client.EnrollmentRequest) (*client.EnrollmentResponse, error) {
		enrollmentRequest = request
		response := &client.EnrollmentResponse{}
		response.Member.DisplayName = "Alice"
		response.Device.AgentID = "agent_recovery"
		response.Device.Name = "laptop"
		return response, nil
	}

	originalRename := renameSetupFile
	defer func() { renameSetupFile = originalRename }()
	renameSetupFile = func(oldPath, newPath string) error {
		if newPath == configPath {
			return errors.New("injected rename failure")
		}
		return os.Rename(oldPath, newPath)
	}

	err := setup([]string{
		"--server", "http://localhost:8080",
		"--runtime", "claude-code",
		"--name", "Alice",
		"--device-name", "laptop",
		"--work-dir", directory,
		"--config", configPath,
	})
	if err == nil {
		t.Fatal("setup unexpectedly succeeded")
	}
	for _, fragment := range []string{"agent_recovery", "device token is complete", "config remains unpublished", "retry state remains", "rerun the identical setup command"} {
		if !strings.Contains(err.Error(), fragment) {
			t.Fatalf("error %q does not contain %q", err, fragment)
		}
	}
	token, readErr := os.ReadFile(tokenPath)
	if readErr != nil || auth.Hash(string(token)) != enrollmentRequest.DeviceTokenHash {
		t.Fatalf("complete published token was not retained: %q, %v", token, readErr)
	}
	if _, statErr := os.Stat(configPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("empty config reservation was not removed: %v", statErr)
	}
	configStages, _ := filepath.Glob(filepath.Join(directory, ".config.yaml.setup-*"))
	if len(configStages) != 0 {
		t.Fatalf("config publication failure left stale stages: %v", configStages)
	}
}

func TestSetupRetriesResponseLossWithSameStagedTokenAndIdempotencyKey(t *testing.T) {
	t.Setenv("TEAM_RELAY_INVITE_TOKEN", "tr_inv_test")
	directory := filepath.Join(t.TempDir(), "state")
	configPath := filepath.Join(directory, "config.yaml")
	tokenPath := filepath.Join(directory, "device-token")
	originalEnroll := enrollRelayDevice
	defer func() { enrollRelayDevice = originalEnroll }()
	var requests []client.EnrollmentRequest
	enrollRelayDevice = func(_ context.Context, _ string, _ string, request client.EnrollmentRequest) (*client.EnrollmentResponse, error) {
		requests = append(requests, request)
		if len(requests) == 1 {
			return nil, errors.New("connection reset after request write")
		}
		response := &client.EnrollmentResponse{}
		response.Member.DisplayName = "Alice"
		response.Device.AgentID = "agent_recovered"
		response.Device.Name = "laptop"
		return response, nil
	}

	arguments := []string{
		"--server", "http://localhost:8080",
		"--runtime", "claude-code",
		"--name", "Alice",
		"--device-name", "laptop",
		"--work-dir", directory,
		"--config", configPath,
	}
	err := setup(arguments)
	if err == nil {
		t.Fatal("first setup unexpectedly succeeded")
	}
	for _, fragment := range []string{"outcome is unknown", "complete device token remains", "rerun the identical setup command"} {
		if !strings.Contains(err.Error(), fragment) {
			t.Fatalf("error %q does not contain %q", err, fragment)
		}
	}
	firstToken, err := os.ReadFile(tokenPath)
	if err != nil || auth.Hash(string(firstToken)) != requests[0].DeviceTokenHash {
		t.Fatalf("staged token did not survive ambiguous response: %q, %v", firstToken, err)
	}
	if _, err := os.Stat(configPath + ".enrollment-attempt"); err != nil {
		t.Fatalf("retry state did not survive ambiguous response: %v", err)
	}
	if _, err := os.Stat(configPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("config should remain unpublished while enrollment is ambiguous: %v", err)
	}
	mismatchedArguments := append([]string(nil), arguments...)
	mismatchedArguments[7] = "different-laptop"
	if err := setup(mismatchedArguments); err == nil || !strings.Contains(err.Error(), "saved enrollment attempt does not match") {
		t.Fatalf("mismatched local retry error = %v", err)
	}
	if len(requests) != 1 {
		t.Fatalf("mismatched local retry reached enrollment: %#v", requests)
	}

	if err := setup(arguments); err != nil {
		t.Fatalf("retry setup failed: %v", err)
	}
	if len(requests) != 2 || requests[0].DeviceTokenHash != requests[1].DeviceTokenHash || requests[0].IdempotencyKey != requests[1].IdempotencyKey {
		t.Fatalf("retry changed enrollment identity: %#v", requests)
	}
	secondToken, err := os.ReadFile(tokenPath)
	if err != nil || string(secondToken) != string(firstToken) {
		t.Fatalf("retry changed staged token: before=%q after=%q err=%v", firstToken, secondToken, err)
	}
	if _, err := os.Stat(configPath + ".enrollment-attempt"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("successful retry left enrollment state: %v", err)
	}
}

type faultingSecretFile struct {
	*os.File
	writeErr error
	closeErr error
}

func (f *faultingSecretFile) Write(payload []byte) (int, error) {
	if f.writeErr == nil {
		return f.File.Write(payload)
	}
	if len(payload) > 0 {
		_, _ = f.File.Write(payload[:1])
	}
	return 0, f.writeErr
}

func (f *faultingSecretFile) Close() error {
	err := f.File.Close()
	if f.closeErr != nil {
		return f.closeErr
	}
	return err
}

func assertFileSize(t *testing.T, path string, want int64) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Errorf("stat %s during enrollment: %v", path, err)
		return
	}
	if info.Size() != want {
		t.Errorf("size of %s during enrollment = %d; want %d", path, info.Size(), want)
	}
}

func assertPrivateRegularFile(t *testing.T, path string) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Errorf("inspect private file %s: %v", path, err)
		return
	}
	if err := platformValidatePrivateRegularFile(path, info); err != nil {
		t.Errorf("file %s is not private: %v", path, err)
	}
}
