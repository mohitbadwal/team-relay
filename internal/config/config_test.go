package config

import (
	"path/filepath"
	"testing"

	"github.com/mohitbadwal/team-relay/internal/privatefs"
)

func TestLoadRejectsUnknownFields(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "state", "config.yaml")
	writePrivateTestFile(t, path, []byte("version: 1\nrelay:\n  url: https://relay.example\nunknown: true\n"))
	if _, err := Load(path); err == nil {
		t.Fatal("expected unknown field error")
	}
}

func TestEnvironmentOverridesRelayURL(t *testing.T) {
	t.Setenv("TEAM_RELAY_URL", "https://override.example")
	path := filepath.Join(t.TempDir(), "state", "config.yaml")
	writePrivateTestFile(t, path, []byte("version: 1\nrelay:\n  url: https://original.example\n"))
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Relay.URL != "https://override.example" {
		t.Fatalf("unexpected relay URL %q", cfg.Relay.URL)
	}
}

func TestRuntimeEnvironmentAllowlistUsesPortableUniqueNames(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		variables string
	}{
		{name: "invalid", variables: "    - BAD-NAME"},
		{name: "duplicate case insensitive", variables: "    - API_TOKEN\n    - api_token"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "state", "config.yaml")
			payload := "version: 1\nrelay:\n  url: https://relay.example\nreceiver:\n  profile: default\nprofiles:\n  default:\n    runtime: codex\n    environment_allowlist:\n" + testCase.variables + "\n"
			writePrivateTestFile(t, path, []byte(payload))
			if _, err := Load(path); err == nil {
				t.Fatal("expected invalid environment allowlist to be rejected")
			}
		})
	}
}

func TestDeviceTokenLoadsFromPrivateFile(t *testing.T) {
	t.Setenv("TEAM_RELAY_DEVICE_TOKEN", "")
	path := filepath.Join(t.TempDir(), "state", "device-token")
	writePrivateTestFile(t, path, []byte("tr_dev_test\n"))
	config := Config{Relay: RelayConfig{TokenFile: path}}
	token, err := config.DeviceToken()
	if err != nil {
		t.Fatal(err)
	}
	if token != "tr_dev_test" {
		t.Fatalf("token = %q", token)
	}
}

func writePrivateTestFile(t *testing.T, path string, payload []byte) {
	t.Helper()
	if err := privatefs.EnsureDirectory(filepath.Dir(path)); err != nil {
		t.Fatal(err)
	}
	if err := privatefs.AtomicWriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
}
