//go:build !windows

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigAndDeviceTokenRejectGroupReadableFiles(t *testing.T) {
	t.Setenv("TEAM_RELAY_DEVICE_TOKEN", "")
	directory := filepath.Join(t.TempDir(), "state")
	configPath := filepath.Join(directory, "config.yaml")
	tokenPath := filepath.Join(directory, "device-token")
	writePrivateTestFile(t, configPath, []byte("version: 1\nrelay:\n  url: https://relay.example\n"))
	writePrivateTestFile(t, tokenPath, []byte("tr_dev_test\n"))

	if err := os.Chmod(configPath, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(configPath); err == nil {
		t.Fatal("config loader accepted a group-readable config")
	}
	if err := os.Chmod(configPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tokenPath, 0o640); err != nil {
		t.Fatal(err)
	}
	config := Config{Relay: RelayConfig{TokenFile: tokenPath}}
	if _, err := config.DeviceToken(); err == nil {
		t.Fatal("device-token loader accepted a group-readable credential")
	}
}
