package main

import (
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLifecycleOptions(t *testing.T) {
	defaultConfig := filepath.Join(t.TempDir(), "team-relay.conf")
	explicitConfig := filepath.Join(t.TempDir(), "custom service.conf")
	tests := []struct {
		name      string
		args      []string
		wantError string
		wantHelp  bool
		want      lifecycleOptions
	}{
		{name: "default start", args: []string{"start"}, want: lifecycleOptions{action: "start", configPath: defaultConfig}},
		{name: "explicit log follow", args: []string{"logs", "--config", explicitConfig, "--follow"}, want: lifecycleOptions{action: "logs", configPath: explicitConfig, follow: true}},
		{name: "missing action", wantError: "requires"},
		{name: "invalid action", args: []string{"delete"}, wantError: "unknown"},
		{name: "extra argument", args: []string{"stop", "receiver"}, wantError: "positional"},
		{name: "follow start rejected", args: []string{"start", "--follow"}, wantError: "only with logs"},
		{name: "empty config", args: []string{"status", "--config="}, wantError: "cannot be empty"},
		{name: "role help", args: []string{"--help"}, wantHelp: true},
		{name: "action help", args: []string{"restart", "--help"}, wantHelp: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseLifecycleOptions("receiver", test.args, defaultConfig, io.Discard)
			if test.wantHelp {
				if !errors.Is(err, flag.ErrHelp) {
					t.Fatalf("got %v, want help", err)
				}
				return
			}
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("got %v, want error containing %q", err, test.wantError)
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("got %+v, %v; want %+v", got, err, test.want)
			}
		})
	}
}

func TestDefaultLifecycleConfigFindsCheckoutAndHonorsLocalOverride(t *testing.T) {
	directory := t.TempDir()
	checkout := filepath.Join(directory, "checkout")
	cwd := filepath.Join(directory, "elsewhere")
	if err := os.MkdirAll(checkout, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(checkout, "bin", "team-relay")
	checkoutConfig := filepath.Join(checkout, "team-relay.conf")
	if err := os.WriteFile(checkoutConfig, []byte("TEAM_RELAY_SERVER_MODE=native\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := defaultLifecycleConfig(cwd, executable); got != checkoutConfig {
		t.Fatalf("got %q, want checkout config %q", got, checkoutConfig)
	}
	localConfig := filepath.Join(cwd, "team-relay.conf")
	if err := os.WriteFile(localConfig, []byte("TEAM_RELAY_SERVER_MODE=docker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := defaultLifecycleConfig(cwd, executable); got != localConfig {
		t.Fatalf("got %q, want local override %q", got, localConfig)
	}
}
