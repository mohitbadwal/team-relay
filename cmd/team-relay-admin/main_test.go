package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/mohitbadwal/team-relay/internal/auth"
	"github.com/mohitbadwal/team-relay/internal/privatefs"
)

func TestAdminClientRequiresHTTPSOutsideExplicitInternalHost(t *testing.T) {
	t.Setenv("TEAM_RELAY_ALLOW_HTTP_HOST", "")
	if _, err := newAPIClient("http://relay:8080", "token"); err == nil {
		t.Fatal("remote HTTP was accepted without an exact-host exception")
	}
	if _, err := newAPIClient("http://127.0.0.1:8080", "token"); err != nil {
		t.Fatalf("loopback HTTP was rejected: %v", err)
	}
	if _, err := newAPIClient("https://relay.example.test", "token"); err != nil {
		t.Fatalf("HTTPS was rejected: %v", err)
	}

	t.Setenv("TEAM_RELAY_ALLOW_HTTP_HOST", "relay")
	if _, err := newAPIClient("http://relay:8080", "token"); err != nil {
		t.Fatalf("exact internal host was rejected: %v", err)
	}
	if _, err := newAPIClient("http://other:8080", "token"); err == nil {
		t.Fatal("HTTP exception applied to a different host")
	}
}

func TestBootstrapStagesClientCredentialAndRecoversLostResponse(t *testing.T) {
	t.Setenv("TEAM_RELAY_BOOTSTRAP_TOKEN", "")
	t.Setenv("TEAM_RELAY_ADMIN_TOKEN_FILE", "")
	directory := filepath.Join(t.TempDir(), "private")
	if err := privatefs.EnsureDirectory(directory); err != nil {
		t.Fatal(err)
	}
	bootstrapToken, _ := auth.NewToken(auth.TokenBootstrap)
	bootstrapPath := filepath.Join(directory, "bootstrap-token")
	if err := os.WriteFile(bootstrapPath, []byte(bootstrapToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	adminPath := filepath.Join(directory, "admin-token")
	var firstRequest map[string]string
	calls := 0
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if calls == 1 {
			firstRequest = body
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if body["admin_token_hash"] != firstRequest["admin_token_hash"] || body["idempotency_key"] != firstRequest["idempotency_key"] {
			t.Errorf("bootstrap retry changed identity: first=%#v retry=%#v", firstRequest, body)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"organization":{"id":"org_1","name":"Test"},"admin":{"id":"mem_1","display_name":"Admin"}}`))
	}))
	defer relay.Close()
	arguments := []string{"bootstrap", "--server", relay.URL, "--token-file", bootstrapPath, "--admin-token-file", adminPath,
		"--organization", "Test", "--name", "Admin", "--email", "admin@example.test"}
	if err := run(arguments); err == nil {
		t.Fatal("uncertain bootstrap response unexpectedly succeeded")
	}
	if _, err := os.Stat(adminPath); !os.IsNotExist(err) {
		t.Fatalf("admin token was finalized before confirmation: %v", err)
	}
	var attempt bootstrapAttempt
	if err := readRecoveryFile(bootstrapAttemptPath(adminPath), &attempt); err != nil {
		t.Fatal(err)
	}
	if firstRequest["admin_token_hash"] != auth.Hash(attempt.AdminToken) || firstRequest["admin_token"] != "" {
		t.Fatalf("server request did not contain only the staged hash: %#v", firstRequest)
	}
	if err := run(arguments); err != nil {
		t.Fatal(err)
	}
	stored, err := privatefs.ReadFile(adminPath)
	if err != nil || !auth.Equal(string(stored), attempt.AdminToken) {
		t.Fatalf("final admin token = %q, %v", stored, err)
	}
	if _, err := os.Stat(bootstrapAttemptPath(adminPath)); !os.IsNotExist(err) {
		t.Fatalf("completed bootstrap recovery file remains: %v", err)
	}
}

func TestRotationRecoversWithStagedNewCredentialAfterOldIsInvalid(t *testing.T) {
	t.Setenv("TEAM_RELAY_ADMIN_TOKEN", "")
	t.Setenv("TEAM_RELAY_REPLACEMENT_ADMIN_TOKEN_FILE", "")
	directory := filepath.Join(t.TempDir(), "private")
	if err := privatefs.EnsureDirectory(directory); err != nil {
		t.Fatal(err)
	}
	oldToken, _ := auth.NewToken(auth.TokenAdmin)
	tokenPath := filepath.Join(directory, "admin-token")
	if err := os.WriteFile(tokenPath, []byte(oldToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var firstRequest map[string]string
	calls := 0
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if calls == 1 {
			firstRequest = body
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if body["new_token_hash"] != firstRequest["new_token_hash"] || body["idempotency_key"] != firstRequest["idempotency_key"] {
			t.Errorf("rotation retry changed identity: first=%#v retry=%#v", firstRequest, body)
		}
		if calls == 2 {
			if r.Header.Get("Authorization") != "Bearer "+oldToken {
				t.Errorf("first recovery attempt did not use old token")
			}
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"rotated_at":"2026-09-05T12:00:00Z","replayed":true}`))
	}))
	defer relay.Close()
	arguments := []string{"credential", "rotate", "--server", relay.URL, "--token-file", tokenPath}
	if err := run(arguments); err == nil {
		t.Fatal("uncertain rotation response unexpectedly succeeded")
	}
	var attempt rotationAttempt
	if err := readRecoveryFile(rotationAttemptPath(tokenPath), &attempt); err != nil {
		t.Fatal(err)
	}
	if firstRequest["new_token_hash"] != auth.Hash(attempt.NewAdminToken) || firstRequest["admin_token"] != "" {
		t.Fatalf("server request did not contain only the staged hash: %#v", firstRequest)
	}
	if err := run(arguments); err != nil {
		t.Fatal(err)
	}
	stored, err := privatefs.ReadFile(tokenPath)
	if err != nil || !auth.Equal(string(stored), attempt.NewAdminToken) {
		t.Fatalf("final replacement token = %q, %v", stored, err)
	}
	if _, err := os.Stat(rotationAttemptPath(tokenPath)); !os.IsNotExist(err) {
		t.Fatalf("completed rotation recovery file remains: %v", err)
	}
}
