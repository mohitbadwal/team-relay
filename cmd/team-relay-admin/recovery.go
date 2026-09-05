package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/mohitbadwal/team-relay/internal/auth"
	"github.com/mohitbadwal/team-relay/internal/privatefs"
)

const recoveryVersion = 1

type bootstrapAttempt struct {
	Version          int    `json:"version"`
	ServerURL        string `json:"server_url"`
	OrganizationName string `json:"organization_name"`
	AdminDisplayName string `json:"admin_display_name"`
	AdminEmail       string `json:"admin_email"`
	AdminToken       string `json:"admin_token"`
	IdempotencyKey   string `json:"idempotency_key"`
}

type rotationAttempt struct {
	Version         int    `json:"version"`
	ServerURL       string `json:"server_url"`
	SourceTokenHash string `json:"source_token_hash"`
	NewAdminToken   string `json:"new_admin_token"`
	IdempotencyKey  string `json:"idempotency_key"`
}

func bootstrapAttemptPath(tokenPath string) string {
	return strings.TrimSpace(tokenPath) + ".bootstrap-attempt"
}

func rotationAttemptPath(tokenPath string) string {
	return strings.TrimSpace(tokenPath) + ".rotation-attempt"
}

func prepareBootstrapAttempt(tokenPath, serverURL, organization, displayName, email string) (bootstrapAttempt, error) {
	tokenPath = strings.TrimSpace(tokenPath)
	expected := bootstrapAttempt{
		Version: recoveryVersion, ServerURL: serverURL,
		OrganizationName: strings.TrimSpace(organization), AdminDisplayName: strings.TrimSpace(displayName),
		AdminEmail: strings.ToLower(strings.TrimSpace(email)),
	}
	if err := ensurePrivateOutputDirectory(tokenPath); err != nil {
		return bootstrapAttempt{}, err
	}
	attemptPath := bootstrapAttemptPath(tokenPath)
	var existing bootstrapAttempt
	if err := readRecoveryFile(attemptPath, &existing); err == nil {
		if existing.Version != expected.Version || existing.ServerURL != expected.ServerURL ||
			existing.OrganizationName != expected.OrganizationName || existing.AdminDisplayName != expected.AdminDisplayName ||
			existing.AdminEmail != expected.AdminEmail || !validRecoveryToken(existing.AdminToken, auth.TokenAdmin) ||
			!validRecoveryID(existing.IdempotencyKey, "tr_bootstrap_") {
			return bootstrapAttempt{}, errors.New("bootstrap recovery state does not match this command; use the original arguments and server")
		}
		if err := ensureFinalTokenMatchesOrAbsent(tokenPath, existing.AdminToken); err != nil {
			return bootstrapAttempt{}, err
		}
		return existing, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return bootstrapAttempt{}, fmt.Errorf("read bootstrap recovery state: %w", err)
	}
	if _, err := os.Lstat(tokenPath); err == nil {
		return bootstrapAttempt{}, errors.New("admin token destination already exists without matching bootstrap recovery state")
	} else if !errors.Is(err, fs.ErrNotExist) {
		return bootstrapAttempt{}, fmt.Errorf("inspect admin token destination: %w", err)
	}
	var err error
	expected.AdminToken, err = auth.NewToken(auth.TokenAdmin)
	if err != nil {
		return bootstrapAttempt{}, err
	}
	expected.IdempotencyKey, err = newRecoveryID("tr_bootstrap_")
	if err != nil {
		return bootstrapAttempt{}, err
	}
	if err := writeRecoveryFile(attemptPath, expected); err != nil {
		return bootstrapAttempt{}, fmt.Errorf("stage bootstrap recovery state: %w", err)
	}
	return expected, nil
}

func prepareRotationAttempt(tokenPath, serverURL, currentToken string) (rotationAttempt, error) {
	tokenPath = strings.TrimSpace(tokenPath)
	if err := ensurePrivateOutputDirectory(tokenPath); err != nil {
		return rotationAttempt{}, err
	}
	attemptPath := rotationAttemptPath(tokenPath)
	var existing rotationAttempt
	if err := readRecoveryFile(attemptPath, &existing); err == nil {
		currentHash := auth.Hash(currentToken)
		if existing.Version != recoveryVersion || existing.ServerURL != serverURL ||
			(currentHash != existing.SourceTokenHash && currentHash != auth.Hash(existing.NewAdminToken)) ||
			!validRecoveryToken(existing.NewAdminToken, auth.TokenAdmin) ||
			!validRecoveryID(existing.IdempotencyKey, "tr_rotate_") {
			return rotationAttempt{}, errors.New("rotation recovery state does not match this server or current credential")
		}
		if err := ensureRotationTokenMatchesOrAbsent(tokenPath, existing.SourceTokenHash, existing.NewAdminToken); err != nil {
			return rotationAttempt{}, err
		}
		return existing, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return rotationAttempt{}, fmt.Errorf("read rotation recovery state: %w", err)
	}
	attempt := rotationAttempt{
		Version: recoveryVersion, ServerURL: serverURL, SourceTokenHash: auth.Hash(currentToken),
	}
	var err error
	attempt.NewAdminToken, err = auth.NewToken(auth.TokenAdmin)
	if err != nil {
		return rotationAttempt{}, err
	}
	attempt.IdempotencyKey, err = newRecoveryID("tr_rotate_")
	if err != nil {
		return rotationAttempt{}, err
	}
	if err := writeRecoveryFile(attemptPath, attempt); err != nil {
		return rotationAttempt{}, fmt.Errorf("stage rotation recovery state: %w", err)
	}
	return attempt, nil
}

func finalizeAdminToken(tokenPath, attemptPath, rawToken, replaceTokenHash string) error {
	if err := ensurePrivateOutputDirectory(tokenPath); err != nil {
		return err
	}
	if _, err := os.Lstat(tokenPath); errors.Is(err, fs.ErrNotExist) {
		if err := privatefs.WriteNewFile(tokenPath, []byte(rawToken+"\n"), 0o600); err != nil {
			return fmt.Errorf("write admin token: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("inspect admin token: %w", err)
	} else {
		payload, readErr := privatefs.ReadFile(tokenPath)
		if readErr != nil {
			return fmt.Errorf("read existing admin token destination: %w", readErr)
		}
		if !auth.Equal(string(payload), rawToken) {
			if replaceTokenHash == "" || auth.Hash(string(payload)) != replaceTokenHash {
				return errors.New("admin token destination contains a different credential")
			}
			if err := privatefs.AtomicWriteFile(tokenPath, []byte(rawToken+"\n"), 0o600); err != nil {
				return fmt.Errorf("replace admin token: %w", err)
			}
		}
	}
	if err := os.Remove(attemptPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove completed recovery state: %w", err)
	}
	if err := privatefs.SyncDirectory(filepath.Dir(tokenPath)); err != nil {
		return fmt.Errorf("sync admin token directory: %w", err)
	}
	return nil
}

func ensureRotationTokenMatchesOrAbsent(path, sourceHash, replacement string) error {
	if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect admin token destination: %w", err)
	}
	payload, err := privatefs.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read existing admin token destination: %w", err)
	}
	if !auth.Equal(string(payload), replacement) && auth.Hash(string(payload)) != sourceHash {
		return errors.New("admin token destination contains neither the original nor staged replacement credential")
	}
	return nil
}

func ensureFinalTokenMatchesOrAbsent(path, expected string) error {
	if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect admin token destination: %w", err)
	}
	payload, err := privatefs.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read existing admin token destination: %w", err)
	}
	if !auth.Equal(string(payload), expected) {
		return errors.New("admin token destination contains a different credential")
	}
	return nil
}

func ensurePrivateOutputDirectory(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return errors.New("admin token destination is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	directory := filepath.Dir(absolute)
	if _, err := os.Lstat(directory); errors.Is(err, fs.ErrNotExist) {
		if err := privatefs.EnsureDirectory(directory); err != nil {
			return fmt.Errorf("create private admin token directory: %w", err)
		}
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect admin token directory: %w", err)
	}
	if err := privatefs.ValidateDirectory(directory); err != nil {
		return fmt.Errorf("admin token directory must be private: %w", err)
	}
	return nil
}

func writeRecoveryFile(path string, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return privatefs.WriteNewFile(path, append(payload, '\n'), 0o600)
}

func readRecoveryFile(path string, destination any) error {
	payload, err := privatefs.ReadFile(path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("recovery file must contain one JSON object")
	}
	return nil
}

func newRecoveryID(prefix string) (string, error) {
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(random[:]), nil
}

func validRecoveryID(value, prefix string) bool {
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+64 {
		return false
	}
	_, err := hex.DecodeString(value[len(prefix):])
	return err == nil
}

func validRecoveryToken(value string, kind auth.TokenKind) bool {
	actual, err := auth.Kind(value)
	return err == nil && actual == kind
}
