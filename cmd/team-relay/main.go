package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/mohitbadwal/team-relay/internal/auth"
	"github.com/mohitbadwal/team-relay/internal/client"
	"github.com/mohitbadwal/team-relay/internal/config"
	"github.com/mohitbadwal/team-relay/internal/privatefs"
	"github.com/mohitbadwal/team-relay/internal/protocol"
	"gopkg.in/yaml.v3"
)

const version = "0.1.0-dev"

type secretFile interface {
	Write([]byte) (int, error)
	Sync() error
	Close() error
}

var (
	openNewSecretFile  = platformOpenNewSecretFile
	renameSetupFile    = platformRenameSetupFile
	syncSetupDirectory = platformSyncSetupDirectory
	enrollRelayDevice  = func(ctx context.Context, serverURL, invite string, request client.EnrollmentRequest) (*client.EnrollmentResponse, error) {
		relay, err := client.New(serverURL, invite, nil)
		if err != nil {
			return nil, err
		}
		return relay.Enroll(ctx, request)
	}
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) == 0 {
		return usage()
	}
	switch arguments[0] {
	case "setup", "join":
		return setup(arguments[1:])
	case "version", "--version":
		fmt.Println(version)
		return nil
	default:
		return usage()
	}
}

func setup(arguments []string) error {
	defaultConfig, err := config.DefaultPath()
	if err != nil {
		return err
	}
	hostname, _ := os.Hostname()
	displayName := ""
	if current, currentErr := user.Current(); currentErr == nil {
		displayName = firstNonEmpty(current.Name, current.Username)
	}

	flags := flag.NewFlagSet("setup", flag.ContinueOnError)
	serverURL := flags.String("server", "", "relay server URL")
	inviteFile := flags.String("invite-file", "", "file containing one-time invitation token")
	inviteStdin := flags.Bool("invite-stdin", false, "read one-time invitation token from stdin")
	name := flags.String("name", displayName, "member display name")
	deviceName := flags.String("device-name", hostname, "this device name")
	runtimeID := flags.String("runtime", "", "recipient runtime: claude-code, codex, or external")
	externalID := flags.String("external-id", "local", "stable external runner ID; used only with --runtime external")
	externalName := flags.String("external-name", "", "display name for an external runner; used only with --runtime external")
	executable := flags.String("executable", "auto", "runtime executable path; required for external")
	model := flags.String("model", "", "recipient-controlled model override; blank uses the adapter's isolated default")
	workDir := flags.String("work-dir", "", "default working directory")
	permission := flags.String("permission", string(protocol.PermissionReadOnly), "read_only, guarded_write, or custom")
	allowShell := flags.Bool("allow-shell", false, "explicitly allow shell use for a custom permission policy")
	inheritMCPs := flags.Bool("inherit-mcps", true, "let the recipient runtime load local MCP servers when the adapter can isolate them")
	configPath := flags.String("config", defaultConfig, "destination config path")
	outbound := flags.Bool("outbound-attachments", false, "allow requester MCP to upload files from configured aliases")
	var workspaces stringList
	flags.Var(&workspaces, "workspace", "workspace alias and path as alias=/path; repeatable")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("setup does not accept positional arguments")
	}
	inheritMCPsExplicit := false
	flags.Visit(func(selected *flag.Flag) {
		if selected.Name == "inherit-mcps" {
			inheritMCPsExplicit = true
		}
	})
	if strings.TrimSpace(*serverURL) == "" || strings.TrimSpace(*runtimeID) == "" || strings.TrimSpace(*name) == "" || strings.TrimSpace(*deviceName) == "" {
		return errors.New("setup requires --server, --runtime, --name, and --device-name")
	}
	if err := validateRelayURL(*serverURL); err != nil {
		return err
	}
	if *runtimeID != "claude-code" && *runtimeID != "codex" && *runtimeID != "external" {
		return errors.New("runtime must be claude-code, codex, or external")
	}
	effectiveInheritMCPs, err := setupMCPInheritance(*runtimeID, *inheritMCPs, inheritMCPsExplicit)
	if err != nil {
		return err
	}
	if *runtimeID == "external" && (*executable == "" || *executable == "auto") {
		return errors.New("external runtime requires an explicit local --executable")
	}
	enrolledRuntime, err := configuredRuntimeID(*runtimeID, *externalID)
	if err != nil {
		return err
	}
	mode := protocol.PermissionMode(*permission)
	if !mode.Valid() {
		return errors.New("permission must be read_only, guarded_write, or custom")
	}
	if *runtimeID == "codex" && (mode == protocol.PermissionReadOnly || mode == protocol.PermissionCustom && !*allowShell) {
		return errors.New("Codex cannot run with a shell-disabled policy; use claude-code or external with read_only, or use Codex with guarded_write (or custom plus --allow-shell)")
	}
	if strings.TrimSpace(*workDir) == "" {
		return errors.New("setup requires --work-dir")
	}
	inviteSources := 0
	if strings.TrimSpace(*inviteFile) != "" {
		inviteSources++
	}
	if *inviteStdin {
		inviteSources++
	}
	if strings.TrimSpace(os.Getenv("TEAM_RELAY_INVITE_TOKEN")) != "" {
		inviteSources++
	}
	if inviteSources != 1 {
		return errors.New("provide exactly one of --invite-file, --invite-stdin, or TEAM_RELAY_INVITE_TOKEN")
	}

	absConfig, err := filepath.Abs(*configPath)
	if err != nil {
		return err
	}
	tokenPath := filepath.Join(filepath.Dir(absConfig), "device-token")
	workspaceMap, err := parseWorkspaces(workspaces)
	if err != nil {
		return err
	}
	absWorkDir, err := filepath.Abs(*workDir)
	if err != nil {
		return err
	}
	trueValue := true
	var allowShellValue *bool
	if *allowShell {
		allowShellValue = &trueValue
	}
	selectedModel := strings.TrimSpace(*model)
	var runtimeOptions map[string]any
	if *runtimeID == "external" {
		runtimeOptions = map[string]any{"id": strings.TrimSpace(*externalID)}
		if name := strings.TrimSpace(*externalName); name != "" {
			runtimeOptions["name"] = name
		}
	}
	configuration := config.Config{
		Version:  1,
		Relay:    config.RelayConfig{URL: strings.TrimRight(*serverURL, "/"), TokenFile: tokenPath},
		Receiver: config.ReceiverConfig{Profile: "default", MaxConcurrent: 1, RuntimeSecs: 900},
		Profiles: map[string]config.ReceiverProfile{
			"default": {
				Runtime: *runtimeID, Executable: *executable, Model: selectedModel, WorkDir: absWorkDir,
				Options: runtimeOptions,
				Policy: config.PolicyConfig{
					Mode: string(mode), Network: "inherit", AllowShell: allowShellValue, DenyNestedRelay: &trueValue,
				},
				Context: config.ContextConfig{
					InheritUserConfig: &trueValue, InheritProjectInstructions: &trueValue,
					InheritSkills: &trueValue, InheritMCPs: &effectiveInheritMCPs,
				},
			},
		},
		Workspaces: workspaceMap, OutboundAttachments: *outbound,
	}
	payload, err := yaml.Marshal(configuration)
	if err != nil {
		return err
	}
	invite, err := readInvite(*inviteFile, *inviteStdin)
	if err != nil {
		return err
	}
	enrollmentRequest := client.EnrollmentRequest{
		DisplayName: strings.TrimSpace(*name), DeviceName: strings.TrimSpace(*deviceName),
		Runtime: enrolledRuntime, PermissionProfile: string(mode),
	}
	attemptPath := absConfig + ".enrollment-attempt"
	if err := privatefs.EnsureDirectory(filepath.Dir(absConfig)); err != nil {
		return fmt.Errorf("protect setup directory: %w", err)
	}
	identity := enrollmentAttemptIdentity{
		ServerURL: strings.TrimRight(*serverURL, "/"), InviteTokenHash: auth.Hash(invite),
		DisplayName: enrollmentRequest.DisplayName, DeviceName: enrollmentRequest.DeviceName,
		Runtime: enrollmentRequest.Runtime, PermissionProfile: enrollmentRequest.PermissionProfile,
		ConfigPath: absConfig, TokenPath: tokenPath, ConfigHash: auth.Hash(string(payload)),
	}
	var publication *setupPublication
	if exists(attemptPath) {
		attempt, loadErr := loadEnrollmentAttempt(attemptPath)
		if loadErr != nil {
			return loadErr
		}
		if err := attempt.matches(identity); err != nil {
			return err
		}
		enrollmentRequest.DeviceTokenHash = auth.Hash(attempt.DeviceToken)
		enrollmentRequest.IdempotencyKey = attempt.IdempotencyKey
		publication, err = resumeSetupPublication(absConfig, tokenPath, attemptPath, payload, attempt.DeviceToken)
	} else {
		deviceToken, tokenErr := auth.NewToken(auth.TokenDevice)
		if tokenErr != nil {
			return fmt.Errorf("generate device token: %w", tokenErr)
		}
		idempotencyKey, keyErr := newEnrollmentIdempotencyKey()
		if keyErr != nil {
			return fmt.Errorf("generate enrollment idempotency key: %w", keyErr)
		}
		enrollmentRequest.DeviceTokenHash = auth.Hash(deviceToken)
		enrollmentRequest.IdempotencyKey = idempotencyKey
		attempt := enrollmentAttempt{
			Version: 1, Identity: identity,
			DeviceToken: deviceToken, IdempotencyKey: idempotencyKey,
		}
		publication, err = prepareSetupPublication(absConfig, tokenPath, attemptPath, payload, attempt)
	}
	if err != nil {
		return err
	}
	// The raw device token and retry identity are durable before this first
	// network call. Only their hashes cross the server/store boundary.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	enrollment, err := enrollRelayDevice(ctx, *serverURL, invite, enrollmentRequest)
	if err != nil {
		publication.preserveForRetry()
		return fmt.Errorf("enrollment outcome is unknown: %w; the complete device token remains at %s and retry identity at %s; rerun the identical setup command with the original invitation to safely retry without creating another device",
			err, tokenPath, attemptPath)
	}
	if err := publication.publishConfig(); err != nil {
		return fmt.Errorf("device enrolled as agent %q, but local setup publication failed: %w; %s",
			enrollment.Device.AgentID, err, publication.recoveryInstructions())
	}
	fmt.Printf("Joined as %s on device %s\n", enrollment.Member.DisplayName, enrollment.Device.Name)
	fmt.Printf("Agent ID: %s\n", enrollment.Device.AgentID)
	fmt.Printf("Runtime: %s; permissions: %s\n", enrolledRuntime, mode)
	if selectedModel != "" {
		fmt.Printf("Model: %s\n", selectedModel)
	}
	if *runtimeID == "codex" {
		fmt.Println("Local MCPs: disabled for isolated Codex recipient runs")
	}
	fmt.Printf("Config: %s\n", absConfig)
	fmt.Println("Next: run team-relay-agent doctor, then team-relay-agent run")
	return nil
}

// setupMCPInheritance selects a safe setup default without making every
// provider inherit Codex's current limitation. Claude Code and external
// adapters keep the user's requested value. Codex defaults to an exact empty
// MCP inventory; explicitly trying to enable its mutable local MCP sources is
// rejected before an invitation is read or enrollment is attempted.
func setupMCPInheritance(runtimeID string, requested, explicitlySet bool) (bool, error) {
	if strings.TrimSpace(runtimeID) != "codex" {
		return requested, nil
	}
	if explicitlySet && requested {
		return false, errors.New("Codex recipient runs cannot currently inherit local MCP servers safely; use --inherit-mcps=false, or choose claude-code if this receiver needs local MCPs")
	}
	return false, nil
}

func configuredRuntimeID(runtimeID, externalID string) (string, error) {
	runtimeID = strings.TrimSpace(runtimeID)
	if runtimeID != "external" {
		return runtimeID, nil
	}
	externalID = strings.TrimSpace(externalID)
	if externalID == "" || len(externalID) > 64 {
		return "", errors.New("external-id must contain 1 through 64 characters")
	}
	for index, character := range externalID {
		valid := character >= 'a' && character <= 'z' || character >= '0' && character <= '9' ||
			(index > 0 && (character == '.' || character == '_' || character == '-'))
		if !valid {
			return "", errors.New("external-id must start with a lowercase letter or digit and contain only lowercase letters, digits, dots, underscores, or hyphens")
		}
	}
	return "external:" + externalID, nil
}

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func parseWorkspaces(values []string) (map[string]string, error) {
	result := make(map[string]string, len(values))
	for _, value := range values {
		alias, root, ok := strings.Cut(value, "=")
		alias, root = strings.TrimSpace(alias), strings.TrimSpace(root)
		if !ok || alias == "" || root == "" || strings.ContainsAny(alias, "/\\") {
			return nil, fmt.Errorf("invalid workspace %q; use alias=/path", value)
		}
		if _, exists := result[alias]; exists {
			return nil, fmt.Errorf("workspace alias %q is repeated", alias)
		}
		absolute, err := filepath.Abs(root)
		if err != nil {
			return nil, err
		}
		result[alias] = absolute
	}
	return result, nil
}

func readInvite(path string, stdin bool) (string, error) {
	if value := strings.TrimSpace(os.Getenv("TEAM_RELAY_INVITE_TOKEN")); value != "" {
		return value, nil
	}
	var payload []byte
	var err error
	if stdin {
		payload, err = io.ReadAll(io.LimitReader(os.Stdin, 1024))
	} else {
		payload, err = os.ReadFile(path)
	}
	if err != nil {
		return "", fmt.Errorf("read invitation token: %w", err)
	}
	value := strings.TrimSpace(string(payload))
	if !strings.HasPrefix(value, "tr_inv_") {
		return "", errors.New("invitation credential is invalid")
	}
	return value, nil
}

func validateRelayURL(raw string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" || parsed.User != nil {
		return errors.New("server must be an absolute HTTP or HTTPS URL without embedded credentials")
	}
	if parsed.Scheme == "https" {
		return nil
	}
	host := parsed.Hostname()
	if parsed.Scheme == "http" && (host == "127.0.0.1" || host == "localhost" || host == "::1") {
		return nil
	}
	return errors.New("server must use HTTPS unless it is loopback-only")
}

func writeSecret(path string, payload []byte) error {
	file, err := openNewSecretFile(path)
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return writeOpenedSecret(path, file, payload)
}

func writeOpenedSecret(path string, file secretFile, payload []byte) error {
	for len(payload) > 0 {
		written, err := file.Write(payload)
		if err != nil {
			_ = file.Close()
			_ = os.Remove(path)
			return fmt.Errorf("write %s: %w", path, err)
		}
		if written == 0 {
			_ = file.Close()
			_ = os.Remove(path)
			return fmt.Errorf("write %s: %w", path, io.ErrShortWrite)
		}
		payload = payload[written:]
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return fmt.Errorf("sync %s: %w", path, err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("close %s: %w", path, err)
	}
	return nil
}

type setupPublication struct {
	configPath      string
	tokenPath       string
	attemptPath     string
	configStagePath string
	configPublished bool
	tokenPublished  bool
}

type enrollmentAttemptIdentity struct {
	ServerURL         string `json:"server_url"`
	InviteTokenHash   string `json:"invite_token_hash"`
	DisplayName       string `json:"display_name"`
	DeviceName        string `json:"device_name"`
	Runtime           string `json:"runtime"`
	PermissionProfile string `json:"permission_profile"`
	ConfigPath        string `json:"config_path"`
	TokenPath         string `json:"token_path"`
	ConfigHash        string `json:"config_hash"`
}

type enrollmentAttempt struct {
	Version        int                       `json:"version"`
	Identity       enrollmentAttemptIdentity `json:"identity"`
	DeviceToken    string                    `json:"device_token"`
	IdempotencyKey string                    `json:"idempotency_key"`
}

func prepareSetupPublication(configPath, tokenPath, attemptPath string, configPayload []byte, attempt enrollmentAttempt) (*setupPublication, error) {
	directory := filepath.Dir(configPath)
	if err := privatefs.EnsureDirectory(directory); err != nil {
		return nil, fmt.Errorf("create config directory: %w", err)
	}
	publication := &setupPublication{configPath: configPath, tokenPath: tokenPath, attemptPath: attemptPath}
	if err := writeSecret(configPath, nil); err != nil {
		if exists(configPath) {
			return nil, errors.New("local Team Relay configuration already exists; move or remove it explicitly before enrolling again")
		}
		return nil, fmt.Errorf("reserve config destination: %w", err)
	}
	if err := writeSecret(tokenPath, nil); err != nil {
		publication.cleanup()
		if exists(tokenPath) {
			return nil, errors.New("local Team Relay configuration already exists; move or remove it explicitly before enrolling again")
		}
		return nil, fmt.Errorf("reserve token destination: %w", err)
	}
	var err error
	publication.configStagePath, err = stageSecret(directory, filepath.Base(configPath), configPayload)
	if err != nil {
		publication.cleanup()
		return nil, fmt.Errorf("stage config: %w", err)
	}
	tokenStagePath, err := stageSecret(directory, filepath.Base(tokenPath), []byte(attempt.DeviceToken+"\n"))
	if err != nil {
		publication.cleanup()
		return nil, fmt.Errorf("stage device token: %w", err)
	}
	attemptPayload, err := json.Marshal(attempt)
	if err != nil {
		_ = os.Remove(tokenStagePath)
		publication.cleanup()
		return nil, fmt.Errorf("encode enrollment recovery state: %w", err)
	}
	if err := publishNewSecret(attemptPath, append(attemptPayload, '\n')); err != nil {
		_ = os.Remove(tokenStagePath)
		publication.cleanup()
		return nil, fmt.Errorf("stage enrollment recovery state: %w", err)
	}
	if err := renameSetupFile(tokenStagePath, tokenPath); err != nil {
		_ = os.Remove(attemptPath)
		_ = os.Remove(tokenStagePath)
		publication.cleanup()
		return nil, fmt.Errorf("publish staged device token: %w", err)
	}
	publication.tokenPublished = true
	if err := syncSetupDirectory(directory); err != nil {
		_ = os.Remove(attemptPath)
		publication.tokenPublished = false
		publication.cleanup()
		return nil, fmt.Errorf("sync staged enrollment state: %w", err)
	}
	return publication, nil
}

func resumeSetupPublication(configPath, tokenPath, attemptPath string, configPayload []byte, deviceToken string) (*setupPublication, error) {
	publication := &setupPublication{configPath: configPath, tokenPath: tokenPath, attemptPath: attemptPath}
	wantToken := deviceToken + "\n"
	tokenPayload, err := readPrivateSetupFile(tokenPath)
	switch {
	case err == nil && string(tokenPayload) == wantToken:
		publication.tokenPublished = true
	case err == nil && len(tokenPayload) == 0:
		tokenStagePath, stageErr := stageSecret(filepath.Dir(tokenPath), filepath.Base(tokenPath), []byte(wantToken))
		if stageErr != nil {
			return nil, fmt.Errorf("restore staged device token: %w", stageErr)
		}
		if renameErr := renameSetupFile(tokenStagePath, tokenPath); renameErr != nil {
			_ = os.Remove(tokenStagePath)
			return nil, fmt.Errorf("restore staged device token: %w", renameErr)
		}
		publication.tokenPublished = true
	case errors.Is(err, os.ErrNotExist):
		if err := publishNewSecret(tokenPath, []byte(wantToken)); err != nil {
			return nil, fmt.Errorf("restore staged device token: %w", err)
		}
		publication.tokenPublished = true
	case err != nil:
		return nil, fmt.Errorf("read staged device token: %w", err)
	default:
		return nil, errors.New("saved enrollment attempt does not match the device token file; move the local setup files aside before starting a different enrollment")
	}

	configOnDisk, err := readPrivateSetupFile(configPath)
	switch {
	case err == nil && string(configOnDisk) == string(configPayload):
		publication.configPublished = true
	case err == nil && len(configOnDisk) == 0:
		publication.configStagePath, err = stageSecret(filepath.Dir(configPath), filepath.Base(configPath), configPayload)
	case errors.Is(err, os.ErrNotExist):
		if err = writeSecret(configPath, nil); err == nil {
			publication.configStagePath, err = stageSecret(filepath.Dir(configPath), filepath.Base(configPath), configPayload)
		}
	case err != nil:
		return nil, fmt.Errorf("read config destination: %w", err)
	default:
		return nil, errors.New("saved enrollment attempt does not match the existing config; move the local setup files aside before starting a different enrollment")
	}
	if err != nil {
		publication.preserveForRetry()
		return nil, fmt.Errorf("restore staged config: %w", err)
	}
	if err := syncSetupDirectory(filepath.Dir(configPath)); err != nil {
		publication.preserveForRetry()
		return nil, fmt.Errorf("sync restored enrollment state: %w", err)
	}
	return publication, nil
}

func readPrivateSetupFile(path string) ([]byte, error) {
	payload, err := privatefs.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%s is not a private regular file: %w", path, err)
	}
	return payload, nil
}

func stageSecret(directory, base string, payload []byte) (string, error) {
	path, file, err := createPrivateSetupTemp(directory, "."+base+".setup-")
	if err != nil {
		return "", err
	}
	if err := writeOpenedSecret(path, file, payload); err != nil {
		return "", err
	}
	return path, nil
}

func createPrivateSetupTemp(directory, prefix string) (string, secretFile, error) {
	for range 100 {
		random := make([]byte, 16)
		if _, err := rand.Read(random); err != nil {
			return "", nil, fmt.Errorf("generate private staging name: %w", err)
		}
		path := filepath.Join(directory, prefix+hex.EncodeToString(random))
		file, err := openNewSecretFile(path)
		if err == nil {
			return path, file, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return "", nil, err
		}
	}
	return "", nil, errors.New("could not allocate a private setup staging file")
}

func publishNewSecret(path string, payload []byte) error {
	if err := writeSecret(path, nil); err != nil {
		return err
	}
	stagePath, err := stageSecret(filepath.Dir(path), filepath.Base(path), payload)
	if err != nil {
		_ = os.Remove(path)
		return err
	}
	if err := renameSetupFile(stagePath, path); err != nil {
		_ = os.Remove(stagePath)
		_ = os.Remove(path)
		return err
	}
	if err := syncSetupDirectory(filepath.Dir(path)); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

func (p *setupPublication) publishConfig() error {
	if !p.configPublished {
		if err := renameSetupFile(p.configStagePath, p.configPath); err != nil {
			p.preserveForRetry()
			return fmt.Errorf("publish config: %w", err)
		}
		p.configPublished = true
		p.configStagePath = ""
	}
	if err := syncSetupDirectory(filepath.Dir(p.configPath)); err != nil {
		return fmt.Errorf("sync setup directory: %w", err)
	}
	if err := os.Remove(p.attemptPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove completed enrollment recovery state: %w", err)
	}
	if err := syncSetupDirectory(filepath.Dir(p.configPath)); err != nil {
		return fmt.Errorf("sync enrollment recovery cleanup: %w", err)
	}
	return nil
}

func (p *setupPublication) cleanup() {
	if p.configStagePath != "" {
		_ = os.Remove(p.configStagePath)
	}
	if !p.configPublished {
		_ = os.Remove(p.configPath)
	}
	if !p.tokenPublished {
		_ = os.Remove(p.tokenPath)
	}
}

func (p *setupPublication) preserveForRetry() {
	if p.configStagePath != "" {
		_ = os.Remove(p.configStagePath)
		p.configStagePath = ""
	}
	if !p.configPublished {
		_ = os.Remove(p.configPath)
	}
}

func (p *setupPublication) recoveryInstructions() string {
	actions := make([]string, 0, 2)
	actions = append(actions, fmt.Sprintf("the device token is complete at %s", p.tokenPath))
	if !p.configPublished {
		actions = append(actions, "the config remains unpublished and will be rebuilt on retry")
	} else {
		actions = append(actions, fmt.Sprintf("the config is already complete at %s", p.configPath))
	}
	if exists(p.attemptPath) {
		return strings.Join(actions, ", then ") + fmt.Sprintf("; retry state remains at %s; rerun the identical setup command with the original invitation to confirm the same enrollment and clean recovery state", p.attemptPath)
	}
	return strings.Join(actions, ", then ") + "; run team-relay-agent doctor before starting the receiver"
}

func newEnrollmentIdempotencyKey() (string, error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return "tr_enroll_" + hex.EncodeToString(random), nil
}

func loadEnrollmentAttempt(path string) (enrollmentAttempt, error) {
	var attempt enrollmentAttempt
	payload, err := privatefs.ReadFile(path)
	if err != nil {
		return attempt, fmt.Errorf("read enrollment recovery state: %w", err)
	}
	if len(payload) > 16<<10 {
		return attempt, errors.New("enrollment recovery state exceeds the 16 KiB limit")
	}
	decoder := json.NewDecoder(io.LimitReader(bytes.NewReader(payload), 16<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&attempt); err != nil {
		return attempt, fmt.Errorf("decode enrollment recovery state: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return attempt, errors.New("enrollment recovery state contains trailing data")
	}
	if attempt.Version != 1 || !validEnrollmentIdempotencyKey(attempt.IdempotencyKey) {
		return attempt, errors.New("enrollment recovery state is invalid")
	}
	if kind, err := auth.Kind(attempt.DeviceToken); err != nil || kind != auth.TokenDevice {
		return attempt, errors.New("enrollment recovery state contains an invalid device token")
	}
	return attempt, nil
}

func (attempt enrollmentAttempt) matches(identity enrollmentAttemptIdentity) error {
	if attempt.Identity != identity {
		return errors.New("saved enrollment attempt does not match this setup request; rerun the identical command with the original invitation, or revoke the possibly-created device before moving the recovery files aside")
	}
	return nil
}

func validEnrollmentIdempotencyKey(value string) bool {
	const prefix = "tr_enroll_"
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+64 {
		return false
	}
	_, err := hex.DecodeString(value[len(prefix):])
	return err == nil
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return "Team Relay user"
}

func usage() error {
	return errors.New("usage: team-relay setup|join [flags] or team-relay version")
}
