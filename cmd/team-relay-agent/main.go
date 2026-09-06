package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/mohitbadwal/team-relay/internal/artifact"
	"github.com/mohitbadwal/team-relay/internal/client"
	appconfig "github.com/mohitbadwal/team-relay/internal/config"
	"github.com/mohitbadwal/team-relay/internal/receiver"
	relayruntime "github.com/mohitbadwal/team-relay/internal/runtime"
)

type options struct {
	configPath      string
	stateDir        string
	controlAddr     string
	displayName     string
	deviceName      string
	accepting       bool
	command         string
	commandArgs     []string
	displayExplicit bool
	deviceExplicit  bool
}

func main() { os.Exit(run(os.Args[1:])) }

func run(arguments []string) int {
	opts, err := parseOptions(arguments)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	switch opts.command {
	case "pending", "inspect", "allow-once", "approve", "approval-grants", "revoke-approval-grant", "deny":
		return runControlCommand(opts)
	case "doctor", "run-once", "run":
		return runReceiverCommand(opts)
	default:
		fmt.Fprintln(os.Stderr, "command must be run, doctor, run-once, pending, inspect, allow-once, approve, approval-grants, revoke-approval-grant, or deny")
		return 2
	}
}

func parseOptions(arguments []string) (options, error) {
	defaultConfig, _ := appconfig.DefaultPath()
	defaultState, _ := receiver.DefaultStateDir()
	defaultControl := strings.TrimSpace(os.Getenv("TEAM_RELAY_CONTROL_ADDRESS"))
	if defaultControl == "" {
		defaultControl = "127.0.0.1:8787"
	}
	hostname, _ := os.Hostname()
	displayName := strings.TrimSpace(os.Getenv("TEAM_RELAY_DISPLAY_NAME"))
	if displayName == "" {
		if current, err := user.Current(); err == nil {
			displayName = current.Name
			if displayName == "" {
				displayName = current.Username
			}
		}
	}
	flags := flag.NewFlagSet("team-relay-agent", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", defaultConfig, "path to Team Relay config")
	stateDir := flags.String("state-dir", defaultState, "private recipient state directory")
	controlAddr := flags.String("control-address", defaultControl, "loopback-only local control address")
	display := flags.String("display-name", displayName, "display name advertised to teammates")
	device := flags.String("device-name", hostname, "device name advertised to teammates")
	accepting := flags.Bool("accepting-requests", true, "advertise that this receiver accepts requests")
	if err := flags.Parse(arguments); err != nil {
		return options{}, err
	}
	displayExplicit, deviceExplicit := os.Getenv("TEAM_RELAY_DISPLAY_NAME") != "", false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "display-name" {
			displayExplicit = true
		}
		if f.Name == "device-name" {
			deviceExplicit = true
		}
	})
	if flags.NArg() == 0 {
		return options{}, fmt.Errorf("a command is required")
	}
	if *stateDir == "" {
		return options{}, fmt.Errorf("state directory is required")
	}
	stateAbs, err := filepath.Abs(*stateDir)
	if err != nil {
		return options{}, err
	}
	return options{
		configPath:      *configPath,
		stateDir:        stateAbs,
		controlAddr:     *controlAddr,
		displayName:     strings.TrimSpace(*display),
		deviceName:      strings.TrimSpace(*device),
		accepting:       *accepting,
		command:         flags.Arg(0),
		commandArgs:     flags.Args()[1:],
		displayExplicit: displayExplicit,
		deviceExplicit:  deviceExplicit,
	}, nil
}

func runReceiverCommand(opts options) int {
	config, err := appconfig.Load(opts.configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if !opts.displayExplicit && config.Receiver.DisplayName != "" {
		opts.displayName = config.Receiver.DisplayName
	}
	if !opts.deviceExplicit && config.Receiver.DeviceName != "" {
		opts.deviceName = config.Receiver.DeviceName
	}
	controller, err := receiver.BuildController(config, filepath.Join(opts.stateDir, "receiver_sessions.json"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	switch opts.command {
	case "doctor":
		capabilities, err := controller.Probe(ctx)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if err := encoder.Encode(capabilities); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if !capabilities.Available {
			return 1
		}
		return 0
	case "run-once":
		var request relayruntime.RunRequest
		if err := json.NewDecoder(os.Stdin).Decode(&request); err != nil {
			fmt.Fprintln(os.Stderr, "decode request:", err)
			return 2
		}
		result, err := controller.Execute(ctx, request, relayruntime.EventSinkFunc(func(_ context.Context, event relayruntime.Event) error {
			data, marshalErr := json.Marshal(event)
			if marshalErr != nil {
				return marshalErr
			}
			_, writeErr := fmt.Fprintln(os.Stderr, string(data))
			return writeErr
		}))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if err := encoder.Encode(result); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	case "run":
		return runDaemon(ctx, opts, config, controller)
	default:
		return 2
	}
}

func runDaemon(parent context.Context, opts options, config appconfig.Config, controller *receiver.Controller) int {
	if opts.displayName == "" || opts.deviceName == "" {
		fmt.Fprintln(os.Stderr, "display name and device name are required")
		return 2
	}
	deviceToken, err := config.DeviceToken()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	relayClient, err := client.New(config.Relay.URL, deviceToken, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	pending, err := receiver.NewPendingStore(filepath.Join(opts.stateDir, "pending_requests.json"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	artifacts, err := artifact.NewManager(filepath.Join(opts.stateDir, "artifacts"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer artifacts.Close()
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	approvalFingerprint, err := approvalAuthorityFingerprint(config, deviceToken)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	service, err := receiver.NewService(receiver.ServiceConfig{
		Client:                       relayClient,
		Controller:                   controller,
		Pending:                      pending,
		Artifacts:                    artifacts,
		ApprovalAuthorityFingerprint: approvalFingerprint,
		DisplayName:                  opts.displayName,
		DeviceName:                   opts.deviceName,
		AcceptingRequests:            opts.accepting,
		Workspaces:                   config.Workspaces,
		HeartbeatInterval:            25 * time.Second,
		Logger:                       logger,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	controlToken, err := receiver.LoadOrCreateControlToken(filepath.Join(opts.stateDir, "control.token"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	control, err := receiver.NewControlServer(opts.controlAddr, controlToken, service)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	errorsChannel := make(chan error, 2)
	go func() { errorsChannel <- service.Run(ctx) }()
	go func() { errorsChannel <- control.Serve(ctx) }()
	first := <-errorsChannel
	cancel()
	second := <-errorsChannel
	if first != nil {
		fmt.Fprintln(os.Stderr, first)
		return 1
	}
	if second != nil {
		fmt.Fprintln(os.Stderr, second)
		return 1
	}
	return 0
}

func runControlCommand(opts options) int {
	if err := receiver.ValidateControlAddress(opts.controlAddr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	token, err := receiver.LoadOrCreateControlToken(filepath.Join(opts.stateDir, "control.token"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	method, endpoint, body, err := controlRequestTarget(opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, method, "http://"+opts.controlAddr+endpoint, bytes.NewReader(body))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	request.Header.Set("Authorization", "Bearer "+token)
	if len(body) > 0 {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := (&http.Client{Timeout: 10 * time.Second}).Do(request)
	if err != nil {
		fmt.Fprintln(os.Stderr, "local receiver control is unavailable:", err)
		return 1
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		fmt.Fprintf(os.Stderr, "local receiver returned HTTP %d: %s\n", response.StatusCode, strings.TrimSpace(string(payload)))
		return 1
	}
	var value any
	if json.Unmarshal(payload, &value) == nil {
		output, _ := json.MarshalIndent(value, "", "  ")
		fmt.Println(string(output))
	} else {
		fmt.Println(strings.TrimSpace(string(payload)))
	}
	return 0
}

func controlRequestTarget(opts options) (string, string, []byte, error) {
	switch opts.command {
	case "pending":
		if len(opts.commandArgs) != 0 {
			return "", "", nil, errors.New("pending does not accept arguments")
		}
		return http.MethodGet, "/v1/pending", nil, nil
	case "inspect", "allow-once", "deny":
		if len(opts.commandArgs) != 1 || strings.TrimSpace(opts.commandArgs[0]) == "" {
			return "", "", nil, fmt.Errorf("%s requires exactly one request_id", opts.command)
		}
		requestID := url.PathEscape(strings.TrimSpace(opts.commandArgs[0]))
		if opts.command == "inspect" {
			return http.MethodGet, "/v1/requests/" + requestID + "/proposal", nil, nil
		}
		return http.MethodPost, "/v1/requests/" + requestID + "/" + opts.command, nil, nil
	case "approve":
		if len(opts.commandArgs) != 2 || strings.TrimSpace(opts.commandArgs[0]) == "" {
			return "", "", nil, errors.New("approve requires REQUEST_ID and LEVEL")
		}
		level := receiver.ApprovalLevel(strings.TrimSpace(opts.commandArgs[1]))
		if !level.Valid() {
			return "", "", nil, errors.New("approval LEVEL must be ask_always, conversation_30m, teammate_always, or all_always")
		}
		body, err := json.Marshal(map[string]receiver.ApprovalLevel{"level": level})
		if err != nil {
			return "", "", nil, err
		}
		return http.MethodPost, "/v1/requests/" + url.PathEscape(strings.TrimSpace(opts.commandArgs[0])) + "/approve", body, nil
	case "approval-grants":
		if len(opts.commandArgs) != 0 {
			return "", "", nil, errors.New("approval-grants does not accept arguments")
		}
		return http.MethodGet, "/v1/approval-grants", nil, nil
	case "revoke-approval-grant":
		if len(opts.commandArgs) != 1 || strings.TrimSpace(opts.commandArgs[0]) == "" {
			return "", "", nil, errors.New("revoke-approval-grant requires exactly one grant_id")
		}
		return http.MethodDelete, "/v1/approval-grants/" + url.PathEscape(strings.TrimSpace(opts.commandArgs[0])), nil, nil
	default:
		return "", "", nil, fmt.Errorf("unsupported control command %q", opts.command)
	}
}

func approvalAuthorityFingerprint(config appconfig.Config, deviceToken string) (string, error) {
	profile, ok := config.Profiles[config.Receiver.Profile]
	if !ok {
		return "", fmt.Errorf("receiver profile %q is unavailable for approval authority", config.Receiver.Profile)
	}
	tokenDigest := sha256.Sum256([]byte(strings.TrimSpace(deviceToken)))
	payload, err := json.Marshal(struct {
		Version             int                       `json:"version"`
		RelayURL            string                    `json:"relay_url"`
		DeviceTokenSHA256   string                    `json:"device_token_sha256"`
		Receiver            appconfig.ReceiverConfig  `json:"receiver"`
		ProfileName         string                    `json:"profile_name"`
		Profile             appconfig.ReceiverProfile `json:"profile"`
		Workspaces          map[string]string         `json:"workspaces"`
		OutboundAttachments bool                      `json:"outbound_attachments"`
	}{
		Version: 1, RelayURL: strings.TrimRight(strings.TrimSpace(config.Relay.URL), "/"),
		DeviceTokenSHA256: hex.EncodeToString(tokenDigest[:]), Receiver: config.Receiver,
		ProfileName: config.Receiver.Profile, Profile: profile, Workspaces: config.Workspaces,
		OutboundAttachments: config.OutboundAttachments,
	})
	if err != nil {
		return "", fmt.Errorf("encode approval authority: %w", err)
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]), nil
}
