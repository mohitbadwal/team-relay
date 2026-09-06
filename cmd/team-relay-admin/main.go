package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/mohitbadwal/team-relay/internal/auth"
	"github.com/mohitbadwal/team-relay/internal/store"
	"github.com/mohitbadwal/team-relay/internal/transportpolicy"
)

const maximumResponseBody = 2 << 20

type apiClient struct {
	baseURL string
	token   string
	http    *http.Client
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) == 0 {
		return usageError()
	}
	switch arguments[0] {
	case "generate-bootstrap-token":
		token, err := auth.NewToken(auth.TokenBootstrap)
		if err != nil {
			return err
		}
		fmt.Println(token)
		return nil
	case "bootstrap":
		return bootstrapCommand(arguments[1:])
	case "invite":
		return inviteCommand(arguments[1:])
	case "member":
		return memberCommand(arguments[1:])
	case "device":
		return deviceCommand(arguments[1:])
	case "audit":
		return auditCommand(arguments[1:])
	case "credential":
		return credentialCommand(arguments[1:])
	default:
		return usageError()
	}
}

func credentialCommand(arguments []string) error {
	if len(arguments) == 0 || arguments[0] != "rotate" {
		return errors.New("credential requires rotate")
	}
	flags := flag.NewFlagSet("credential rotate", flag.ContinueOnError)
	serverURL, tokenFile := commonFlags(flags)
	replacementTokenFile := flags.String("replacement-token-file", os.Getenv("TEAM_RELAY_REPLACEMENT_ADMIN_TOKEN_FILE"), "private path for the replacement admin token; defaults to --token-file")
	if err := flags.Parse(arguments[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("credential rotate does not accept positional arguments")
	}
	client, err := adminClient(*serverURL, *tokenFile)
	if err != nil {
		return err
	}
	outputPath := strings.TrimSpace(*replacementTokenFile)
	if outputPath == "" {
		outputPath = strings.TrimSpace(*tokenFile)
	}
	if outputPath == "" {
		return errors.New("credential rotate requires --replacement-token-file when the current token comes from TEAM_RELAY_ADMIN_TOKEN")
	}
	attempt, err := prepareRotationAttempt(outputPath, client.baseURL, client.token)
	if err != nil {
		return err
	}
	payload := map[string]string{
		"new_token_hash":  auth.Hash(attempt.NewAdminToken),
		"idempotency_key": attempt.IdempotencyKey,
	}
	var response store.RotateAdminCredentialResult
	err = client.request(http.MethodPost, "/v1/admin/credential/rotate", payload, &response)
	if isUnauthorizedResponse(err) && !auth.Equal(client.token, attempt.NewAdminToken) {
		recoveryClient, clientErr := newAPIClient(client.baseURL, attempt.NewAdminToken)
		if clientErr != nil {
			return clientErr
		}
		err = recoveryClient.request(http.MethodPost, "/v1/admin/credential/rotate", payload, &response)
	}
	if err != nil {
		return fmt.Errorf("rotate administrator credential (retry the same command to recover an uncertain response): %w", err)
	}
	if err := finalizeAdminToken(outputPath, rotationAttemptPath(outputPath), attempt.NewAdminToken, attempt.SourceTokenHash); err != nil {
		return fmt.Errorf("rotation committed; finalize replacement credential from recovery state: %w", err)
	}
	fmt.Printf("Replacement admin credential saved to %s.\n", outputPath)
	fmt.Println("The credential used for this rotation is now invalid; future commands must use the saved replacement file.")
	return nil
}

func bootstrapCommand(arguments []string) error {
	flags := flag.NewFlagSet("bootstrap", flag.ContinueOnError)
	serverURL := flags.String("server", defaultServerURL(), "relay server URL")
	tokenFile := flags.String("token-file", os.Getenv("TEAM_RELAY_BOOTSTRAP_TOKEN_FILE"), "file containing bootstrap token")
	organization := flags.String("organization", "", "organization name")
	displayName := flags.String("name", "", "administrator display name")
	email := flags.String("email", "", "administrator email")
	adminTokenFile := flags.String("admin-token-file", os.Getenv("TEAM_RELAY_ADMIN_TOKEN_FILE"), "private destination for the generated admin token")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *organization == "" || *displayName == "" || *email == "" || strings.TrimSpace(*adminTokenFile) == "" {
		return errors.New("bootstrap requires --organization, --name, --email, and --admin-token-file")
	}
	token, err := readCredential(*tokenFile, "TEAM_RELAY_BOOTSTRAP_TOKEN")
	if err != nil {
		return err
	}
	client, err := newAPIClient(*serverURL, token)
	if err != nil {
		return err
	}
	attempt, err := prepareBootstrapAttempt(*adminTokenFile, client.baseURL, *organization, *displayName, *email)
	if err != nil {
		return err
	}
	var response struct {
		Organization store.Organization `json:"organization"`
		Admin        store.Member       `json:"admin"`
	}
	if err := client.request(http.MethodPost, "/v1/bootstrap", map[string]any{
		"organization_name":  *organization,
		"admin_display_name": *displayName,
		"admin_email":        *email,
		"admin_token_hash":   auth.Hash(attempt.AdminToken),
		"idempotency_key":    attempt.IdempotencyKey,
	}, &response); err != nil {
		return fmt.Errorf("bootstrap relay (retry the same command to recover an uncertain response): %w", err)
	}
	if err := finalizeAdminToken(*adminTokenFile, bootstrapAttemptPath(*adminTokenFile), attempt.AdminToken, ""); err != nil {
		return fmt.Errorf("bootstrap committed; finalize administrator credential from recovery state: %w", err)
	}
	fmt.Printf("Organization: %s (%s)\n", response.Organization.Name, response.Organization.ID)
	fmt.Printf("Admin: %s (%s)\n", response.Admin.DisplayName, response.Admin.ID)
	fmt.Printf("Admin credential saved to %s.\n", *adminTokenFile)
	return nil
}

func inviteCommand(arguments []string) error {
	if len(arguments) == 0 {
		return errors.New("invite requires create, list, or revoke")
	}
	switch arguments[0] {
	case "create":
		flags := flag.NewFlagSet("invite create", flag.ContinueOnError)
		serverURL, tokenFile := commonFlags(flags)
		name := flags.String("name", "", "new member display name")
		email := flags.String("email", "", "new member email")
		memberID := flags.String("member", "", "existing member ID for another device")
		expires := flags.Duration("expires", 24*time.Hour, "invitation lifetime")
		if err := flags.Parse(arguments[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 || (*memberID == "" && *name == "" && *email == "") {
			return errors.New("invite create requires --name or --email, or --member for an existing member")
		}
		client, err := adminClient(*serverURL, *tokenFile)
		if err != nil {
			return err
		}
		var response struct {
			Invite      store.Invite `json:"invite"`
			InviteToken string       `json:"invite_token"`
		}
		err = client.request(http.MethodPost, "/v1/admin/invites", map[string]any{
			"display_name":       *name,
			"email":              *email,
			"member_id":          *memberID,
			"expires_in_seconds": int64(expires.Seconds()),
		}, &response)
		if err != nil {
			return err
		}
		fmt.Printf("Invite: %s (expires %s)\n", response.Invite.ID, response.Invite.ExpiresAt.Format(time.RFC3339))
		fmt.Printf("Invite token (shown once): %s\n", response.InviteToken)
		return nil
	case "list":
		flags := flag.NewFlagSet("invite list", flag.ContinueOnError)
		serverURL, tokenFile := commonFlags(flags)
		if err := flags.Parse(arguments[1:]); err != nil {
			return err
		}
		client, err := adminClient(*serverURL, *tokenFile)
		if err != nil {
			return err
		}
		var response struct {
			Invites []store.Invite `json:"invites"`
		}
		if err := client.request(http.MethodGet, "/v1/admin/invites", nil, &response); err != nil {
			return err
		}
		for _, invite := range response.Invites {
			fmt.Printf("%s\t%s\t%s\t%s\n", invite.ID, invite.Status, invite.ExpiresAt.Format(time.RFC3339), firstNonEmpty(invite.Email, invite.DisplayName, invite.MemberID))
		}
		return nil
	case "revoke":
		return revokeCommand("invite", "/v1/admin/invites/", arguments[1:])
	default:
		return errors.New("invite requires create, list, or revoke")
	}
}

func memberCommand(arguments []string) error {
	if len(arguments) == 0 {
		return errors.New("member requires list or revoke")
	}
	switch arguments[0] {
	case "list":
		flags := flag.NewFlagSet("member list", flag.ContinueOnError)
		serverURL, tokenFile := commonFlags(flags)
		if err := flags.Parse(arguments[1:]); err != nil {
			return err
		}
		client, err := adminClient(*serverURL, *tokenFile)
		if err != nil {
			return err
		}
		var response struct {
			Members []store.Member `json:"members"`
		}
		if err := client.request(http.MethodGet, "/v1/admin/members", nil, &response); err != nil {
			return err
		}
		for _, member := range response.Members {
			fmt.Printf("%s\t%s\t%s\t%s\t%s\n", member.ID, member.Role, member.Status, member.DisplayName, member.Email)
		}
		return nil
	case "revoke":
		return revokeCommand("member", "/v1/admin/members/", arguments[1:])
	default:
		return errors.New("member requires list or revoke")
	}
}

func deviceCommand(arguments []string) error {
	if len(arguments) == 0 {
		return errors.New("device requires list or revoke")
	}
	switch arguments[0] {
	case "list":
		flags := flag.NewFlagSet("device list", flag.ContinueOnError)
		serverURL, tokenFile := commonFlags(flags)
		memberID := flags.String("member", "", "filter by member ID")
		if err := flags.Parse(arguments[1:]); err != nil {
			return err
		}
		client, err := adminClient(*serverURL, *tokenFile)
		if err != nil {
			return err
		}
		path := "/v1/admin/devices"
		if *memberID != "" {
			path += "?member_id=" + url.QueryEscape(*memberID)
		}
		var response struct {
			Devices []store.Device `json:"devices"`
		}
		if err := client.request(http.MethodGet, path, nil, &response); err != nil {
			return err
		}
		for _, device := range response.Devices {
			fmt.Printf("%s\t%s\t%s\t%s\t%s\t%s\n", device.ID, device.Status, device.AgentID, device.Runtime, device.PermissionProfile, device.Name)
		}
		return nil
	case "revoke":
		return revokeCommand("device", "/v1/admin/devices/", arguments[1:])
	default:
		return errors.New("device requires list or revoke")
	}
}

func auditCommand(arguments []string) error {
	flags := flag.NewFlagSet("audit", flag.ContinueOnError)
	serverURL, tokenFile := commonFlags(flags)
	limit := flags.Int("limit", 100, "maximum events")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	client, err := adminClient(*serverURL, *tokenFile)
	if err != nil {
		return err
	}
	var response struct {
		Events []store.AuditEvent `json:"events"`
	}
	path := "/v1/admin/audit?limit=" + strconv.Itoa(*limit)
	if err := client.request(http.MethodGet, path, nil, &response); err != nil {
		return err
	}
	for _, event := range response.Events {
		fmt.Printf("%s\t%s\t%s\t%s\n", event.OccurredAt.Format(time.RFC3339), event.Action, event.TargetType, event.TargetID)
	}
	return nil
}

func revokeCommand(noun, pathPrefix string, arguments []string) error {
	flags := flag.NewFlagSet(noun+" revoke", flag.ContinueOnError)
	serverURL, tokenFile := commonFlags(flags)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return fmt.Errorf("%s revoke requires exactly one ID", noun)
	}
	client, err := adminClient(*serverURL, *tokenFile)
	if err != nil {
		return err
	}
	if err := client.request(http.MethodDelete, pathPrefix+url.PathEscape(flags.Arg(0)), nil, nil); err != nil {
		return err
	}
	fmt.Printf("Revoked %s %s\n", noun, flags.Arg(0))
	return nil
}

func commonFlags(flags *flag.FlagSet) (*string, *string) {
	serverURL := flags.String("server", defaultServerURL(), "relay server URL")
	tokenFile := flags.String("token-file", os.Getenv("TEAM_RELAY_ADMIN_TOKEN_FILE"), "file containing admin token")
	return serverURL, tokenFile
}

func adminClient(serverURL, tokenFile string) (*apiClient, error) {
	token, err := readCredential(tokenFile, "TEAM_RELAY_ADMIN_TOKEN")
	if err != nil {
		return nil, err
	}
	if kind, kindErr := auth.Kind(token); kindErr != nil || kind != auth.TokenAdmin {
		return nil, errors.New("admin credential is invalid")
	}
	return newAPIClient(serverURL, token)
}

func newAPIClient(rawURL, token string) (*apiClient, error) {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.Hostname() == "" || parsed.User != nil {
		return nil, errors.New("server must be an http or https URL without embedded credentials")
	}
	if parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || strings.Contains(rawURL, "#") {
		return nil, errors.New("server URL must not contain a query or a fragment")
	}
	if parsed.Scheme == "http" && !transportpolicy.PlainHTTPAllowed(parsed.Hostname()) {
		// A Compose tools container may reach the relay by its exact service DNS
		// name on an isolated internal network. The exception is opt-in and bound
		// to one operator-configured hostname; other non-private HTTP stays denied.
		allowedHost := strings.TrimSpace(os.Getenv("TEAM_RELAY_ALLOW_HTTP_HOST"))
		if allowedHost == "" || !strings.EqualFold(parsed.Hostname(), allowedHost) {
			return nil, errors.New(transportpolicy.HTTPRequirement + "; an admin-only exact internal hostname may be configured with TEAM_RELAY_ALLOW_HTTP_HOST")
		}
	}
	transportpolicy.WarnPrivateLANHTTP(rawURL, os.Stderr)
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return &apiClient{
		baseURL: strings.TrimRight(parsed.String(), "/"),
		token:   strings.TrimSpace(token),
		http: &http.Client{
			Timeout:       15 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

type apiError struct {
	Status  int
	Code    string
	Message string
}

func (e *apiError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("relay returned HTTP %d (%s): %s", e.Status, e.Code, e.Message)
	}
	return fmt.Sprintf("relay returned HTTP %d", e.Status)
}

func isUnauthorizedResponse(err error) bool {
	var responseError *apiError
	return errors.As(err, &responseError) && responseError.Status == http.StatusUnauthorized
}

func (c *apiClient) request(method, path string, body, destination any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequest(method, c.baseURL+path, reader)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	limited := io.LimitReader(response.Body, maximumResponseBody)
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var envelope struct {
			Code  string          `json:"code"`
			Error json.RawMessage `json:"error"`
		}
		if json.NewDecoder(limited).Decode(&envelope) == nil {
			code := envelope.Code
			var message string
			if json.Unmarshal(envelope.Error, &message) != nil {
				var nested struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				}
				if json.Unmarshal(envelope.Error, &nested) == nil {
					code, message = nested.Code, nested.Message
				}
			}
			if message != "" {
				return &apiError{Status: response.StatusCode, Code: code, Message: message}
			}
		}
		return &apiError{Status: response.StatusCode}
	}
	if destination == nil || response.StatusCode == http.StatusNoContent {
		_, _ = io.Copy(io.Discard, limited)
		return nil
	}
	if err := json.NewDecoder(limited).Decode(destination); err != nil {
		return fmt.Errorf("decode relay response: %w", err)
	}
	return nil
}

func readCredential(filePath, environmentName string) (string, error) {
	filePath = strings.TrimSpace(filePath)
	direct := strings.TrimSpace(os.Getenv(environmentName))
	if filePath != "" && direct != "" {
		return "", fmt.Errorf("set only --token-file or %s", environmentName)
	}
	if filePath == "" {
		if direct == "" {
			return "", fmt.Errorf("set --token-file or %s", environmentName)
		}
		return direct, nil
	}
	value, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("read credential file: %w", err)
	}
	valueText := strings.TrimSpace(string(value))
	if valueText == "" {
		return "", errors.New("credential file is empty")
	}
	return valueText, nil
}

func defaultServerURL() string {
	if value := strings.TrimSpace(os.Getenv("TEAM_RELAY_URL")); value != "" {
		return value
	}
	return "http://127.0.0.1:8080"
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return "-"
}

func usageError() error {
	return errors.New("usage: team-relay-admin <generate-bootstrap-token|bootstrap|credential|invite|member|device|audit> ...")
}
