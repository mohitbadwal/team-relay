// Package client provides the authenticated HTTP client used by both the
// requester MCP and the recipient daemon.
package client

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/mohitbadwal/team-relay/internal/protocol"
	"github.com/mohitbadwal/team-relay/internal/transportpolicy"
)

const (
	maxResponseBytes         = 6 << 20
	defaultRequestTimeout    = 30 * time.Second
	defaultSSEConnectTimeout = 30 * time.Second
)

type Error struct {
	StatusCode int
	Code       string
	Message    string
}

func (e *Error) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("relay returned HTTP %d: %s", e.StatusCode, e.Message)
	}
	return fmt.Sprintf("relay returned HTTP %d (%s): %s", e.StatusCode, e.Code, e.Message)
}

type AgentQuery struct {
	Need             string
	Capabilities     []string
	WorkspaceAliases []string
	OnlineOnly       bool
	AcceptingOnly    bool
	Limit            int
}

type Event struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

type EnrollmentRequest struct {
	DisplayName       string `json:"display_name,omitempty"`
	DeviceName        string `json:"device_name"`
	Runtime           string `json:"runtime"`
	PermissionProfile string `json:"permission_profile"`
	DeviceTokenHash   string `json:"device_token_hash"`
	IdempotencyKey    string `json:"idempotency_key"`
}

type EnrollmentResponse struct {
	Member struct {
		ID          string `json:"id"`
		DisplayName string `json:"display_name"`
	} `json:"member"`
	Device struct {
		ID      string `json:"id"`
		AgentID string `json:"agent_id"`
		Name    string `json:"name"`
	} `json:"device"`
}

type Client struct {
	baseURL          *url.URL
	token            string
	http             *http.Client
	streamHTTP       *http.Client
	streamConnectTTL time.Duration
}

func New(rawURL, token string, httpClient *http.Client) (*Client, error) {
	rawURL = strings.TrimSpace(rawURL)
	token = strings.TrimSpace(token)
	if rawURL == "" {
		return nil, errors.New("relay URL is required")
	}
	if token == "" {
		return nil, errors.New("device token is required")
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" || u.Hostname() == "" {
		return nil, errors.New("relay URL must be an absolute HTTP or HTTPS URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, errors.New("relay URL must use HTTP or HTTPS")
	}
	if u.Scheme == "http" && !transportpolicy.PlainHTTPAllowed(u.Hostname()) {
		return nil, errors.New(transportpolicy.HTTPRequirement)
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(rawURL, "#") {
		return nil, errors.New("relay URL must not contain credentials, a query, or a fragment")
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultRequestTimeout}
	} else {
		copy := *httpClient
		httpClient = &copy
	}
	// Bearer credentials must never be replayed to a redirect target, including
	// a same-host HTTPS-to-HTTP downgrade.
	httpClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	streamHTTP := *httpClient
	// http.Client.Timeout includes response-body reads, so inheriting the
	// ordinary request timeout would terminate every healthy long-lived SSE
	// stream. StreamEvents applies a separate timeout only until response
	// headers arrive; afterwards the caller's context owns stream lifetime.
	streamHTTP.Timeout = 0
	return &Client{
		baseURL:          u,
		token:            token,
		http:             httpClient,
		streamHTTP:       &streamHTTP,
		streamConnectTTL: defaultSSEConnectTimeout,
	}, nil
}

func (c *Client) ListAgents(ctx context.Context, query AgentQuery) (*protocol.AgentDirectoryResponse, error) {
	values := url.Values{}
	if query.Need != "" {
		values.Set("need", query.Need)
	}
	for _, capability := range query.Capabilities {
		values.Add("capability", capability)
	}
	for _, alias := range query.WorkspaceAliases {
		values.Add("workspace_alias", alias)
	}
	if query.OnlineOnly {
		values.Set("online_only", "true")
	}
	if query.AcceptingOnly {
		values.Set("accepting_only", "true")
	}
	if query.Limit > 0 {
		values.Set("limit", strconv.Itoa(query.Limit))
	}
	var out protocol.AgentDirectoryResponse
	if err := c.doJSON(ctx, http.MethodGet, "/v1/agents", values, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) Heartbeat(ctx context.Context, heartbeat protocol.AgentHeartbeat) (*protocol.AgentCard, error) {
	var out protocol.AgentCard
	if err := c.doJSON(ctx, http.MethodPost, "/v1/agents/heartbeat", nil, heartbeat, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) Enroll(ctx context.Context, request EnrollmentRequest) (*EnrollmentResponse, error) {
	var out EnrollmentResponse
	if err := c.doJSON(ctx, http.MethodPost, "/v1/enroll", nil, request, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) Inbox(ctx context.Context) (*protocol.InboxResponse, error) {
	var out protocol.InboxResponse
	if err := c.doJSON(ctx, http.MethodGet, "/v1/inbox", nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) CreateRequest(ctx context.Context, request protocol.CreateRequest) (*protocol.MutationResponse, error) {
	var out protocol.MutationResponse
	if err := c.doJSON(ctx, http.MethodPost, "/v1/peer-requests", nil, request, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) GetRequest(ctx context.Context, requestID string) (*protocol.Request, error) {
	var out protocol.Request
	if err := c.doJSON(ctx, http.MethodGet, requestPath(requestID), nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) Decide(ctx context.Context, requestID string, decision protocol.DecisionPayload) (*protocol.MutationResponse, error) {
	var out protocol.MutationResponse
	if err := c.doJSON(ctx, http.MethodPost, requestPath(requestID)+"/decision", nil, decision, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) FetchExecution(ctx context.Context, requestID string) (*protocol.ExecutionPayload, error) {
	var out protocol.ExecutionPayload
	if err := c.doJSON(ctx, http.MethodGet, requestPath(requestID)+"/execution", nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) InspectProposal(ctx context.Context, requestID string) (*protocol.ProposalPayload, error) {
	var out protocol.ProposalPayload
	if err := c.doJSON(ctx, http.MethodGet, requestPath(requestID)+"/proposal", nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) MarkRunning(ctx context.Context, requestID, executionClaimID string) (*protocol.MutationResponse, error) {
	var out protocol.MutationResponse
	if err := c.doJSON(ctx, http.MethodPost, requestPath(requestID)+"/running", nil, protocol.ExecutionClaimPayload{ExecutionClaimID: executionClaimID}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) SubmitResult(ctx context.Context, requestID string, result protocol.ResultPayload) (*protocol.MutationResponse, error) {
	var out protocol.MutationResponse
	if err := c.doJSON(ctx, http.MethodPost, requestPath(requestID)+"/result", nil, result, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) CancelRequest(ctx context.Context, requestID string) (*protocol.MutationResponse, error) {
	var out protocol.MutationResponse
	if err := c.doJSON(ctx, http.MethodPost, requestPath(requestID)+"/cancel", nil, struct{}{}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) FetchArtifact(ctx context.Context, artifactID string) (*protocol.ArtifactContent, error) {
	var out protocol.ArtifactContent
	if err := c.doJSON(ctx, http.MethodGet, "/v1/artifacts/"+url.PathEscape(strings.TrimSpace(artifactID)), nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// StreamEvents consumes server-sent events until the context is cancelled or
// the connection closes. Event payloads remain raw so the receiver can evolve
// independently of the transport client.
func (c *Client) StreamEvents(ctx context.Context, onEvent func(Event) error) error {
	if onEvent == nil {
		return errors.New("event callback is required")
	}
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	headerTimedOut := make(chan struct{})
	headerTimer := time.AfterFunc(c.streamConnectTTL, func() {
		close(headerTimedOut)
		cancel()
	})
	defer headerTimer.Stop()

	req, err := c.request(streamCtx, http.MethodGet, "/v1/events", nil, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/event-stream")
	resp, err := c.streamHTTP.Do(req)
	if !headerTimer.Stop() {
		// The timeout callback may be running concurrently with Do returning.
		// Wait until it has definitely cancelled this request; otherwise a
		// seemingly successful response could begin streaming on an already
		// cancelled context and disconnect immediately with a misleading error.
		<-headerTimedOut
		if resp != nil {
			_ = resp.Body.Close()
		}
		if ctx.Err() == nil {
			return fmt.Errorf("connect to relay event stream: response headers exceeded %s", c.streamConnectTTL)
		}
		return fmt.Errorf("connect to relay event stream: %w", ctx.Err())
	}
	if err != nil {
		return fmt.Errorf("connect to relay event stream: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return decodeError(resp)
	}

	scanner := bufio.NewScanner(io.LimitReader(resp.Body, 64<<20))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	var eventType string
	var data []byte
	flush := func() error {
		if len(data) == 0 {
			eventType = ""
			return nil
		}
		event := Event{Type: eventType, Payload: append(json.RawMessage(nil), data...)}
		if event.Type == "" {
			event.Type = "message"
		}
		data = nil
		eventType = ""
		return onEvent(event)
	}
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if err := flush(); err != nil {
				return err
			}
			continue
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		if strings.HasPrefix(line, "event:") {
			eventType = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			continue
		}
		if strings.HasPrefix(line, "data:") {
			fragment := []byte(strings.TrimSpace(strings.TrimPrefix(line, "data:")))
			if len(data) > 0 {
				data = append(data, '\n')
			}
			data = append(data, fragment...)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read relay event stream: %w", err)
	}
	return flush()
}

func (c *Client) doJSON(ctx context.Context, method, endpoint string, query url.Values, body, out any) error {
	req, err := c.request(ctx, method, endpoint, query, body)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("call relay: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return decodeError(resp)
	}
	if out == nil || resp.StatusCode == http.StatusNoContent {
		_, err = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
		return err
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes))
	if err := decoder.Decode(out); err != nil {
		return fmt.Errorf("decode relay response: %w", err)
	}
	return nil
}

func (c *Client) request(ctx context.Context, method, endpoint string, query url.Values, body any) (*http.Request, error) {
	u := *c.baseURL
	u.Path = strings.TrimSuffix(c.baseURL.Path, "/") + endpoint
	if query != nil {
		u.RawQuery = query.Encode()
	}
	var reader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("encode relay request: %w", err)
		}
		reader = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("User-Agent", "team-relay/0.1")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

func decodeError(resp *http.Response) error {
	payload, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var decoded protocol.ErrorResponse
	if json.Unmarshal(payload, &decoded) != nil || strings.TrimSpace(decoded.Error) == "" {
		decoded.Error = strings.TrimSpace(string(payload))
	}
	if decoded.Error == "" {
		decoded.Error = http.StatusText(resp.StatusCode)
	}
	return &Error{StatusCode: resp.StatusCode, Code: decoded.Code, Message: decoded.Error}
}

func requestPath(requestID string) string {
	return path.Join("/v1/peer-requests", url.PathEscape(strings.TrimSpace(requestID)))
}
