package collaboration

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mohitbadwal/team-relay/internal/auth"
	"github.com/mohitbadwal/team-relay/internal/protocol"
)

const maximumJSONBody = 4 << 20

type Authenticator func(*http.Request) (auth.Principal, error)

type Handler struct {
	store        *RedisStore
	authenticate Authenticator
	hub          *Hub
	logger       *slog.Logger
}

func NewHandler(store *RedisStore, authenticate Authenticator, hub *Hub, logger *slog.Logger) *Handler {
	if hub == nil {
		hub = NewHub()
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Handler{store: store, authenticate: authenticate, hub: hub, logger: logger}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/agents/heartbeat", h.heartbeat)
	mux.HandleFunc("GET /v1/agents", h.listAgents)
	mux.HandleFunc("GET /v1/events", h.events)
	mux.HandleFunc("GET /v1/inbox", h.inbox)
	mux.HandleFunc("POST /v1/peer-requests", h.createRequest)
	mux.HandleFunc("GET /v1/peer-requests/{request_id}", h.getRequest)
	mux.HandleFunc("GET /v1/peer-requests/{request_id}/proposal", h.inspectProposal)
	mux.HandleFunc("POST /v1/peer-requests/{request_id}/decision", h.decide)
	mux.HandleFunc("GET /v1/peer-requests/{request_id}/execution", h.fetchExecution)
	mux.HandleFunc("POST /v1/peer-requests/{request_id}/running", h.markRunning)
	mux.HandleFunc("POST /v1/peer-requests/{request_id}/result", h.submitResult)
	mux.HandleFunc("POST /v1/peer-requests/{request_id}/cancel", h.cancel)
	mux.HandleFunc("GET /v1/artifacts/{artifact_id}", h.fetchArtifact)
}

func (h *Handler) inspectProposal(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.principal(w, r)
	if !ok {
		return
	}
	result, err := h.store.InspectProposal(r.Context(), principal, r.PathValue("request_id"))
	if err != nil {
		h.writeStoreError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) heartbeat(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.principal(w, r)
	if !ok {
		return
	}
	var input protocol.AgentHeartbeat
	if !decodeJSON(w, r, &input) {
		return
	}
	card, err := h.store.Heartbeat(r.Context(), principal, input)
	if err != nil {
		h.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, card)
}

func (h *Handler) listAgents(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.principal(w, r)
	if !ok {
		return
	}
	limit := 50
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 50 {
			writeError(w, http.StatusBadRequest, "invalid_request", "limit must be between 1 and 50")
			return
		}
		limit = parsed
	}
	result, err := h.store.ListAgents(r.Context(), principal, AgentQuery{
		Need:             r.URL.Query().Get("need"),
		Capabilities:     r.URL.Query()["capability"],
		WorkspaceAliases: r.URL.Query()["workspace_alias"],
		OnlineOnly:       r.URL.Query().Get("online_only") == "true",
		AcceptingOnly:    r.URL.Query().Get("accepting_only") == "true",
		Limit:            limit,
	})
	if err != nil {
		h.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) createRequest(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.principal(w, r)
	if !ok {
		return
	}
	var input protocol.CreateRequest
	if !decodeJSON(w, r, &input) {
		return
	}
	result, requestNotice, created, err := h.store.CreateRequest(r.Context(), principal, input)
	if err != nil {
		h.writeStoreError(w, err)
		return
	}
	if created {
		targetAgentID := strings.TrimSpace(input.TargetAgentID)
		if targetAgentID == "" {
			stored, readErr := h.store.GetRequest(r.Context(), principal, result.RequestID)
			if readErr != nil {
				h.writeStoreError(w, readErr)
				return
			}
			targetAgentID = stored.TargetAgentID
		}
		h.hub.Publish(principal.OrganizationID, targetAgentID, event{Type: "peer_request", Payload: requestNotice})
	}
	// Preserve the original create response contract on an idempotent replay;
	// the internal created flag controls side effects, not the response shape.
	writeJSON(w, http.StatusCreated, result)
}

func (h *Handler) getRequest(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.principal(w, r)
	if !ok {
		return
	}
	result, err := h.store.GetRequest(r.Context(), principal, r.PathValue("request_id"))
	if err != nil {
		h.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) inbox(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.principal(w, r)
	if !ok {
		return
	}
	result, err := h.store.Inbox(r.Context(), principal)
	if err != nil {
		h.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"requests": result, "observed_at": time.Now().UTC()})
}

func (h *Handler) decide(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.principal(w, r)
	if !ok {
		return
	}
	var input protocol.DecisionPayload
	if !decodeJSON(w, r, &input) {
		return
	}
	result, err := h.store.Decide(r.Context(), principal, r.PathValue("request_id"), input)
	if err != nil {
		h.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) fetchExecution(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.principal(w, r)
	if !ok {
		return
	}
	result, err := h.store.FetchExecution(r.Context(), principal, r.PathValue("request_id"))
	if err != nil {
		h.writeStoreError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) markRunning(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.principal(w, r)
	if !ok {
		return
	}
	var input protocol.ExecutionClaimPayload
	if !decodeJSON(w, r, &input) {
		return
	}
	result, err := h.store.MarkRunning(r.Context(), principal, r.PathValue("request_id"), input.ExecutionClaimID)
	if err != nil {
		h.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) submitResult(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.principal(w, r)
	if !ok {
		return
	}
	var input protocol.ResultPayload
	if !decodeJSON(w, r, &input) {
		return
	}
	result, err := h.store.SubmitResult(r.Context(), principal, r.PathValue("request_id"), input)
	if err != nil {
		h.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) cancel(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.principal(w, r)
	if !ok {
		return
	}
	requestID := r.PathValue("request_id")
	request, err := h.store.GetRequest(r.Context(), principal, requestID)
	if err != nil {
		h.writeStoreError(w, err)
		return
	}
	result, changed, err := h.store.Cancel(r.Context(), principal, requestID)
	if err != nil {
		h.writeStoreError(w, err)
		return
	}
	if changed {
		h.hub.Publish(principal.OrganizationID, request.TargetAgentID, event{Type: "peer_cancelled", Payload: map[string]string{"request_id": requestID, "conversation_id": request.ConversationID}})
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) fetchArtifact(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.principal(w, r)
	if !ok {
		return
	}
	result, err := h.store.FetchArtifact(r.Context(), principal, r.PathValue("artifact_id"))
	if err != nil {
		h.writeStoreError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) events(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.principal(w, r)
	if !ok {
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "stream_unavailable", "streaming is unavailable")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	channel, unsubscribe := h.hub.Subscribe(principal.OrganizationID, principal.AgentID)
	defer unsubscribe()
	if h.hub.IsRevoked(principal.OrganizationID, principal.AgentID) {
		return
	}

	if _, err := fmt.Fprint(w, "event: ready\ndata: {\"api_version\":\"v1\"}\n\n"); err != nil {
		return
	}
	// Reconcile durable pending state after subscription so an event cannot be
	// lost between replay and attaching the live stream.
	pending, err := h.store.Inbox(r.Context(), principal)
	if err != nil {
		h.logger.Warn("event inbox reconciliation failed", "agent_id", principal.AgentID, "err", err)
		return
	}
	for _, item := range pending {
		if err := writeSSE(w, event{Type: "peer_request", Payload: item}); err != nil {
			return
		}
	}
	flusher.Flush()

	keepalive := time.NewTicker(20 * time.Second)
	defer keepalive.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case value, open := <-channel:
			if !open || writeSSE(w, value) != nil {
				return
			}
			flusher.Flush()
		case <-keepalive.C:
			if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func writeSSE(w io.Writer, value event) error {
	payload, err := json.Marshal(value.Payload)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", value.Type, payload)
	return err
}

func (h *Handler) principal(w http.ResponseWriter, r *http.Request) (auth.Principal, bool) {
	if h.authenticate == nil {
		writeError(w, http.StatusInternalServerError, "server_error", "authentication is unavailable")
		return auth.Principal{}, false
	}
	principal, err := h.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized", "valid bearer device credential required")
		return auth.Principal{}, false
	}
	if principal.TokenKind != auth.TokenDevice {
		writeError(w, http.StatusForbidden, "forbidden", "a device credential is required")
		return auth.Principal{}, false
	}
	return principal, true
}

func decodeJSON(w http.ResponseWriter, r *http.Request, output any) bool {
	if contentType := r.Header.Get("Content-Type"); contentType != "" && !strings.HasPrefix(strings.ToLower(contentType), "application/json") {
		writeError(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")
		return false
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maximumJSONBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON request: "+err.Error())
		return false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid_request", "request must contain one JSON value")
		return false
	}
	return true
}

func (h *Handler) writeStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrUnauthorized):
		writeError(w, http.StatusUnauthorized, "unauthorized", "valid bearer credential required")
	case errors.Is(err, ErrForbidden):
		writeError(w, http.StatusForbidden, "forbidden", "the authenticated device is not allowed to perform this operation")
	case errors.Is(err, ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "resource was not found")
	case errors.Is(err, ErrInvalid):
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
	case errors.Is(err, ErrConflict):
		writeError(w, http.StatusConflict, "conflict", err.Error())
	default:
		h.logger.Error("collaboration operation failed", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "internal relay error")
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, protocol.ErrorResponse{Code: code, Error: message})
}
