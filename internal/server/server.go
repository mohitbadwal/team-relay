package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mohitbadwal/team-relay/internal/auth"
	"github.com/mohitbadwal/team-relay/internal/store"
)

const maximumJSONBody = 64 << 10

type Config struct {
	BootstrapToken    string
	Now               func() time.Time
	RevocationEvicter RevocationEvicter
}

// RevocationEvicter removes collaboration presence and terminates active event
// streams after the authoritative member/device revocation commits.
type RevocationEvicter interface {
	EvictRevokedAgents(context.Context, string, []string) error
}

type Handler struct {
	repository          store.Repository
	bootstrapTokenHash  [32]byte
	bootstrapConfigured bool
	now                 func() time.Time
	logger              *slog.Logger
	revocationEvicter   RevocationEvicter
}

func NewHandler(repository store.Repository, config Config, logger *slog.Logger) *Handler {
	if config.Now == nil {
		config.Now = time.Now
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	bootstrapToken := strings.TrimSpace(config.BootstrapToken)
	handler := &Handler{
		repository:        repository,
		now:               config.Now,
		logger:            logger,
		revocationEvicter: config.RevocationEvicter,
	}
	if bootstrapToken != "" {
		handler.bootstrapTokenHash = sha256.Sum256([]byte(bootstrapToken))
		handler.bootstrapConfigured = true
	}
	return handler
}

func New(repository store.Repository, config Config, logger *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	NewHandler(repository, config, logger).RegisterRoutes(mux)
	return WithSecurityHeaders(mux)
}

// WithSecurityHeaders wraps both administrative and collaboration routes when
// they are composed by the server binary.
func WithSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// RegisterRoutes lets the relay command compose these administrative routes
// with collaboration routes without duplicating authentication state.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /health/live", h.live)
	mux.HandleFunc("GET /health/ready", h.ready)
	mux.HandleFunc("GET /v1/server-info", h.serverInfo)
	mux.HandleFunc("POST /v1/bootstrap", h.bootstrap)
	mux.HandleFunc("POST /v1/enroll", h.enroll)
	mux.HandleFunc("GET /v1/me", h.me)
	mux.HandleFunc("POST /v1/admin/credential/rotate", h.rotateAdminCredential)
	mux.HandleFunc("POST /v1/admin/invites", h.createInvite)
	mux.HandleFunc("GET /v1/admin/invites", h.listInvites)
	mux.HandleFunc("DELETE /v1/admin/invites/{invite_id}", h.revokeInvite)
	mux.HandleFunc("GET /v1/admin/members", h.listMembers)
	mux.HandleFunc("DELETE /v1/admin/members/{member_id}", h.revokeMember)
	mux.HandleFunc("GET /v1/admin/devices", h.listDevices)
	mux.HandleFunc("DELETE /v1/admin/devices/{device_id}", h.revokeDevice)
	mux.HandleFunc("GET /v1/admin/audit", h.listAudit)
}

func (h *Handler) rotateAdminCredential(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}
	var request struct {
		NewTokenHash   string `json:"new_token_hash"`
		IdempotencyKey string `json:"idempotency_key"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if !validIdempotencyKey(request.IdempotencyKey, "tr_rotate_") {
		writeStoreError(w, store.ErrInvalid)
		return
	}
	result, err := h.repository.RotateAdminCredential(r.Context(), principal, store.RotateAdminCredentialInput{
		NewTokenHash: request.NewTokenHash, IdempotencyHash: auth.Hash(request.IdempotencyKey), Now: h.now().UTC(),
	})
	if err != nil {
		h.handleStoreError(w, "rotate admin credential", err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, result)
}

// AuthenticateRequest accepts bearer credentials only. In particular, it does
// not inspect or trust identity headers inserted by a reverse proxy.
func (h *Handler) AuthenticateRequest(r *http.Request) (auth.Principal, error) {
	token, err := bearerToken(r)
	if err != nil {
		return auth.Principal{}, store.ErrUnauthorized
	}
	return h.repository.Authenticate(r.Context(), token)
}

func (h *Handler) live(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := h.repository.Ping(ctx); err != nil {
		h.logger.Warn("state store readiness check failed", "err", err)
		writeError(w, http.StatusServiceUnavailable, "not_ready", "state store is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (h *Handler) serverInfo(w http.ResponseWriter, r *http.Request) {
	initialized, err := h.repository.IsBootstrapped(r.Context())
	if err != nil {
		h.internalError(w, "read server state", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"name":           "team-relay",
		"api_version":    "v1",
		"initialized":    initialized,
		"authentication": "bearer",
	})
}

func (h *Handler) bootstrap(w http.ResponseWriter, r *http.Request) {
	if !h.bootstrapConfigured {
		writeError(w, http.StatusServiceUnavailable, "bootstrap_not_configured", "server bootstrap is not configured")
		return
	}
	rawToken, err := bearerToken(r)
	if err != nil || !h.validBootstrapToken(rawToken) {
		writeStoreError(w, store.ErrUnauthorized)
		return
	}
	var request struct {
		OrganizationName string `json:"organization_name"`
		AdminDisplayName string `json:"admin_display_name"`
		AdminEmail       string `json:"admin_email"`
		AdminTokenHash   string `json:"admin_token_hash"`
		IdempotencyKey   string `json:"idempotency_key"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if !validIdempotencyKey(request.IdempotencyKey, "tr_bootstrap_") {
		writeStoreError(w, store.ErrInvalid)
		return
	}
	result, err := h.repository.Bootstrap(r.Context(), store.BootstrapInput{
		OrganizationName: request.OrganizationName,
		AdminDisplayName: request.AdminDisplayName,
		AdminEmail:       request.AdminEmail,
		AdminTokenHash:   request.AdminTokenHash,
		IdempotencyHash:  auth.Hash(request.IdempotencyKey),
		Now:              h.now().UTC(),
	})
	if err != nil {
		h.handleStoreError(w, "bootstrap relay", err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, map[string]any{
		"organization": result.Organization,
		"admin":        result.Admin,
	})
}

func (h *Handler) enroll(w http.ResponseWriter, r *http.Request) {
	inviteToken, err := bearerToken(r)
	if err != nil {
		writeStoreError(w, store.ErrUnauthorized)
		return
	}
	var request struct {
		DisplayName       string `json:"display_name,omitempty"`
		DeviceName        string `json:"device_name"`
		Runtime           string `json:"runtime"`
		PermissionProfile string `json:"permission_profile,omitempty"`
		DeviceTokenHash   string `json:"device_token_hash"`
		IdempotencyKey    string `json:"idempotency_key"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if !validEnrollmentIdempotencyKey(request.IdempotencyKey) {
		writeStoreError(w, store.ErrInvalid)
		return
	}
	result, err := h.repository.Enroll(r.Context(), inviteToken, store.EnrollInput{
		DisplayName:        request.DisplayName,
		DeviceName:         request.DeviceName,
		Runtime:            request.Runtime,
		PermissionProfile:  request.PermissionProfile,
		DeviceTokenHash:    request.DeviceTokenHash,
		IdempotencyKeyHash: auth.Hash(request.IdempotencyKey),
		Now:                h.now().UTC(),
	})
	if err != nil {
		h.handleStoreError(w, "enroll device", err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, map[string]any{
		"organization": result.Organization,
		"member":       result.Member,
		"device":       result.Device,
	})
}

func validEnrollmentIdempotencyKey(value string) bool {
	return validIdempotencyKey(value, "tr_enroll_")
}

func validIdempotencyKey(value, prefix string) bool {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+64 {
		return false
	}
	_, err := hex.DecodeString(value[len(prefix):])
	return err == nil
}

func (h *Handler) me(w http.ResponseWriter, r *http.Request) {
	principal, err := h.AuthenticateRequest(r)
	if err != nil {
		h.handleStoreError(w, "authenticate request", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"principal": principal})
}

func (h *Handler) createInvite(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}
	var request struct {
		DisplayName      string `json:"display_name,omitempty"`
		Email            string `json:"email,omitempty"`
		MemberID         string `json:"member_id,omitempty"`
		ExpiresInSeconds int64  `json:"expires_in_seconds,omitempty"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if request.ExpiresInSeconds == 0 {
		request.ExpiresInSeconds = int64((24 * time.Hour).Seconds())
	}
	if request.ExpiresInSeconds < 60 || request.ExpiresInSeconds > int64((30*24*time.Hour).Seconds()) {
		writeError(w, http.StatusBadRequest, "invalid_request", "expires_in_seconds must be between 60 and 2592000")
		return
	}
	inviteToken, err := auth.NewToken(auth.TokenInvite)
	if err != nil {
		h.internalError(w, "generate invitation credential", err)
		return
	}
	now := h.now().UTC()
	invite, err := h.repository.CreateInvite(r.Context(), principal, store.CreateInviteInput{
		DisplayName:      request.DisplayName,
		Email:            request.Email,
		ExistingMemberID: request.MemberID,
		ExpiresAt:        now.Add(time.Duration(request.ExpiresInSeconds) * time.Second),
		InviteTokenHash:  auth.Hash(inviteToken),
		Now:              now,
	})
	if err != nil {
		h.handleStoreError(w, "create invitation", err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, map[string]any{"invite": invite, "invite_token": inviteToken})
}

func (h *Handler) listInvites(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}
	invites, err := h.repository.ListInvites(r.Context(), principal)
	if err != nil {
		h.handleStoreError(w, "list invitations", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"invites": invites})
}

func (h *Handler) revokeInvite(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}
	if err := h.repository.RevokeInvite(r.Context(), principal, r.PathValue("invite_id")); err != nil {
		h.handleStoreError(w, "revoke invitation", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) listMembers(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}
	members, err := h.repository.ListMembers(r.Context(), principal)
	if err != nil {
		h.handleStoreError(w, "list members", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"members": members})
}

func (h *Handler) revokeMember(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}
	result, err := h.repository.RevokeMember(r.Context(), principal, r.PathValue("member_id"))
	if err != nil {
		h.handleStoreError(w, "revoke member", err)
		return
	}
	if err := h.evictRevokedAgents(r.Context(), result); err != nil {
		h.internalError(w, "evict revoked member agents", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) listDevices(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}
	devices, err := h.repository.ListDevices(r.Context(), principal, r.URL.Query().Get("member_id"))
	if err != nil {
		h.handleStoreError(w, "list devices", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": devices})
}

func (h *Handler) revokeDevice(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}
	result, err := h.repository.RevokeDevice(r.Context(), principal, r.PathValue("device_id"))
	if err != nil {
		h.handleStoreError(w, "revoke device", err)
		return
	}
	if err := h.evictRevokedAgents(r.Context(), result); err != nil {
		h.internalError(w, "evict revoked device agent", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) evictRevokedAgents(ctx context.Context, result store.RevocationResult) error {
	if h.revocationEvicter == nil || len(result.AgentIDs) == 0 {
		return nil
	}
	// Once the authoritative revocation has committed, a client disconnect must
	// not cancel live-stream/presence eviction. Bound the detached cleanup so a
	// failed state backend still produces a prompt HTTP error on a connected call.
	evictionContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	return h.revocationEvicter.EvictRevokedAgents(evictionContext, result.OrganizationID, result.AgentIDs)
}

func (h *Handler) listAudit(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 500 {
			writeError(w, http.StatusBadRequest, "invalid_request", "limit must be between 1 and 500")
			return
		}
		limit = parsed
	}
	events, err := h.repository.ListAuditEvents(r.Context(), principal, limit)
	if err != nil {
		h.handleStoreError(w, "list audit events", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

func (h *Handler) requireAdmin(w http.ResponseWriter, r *http.Request) (auth.Principal, bool) {
	principal, err := h.AuthenticateRequest(r)
	if err != nil {
		h.handleStoreError(w, "authenticate admin request", err)
		return auth.Principal{}, false
	}
	if !principal.IsAdmin() {
		writeStoreError(w, store.ErrForbidden)
		return auth.Principal{}, false
	}
	return principal, true
}

func (h *Handler) validBootstrapToken(rawToken string) bool {
	if kind, err := auth.Kind(rawToken); err != nil || kind != auth.TokenBootstrap {
		return false
	}
	candidate := sha256.Sum256([]byte(strings.TrimSpace(rawToken)))
	return subtle.ConstantTimeCompare(candidate[:], h.bootstrapTokenHash[:]) == 1
}

func (h *Handler) handleStoreError(w http.ResponseWriter, operation string, err error) {
	if knownStoreError(err) {
		writeStoreError(w, err)
		return
	}
	h.internalError(w, operation, err)
}

func (h *Handler) internalError(w http.ResponseWriter, operation string, err error) {
	h.logger.Error(operation, "err", err)
	writeError(w, http.StatusInternalServerError, "internal_error", "an internal error occurred")
}

func knownStoreError(err error) bool {
	return errors.Is(err, store.ErrAlreadyBootstrapped) || errors.Is(err, store.ErrNotBootstrapped) ||
		errors.Is(err, store.ErrUnauthorized) || errors.Is(err, store.ErrForbidden) ||
		errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrConflict) ||
		errors.Is(err, store.ErrInviteExpired) || errors.Is(err, store.ErrInviteUsed) ||
		errors.Is(err, store.ErrInviteRevoked) || errors.Is(err, store.ErrInvalid)
}

func writeStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrUnauthorized):
		w.Header().Set("WWW-Authenticate", `Bearer realm="team-relay"`)
		writeError(w, http.StatusUnauthorized, "unauthorized", "a valid bearer credential is required")
	case errors.Is(err, store.ErrForbidden):
		writeError(w, http.StatusForbidden, "forbidden", "administrator access is required")
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "the requested resource was not found")
	case errors.Is(err, store.ErrInviteExpired):
		writeError(w, http.StatusGone, "invite_expired", "the invitation has expired")
	case errors.Is(err, store.ErrInviteUsed):
		writeError(w, http.StatusConflict, "invite_used", "the invitation has already been used")
	case errors.Is(err, store.ErrInviteRevoked):
		writeError(w, http.StatusConflict, "invite_revoked", "the invitation was revoked")
	case errors.Is(err, store.ErrAlreadyBootstrapped):
		writeError(w, http.StatusConflict, "already_bootstrapped", "the relay has already been bootstrapped")
	case errors.Is(err, store.ErrNotBootstrapped):
		writeError(w, http.StatusServiceUnavailable, "not_bootstrapped", "the relay has not been bootstrapped")
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, "conflict", "the operation conflicts with current state")
	case errors.Is(err, store.ErrInvalid):
		writeError(w, http.StatusBadRequest, "invalid_request", "the request contains invalid values")
	default:
		writeError(w, http.StatusInternalServerError, "internal_error", "an internal error occurred")
	}
}

func bearerToken(r *http.Request) (string, error) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return "", store.ErrUnauthorized
	}
	parts := strings.Fields(values[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || len(parts[1]) > 256 {
		return "", store.ErrUnauthorized
	}
	return parts[1], nil
}

func decodeJSON(w http.ResponseWriter, r *http.Request, destination any) error {
	if contentType := r.Header.Get("Content-Type"); contentType != "" {
		mediaType, _, err := mime.ParseMediaType(contentType)
		if err != nil || mediaType != "application/json" {
			return errors.New("Content-Type must be application/json")
		}
	}
	r.Body = http.MaxBytesReader(w, r.Body, maximumJSONBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain one JSON object")
	}
	return nil
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSONStatus(w, status, map[string]any{
		"error": map[string]string{"code": code, "message": message},
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	writeJSONStatus(w, status, value)
}

func writeJSONStatus(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
