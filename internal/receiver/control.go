package receiver

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mohitbadwal/team-relay/internal/privatefs"
	"github.com/mohitbadwal/team-relay/internal/protocol"
)

type ApprovalController interface {
	Pending() []PendingRecord
	InspectProposal(context.Context, string) (*protocol.ProposalPayload, error)
	AllowOnce(context.Context, string) error
	Approve(context.Context, string, ApprovalLevel) (ApprovalResult, error)
	ApprovalGrants() ([]ApprovalGrant, error)
	RevokeApprovalGrant(string) error
	Deny(context.Context, string) error
}

type controlBusyReporter interface {
	ControlBusy() bool
}

type ControlServer struct {
	address    string
	tokenHash  [32]byte
	controller ApprovalController
	server     *http.Server
}

func NewControlServer(address, token string, controller ApprovalController) (*ControlServer, error) {
	if controller == nil {
		return nil, fmt.Errorf("approval controller is required")
	}
	if err := ValidateControlAddress(address); err != nil {
		return nil, err
	}
	if strings.TrimSpace(token) == "" {
		return nil, fmt.Errorf("control token is required")
	}
	control := &ControlServer{address: address, tokenHash: sha256.Sum256([]byte(token)), controller: controller}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", control.authorize(control.health))
	mux.HandleFunc("GET /v1/pending", control.authorize(control.listPending))
	mux.HandleFunc("GET /v1/requests/{request_id}/proposal", control.authorize(control.inspectProposal))
	mux.HandleFunc("POST /v1/requests/{request_id}/allow-once", control.authorize(control.allowOnce))
	mux.HandleFunc("POST /v1/requests/{request_id}/approve", control.authorize(control.approve))
	mux.HandleFunc("POST /v1/requests/{request_id}/deny", control.authorize(control.deny))
	mux.HandleFunc("GET /v1/approval-grants", control.authorize(control.listApprovalGrants))
	mux.HandleFunc("DELETE /v1/approval-grants/{grant_id}", control.authorize(control.revokeApprovalGrant))
	control.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	return control, nil
}

func (s *ControlServer) Serve(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.address)
	if err != nil {
		return fmt.Errorf("listen on local control address: %w", err)
	}
	shutdownDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = s.server.Shutdown(shutdownCtx)
			cancel()
		case <-shutdownDone:
		}
	}()
	err = s.server.Serve(listener)
	close(shutdownDone)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *ControlServer) authorize(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			writeControlError(w, http.StatusUnauthorized, "valid local control token required")
			return
		}
		provided := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
		providedHash := sha256.Sum256([]byte(provided))
		if provided == "" || subtle.ConstantTimeCompare(providedHash[:], s.tokenHash[:]) != 1 {
			writeControlError(w, http.StatusUnauthorized, "valid local control token required")
			return
		}
		// A delegated runtime currently shares the daemon user's OS identity in
		// this preview. Refuse every sensitive control read/mutation while it is
		// active so merely reading the bearer cannot immediately expose or alter
		// another teammate request. Health remains available to supervisors.
		if r.URL.Path != "/health" {
			if reporter, ok := s.controller.(controlBusyReporter); ok && reporter.ControlBusy() {
				writeControlError(w, http.StatusLocked, "local approval control is unavailable while a teammate runtime is active")
				return
			}
		}
		next(w, r)
	}
}

func (s *Service) ControlBusy() bool { return s.hasActiveExecution() }

func (s *ControlServer) health(w http.ResponseWriter, _ *http.Request) {
	writeControlJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *ControlServer) listPending(w http.ResponseWriter, _ *http.Request) {
	writeControlJSON(w, http.StatusOK, map[string]any{"requests": s.controller.Pending(), "observed_at": time.Now().UTC()})
}

func (s *ControlServer) inspectProposal(w http.ResponseWriter, r *http.Request) {
	requestID := strings.TrimSpace(r.PathValue("request_id"))
	if requestID == "" {
		writeControlError(w, http.StatusBadRequest, "request_id is required")
		return
	}
	proposal, err := s.controller.InspectProposal(r.Context(), requestID)
	if err != nil {
		writeControlError(w, http.StatusConflict, err.Error())
		return
	}
	writeControlJSON(w, http.StatusOK, proposal)
}

func (s *ControlServer) allowOnce(w http.ResponseWriter, r *http.Request) {
	requestID := strings.TrimSpace(r.PathValue("request_id"))
	if requestID == "" {
		writeControlError(w, http.StatusBadRequest, "request_id is required")
		return
	}
	result, err := s.controller.Approve(r.Context(), requestID, ApprovalLevelAskAlways)
	if err != nil {
		writeControlError(w, http.StatusConflict, err.Error())
		return
	}
	writeControlJSON(w, http.StatusAccepted, result)
}

func (s *ControlServer) approve(w http.ResponseWriter, r *http.Request) {
	requestID := strings.TrimSpace(r.PathValue("request_id"))
	if requestID == "" {
		writeControlError(w, http.StatusBadRequest, "request_id is required")
		return
	}
	var input struct {
		Level ApprovalLevel `json:"level"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		writeControlError(w, http.StatusBadRequest, "request body must contain one valid approval level")
		return
	}
	if err := ensureControlJSONEnd(decoder); err != nil {
		writeControlError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !input.Level.Valid() {
		writeControlError(w, http.StatusBadRequest, "level must be ask_always, conversation_30m, teammate_always, or all_always")
		return
	}
	result, err := s.controller.Approve(r.Context(), requestID, input.Level)
	if err != nil {
		writeControlError(w, http.StatusConflict, err.Error())
		return
	}
	writeControlJSON(w, http.StatusAccepted, result)
}

func (s *ControlServer) listApprovalGrants(w http.ResponseWriter, _ *http.Request) {
	grants, err := s.controller.ApprovalGrants()
	if err != nil {
		writeControlError(w, http.StatusConflict, err.Error())
		return
	}
	writeControlJSON(w, http.StatusOK, map[string]any{"grants": grants, "observed_at": time.Now().UTC()})
}

func (s *ControlServer) revokeApprovalGrant(w http.ResponseWriter, r *http.Request) {
	grantID := strings.TrimSpace(r.PathValue("grant_id"))
	if grantID == "" {
		writeControlError(w, http.StatusBadRequest, "grant_id is required")
		return
	}
	if err := s.controller.RevokeApprovalGrant(grantID); err != nil {
		writeControlError(w, http.StatusConflict, err.Error())
		return
	}
	writeControlJSON(w, http.StatusOK, map[string]string{"grant_id": grantID, "status": "revoked"})
}

func ensureControlJSONEnd(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain exactly one JSON object")
	}
	return nil
}

func (s *ControlServer) deny(w http.ResponseWriter, r *http.Request) {
	requestID := strings.TrimSpace(r.PathValue("request_id"))
	if requestID == "" {
		writeControlError(w, http.StatusBadRequest, "request_id is required")
		return
	}
	if err := s.controller.Deny(r.Context(), requestID); err != nil {
		writeControlError(w, http.StatusConflict, err.Error())
		return
	}
	writeControlJSON(w, http.StatusOK, map[string]string{"request_id": requestID, "status": "rejected"})
}

func ValidateControlAddress(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("control address must be host:port: %w", err)
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("control address must bind to a loopback IP")
	}
	return nil
}

func LoadOrCreateControlToken(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("control token path is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if err := privatefs.EnsureDirectory(filepath.Dir(abs)); err != nil {
		return "", fmt.Errorf("protect control token directory: %w", err)
	}
	data, err := privatefs.ReadFile(abs)
	if err == nil {
		token := strings.TrimSpace(string(data))
		if token == "" {
			return "", fmt.Errorf("control token file is empty")
		}
		return token, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("read control token: %w", err)
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate control token: %w", err)
	}
	token := "trl_" + base64.RawURLEncoding.EncodeToString(random)
	err = privatefs.AtomicWriteNewFile(abs, []byte(token+"\n"), 0o600)
	if errors.Is(err, os.ErrExist) {
		return LoadOrCreateControlToken(abs)
	}
	if err != nil {
		return "", fmt.Errorf("create control token: %w", err)
	}
	return token, nil
}

func writeControlJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeControlError(w http.ResponseWriter, status int, message string) {
	writeControlJSON(w, status, map[string]string{"error": message})
}
