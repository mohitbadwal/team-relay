package receiver

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/mohitbadwal/team-relay/internal/privatefs"
	relayruntime "github.com/mohitbadwal/team-relay/internal/runtime"
)

const sessionStoreVersion = 1

type SessionStore interface {
	Get(conversationID string) (*relayruntime.SessionRef, error)
	Put(conversationID string, session relayruntime.SessionRef) error
	Delete(conversationID string) error
}

type sessionSnapshot struct {
	Version   int                                `json:"version"`
	UpdatedAt time.Time                          `json:"updated_at"`
	Sessions  map[string]relayruntime.SessionRef `json:"sessions"`
}

// FileSessionStore is private recipient-local state. Opaque provider session
// IDs are never stored by or returned to the relay.
type FileSessionStore struct {
	mu       sync.RWMutex
	path     string
	sessions map[string]relayruntime.SessionRef
}

func NewFileSessionStore(path string) (*FileSessionStore, error) {
	if path == "" {
		return nil, fmt.Errorf("session store path is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve session store path: %w", err)
	}
	if err := privatefs.EnsureDirectory(filepath.Dir(abs)); err != nil {
		return nil, fmt.Errorf("create session store directory: %w", err)
	}
	store := &FileSessionStore{path: abs, sessions: make(map[string]relayruntime.SessionRef)}
	if err := store.load(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *FileSessionStore) Get(conversationID string) (*relayruntime.SessionRef, error) {
	if conversationID == "" {
		return nil, fmt.Errorf("conversation_id is required")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	session, ok := s.sessions[conversationID]
	if !ok {
		return nil, nil
	}
	copy := session
	return &copy, nil
}

func (s *FileSessionStore) Put(conversationID string, session relayruntime.SessionRef) error {
	if conversationID == "" || session.RuntimeID == "" || session.OpaqueID == "" {
		return fmt.Errorf("conversation_id and complete session reference are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[conversationID] = session
	return s.writeLocked()
}

func (s *FileSessionStore) Delete(conversationID string) error {
	if conversationID == "" {
		return fmt.Errorf("conversation_id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sessions[conversationID]; !ok {
		return nil
	}
	delete(s.sessions, conversationID)
	return s.writeLocked()
}

func (s *FileSessionStore) load() error {
	data, err := privatefs.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return s.writeLocked()
	}
	if err != nil {
		return fmt.Errorf("read session store: %w", err)
	}
	var snapshot sessionSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return fmt.Errorf("parse session store: %w", err)
	}
	if snapshot.Version != sessionStoreVersion {
		return fmt.Errorf("unsupported session store version %d", snapshot.Version)
	}
	for conversationID, session := range snapshot.Sessions {
		if conversationID != "" && session.RuntimeID != "" && session.OpaqueID != "" {
			s.sessions[conversationID] = session
		}
	}
	return nil
}

func (s *FileSessionStore) writeLocked() error {
	snapshot := sessionSnapshot{
		Version:   sessionStoreVersion,
		UpdatedAt: time.Now().UTC(),
		Sessions:  make(map[string]relayruntime.SessionRef, len(s.sessions)),
	}
	for key, value := range s.sessions {
		snapshot.Sessions[key] = value
	}
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return fmt.Errorf("encode session store: %w", err)
	}
	if err := privatefs.AtomicWriteFile(s.path, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("publish session store: %w", err)
	}
	return nil
}
