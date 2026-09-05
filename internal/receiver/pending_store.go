package receiver

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/mohitbadwal/team-relay/internal/privatefs"
	"github.com/mohitbadwal/team-relay/internal/protocol"
)

const pendingStoreVersion = 1

type PendingRecord struct {
	Notice     protocol.RequestNotice `json:"notice"`
	ReceivedAt time.Time              `json:"received_at"`
}

type pendingSnapshot struct {
	Version   int                      `json:"version"`
	UpdatedAt time.Time                `json:"updated_at"`
	Requests  map[string]PendingRecord `json:"requests"`
}

// PendingStore contains approval-safe metadata only. Full prompts may be
// fetched for explicit local inspection but are never persisted here; file
// bytes are fetched only after Allow Once.
type PendingStore struct {
	mu       sync.RWMutex
	path     string
	requests map[string]PendingRecord
}

func NewPendingStore(path string) (*PendingStore, error) {
	if path == "" {
		return nil, fmt.Errorf("pending store path is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve pending store path: %w", err)
	}
	if err := privatefs.EnsureDirectory(filepath.Dir(abs)); err != nil {
		return nil, fmt.Errorf("create pending store directory: %w", err)
	}
	store := &PendingStore{path: abs, requests: make(map[string]PendingRecord)}
	if err := store.load(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *PendingStore) List() []PendingRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]PendingRecord, 0, len(s.requests))
	for _, record := range s.requests {
		result = append(result, record)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Notice.CreatedAt.Equal(result[j].Notice.CreatedAt) {
			return result[i].Notice.RequestID < result[j].Notice.RequestID
		}
		return result[i].Notice.CreatedAt.Before(result[j].Notice.CreatedAt)
	})
	return result
}

func (s *PendingStore) Get(requestID string) (PendingRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.requests[requestID]
	return record, ok
}

func (s *PendingStore) Upsert(notice protocol.RequestNotice) error {
	if notice.RequestID == "" {
		return fmt.Errorf("request_id is required")
	}
	if notice.Status == "" {
		notice.Status = protocol.StatusAwaitingApproval
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	received := time.Now().UTC()
	if existing, ok := s.requests[notice.RequestID]; ok {
		received = existing.ReceivedAt
	}
	s.requests[notice.RequestID] = PendingRecord{Notice: notice, ReceivedAt: received}
	return s.writeLocked()
}

func (s *PendingStore) UpdateStatus(requestID string, status protocol.RequestStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.requests[requestID]
	if !ok {
		return fmt.Errorf("request %q is not in the local inbox", requestID)
	}
	record.Notice.Status = status
	s.requests[requestID] = record
	return s.writeLocked()
}

func (s *PendingStore) Remove(requestID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.requests[requestID]; !ok {
		return nil
	}
	delete(s.requests, requestID)
	return s.writeLocked()
}

func (s *PendingStore) Replace(notices []protocol.RequestNotice) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := make(map[string]PendingRecord, len(notices))
	now := time.Now().UTC()
	for _, notice := range notices {
		if notice.RequestID == "" || notice.Status.Terminal() {
			continue
		}
		if notice.Status == "" {
			notice.Status = protocol.StatusAwaitingApproval
		}
		received := now
		if existing, ok := s.requests[notice.RequestID]; ok {
			received = existing.ReceivedAt
		}
		next[notice.RequestID] = PendingRecord{Notice: notice, ReceivedAt: received}
	}
	s.requests = next
	return s.writeLocked()
}

func (s *PendingStore) load() error {
	data, err := privatefs.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return s.writeLocked()
	}
	if err != nil {
		return fmt.Errorf("read pending store: %w", err)
	}
	var snapshot pendingSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return fmt.Errorf("parse pending store: %w", err)
	}
	if snapshot.Version != pendingStoreVersion {
		return fmt.Errorf("unsupported pending store version %d", snapshot.Version)
	}
	for requestID, record := range snapshot.Requests {
		if requestID != "" && !record.Notice.Status.Terminal() {
			s.requests[requestID] = record
		}
	}
	return nil
}

func (s *PendingStore) writeLocked() error {
	snapshot := pendingSnapshot{Version: pendingStoreVersion, UpdatedAt: time.Now().UTC(), Requests: make(map[string]PendingRecord, len(s.requests))}
	for key, value := range s.requests {
		snapshot.Requests[key] = value
	}
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return fmt.Errorf("encode pending store: %w", err)
	}
	if err := privatefs.AtomicWriteFile(s.path, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("publish pending store: %w", err)
	}
	return nil
}
