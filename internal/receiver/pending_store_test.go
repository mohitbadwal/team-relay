package receiver

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/mohitbadwal/team-relay/internal/privatefs"
	"github.com/mohitbadwal/team-relay/internal/protocol"
)

func TestPendingStorePersistsPrivately(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "pending.json")
	store, err := NewPendingStore(path)
	if err != nil {
		t.Fatal(err)
	}
	notice := protocol.RequestNotice{
		RequestID: "req_private",
		Status:    protocol.StatusAwaitingApproval,
		CreatedAt: time.Now().UTC(),
	}
	if err := store.Upsert(notice); err != nil {
		t.Fatal(err)
	}
	if err := privatefs.ValidateRegularFile(path); err != nil {
		t.Fatalf("pending store is not private: %v", err)
	}
	if err := privatefs.ValidateDirectory(filepath.Dir(path)); err != nil {
		t.Fatalf("pending store directory is not private: %v", err)
	}
	reloaded, err := NewPendingStore(path)
	if err != nil {
		t.Fatal(err)
	}
	record, ok := reloaded.Get(notice.RequestID)
	if !ok || record.Notice.RequestID != notice.RequestID {
		t.Fatalf("reloaded record = %#v, present = %v", record, ok)
	}
}
