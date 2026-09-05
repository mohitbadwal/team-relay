//go:build !windows

package receiver

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLocalStateLoadersRejectGroupReadableFiles(t *testing.T) {
	tests := []struct {
		name   string
		create func(string) error
		load   func(string) error
	}{
		{
			name: "control token",
			create: func(path string) error {
				_, err := LoadOrCreateControlToken(path)
				return err
			},
			load: func(path string) error {
				_, err := LoadOrCreateControlToken(path)
				return err
			},
		},
		{
			name: "pending store",
			create: func(path string) error {
				_, err := NewPendingStore(path)
				return err
			},
			load: func(path string) error {
				_, err := NewPendingStore(path)
				return err
			},
		},
		{
			name: "approval store",
			create: func(path string) error {
				_, err := NewApprovalStore(path)
				return err
			},
			load: func(path string) error {
				_, err := NewApprovalStore(path)
				return err
			},
		},
		{
			name: "session store",
			create: func(path string) error {
				_, err := NewFileSessionStore(path)
				return err
			},
			load: func(path string) error {
				_, err := NewFileSessionStore(path)
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state", "local-state")
			if err := test.create(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o640); err != nil {
				t.Fatal(err)
			}
			if err := test.load(path); err == nil {
				t.Fatal("loader accepted a group-readable local-state file")
			}
		})
	}
}
