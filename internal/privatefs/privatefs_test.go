package privatefs

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPrivateDirectoryAndAtomicFileLifecycle(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state", "nested")
	if err := EnsureDirectory(directory); err != nil {
		t.Fatal(err)
	}
	if err := ValidateDirectory(directory); err != nil {
		t.Fatalf("new directory is not private: %v", err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(directory)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o700 {
			t.Fatalf("directory mode = %o, want 700", info.Mode().Perm())
		}
	}

	path := filepath.Join(directory, "state.json")
	if err := AtomicWriteFile(path, []byte("first\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := AtomicWriteFile(path, []byte("second\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	payload, err := ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != "second\n" {
		t.Fatalf("payload = %q", payload)
	}
	if err := ValidateRegularFile(path); err != nil {
		t.Fatalf("published file is not private: %v", err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("file mode = %o, want 600", info.Mode().Perm())
		}
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "state.json" {
		t.Fatalf("private temporary file leaked: %#v", entries)
	}
}

func TestWriteNewFileRefusesReplacement(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	if err := EnsureDirectory(directory); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "token")
	if err := WriteNewFile(path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteNewFile(path, []byte("second"), 0o600); !errors.Is(err, os.ErrExist) {
		t.Fatalf("replacement error = %v, want os.ErrExist", err)
	}
	payload, err := ReadFile(path)
	if err != nil || string(payload) != "first" {
		t.Fatalf("payload = %q, err = %v", payload, err)
	}
}

func TestAtomicWriteNewFileRefusesReplacementWithoutPublishingPartialData(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	if err := EnsureDirectory(directory); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "token")
	if err := AtomicWriteNewFile(path, []byte("complete"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := AtomicWriteNewFile(path, []byte("replacement"), 0o600); !errors.Is(err, os.ErrExist) {
		t.Fatalf("replacement error = %v, want os.ErrExist", err)
	}
	payload, err := ReadFile(path)
	if err != nil || string(payload) != "complete" {
		t.Fatalf("payload = %q, err = %v", payload, err)
	}
}
