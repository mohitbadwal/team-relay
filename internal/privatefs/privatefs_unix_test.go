//go:build !windows

package privatefs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateReadersRejectRelaxedUnixPermissions(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	if err := EnsureDirectory(directory); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "token")
	if err := WriteNewFile(path, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(path); err == nil {
		t.Fatal("private reader accepted a group-readable file")
	}

	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ValidateDirectory(directory); err == nil {
		t.Fatal("directory validator accepted permissions other than 0700")
	}
	if err := EnsureDirectory(directory); err == nil {
		t.Fatal("EnsureDirectory silently changed a caller-owned permissive directory")
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := ValidateDirectory(directory); err != nil {
		t.Fatalf("manually repaired directory is not private: %v", err)
	}
}

func TestEnsureDirectoryRejectsSymlink(t *testing.T) {
	target := filepath.Join(t.TempDir(), "target")
	if err := EnsureDirectory(target); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(filepath.Dir(target), "state-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := EnsureDirectory(link); err == nil {
		t.Fatal("private directory setup accepted a symlink")
	}
}
