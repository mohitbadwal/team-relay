//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadPrivateSetupFileRejectsGroupReadableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml.enrollment-attempt")
	if err := os.WriteFile(path, []byte("sensitive"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateSetupFile(path); err == nil {
		t.Fatal("private setup reader accepted a group-readable file")
	}
}
