//go:build !windows

package main

import (
	"os"

	"github.com/mohitbadwal/team-relay/internal/privatefs"
)

func platformOpenNewSecretFile(path string) (secretFile, error) {
	return privatefs.OpenNewFile(path, 0o600)
}

func platformRenameSetupFile(oldPath, newPath string) error {
	return privatefs.ReplaceFile(oldPath, newPath)
}

func platformSyncSetupDirectory(path string) error {
	return privatefs.SyncDirectory(path)
}

func platformValidatePrivateRegularFile(path string, _ os.FileInfo) error {
	return privatefs.ValidateRegularFile(path)
}
