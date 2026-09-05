//go:build windows

package main

import (
	"os"

	"github.com/mohitbadwal/team-relay/internal/privatefs"
	"golang.org/x/sys/windows"
)

const privateFileFullControl windows.ACCESS_MASK = 0x001f01ff

func platformOpenNewSecretFile(path string) (secretFile, error) {
	return privatefs.OpenNewFile(path, 0o600)
}

func platformRenameSetupFile(oldPath, newPath string) error {
	return privatefs.ReplaceFile(oldPath, newPath)
}

func platformSyncSetupDirectory(path string) error {
	// Windows has no supported equivalent of POSIX fsync on a directory.
	// Each file is opened write-through and explicitly flushed, and every
	// publication rename uses MOVEFILE_WRITE_THROUGH. That is the strongest
	// supported sequence available here without depending on filesystem-specific
	// native APIs.
	return privatefs.SyncDirectory(path)
}

func platformValidatePrivateRegularFile(path string, _ os.FileInfo) error {
	return privatefs.ValidateRegularFile(path)
}
