//go:build !windows

package privatefs

import (
	"errors"
	"io/fs"
	"os"
)

func platformCreatePrivateDirectory(path string) error {
	return os.Mkdir(path, 0o700)
}

func platformValidatePrivateDirectory(_ string, info os.FileInfo) error {
	if info.Mode().Perm() != 0o700 {
		return errors.New("directory permissions must be 0700")
	}
	return nil
}

func platformOpenNewPrivateFile(path string, mode fs.FileMode) (*os.File, error) {
	return os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, mode.Perm())
}

func platformValidatePrivateRegularFile(_ string, info os.FileInfo) error {
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("file permissions allow group or other access")
	}
	return nil
}

func platformValidateContainedRegularFile(_ string, _ os.FileInfo) error {
	return nil
}

func platformValidatePrivateFileHandle(file *os.File) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	return platformValidatePrivateRegularFile(file.Name(), info)
}

func platformReplaceFile(oldPath, newPath string) error {
	return os.Rename(oldPath, newPath)
}

func platformPublishNewFile(oldPath, newPath string) error {
	return os.Link(oldPath, newPath)
}

func platformSyncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	return errors.Join(syncErr, closeErr)
}
