// Package privatefs creates and validates recipient-local state that must only
// be accessible to the current operating-system user.
package privatefs

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

const temporaryNameAttempts = 100

// EnsureDirectory creates path and any missing descendants with private
// permissions. If path already exists, its privacy is validated without
// mutating an arbitrary caller-owned directory; private files within it are
// validated separately when loaded.
func EnsureDirectory(path string) error {
	abs, err := absolutePath(path)
	if err != nil {
		return err
	}
	if info, statErr := os.Lstat(abs); statErr == nil {
		return validatePrivateDirectory(abs, info)
	} else if !errors.Is(statErr, fs.ErrNotExist) {
		return fmt.Errorf("inspect private directory %s: %w", abs, statErr)
	}

	missing := make([]string, 0, 2)
	for current := abs; ; current = filepath.Dir(current) {
		info, statErr := os.Stat(current)
		if statErr == nil {
			if !info.IsDir() {
				return fmt.Errorf("private directory parent %s is not a directory", current)
			}
			break
		}
		if !errors.Is(statErr, fs.ErrNotExist) {
			return fmt.Errorf("inspect private directory parent %s: %w", current, statErr)
		}
		missing = append(missing, current)
		parent := filepath.Dir(current)
		if parent == current {
			return fmt.Errorf("no existing parent for private directory %s", abs)
		}
	}
	for index := len(missing) - 1; index >= 0; index-- {
		current := missing[index]
		if err := platformCreatePrivateDirectory(current); err != nil {
			if !errors.Is(err, fs.ErrExist) {
				return fmt.Errorf("create private directory %s: %w", current, err)
			}
		}
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect created private directory %s: %w", current, err)
		}
		if err := validatePrivateDirectory(current, info); err != nil {
			return fmt.Errorf("created directory %s is not private: %w", current, err)
		}
		if err := SyncDirectory(filepath.Dir(current)); err != nil {
			return fmt.Errorf("sync parent of private directory %s: %w", current, err)
		}
	}
	return nil
}

// CreateDirectory creates exactly one new private directory. Its parent must
// already exist. Privacy is applied by the operating system at creation time.
func CreateDirectory(path string) error {
	abs, err := absolutePath(path)
	if err != nil {
		return err
	}
	if err := platformCreatePrivateDirectory(abs); err != nil {
		return err
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return fmt.Errorf("inspect new private directory: %w", err)
	}
	if err := validatePrivateDirectory(abs, info); err != nil {
		_ = os.Remove(abs)
		return fmt.Errorf("new directory is not private: %w", err)
	}
	if err := SyncDirectory(filepath.Dir(abs)); err != nil {
		_ = os.Remove(abs)
		return err
	}
	return nil
}

// ValidateDirectory confirms that path is a non-symlink directory protected
// from every identity except the current OS user.
func ValidateDirectory(path string) error {
	abs, err := absolutePath(path)
	if err != nil {
		return err
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return err
	}
	return validatePrivateDirectory(abs, info)
}

func validatePrivateDirectory(path string, info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("path is not a non-symlink directory")
	}
	return platformValidatePrivateDirectory(path, info)
}

// OpenNewFile creates a new private regular file without a permissive window.
// The requested mode is honored on Unix; Windows uses a protected current-user
// DACL and ignores POSIX mode bits.
func OpenNewFile(path string, mode fs.FileMode) (*os.File, error) {
	abs, err := absolutePath(path)
	if err != nil {
		return nil, err
	}
	return platformOpenNewPrivateFile(abs, mode)
}

// WriteNewFile durably writes a new private file and refuses to replace an
// existing path.
func WriteNewFile(path string, payload []byte, mode fs.FileMode) error {
	abs, err := absolutePath(path)
	if err != nil {
		return err
	}
	file, err := OpenNewFile(abs, mode)
	if err != nil {
		return err
	}
	if err := writeAndClose(abs, file, payload); err != nil {
		return err
	}
	if err := ValidateRegularFile(abs); err != nil {
		_ = os.Remove(abs)
		return fmt.Errorf("validate new private file: %w", err)
	}
	if err := SyncDirectory(filepath.Dir(abs)); err != nil {
		_ = os.Remove(abs)
		return err
	}
	return nil
}

// AtomicWriteNewFile durably stages a private file and atomically publishes it
// only if path does not already exist. A reader therefore never observes a
// partially written new file.
func AtomicWriteNewFile(path string, payload []byte, mode fs.FileMode) error {
	abs, err := absolutePath(path)
	if err != nil {
		return err
	}
	directory := filepath.Dir(abs)
	if err := EnsureDirectory(directory); err != nil {
		return fmt.Errorf("prepare private file directory: %w", err)
	}
	temporaryPath, file, err := createTemporary(directory, "."+filepath.Base(abs)+".private-", mode)
	if err != nil {
		return err
	}
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := writeAndClose(temporaryPath, file, payload); err != nil {
		return err
	}
	if err := platformPublishNewFile(temporaryPath, abs); err != nil {
		return fmt.Errorf("publish new private file: %w", err)
	}
	if err := os.Remove(temporaryPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove private publication link: %w", err)
	}
	removeTemporary = false
	if err := ValidateRegularFile(abs); err != nil {
		_ = os.Remove(abs)
		return fmt.Errorf("validate published private file: %w", err)
	}
	if err := SyncDirectory(directory); err != nil {
		return fmt.Errorf("sync private file directory: %w", err)
	}
	return nil
}

// AtomicWriteFile writes a private temporary file in the destination directory
// and atomically publishes it over path. The directory must itself be private.
func AtomicWriteFile(path string, payload []byte, mode fs.FileMode) error {
	abs, err := absolutePath(path)
	if err != nil {
		return err
	}
	directory := filepath.Dir(abs)
	if err := EnsureDirectory(directory); err != nil {
		return fmt.Errorf("prepare private file directory: %w", err)
	}
	temporaryPath, file, err := createTemporary(directory, "."+filepath.Base(abs)+".private-", mode)
	if err != nil {
		return err
	}
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := writeAndClose(temporaryPath, file, payload); err != nil {
		return err
	}
	if err := ReplaceFile(temporaryPath, abs); err != nil {
		return fmt.Errorf("publish private file: %w", err)
	}
	removeTemporary = false
	if err := SyncDirectory(directory); err != nil {
		return fmt.Errorf("sync private file directory: %w", err)
	}
	return nil
}

// ReadFile validates both the containing directory and file, reads through the
// validated handle, then confirms that the path was not replaced during use.
func ReadFile(path string) ([]byte, error) {
	abs, err := absolutePath(path)
	if err != nil {
		return nil, err
	}
	if err := ValidateDirectory(filepath.Dir(abs)); err != nil {
		return nil, fmt.Errorf("private file directory is unsafe: %w", err)
	}
	before, err := os.Lstat(abs)
	if err != nil {
		return nil, err
	}
	if err := validatePrivateRegularFile(abs, before); err != nil {
		return nil, fmt.Errorf("file is not private: %w", err)
	}
	file, err := os.Open(abs)
	if err != nil {
		return nil, err
	}
	if err := platformValidatePrivateFileHandle(file); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("opened file is not private: %w", err)
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		_ = file.Close()
		return nil, errors.New("private file changed while it was opened")
	}
	payload, readErr := io.ReadAll(file)
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return nil, errors.Join(readErr, closeErr)
	}
	after, err := os.Lstat(abs)
	if err != nil || !os.SameFile(before, after) {
		return nil, errors.New("private file changed while it was read")
	}
	return payload, nil
}

// ValidateRegularFile confirms that path is a private non-symlink regular file.
func ValidateRegularFile(path string) error {
	abs, err := absolutePath(path)
	if err != nil {
		return err
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return err
	}
	return validatePrivateRegularFile(abs, info)
}

// ValidateContainedRegularFile confirms that a runtime-created file is a
// regular direct child of a private directory and cannot be read by another
// Windows identity. On Unix the enclosing 0700 directory supplies this
// containment even if the runtime's umask left owner-neutral mode bits.
func ValidateContainedRegularFile(path string) error {
	abs, err := absolutePath(path)
	if err != nil {
		return err
	}
	if err := ValidateDirectory(filepath.Dir(abs)); err != nil {
		return fmt.Errorf("containing directory is not private: %w", err)
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("path is not a non-symlink regular file")
	}
	return platformValidateContainedRegularFile(abs, info)
}

func validatePrivateRegularFile(path string, info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("path is not a non-symlink regular file")
	}
	return platformValidatePrivateRegularFile(path, info)
}

// SyncDirectory persists directory-entry changes where the platform supports
// that operation. Windows publications use write-through handles and renames.
func SyncDirectory(path string) error {
	return platformSyncDirectory(path)
}

// ReplaceFile atomically replaces newPath with oldPath and preserves the
// platform's strongest available publication durability semantics.
func ReplaceFile(oldPath, newPath string) error {
	if err := platformReplaceFile(oldPath, newPath); err != nil {
		return err
	}
	if err := ValidateRegularFile(newPath); err != nil {
		_ = os.Remove(newPath)
		return fmt.Errorf("published file did not retain private permissions: %w", err)
	}
	return nil
}

func createTemporary(directory, prefix string, mode fs.FileMode) (string, *os.File, error) {
	for range temporaryNameAttempts {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return "", nil, fmt.Errorf("generate private temporary name: %w", err)
		}
		path := filepath.Join(directory, prefix+hex.EncodeToString(random[:]))
		file, err := OpenNewFile(path, mode)
		if err == nil {
			return path, file, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return "", nil, err
		}
	}
	return "", nil, errors.New("could not allocate a private temporary file")
}

func writeAndClose(path string, file *os.File, payload []byte) error {
	for len(payload) > 0 {
		written, err := file.Write(payload)
		if err != nil {
			_ = file.Close()
			_ = os.Remove(path)
			return fmt.Errorf("write private file: %w", err)
		}
		if written == 0 {
			_ = file.Close()
			_ = os.Remove(path)
			return fmt.Errorf("write private file: %w", io.ErrShortWrite)
		}
		payload = payload[written:]
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return fmt.Errorf("sync private file: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("close private file: %w", err)
	}
	return nil
}

func absolutePath(path string) (string, error) {
	if path == "" {
		return "", errors.New("private path is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.Clean(abs), nil
}
