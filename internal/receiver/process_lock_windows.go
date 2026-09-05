//go:build windows

package receiver

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

type windowsReceiverProcessLock struct {
	file       *os.File
	overlapped windows.Overlapped
}

func platformAcquireReceiverProcessLock(path string) (receiverProcessLock, error) {
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open receiver process lock: %w", err)
	}
	before, beforeErr := os.Lstat(path)
	opened, openedErr := file.Stat()
	if beforeErr != nil || openedErr != nil || before.Mode()&os.ModeSymlink != 0 || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		_ = file.Close()
		return nil, errors.New("receiver process lock changed while it was opened")
	}
	lock := &windowsReceiverProcessLock{file: file}
	err = windows.LockFileEx(
		windows.Handle(file.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0,
		1,
		0,
		&lock.overlapped,
	)
	if err != nil {
		_ = file.Close()
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return nil, errReceiverStateLocked
		}
		return nil, fmt.Errorf("lock receiver state directory: %w", err)
	}
	return lock, nil
}

func (l *windowsReceiverProcessLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	err := errors.Join(
		windows.UnlockFileEx(windows.Handle(l.file.Fd()), 0, 1, 0, &l.overlapped),
		l.file.Close(),
	)
	l.file = nil
	return err
}
