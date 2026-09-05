//go:build !windows

package receiver

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

type unixReceiverProcessLock struct {
	file *os.File
}

func platformAcquireReceiverProcessLock(path string) (receiverProcessLock, error) {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open receiver process lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("open receiver process lock handle")
	}
	before, beforeErr := os.Lstat(path)
	opened, openedErr := file.Stat()
	if beforeErr != nil || openedErr != nil || before.Mode()&os.ModeSymlink != 0 || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		_ = file.Close()
		return nil, errors.New("receiver process lock changed while it was opened")
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, errReceiverStateLocked
		}
		return nil, fmt.Errorf("lock receiver state directory: %w", err)
	}
	return &unixReceiverProcessLock{file: file}, nil
}

func (l *unixReceiverProcessLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	err := errors.Join(unix.Flock(int(l.file.Fd()), unix.LOCK_UN), l.file.Close())
	l.file = nil
	return err
}
