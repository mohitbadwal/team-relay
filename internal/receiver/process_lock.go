package receiver

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/mohitbadwal/team-relay/internal/privatefs"
)

var errReceiverStateLocked = errors.New("receiver state directory is already in use by another daemon")

type receiverProcessLock interface {
	Close() error
}

// acquireReceiverProcessLock prevents two receiver daemons from executing the
// same durable claim. The lock file is intentionally persistent: the operating
// system releases the advisory lock on process exit, including a crash.
func acquireReceiverProcessLock(path string) (receiverProcessLock, error) {
	if err := privatefs.AtomicWriteNewFile(path, nil, 0o600); err != nil {
		// Another startup may have published the stable lock file first. Only
		// ignore the creation error when the resulting path exists and passes
		// the same private-file validation as all other receiver state.
		if _, statErr := os.Lstat(path); statErr != nil {
			if errors.Is(err, fs.ErrExist) {
				return nil, statErr
			}
			return nil, err
		}
	}
	if err := privatefs.ValidateRegularFile(path); err != nil {
		return nil, fmt.Errorf("validate receiver process lock: %w", err)
	}
	lock, err := platformAcquireReceiverProcessLock(path)
	if err != nil {
		return nil, err
	}
	return lock, nil
}
