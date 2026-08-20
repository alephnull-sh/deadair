// Package securefile writes sensitive local artifacts without exposing a
// partially written file or inheriting permissive mode bits from an existing
// destination.
package securefile

import (
	"fmt"
	"os"
	"path/filepath"
)

// Write replaces path with data through the platform's replace operation. On
// POSIX filesystems the publication is an atomic rename. The replacement is
// created with 0600 permissions on POSIX, so an existing 0644 mode is never
// inherited there. Windows relies on the destination directory's ACL.
func Write(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".deadair-*")
	if err != nil {
		return fmt.Errorf("creating temporary file: %w", err)
	}
	tmpPath := tmp.Name()
	keep := false
	defer func() {
		_ = tmp.Close()
		if !keep {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("restricting temporary file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("writing temporary file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("syncing temporary file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing temporary file: %w", err)
	}
	if err := replaceFile(tmpPath, path); err != nil {
		return fmt.Errorf("replacing destination: %w", err)
	}
	keep = true
	return nil
}
