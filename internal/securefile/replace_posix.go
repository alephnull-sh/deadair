//go:build !windows

package securefile

import "os"

func replaceFile(from, to string) error {
	return os.Rename(from, to)
}
