//go:build !windows

package securefile

func isTransientReadError(error) bool {
	return false
}
