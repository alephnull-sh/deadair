//go:build windows

package securefile

import (
	"errors"
	"syscall"
	"time"
	"unsafe"
)

const (
	movefileReplaceExisting = 0x1
	movefileWriteThrough    = 0x8
	errorSharingViolation   = syscall.Errno(32)
)

var moveFileExW = syscall.NewLazyDLL("kernel32.dll").NewProc("MoveFileExW")

func replaceFile(from, to string) error {
	fromPtr, err := syscall.UTF16PtrFromString(from)
	if err != nil {
		return err
	}
	toPtr, err := syscall.UTF16PtrFromString(to)
	if err != nil {
		return err
	}
	// Go opens files without FILE_SHARE_DELETE on Windows. A reader can
	// therefore block replacement briefly even though it does not modify the
	// file. Retry those transient failures without falling back to a
	// remove-then-rename sequence, which would expose a missing destination.
	deadline := time.Now().Add(2 * time.Second)
	delay := time.Millisecond
	for {
		ok, _, callErr := moveFileExW.Call(
			uintptr(unsafe.Pointer(fromPtr)),
			uintptr(unsafe.Pointer(toPtr)),
			uintptr(movefileReplaceExisting|movefileWriteThrough),
		)
		if ok != 0 {
			return nil
		}
		if !errors.Is(callErr, syscall.ERROR_ACCESS_DENIED) &&
			!errors.Is(callErr, errorSharingViolation) {
			return callErr
		}
		if time.Now().After(deadline) {
			return callErr
		}
		time.Sleep(delay)
		delay *= 2
		if delay > 50*time.Millisecond {
			delay = 50 * time.Millisecond
		}
	}
}
