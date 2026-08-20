//go:build windows

package securefile

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func isTransientReadError(err error) bool {
	return errors.Is(err, syscall.ERROR_ACCESS_DENIED) || errors.Is(err, errorSharingViolation)
}

func TestTransientReadErrors(t *testing.T) {
	for _, err := range []error{
		&os.PathError{Op: "open", Path: "state.json", Err: syscall.ERROR_ACCESS_DENIED},
		&os.PathError{Op: "open", Path: "state.json", Err: errorSharingViolation},
	} {
		if !isTransientReadError(err) {
			t.Fatalf("isTransientReadError(%v) = false, want true", err)
		}
	}
	for _, err := range []error{
		&os.PathError{Op: "open", Path: "state.json", Err: syscall.ERROR_FILE_NOT_FOUND},
		errors.New("other read failure"),
	} {
		if isTransientReadError(err) {
			t.Fatalf("isTransientReadError(%v) = true, want false", err)
		}
	}
}

func TestWriteWhileDestinationIsOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}

	open, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}

	closed := make(chan error, 1)
	go func() {
		time.Sleep(50 * time.Millisecond)
		closed <- open.Close()
	}()

	writeErr := Write(path, []byte("new"))
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if writeErr != nil {
		t.Fatal(writeErr)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "new" {
		t.Fatalf("contents = %q, want new", data)
	}
}
