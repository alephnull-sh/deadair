//go:build windows

package securefile

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

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
