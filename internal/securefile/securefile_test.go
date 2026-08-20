package securefile

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestWriteReplacesPermissiveFileWithRestrictedFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not enforced on Windows")
	}
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, []byte("new")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %o, want 0600", got)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "new" {
		t.Fatalf("contents = %q, want new", data)
	}
}

func TestWritePublishesOnlyCompleteContents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	a := bytes.Repeat([]byte("a"), 256*1024)
	b := bytes.Repeat([]byte("b"), 256*1024)
	if err := Write(path, a); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		for i := 0; i < 20; i++ {
			data := a
			if i%2 == 0 {
				data = b
			}
			if err := Write(path, data); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()

	for {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
			return
		default:
			data, err := os.ReadFile(path)
			if err != nil {
				if isTransientReadError(err) {
					time.Sleep(time.Millisecond)
					continue
				}
				t.Fatal(err)
			}
			if !bytes.Equal(data, a) && !bytes.Equal(data, b) {
				t.Fatalf("reader observed partial contents: %d bytes", len(data))
			}
		}
	}
}
