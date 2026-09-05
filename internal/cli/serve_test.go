package cli

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestServeRejectsInvalidInterval(t *testing.T) {
	for _, interval := range []string{"0s", "-1s"} {
		var stderr bytes.Buffer
		if code := runServe([]string{"--interval", interval}, &stderr); code != 2 || !strings.Contains(stderr.String(), "--interval") {
			t.Fatalf("interval=%s code=%d error=%s", interval, code, stderr.String())
		}
	}
}

func TestServeBindFailureDoesNotScan(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var requests atomic.Int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(503)
	}))
	defer backend.Close()
	t.Setenv("DEADAIR_BACKEND", "elastic")
	t.Setenv("DEADAIR_REDACT_KEY_FILE", "")
	statePath := filepath.Join(t.TempDir(), "state.json")
	var stderr bytes.Buffer
	code := runServe([]string{"--bind", listener.Addr().String(), "--es-url", backend.URL, "--kibana-url", backend.URL, "--state-file", statePath}, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "cannot listen") {
		t.Fatalf("code=%d error=%s", code, stderr.String())
	}
	if requests.Load() != 0 {
		t.Fatalf("backend contacted %d times before bind", requests.Load())
	}
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatalf("state side effect: %v", err)
	}
}

func TestServeShutdownWaitsForScan(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	done := make(chan error, 1)
	go func() {
		done <- serveMetrics(ctx, listener, time.Hour, http.NewServeMux(), func(ctx context.Context) {
			close(started)
			<-ctx.Done()
			close(cancelled)
			<-release
		})
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("scan did not start")
	}
	cancel()
	select {
	case <-cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("scan was not cancelled")
	}
	select {
	case err := <-done:
		t.Fatalf("returned before scan stopped: %v", err)
	default:
	}
	unblock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown did not finish")
	}
}
