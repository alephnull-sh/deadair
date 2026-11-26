package cli

import (
	"bytes"
	"context"
	"fmt"
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

func TestServePersistsReportsAndReloadsRotatedSecretFile(t *testing.T) {
	t.Setenv("DEADAIR_BACKEND", "elastic")
	t.Setenv("DEADAIR_REDACT_KEY_FILE", "")
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "api.key")
	if err := os.WriteFile(keyPath, []byte("key-v1"), 0o600); err != nil {
		t.Fatal(err)
	}

	var currentExpectedKey atomic.Value
	currentExpectedKey.Store("key-v1")
	var completedScans atomic.Int32
	secondTickDone := make(chan struct{})
	var closeOnce sync.Once

	now := time.Now().UTC()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wantAuth := "ApiKey " + currentExpectedKey.Load().(string)
		if r.Header.Get("Authorization") != wantAuth {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `{"version":{"number":"9.5.6"}}`)
		case "/api/detection_engine/rules/_find":
			fmt.Fprint(w, `{"page":1,"perPage":100,"total":1,"data":[{"id":"r1","rule_id":"r1","name":"Live Rule","enabled":true,"severity":"high","index":["logs-app-*"]}]}`)
		case "/_data_stream/_stats":
			fmt.Fprintf(w, `{"data_streams":[{"data_stream":"logs-app-default","store_size_bytes":1024,"maximum_timestamp":%d}]}`, now.UnixMilli())
		case "/_cat/indices":
			fmt.Fprint(w, `[{"index":".ds-logs-app-default-2026.11.25-000001","docs.count":"10","store.size":"1024"}]`)
		case "/_resolve/index/logs-app-*":
			n := completedScans.Add(1)
			if n == 1 {
				// Rotate the API key file on disk before the next serve tick!
				if err := os.WriteFile(keyPath, []byte("key-v2\n"), 0o600); err == nil {
					currentExpectedKey.Store("key-v2")
				}
			}
			if n >= 2 {
				closeOnce.Do(func() { close(secondTickDone) })
			}
			fmt.Fprint(w, `{"data_streams":[{"name":"logs-app-default"}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer backend.Close()

	// Find an available loopback port cleanly.
	probeListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	bindAddr := probeListener.Addr().String()
	probeListener.Close()

	jsonPath := filepath.Join(dir, "latest.json")
	htmlPath := filepath.Join(dir, "latest.html")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var stderr bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- runServeWithContext(ctx, []string{
			"--bind", bindAddr,
			"--interval", "30ms",
			"--es-url", backend.URL,
			"--kibana-url", backend.URL,
			"--api-key-file", keyPath,
			"--json-out", jsonPath,
			"--html-out", htmlPath,
		}, &stderr)
	}()

	select {
	case <-secondTickDone:
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatalf("second tick with rotated secret did not succeed; stderr:\n%s", stderr.String())
	}
	// Give the second tick a moment to finish writing latest.json / latest.html before cancelling.
	time.Sleep(25 * time.Millisecond)
	cancel()

	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("serve exit = %d; stderr:\n%s", code, stderr.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serve did not exit after cancel")
	}

	if strings.Contains(stderr.String(), "scan failed") {
		t.Fatalf("unexpected scan failure during credential rotation:\n%s", stderr.String())
	}
	if _, err := os.Stat(jsonPath); err != nil {
		t.Fatalf("expected persisted JSON report: %v", err)
	}
	if _, err := os.Stat(htmlPath); err != nil {
		t.Fatalf("expected persisted HTML report: %v", err)
	}
}
