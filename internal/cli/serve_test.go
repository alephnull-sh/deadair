package cli

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alephnull-sh/deadair/internal/exporter"
	"github.com/alephnull-sh/deadair/internal/report"
)

func TestServeRejectsNonPositiveIntervalBeforeTargetResolution(t *testing.T) {
	for _, interval := range []string{"0", "-1s"} {
		t.Run(interval, func(t *testing.T) {
			statePath := filepath.Join(t.TempDir(), "state.json")
			missingFleet := filepath.Join(t.TempDir(), "missing-fleet.json")
			var stderr bytes.Buffer
			code := runServeWithContext([]string{
				"--interval", interval,
				"--fleet", missingFleet,
				"--state-file", statePath,
			}, &stderr, context.Background())
			if code != report.ExitError {
				t.Fatalf("exit = %d, want %d", code, report.ExitError)
			}
			if !strings.Contains(stderr.String(), "--interval must be greater than zero") {
				t.Fatalf("interval error was not reported first:\n%s", stderr.String())
			}
			if strings.Contains(stderr.String(), "fleet") {
				t.Fatalf("invalid interval reached target resolution:\n%s", stderr.String())
			}
			if _, err := os.Stat(statePath); !os.IsNotExist(err) {
				t.Fatalf("invalid interval created state: %v", err)
			}
		})
	}
}

func TestServeBindFailurePerformsNoScanOrStateWrite(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()

	var requests atomic.Int64
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		http.Error(w, "backend must not be contacted", http.StatusInternalServerError)
	}))
	defer backend.Close()
	t.Setenv("DEADAIR_API_KEY", "test-key")
	statePath := filepath.Join(t.TempDir(), "state.json")

	var stderr bytes.Buffer
	code := runServeWithContext([]string{
		"--bind", occupied.Addr().String(),
		"--es-url", backend.URL,
		"--kibana-url", backend.URL,
		"--state-file", statePath,
	}, &stderr, context.Background())
	if code != report.ExitError {
		t.Fatalf("exit = %d, want %d", code, report.ExitError)
	}
	if requests.Load() != 0 {
		t.Fatalf("bind failure contacted backend %d time(s)", requests.Load())
	}
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatalf("bind failure created state: %v", err)
	}
	if !strings.Contains(stderr.String(), "address already in use") {
		t.Fatalf("bind error not reported:\n%s", stderr.String())
	}
}

func TestServeMetricsStartsAndShutsDownCleanly(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	scanStarted := make(chan struct{})
	scanFinished := make(chan struct{})
	scan := func(ctx context.Context) {
		close(scanStarted)
		<-ctx.Done()
		close(scanFinished)
	}
	server := &exporter.Server{}
	result := make(chan error, 1)
	go func() {
		result <- serveMetrics(ctx, listener, server.Handler(), time.Hour, scan)
	}()

	select {
	case <-scanStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("initial scan did not start")
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://" + address + "/metrics")
	if err != nil {
		t.Fatalf("metrics endpoint was not served: %v", err)
	}
	_, readErr := io.Copy(io.Discard, resp.Body)
	closeErr := resp.Body.Close()
	if readErr != nil || closeErr != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("metrics response = status %d, read %v, close %v", resp.StatusCode, readErr, closeErr)
	}

	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("clean shutdown returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serve did not stop after cancellation")
	}
	select {
	case <-scanFinished:
	default:
		t.Fatal("serve returned before the scan worker stopped")
	}

	rebound, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatalf("listener was not released after shutdown: %v", err)
	}
	_ = rebound.Close()
}

func TestServeMetricsAlreadyCancelledDoesNotScanOrLeakListener(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var scans atomic.Int64
	err = serveMetrics(ctx, listener, http.NewServeMux(), time.Hour, func(context.Context) {
		scans.Add(1)
	})
	if err != nil {
		t.Fatalf("already-cancelled shutdown returned error: %v", err)
	}
	if scans.Load() != 0 {
		t.Fatalf("already-cancelled server ran %d scan(s)", scans.Load())
	}
	rebound, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatalf("already-cancelled listener leaked: %v", err)
	}
	_ = rebound.Close()
}
