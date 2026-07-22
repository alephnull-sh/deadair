package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Big-Comfy/deadair/internal/report"
)

func TestRunDemoJSONIsDeterministicAndDoesNotUseLiveConfiguration(t *testing.T) {
	for _, key := range []string{
		"DEADAIR_ES_URL",
		"DEADAIR_KIBANA_URL",
		"DEADAIR_API_KEY",
		"DEADAIR_OPENSEARCH_URL",
		"DEADAIR_OPENSEARCH_USERNAME",
		"DEADAIR_OPENSEARCH_PASSWORD",
	} {
		t.Setenv(key, "invalid-live-value")
	}

	var firstOut, firstErr bytes.Buffer
	if code := runDemo([]string{"--json"}, &firstOut, &firstErr); code != report.ExitHealthy {
		t.Fatalf("exit = %d, want %d; stderr: %s", code, report.ExitHealthy, firstErr.String())
	}
	var got report.Report
	if err := json.Unmarshal(firstOut.Bytes(), &got); err != nil {
		t.Fatalf("stdout is not a JSON report: %v\n%s", err, firstOut.String())
	}
	if got.Summary.DeadDetections == 0 || got.Summary.ImpairedDetections == 0 || got.Summary.UnusedSources == 0 {
		t.Fatalf("demo report is missing illustrative findings: %+v", got.Summary)
	}
	for _, guidance := range []string{"deadair setup", "deadair check", "deadair scan", "no SIEM connection"} {
		if strings.Contains(firstOut.String(), guidance) {
			t.Errorf("JSON stdout contains terminal guidance %q", guidance)
		}
	}
	if firstErr.Len() != 0 {
		t.Fatalf("stderr = %q", firstErr.String())
	}

	var secondOut, secondErr bytes.Buffer
	if code := runDemo([]string{"--json"}, &secondOut, &secondErr); code != report.ExitHealthy {
		t.Fatalf("second exit = %d; stderr: %s", code, secondErr.String())
	}
	if !bytes.Equal(firstOut.Bytes(), secondOut.Bytes()) {
		t.Fatal("successive demo JSON output differs")
	}
}

func TestRunDemoTerminalSummaryIncludesNextSteps(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runDemo(nil, &stdout, &stderr); code != report.ExitHealthy {
		t.Fatalf("exit = %d; stderr: %s", code, stderr.String())
	}
	for _, want := range []string{
		"DEAD: 2 enabled detection(s)",
		"IMPAIRED: 2 enabled detection(s)",
		"unused telemetry: 1 source(s)",
		"no SIEM connection was made",
		"deadair setup",
		"deadair check",
		"deadair scan",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("terminal output missing %q:\n%s", want, stdout.String())
		}
	}
}

func TestRunDemoWritesPrivateJSONAndHTML(t *testing.T) {
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "demo.json")
	htmlPath := filepath.Join(dir, "demo.html")
	var stdout, stderr bytes.Buffer
	code := runDemo([]string{"--json", "--out", jsonPath, "--html-out", htmlPath}, &stdout, &stderr)
	if code != report.ExitHealthy {
		t.Fatalf("exit = %d; stderr: %s", code, stderr.String())
	}

	fileJSON, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	var got report.Report
	if err := json.Unmarshal(fileJSON, &got); err != nil {
		t.Fatalf("JSON file is invalid: %v", err)
	}
	html, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(html, []byte("<!doctype html>")) || !bytes.Contains(html, []byte("Network flow anomaly")) {
		t.Fatalf("HTML file does not contain the demo report")
	}

	if runtime.GOOS != "windows" {
		for _, path := range []string{jsonPath, htmlPath} {
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if got := info.Mode().Perm(); got != 0o600 {
				t.Errorf("%s permissions = %o, want 600", filepath.Base(path), got)
			}
		}
	}
}

func TestRunDemoRedactsOutput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runDemo([]string{"--json", "--redact"}, &stdout, &stderr); code != report.ExitHealthy {
		t.Fatalf("exit = %d; stderr: %s", code, stderr.String())
	}
	for _, leak := range []string{"Network flow anomaly", "logs-batch-default", "device.trust.score"} {
		if strings.Contains(stdout.String(), leak) {
			t.Errorf("redacted output leaks %q", leak)
		}
	}
	var got report.Report
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Redacted {
		t.Error("redacted marker is false")
	}
}
