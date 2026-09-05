package cli_test

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alephnull-sh/deadair/internal/cli"
	"github.com/alephnull-sh/deadair/internal/report"
)

// fixtureServer emulates the minimal Kibana + Elasticsearch surface a scan
// touches: one healthy data stream, one unused data stream, one stale plain
// index, and five rules covering every classification path.
func fixtureServer(t *testing.T) *httptest.Server {
	return fixtureServerOptions(t, "9.4.4", 0)
}

func fixtureServerOptions(t *testing.T, version string, resolveStatus int) *httptest.Server {
	return fixtureServerCapabilities(t, version, resolveStatus, 0)
}

func fixtureServerCapabilities(t *testing.T, version string, resolveStatus, dataViewStatus int) *httptest.Server {
	t.Helper()
	now := time.Now()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/detection_engine/rules/_find", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "ApiKey testkey" {
			t.Errorf("Authorization = %q, want ApiKey testkey", got)
		}
		totalRules := 5
		extraRule := ""
		if dataViewStatus != 0 {
			totalRules++
			extraRule = `,
			{"id":"r6","name":"Data view rule","enabled":true,"severity":"medium","risk_score":40,"data_view_id":"dv-check"}`
		}
		fmt.Fprintf(w, `{"page":1,"perPage":100,"total":%d,"data":[
			{"id":"r1","name":"Endpoint process anomaly","enabled":true,"severity":"critical","risk_score":99,"index":["logs-endpoint.events.*"]},
			{"id":"r2","name":"Winlog suspicious logon","enabled":true,"severity":"high","risk_score":73,"index":["winlogbeat-*"]},
			{"id":"r3","name":"Legacy netflow rule","enabled":true,"severity":"medium","risk_score":47,"index":["netflow-*"]},
			{"id":"r4","name":"ML anomaly rule","enabled":true,"severity":"low","risk_score":21},
			{"id":"r5","name":"Disabled endpoint rule","enabled":false,"severity":"high","risk_score":73,"index":["logs-endpoint.events.*"]}%s
		]}`, totalRules, extraRule)
	})
	mux.HandleFunc("/api/data_views/data_view/dv-check", func(w http.ResponseWriter, r *http.Request) {
		if dataViewStatus != 0 {
			http.Error(w, "data view denied", dataViewStatus)
			return
		}
		fmt.Fprint(w, `{"data_view":{"id":"dv-check","title":"logs-endpoint.events.*"}}`)
	})
	mux.HandleFunc("/_data_stream/_stats", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"data_streams":[
			{"data_stream":"logs-endpoint.events.process-default","store_size_bytes":1048576,"maximum_timestamp":%d},
			{"data_stream":"logs-unused-default","store_size_bytes":5368709120,"maximum_timestamp":%d}
		]}`, now.Add(-5*time.Minute).UnixMilli(), now.Add(-time.Minute).UnixMilli())
	})
	mux.HandleFunc("/_cat/indices", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `[
			{"index":".ds-logs-endpoint.events.process-default-2026.07.01-000001","docs.count":"5000","store.size":"1048576"},
			{"index":".ds-logs-unused-default-2026.07.01-000001","docs.count":"100000","store.size":"5368709120"},
			{"index":"winlogbeat-2026.07","docs.count":"42","store.size":"123456"},
			{"index":".internal-index","docs.count":"1","store.size":"10"}
		]`)
	})
	mux.HandleFunc("/winlogbeat-2026.07/_search", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"aggregations":{"latest":{"value":%d}}}`, now.Add(-26*time.Hour).UnixMilli())
	})
	mux.HandleFunc("/logs-endpoint.events.process-default/_search", func(w http.ResponseWriter, r *http.Request) {
		eventTime := now.Add(-2 * time.Minute).UnixMilli()
		ingestTime := now.Add(-90 * time.Second).UnixMilli()
		fmt.Fprintf(w, `{"hits":{"hits":[{"fields":{"@timestamp":[%d],"event.ingested":[%d]}}]}}`, eventTime, ingestTime)
	})
	mux.HandleFunc("/logs-endpoint.events.process-default/_field_caps", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"fields":{"@timestamp":{"date":{}},"event.action":{"keyword":{}}}}`)
	})
	mux.HandleFunc("/logs-unused-default/_field_caps", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"fields":{"@timestamp":{"date":{}},"unused.field":{"keyword":{}}}}`)
	})
	mux.HandleFunc("/winlogbeat-2026.07/_field_caps", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"fields":{"@timestamp":{"date":{}},"event.code":{"long":{}},"host.name":{"keyword":{}}}}`)
	})
	mux.HandleFunc("/_resolve/index/", func(w http.ResponseWriter, r *http.Request) {
		if resolveStatus != 0 {
			http.Error(w, "resolution denied", resolveStatus)
			return
		}
		expression := strings.TrimPrefix(r.URL.Path, "/_resolve/index/")
		switch expression {
		case "logs-endpoint.events.*":
			fmt.Fprint(w, `{"data_streams":[{"name":"logs-endpoint.events.process-default","backing_indices":[".ds-logs-endpoint.events.process-default-2026.07.01-000001"]}]}`)
		case "winlogbeat-*":
			fmt.Fprint(w, `{"indices":[{"name":"winlogbeat-2026.07"}]}`)
		default:
			fmt.Fprint(w, `{}`)
		}
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprintf(w, `{"version":{"number":%q}}`, version)
	})
	return httptest.NewServer(mux)
}

func TestScanEndToEnd(t *testing.T) {
	srv := fixtureServer(t)
	defer srv.Close()
	t.Setenv("DEADAIR_API_KEY", "testkey")

	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"scan", "--es-url", srv.URL, "--kibana-url", srv.URL, "--json"}, &stdout, &stderr)
	if code != report.ExitFindings {
		t.Fatalf("exit = %d, want %d; stderr: %s", code, report.ExitFindings, stderr.String())
	}

	var r report.Report
	if err := json.Unmarshal(stdout.Bytes(), &r); err != nil {
		t.Fatalf("output is not a JSON report: %v", err)
	}
	s := r.Summary
	if s.Sources != 3 || s.DeadDetections != 2 || s.UnmappedRules != 1 || s.UnusedSources != 0 ||
		s.UnusedTelemetryAssessment != report.UnusedAssessmentUnavailable {
		t.Errorf("summary = %+v", s)
	}
	if r.SchemaVersion != report.ReportSchemaVersion || r.Producer.Name != "deadair" || r.BackendMetadata.ObservedVersion != "9.4.4" {
		t.Errorf("report contract metadata = schema %q producer %+v backend %+v", r.SchemaVersion, r.Producer, r.BackendMetadata)
	}
	if len(r.InputResolutions) != 5 || s.InputResolution.Resolved != 3 || s.InputResolution.Empty != 1 || s.InputResolution.Unsupported != 1 {
		t.Errorf("input resolution evidence = %d / %+v", len(r.InputResolutions), s.InputResolution)
	}
	reasons := map[string]string{}
	for _, d := range r.DeadDetections {
		reasons[d.Name] = d.Reason
	}
	if reasons["Winlog suspicious logon"] != "starved" {
		t.Errorf("winlog rule reason = %q, want starved (its only source went stale)", reasons["Winlog suspicious logon"])
	}
	if reasons["Legacy netflow rule"] != "disconnected" {
		t.Errorf("netflow rule reason = %q, want disconnected", reasons["Legacy netflow rule"])
	}
	for _, src := range r.Sources {
		if src.Name == "logs-endpoint.events.process-default" && src.Consumers != 1 {
			t.Errorf("consumers = %d, want 1 (disabled rules must not count)", src.Consumers)
		}
	}
}

func TestScanSavedReportHint(t *testing.T) {
	srv := fixtureServer(t)
	defer srv.Close()
	t.Setenv("DEADAIR_API_KEY", "testkey")
	t.Setenv("DEADAIR_REDACT_KEY_FILE", "")
	for _, mode := range []string{"human", "json", "redacted", "no-file"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "saved-report.json")
			args := []string{"scan", "--es-url", srv.URL, "--kibana-url", srv.URL}
			if mode != "no-file" {
				args = append(args, "--json-out", path)
			}
			if mode == "json" {
				args = append(args, "--json")
			} else if mode == "redacted" {
				args = append(args, "--redact")
			}
			var out, errors bytes.Buffer
			if code := cli.Run(args, &out, &errors); code != report.ExitFindings {
				t.Fatalf("exit %d: %s", code, errors.String())
			}
			if mode == "human" {
				if !strings.Contains(out.String(), path) {
					t.Fatal("saved report filename missing")
				}
				var inspectOut bytes.Buffer
				if code := cli.Run([]string{"inspect", "--", path}, &inspectOut, &errors); code != 0 {
					t.Fatalf("suggested inspection failed: %d, %s", code, errors.String())
				}
			} else if strings.Contains(out.String(), "Inspect:") || strings.Contains(out.String(), "Saved JSON:") {
				t.Fatal("unexpected saved report hint")
			}
			if mode == "json" && !json.Valid(out.Bytes()) {
				t.Fatal("human text in JSON output")
			}
		})
	}
}

func TestScanRedacted(t *testing.T) {
	srv := fixtureServer(t)
	defer srv.Close()
	t.Setenv("DEADAIR_API_KEY", "testkey")
	keyPath := filepath.Join(t.TempDir(), "redaction.key")
	if err := os.WriteFile(keyPath, []byte(strings.Repeat("r", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEADAIR_REDACT_KEY_FILE", keyPath)

	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"scan", "--es-url", srv.URL, "--kibana-url", srv.URL, "--json", "--redact"}, &stdout, &stderr)
	if code != report.ExitFindings {
		t.Fatalf("exit = %d; stderr: %s", code, stderr.String())
	}
	for _, leak := range []string{"winlogbeat", "netflow", "Endpoint", "logs-"} {
		if strings.Contains(stdout.String(), leak) {
			t.Errorf("redacted output leaks %q", leak)
		}
	}
	var first report.Report
	if err := json.Unmarshal(stdout.Bytes(), &first); err != nil {
		t.Fatal(err)
	}
	if first.Redaction == nil || first.Redaction.Algorithm != "hmac-sha256" || first.Redaction.KeyID == "" {
		t.Fatalf("redaction metadata = %+v", first.Redaction)
	}

	stdout.Reset()
	stderr.Reset()
	// A supplied key is itself an instruction to redact; silently ignoring it
	// would leave a report unprotected.
	code = cli.Run([]string{"scan", "--es-url", srv.URL, "--kibana-url", srv.URL, "--json"}, &stdout, &stderr)
	if code != report.ExitFindings {
		t.Fatalf("second exit = %d; stderr: %s", code, stderr.String())
	}
	var second report.Report
	if err := json.Unmarshal(stdout.Bytes(), &second); err != nil {
		t.Fatal(err)
	}
	if first.Redaction.KeyID != second.Redaction.KeyID || first.Sources[0].Name != second.Sources[0].Name {
		t.Fatal("caller-held redaction key did not preserve cross-run pseudonyms")
	}
}

func TestRedactedScanSanitizesFatalBackendError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/detection_engine/rules/_find" {
			http.Error(w, "private-index-name from backend", http.StatusInternalServerError)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	t.Setenv("DEADAIR_API_KEY", "testkey")
	keyPath := filepath.Join(t.TempDir(), "redaction.key")
	if err := os.WriteFile(keyPath, []byte(strings.Repeat("r", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEADAIR_REDACT_KEY_FILE", keyPath)

	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"scan", "--es-url", srv.URL, "--kibana-url", srv.URL, "--json"}, &stdout, &stderr)
	if code != report.ExitError {
		t.Fatalf("exit = %d, want %d", code, report.ExitError)
	}
	if got := stderr.String(); !strings.Contains(got, "scan failed: scan failed") ||
		strings.Contains(got, "private-index-name") || strings.Contains(got, "/api/detection_engine/") {
		t.Fatalf("redacted fatal error was not sanitized: %s", got)
	}
}

func TestRedactedConfigurationErrorsDoNotLeakDetails(t *testing.T) {
	tmp := t.TempDir()
	duplicateFleet := filepath.Join(tmp, "duplicate.json")
	if err := os.WriteFile(duplicateFleet, []byte(`{"instances":[
		{"name":"private-client-alpha","backend":"elastic","es_url":"http://es.invalid","kibana_url":"http://kibana.invalid"},
		{"name":"private-client-alpha","backend":"elastic","es_url":"http://es.invalid","kibana_url":"http://kibana.invalid"}
	]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	secretFleet := filepath.Join(tmp, "secret.json")
	if err := os.WriteFile(secretFleet, []byte(`{"instances":[{
		"name":"private-client-beta","backend":"elastic","es_url":"http://es.invalid","kibana_url":"http://kibana.invalid",
		"api_key_file":"/restricted/private-client-beta.key"
	}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(tmp, "policy.json")
	if err := os.WriteFile(policyPath, []byte(`{"version":1,"gate_classes":["dead-detection"],"private_source":"secret-*"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		args  []string
		leaks []string
	}{
		{name: "duplicate tenant", args: []string{"scan", "--redact", "--fleet", duplicateFleet}, leaks: []string{"private-client-alpha", "duplicate instance"}},
		{name: "secret file", args: []string{"scan", "--redact", "--fleet", secretFleet}, leaks: []string{"private-client-beta", "/restricted/private-client-beta.key"}},
		{name: "policy detail", args: []string{"scan", "--redact", "--policy", policyPath}, leaks: []string{"private_source", "secret-*", policyPath}},
		{name: "redaction key path", args: []string{"scan", "--redact-key-file", "/restricted/private-client-gamma.key"}, leaks: []string{"/restricted/private-client-gamma.key"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := cli.Run(tt.args, &stdout, &stderr); code != report.ExitError {
				t.Fatalf("exit = %d, want %d", code, report.ExitError)
			}
			for _, leak := range tt.leaks {
				if strings.Contains(stderr.String(), leak) {
					t.Fatalf("protected error leaked %q: %s", leak, stderr.String())
				}
			}
		})
	}
}

func TestScanSourceFilters(t *testing.T) {
	srv := fixtureServer(t)
	defer srv.Close()
	t.Setenv("DEADAIR_API_KEY", "testkey")

	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{
		"scan",
		"--es-url", srv.URL,
		"--kibana-url", srv.URL,
		"--json",
		"--include", "logs-*",
		"--include", "winlogbeat-*",
		"--exclude", "logs-unused-*",
	}, &stdout, &stderr)
	if code != report.ExitFindings {
		t.Fatalf("exit = %d, want %d; stderr: %s", code, report.ExitFindings, stderr.String())
	}

	var r report.Report
	if err := json.Unmarshal(stdout.Bytes(), &r); err != nil {
		t.Fatalf("output is not a JSON report: %v", err)
	}
	if r.Summary.Sources != 2 {
		t.Fatalf("sources = %d, want 2: %+v", r.Summary.Sources, r.Sources)
	}
	if r.Summary.UnusedSources != 0 || len(r.UnusedTelemetry) != 0 {
		t.Fatalf("unused telemetry = %d/%d, want none: %+v", r.Summary.UnusedSources, len(r.UnusedTelemetry), r.UnusedTelemetry)
	}
	for _, src := range r.Sources {
		if strings.HasPrefix(src.Name, "logs-unused-") {
			t.Fatalf("excluded source leaked into sources: %+v", src)
		}
	}
	if strings.Contains(stdout.String(), "logs-unused-default") {
		t.Fatalf("excluded source leaked into JSON report:\n%s", stdout.String())
	}
}

func TestScanFilterCannotManufactureDeadDetections(t *testing.T) {
	srv := fixtureServer(t)
	defer srv.Close()
	t.Setenv("DEADAIR_API_KEY", "testkey")

	// Excluding a HEALTHY consumed source must not turn its live rule into a
	// dead detection: filters scope the listing, never the verdicts.
	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{
		"scan", "--es-url", srv.URL, "--kibana-url", srv.URL, "--json",
		"--exclude", "logs-endpoint.*",
	}, &stdout, &stderr)
	if code != report.ExitFindings { // the genuinely dead rules still exist
		t.Fatalf("exit = %d, want %d; stderr: %s", code, report.ExitFindings, stderr.String())
	}
	var r report.Report
	if err := json.Unmarshal(stdout.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	reasons := map[string]string{}
	for _, d := range r.DeadDetections {
		reasons[d.Name] = d.Reason
	}
	if _, dead := reasons["Endpoint process anomaly"]; dead {
		t.Fatal("excluding a healthy source manufactured a dead detection")
	}
	if reasons["Winlog suspicious logon"] != "starved" || reasons["Legacy netflow rule"] != "disconnected" {
		t.Fatalf("real dead detections must survive filtering: %v", reasons)
	}
	for _, src := range r.Sources {
		if strings.HasPrefix(src.Name, "logs-endpoint.") {
			t.Fatalf("excluded source listed: %+v", src)
		}
	}
}

func TestScanStateCommitDeferredUntilRender(t *testing.T) {
	srv := fixtureServer(t)
	defer srv.Close()
	t.Setenv("DEADAIR_API_KEY", "testkey")

	statePath := filepath.Join(t.TempDir(), "state.json")
	badOut := filepath.Join(t.TempDir(), "no-such-dir", "report.json")
	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{
		"scan", "--es-url", srv.URL, "--kibana-url", srv.URL,
		"--state-file", statePath, "--out", badOut,
	}, &stdout, &stderr)
	if code != report.ExitError {
		t.Fatalf("exit = %d, want %d (render must fail)", code, report.ExitError)
	}
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatalf("state committed despite failed render (stat err=%v) — one-shot drift findings would be consumed", err)
	}
}

func TestScanStateVolumeAndHTML(t *testing.T) {
	srv := fixtureServer(t)
	defer srv.Close()
	t.Setenv("DEADAIR_API_KEY", "testkey")

	now := time.Now().UTC()
	bucket := fmt.Sprintf("%d:%02d", int(now.Weekday()), now.Hour())
	statePath := filepath.Join(t.TempDir(), "state.json")
	stateJSON := fmt.Sprintf(`{
  "version": 1,
  "sources": {
    "logs-endpoint.events.process-default": {
      "first_seen": %q,
      "last_seen": %q,
      "last_docs": 4999,
      "buckets": { %q: [100, 101, 99, 100] }
    }
  }
}`, now.Add(-48*time.Hour).Format(time.RFC3339), now.Add(-time.Hour).Format(time.RFC3339), bucket)
	if err := os.WriteFile(statePath, []byte(stateJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	htmlPath := filepath.Join(t.TempDir(), "report.html")

	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{
		"scan",
		"--es-url", srv.URL,
		"--kibana-url", srv.URL,
		"--json",
		"--state-file", statePath,
		"--volume-hysteresis", "1",
		"--html-out", htmlPath,
	}, &stdout, &stderr)
	if code != report.ExitFindings {
		t.Fatalf("exit = %d, want %d; stderr: %s", code, report.ExitFindings, stderr.String())
	}

	var r report.Report
	if err := json.Unmarshal(stdout.Bytes(), &r); err != nil {
		t.Fatalf("output is not a JSON report: %v", err)
	}
	if r.Summary.VolumeLowSources != 1 {
		t.Fatalf("volume low sources = %d, want 1: %+v", r.Summary.VolumeLowSources, r.Sources)
	}
	var found bool
	for _, src := range r.Sources {
		if src.Name == "logs-endpoint.events.process-default" {
			found = true
			if src.Volume == nil || src.Volume.Status != "low" || src.Volume.ZScore == nil {
				t.Fatalf("volume result = %+v, want low with z-score", src.Volume)
			}
		}
	}
	if !found {
		t.Fatal("endpoint source missing from report")
	}
	data, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "deadair report") {
		t.Fatalf("html report was not written:\n%s", data)
	}
}

func TestScanDowntimeFile(t *testing.T) {
	srv := fixtureServer(t)
	defer srv.Close()
	t.Setenv("DEADAIR_API_KEY", "testkey")

	now := time.Now().UTC()
	start := now.Add(-time.Hour).Format("15:04")
	end := now.Add(time.Hour).Format("15:04")
	downtimePath := filepath.Join(t.TempDir(), "downtime.json")
	body := fmt.Sprintf(`{"windows":[{"name":"patch","sources":["winlogbeat-*"],"start":%q,"end":%q,"timezone":"UTC"}]}`, start, end)
	if err := os.WriteFile(downtimePath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{
		"scan",
		"--es-url", srv.URL,
		"--kibana-url", srv.URL,
		"--json",
		"--downtime-file", downtimePath,
	}, &stdout, &stderr)
	if code != report.ExitFindings {
		t.Fatalf("exit = %d, want %d; stderr: %s", code, report.ExitFindings, stderr.String())
	}

	var r report.Report
	if err := json.Unmarshal(stdout.Bytes(), &r); err != nil {
		t.Fatalf("output is not a JSON report: %v", err)
	}
	for _, src := range r.Sources {
		if src.Name == "winlogbeat-2026.07" {
			if src.Status != "maintenance" || !src.ExpectedDowntime {
				t.Fatalf("winlog status = %+v, want maintenance", src)
			}
			return
		}
	}
	t.Fatal("winlog source missing from report")
}

func TestScanSchemaDrift(t *testing.T) {
	srv := fixtureServer(t)
	defer srv.Close()
	t.Setenv("DEADAIR_API_KEY", "testkey")

	now := time.Now().UTC()
	statePath := filepath.Join(t.TempDir(), "state.json")
	stateJSON := fmt.Sprintf(`{
  "version": 1,
  "sources": {
    "winlogbeat-2026.07": {
      "first_seen": %q,
      "last_seen": %q,
      "last_docs": 42,
      "schema": {
        "last_seen": %q,
        "fields": {
          "@timestamp": ["date"],
          "event.code": ["keyword"],
          "old.field": ["keyword"]
        }
      }
    }
  }
}`, now.Add(-48*time.Hour).Format(time.RFC3339), now.Add(-time.Hour).Format(time.RFC3339), now.Add(-time.Hour).Format(time.RFC3339))
	if err := os.WriteFile(statePath, []byte(stateJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{
		"scan",
		"--es-url", srv.URL,
		"--kibana-url", srv.URL,
		"--json",
		"--state-file", statePath,
		"--schema",
	}, &stdout, &stderr)
	if code != report.ExitFindings {
		t.Fatalf("exit = %d, want %d; stderr: %s", code, report.ExitFindings, stderr.String())
	}

	var r report.Report
	if err := json.Unmarshal(stdout.Bytes(), &r); err != nil {
		t.Fatalf("output is not a JSON report: %v", err)
	}
	if r.Summary.SchemaDriftSources != 1 {
		t.Fatalf("schema drift sources = %d, want 1: %+v", r.Summary.SchemaDriftSources, r.Sources)
	}
	for _, src := range r.Sources {
		if src.Name == "winlogbeat-2026.07" {
			if src.Schema == nil || src.Schema.Status != "drift" {
				t.Fatalf("schema = %+v, want drift", src.Schema)
			}
			if len(src.Schema.Added) != 1 || len(src.Schema.Removed) != 1 || len(src.Schema.TypeChanged) != 1 {
				t.Fatalf("schema changes = %+v", src.Schema)
			}
			return
		}
	}
	t.Fatal("winlog source missing from report")
}

func TestTune(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	stateJSON := `{
  "version": 1,
  "sources": {
    "logs-sensitive-default": {
      "buckets": {
        "1:10": [100, 110],
        "2:10": [90]
      }
    }
  }
}`
	if err := os.WriteFile(statePath, []byte(stateJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"tune", "--state-file", statePath, "--json", "--redact"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d; stderr: %s", code, stderr.String())
	}
	if strings.Contains(stdout.String(), "logs-sensitive") {
		t.Fatalf("redacted tune output leaks source name:\n%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), `"name": "src-`) {
		t.Fatalf("redacted tune output missing source digest:\n%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), `"total_samples": 3`) {
		t.Fatalf("tune output missing sample count:\n%s", stdout.String())
	}
}

func opensearchFixtureServer(t *testing.T) *httptest.Server {
	t.Helper()
	now := time.Now()
	mux := http.NewServeMux()
	mux.HandleFunc("/_plugins/_security_analytics/detectors/_search", func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "admin" || pass != "secret" {
			t.Errorf("basic auth = %q/%q/%v, want admin/secret/true", user, pass, ok)
		}
		fmt.Fprint(w, `{"hits":{"total":{"value":5},"hits":[
			{"_id":"det-live","_source":{"name":"OpenSearch live detector","enabled":true,
				"inputs":[{"detector_input":{"indices":["logs-os-*"]}}],
				"triggers":[{"severity":"4"}]}},
			{"_id":"det-stale","_source":{"name":"OpenSearch stale detector","enabled":true,
				"inputs":[{"detector_input":{"indices":["os-stale-*"]}}],
				"triggers":[{"severity":"2"}]}},
			{"_id":"det-disconnected","_source":{"name":"OpenSearch disconnected detector","enabled":true,
				"inputs":[{"detector_input":{"indices":["os-missing-*"]}}],
				"triggers":[{"severity":"3"}]}},
			{"_id":"det-unmapped","_source":{"name":"OpenSearch unmapped detector","enabled":true}},
			{"_id":"det-disabled","_source":{"name":"OpenSearch disabled detector","enabled":false,
				"inputs":[{"detector_input":{"indices":["logs-os-*"]}}],
				"triggers":[{"severity":"1"}]}}
		]}}`)
	})
	mux.HandleFunc("/_data_stream/_stats", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"data_streams":[
			{"data_stream":"logs-os-default","store_size_bytes":1048576,"maximum_timestamp":%d},
			{"data_stream":"logs-unused-default","store_size_bytes":2097152,"maximum_timestamp":%d}
		]}`, now.Add(-5*time.Minute).UnixMilli(), now.Add(-time.Minute).UnixMilli())
	})
	mux.HandleFunc("/_cat/indices", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `[
			{"index":".ds-logs-os-default-2026.07.01-000001","docs.count":"5000","store.size":"1048576"},
			{"index":".ds-logs-unused-default-2026.07.01-000001","docs.count":"100000","store.size":"2097152"},
			{"index":"os-stale-2026","docs.count":"42","store.size":"123456"},
			{"index":".opensearch-security","docs.count":"1","store.size":"10"}
		]`)
	})
	mux.HandleFunc("/os-stale-2026/_search", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"aggregations":{"latest":{"value":%d}}}`, now.Add(-26*time.Hour).UnixMilli())
	})
	mux.HandleFunc("/_resolve/index/", func(w http.ResponseWriter, r *http.Request) {
		expression := strings.TrimPrefix(r.URL.Path, "/_resolve/index/")
		switch expression {
		case "logs-os-*":
			fmt.Fprint(w, `{"data_streams":[{"name":"logs-os-default","backing_indices":[".ds-logs-os-default-2026.07.01-000001"]}]}`)
		case "os-stale-*":
			fmt.Fprint(w, `{"indices":[{"name":"os-stale-2026"}]}`)
		default:
			fmt.Fprint(w, `{}`)
		}
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, `{"version":{"number":"3.7.0"}}`)
	})
	return httptest.NewServer(mux)
}

func TestScanOpenSearchEndToEnd(t *testing.T) {
	srv := opensearchFixtureServer(t)
	defer srv.Close()
	t.Setenv("DEADAIR_OPENSEARCH_USERNAME", "admin")
	t.Setenv("DEADAIR_OPENSEARCH_PASSWORD", "secret")
	t.Setenv("DEADAIR_OPENSEARCH_API_KEY", "")

	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"scan", "--backend", "opensearch", "--opensearch-url", srv.URL, "--json", "--max-stale", "1h"}, &stdout, &stderr)
	if code != report.ExitFindings {
		t.Fatalf("exit = %d, want %d; stderr: %s", code, report.ExitFindings, stderr.String())
	}

	var r report.Report
	if err := json.Unmarshal(stdout.Bytes(), &r); err != nil {
		t.Fatalf("output is not a JSON report: %v", err)
	}
	if r.Backend != "opensearch" {
		t.Errorf("backend = %q, want opensearch", r.Backend)
	}
	if r.BackendMetadata.ObservedVersion != "3.7.0" {
		t.Errorf("observed OpenSearch version = %q", r.BackendMetadata.ObservedVersion)
	}
	s := r.Summary
	if s.Sources != 3 || s.DeadDetections != 2 || s.UnmappedRules != 1 || s.UnusedSources != 0 ||
		s.UnusedTelemetryAssessment != report.UnusedAssessmentUnavailable {
		t.Errorf("summary = %+v", s)
	}
	reasons := map[string]string{}
	for _, d := range r.DeadDetections {
		reasons[d.Name] = d.Reason
	}
	if reasons["OpenSearch stale detector"] != "starved" {
		t.Errorf("stale detector reason = %q, want starved", reasons["OpenSearch stale detector"])
	}
	if reasons["OpenSearch disconnected detector"] != "disconnected" {
		t.Errorf("disconnected detector reason = %q, want disconnected", reasons["OpenSearch disconnected detector"])
	}
}

func TestScanCandidateRule(t *testing.T) {
	srv := fixtureServer(t)
	defer srv.Close()
	t.Setenv("DEADAIR_API_KEY", "testkey")

	dir := t.TempDir()
	dead := filepath.Join(dir, "dead.json")
	os.WriteFile(dead, []byte(`{"rule_id":"cand-1","name":"Candidate dead","severity":"high","index":["netflow-*"],"from":"now-6m","interval":"5m"}`), 0o600)
	live := filepath.Join(dir, "live.json")
	os.WriteFile(live, []byte(`{"rule_id":"cand-2","name":"Candidate live","severity":"high","index":["logs-endpoint.events.*"],"from":"now-6m","interval":"5m"}`), 0o600)

	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"scan", "--es-url", srv.URL, "--kibana-url", srv.URL, "--json", "--rule", dead}, &stdout, &stderr)
	if code != report.ExitFindings {
		t.Fatalf("dead candidate exit = %d, want 1; stderr: %s", code, stderr.String())
	}
	var r report.Report
	if err := json.Unmarshal(stdout.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if r.Summary.Rules != 1 || len(r.DeadDetections) != 1 || r.DeadDetections[0].Name != "Candidate dead" {
		t.Fatalf("candidate report = %+v", r.Summary)
	}
	if len(r.UnusedTelemetry) != 0 {
		t.Fatal("candidate mode must not report unused telemetry")
	}

	// A viable candidate passes even though an unrelated source is stale.
	stdout.Reset()
	stderr.Reset()
	code = cli.Run([]string{"scan", "--es-url", srv.URL, "--kibana-url", srv.URL, "--json", "--rule", live}, &stdout, &stderr)
	if code != report.ExitHealthy {
		t.Fatalf("live candidate exit = %d, want 0; stderr: %s\nstdout: %s", code, stderr.String(), stdout.String())
	}

	esql := filepath.Join(dir, "esql.json")
	os.WriteFile(esql, []byte(`{"rule_id":"cand-3","name":"Candidate ES|QL","severity":"high","type":"esql","query":"FROM logs-*"}`), 0o600)
	stdout.Reset()
	stderr.Reset()
	code = cli.Run([]string{"scan", "--es-url", srv.URL, "--kibana-url", srv.URL, "--json", "--rule", esql}, &stdout, &stderr)
	if code != report.ExitFindings {
		t.Fatalf("ES|QL candidate exit = %d, want 1; stderr: %s\nstdout: %s", code, stderr.String(), stdout.String())
	}
	var esqlReport report.Report
	if err := json.Unmarshal(stdout.Bytes(), &esqlReport); err != nil || esqlReport.Summary.DeadDetections != 1 ||
		len(esqlReport.DeadDetections) != 1 || esqlReport.DeadDetections[0].Patterns[0] != "logs-*" {
		t.Fatalf("ES|QL candidate report = %+v / %+v, %v", esqlReport.Summary, esqlReport.DeadDetections, err)
	}
}

func TestScanOpenSearchCandidateDetector(t *testing.T) {
	srv := opensearchFixtureServer(t)
	defer srv.Close()
	t.Setenv("DEADAIR_OPENSEARCH_USERNAME", "admin")
	t.Setenv("DEADAIR_OPENSEARCH_PASSWORD", "secret")

	candidate := filepath.Join(t.TempDir(), "candidate.json")
	if err := os.WriteFile(candidate, []byte(`{
		"name":"OpenSearch candidate",
		"detector_type":"windows",
		"inputs":[{"detector_input":{"indices":["logs-os-*"]}}],
		"triggers":[{"severity":"2"}]
	}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{
		"scan", "--backend", "opensearch", "--opensearch-url", srv.URL,
		"--json", "--rule", candidate,
	}, &stdout, &stderr)
	if code != report.ExitHealthy {
		t.Fatalf("exit = %d, want 0; stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	var got report.Report
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Summary.Rules != 1 || got.Summary.DeadDetections != 0 || got.Summary.UnmappedRules != 0 ||
		len(got.InputResolutions) != 1 || got.InputResolutions[0].Expression != "logs-os-*" {
		t.Fatalf("candidate report = %+v / %+v", got.Summary, got.InputResolutions)
	}
}

func TestDiffCommand(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, r report.Report) string {
		data, _ := json.Marshal(r)
		p := filepath.Join(dir, name)
		os.WriteFile(p, data, 0o600)
		return p
	}
	older := write("old.json", report.Report{
		SchemaVersion: report.ReportSchemaVersion, Backend: "elastic", Instance: "prod", TargetID: "target-1",
		Scope:   report.ScanScope{Mode: "installed", ConfigurationID: "config-1"},
		Sources: []report.SourceHealth{{Name: "a", Status: "ok"}},
	})
	newer := write("new.json", report.Report{
		SchemaVersion: report.ReportSchemaVersion, Backend: "elastic", Instance: "prod", TargetID: "target-1",
		Scope:          report.ScanScope{Mode: "installed", ConfigurationID: "config-1"},
		Sources:        []report.SourceHealth{{Name: "a", Status: "stale"}},
		DeadDetections: []report.DeadDetection{{ID: "d1", Name: "Now dead", Severity: "high", Reason: "starved"}},
		Findings: []report.Finding{
			{ID: "dead-1", Class: report.FindingDead, RuleID: "d1", RuleName: "Now dead", Severity: "high", Reason: report.ReasonStarved},
			{ID: "source-1", Class: report.FindingSourceDegraded, Source: "a", Reason: "stale"},
		},
	})

	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"diff", older, newer}, &stdout, &stderr)
	if code != report.ExitFindings {
		t.Fatalf("diff exit = %d, want 1; stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Now dead — all matching sources stale or empty") ||
		!strings.Contains(stdout.String(), "DEGRADED a") || strings.Contains(stdout.String(), " — starved") {
		t.Fatalf("diff output:\n%s", stdout.String())
	}

	// Reverse direction is recovery only: exit 0.
	stdout.Reset()
	if code := cli.Run([]string{"diff", newer, older}, &stdout, &stderr); code != report.ExitHealthy {
		t.Fatalf("recovery diff exit = %d, want 0", code)
	}
}

func TestScanFleet(t *testing.T) {
	srv := fixtureServer(t)
	defer srv.Close()
	t.Setenv("DEADAIR_API_KEY", "testkey")

	// Two tenants pointing at the same fixture: identical findings, so the
	// rollup must report them as fleet-wide.
	cfg := filepath.Join(t.TempDir(), "fleet.json")
	os.WriteFile(cfg, []byte(fmt.Sprintf(`{"instances":[
		{"name":"acme-prod","backend":"elastic","es_url":%q,"kibana_url":%q,"api_key_env":"DEADAIR_API_KEY"},
		{"name":"beta-corp","backend":"elastic","es_url":%q,"kibana_url":%q,"api_key_env":"DEADAIR_API_KEY"}
	]}`, srv.URL, srv.URL, srv.URL, srv.URL)), 0o600)

	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"scan", "--fleet", cfg, "--json"}, &stdout, &stderr)
	if code != report.ExitFindings {
		t.Fatalf("fleet exit = %d, want 1; stderr: %s", code, stderr.String())
	}
	var f report.FleetReport
	if err := json.Unmarshal(stdout.Bytes(), &f); err != nil {
		t.Fatal(err)
	}
	if f.Summary.Instances != 2 || len(f.Instances) != 2 {
		t.Fatalf("instances = %+v", f.Summary)
	}
	if f.Instances[0].Instance != "acme-prod" || f.Instances[1].Instance != "beta-corp" {
		t.Fatalf("instance names = %q, %q", f.Instances[0].Instance, f.Instances[1].Instance)
	}
	found := false
	for _, ru := range f.Rollups {
		if ru.Name == "Winlog suspicious logon" && ru.DeadIn == 2 && ru.Of == 2 {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected 'dead in 2 of 2' rollup, got %+v", f.Rollups)
	}

	// The fixture contains an input-unsupported rule, so consumer coverage is
	// incomplete and the terminal summary must not present zero unused bytes as
	// a measured result.
	stdout.Reset()
	stderr.Reset()
	code = cli.Run([]string{"scan", "--fleet", cfg}, &stdout, &stderr)
	if code != report.ExitFindings {
		t.Fatalf("terminal fleet exit = %d, want 1; stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "unused not assessed") || strings.Contains(stdout.String(), "0 B unused") {
		t.Fatalf("terminal fleet summary misstates unused coverage:\n%s", stdout.String())
	}

	// Redacted fleet output leaks no tenant names.
	stdout.Reset()
	code = cli.Run([]string{"scan", "--fleet", cfg, "--json", "--redact"}, &stdout, &stderr)
	if code != report.ExitFindings {
		t.Fatalf("redacted fleet exit = %d; stderr: %s", code, stderr.String())
	}
	for _, leak := range []string{"acme-prod", "beta-corp", "winlogbeat"} {
		if strings.Contains(stdout.String(), leak) {
			t.Fatalf("redacted fleet leaks %q", leak)
		}
	}
}

func TestSetupCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := cli.Run([]string{"setup"}, &stdout, &stderr); code != 0 {
		t.Fatalf("setup exit = %d", code)
	}
	for _, want := range []string{"deadair setup elastic", "deadair setup opensearch", "deadair setup sentinel"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("setup output missing %q", want)
		}
	}
	if strings.Contains(stdout.String(), "DEADAIR_ES_URL") {
		t.Fatal("bare setup silently selected Elastic")
	}
	stdout.Reset()
	if code := cli.Run([]string{"setup", "elastic"}, &stdout, &stderr); code != 0 {
		t.Fatalf("setup elastic exit = %d", code)
	}
	for _, want := range []string{"deadair_monitor", "feature_siemV2.read", "feature_indexPatterns.read", "DEADAIR_ES_URL", "deadair scan"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("setup elastic output missing %q", want)
		}
	}
	if code := cli.Run([]string{"setup", "opensearch"}, &stdout, &stderr); code != 0 {
		t.Fatalf("setup opensearch exit = %d", code)
	}
	if code := cli.Run([]string{"setup", "splunk"}, &stdout, &stderr); code == 0 {
		t.Fatal("unknown backend must fail")
	}
}

func TestUnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := cli.Run([]string{"bogus"}, &stdout, &stderr); code != report.ExitError {
		t.Errorf("exit = %d, want %d", code, report.ExitError)
	}
	if !strings.Contains(stderr.String(), "unknown command") {
		t.Errorf("stderr = %q", stderr.String())
	}
}

func tlsFixture(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/detection_engine/rules/_find", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"page":1,"perPage":100,"total":0,"data":[]}`)
	})
	mux.HandleFunc("/_data_stream/_stats", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"data_streams":[]}`)
	})
	mux.HandleFunc("/_cat/indices", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `[]`) })
	srv := httptest.NewTLSServer(mux)
	certPath := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	os.WriteFile(certPath, pemBytes, 0o600)
	return srv, certPath
}

func TestScanTLS(t *testing.T) {
	srv, ca := tlsFixture(t)
	defer srv.Close()
	t.Setenv("DEADAIR_API_KEY", "k")

	var stdout, stderr bytes.Buffer
	if code := cli.Run([]string{"scan", "--es-url", srv.URL, "--kibana-url", srv.URL}, &stdout, &stderr); code != report.ExitError {
		t.Fatalf("untrusted cert must fail: exit %d", code)
	}
	if code := cli.Run([]string{"scan", "--es-url", srv.URL, "--kibana-url", srv.URL, "--ca-cert", ca}, &stdout, &stderr); code != report.ExitHealthy {
		t.Fatalf("--ca-cert scan exit = %d; stderr: %s", code, stderr.String())
	}
	stderr.Reset()
	if code := cli.Run([]string{"scan", "--es-url", srv.URL, "--kibana-url", srv.URL, "--insecure-skip-verify"}, &stdout, &stderr); code != report.ExitHealthy {
		t.Fatalf("--insecure-skip-verify exit = %d", code)
	}
	if !strings.Contains(stderr.String(), "verification disabled") {
		t.Error("insecure mode must warn")
	}
}

func TestScanKibanaSpace(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/s/soc/api/detection_engine/rules/_find", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"page":1,"perPage":100,"total":1,"data":[{"id":"a","name":"Space rule","enabled":true,"severity":"low","index":["logs-*"]}]}`)
	})
	mux.HandleFunc("/_data_stream/_stats", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"data_streams":[]}`)
	})
	mux.HandleFunc("/_cat/indices", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `[]`) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	t.Setenv("DEADAIR_API_KEY", "k")

	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"scan", "--es-url", srv.URL, "--kibana-url", srv.URL, "--kibana-space", "soc", "--json"}, &stdout, &stderr)
	if code == report.ExitError {
		t.Fatalf("space scan failed: %s", stderr.String())
	}
	var r report.Report
	json.Unmarshal(stdout.Bytes(), &r)
	if r.Summary.Rules != 1 {
		t.Fatalf("rules = %d, want 1 (space-scoped inventory)", r.Summary.Rules)
	}
}

func TestBareInvocationShowsHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := cli.Run(nil, &stdout, &stderr); code != 0 {
		t.Fatalf("bare invocation exit = %d, want 0", code)
	}
	for _, want := range []string{"COMMANDS", "GET STARTED", "deadair setup <backend>", "deadair check", "deadair scan", "https://github.com/alephnull-sh/deadair/blob/main/docs/usage.md"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("help missing %q", want)
		}
	}
	for _, unwanted := range []string{"deadair demo", "Guides: docs/usage.md"} {
		if strings.Contains(stdout.String(), unwanted) {
			t.Errorf("help contains stale guidance %q:\n%s", unwanted, stdout.String())
		}
	}
}

func TestCommandHelpIsSuccessfulAndFocused(t *testing.T) {
	for _, command := range []string{"scan", "check", "diff", "inspect", "serve", "tune", "setup"} {
		t.Run(command, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := cli.Run([]string{command, "-h"}, &stdout, &stderr); code != report.ExitHealthy {
				t.Fatalf("%s -h exit = %d, want 0\nstderr: %s", command, code, stderr.String())
			}
			if !strings.Contains(stderr.String(), "Usage: deadair "+command) {
				t.Fatalf("%s help is missing its usage line:\n%s", command, stderr.String())
			}
		})
	}

	var stdout, stderr bytes.Buffer
	if code := cli.Run([]string{"check", "-h"}, &stdout, &stderr); code != report.ExitHealthy {
		t.Fatalf("check -h exit = %d", code)
	}
	for _, scanOnly := range []string{"--max-stale", "--state-file", "--schema", "--volume-warmup", "--include"} {
		if strings.Contains(stderr.String(), scanOnly) {
			t.Errorf("check help exposes scan-only option %q:\n%s", scanOnly, stderr.String())
		}
	}
}

func TestCommandHelpLinksMatchUsageHeadings(t *testing.T) {
	usage, err := os.ReadFile(filepath.Join("..", "..", "docs", "usage.md"))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		command string
		anchor  string
		heading string
	}{
		{command: "diff", anchor: "#gate-detection-changes", heading: "## Gate detection changes"},
		{command: "tune", anchor: "#add-history-based-checks", heading: "## Add history-based checks"},
		{command: "serve", anchor: "#run-the-exporter", heading: "## Run the exporter"},
	}
	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := cli.Run([]string{tt.command, "-h"}, &stdout, &stderr); code != report.ExitHealthy {
				t.Fatalf("%s -h exit = %d", tt.command, code)
			}
			if !strings.Contains(stderr.String(), tt.anchor) {
				t.Errorf("%s help missing %s:\n%s", tt.command, tt.anchor, stderr.String())
			}
			if !bytes.Contains(usage, []byte(tt.heading)) {
				t.Errorf("usage guide missing heading %q", tt.heading)
			}
		})
	}
}

func TestEmbeddedDemoCommandWasRemoved(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := cli.Run([]string{"demo"}, &stdout, &stderr); code != report.ExitError {
		t.Fatalf("demo exit = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), `unknown command "demo"`) {
		t.Fatalf("demo command was not rejected clearly:\n%s", stderr.String())
	}
}

func TestScanRejectsIncompatibleOptionsBeforeConfiguration(t *testing.T) {
	fleetFile := filepath.Join(t.TempDir(), "fleet.json")
	if err := os.WriteFile(fleetFile, []byte(`{"instances":[
		{
			"name":"elastic-lab",
			"backend":"elastic",
			"es_url":"https://127.0.0.1:1",
			"kibana_url":"https://127.0.0.1:2",
			"api_key_file":"missing-key"
		},
		{
			"name":"os-lab",
			"backend":"opensearch",
			"opensearch_url":"https://127.0.0.1:3",
			"api_key_file":"missing-key"
		}
	]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "schema without state",
			args: []string{"scan", "--schema"},
			want: "--schema requires --state-file",
		},
		{
			name: "fleet HTML before reading fleet",
			args: []string{"scan", "--fleet", "does-not-exist.json", "--html-out", "report.html"},
			want: "--html-out is available only for single-instance scans",
		},
		{
			name: "mixed-backend candidate fleet before credentials",
			args: []string{"scan", "--fleet", fleetFile, "--rule", "candidate.json"},
			want: "--rule cannot scan a mixed-backend fleet",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := cli.Run(tt.args, &stdout, &stderr); code != report.ExitError {
				t.Fatalf("exit = %d, want 2", code)
			}
			if !strings.Contains(stderr.String(), tt.want) {
				t.Fatalf("stderr missing %q:\n%s", tt.want, stderr.String())
			}
			if strings.Contains(stderr.String(), "no deployment configured") ||
				strings.Contains(stderr.String(), "reading fleet file") ||
				strings.Contains(stderr.String(), "missing-key") {
				t.Fatalf("validation ran after configuration work:\n%s", stderr.String())
			}
		})
	}
}

func TestUnknownCommandSuggests(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := cli.Run([]string{"scna"}, &stdout, &stderr); code != report.ExitError {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(stderr.String(), `did you mean "scan"`) {
		t.Errorf("no suggestion for scna:\n%s", stderr.String())
	}
}

func TestCheck(t *testing.T) {
	srv := fixtureServer(t)
	defer srv.Close()
	t.Setenv("DEADAIR_API_KEY", "testkey")

	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"check", "--es-url", srv.URL, "--kibana-url", srv.URL}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("check exit = %d; stderr: %s\nstdout: %s", code, stderr.String(), stdout.String())
	}
	for _, want := range []string{"READY", "backend version 9.4.4", "detection rules readable (5 rules)", "source inventory readable (3 sources)", "source schemas readable", "native input resolution readable (missing sources can be proved)", "next: deadair scan"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("check output missing %q:\n%s", want, stdout.String())
		}
	}
	if !strings.HasPrefix(stdout.String(), "READY\n") || strings.Contains(stdout.String(), "capabilities (") {
		t.Errorf("check does not lead with a concise status:\n%s", stdout.String())
	}

	stdout.Reset()
	code = cli.Run([]string{"check", "--es-url", "http://127.0.0.1:1", "--kibana-url", "http://127.0.0.1:1", "--timeout", "2s"}, &stdout, &stderr)
	if code != report.ExitError {
		t.Fatalf("unreachable check exit = %d, want 2", code)
	}
	if !strings.Contains(stdout.String(), "not readable") {
		t.Errorf("failure output:\n%s", stdout.String())
	}

	unsupported := fixtureServerOptions(t, "7.17.0", 0)
	defer unsupported.Close()
	stdout.Reset()
	stderr.Reset()
	code = cli.Run([]string{"check", "--es-url", unsupported.URL, "--kibana-url", unsupported.URL}, &stdout, &stderr)
	if code != report.ExitError || !strings.Contains(stdout.String(), "backend version 7.17.0 unsupported") ||
		!strings.HasPrefix(stdout.String(), "BLOCKED\n") || strings.Contains(stdout.String(), "next:") {
		t.Fatalf("unsupported version check exit = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}

	denied := fixtureServerOptions(t, "9.4.4", http.StatusForbidden)
	defer denied.Close()
	stdout.Reset()
	stderr.Reset()
	code = cli.Run([]string{"check", "--es-url", denied.URL, "--kibana-url", denied.URL}, &stdout, &stderr)
	if code != report.ExitError || !strings.Contains(stdout.String(), "native input resolution is unavailable") ||
		!strings.HasPrefix(stdout.String(), "BLOCKED\n") {
		t.Fatalf("resolution capability check exit = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}

	dataViewDenied := fixtureServerCapabilities(t, "9.4.4", 0, http.StatusForbidden)
	defer dataViewDenied.Close()
	stdout.Reset()
	stderr.Reset()
	code = cli.Run([]string{"check", "--es-url", dataViewDenied.URL, "--kibana-url", dataViewDenied.URL}, &stdout, &stderr)
	if code != report.ExitError || !strings.Contains(stdout.String(), "rule input discovery unavailable for 1 enabled rule") ||
		!strings.HasPrefix(stdout.String(), "BLOCKED\n") || strings.Contains(stdout.String(), "next:") {
		t.Fatalf("data-view capability check exit = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}

	bestEffort := fixtureServerOptions(t, "9.5.0", 0)
	defer bestEffort.Close()
	stdout.Reset()
	stderr.Reset()
	code = cli.Run([]string{"check", "--es-url", bestEffort.URL, "--kibana-url", bestEffort.URL}, &stdout, &stderr)
	if code != report.ExitHealthy || !strings.HasPrefix(stdout.String(), "READY WITH LIMITS\n") ||
		!strings.Contains(stdout.String(), "best-effort") || !strings.Contains(stdout.String(), "next: deadair scan") {
		t.Fatalf("best-effort version check exit = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
}

func TestCheckFleet(t *testing.T) {
	srv := fixtureServer(t)
	defer srv.Close()
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "api-key")
	if err := os.WriteFile(keyFile, []byte("testkey"), 0600); err != nil {
		t.Fatal(err)
	}
	fleetFile := filepath.Join(dir, "fleet.json")
	fleet := fmt.Sprintf(`{"instances":[
		{"name":"tenant-a","backend":"elastic","es_url":%q,"kibana_url":%q,"api_key_file":%q},
		{"name":"tenant-b","backend":"elastic","es_url":%q,"kibana_url":%q,"api_key_file":%q}
	]}`, srv.URL, srv.URL, keyFile, srv.URL, srv.URL, keyFile)
	if err := os.WriteFile(fleetFile, []byte(fleet), 0600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"check", "--fleet", fleetFile}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("check --fleet exit = %d; stderr: %s\nstdout: %s", code, stderr.String(), stdout.String())
	}
	for _, want := range []string{"READY", "tenant-a (elastic)", "tenant-b (elastic)", "next: deadair scan --fleet " + fleetFile} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("check --fleet output missing %q:\n%s", want, stdout.String())
		}
	}
}
