package exporter

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Big-Comfy/deadair/internal/report"
)

func get(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func fleetOf(rs ...*report.Report) *report.FleetReport {
	return report.BuildFleet(rs, nil)
}

func TestMetrics(t *testing.T) {
	s := &Server{}
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	body := get(t, ts.URL+"/metrics")
	if !strings.Contains(body, "deadair_up 0") {
		t.Errorf("before first scan, want deadair_up 0:\n%s", body)
	}

	r := &report.Report{GeneratedAt: time.Unix(1000, 0), Instance: "acme-prod"}
	r.Sources = []report.SourceHealth{
		{Name: `quoted"src`, Status: "ok", AgeSeconds: 12.5, Consumers: 3},
		{Name: "stale-src", Status: "stale", AgeSeconds: 100000, Consumers: 1},
	}
	r.Summary.DeadDetections = 2
	r.Summary.ImpairedDetections = 3
	r.Summary.UnusedBytes = 42
	r.Summary.UnusedTelemetryAssessment = report.UnusedAssessmentComplete
	r.Summary.InputResolution = report.InputResolutionSummary{Resolved: 4, Empty: 2, Unavailable: 1}
	s.Update(fleetOf(r))

	body = get(t, ts.URL+"/metrics")
	for _, want := range []string{
		"deadair_up 1",
		`deadair_instance_up{instance="acme-prod"} 1`,
		`deadair_sources{instance="acme-prod",status="ok"} 1`,
		`deadair_sources{instance="acme-prod",status="stale"} 1`,
		`deadair_detections_dead{instance="acme-prod"} 2`,
		`deadair_detections_impaired{instance="acme-prod"} 3`,
		`deadair_unused_telemetry_bytes{instance="acme-prod"} 42`,
		`deadair_unused_telemetry_assessed{instance="acme-prod"} 1`,
		`deadair_input_resolutions{instance="acme-prod",status="resolved"} 4`,
		`deadair_input_resolutions{instance="acme-prod",status="unavailable"} 1`,
		`deadair_source_freshness_seconds{instance="acme-prod",source="quoted\"src"} 12.5`,
		`deadair_source_consumers{instance="acme-prod",source="stale-src"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}

	// A failed cycle keeps the last snapshot but flips up to 0.
	s.Update(nil)
	body = get(t, ts.URL+"/metrics")
	if !strings.Contains(body, "deadair_up 0") {
		t.Error("deadair_up should be 0 after a failed cycle")
	}
	if !strings.Contains(body, `deadair_sources{instance="acme-prod",status="ok"} 1`) {
		t.Error("last-known-good snapshot should be retained")
	}
}

func TestMetricsFleetInstanceFailure(t *testing.T) {
	s := &Server{}
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	ok := &report.Report{GeneratedAt: time.Unix(1000, 0), Instance: "tenant-a"}
	f := report.BuildFleet([]*report.Report{ok}, []report.InstanceError{{Instance: "tenant-b", Error: "connection refused"}})
	s.Update(f)

	body := get(t, ts.URL+"/metrics")
	if !strings.Contains(body, "deadair_up 0") {
		t.Error("a failed instance must flip fleet-wide deadair_up to 0")
	}
	if !strings.Contains(body, `deadair_instance_up{instance="tenant-a"} 1`) ||
		!strings.Contains(body, `deadair_instance_up{instance="tenant-b"} 0`) {
		t.Errorf("per-instance up gauges wrong:\n%s", body)
	}
}

func TestMetricsMaintenanceFreshnessEmitted(t *testing.T) {
	s := &Server{}
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	r := &report.Report{GeneratedAt: time.Unix(1000, 0), Instance: "elastic"}
	r.Sources = []report.SourceHealth{{Name: "maint-src", Status: "maintenance", AgeSeconds: 4200}}
	s.Update(fleetOf(r))

	body := get(t, ts.URL+"/metrics")
	if !strings.Contains(body, `deadair_source_freshness_seconds{instance="elastic",source="maint-src"} 4200`) {
		t.Errorf("maintenance source must stay in the freshness series:\n%s", body)
	}
}

func TestMetricsRedactedLabelsLeakNoNames(t *testing.T) {
	s := &Server{}
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	r := &report.Report{GeneratedAt: time.Unix(1000, 0), Instance: "client-acme"}
	r.Sources = []report.SourceHealth{
		{Name: "logs-endpoint.events.process-default", Status: "ok", AgeSeconds: 12.5, Consumers: 3},
		{Name: "winlogbeat-2026.07", Status: "stale", AgeSeconds: 100000, Consumers: 1},
	}
	f := fleetOf(r)
	f.Redact()
	s.Update(f)

	body := get(t, ts.URL+"/metrics")
	// Instance names are MSSP client identities: they must redact too.
	for _, leak := range []string{"logs-endpoint", "winlogbeat", "process-default", "client-acme"} {
		if strings.Contains(body, leak) {
			t.Fatalf("redacted metrics leak %q:\n%s", leak, body)
		}
	}
	if !strings.Contains(body, `source="src-`) || !strings.Contains(body, `instance="ten-`) {
		t.Fatalf("redacted metrics should retain stable labels:\n%s", body)
	}
}
