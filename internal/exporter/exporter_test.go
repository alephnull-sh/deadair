package exporter

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alephnull-sh/deadair/internal/report"
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
		{Name: "bounded-src", Status: "stale", AgeSeconds: 86400, AgeLowerBound: true},
	}
	r.Summary.DeadDetections = 2
	r.Summary.ImpairedDetections = 3
	r.Summary.UnusedBytes = 42
	r.Summary.UnusedTelemetryAssessment = report.UnusedAssessmentComplete
	r.Summary.InputResolution = report.InputResolutionSummary{Resolved: 4, Empty: 2, Unavailable: 1, Incompatible: 3}
	s.Update(fleetOf(r))

	body = get(t, ts.URL+"/metrics")
	for _, want := range []string{
		"deadair_up 1",
		`deadair_instance_up{instance="acme-prod"} 1`,
		`deadair_sources{instance="acme-prod",status="ok"} 1`,
		`deadair_sources{instance="acme-prod",status="stale"} 2`,
		`deadair_detections_dead{instance="acme-prod"} 2`,
		`deadair_detections_impaired{instance="acme-prod"} 3`,
		`deadair_unused_telemetry_bytes{instance="acme-prod"} 42`,
		`deadair_unused_telemetry_assessed{instance="acme-prod"} 1`,
		`deadair_input_resolutions{instance="acme-prod",status="resolved"} 4`,
		`deadair_input_resolutions{instance="acme-prod",status="unavailable"} 1`,
		`deadair_input_resolutions{instance="acme-prod",status="incompatible"} 3`,
		`deadair_source_freshness_seconds{instance="acme-prod",source="quoted\"src"} 12.5`,
		`deadair_source_consumers{instance="acme-prod",source="stale-src"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}
	for _, help := range []string{
		"# HELP deadair_input_resolutions Backend-native rule input resolution evidence by outcome.",
		"# HELP deadair_source_freshness_seconds Seconds since the exact last event observed in the source; lower-bound ages are omitted.",
	} {
		if !strings.Contains(body, help) {
			t.Errorf("missing HELP line %q in:\n%s", help, body)
		}
	}
	if strings.Contains(body, `deadair_source_freshness_seconds{instance="acme-prod",source="bounded-src"}`) {
		t.Errorf("lower-bound source age was exported as exact:\n%s", body)
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

func TestMetricsFleetFailureRetainsPerInstanceLastKnownGoodData(t *testing.T) {
	s := &Server{}
	firstAt := time.Unix(1000, 0)
	firstA := &report.Report{GeneratedAt: firstAt, Instance: "tenant-a"}
	firstA.Summary.DeadDetections = 1
	firstB := &report.Report{GeneratedAt: firstAt, Instance: "tenant-b"}
	firstB.Summary.DeadDetections = 7
	firstB.Sources = []report.SourceHealth{{Name: "retained-source", Status: "stale", AgeSeconds: 42}}
	first := fleetOf(firstA, firstB)
	first.GeneratedAt = firstAt
	s.Update(first)

	failedAt := time.Unix(2000, 0)
	currentA := &report.Report{GeneratedAt: failedAt, Instance: "tenant-a"}
	currentA.Summary.DeadDetections = 2
	failed := report.BuildFleet([]*report.Report{currentA}, []report.InstanceError{{Instance: "tenant-b", Error: "connection refused"}})
	failed.GeneratedAt = failedAt
	s.Update(failed)

	recorder := httptest.NewRecorder()
	s.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := recorder.Body.String()
	for _, want := range []string{
		"deadair_up 0",
		"deadair_last_scan_timestamp_seconds 2000",
		`deadair_instance_up{instance="tenant-a"} 1`,
		`deadair_instance_up{instance="tenant-b"} 0`,
		`deadair_detections_dead{instance="tenant-a"} 2`,
		`deadair_detections_dead{instance="tenant-b"} 7`,
		`deadair_source_freshness_seconds{instance="tenant-b",source="retained-source"} 42`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("failed-cycle metrics missing %q:\n%s", want, body)
		}
	}
	if strings.Count(body, `deadair_instance_up{instance="tenant-b"}`) != 1 {
		t.Fatalf("failed instance emitted more than one up series:\n%s", body)
	}
}

func TestMetricsFirstCycleFailureDoesNotFabricateInstanceData(t *testing.T) {
	s := &Server{}
	failed := report.BuildFleet(nil, []report.InstanceError{{Instance: "tenant-a", Error: "unauthorized"}})
	failed.GeneratedAt = time.Unix(3000, 0)
	s.Update(failed)

	recorder := httptest.NewRecorder()
	s.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := recorder.Body.String()
	for _, want := range []string{
		"deadair_up 0",
		"deadair_last_scan_timestamp_seconds 3000",
		`deadair_instance_up{instance="tenant-a"} 0`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("first failure missing %q:\n%s", want, body)
		}
	}
	for _, fabricated := range []string{
		`deadair_sources{instance="tenant-a"`,
		`deadair_detections_dead{instance="tenant-a"}`,
		`deadair_source_freshness_seconds{instance="tenant-a"`,
	} {
		if strings.Contains(body, fabricated) {
			t.Errorf("first failure fabricated historical data %q:\n%s", fabricated, body)
		}
	}
}

func TestMetricsRecoveryReplacesRetainedReport(t *testing.T) {
	s := &Server{}
	old := &report.Report{Instance: "tenant-a"}
	old.Summary.DeadDetections = 9
	s.Update(fleetOf(old))
	s.Update(report.BuildFleet(nil, []report.InstanceError{{Instance: "tenant-a", Error: "timeout"}}))

	recovered := &report.Report{Instance: "tenant-a"}
	recovered.Summary.DeadDetections = 1
	s.Update(fleetOf(recovered))

	recorder := httptest.NewRecorder()
	s.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := recorder.Body.String()
	if !strings.Contains(body, "deadair_up 1") || !strings.Contains(body, `deadair_instance_up{instance="tenant-a"} 1`) {
		t.Fatalf("recovered instance did not return to healthy:\n%s", body)
	}
	if !strings.Contains(body, `deadair_detections_dead{instance="tenant-a"} 1`) ||
		strings.Contains(body, `deadair_detections_dead{instance="tenant-a"} 9`) {
		t.Fatalf("recovery did not replace retained report:\n%s", body)
	}
}

func TestMetricsConcurrentReadsAndUpdates(t *testing.T) {
	s := &Server{}
	handler := s.Handler()
	var wg sync.WaitGroup
	for writer := 0; writer < 4; writer++ {
		wg.Add(1)
		go func(writer int) {
			defer wg.Done()
			for cycle := 0; cycle < 250; cycle++ {
				r := &report.Report{Instance: fmt.Sprintf("tenant-%d", writer)}
				r.Summary.DeadDetections = cycle
				if cycle%3 == 0 {
					s.Update(report.BuildFleet(nil, []report.InstanceError{{Instance: r.Instance, Error: "temporary"}}))
				} else {
					s.Update(fleetOf(r))
				}
			}
		}(writer)
	}
	for reader := 0; reader < 8; reader++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				recorder := httptest.NewRecorder()
				handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
				if !strings.Contains(recorder.Body.String(), "deadair_up ") {
					t.Errorf("concurrent scrape omitted fleet health")
					return
				}
			}
		}()
	}
	wg.Wait()
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
