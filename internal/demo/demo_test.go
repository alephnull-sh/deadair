package demo

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/Big-Comfy/deadair/internal/report"
)

func TestBuildIsDeterministicAndShowsEachVerdict(t *testing.T) {
	first, err := Build()
	if err != nil {
		t.Fatal(err)
	}
	second, err := Build()
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Fatal("successive embedded reports differ")
	}

	wantTime := time.Date(2026, time.July, 15, 12, 0, 0, 0, time.UTC)
	if !first.GeneratedAt.Equal(wantTime) {
		t.Errorf("generated_at = %s, want %s", first.GeneratedAt, wantTime)
	}
	if got, want := first.Summary, (report.Summary{
		Rules:                     6,
		EnabledRules:              5,
		Sources:                   5,
		HealthySources:            4,
		DegradedSources:           1,
		DeadDetections:            2,
		ImpairedDetections:        2,
		UnusedSources:             1,
		UnusedBytes:               2147483648,
		InputResolution:           report.InputResolutionSummary{Resolved: 5, Empty: 1},
		UnusedTelemetryAssessment: report.UnusedAssessmentComplete,
	}); got != want {
		t.Errorf("summary = %+v, want %+v", got, want)
	}

	dead := make(map[string]report.DeadDetection, len(first.DeadDetections))
	for _, finding := range first.DeadDetections {
		dead[finding.ID] = finding
	}
	if got := dead["rule-disconnected"].Reason; got != report.ReasonDisconnected {
		t.Errorf("disconnected reason = %q", got)
	}
	if got := dead["rule-starved"].Reason; got != report.ReasonStarved {
		t.Errorf("starved reason = %q", got)
	}

	impaired := make(map[string]report.ImpairedDetection, len(first.ImpairedDetections))
	for _, finding := range first.ImpairedDetections {
		impaired[finding.ID] = finding
	}
	missing := impaired["rule-missing-fields"]
	if len(missing.Reasons) != 1 || missing.Reasons[0] != report.ReasonMissingFields ||
		len(missing.MissingFields) != 1 || missing.MissingFields[0] != "device.trust.score" {
		t.Errorf("missing-fields finding = %+v", missing)
	}
	lag := impaired["rule-lag-blind-window"]
	if len(lag.Reasons) != 1 || lag.Reasons[0] != report.ReasonLagBlindWindow ||
		len(lag.LagSources) != 1 || lag.LagSources[0] != "logs-batch-default" {
		t.Errorf("lag finding = %+v", lag)
	}

	if len(first.UnusedTelemetry) != 1 || first.UnusedTelemetry[0].Name != "logs-cloud-archive-default" ||
		first.UnusedTelemetry[0].DisabledConsumers != 1 {
		t.Errorf("unused telemetry = %+v", first.UnusedTelemetry)
	}
	if len(first.InputResolutions) != 6 {
		t.Fatalf("input resolutions = %d, want 6", len(first.InputResolutions))
	}

	statuses := make(map[string]string, len(first.Sources))
	for _, source := range first.Sources {
		statuses[source.Name] = source.Status
	}
	if statuses["logs-endpoint-default"] != "ok" || statuses["logs-legacy-audit-default"] != "stale" {
		t.Errorf("source statuses = %v", statuses)
	}
}
