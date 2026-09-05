package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/alephnull-sh/deadair/internal/backend"
	"github.com/alephnull-sh/deadair/internal/graph"
	"github.com/alephnull-sh/deadair/internal/health"
)

func TestSourceInvestigationKeepsRuleClocksAndSeverity(t *testing.T) {
	now := time.Now().UTC()
	rules := []backend.Rule{{ID: "scheduled", Name: "Old event data", Enabled: true, Severity: "critical", Patterns: []string{"CommonSecurityLog"}},
		{ID: "nrt", Name: "New arrivals", Enabled: true, Severity: "high", TimestampOverride: "ingestion_time()", Patterns: []string{"CommonSecurityLog"}},
		{ID: "disabled", Enabled: false, Patterns: []string{"CommonSecurityLog"}}}
	clock := func(last time.Time) backend.FreshnessEvidence {
		return backend.FreshnessEvidence{Status: backend.EvidenceAssessed, ObservedAt: now, LastEvent: last, Window: 24 * time.Hour}
	}
	sources := []backend.Source{{Name: "CommonSecurityLog", Docs: -1, Freshness: backend.FreshnessEvidence{Status: backend.EvidenceAssessed, Clocks: map[backend.FreshnessBasis]backend.FreshnessEvidence{
		backend.FreshnessEventTime: clock(now.Add(-time.Hour)), backend.FreshnessIngestionTime: clock(now.Add(-time.Minute)),
	}}}}
	r := Build("sentinel", graph.Build(rules, sources), health.Check{MaxStale: 30 * time.Minute, Now: func() time.Time { return now }})
	if len(r.DeadDetections) != 1 || r.DeadDetections[0].RuleID != "scheduled" {
		t.Fatalf("clock-specific verdicts: %+v", r.DeadDetections)
	}
	if r.Sources[0].Status != "stale" {
		t.Fatalf("source summary: %+v", r.Sources)
	}
	impact := r.SourceImpacts[0]
	if len(impact.Freshness) != 2 || len(impact.Detections) != 2 || impact.Detections[0].RuleID != "scheduled" || impact.Detections[1].Status != "consumes_source" {
		t.Fatalf("investigation: %+v", impact)
	}
	if impact.Freshness[0].FreshnessStatus != "stale" || impact.Freshness[1].FreshnessStatus != "ok" {
		t.Fatalf("clock observations: %+v", impact.Freshness)
	}
	// Losing one clock does not erase the other one's positive observation.
	sources[0].Freshness.Clocks[backend.FreshnessEventTime] = backend.FreshnessEvidence{Status: backend.EvidenceUnavailable}
	r = Build("sentinel", graph.Build(rules, sources), health.Check{MaxStale: 30 * time.Minute, Now: func() time.Time { return now }})
	if len(r.DeadDetections) != 0 {
		t.Fatalf("unavailable event clock became dead: %+v", r.DeadDetections)
	}
}

func TestEmptySourceInventoryStaysEmptyInInvestigation(t *testing.T) {
	r := Build("elastic", graph.Build(nil, []backend.Source{{Name: "logs-empty", Docs: 0}}), health.Check{MaxStale: time.Hour})
	if len(r.SourceImpacts) != 1 || r.SourceImpacts[0].Freshness[0].FreshnessStatus != "empty" {
		t.Fatalf("empty inventory became unavailable freshness: %+v", r.SourceImpacts)
	}
}

func TestSourceInvestigationRetainsHistoryWithoutSharingRedactedFields(t *testing.T) {
	r := &Report{Sources: []SourceHealth{{Name: "endpoint-events",
		Volume: &VolumeHealth{Status: "low", RatePerHour: 10, BaselineMean: 1000, SampleCount: 12},
		Schema: &SchemaHealth{Status: "drift", Added: []string{"process.args"}, Removed: []string{"process.command_line"}, TypeChanged: []FieldTypeChange{{Name: "process.pid", Before: []string{"keyword"}, After: []string{"long"}}}},
	}}}
	g := graph.Build(nil, []backend.Source{{Name: "endpoint-events", Docs: 100, LastEvent: time.Now()}})
	r.SourceImpacts = buildSourceImpacts(r, g, BuildOptions{Check: health.Check{MaxStale: time.Hour}})
	impact := r.SourceImpacts[0]
	if impact.Volume == nil || impact.Volume.RatePerHour != 10 || impact.Schema == nil || len(impact.Schema.Removed) != 1 {
		t.Fatalf("history missing from source view: %+v", impact)
	}
	var out bytes.Buffer
	if err := htmlReport.Execute(&out, r); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Schema changed", "process.command_line", "process.pid", "1000"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("source card omitted %q", want)
		}
	}
	r.Redact()
	original, copied := r.Sources[0].Schema, r.SourceImpacts[0].Schema
	if original.Added[0] != copied.Added[0] || original.Removed[0] != copied.Removed[0] || original.TypeChanged[0].Name != copied.TypeChanged[0].Name {
		t.Fatal("shared field slices were redacted twice, breaking joins")
	}
	if original.Removed[0] == "process.command_line" {
		t.Fatal("schema field was not redacted")
	}
}

func TestHTMLInvestigationUsesSpecificStatusAndSectionLinks(t *testing.T) {
	r := &Report{Backend: "elastic", SourceImpacts: []SourceImpact{{Source: "endpoint-process-events-legacy", Status: "ok", FirstCheck: "Compare the mapping.", MissingFields: []string{"process.command_line"}, Detections: []SourceConsumer{{Name: "PowerShell from legacy endpoints", Severity: "high"}}}}}
	var out bytes.Buffer
	if err := htmlReport.Execute(&out, r); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`aria-label="Report sections"`, `href="#sources-heading"`, "Missing fields", "1 enabled detection reads this source"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestInvestigationRedactionKeepsJoinsAndRemovesLinks(t *testing.T) {
	r := &Report{SourceImpacts: []SourceImpact{{Source: "private-table", Owner: "private-team", Runbook: "https://private.example/runbook", URL: "https://private.example/source", Detections: []SourceConsumer{{RuleID: "private-rule", BackendObjectID: "private-object", Name: "private-name", URL: "https://private.example/rule"}}}},
		Producers: []ProducerHealth{{ID: "private-feed", Source: "private-table", Owner: "private-team", Runbook: "https://private.example/runbook", ConfirmedDetections: []SourceConsumer{{RuleID: "private-rule", BackendObjectID: "private-object", Name: "private-name"}}}}}
	r.Redact()
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "private-") || strings.Contains(string(data), "private.example") {
		t.Fatalf("private identifier survived: %s", data)
	}
	if r.SourceImpacts[0].Source != r.Producers[0].Source || r.SourceImpacts[0].Detections[0].RuleID != r.Producers[0].ConfirmedDetections[0].RuleID {
		t.Fatal("redaction broke investigation joins")
	}
}
