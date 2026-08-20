package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/alephnull-sh/deadair/internal/backend"
	"github.com/alephnull-sh/deadair/internal/graph"
	"github.com/alephnull-sh/deadair/internal/health"
	redactpkg "github.com/alephnull-sh/deadair/internal/redact"
	"github.com/alephnull-sh/deadair/internal/state"
)

func fixtureReport(t *testing.T) *Report {
	t.Helper()
	now := time.Now()
	rules := []backend.Rule{
		{ID: "r-live", Name: "Live rule", Enabled: true, Severity: "high", Patterns: []string{"logs-live-*"}},
		{ID: "r-starved", Name: "Starved rule", Enabled: true, Severity: "critical", Patterns: []string{"logs-stale-*"}},
		{ID: "r-disconnected", Name: "Disconnected rule", Enabled: true, Severity: "medium", Patterns: []string{"netflow-*"}},
		{ID: "r-unmapped", Name: "ML rule", Enabled: true, Severity: "low"},
		{ID: "r-disabled", Name: "Disabled rule", Enabled: false, Severity: "high", Patterns: []string{"logs-live-*", "logs-shelfware-*"}},
		{ID: "r-uncertain", Name: "Unknown-fed rule", Enabled: true, Severity: "high", Patterns: []string{"mystery-*"}},
	}
	sources := []backend.Source{
		{Name: "logs-live-default", Docs: 100, SizeBytes: 10, LastEvent: now.Add(-time.Minute)},
		{Name: "logs-stale-default", Docs: 100, SizeBytes: 20, LastEvent: now.Add(-2 * time.Hour)},
		{Name: "logs-unused-default", Docs: 100, SizeBytes: 999, LastEvent: now.Add(-time.Minute)},
		// read only by a disabled rule: unused for the cost story, with the
		// disabled reference surfaced as context
		{Name: "logs-shelfware-default", Docs: 100, SizeBytes: 500, LastEvent: now.Add(-time.Minute)},
		{Name: "mystery-default", Docs: 100, SizeBytes: 5}, // freshness unknown
	}
	g := graph.Build(rules, sources)
	return Build("elastic", g, health.Check{MaxStale: 30 * time.Minute})
}

func TestBuildClassification(t *testing.T) {
	r := fixtureReport(t)
	s := r.Summary

	if s.Rules != 6 || s.EnabledRules != 5 {
		t.Errorf("rule counts = %d/%d, want 6/5", s.Rules, s.EnabledRules)
	}
	if s.Sources != 5 || s.HealthySources != 3 || s.DegradedSources != 1 {
		t.Errorf("source counts = %+v", s)
	}
	if s.DeadDetections != 2 {
		t.Fatalf("dead = %d, want 2: %+v", s.DeadDetections, r.DeadDetections)
	}
	// critical sorts first
	if r.DeadDetections[0].Name != "Starved rule" || r.DeadDetections[0].Reason != "starved" {
		t.Errorf("first dead = %+v", r.DeadDetections[0])
	}
	if r.DeadDetections[1].Name != "Disconnected rule" || r.DeadDetections[1].Reason != "disconnected" {
		t.Errorf("second dead = %+v", r.DeadDetections[1])
	}
	for _, d := range r.DeadDetections {
		if d.Name == "Unknown-fed rule" {
			t.Error("a source with unknown freshness must keep its rule alive")
		}
	}
	if s.UnmappedRules != 1 || r.UnmappedRules[0].Name != "ML rule" {
		t.Errorf("unmapped = %+v", r.UnmappedRules)
	}
	if s.UnusedSources != 2 || s.UnusedBytes != 1499 {
		t.Fatalf("unused = %+v (bytes %d), want 2 sources / 1499 bytes", r.UnusedTelemetry, s.UnusedBytes)
	}
	if s.UnusedTelemetryAssessment != UnusedAssessmentLegacy {
		t.Fatalf("unused assessment = %q, want legacy", s.UnusedTelemetryAssessment)
	}
	if r.UnusedTelemetry[0].Name != "logs-unused-default" || r.UnusedTelemetry[0].DisabledConsumers != 0 {
		t.Errorf("largest unused = %+v, want logs-unused-default with no disabled consumers", r.UnusedTelemetry[0])
	}
	// A source read only by a disabled rule is unused (nothing enabled reads
	// it) — the disabled reference is context, not consumption.
	if r.UnusedTelemetry[1].Name != "logs-shelfware-default" || r.UnusedTelemetry[1].DisabledConsumers != 1 {
		t.Errorf("shelfware unused = %+v, want logs-shelfware-default with 1 disabled consumer", r.UnusedTelemetry[1])
	}
	for _, src := range r.Sources {
		if src.Name == "logs-live-default" && src.Consumers != 1 {
			t.Errorf("consumers = %d, want 1 (disabled rules don't count)", src.Consumers)
		}
	}
	if r.ExitCode() != ExitFindings {
		t.Errorf("exit = %d, want %d", r.ExitCode(), ExitFindings)
	}
}

func TestImpairments(t *testing.T) {
	now := time.Now()
	lag := 30 * time.Minute
	rules := []backend.Rule{
		{ID: "r-fields", Name: "MissingFields", Enabled: true, Severity: "medium", Patterns: []string{"healthy-*"}, RequiredFields: []string{"process.name", "custom.gone"}},
		{ID: "r-lag", Name: "Lagged", Enabled: true, Severity: "low", Patterns: []string{"laggy-*"}, Lookback: 10 * time.Minute, Interval: 5 * time.Minute},
		// broad rule reads one laggy source and one healthy one; the finding
		// must attribute lag to the laggy source only, not the whole rule.
		{ID: "r-broad", Name: "Broad", Enabled: true, Severity: "high", Patterns: []string{"*-1"}, Lookback: 10 * time.Minute, Interval: 5 * time.Minute},
		{ID: "r-ok", Name: "Fine", Enabled: true, Severity: "low", Patterns: []string{"healthy-*"}, RequiredFields: []string{"process.name"}, Lookback: 6 * time.Minute, Interval: 5 * time.Minute},
	}
	sources := []backend.Source{
		{Name: "healthy-1", Docs: 10, LastEvent: now},
		{Name: "laggy-1", Docs: 10, LastEvent: now, IngestLag: backend.IngestLagEvidence{
			Status: backend.EvidenceAssessed, Method: "paired-recent-events", SampleCount: 100, P95: lag, Max: lag,
		}},
	}
	g := graph.Build(rules, sources)
	r := BuildWithOptions("elastic", g, BuildOptions{
		Check:        health.Check{MaxStale: time.Hour},
		SourceFields: map[string]map[string]bool{"healthy-1": {"process.name": true}},
	})

	byID := map[string]ImpairedDetection{}
	for _, d := range r.ImpairedDetections {
		byID[d.ID] = d
	}
	if len(byID) != 3 {
		t.Fatalf("impaired = %+v, want r-fields, r-lag, r-broad", byID)
	}
	if d := byID["r-fields"]; len(d.MissingFields) != 1 || d.MissingFields[0] != "custom.gone" {
		t.Errorf("missing fields = %+v", d)
	}
	if d := byID["r-lag"]; len(d.Reasons) != 1 || d.Reasons[0] != ReasonLagBlindWindow ||
		d.MaxLagSeconds != lag.Seconds() || len(d.LagSources) != 1 || d.LagSources[0] != "laggy-1" {
		t.Errorf("lag = %+v", d)
	}
	// The broad rule is impaired, but only via the laggy source — the healthy
	// one it also reads must not appear in LagSources.
	if d := byID["r-broad"]; len(d.LagSources) != 1 || d.LagSources[0] != "laggy-1" {
		t.Errorf("broad rule lag attribution = %+v, want [laggy-1] only", d.LagSources)
	}
	if _, ok := byID["r-ok"]; ok {
		t.Error("r-ok reads only the healthy source and must not be impaired")
	}
	if r.Summary.ImpairedDetections != 3 || r.ExitCode() != ExitFindings {
		t.Errorf("summary/exit = %d/%d", r.Summary.ImpairedDetections, r.ExitCode())
	}
	if r.CandidateExitCode() != ExitFindings {
		t.Errorf("candidate exit = %d, want findings", r.CandidateExitCode())
	}
	r.UnmappedRules = []RuleRef{{ID: "unassessed"}}
	r.Summary.UnmappedRules = 1
	if r.CandidateExitCode() != ExitError {
		t.Errorf("unassessed candidate exit = %d, want error", r.CandidateExitCode())
	}

	// Redacted impaired output must leak neither rule, field, nor source names.
	r.Redact()
	data, _ := json.Marshal(r)
	for _, leak := range []string{"custom.gone", "Lagged", "laggy-1"} {
		if strings.Contains(string(data), leak) {
			t.Errorf("redacted report leaks %q", leak)
		}
	}
}

// TestLagCheckSkipsIngestTimeRules pins the fix for the lag check's one
// false-positive class: a rule that windows on ingest time (or any non-
// @timestamp field) cannot be blinded by ingest lag, so it must not be flagged
// even when its source lags well past the margin. The @timestamp rule is the
// control that proves the setup would otherwise fire.
func TestLagCheckSkipsIngestTimeRules(t *testing.T) {
	now := time.Now()
	lag := 30 * time.Minute // far past the 5m margin (lookback 10m - interval 5m)
	rules := []backend.Rule{
		{ID: "evt", Name: "EventTime", Enabled: true, Severity: "low", Patterns: []string{"laggy-*"}, Lookback: 10 * time.Minute, Interval: 5 * time.Minute},
		{ID: "ing", Name: "IngestTime", Enabled: true, Severity: "low", Patterns: []string{"laggy-*"}, Lookback: 10 * time.Minute, Interval: 5 * time.Minute, TimestampOverride: "event.ingested"},
		{ID: "oth", Name: "OtherField", Enabled: true, Severity: "low", Patterns: []string{"laggy-*"}, Lookback: 10 * time.Minute, Interval: 5 * time.Minute, TimestampOverride: "custom.time"},
	}
	sources := []backend.Source{{Name: "laggy-1", Docs: 10, LastEvent: now, IngestLag: backend.IngestLagEvidence{
		Status: backend.EvidenceAssessed, Method: "paired-recent-events", SampleCount: 100, P95: lag, Max: lag,
	}}}
	g := graph.Build(rules, sources)
	r := BuildWithOptions("elastic", g, BuildOptions{Check: health.Check{MaxStale: time.Hour}})

	byID := map[string]ImpairedDetection{}
	for _, d := range r.ImpairedDetections {
		byID[d.ID] = d
	}
	// Control: the @timestamp-windowed rule is genuinely exposed and must fire.
	if d, ok := byID["evt"]; !ok || len(d.LagSources) != 1 || d.LagSources[0] != "laggy-1" {
		t.Errorf("event-time rule = %+v, want laggy-1 flagged", byID["evt"])
	}
	// A rule windowing on ingest time catches late events as they arrive.
	if d, ok := byID["ing"]; ok {
		t.Errorf("ingest-time (event.ingested) rule must not be impaired, got %+v", d)
	}
	// An override to any other field is not what the lag metric describes, so
	// stay quiet rather than guess.
	if d, ok := byID["oth"]; ok {
		t.Errorf("non-@timestamp override rule must not be impaired, got %+v", d)
	}
}

func TestLagFindingRequiresAssessedPairedEvidence(t *testing.T) {
	now := time.Now()
	rule := backend.Rule{
		ID: "lag", Name: "Lag", Enabled: true, Severity: "medium", Patterns: []string{"logs-*"},
		Lookback: 10 * time.Minute, Interval: 5 * time.Minute,
	}
	source := backend.Source{
		Name: "logs-a", Docs: 10, LastEvent: now,
		IngestLag: backend.IngestLagEvidence{
			Status: backend.EvidenceIncomplete, Method: "paired-recent-events",
			P95: 30 * time.Minute, Max: 30 * time.Minute, Detail: "no paired sample",
		},
	}
	r := BuildWithOptions("elastic", graph.Build([]backend.Rule{rule}, []backend.Source{source}), BuildOptions{
		Check: health.Check{MaxStale: time.Hour},
	})
	if len(r.ImpairedDetections) != 0 {
		t.Fatalf("incomplete lag evidence must never emit a finding: %+v", r.ImpairedDetections)
	}
	if len(r.Sources) != 1 || r.Sources[0].IngestLag == nil || r.Sources[0].IngestLag.Status != backend.EvidenceIncomplete {
		t.Fatalf("incomplete lag evidence must remain visible: %+v", r.Sources)
	}
}

func TestLagFindingAtZeroWindowMargin(t *testing.T) {
	now := time.Now()
	rule := backend.Rule{
		ID: "zero-margin", Name: "Zero margin", Enabled: true, Severity: "medium", Patterns: []string{"logs-*"},
		Lookback: 5 * time.Minute, Interval: 5 * time.Minute,
	}
	source := backend.Source{
		Name: "logs-a", Docs: 10, LastEvent: now,
		IngestLag: backend.IngestLagEvidence{
			Status: backend.EvidenceAssessed, Method: "paired-recent-events", SampleCount: 25,
			P95: time.Second, Max: 2 * time.Second,
		},
	}
	r := BuildWithOptions("elastic", graph.Build([]backend.Rule{rule}, []backend.Source{source}), BuildOptions{
		Check: health.Check{MaxStale: time.Hour},
	})
	if len(r.ImpairedDetections) != 1 || len(r.ImpairedDetections[0].Reasons) != 1 ||
		r.ImpairedDetections[0].Reasons[0] != ReasonLagBlindWindow {
		t.Fatalf("zero-margin rule = %+v, want lag-blind-window", r.ImpairedDetections)
	}
}

// TestMissingFieldsLimits pins the two honest limits of the schema-drift check.
// It inspects only a rule's DECLARED required_fields (it never parses the query
// body), and it stays silent when a source's schema could not be fetched instead
// of flagging every declared field as missing. The "declared" rule is the
// control that proves the same missing field IS flagged when the evidence exists.
func TestMissingFieldsLimits(t *testing.T) {
	now := time.Now()
	sources := []backend.Source{
		{Name: "mapped-1", Docs: 10, LastEvent: now},     // schema fetched below
		{Name: "unreadable-1", Docs: 10, LastEvent: now}, // schema fetch failed: absent from SourceFields
	}
	rules := []backend.Rule{
		// declares the missing field over a source with a fetched schema -> flagged
		{ID: "declared", Name: "Declared", Enabled: true, Severity: "medium", Patterns: []string{"mapped-*"}, RequiredFields: []string{"process.name", "process.command_line"}},
		// declares only fields that are present; drift in an undeclared field
		// (process.command_line, absent from the mapping) is invisible because
		// the query body is never parsed
		{ID: "undeclared", Name: "Undeclared", Enabled: true, Severity: "medium", Patterns: []string{"mapped-*"}, RequiredFields: []string{"process.name"}},
		// declares the same missing field, but over a source whose schema could
		// not be read -> stay silent rather than flag on no evidence
		{ID: "unreadable", Name: "Unreadable", Enabled: true, Severity: "medium", Patterns: []string{"unreadable-*"}, RequiredFields: []string{"process.command_line"}},
	}
	g := graph.Build(rules, sources)
	r := BuildWithOptions("elastic", g, BuildOptions{
		Check:        health.Check{MaxStale: time.Hour},
		SourceFields: map[string]map[string]bool{"mapped-1": {"process.name": true}},
	})

	byID := map[string]ImpairedDetection{}
	for _, d := range r.ImpairedDetections {
		byID[d.ID] = d
	}
	// Control: the declared field missing from a readable schema is flagged.
	if d, ok := byID["declared"]; !ok || len(d.MissingFields) != 1 || d.MissingFields[0] != "process.command_line" {
		t.Errorf("declared rule = %+v, want MissingFields [process.command_line]", byID["declared"])
	}
	// Limit 1: an undeclared drifted field is never checked (no query parsing).
	if d, ok := byID["undeclared"]; ok {
		t.Errorf("rule declaring only present fields must not be flagged, got %+v", d)
	}
	// Limit 2: an unreadable source schema stays silent, not flagged-as-missing.
	if d, ok := byID["unreadable"]; ok {
		t.Errorf("rule over an unreadable-schema source must not be flagged, got %+v", d)
	}
}

func TestRequiredFieldsAreAssessedPerConcreteSource(t *testing.T) {
	now := time.Now()
	rule := backend.Rule{
		ID: "field-rule", Name: "Field rule", Enabled: true, Severity: "medium",
		Patterns: []string{"logs-*"}, RequiredFields: []string{"process.name"},
	}
	sources := []backend.Source{
		{Name: "logs-a", Docs: 10, LastEvent: now},
		{Name: "logs-b", Docs: 10, LastEvent: now},
	}
	g := graph.Build([]backend.Rule{rule}, sources)
	complete := map[string]backend.FieldEvidence{
		"logs-a": {Status: backend.EvidenceAssessed, Fields: map[string]bool{"process.name": true}},
		"logs-b": {Status: backend.EvidenceAssessed, Fields: map[string]bool{}},
	}
	r := BuildWithOptions("elastic", g, BuildOptions{
		Check: health.Check{MaxStale: time.Hour}, FieldEvidence: complete,
	})
	if len(r.ImpairedDetections) != 1 || len(r.ImpairedDetections[0].MissingFields) != 1 {
		t.Fatalf("complete per-source evidence should report the known gap: %+v", r.ImpairedDetections)
	}
	if len(r.RequiredFieldEvidence) != 1 || len(r.RequiredFieldEvidence[0].Sources) != 2 ||
		len(r.RequiredFieldEvidence[0].Sources[1].Missing) != 1 {
		t.Fatalf("required-field evidence = %+v, want present/missing by source", r.RequiredFieldEvidence)
	}

	incomplete := map[string]backend.FieldEvidence{
		"logs-a": complete["logs-a"],
		"logs-b": {Status: backend.EvidenceIncomplete, Detail: "forbidden"},
	}
	r = BuildWithOptions("elastic", g, BuildOptions{
		Check: health.Check{MaxStale: time.Hour}, FieldEvidence: incomplete,
	})
	if len(r.ImpairedDetections) != 0 {
		t.Fatalf("an incomplete concrete-source read must suppress the conclusion: %+v", r.ImpairedDetections)
	}
	if got := r.RequiredFieldEvidence[0].Sources[1].Status; got != backend.EvidenceIncomplete {
		t.Fatalf("unreadable source status = %q, want incomplete", got)
	}

	r = BuildWithOptions("elastic", g, BuildOptions{
		Check: health.Check{MaxStale: time.Hour}, FieldEvidence: complete,
		Scope: map[string]bool{"logs-a": true},
	})
	if len(r.Sources) != 1 || r.Sources[0].Name != "logs-a" {
		t.Fatalf("partial scan scope did not limit source listing: %+v", r.Sources)
	}
	if len(r.ImpairedDetections) != 1 {
		t.Fatalf("listing scope hid an excluded source field gap: %+v", r.ImpairedDetections)
	}
	if got := r.RequiredFieldEvidence[0].Sources[1]; got.Status != backend.EvidenceAssessed || len(got.Missing) != 1 {
		t.Fatalf("excluded source evidence = %+v, want assessed missing field", got)
	}
}

func TestSkipUnused(t *testing.T) {
	g := graph.Build(nil, []backend.Source{{Name: "orphan", Docs: 1, LastEvent: time.Now()}})
	r := BuildWithOptions("elastic", g, BuildOptions{Check: health.Check{MaxStale: time.Hour}, SkipUnused: true})
	if len(r.UnusedTelemetry) != 0 || r.Summary.UnusedSources != 0 || r.Summary.UnusedBytes != 0 {
		t.Fatalf("unused must be suppressed in candidate mode: %+v", r.UnusedTelemetry)
	}
	if r.Summary.UnusedTelemetryAssessment != UnusedAssessmentNotApplicable {
		t.Fatalf("unused assessment = %q, want not-applicable", r.Summary.UnusedTelemetryAssessment)
	}
}

func TestUnusedTelemetryExcludesEmptySources(t *testing.T) {
	now := time.Now()
	sources := []backend.Source{
		{Name: "empty", Docs: 0, SizeBytes: 0},
		{Name: "empty-with-storage-overhead", Docs: 0, SizeBytes: 25},
		{Name: "ingested", Docs: 10, SizeBytes: 100, LastEvent: now},
		{Name: "docs-unknown", Docs: -1, SizeBytes: 50, LastEvent: now},
		{Name: "all-unknown", Docs: -1},
		{Name: "docs-unknown-with-storage-overhead", Docs: -1, SizeBytes: 75},
	}
	g := graph.BuildResolved(nil, sources, nil)
	r := BuildWithOptions("elastic", g, BuildOptions{Check: health.Check{MaxStale: time.Hour}})

	if r.Summary.UnusedTelemetryAssessment != UnusedAssessmentComplete {
		t.Fatalf("unused assessment = %q, want complete", r.Summary.UnusedTelemetryAssessment)
	}
	if r.Summary.UnusedSources != 2 || r.Summary.UnusedBytes != 150 {
		t.Fatalf("unused summary = %d sources / %d bytes, want 2 / 150: %+v",
			r.Summary.UnusedSources, r.Summary.UnusedBytes, r.UnusedTelemetry)
	}
	for _, source := range r.UnusedTelemetry {
		if source.Name == "empty" || source.Name == "empty-with-storage-overhead" ||
			source.Name == "all-unknown" || source.Name == "docs-unknown-with-storage-overhead" {
			t.Fatalf("source without positive telemetry evidence was reported unused: %s", source.Name)
		}
	}
}

func TestDiff(t *testing.T) {
	older := &Report{
		SchemaVersion: ReportSchemaVersion, Backend: "elastic", Instance: "prod", TargetID: "target-1",
		Scope:          ScanScope{Mode: "installed", ConfigurationID: "config-1"},
		Sources:        []SourceHealth{{Name: "a", Status: "ok"}, {Name: "b", Status: "stale"}},
		DeadDetections: []DeadDetection{{ID: "d1", Name: "Old dead", Reason: "disconnected"}},
		Findings: []Finding{
			{ID: "old-dead", Class: FindingDead, RuleID: "d1", RuleName: "Old dead", Reason: ReasonDisconnected},
			{ID: "old-source", Class: FindingSourceDegraded, Source: "b", Reason: "stale"},
		},
	}
	newer := &Report{
		SchemaVersion: ReportSchemaVersion, Backend: "elastic", Instance: "prod", TargetID: "target-1",
		Scope:              ScanScope{Mode: "installed", ConfigurationID: "config-1"},
		Assessments:        []RuntimeAssessment{{Name: AssessmentSourceResolution, Status: backend.EvidenceAssessed}},
		Sources:            []SourceHealth{{Name: "a", Status: "stale"}, {Name: "b", Status: "ok"}},
		DeadDetections:     []DeadDetection{{ID: "d2", Name: "New dead", Reason: "starved"}},
		ImpairedDetections: []ImpairedDetection{{ID: "i1", Name: "New impaired", Reasons: []string{ReasonMissingFields}, MissingFields: []string{"host.name"}}},
		InputResolutions: []backend.InputResolution{{
			RuleID: "d1", Status: backend.ResolutionResolved, ResolvedSources: []string{"b"},
		}},
		Findings: []Finding{
			{ID: "new-dead", Class: FindingDead, RuleID: "d2", RuleName: "New dead", Reason: ReasonStarved},
			{ID: "new-impaired", Class: FindingImpaired, RuleID: "i1", RuleName: "New impaired", Reason: ReasonMissingFields, Dependency: "host.name"},
			{ID: "new-source", Class: FindingSourceDegraded, Source: "a", Reason: "stale"},
		},
	}
	d, err := Diff(older, newer)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.NewlyDead) != 1 || d.NewlyDead[0].ID != "d2" {
		t.Errorf("newly dead = %+v", d.NewlyDead)
	}
	if len(d.RecoveredDead) != 1 || d.RecoveredDead[0].ID != "d1" {
		t.Errorf("recovered dead = %+v", d.RecoveredDead)
	}
	if len(d.NewlyImpaired) != 1 || len(d.NewlyDegraded) != 1 || d.NewlyDegraded[0].Name != "a" {
		t.Errorf("impaired/degraded = %+v / %+v", d.NewlyImpaired, d.NewlyDegraded)
	}
	if len(d.RecoveredSources) != 1 || d.RecoveredSources[0].Name != "b" {
		t.Errorf("recovered sources = %+v", d.RecoveredSources)
	}
	if d.Regressions() != 3 {
		t.Errorf("regressions = %d, want 3", d.Regressions())
	}
}

func TestHealthyExitCode(t *testing.T) {
	g := graph.Build(
		[]backend.Rule{{ID: "r", Name: "R", Enabled: true, Patterns: []string{"logs-*"}}},
		[]backend.Source{{Name: "logs-x", Docs: 1, LastEvent: time.Now()}},
	)
	r := Build("elastic", g, health.Check{MaxStale: time.Hour})
	if r.ExitCode() != ExitHealthy {
		t.Errorf("exit = %d, want %d", r.ExitCode(), ExitHealthy)
	}
}

func TestVolumeLowCountsAsFinding(t *testing.T) {
	g := graph.Build(
		[]backend.Rule{{ID: "r", Name: "R", Enabled: true, Patterns: []string{"logs-*"}}},
		[]backend.Source{{Name: "logs-x", Docs: 100, LastEvent: time.Now()}},
	)
	z := -4.2
	r := BuildWithOptions("elastic", g, BuildOptions{
		Check: health.Check{MaxStale: time.Hour},
		Volume: map[string]state.VolumeAssessment{
			"logs-x": {
				Status:       state.VolumeLow,
				RatePerHour:  1,
				BaselineMean: 100,
				BaselineStd:  10,
				ZScore:       &z,
				SampleCount:  8,
			},
		},
	})
	if r.Summary.VolumeLowSources != 1 {
		t.Fatalf("volume low sources = %d, want 1", r.Summary.VolumeLowSources)
	}
	if r.Sources[0].Volume == nil || r.Sources[0].Volume.ZScore == nil {
		t.Fatalf("missing volume details: %+v", r.Sources[0])
	}
	if r.ExitCode() != ExitFindings {
		t.Fatalf("exit = %d, want findings", r.ExitCode())
	}
}

func TestSchemaDriftCountsAsFinding(t *testing.T) {
	g := graph.Build(
		[]backend.Rule{{ID: "r", Name: "R", Enabled: true, Patterns: []string{"logs-*"}}},
		[]backend.Source{{Name: "logs-x", Docs: 100, LastEvent: time.Now()}},
	)
	r := BuildWithOptions("elastic", g, BuildOptions{
		Check: health.Check{MaxStale: time.Hour},
		Schema: map[string]state.SchemaAssessment{
			"logs-x": {
				Status:     state.SchemaDrift,
				FieldCount: 2,
				Added:      []string{"host.name"},
				Removed:    []string{"event.code"},
				TypeChanged: []state.FieldTypeChange{{
					Name:   "process.pid",
					Before: []string{"keyword"},
					After:  []string{"long"},
				}},
			},
		},
	})
	if r.Summary.SchemaDriftSources != 1 {
		t.Fatalf("schema drift sources = %d, want 1", r.Summary.SchemaDriftSources)
	}
	if r.Sources[0].Schema == nil || len(r.Sources[0].Schema.TypeChanged) != 1 {
		t.Fatalf("missing schema details: %+v", r.Sources[0])
	}
	if r.ExitCode() != ExitFindings {
		t.Fatalf("exit = %d, want findings", r.ExitCode())
	}
}

func TestDowntimeSuppressesDeadDetection(t *testing.T) {
	now := time.Date(2026, 7, 5, 2, 30, 0, 0, time.UTC)
	g := graph.Build(
		[]backend.Rule{{ID: "r", Name: "R", Enabled: true, Patterns: []string{"logs-*"}}},
		[]backend.Source{{Name: "logs-x", Docs: 10, LastEvent: now.Add(-2 * time.Hour)}},
	)
	r := Build("elastic", g, health.Check{
		MaxStale: time.Hour,
		Now:      func() time.Time { return now },
		Downtime: []health.DowntimeWindow{{
			Patterns: []string{"logs-*"},
			Days:     map[time.Weekday]bool{time.Sunday: true},
			Start:    2 * time.Hour,
			End:      3 * time.Hour,
			Location: time.UTC,
		}},
	})
	if r.Summary.DegradedSources != 0 || r.Summary.DeadDetections != 0 {
		t.Fatalf("summary = %+v, want downtime to suppress stale finding", r.Summary)
	}
	if r.Sources[0].Status != string(health.StatusMaintenance) || !r.Sources[0].ExpectedDowntime {
		t.Fatalf("source = %+v, want maintenance with expected_downtime", r.Sources[0])
	}
}

func TestRedact(t *testing.T) {
	a, b := fixtureReport(t), fixtureReport(t)
	a.Sources[0].Schema = &SchemaHealth{
		Status:      state.SchemaDrift,
		Added:       []string{"host.name"},
		Removed:     []string{"event.code"},
		TypeChanged: []FieldTypeChange{{Name: "process.pid", Before: []string{"keyword"}, After: []string{"long"}}},
	}
	a.Redact()
	b.Redact()
	if a.Sources[0].Name != b.Sources[0].Name {
		t.Error("redaction must be deterministic")
	}
	if !a.Redacted {
		t.Error("Redacted flag not set")
	}
	if a.Redaction == nil || a.Redaction.Algorithm != redactpkg.Algorithm || a.Redaction.KeyID == "" {
		t.Fatalf("redaction metadata = %+v", a.Redaction)
	}
	data, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"logs-live", "logs-stale", "logs-unused", "mystery", "Starved rule", "netflow", "r-disconnected", "host.name", "event.code", "process.pid"} {
		if strings.Contains(string(data), leak) {
			t.Errorf("redacted report leaks %q", leak)
		}
	}
}

func TestRedactWithUsesCallerKeyAndHidesInstance(t *testing.T) {
	one, err := redactpkg.New([]byte(strings.Repeat("a", 32)))
	if err != nil {
		t.Fatal(err)
	}
	two, err := redactpkg.New([]byte(strings.Repeat("b", 32)))
	if err != nil {
		t.Fatal(err)
	}
	a, b := fixtureReport(t), fixtureReport(t)
	a.Instance, b.Instance = "customer-prod", "customer-prod"
	a.Scope.ConfigurationID, b.Scope.ConfigurationID = "config-sensitive", "config-sensitive"
	a.RedactWith(one)
	b.RedactWith(two)
	if a.Redaction.KeyID != one.KeyID() || b.Redaction.KeyID != two.KeyID() {
		t.Fatalf("report key IDs = %q and %q", a.Redaction.KeyID, b.Redaction.KeyID)
	}
	if a.Sources[0].Name == b.Sources[0].Name || a.Instance == b.Instance || a.Scope.ConfigurationID == b.Scope.ConfigurationID {
		t.Fatal("different keys produced correlatable identifiers")
	}
	data, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "customer-prod") {
		t.Fatal("redacted report leaks instance name")
	}
}

func TestRedactFindingDependenciesUseEvidenceNamespaces(t *testing.T) {
	redactor, err := redactpkg.New([]byte(strings.Repeat("a", 32)))
	if err != nil {
		t.Fatal(err)
	}
	r := &Report{
		RequiredFieldEvidence: []RequiredFieldAssessment{{
			RuleID: "rule-1", RuleName: "Rule one",
			Sources: []RequiredFieldSourceEvidence{{Source: "logs-one", Missing: []string{"host.name"}}},
		}},
		PartialInputCoverage: []PartialInputCoverage{{
			RuleID: "rule-2", RuleName: "Rule two", Expression: "auditbeat-*",
		}},
		Findings: []Finding{
			{ID: "finding-field", Class: FindingImpaired, Reason: ReasonMissingFields, Dependency: "host.name"},
			{ID: "finding-input", Class: FindingPartialInput, Reason: "selector-empty", Dependency: "auditbeat-*"},
		},
	}
	r.RedactWith(redactor)
	if got, want := r.Findings[0].Dependency, r.RequiredFieldEvidence[0].Sources[0].Missing[0]; got != want {
		t.Fatalf("missing-field dependency = %q, evidence field = %q", got, want)
	}
	if got, want := r.Findings[1].Dependency, r.PartialInputCoverage[0].Expression; got != want {
		t.Fatalf("partial-input dependency = %q, evidence expression = %q", got, want)
	}
}

func TestRedactWithRemovesEverySensitiveReportField(t *testing.T) {
	redactor, err := redactpkg.New([]byte(strings.Repeat("r", 32)))
	if err != nil {
		t.Fatal(err)
	}
	var raw []string
	secret := func(name string) string {
		value := "raw-sensitive-" + name
		raw = append(raw, value)
		return value
	}
	r := &Report{
		TargetID: secret("target"),
		Instance: secret("instance"),
		Scope: ScanScope{
			Include:          []string{secret("scope-include")},
			Exclude:          []string{secret("scope-exclude")},
			ConfigurationID:  secret("scope-config"),
			CandidateRuleIDs: []string{secret("scope-candidate")},
		},
		Sources: []SourceHealth{{
			Name: secret("source"),
			Schema: &SchemaHealth{
				Added:   []string{secret("schema-added")},
				Removed: []string{secret("schema-removed")},
				TypeChanged: []FieldTypeChange{{
					Name: secret("schema-type-changed"), Before: []string{"keyword"}, After: []string{"long"},
				}},
			},
			IngestLag: &IngestLagHealth{Detail: secret("lag-detail")},
		}},
		DeadDetections: []DeadDetection{{
			ID: secret("dead-id"), RuleID: secret("dead-rule-id"), BackendObjectID: secret("dead-object"),
			Name: secret("dead-name"), Patterns: []string{secret("dead-pattern")}, Sources: []string{secret("dead-source")},
		}},
		ImpairedDetections: []ImpairedDetection{{
			ID: secret("impaired-id"), RuleID: secret("impaired-rule-id"), BackendObjectID: secret("impaired-object"),
			Name: secret("impaired-name"), MissingFields: []string{secret("impaired-field")},
			LagSources: []string{secret("impaired-lag-source")}, Sources: []string{secret("impaired-source")},
		}},
		UnmappedRules: []RuleRef{{
			ID: secret("unmapped-id"), RuleID: secret("unmapped-rule-id"), BackendObjectID: secret("unmapped-object"),
			FindingID: secret("unmapped-finding"), Dependency: secret("unmapped-dependency"),
			Name: secret("unmapped-name"), Detail: secret("unmapped-detail"),
		}},
		RemoteRules: []RuleRef{{
			ID: secret("remote-id"), RuleID: secret("remote-rule-id"), BackendObjectID: secret("remote-object"),
			FindingID: secret("remote-finding"), Dependency: secret("remote-dependency"),
			Name: secret("remote-name"), Detail: secret("remote-detail"),
		}},
		InputResolutions: []backend.InputResolution{{
			RuleID: secret("resolution-rule"), Selector: secret("resolution-selector"),
			Expression: secret("resolution-expression"), ResolvedSources: []string{secret("resolution-source")},
			Aliases: []string{secret("resolution-alias")}, Detail: secret("resolution-detail"),
		}},
		PartialInputCoverage: []PartialInputCoverage{{
			RuleID: secret("partial-rule"), BackendObjectID: secret("partial-object"), RuleName: secret("partial-name"),
			Selector: secret("partial-selector"), Expression: secret("partial-expression"),
		}},
		UnusedTelemetry: []UnusedSource{{Name: secret("unused-source")}},
		Findings: []Finding{{
			ID: secret("finding-id"), RuleID: secret("finding-rule"), BackendObjectID: secret("finding-object"),
			RuleName: secret("finding-name"), Source: secret("finding-source"),
			Reason: ReasonMissingFields, Dependency: secret("finding-field"),
			Accepted: &FindingAcceptance{Reason: secret("acceptance-reason")},
		}},
		RecoveredFindings: []Finding{{
			ID: secret("recovered-id"), RuleID: secret("recovered-rule"), BackendObjectID: secret("recovered-object"),
			RuleName: secret("recovered-name"), Source: secret("recovered-source"), Dependency: secret("recovered-dependency"),
		}},
		RequiredFieldEvidence: []RequiredFieldAssessment{{
			RuleID: secret("field-rule"), RuleName: secret("field-rule-name"),
			Sources: []RequiredFieldSourceEvidence{{
				Source: secret("field-source"), Present: []string{secret("field-present")},
				Missing: []string{secret("field-missing")}, Detail: secret("field-detail"),
			}},
		}},
	}
	r.RedactWith(redactor)
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range raw {
		if strings.Contains(string(data), value) {
			t.Errorf("redacted report leaks %q", value)
		}
	}
}

func TestCandidateExitCodeFailsClosedOnIncompleteResolution(t *testing.T) {
	for _, name := range []string{AssessmentSourceResolution, AssessmentRequiredFields, AssessmentIngestLag} {
		t.Run(name, func(t *testing.T) {
			r := &Report{Assessments: []RuntimeAssessment{{Name: name, Status: backend.EvidenceIncomplete}}}
			if got := r.CandidateExitCode(); got != ExitError {
				t.Fatalf("candidate exit = %d, want error", got)
			}
		})
	}
	for _, name := range []string{AssessmentRequiredFields, AssessmentIngestLag} {
		t.Run(name+"-unavailable", func(t *testing.T) {
			r := &Report{Assessments: []RuntimeAssessment{{Name: name, Status: backend.EvidenceUnavailable}}}
			if got := r.CandidateExitCode(); got != ExitHealthy {
				t.Fatalf("candidate exit = %d, want healthy when backend capability is unavailable", got)
			}
		})
	}
}

func TestWritePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not enforced on Windows")
	}
	r := fixtureReport(t)
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := r.Write(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("report written %o, want 0600 — the report is a blind-spot map", info.Mode().Perm())
	}
}

func TestWriteHTML(t *testing.T) {
	r := fixtureReport(t)
	r.Producer = producer("1.2.3")
	r.BackendMetadata = backendMetadata("elastic", "8.17.4")
	r.Sources[0].Name = `<script>alert(1)</script>`
	r.Summary.PartialInputs = 1
	r.PartialInputCoverage = []PartialInputCoverage{{
		RuleID: "migration", RuleName: "Migrating input", Severity: "medium",
		Selector: "logs-legacy-*", Expression: "logs-legacy-*", ObservedAt: time.Now().UTC(),
	}}
	path := filepath.Join(t.TempDir(), "report.html")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := r.WriteHTML(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("html report written %o, want 0600", info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "deadair report") {
		t.Fatalf("html report missing title:\n%s", data)
	}
	for _, metadata := range []string{
		ReportSchemaVersion,
		"producer deadair 1.2.3",
		"Elastic Security 8.17.4 (elastic)",
		"recognized versions 8.x",
		"rule_inventory=supported",
		"remote=listed-only",
		"Partial input coverage",
		"Migrating input",
		"logs-legacy-*",
	} {
		if !strings.Contains(string(data), metadata) {
			t.Errorf("html report missing metadata %q", metadata)
		}
	}
	if strings.Contains(string(data), "<script>alert(1)</script>") {
		t.Fatal("html report did not escape source name")
	}
	if !strings.Contains(string(data), "no matching source") ||
		!strings.Contains(string(data), "all matching sources stale or empty") {
		t.Fatalf("html report does not use plain-language reasons:\n%s", data)
	}
	if strings.Contains(string(data), ">disconnected<") || strings.Contains(string(data), ">starved<") {
		t.Fatalf("html report exposes machine reason codes:\n%s", data)
	}
	for lineNo, line := range strings.Split(string(data), "\n") {
		if strings.TrimRight(line, " \t") != line {
			t.Errorf("html report line %d has trailing whitespace", lineNo+1)
		}
	}
}

func TestRemoteRulesNeverDead(t *testing.T) {
	rules := []backend.Rule{
		{ID: "r-ccs", Name: "CCS rule", Enabled: true, Severity: "high", Patterns: []string{"eu-cluster:logs-*"}},
		{ID: "r-mixed", Name: "Mixed rule", Enabled: true, Severity: "low", Patterns: []string{"*:logs-*", "nothere-*"}},
	}
	sources := []backend.Source{{Name: "logs-x", Docs: 1, LastEvent: time.Now()}}
	r := Build("elastic", graph.Build(rules, sources), health.Check{MaxStale: time.Hour})
	if len(r.DeadDetections) != 0 {
		t.Fatalf("cross-cluster rules must never be reported dead: %+v", r.DeadDetections)
	}
	if r.Summary.RemoteRules != 2 || len(r.RemoteRules) != 2 {
		t.Fatalf("remote rules = %+v", r.RemoteRules)
	}
}

func TestNativeResolutionOnlyEmptyCanDisconnect(t *testing.T) {
	now := time.Now().UTC()
	rules := []backend.Rule{
		{ID: "empty", Name: "Empty input", Enabled: true, Severity: "high", Patterns: []string{"missing-*"}},
		{ID: "unavailable", Name: "Unavailable input", Enabled: true, Severity: "high", Patterns: []string{"secret-*"}},
		{ID: "remote", Name: "Remote input", Enabled: true, Severity: "medium", Patterns: []string{"eu:logs-*"}},
		{ID: "mixed", Name: "Mixed local and remote", Enabled: true, Severity: "critical", Patterns: []string{"stale-*", "eu:logs-*"}},
		{ID: "missing-evidence", Name: "Missing evidence", Enabled: true, Severity: "medium", Patterns: []string{"maybe-*"}},
		{ID: "partial-inventory", Name: "Partial inventory", Enabled: true, Severity: "high", Patterns: []string{"stale-*"}},
	}
	sources := []backend.Source{
		{Name: "stale-source", Docs: 10, LastEvent: now.Add(-24 * time.Hour)},
		{Name: "maybe-unused", Docs: 10, SizeBytes: 100, LastEvent: now},
	}
	resolutions := []backend.InputResolution{
		{RuleID: "empty", Expression: "missing-*", SelectorKind: "index_expression", ResolutionMethod: "resolve_index", ObservedAt: now, Status: backend.ResolutionEmpty},
		{RuleID: "unavailable", Expression: "secret-*", SelectorKind: "index_expression", ResolutionMethod: "resolve_index", ObservedAt: now, Status: backend.ResolutionUnavailable, Detail: "403 for secret-*"},
		{RuleID: "remote", Selector: "eu:logs-*", SelectorKind: "remote_index", ResolutionMethod: "remote_selector", ObservedAt: now, Status: backend.ResolutionRemote},
		{RuleID: "mixed", Expression: "stale-*", SelectorKind: "index_expression", ResolvedSources: []string{"stale-source"}, ResolutionMethod: "resolve_index", ObservedAt: now, Status: backend.ResolutionResolved},
		{RuleID: "mixed", Selector: "eu:logs-*", SelectorKind: "remote_index", ResolutionMethod: "remote_selector", ObservedAt: now, Status: backend.ResolutionRemote},
		{RuleID: "partial-inventory", Expression: "stale-*", SelectorKind: "index_expression", ResolvedSources: []string{"stale-source", ".hidden-target"}, ResolutionMethod: "resolve_index", ObservedAt: now, Status: backend.ResolutionResolved},
	}
	r := BuildWithOptions("elastic", graph.BuildResolved(rules, sources, resolutions), BuildOptions{
		Check: health.Check{MaxStale: time.Hour, Now: func() time.Time { return now }},
	})
	if len(r.DeadDetections) != 1 || r.DeadDetections[0].ID != "empty" || r.DeadDetections[0].Reason != ReasonDisconnected {
		t.Fatalf("dead detections = %+v, want only positive empty evidence", r.DeadDetections)
	}
	if len(r.UnmappedRules) != 3 {
		t.Fatalf("unmapped rules = %+v, want unavailable, missing-evidence, and partial-inventory", r.UnmappedRules)
	}
	unmapped := map[string]RuleRef{}
	for _, rule := range r.UnmappedRules {
		unmapped[rule.ID] = rule
	}
	if unmapped["unavailable"].AssessmentStatus != backend.ResolutionUnavailable ||
		unmapped["missing-evidence"].AssessmentStatus != backend.ResolutionUnsupported ||
		unmapped["partial-inventory"].AssessmentStatus != backend.ResolutionAmbiguous {
		t.Fatalf("unmapped rules = %+v", r.UnmappedRules)
	}
	if len(r.RemoteRules) != 2 {
		t.Fatalf("remote rules = %+v, want remote and mixed", r.RemoteRules)
	}
	if got := r.Summary.InputResolution; got != (InputResolutionSummary{Resolved: 2, Empty: 1, Unavailable: 1, Remote: 2}) {
		t.Fatalf("resolution summary = %+v", got)
	}
	if len(r.InputResolutions) != len(resolutions) {
		t.Fatalf("resolution evidence = %d, want %d", len(r.InputResolutions), len(resolutions))
	}
	if r.Summary.UnusedTelemetryAssessment != UnusedAssessmentUnavailable ||
		len(r.UnusedTelemetry) != 0 || r.Summary.UnusedBytes != 0 {
		t.Fatalf("unused telemetry must stay unassessed when a local input is uncertain: %+v / %+v",
			r.Summary, r.UnusedTelemetry)
	}

	r.Redact()
	encoded, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"secret-*", "eu:logs-*", "stale-source", "403 for"} {
		if strings.Contains(string(encoded), leak) {
			t.Errorf("redacted resolution evidence leaks %q", leak)
		}
	}
}

func TestPartialInputCoverageUsesOnlyDiagnosticEmptyEvidence(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	rule := backend.Rule{
		ID: "migration", BackendObjectID: "saved-migration", Name: "Migrating input",
		Enabled: true, Severity: "high", Patterns: []string{"logs-legacy-*", "logs-current-*", "-logs-old-*"},
	}
	sources := []backend.Source{{Name: "logs-current-default", Docs: 10, LastEvent: now}}
	authoritative := backend.InputResolution{
		RuleID: rule.ID, Expression: "logs-legacy-*,logs-current-*,-logs-old-*",
		SelectorKind: "index_expression", ResolutionMethod: "resolve_index",
		ObservedAt: now, Status: backend.ResolutionResolved, ResolvedSources: []string{"logs-current-default"},
	}
	build := func(diagnostic backend.InputResolution) *Report {
		diagnostic.RuleID = rule.ID
		diagnostic.Diagnostic = true
		diagnostic.SelectorKind = "index_selector"
		diagnostic.ResolutionMethod = "resolve_index_diagnostic"
		diagnostic.ObservedAt = now
		return BuildWithOptions("elastic", graph.BuildResolved(
			[]backend.Rule{rule}, sources, []backend.InputResolution{authoritative, diagnostic}),
			BuildOptions{Check: health.Check{MaxStale: time.Hour, Now: func() time.Time { return now }}},
		)
	}

	partial := build(backend.InputResolution{
		Selector: "logs-legacy-*", Expression: "logs-legacy-*,-logs-old-*", Status: backend.ResolutionEmpty,
	})
	if len(partial.PartialInputCoverage) != 1 || partial.Summary.PartialInputs != 1 {
		t.Fatalf("partial coverage = %+v / %+v", partial.PartialInputCoverage, partial.Summary)
	}
	if got := partial.PartialInputCoverage[0]; got.RuleID != rule.ID || got.Expression != "logs-legacy-*,-logs-old-*" {
		t.Fatalf("partial evidence = %+v", got)
	}
	if partial.Summary.InputResolution != (InputResolutionSummary{Resolved: 1}) {
		t.Fatalf("diagnostic outcome leaked into primary summary: %+v", partial.Summary.InputResolution)
	}
	if len(partial.DeadDetections) != 0 || partial.ExitCode() != ExitHealthy {
		t.Fatalf("partial coverage changed default verdict: %+v / exit %d", partial.DeadDetections, partial.ExitCode())
	}
	if len(partial.Findings) != 1 || partial.Findings[0].Class != FindingPartialInput ||
		partial.Findings[0].Dependency != "logs-legacy-*,-logs-old-*" || partial.Findings[0].Gates {
		t.Fatalf("partial finding = %+v", partial.Findings)
	}

	incomplete := build(backend.InputResolution{
		Selector: "logs-legacy-*", Expression: "logs-legacy-*,-logs-old-*",
		Status: backend.ResolutionUnavailable, Detail: "resolver unavailable",
	})
	if len(incomplete.PartialInputCoverage) != 0 || len(incomplete.Findings) != 0 || len(incomplete.UnmappedRules) != 0 {
		t.Fatalf("unavailable diagnostic became a finding: %+v", incomplete)
	}
	if incomplete.Summary.InputResolution != (InputResolutionSummary{Resolved: 1}) {
		t.Fatalf("unavailable diagnostic changed primary summary: %+v", incomplete.Summary.InputResolution)
	}

	redacted := partial
	redacted.Redact()
	encoded, err := json.Marshal(redacted)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"logs-legacy-*", "logs-current-default", "Migrating input"} {
		if strings.Contains(string(encoded), leak) {
			t.Errorf("redacted partial evidence leaks %q", leak)
		}
	}
}

func TestAuthoritativeEmptyIsDeadAndNeverPartial(t *testing.T) {
	now := time.Now().UTC()
	rule := backend.Rule{ID: "all-empty", Name: "All inputs missing", Enabled: true, Severity: "high"}
	resolutions := []backend.InputResolution{
		{RuleID: rule.ID, Expression: "legacy-*,current-*", Status: backend.ResolutionEmpty, ObservedAt: now},
		{RuleID: rule.ID, Selector: "legacy-*", Expression: "legacy-*", Diagnostic: true, Status: backend.ResolutionEmpty, ObservedAt: now},
		{RuleID: rule.ID, Selector: "current-*", Expression: "current-*", Diagnostic: true, Status: backend.ResolutionEmpty, ObservedAt: now},
	}
	r := BuildWithOptions("elastic", graph.BuildResolved([]backend.Rule{rule}, nil, resolutions), BuildOptions{
		Check: health.Check{MaxStale: time.Hour, Now: func() time.Time { return now }},
	})
	if len(r.DeadDetections) != 1 || len(r.PartialInputCoverage) != 0 || r.Summary.PartialInputs != 0 {
		t.Fatalf("authoritative empty result = dead %+v, partial %+v", r.DeadDetections, r.PartialInputCoverage)
	}
	if r.Summary.InputResolution != (InputResolutionSummary{Empty: 1}) {
		t.Fatalf("diagnostics changed authoritative summary: %+v", r.Summary.InputResolution)
	}
}

func TestPartialInputFindingGatesOnlyWhenPolicyRequestsIt(t *testing.T) {
	now := time.Now().UTC()
	rule := backend.Rule{ID: "migration", Name: "Migrating input", Enabled: true, Severity: "medium"}
	sources := []backend.Source{{Name: "logs-current", Docs: 1, LastEvent: now}}
	resolutions := []backend.InputResolution{
		{RuleID: rule.ID, Expression: "logs-legacy,logs-current", Status: backend.ResolutionResolved, ResolvedSources: []string{"logs-current"}, ObservedAt: now},
		{RuleID: rule.ID, Selector: "logs-legacy", Expression: "logs-legacy", Diagnostic: true, Status: backend.ResolutionEmpty, ObservedAt: now},
	}
	build := func(policy *Policy) *Report {
		return BuildWithOptions("elastic", graph.BuildResolved([]backend.Rule{rule}, sources, resolutions), BuildOptions{
			Check: health.Check{MaxStale: time.Hour, Now: func() time.Time { return now }}, Policy: policy,
		})
	}
	if got := build(nil).ExitCode(); got != ExitHealthy {
		t.Fatalf("default exit = %d, want healthy", got)
	}
	policy := &Policy{Version: PolicyVersion, GateClasses: []string{FindingPartialInput}}
	withPolicy := build(policy)
	if withPolicy.ExitCode() != ExitFindings || withPolicy.Summary.GatedFindings != 1 || !withPolicy.Findings[0].Gates {
		t.Fatalf("policy did not gate partial input: %+v / exit %d", withPolicy, withPolicy.ExitCode())
	}
}
