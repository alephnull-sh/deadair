package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Big-Comfy/deadair/internal/backend"
	"github.com/Big-Comfy/deadair/internal/graph"
	"github.com/Big-Comfy/deadair/internal/health"
	"github.com/Big-Comfy/deadair/internal/state"
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
		{ID: "r-trunc", Name: "Truncated", Enabled: true, Severity: "high", Patterns: []string{"logs-ret-*"}, Lookback: 90 * 24 * time.Hour},
		{ID: "r-fields", Name: "MissingFields", Enabled: true, Severity: "medium", Patterns: []string{"logs-live2-*"}, RequiredFields: []string{"process.name", "custom.gone"}},
		{ID: "r-lag", Name: "Lagged", Enabled: true, Severity: "low", Patterns: []string{"logs-lag-*"}, Lookback: 10 * time.Minute, Interval: 5 * time.Minute},
		{ID: "r-ok", Name: "Fine", Enabled: true, Severity: "low", Patterns: []string{"logs-live2-*"}, RequiredFields: []string{"process.name"}, Lookback: 6 * time.Minute, Interval: 5 * time.Minute},
		{ID: "r-unk", Name: "UnknownRetention", Enabled: true, Severity: "high", Patterns: []string{"logs-mixed-*"}, Lookback: 90 * 24 * time.Hour},
	}
	sources := []backend.Source{
		{Name: "logs-ret-a", Docs: 10, LastEvent: now, Retention: 30 * 24 * time.Hour},
		{Name: "logs-live2-a", Docs: 10, LastEvent: now},
		{Name: "logs-lag-a", Docs: 10, LastEvent: now, IngestLag: &lag},
		{Name: "logs-mixed-a", Docs: 10, LastEvent: now, Retention: 30 * 24 * time.Hour},
		{Name: "logs-mixed-b", Docs: 10, LastEvent: now}, // retention unknown
	}
	g := graph.Build(rules, sources)
	r := BuildWithOptions("elastic", g, BuildOptions{
		Check:        health.Check{MaxStale: time.Hour},
		SourceFields: map[string]map[string]bool{"logs-live2-a": {"process.name": true}},
	})

	byID := map[string]ImpairedDetection{}
	for _, d := range r.ImpairedDetections {
		byID[d.ID] = d
	}
	if len(byID) != 3 {
		t.Fatalf("impaired = %+v, want r-trunc, r-fields, r-lag", byID)
	}
	if d := byID["r-trunc"]; len(d.Reasons) != 1 || d.Reasons[0] != ReasonTruncatedLookback || d.RetentionSeconds != (30*24*time.Hour).Seconds() {
		t.Errorf("truncated = %+v", d)
	}
	if d := byID["r-fields"]; len(d.MissingFields) != 1 || d.MissingFields[0] != "custom.gone" {
		t.Errorf("missing fields = %+v", d)
	}
	if d := byID["r-lag"]; len(d.Reasons) != 1 || d.Reasons[0] != ReasonLagBlindWindow || d.MaxLagSeconds != lag.Seconds() {
		t.Errorf("lag = %+v", d)
	}
	if _, ok := byID["r-unk"]; ok {
		t.Error("a matched source with unknown retention must suppress the truncated-lookback finding")
	}
	if _, ok := byID["r-ok"]; ok {
		t.Error("r-ok must not be impaired")
	}
	if r.Summary.ImpairedDetections != 3 || r.ExitCode() != ExitFindings {
		t.Errorf("summary/exit = %d/%d", r.Summary.ImpairedDetections, r.ExitCode())
	}
	if r.CandidateExitCode() != ExitFindings {
		t.Errorf("candidate exit = %d, want findings", r.CandidateExitCode())
	}

	// Redacted impaired output must leak neither rule nor field names.
	r.Redact()
	data, _ := json.Marshal(r)
	for _, leak := range []string{"custom.gone", "Truncated", "logs-lag-a"} {
		if strings.Contains(string(data), leak) {
			t.Errorf("redacted report leaks %q", leak)
		}
	}
}

func TestSkipUnused(t *testing.T) {
	g := graph.Build(nil, []backend.Source{{Name: "orphan", Docs: 1, LastEvent: time.Now()}})
	r := BuildWithOptions("elastic", g, BuildOptions{Check: health.Check{MaxStale: time.Hour}, SkipUnused: true})
	if len(r.UnusedTelemetry) != 0 || r.Summary.UnusedSources != 0 || r.Summary.UnusedBytes != 0 {
		t.Fatalf("unused must be suppressed in candidate mode: %+v", r.UnusedTelemetry)
	}
}

func TestDiff(t *testing.T) {
	older := &Report{
		Sources:        []SourceHealth{{Name: "a", Status: "ok"}, {Name: "b", Status: "stale"}},
		DeadDetections: []DeadDetection{{ID: "d1", Name: "Old dead", Reason: "disconnected"}},
	}
	newer := &Report{
		Sources:            []SourceHealth{{Name: "a", Status: "stale"}, {Name: "b", Status: "ok"}},
		DeadDetections:     []DeadDetection{{ID: "d2", Name: "New dead", Reason: "starved"}},
		ImpairedDetections: []ImpairedDetection{{ID: "i1", Name: "New impaired", Reasons: []string{ReasonMissingFields}}},
	}
	d := Diff(older, newer)
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

func TestWritePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not enforced on Windows")
	}
	r := fixtureReport(t)
	path := filepath.Join(t.TempDir(), "report.json")
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
	r.Sources[0].Name = `<script>alert(1)</script>`
	path := filepath.Join(t.TempDir(), "report.html")
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
	if strings.Contains(string(data), "<script>alert(1)</script>") {
		t.Fatal("html report did not escape source name")
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
