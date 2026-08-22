package cli

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/alephnull-sh/deadair/internal/backend"
	"github.com/alephnull-sh/deadair/internal/graph"
	"github.com/alephnull-sh/deadair/internal/health"
	"github.com/alephnull-sh/deadair/internal/report"
	"github.com/alephnull-sh/deadair/internal/state"
)

type lagProbeBackend struct {
	requested       []string
	fieldSources    []string
	requestedFields []string
	fields          map[string]backend.FieldEvidence
	lags            map[string]backend.IngestLagEvidence
}

type freshnessProbeBackend struct {
	lagProbeBackend
	requestedFreshness []string
	freshness          map[string]backend.FreshnessEvidence
}

func (b *freshnessProbeBackend) FreshnessEvidence(_ context.Context, sources []backend.Source) (map[string]backend.FreshnessEvidence, error) {
	out := make(map[string]backend.FreshnessEvidence, len(sources))
	for _, source := range sources {
		b.requestedFreshness = append(b.requestedFreshness, source.Name)
		if item, ok := b.freshness[source.Name]; ok {
			out[source.Name] = item
		}
	}
	return out, nil
}

func (b *lagProbeBackend) RequiredFieldEvidence(_ context.Context, sources []backend.Source, fields []string) (map[string]backend.FieldEvidence, error) {
	b.requestedFields = append(b.requestedFields, fields...)
	out := make(map[string]backend.FieldEvidence, len(sources))
	for _, source := range sources {
		b.fieldSources = append(b.fieldSources, source.Name)
		item, ok := b.fields[source.Name]
		if !ok {
			item = backend.FieldEvidence{Status: backend.EvidenceAssessed, Fields: map[string]bool{}}
		}
		out[source.Name] = item
	}
	return out, nil
}

func (b *lagProbeBackend) Name() string                                      { return "probe" }
func (b *lagProbeBackend) Rules(context.Context) ([]backend.Rule, error)     { return nil, nil }
func (b *lagProbeBackend) Sources(context.Context) ([]backend.Source, error) { return nil, nil }
func (b *lagProbeBackend) Schemas(context.Context, []backend.Source) (map[string]backend.Schema, error) {
	return nil, nil
}

func TestCollectRequiredFieldEvidenceAssessesAllResolvedSources(t *testing.T) {
	rules := []backend.Rule{
		{ID: "in", Enabled: true, Patterns: []string{"logs-a"}, RequiredFields: []string{"process.name"}},
		{ID: "out", Enabled: true, Patterns: []string{"logs-b"}, RequiredFields: []string{"host.name"}},
	}
	sources := []backend.Source{{Name: "logs-a"}, {Name: "logs-b"}}
	g := graph.Build(rules, sources)
	probe := &lagProbeBackend{}
	evidence, assessment, err := collectRequiredFieldEvidence(context.Background(), probe, rules, g, sources)
	if err != nil {
		t.Fatal(err)
	}
	if len(probe.fieldSources) != 2 || probe.fieldSources[0] != "logs-a" || probe.fieldSources[1] != "logs-b" || len(evidence) != 2 {
		t.Fatalf("field sources = %v, evidence = %+v; want both resolved sources", probe.fieldSources, evidence)
	}
	if len(probe.requestedFields) != 2 || probe.requestedFields[0] != "host.name" || probe.requestedFields[1] != "process.name" || assessment.Status != backend.EvidenceAssessed {
		t.Fatalf("fields/status = %v/%+v", probe.requestedFields, assessment)
	}
}

func TestCollectFreshnessEvidenceUsesDedupedEnabledConcreteSources(t *testing.T) {
	rules := []backend.Rule{
		{ID: "one", Enabled: true},
		{ID: "two", Enabled: true},
		{ID: "disabled", Enabled: false},
	}
	sources := []backend.Source{{Name: "SecurityEvent"}, {Name: "SigninLogs"}, {Name: "Heartbeat"}, {Name: "unused"}}
	resolutions := []backend.InputResolution{
		{RuleID: "one", Status: backend.ResolutionResolved, ResolvedSources: []string{"SecurityEvent", "SigninLogs"}},
		{RuleID: "two", Status: backend.ResolutionResolved, ResolvedSources: []string{"SigninLogs"}},
		{RuleID: "disabled", Status: backend.ResolutionResolved, ResolvedSources: []string{"Heartbeat"}},
	}
	g := graph.BuildResolved(rules, sources, resolutions)
	probe := &freshnessProbeBackend{freshness: map[string]backend.FreshnessEvidence{
		"SecurityEvent": {Status: backend.EvidenceAssessed, LastEvent: time.Now().UTC()},
	}}
	evidence, assessment, err := collectFreshnessEvidence(context.Background(), probe, rules, g, sources, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := probe.requestedFreshness, []string{"SecurityEvent", "SigninLogs"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("freshness sources = %v, want %v", got, want)
	}
	if len(evidence) != 1 || assessment.Status != backend.EvidenceIncomplete || assessment.Name != report.AssessmentSourceFreshness {
		t.Fatalf("freshness evidence/assessment = %+v / %+v", evidence, assessment)
	}
}

func TestFreshnessRequestsKeepScheduledAndNRTClocksSeparate(t *testing.T) {
	rules := []backend.Rule{
		{ID: "scheduled", Enabled: true},
		{ID: "nrt", Enabled: true, TimestampOverride: "ingestion_time()"},
		{ID: "shared-scheduled", Enabled: true},
		{ID: "shared-nrt", Enabled: true, TimestampOverride: "ingestion_time()"},
	}
	sources := []backend.Source{{Name: "ScheduledOnly"}, {Name: "NRTOnly"}, {Name: "Shared"}}
	resolutions := []backend.InputResolution{
		{RuleID: "scheduled", Status: backend.ResolutionResolved, ResolvedSources: []string{"ScheduledOnly"}},
		{RuleID: "nrt", Status: backend.ResolutionResolved, ResolvedSources: []string{"NRTOnly"}},
		{RuleID: "shared-scheduled", Status: backend.ResolutionResolved, ResolvedSources: []string{"Shared"}},
		{RuleID: "shared-nrt", Status: backend.ResolutionResolved, ResolvedSources: []string{"Shared"}},
	}
	requests := freshnessRequests(rules, graph.BuildResolved(rules, sources, resolutions), sources, 30*time.Minute)
	got := map[string]backend.FreshnessBasis{}
	for _, request := range requests {
		got[request.Source.Name] = request.Basis
	}
	want := map[string]backend.FreshnessBasis{
		"ScheduledOnly": backend.FreshnessEventTime,
		"NRTOnly":       backend.FreshnessIngestionTime,
		"Shared":        backend.FreshnessMixed,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("freshness timing = %v, want %v", got, want)
	}
}

func TestCollectFreshnessMarksShortEmptyWindowIncomplete(t *testing.T) {
	rules := []backend.Rule{{ID: "candidate", Enabled: true, Patterns: []string{"SecurityEvent"}}}
	sources := []backend.Source{{Name: "SecurityEvent"}}
	g := graph.Build(rules, sources)
	probe := &freshnessProbeBackend{freshness: map[string]backend.FreshnessEvidence{
		"SecurityEvent": {Status: backend.EvidenceAssessed, Window: 24 * time.Hour},
	}}
	evidence, assessment, err := collectFreshnessEvidence(context.Background(), probe, rules, g, sources, 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if assessment.Status != backend.EvidenceIncomplete || evidence["SecurityEvent"].Status != backend.EvidenceIncomplete {
		t.Fatalf("freshness evidence/assessment = %+v / %+v, want incomplete", evidence, assessment)
	}
}

func TestRuntimeAssessmentStates(t *testing.T) {
	probe := &lagProbeBackend{}
	g := graph.Build(nil, []backend.Source{{Name: "logs-a"}})
	_, fields, err := collectRequiredFieldEvidence(context.Background(), probe, nil, g, g.Sources)
	if err != nil {
		t.Fatal(err)
	}
	if fields.Status != backend.EvidenceDisabled {
		t.Fatalf("supported required fields with no declarations = %+v, want disabled", fields)
	}

	lag := report.RuntimeAssessment{Name: report.AssessmentIngestLag, Status: backend.EvidenceDisabled}
	assessments := runtimeAssessments(connOpts{schemaTrack: true}, g, g.Sources,
		map[string]state.SchemaAssessment{"logs-a": {Status: state.SchemaUnknown}}, fields, lag)
	foundSchema := false
	for _, assessment := range assessments {
		if assessment.Name == report.AssessmentSchemaDrift {
			foundSchema = true
			if assessment.Status != backend.EvidenceIncomplete {
				t.Fatalf("schema assessment = %+v, want incomplete", assessment)
			}
		}
	}
	if !foundSchema {
		t.Fatal("schema runtime assessment missing")
	}
}

func TestRuntimeAssessmentMarksUnavailableDiagnosticIncomplete(t *testing.T) {
	rules := []backend.Rule{{ID: "migration", Enabled: true}}
	sources := []backend.Source{{Name: "logs-current"}}
	resolutions := []backend.InputResolution{
		{RuleID: "migration", Status: backend.ResolutionResolved, ResolvedSources: []string{"logs-current"}},
		{RuleID: "migration", Diagnostic: true, Status: backend.ResolutionUnavailable},
	}
	g := graph.BuildResolved(rules, sources, resolutions)
	assessments := runtimeAssessments(connOpts{}, g, sources, nil,
		report.RuntimeAssessment{Name: report.AssessmentRequiredFields, Status: backend.EvidenceDisabled},
		report.RuntimeAssessment{Name: report.AssessmentIngestLag, Status: backend.EvidenceDisabled})
	for _, assessment := range assessments {
		if assessment.Name == report.AssessmentSourceResolution {
			if assessment.Status != backend.EvidenceIncomplete {
				t.Fatalf("source resolution = %+v, want incomplete", assessment)
			}
			candidate := report.Report{Assessments: assessments}
			if got := candidate.CandidateExitCode(); got != report.ExitError {
				t.Fatalf("candidate exit = %d, want error for incomplete diagnostic evidence", got)
			}
			return
		}
	}
	t.Fatal("source-resolution assessment missing")
}

func TestRuntimeAssessmentIgnoresDisabledRuleResolutionFailures(t *testing.T) {
	rules := []backend.Rule{
		{ID: "enabled", Enabled: true},
		{ID: "disabled", Enabled: false},
	}
	resolutions := []backend.InputResolution{
		{RuleID: "enabled", Status: backend.ResolutionResolved, ResolvedSources: []string{"logs-current"}},
		{RuleID: "disabled", Status: backend.ResolutionUnsupported},
	}
	g := graph.BuildResolved(rules, []backend.Source{{Name: "logs-current"}}, resolutions)
	assessments := runtimeAssessments(connOpts{}, g, g.Sources, nil,
		report.RuntimeAssessment{Name: report.AssessmentRequiredFields, Status: backend.EvidenceDisabled},
		report.RuntimeAssessment{Name: report.AssessmentIngestLag, Status: backend.EvidenceDisabled})
	for _, assessment := range assessments {
		if assessment.Name == report.AssessmentSourceResolution {
			if assessment.Status != backend.EvidenceAssessed {
				t.Fatalf("source resolution = %+v, want assessed", assessment)
			}
			return
		}
	}
	t.Fatal("source-resolution assessment missing")
}

func TestRuntimeAssessmentTreatsIncompatibleResolutionAsAssessed(t *testing.T) {
	rules := []backend.Rule{{ID: "enabled", Enabled: true}}
	resolutions := []backend.InputResolution{{
		RuleID: "enabled", Selector: "BasicTable", Status: backend.ResolutionIncompatible,
	}}
	g := graph.BuildResolved(rules, []backend.Source{{Name: "BasicTable"}}, resolutions)
	assessments := runtimeAssessments(connOpts{}, g, g.Sources, nil,
		report.RuntimeAssessment{Name: report.AssessmentRequiredFields, Status: backend.EvidenceDisabled},
		report.RuntimeAssessment{Name: report.AssessmentIngestLag, Status: backend.EvidenceDisabled})
	for _, assessment := range assessments {
		if assessment.Name == report.AssessmentSourceResolution {
			if assessment.Status != backend.EvidenceAssessed {
				t.Fatalf("source resolution = %+v, want assessed", assessment)
			}
			return
		}
	}
	t.Fatal("source-resolution assessment missing")
}

func TestRuntimeAssessmentRequiresAuthoritativeEvidenceForEveryEnabledRule(t *testing.T) {
	rules := []backend.Rule{
		{ID: "enabled", Enabled: true},
		{ID: "disabled", Enabled: false},
	}
	resolutions := []backend.InputResolution{
		{RuleID: "disabled", Status: backend.ResolutionResolved, ResolvedSources: []string{"logs-current"}},
	}
	g := graph.BuildResolved(rules, []backend.Source{{Name: "logs-current"}}, resolutions)
	assessments := runtimeAssessments(connOpts{}, g, g.Sources, nil,
		report.RuntimeAssessment{Name: report.AssessmentRequiredFields, Status: backend.EvidenceDisabled},
		report.RuntimeAssessment{Name: report.AssessmentIngestLag, Status: backend.EvidenceDisabled})
	for _, assessment := range assessments {
		if assessment.Name == report.AssessmentSourceResolution {
			if assessment.Status != backend.EvidenceIncomplete {
				t.Fatalf("source resolution = %+v, want incomplete", assessment)
			}
			return
		}
	}
	t.Fatal("source-resolution assessment missing")
}

func (b *lagProbeBackend) IngestLagEvidence(_ context.Context, sources []backend.Source) (map[string]backend.IngestLagEvidence, error) {
	out := make(map[string]backend.IngestLagEvidence, len(sources))
	for _, source := range sources {
		b.requested = append(b.requested, source.Name)
		item, ok := b.lags[source.Name]
		if !ok {
			item = backend.IngestLagEvidence{
				Status: backend.EvidenceAssessed, Method: "paired-recent-events", SampleCount: 1,
			}
		}
		out[source.Name] = item
	}
	return out, nil
}

func TestCollectIngestLagEvidenceSamplesOnlyRelevantResolvedSources(t *testing.T) {
	rules := []backend.Rule{
		{ID: "relevant", Enabled: true, Patterns: []string{"logs-a"}, Lookback: 10 * time.Minute, Interval: 5 * time.Minute},
		{ID: "no-margin", Enabled: true, Patterns: []string{"logs-b"}, Lookback: 5 * time.Minute, Interval: 5 * time.Minute},
		{ID: "ingest-time", Enabled: true, Patterns: []string{"logs-c"}, Lookback: 10 * time.Minute, Interval: 5 * time.Minute, TimestampOverride: "event.ingested"},
		{ID: "out-of-scope", Enabled: true, Patterns: []string{"logs-d"}, Lookback: 10 * time.Minute, Interval: 5 * time.Minute},
	}
	sources := []backend.Source{{Name: "logs-a"}, {Name: "logs-b"}, {Name: "logs-c"}, {Name: "logs-d"}, {Name: "unused"}}
	g := graph.Build(rules, sources)
	probe := &lagProbeBackend{}
	evidence, assessment, err := collectIngestLagEvidence(context.Background(), probe, rules, g, sources)
	if err != nil {
		t.Fatal(err)
	}
	if len(probe.requested) != 3 || probe.requested[0] != "logs-a" || probe.requested[1] != "logs-b" || probe.requested[2] != "logs-d" || len(evidence) != 3 {
		t.Fatalf("requested = %v, evidence = %+v; want all relevant resolved sources", probe.requested, evidence)
	}
	if assessment.Status != backend.EvidenceAssessed {
		t.Fatalf("assessment = %+v, want assessed", assessment)
	}
}

func TestListingFilterCannotHideFieldOrLagFinding(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	rules := []backend.Rule{{
		ID: "broad", Name: "Broad rule", Enabled: true, Severity: "high",
		Patterns: []string{"logs-*"}, RequiredFields: []string{"process.name"},
		Lookback: 10 * time.Minute, Interval: 5 * time.Minute,
	}}
	sources := []backend.Source{
		{Name: "logs-included", Docs: 1, LastEvent: now},
		{Name: "logs-excluded", Docs: 1, LastEvent: now},
	}
	g := graph.Build(rules, sources)
	probe := &lagProbeBackend{
		fields: map[string]backend.FieldEvidence{
			"logs-included": {Status: backend.EvidenceAssessed, Fields: map[string]bool{"process.name": true}},
			"logs-excluded": {Status: backend.EvidenceAssessed, Fields: map[string]bool{}},
		},
		lags: map[string]backend.IngestLagEvidence{
			"logs-included": {Status: backend.EvidenceAssessed, Method: "paired-recent-events", SampleCount: 10, P95: time.Minute, Max: 2 * time.Minute},
			"logs-excluded": {Status: backend.EvidenceAssessed, Method: "paired-recent-events", SampleCount: 10, P95: 6 * time.Minute, Max: 7 * time.Minute},
		},
	}

	fieldEvidence, fieldsAssessment, err := collectRequiredFieldEvidence(context.Background(), probe, rules, g, sources)
	if err != nil {
		t.Fatal(err)
	}
	lagEvidence, lagAssessment, err := collectIngestLagEvidence(context.Background(), probe, rules, g, sources)
	if err != nil {
		t.Fatal(err)
	}
	if fieldsAssessment.Status != backend.EvidenceAssessed || lagAssessment.Status != backend.EvidenceAssessed {
		t.Fatalf("measurement status = fields %+v, lag %+v", fieldsAssessment, lagAssessment)
	}
	for i := range sources {
		sources[i].IngestLag = lagEvidence[sources[i].Name]
	}

	r := report.BuildWithOptions("elastic", graph.Build(rules, sources), report.BuildOptions{
		Check:         health.Check{MaxStale: time.Hour, Now: func() time.Time { return now }},
		Scope:         map[string]bool{"logs-included": true},
		FieldEvidence: fieldEvidence,
	})
	if len(r.Sources) != 1 || r.Sources[0].Name != "logs-included" || r.Summary.Sources != 1 {
		t.Fatalf("listing scope was not preserved: %+v", r.Sources)
	}
	if len(r.ImpairedDetections) != 1 {
		t.Fatalf("excluded source findings were hidden: %+v", r.ImpairedDetections)
	}
	impaired := r.ImpairedDetections[0]
	if len(impaired.Reasons) != 2 || impaired.Reasons[0] != report.ReasonMissingFields || impaired.Reasons[1] != report.ReasonLagBlindWindow ||
		len(impaired.MissingFields) != 1 || impaired.MissingFields[0] != "process.name" ||
		len(impaired.LagSources) != 1 || impaired.LagSources[0] != "logs-excluded" {
		t.Fatalf("excluded source evidence did not produce both findings: %+v", impaired)
	}
	if len(r.RequiredFieldEvidence) != 1 || len(r.RequiredFieldEvidence[0].Sources) != 2 {
		t.Fatalf("required-field evidence omitted the excluded verdict source: %+v", r.RequiredFieldEvidence)
	}
	for _, source := range r.RequiredFieldEvidence[0].Sources {
		if source.Source == "logs-excluded" && (source.Status != backend.EvidenceAssessed || len(source.Missing) != 1) {
			t.Fatalf("excluded source evidence = %+v, want assessed missing field", source)
		}
	}
}
