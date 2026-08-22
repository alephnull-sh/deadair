package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	backendpkg "github.com/alephnull-sh/deadair/internal/backend"
)

type enrichmentProbe struct {
	sentinelReportProbe
	provenanceCalls  int
	lineageCalls     int
	summaryRunCalls  int
	lineageRules     []backendpkg.Rule
	provenanceErr    error
	lineageErr       error
	summaryRunErr    error
	summaryRunStatus string
	waitForContext   bool
}

func (p *enrichmentProbe) SummaryRuleRunEvidence(ctx context.Context, rules []backendpkg.Rule) ([]backendpkg.SummaryRuleRunEvidence, error) {
	p.summaryRunCalls++
	if p.waitForContext {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if p.summaryRunErr != nil {
		return nil, p.summaryRunErr
	}
	status := p.summaryRunStatus
	if status == "" {
		status = "Succeeded"
	}
	item := backendpkg.SummaryRuleRunEvidence{
		ID: "summary-1", Rule: backendpkg.DependencyRef{ID: "summary-1", Name: "Summary 1", Kind: "sentinel_summary_rule"},
		Output: backendpkg.DependencyRef{ID: "TableSummary_CL", Name: "TableSummary_CL", Kind: "telemetry_table", Monitorable: true, Required: true},
		Status: backendpkg.EvidenceAssessed, Method: "fixture-summary-runs", ObservedAt: time.Now().UTC(),
		RunAt: time.Now().UTC(), RunStatus: status, QueryDurationMillis: 1250, ResultCount: 8,
	}
	if status == "Failed" {
		item.Error = "fixture summary query failed"
	}
	return []backendpkg.SummaryRuleRunEvidence{item}, nil
}

func TestSummaryRuleRuntimeFailureIsVisibleButDoesNotGate(t *testing.T) {
	probe := &enrichmentProbe{summaryRunStatus: "Failed"}
	result, err := scanOnce(context.Background(), probe, connOpts{maxStale: time.Hour}, "lab", "target-sentinel")
	if err != nil {
		t.Fatal(err)
	}
	if result.report.ExitCode() != 0 || len(result.report.DeadDetections) != 0 || len(result.report.ImpairedDetections) != 0 {
		t.Fatalf("summary runtime evidence changed findings or exit: %+v", result.report.Summary)
	}
	for name, render := range map[string]func(*bytes.Buffer){
		"plain":  func(output *bytes.Buffer) { printPlainSummary(output, result.report) },
		"visual": func(output *bytes.Buffer) { printVisualSummary(output, result.report) },
	} {
		t.Run(name, func(t *testing.T) {
			var output bytes.Buffer
			render(&output)
			if !strings.Contains(strings.ToLower(output.String()), "summary pipeline") || !strings.Contains(output.String(), "Failed") {
				t.Fatalf("%s summary runtime output = %q", name, output.String())
			}
		})
	}
}

func (p *enrichmentProbe) ProvenanceEvidence(ctx context.Context, rules []backendpkg.Rule) ([]backendpkg.ProvenanceEvidence, error) {
	p.provenanceCalls++
	if p.waitForContext {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if p.provenanceErr != nil {
		return nil, p.provenanceErr
	}
	return []backendpkg.ProvenanceEvidence{{
		RuleID: rules[0].ID,
		Provenance: backendpkg.ProvenanceRef{
			ID: "package-1", Name: "Package 1", Kind: "sentinel_content_package",
		},
		Status: backendpkg.EvidenceAssessed, Method: "fixture-provenance", ObservedAt: time.Now().UTC(),
	}}, nil
}

func (p *enrichmentProbe) LineageEvidence(ctx context.Context, rules []backendpkg.Rule) ([]backendpkg.LineageEvidence, error) {
	p.lineageCalls++
	p.lineageRules = append([]backendpkg.Rule(nil), rules...)
	if p.waitForContext {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if p.lineageErr != nil {
		return nil, p.lineageErr
	}
	return []backendpkg.LineageEvidence{{
		ID: "summary-1/table-a", Kind: "sentinel_summary_rule", Name: "Summary 1",
		Input:  backendpkg.DependencyRef{ID: "TableA", Name: "TableA", Kind: "telemetry_table", Monitorable: true, Required: true},
		Output: backendpkg.DependencyRef{ID: "TableSummary_CL", Name: "TableSummary_CL", Kind: "telemetry_table", Monitorable: true, Required: true},
		Status: backendpkg.EvidenceAssessed, Method: "fixture-lineage", ObservedAt: time.Now().UTC(),
	}}, nil
}

func TestScanCarriesReadOnlyBackendEnrichment(t *testing.T) {
	probe := &enrichmentProbe{}
	result, err := scanOnce(context.Background(), probe, connOpts{maxStale: time.Hour}, "lab", "target-sentinel")
	if err != nil {
		t.Fatal(err)
	}
	if probe.provenanceCalls != 1 || probe.lineageCalls != 1 || probe.summaryRunCalls != 1 {
		t.Fatalf("provider calls = provenance %d, lineage %d, summary runs %d", probe.provenanceCalls, probe.lineageCalls, probe.summaryRunCalls)
	}
	if len(probe.lineageRules) != 1 || probe.lineageRules[0].ID != "rule-1" {
		t.Fatalf("lineage rule inventory = %+v", probe.lineageRules)
	}
	if len(result.report.RuleProvenance) != 1 || result.report.RuleProvenance[0].Provenance.ID != "package-1" {
		t.Fatalf("rule provenance = %+v", result.report.RuleProvenance)
	}
	if len(result.report.SourceLineage) != 1 || result.report.SourceLineage[0].Output.Name != "TableSummary_CL" {
		t.Fatalf("source lineage = %+v", result.report.SourceLineage)
	}
	if len(result.report.SummaryRuleRuns) != 1 || result.report.SummaryRuleRuns[0].RunStatus != "Succeeded" {
		t.Fatalf("summary rule runs = %+v", result.report.SummaryRuleRuns)
	}
}

func TestReadOnlyBackendEnrichmentFailureIsVisibleButNonfatal(t *testing.T) {
	probe := &enrichmentProbe{
		provenanceErr: errors.New("private provenance error"),
		lineageErr:    errors.New("private lineage error"),
		summaryRunErr: errors.New("private summary-run error"),
	}
	rules, err := probe.Rules(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	provenance, lineage, summaryRuns, err := collectReadOnlyEnrichment(context.Background(), probe, rules, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(provenance) != 1 || provenance[0].Status != backendpkg.EvidenceUnavailable || provenance[0].Detail != "rule provenance could not be read" {
		t.Fatalf("fallback provenance = %+v", provenance)
	}
	if len(lineage) != 1 || lineage[0].Status != backendpkg.EvidenceUnavailable || lineage[0].Detail != "source lineage could not be read" {
		t.Fatalf("fallback lineage = %+v", lineage)
	}
	if len(summaryRuns) != 1 || summaryRuns[0].Status != backendpkg.EvidenceUnavailable || summaryRuns[0].Detail != "summary-rule runtime evidence could not be read" {
		t.Fatalf("fallback summary runs = %+v", summaryRuns)
	}
	if probe.provenanceCalls != 1 || probe.lineageCalls != 1 || probe.summaryRunCalls != 1 {
		t.Fatalf("provider calls = provenance %d, lineage %d, summary runs %d", probe.provenanceCalls, probe.lineageCalls, probe.summaryRunCalls)
	}
}

func TestCandidateScanSkipsWorkspaceWideEnrichment(t *testing.T) {
	probe := &enrichmentProbe{}
	provenance, lineage, summaryRuns, err := collectReadOnlyEnrichment(context.Background(), probe, []backendpkg.Rule{{ID: "candidate"}}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(provenance) != 0 || len(lineage) != 0 || len(summaryRuns) != 0 || probe.provenanceCalls != 0 || probe.lineageCalls != 0 || probe.summaryRunCalls != 0 {
		t.Fatalf("candidate enrichment = provenance %+v, lineage %+v, summary runs %+v, calls %d/%d/%d", provenance, lineage, summaryRuns, probe.provenanceCalls, probe.lineageCalls, probe.summaryRunCalls)
	}
}

func TestReadOnlyBackendEnrichmentTimeoutIsNonfatal(t *testing.T) {
	previous := readOnlyEnrichmentTimeout
	readOnlyEnrichmentTimeout = time.Millisecond
	defer func() { readOnlyEnrichmentTimeout = previous }()

	probe := &enrichmentProbe{waitForContext: true}
	rules, err := probe.Rules(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	provenance, lineage, summaryRuns, err := collectReadOnlyEnrichment(context.Background(), probe, rules, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(provenance) != 1 || provenance[0].Status != backendpkg.EvidenceUnavailable ||
		len(lineage) != 1 || lineage[0].Status != backendpkg.EvidenceUnavailable ||
		len(summaryRuns) != 1 || summaryRuns[0].Status != backendpkg.EvidenceUnavailable {
		t.Fatalf("timed-out enrichment = provenance %+v, lineage %+v, summary runs %+v", provenance, lineage, summaryRuns)
	}
}

func TestReadOnlyBackendEnrichmentHonorsParentCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	probe := &enrichmentProbe{waitForContext: true}
	_, _, _, err := collectReadOnlyEnrichment(ctx, probe, []backendpkg.Rule{{ID: "rule"}}, false)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("parent cancellation error = %v", err)
	}
}
