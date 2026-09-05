package report

import (
	"testing"
	"time"

	"github.com/alephnull-sh/deadair/internal/backend"
	"github.com/alephnull-sh/deadair/internal/graph"
	"github.com/alephnull-sh/deadair/internal/health"
)

func TestProducerFindingsMaintenanceAndRecovery(t *testing.T) {
	now := time.Now().UTC()
	p := &Policy{Version: 1, GateClasses: []string{FindingProducerStale}, Producers: []ProducerPolicy{{ID: "edge-fw", Source: "CommonSecurityLog", Match: map[string]string{"DeviceName": "fw-london-01"}, MaxStale: "15m"}}}
	if err := p.validate(now); err != nil {
		t.Fatal(err)
	}
	rules := []backend.Rule{{ID: "feed", Name: "Firewall rule", Enabled: true, Severity: "high", Patterns: []string{"CommonSecurityLog"}}, {ID: "other", Name: "Other vendor", Enabled: true, Patterns: []string{"CommonSecurityLog"}}}
	g := graph.Build(rules, []backend.Source{{Name: "CommonSecurityLog", Docs: 100, LastEvent: now}})
	item := backend.ProducerEvidence{ID: "edge-fw", Source: "CommonSecurityLog", ConfirmedRules: []string{"feed"}, Freshness: backend.FreshnessEvidence{Status: backend.EvidenceAssessed, LastEvent: now.Add(-time.Hour), ObservedAt: now, Window: 24 * time.Hour}}
	opts := BuildOptions{Policy: p, Check: health.Check{MaxStale: time.Hour, Now: func() time.Time { return now }}, ProducerEvidence: []backend.ProducerEvidence{item}}
	r := BuildWithOptions("sentinel", g, opts)
	if len(r.Findings) != 1 || r.Findings[0].Class != FindingProducerStale || r.ExitCode() != ExitFindings || len(r.DeadDetections) != 0 {
		t.Fatalf("producer gate: %+v", r.Findings)
	}
	feed := r.Producers[0]
	if len(feed.ConfirmedDetections) != 1 || feed.ConfirmedDetections[0].RuleID != "feed" || len(feed.OtherTableConsumers) != 1 {
		t.Fatalf("producer associations: %+v", feed)
	}
	previous := r.Findings[0]
	opts.Scope = map[string]bool{"OtherTable": true}
	r = BuildWithOptions("sentinel", g, opts)
	if len(r.SourceImpacts) != 0 || len(r.Producers[0].ConfirmedDetections) != 1 {
		t.Fatal("source display filter erased producer dependencies")
	}
	opts.Scope = nil
	opts.Check.Downtime = []health.DowntimeWindow{{Patterns: []string{"producer:edge-fw"}, Start: 0, End: 24 * time.Hour}}
	r = BuildWithOptions("sentinel", g, opts)
	if len(r.Findings) != 1 || !r.Findings[0].Suppressed || r.ExitCode() != ExitHealthy || r.Producers[0].Observation.FreshnessStatus != "stale" {
		t.Fatalf("maintenance erased observation: %+v", r)
	}
	if findingRecoveryConfirmed(r, previous) {
		t.Fatal("maintenance became recovery")
	}
	opts.Check.Downtime = nil
	for _, status := range []backend.EvidenceStatus{backend.EvidenceUnavailable, backend.EvidenceIncomplete} {
		opts.ProducerEvidence[0].Freshness.Status = status
		r = BuildWithOptions("sentinel", g, opts)
		if findingRecoveryConfirmed(r, previous) {
			t.Fatal("missing evidence became recovery")
		}
	}
	opts.ProducerEvidence[0].Freshness = backend.FreshnessEvidence{Status: backend.EvidenceAssessed, LastEvent: now, ObservedAt: previous.LastSeen.Add(time.Minute), Window: 24 * time.Hour}
	r = BuildWithOptions("sentinel", g, opts)
	if !findingRecoveryConfirmed(r, previous) {
		t.Fatal("fresh successful evidence did not recover")
	}
}

func TestSummaryFindingRequiresPolicyAndPositiveRecovery(t *testing.T) {
	now := time.Now().UTC()
	item := backend.SummaryRuleRunEvidence{ID: "network-hourly", Output: backend.DependencyRef{Name: "NetworkSummary_CL"}, Status: backend.EvidenceAssessed, ObservedAt: now, RunAt: now.Add(-time.Minute), RunStatus: "Failed"}
	r := BuildWithOptions("sentinel", emptyGraph(), BuildOptions{SummaryRuleRunEvidence: []backend.SummaryRuleRunEvidence{item}})
	if len(r.Findings) != 1 || r.ExitCode() != ExitHealthy {
		t.Fatalf("default pipeline finding: %+v", r.Findings)
	}
	previous := r.Findings[0]
	item.RunStatus = "Succeeded"
	item.Overdue = true
	item.Status = backend.EvidenceIncomplete
	r = BuildWithOptions("sentinel", emptyGraph(), BuildOptions{SummaryRuleRunEvidence: []backend.SummaryRuleRunEvidence{item}})
	if r.SummaryRuleRuns[0].HealthStatus != "late" || r.Findings[0].ID != previous.ID || findingRecoveryConfirmed(r, previous) {
		t.Fatal("overdue success recovered the pipeline")
	}
	item.Overdue = false
	item.Status = backend.EvidenceAssessed
	item.ObservedAt = previous.LastSeen.Add(time.Minute)
	r = BuildWithOptions("sentinel", emptyGraph(), BuildOptions{SummaryRuleRunEvidence: []backend.SummaryRuleRunEvidence{item}})
	if findingRecoveryConfirmed(r, previous) {
		t.Fatal("rereading an old successful execution became recovery")
	}
	item.RunAt = previous.LastSeen.Add(30 * time.Second)
	r = BuildWithOptions("sentinel", emptyGraph(), BuildOptions{SummaryRuleRunEvidence: []backend.SummaryRuleRunEvidence{item}})
	if !findingRecoveryConfirmed(r, previous) {
		t.Fatal("current successful pipeline did not recover")
	}
}

func TestUnavailableSummaryCannotBecomeOverdueFromAFlagAlone(t *testing.T) {
	now := time.Now().UTC()
	for _, status := range []backend.EvidenceStatus{backend.EvidenceUnavailable, backend.EvidenceDisabled} {
		item := backend.SummaryRuleRunEvidence{Status: status, RunStatus: "Succeeded", RunAt: now.Add(-time.Hour), ObservedAt: now, Overdue: true}
		if got := summaryHealth(item); got != "unknown" {
			t.Fatalf("%s evidence became %s", status, got)
		}
	}
}

func TestRedactedSummaryRecoveryKeepsEvidenceIdentity(t *testing.T) {
	now := time.Now().UTC()
	newReport := func() *Report {
		return &Report{SchemaVersion: ReportSchemaVersion, Backend: "sentinel", Instance: "workspace", TargetID: "target",
			Scope: ScanScope{Mode: "installed", ConfigurationID: "config"}}
	}
	older := newReport()
	older.Findings = []Finding{{ID: "finding", Class: FindingSummaryPipeline, Source: "NetworkSummary_CL", Dependency: "network-summary#latest-run", LastSeen: now}}
	newer := newReport()
	runAt := now.Add(time.Minute)
	newer.SummaryRuleRuns = []SummaryRuleRun{{ID: "network-summary#latest-run", Output: backend.DependencyRef{Name: "NetworkSummary_CL", Monitorable: true},
		Status: backend.EvidenceAssessed, HealthStatus: "ok", RunStatus: "Succeeded", RunAt: &runAt, ObservedAt: runAt.Add(time.Minute)}}
	older.Redact()
	newer.Redact()
	if older.Findings[0].Dependency != newer.SummaryRuleRuns[0].ID {
		t.Fatal("redaction broke the finding-to-execution identity")
	}
	diff, err := Diff(older, newer)
	if err != nil || len(diff.RecoveredFindings) != 1 || diff.RecoveredFindings[0].ID != older.Findings[0].ID {
		t.Fatalf("redacted summary recovery: %+v, %v", diff, err)
	}
}
