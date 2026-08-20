package report

import (
	"testing"
	"time"

	"github.com/alephnull-sh/deadair/internal/backend"
	"github.com/alephnull-sh/deadair/internal/graph"
	"github.com/alephnull-sh/deadair/internal/health"
	"github.com/alephnull-sh/deadair/internal/state"
)

func recoveryOptions(store *state.Store, assessments ...RuntimeAssessment) BuildOptions {
	return BuildOptions{
		Check: health.Check{MaxStale: time.Hour}, Store: store,
		TargetID: "target-prod", Instance: "prod",
		ScanScope:   ScanScope{Mode: "installed", Stateful: store != nil, ConfigurationID: "config-1"},
		Assessments: assessments,
	}
}

func TestLifecycleDoesNotRecoverDisconnectedFindingWhenResolutionBecomesUnavailable(t *testing.T) {
	store := state.New()
	rule := backend.Rule{ID: "rule-1", Name: "Rule", Enabled: true, Severity: "high", Patterns: []string{"logs-*"}}
	first := BuildWithOptions("elastic", graph.BuildResolved([]backend.Rule{rule}, nil, []backend.InputResolution{{
		RuleID: rule.ID, Expression: "logs-*", Status: backend.ResolutionEmpty, ObservedAt: time.Now().UTC(),
	}}), recoveryOptions(store, RuntimeAssessment{Name: AssessmentSourceResolution, Status: backend.EvidenceAssessed}))
	if len(first.Findings) != 1 || first.Findings[0].Class != FindingDead {
		t.Fatalf("first findings = %+v, want disconnected finding", first.Findings)
	}

	second := BuildWithOptions("elastic", graph.BuildResolved([]backend.Rule{rule}, nil, []backend.InputResolution{{
		RuleID: rule.ID, Expression: "logs-*", Status: backend.ResolutionUnavailable,
		ObservedAt: time.Now().UTC(), Detail: "resolver unavailable",
	}}), recoveryOptions(store, RuntimeAssessment{Name: AssessmentSourceResolution, Status: backend.EvidenceIncomplete}))
	if len(second.Findings) != 0 || len(second.RecoveredFindings) != 0 {
		t.Fatalf("incomplete resolution = findings %+v, recovered %+v; want neither", second.Findings, second.RecoveredFindings)
	}
	for _, stored := range store.Findings {
		if stored.FindingID == first.Findings[0].ID && !stored.Active {
			t.Fatal("incomplete resolution deactivated the prior finding")
		}
	}
}

func TestLifecycleRecoveryIgnoresAnotherRulesCollidingBackendObjectID(t *testing.T) {
	store := state.New()
	now := time.Now().UTC()
	recoveredRule := backend.Rule{
		ID: "logical-target", BackendObjectID: "saved-target", Name: "Recovered", Enabled: true,
		Severity: "high", Patterns: []string{"logs-*"},
	}
	uncertainRule := backend.Rule{
		ID: "logical-uncertain", BackendObjectID: recoveredRule.ID, Name: "Uncertain", Enabled: true,
		Severity: "low",
	}
	rules := []backend.Rule{recoveredRule, uncertainRule}
	first := BuildWithOptions("elastic", graph.BuildResolved(rules, nil, []backend.InputResolution{
		{RuleID: recoveredRule.ID, Expression: "logs-*", Status: backend.ResolutionEmpty, ObservedAt: now},
		{RuleID: uncertainRule.ID, Status: backend.ResolutionUnsupported, ObservedAt: now},
	}), recoveryOptions(store, RuntimeAssessment{Name: AssessmentSourceResolution, Status: backend.EvidenceAssessed}))
	if len(first.Findings) != 1 || first.Findings[0].RuleID != recoveredRule.ID {
		t.Fatalf("first findings = %+v, want disconnected %s finding", first.Findings, recoveredRule.ID)
	}

	second := BuildWithOptions("elastic", graph.BuildResolved(rules, []backend.Source{{
		Name: "logs-prod", Docs: 10, LastEvent: now,
	}}, []backend.InputResolution{
		{
			RuleID: recoveredRule.ID, Expression: "logs-*", Status: backend.ResolutionResolved,
			ResolvedSources: []string{"logs-prod"}, ObservedAt: now,
		},
		{RuleID: uncertainRule.ID, Status: backend.ResolutionUnsupported, ObservedAt: now},
	}), recoveryOptions(store, RuntimeAssessment{Name: AssessmentSourceResolution, Status: backend.EvidenceAssessed}))
	if len(second.UnmappedRules) != 1 || second.UnmappedRules[0].ID != recoveredRule.ID ||
		second.UnmappedRules[0].RuleID != uncertainRule.ID {
		t.Fatalf("unmapped collision setup = %+v", second.UnmappedRules)
	}
	if len(second.RecoveredFindings) != 1 || second.RecoveredFindings[0].ID != first.Findings[0].ID {
		t.Fatalf("recovered findings = %+v, want %s", second.RecoveredFindings, first.Findings[0].ID)
	}
}

func TestLifecycleRequiresCompleteRequiredFieldEvidenceForRecovery(t *testing.T) {
	store := state.New()
	now := time.Now().UTC()
	rule := backend.Rule{
		ID: "rule-fields", Name: "Field rule", Enabled: true, Severity: "medium",
		Patterns: []string{"logs-*"}, RequiredFields: []string{"process.name"},
	}
	sources := []backend.Source{{Name: "logs-app", Docs: 10, LastEvent: now}}
	g := graph.Build([]backend.Rule{rule}, sources)
	firstOptions := recoveryOptions(store, RuntimeAssessment{Name: AssessmentRequiredFields, Status: backend.EvidenceAssessed})
	firstOptions.FieldEvidence = map[string]backend.FieldEvidence{
		"logs-app": {Status: backend.EvidenceAssessed, Fields: map[string]bool{}},
	}
	first := BuildWithOptions("elastic", g, firstOptions)
	if len(first.Findings) != 1 || first.Findings[0].Reason != ReasonMissingFields {
		t.Fatalf("first findings = %+v, want missing-field finding", first.Findings)
	}

	incompleteOptions := recoveryOptions(store, RuntimeAssessment{Name: AssessmentRequiredFields, Status: backend.EvidenceIncomplete})
	incompleteOptions.FieldEvidence = map[string]backend.FieldEvidence{
		"logs-app": {Status: backend.EvidenceIncomplete, Detail: "field capabilities unavailable"},
	}
	incomplete := BuildWithOptions("elastic", g, incompleteOptions)
	if len(incomplete.Findings) != 0 || len(incomplete.RecoveredFindings) != 0 {
		t.Fatalf("incomplete fields = findings %+v, recovered %+v; want neither", incomplete.Findings, incomplete.RecoveredFindings)
	}

	completeOptions := recoveryOptions(store, RuntimeAssessment{Name: AssessmentRequiredFields, Status: backend.EvidenceAssessed})
	completeOptions.FieldEvidence = map[string]backend.FieldEvidence{
		"logs-app": {Status: backend.EvidenceAssessed, Fields: map[string]bool{"process.name": true}},
	}
	complete := BuildWithOptions("elastic", g, completeOptions)
	if len(complete.RecoveredFindings) != 1 || complete.RecoveredFindings[0].ID != first.Findings[0].ID {
		t.Fatalf("complete field recovery = %+v, want %s", complete.RecoveredFindings, first.Findings[0].ID)
	}
}

func TestDiffDoesNotCallLostEvidenceARecovery(t *testing.T) {
	now := time.Now().UTC()
	rule := backend.Rule{
		ID: "rule-fields", Name: "Field rule", Enabled: true, Severity: "medium",
		Patterns: []string{"logs-*"}, RequiredFields: []string{"process.name"},
	}
	sources := []backend.Source{{Name: "logs-app", Docs: 10, LastEvent: now}}
	g := graph.Build([]backend.Rule{rule}, sources)
	oldOptions := recoveryOptions(nil, RuntimeAssessment{Name: AssessmentRequiredFields, Status: backend.EvidenceAssessed})
	oldOptions.FieldEvidence = map[string]backend.FieldEvidence{
		"logs-app": {Status: backend.EvidenceAssessed, Fields: map[string]bool{}},
	}
	older := BuildWithOptions("elastic", g, oldOptions)

	newOptions := recoveryOptions(nil, RuntimeAssessment{Name: AssessmentRequiredFields, Status: backend.EvidenceIncomplete})
	newOptions.FieldEvidence = map[string]backend.FieldEvidence{
		"logs-app": {Status: backend.EvidenceIncomplete, Detail: "field capabilities unavailable"},
	}
	newer := BuildWithOptions("elastic", g, newOptions)
	diff, err := Diff(older, newer)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.RecoveredFindings) != 0 || len(diff.RecoveredImpaired) != 0 {
		t.Fatalf("lost evidence was reported recovered: %+v", diff)
	}

	resolvedOptions := recoveryOptions(nil, RuntimeAssessment{Name: AssessmentRequiredFields, Status: backend.EvidenceAssessed})
	resolvedOptions.FieldEvidence = map[string]backend.FieldEvidence{
		"logs-app": {Status: backend.EvidenceAssessed, Fields: map[string]bool{"process.name": true}},
	}
	resolved := BuildWithOptions("elastic", g, resolvedOptions)
	diff, err = Diff(older, resolved)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.RecoveredFindings) != 1 || len(diff.RecoveredImpaired) != 1 {
		t.Fatalf("complete recovery missing from diff: %+v", diff)
	}
}

func TestDiffDoesNotRecoverDisconnectedFindingWhenResolutionIsUnavailable(t *testing.T) {
	rule := backend.Rule{ID: "rule-1", Name: "Rule", Enabled: true, Severity: "high", Patterns: []string{"logs-*"}}
	observedAt := time.Now().UTC()
	older := BuildWithOptions("elastic", graph.BuildResolved([]backend.Rule{rule}, nil, []backend.InputResolution{{
		RuleID: rule.ID, Expression: "logs-*", Status: backend.ResolutionEmpty, ObservedAt: observedAt,
	}}), recoveryOptions(nil, RuntimeAssessment{Name: AssessmentSourceResolution, Status: backend.EvidenceAssessed}))
	newer := BuildWithOptions("elastic", graph.BuildResolved([]backend.Rule{rule}, nil, []backend.InputResolution{{
		RuleID: rule.ID, Expression: "logs-*", Status: backend.ResolutionUnavailable,
		ObservedAt: observedAt.Add(time.Minute), Detail: "resolver unavailable",
	}}), recoveryOptions(nil, RuntimeAssessment{Name: AssessmentSourceResolution, Status: backend.EvidenceIncomplete}))

	diff, err := Diff(older, newer)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.RecoveredFindings) != 0 || len(diff.RecoveredDead) != 0 {
		t.Fatalf("lost resolution was reported recovered: %+v", diff)
	}
}

func TestMissingFieldFindingMovesBetweenConcreteSources(t *testing.T) {
	store := state.New()
	now := time.Now().UTC()
	rule := backend.Rule{
		ID: "rule-fields", Name: "Field rule", Enabled: true, Severity: "high",
		Patterns: []string{"logs-*"}, RequiredFields: []string{"process.name"},
	}
	sources := []backend.Source{
		{Name: "logs-a", Docs: 10, LastEvent: now},
		{Name: "logs-b", Docs: 10, LastEvent: now},
	}
	g := graph.Build([]backend.Rule{rule}, sources)
	build := func(store *state.Store, missing string) *Report {
		options := recoveryOptions(store, RuntimeAssessment{Name: AssessmentRequiredFields, Status: backend.EvidenceAssessed})
		options.FieldEvidence = map[string]backend.FieldEvidence{
			"logs-a": {Status: backend.EvidenceAssessed, Fields: map[string]bool{"process.name": missing != "logs-a"}},
			"logs-b": {Status: backend.EvidenceAssessed, Fields: map[string]bool{"process.name": missing != "logs-b"}},
		}
		return BuildWithOptions("elastic", g, options)
	}

	first := build(store, "logs-a")
	if len(first.Findings) != 1 || first.Findings[0].Source != "logs-a" || first.Findings[0].Dependency != "process.name" {
		t.Fatalf("first findings = %+v, want logs-a/process.name", first.Findings)
	}
	second := build(store, "logs-b")
	if len(second.Findings) != 1 || second.Findings[0].Source != "logs-b" || second.Findings[0].ID == first.Findings[0].ID {
		t.Fatalf("second findings = %+v, want distinct logs-b finding", second.Findings)
	}
	if len(second.RecoveredFindings) != 1 || second.RecoveredFindings[0].Source != "logs-a" {
		t.Fatalf("lifecycle recovery = %+v, want logs-a", second.RecoveredFindings)
	}

	older, newer := build(nil, "logs-a"), build(nil, "logs-b")
	diff, err := Diff(older, newer)
	if err != nil {
		t.Fatal(err)
	}
	if diff.Regressions() != 1 || len(diff.NewFindings) != 1 || diff.NewFindings[0].Source != "logs-b" {
		t.Fatalf("movement regression = %+v, want one new logs-b finding", diff)
	}
	if len(diff.RecoveredFindings) != 1 || diff.RecoveredFindings[0].Source != "logs-a" {
		t.Fatalf("movement recovery = %+v, want logs-a", diff.RecoveredFindings)
	}
	if len(diff.NewlyImpaired) != 1 || len(diff.NewlyImpaired[0].Sources) != 1 || diff.NewlyImpaired[0].Sources[0] != "logs-b" {
		t.Fatalf("legacy impairment projection = %+v, want only logs-b", diff.NewlyImpaired)
	}
}
