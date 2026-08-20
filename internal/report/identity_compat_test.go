package report

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/alephnull-sh/deadair/internal/backend"
	"github.com/alephnull-sh/deadair/internal/graph"
	"github.com/alephnull-sh/deadair/internal/health"
)

func TestReportPreservesV1BackendIDsAndAddsLogicalRuleIDs(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	rules := []backend.Rule{
		{ID: "logical-dead", BackendObjectID: "saved-dead", Name: "Dead", Enabled: true, Severity: "high", Patterns: []string{"missing-*"}},
		{ID: "logical-impaired", BackendObjectID: "saved-impaired", Name: "Impaired", Enabled: true, Severity: "medium", Patterns: []string{"logs-*"}, RequiredFields: []string{"host.name"}},
		{ID: "logical-unmapped", BackendObjectID: "saved-unmapped", Name: "Unmapped", Enabled: true, Severity: "low"},
		{ID: "logical-remote", BackendObjectID: "saved-remote", Name: "Remote", Enabled: true, Severity: "low", Patterns: []string{"archive:logs-*"}},
	}
	resolutions := []backend.InputResolution{
		{RuleID: "logical-dead", Expression: "missing-*", SelectorKind: "index_expression", ResolutionMethod: "resolve_index", ObservedAt: now, Status: backend.ResolutionEmpty},
		{RuleID: "logical-impaired", Expression: "logs-*", SelectorKind: "index_expression", ResolvedSources: []string{"logs-prod"}, ResolutionMethod: "resolve_index", ObservedAt: now, Status: backend.ResolutionResolved},
		{RuleID: "logical-unmapped", SelectorKind: "rule_metadata", ResolutionMethod: "rule_inventory", ObservedAt: now, Status: backend.ResolutionUnsupported},
		{RuleID: "logical-remote", Selector: "archive:logs-*", SelectorKind: "remote_index", ResolutionMethod: "remote_selector", ObservedAt: now, Status: backend.ResolutionRemote},
	}
	r := BuildWithOptions("elastic", graph.BuildResolved(rules, []backend.Source{{
		Name: "logs-prod", Docs: 10, LastEvent: now,
	}}, resolutions), BuildOptions{
		Check:    health.Check{MaxStale: time.Hour, Now: func() time.Time { return now }},
		TargetID: "target", Instance: "prod",
		ScanScope: ScanScope{Mode: "installed", ConfigurationID: "config"},
		Assessments: []RuntimeAssessment{
			{Name: AssessmentSourceResolution, Status: backend.EvidenceAssessed},
			{Name: AssessmentRequiredFields, Status: backend.EvidenceAssessed},
		},
		FieldEvidence: map[string]backend.FieldEvidence{
			"logs-prod": {Status: backend.EvidenceAssessed, Fields: map[string]bool{}},
		},
	})

	if len(r.DeadDetections) != 1 || r.DeadDetections[0].ID != "saved-dead" ||
		r.DeadDetections[0].RuleID != "logical-dead" || r.DeadDetections[0].BackendObjectID != "saved-dead" {
		t.Fatalf("dead identity = %+v", r.DeadDetections)
	}
	if len(r.ImpairedDetections) != 1 || r.ImpairedDetections[0].ID != "saved-impaired" ||
		r.ImpairedDetections[0].RuleID != "logical-impaired" || r.ImpairedDetections[0].BackendObjectID != "saved-impaired" {
		t.Fatalf("impaired identity = %+v", r.ImpairedDetections)
	}
	if len(r.UnmappedRules) != 1 || r.UnmappedRules[0].ID != "saved-unmapped" ||
		r.UnmappedRules[0].RuleID != "logical-unmapped" || r.UnmappedRules[0].BackendObjectID != "saved-unmapped" {
		t.Fatalf("unmapped identity = %+v", r.UnmappedRules)
	}
	if len(r.RemoteRules) != 1 || r.RemoteRules[0].ID != "saved-remote" ||
		r.RemoteRules[0].RuleID != "logical-remote" || r.RemoteRules[0].BackendObjectID != "saved-remote" {
		t.Fatalf("remote identity = %+v", r.RemoteRules)
	}

	wantObjects := map[string]string{
		"logical-dead": "saved-dead", "logical-impaired": "saved-impaired",
		"logical-unmapped": "saved-unmapped", "logical-remote": "saved-remote",
	}
	for _, resolution := range r.InputResolutions {
		wantObject := wantObjects[resolution.LogicalRuleID]
		if wantObject == "" || resolution.RuleID != wantObject || resolution.BackendObjectID != wantObject {
			t.Fatalf("input resolution identity = %+v", resolution)
		}
	}
	for _, finding := range r.Findings {
		if finding.RuleID != "logical-dead" && finding.RuleID != "logical-impaired" {
			continue
		}
		if finding.BackendObjectID != wantObjects[finding.RuleID] {
			t.Fatalf("finding identity = %+v", finding)
		}
		if finding.RuleID == "logical-dead" {
			want := stableFindingID("target", "prod", "elastic", FindingDead, "logical-dead", ReasonDisconnected, "", "")
			if finding.ID != want {
				t.Fatalf("dead finding ID = %q, want logical identity %q", finding.ID, want)
			}
		}
	}

	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		DeadDetections []struct {
			ID              string `json:"id"`
			RuleID          string `json:"rule_id"`
			BackendObjectID string `json:"backend_object_id"`
		} `json:"dead_detections"`
		InputResolutions []struct {
			RuleID          string `json:"rule_id"`
			LogicalRuleID   string `json:"logical_rule_id"`
			BackendObjectID string `json:"backend_object_id"`
		} `json:"input_resolutions"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		t.Fatal(err)
	}
	if len(wire.DeadDetections) != 1 || wire.DeadDetections[0].ID != "saved-dead" ||
		wire.DeadDetections[0].RuleID != "logical-dead" || wire.DeadDetections[0].BackendObjectID != "saved-dead" {
		t.Fatalf("wire dead identity = %+v", wire.DeadDetections)
	}
	for _, resolution := range wire.InputResolutions {
		wantObject := wantObjects[resolution.LogicalRuleID]
		if wantObject == "" || resolution.RuleID != wantObject || resolution.BackendObjectID != wantObject {
			t.Fatalf("wire input resolution identity = %+v", resolution)
		}
	}
}

func TestDiffLegacyRuleRefsKeepBackendObjectID(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	rule := backend.Rule{ID: "logical-rule", BackendObjectID: "saved-rule", Name: "Rule", Enabled: true, Severity: "high", Patterns: []string{"logs-*"}}
	options := BuildOptions{
		Check:       health.Check{MaxStale: time.Hour, Now: func() time.Time { return now }},
		TargetID:    "target",
		Instance:    "prod",
		ScanScope:   ScanScope{Mode: "installed", ConfigurationID: "config"},
		Assessments: []RuntimeAssessment{{Name: AssessmentSourceResolution, Status: backend.EvidenceAssessed}},
	}
	dead := BuildWithOptions("elastic", graph.BuildResolved([]backend.Rule{rule}, nil, []backend.InputResolution{{
		RuleID: rule.ID, Expression: "logs-*", SelectorKind: "index_expression", ResolutionMethod: "resolve_index", ObservedAt: now, Status: backend.ResolutionEmpty,
	}}), options)
	healthy := BuildWithOptions("elastic", graph.BuildResolved([]backend.Rule{rule}, []backend.Source{{
		Name: "logs-prod", Docs: 10, LastEvent: now,
	}}, []backend.InputResolution{{
		RuleID: rule.ID, Expression: "logs-*", SelectorKind: "index_expression", ResolvedSources: []string{"logs-prod"}, ResolutionMethod: "resolve_index", ObservedAt: now, Status: backend.ResolutionResolved,
	}}), options)

	regression, err := Diff(healthy, dead)
	if err != nil {
		t.Fatal(err)
	}
	if len(regression.NewlyDead) != 1 || regression.NewlyDead[0].ID != "saved-rule" || regression.NewlyDead[0].RuleID != "logical-rule" {
		t.Fatalf("newly dead compatibility projection = %+v", regression.NewlyDead)
	}
	recovery, err := Diff(dead, healthy)
	if err != nil {
		t.Fatal(err)
	}
	if len(recovery.RecoveredDead) != 1 || recovery.RecoveredDead[0].ID != "saved-rule" || recovery.RecoveredDead[0].RuleID != "logical-rule" {
		t.Fatalf("recovered dead compatibility projection = %+v", recovery.RecoveredDead)
	}
}
