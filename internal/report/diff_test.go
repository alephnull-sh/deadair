package report

import "testing"

func comparableReport() *Report {
	return &Report{
		SchemaVersion: ReportSchemaVersion,
		Backend:       "elastic",
		Instance:      "prod",
		TargetID:      "target-prod",
		Scope:         ScanScope{Mode: "installed", Include: []string{"logs-*"}, ConfigurationID: "config-1"},
	}
}

func TestDiffTracksImpairmentDependencies(t *testing.T) {
	older := comparableReport()
	older.Findings = []Finding{{
		ID: "field-a", Class: FindingImpaired, RuleID: "rule-1",
		Reason: ReasonMissingFields, Dependency: "field.a",
	}}
	newer := comparableReport()
	newer.ImpairedDetections = []ImpairedDetection{{
		ID: "rule-1", Name: "Rule", Severity: "high",
		Reasons: []string{ReasonMissingFields}, MissingFields: []string{"field.a", "field.b"},
	}}
	newer.Findings = []Finding{
		{ID: "field-a", Class: FindingImpaired, RuleID: "rule-1", Reason: ReasonMissingFields, Dependency: "field.a"},
		{ID: "field-b", Class: FindingImpaired, RuleID: "rule-1", Reason: ReasonMissingFields, Dependency: "field.b"},
	}
	d, err := Diff(older, newer)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.NewFindings) != 1 || d.NewFindings[0].Dependency != "field.b" {
		t.Fatalf("new findings = %+v", d.NewFindings)
	}
	if len(d.NewlyImpaired) != 1 || len(d.NewlyImpaired[0].MissingFields) != 1 || d.NewlyImpaired[0].MissingFields[0] != "field.b" {
		t.Fatalf("new impaired detail = %+v", d.NewlyImpaired)
	}
}

func TestDiffRejectsIncomparableReports(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Report)
	}{
		{"schema", func(r *Report) { r.SchemaVersion = "other" }},
		{"backend", func(r *Report) { r.Backend = "opensearch" }},
		{"instance", func(r *Report) { r.Instance = "staging" }},
		{"target", func(r *Report) { r.TargetID = "target-other" }},
		{"scope", func(r *Report) { r.Scope.Exclude = []string{"metrics-*"} }},
		{"redaction mode", func(r *Report) {
			r.Redacted = true
			r.Redaction = &RedactionMetadata{Algorithm: "hmac-sha256", KeyID: "key-1"}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			older, newer := comparableReport(), comparableReport()
			tt.mutate(newer)
			if _, err := Diff(older, newer); err == nil {
				t.Fatal("incomparable reports were accepted")
			}
		})
	}
}

func TestDiffAcceptsEquivalentScopeOrdering(t *testing.T) {
	older, newer := comparableReport(), comparableReport()
	older.Scope.Include = []string{"metrics-*", "logs-*"}
	newer.Scope.Include = []string{"logs-*", "metrics-*"}
	if _, err := Diff(older, newer); err != nil {
		t.Fatalf("equivalent scopes rejected: %v", err)
	}
}

func TestDiffDetectsExistingFindingBecomingGated(t *testing.T) {
	older, newer := comparableReport(), comparableReport()
	older.Policy = &PolicySummary{Version: 1, GateClasses: []string{FindingDead}, AcceptedActive: 1}
	newer.Policy = &PolicySummary{Version: 1, GateClasses: []string{FindingDead}, AcceptedExpired: 1}
	older.Findings = []Finding{{
		ID: "persistent", Class: FindingDead, RuleID: "rule-1", RuleName: "Rule",
		Reason: ReasonStarved, Gates: false,
		Accepted: &FindingAcceptance{Status: "active", Reason: "migration"},
	}}
	newer.Findings = []Finding{{
		ID: "persistent", Class: FindingDead, RuleID: "rule-1", RuleName: "Rule",
		Reason: ReasonStarved, Gates: true,
		Accepted: &FindingAcceptance{Status: "expired", Reason: "migration"},
	}}
	d, err := Diff(older, newer)
	if err != nil {
		t.Fatal(err)
	}
	if d.Regressions() != 1 || len(d.NewlyGatedFindings) != 1 || len(d.NewFindings) != 0 {
		t.Fatalf("gate transition = %+v", d)
	}
}
