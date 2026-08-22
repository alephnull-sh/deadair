package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alephnull-sh/deadair/internal/backend"
	"github.com/alephnull-sh/deadair/internal/graph"
	"github.com/alephnull-sh/deadair/internal/health"
	redactpkg "github.com/alephnull-sh/deadair/internal/redact"
	"github.com/alephnull-sh/deadair/internal/state"
)

func incompatibleFixture(t *testing.T, incompatible, resolved []string, store *state.Store, policy *Policy) *Report {
	t.Helper()
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	rule := backend.Rule{
		ID: "rule-plans", BackendObjectID: "saved-plans", Name: "Plan-sensitive rule",
		Enabled: true, Severity: "high", Patterns: []string{"AnalyticsTable", "BasicTable"},
	}
	sources := []backend.Source{
		{Name: "AnalyticsTable", Docs: 10, LastEvent: now},
		{Name: "BasicTable", Docs: 10, LastEvent: now},
	}
	allInputs := append(append([]string(nil), incompatible...), resolved...)
	authoritative := backend.InputResolution{
		RuleID: rule.ID, Expression: strings.Join(allInputs, ","),
		SelectorKind: "query", ResolutionMethod: "source_configuration",
		ObservedAt: now, Status: backend.ResolutionIncompatible,
		Detail: "source configuration cannot be queried by this rule type",
	}
	if len(resolved) > 0 {
		authoritative.Status = backend.ResolutionResolved
		authoritative.Detail = ""
		authoritative.ResolvedSources = append([]string(nil), resolved...)
	}
	resolutions := []backend.InputResolution{authoritative}
	for _, source := range incompatible {
		resolutions = append(resolutions, backend.InputResolution{
			RuleID: rule.ID, Selector: source, Expression: source,
			Diagnostic: true, SelectorKind: "table", ResolutionMethod: "table_configuration_diagnostic",
			ObservedAt: now, Status: backend.ResolutionIncompatible,
			Detail: "source configuration cannot be queried by this rule type",
		})
	}
	for _, source := range resolved {
		resolutions = append(resolutions, backend.InputResolution{
			RuleID: rule.ID, Selector: source, Expression: source,
			Diagnostic: true, SelectorKind: "table", ResolutionMethod: "table_configuration_diagnostic",
			ObservedAt: now, Status: backend.ResolutionResolved, ResolvedSources: []string{source},
		})
	}
	return BuildWithOptions("test", graph.BuildResolved([]backend.Rule{rule}, sources, resolutions), BuildOptions{
		Check:       health.Check{MaxStale: time.Hour, Now: func() time.Time { return now }},
		Assessments: []RuntimeAssessment{{Name: AssessmentSourceResolution, Status: backend.EvidenceAssessed}},
		TargetID:    "target", Instance: "prod", Store: store, Policy: policy,
		ScanScope: ScanScope{Mode: "installed", Stateful: store != nil, ConfigurationID: "config"},
	})
}

func TestAllIncompatibleInputsProduceDeadFinding(t *testing.T) {
	r := incompatibleFixture(t, []string{"BasicTable", "AnalyticsTable"}, nil, nil, nil)
	if got := r.Summary.InputResolution; got.Incompatible != 2 || got.Resolved != 0 {
		t.Fatalf("input resolution summary = %+v, want two incompatible inputs", got)
	}
	if len(r.DeadDetections) != 1 || r.DeadDetections[0].Reason != ReasonSourcePlanIncompatible ||
		strings.Join(r.DeadDetections[0].Sources, ",") != "AnalyticsTable,BasicTable" {
		t.Fatalf("dead detections = %+v", r.DeadDetections)
	}
	if len(r.ImpairedDetections) != 0 || len(r.UnmappedRules) != 0 {
		t.Fatalf("incompatible evidence was treated as uncertain or impaired: %+v", r)
	}
	if len(r.Findings) < 1 || !hasFinding(r.Findings, FindingDead, ReasonSourcePlanIncompatible, "") {
		t.Fatalf("stable dead finding missing: %+v", r.Findings)
	}
	if r.ExitCode() != ExitFindings || r.Summary.UnusedTelemetryAssessment != UnusedAssessmentComplete {
		t.Fatalf("exit/unused assessment = %d/%s", r.ExitCode(), r.Summary.UnusedTelemetryAssessment)
	}

	policy := &Policy{Version: PolicyVersion, GateClasses: []string{FindingDead}}
	gated := incompatibleFixture(t, []string{"BasicTable", "AnalyticsTable"}, nil, nil, policy)
	if gated.Summary.GatedFindings != 1 || gated.ExitCode() != ExitFindings {
		t.Fatalf("dead policy gate = %+v / exit %d", gated.Policy, gated.ExitCode())
	}
}

func TestMixedResolvedAndIncompatibleInputsProduceSourceFinding(t *testing.T) {
	r := incompatibleFixture(t, []string{"BasicTable"}, []string{"AnalyticsTable"}, nil, nil)
	if len(r.DeadDetections) != 0 || len(r.ImpairedDetections) != 1 {
		t.Fatalf("dead/impaired = %+v / %+v", r.DeadDetections, r.ImpairedDetections)
	}
	impaired := r.ImpairedDetections[0]
	if strings.Join(impaired.Reasons, ",") != ReasonSourcePlanIncompatible ||
		strings.Join(impaired.IncompatibleSources, ",") != "BasicTable" ||
		strings.Join(impaired.Sources, ",") != "AnalyticsTable" {
		t.Fatalf("impaired detection = %+v", impaired)
	}
	if !hasFinding(r.Findings, FindingImpaired, ReasonSourcePlanIncompatible, "BasicTable") {
		t.Fatalf("source-specific finding missing: %+v", r.Findings)
	}
	if r.Summary.InputResolution.Incompatible != 1 || r.Summary.InputResolution.Resolved != 1 ||
		r.ExitCode() != ExitFindings {
		t.Fatalf("summary/exit = %+v / %d", r.Summary, r.ExitCode())
	}

	policy := &Policy{Version: PolicyVersion, GateClasses: []string{FindingImpaired}}
	gated := incompatibleFixture(t, []string{"BasicTable"}, []string{"AnalyticsTable"}, nil, policy)
	if gated.Summary.GatedFindings != 1 || gated.ExitCode() != ExitFindings {
		t.Fatalf("impaired policy gate = %+v / exit %d", gated.Policy, gated.ExitCode())
	}

	redacted := incompatibleFixture(t, []string{"BasicTable"}, []string{"AnalyticsTable"}, nil, nil)
	redactor, err := redactpkg.New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	redacted.RedactWith(redactor)
	encoded, err := json.Marshal(redacted)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"BasicTable", "AnalyticsTable", "Plan-sensitive rule"} {
		if strings.Contains(string(encoded), leak) {
			t.Errorf("redacted incompatible finding leaks %q", leak)
		}
	}
}

func TestIncompatibleInputDoesNotOverrideUncertainInput(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	rule := backend.Rule{ID: "rule-mixed-evidence", Name: "Mixed evidence", Enabled: true, Severity: "high"}
	r := BuildWithOptions("test", graph.BuildResolved([]backend.Rule{rule}, []backend.Source{{
		Name: "BasicTable", Docs: 10, LastEvent: now,
	}}, []backend.InputResolution{
		{RuleID: rule.ID, Selector: "BasicTable", Status: backend.ResolutionIncompatible, ObservedAt: now},
		{RuleID: rule.ID, Selector: "UnknownTable", Status: backend.ResolutionUnavailable, ObservedAt: now},
	}), BuildOptions{Check: health.Check{MaxStale: time.Hour, Now: func() time.Time { return now }}})
	if len(r.DeadDetections) != 0 || len(r.ImpairedDetections) != 0 || len(r.UnmappedRules) != 1 ||
		r.UnmappedRules[0].AssessmentStatus != backend.ResolutionUnavailable {
		t.Fatalf("uncertain mixed input produced a verdict: %+v", r)
	}
}

func TestIncompatibleFindingLifecycleAndDiffRecovery(t *testing.T) {
	store := state.New()
	dead := incompatibleFixture(t, []string{"AnalyticsTable", "BasicTable"}, nil, store, nil)
	mixed := incompatibleFixture(t, []string{"BasicTable"}, []string{"AnalyticsTable"}, store, nil)
	healthy := incompatibleFixture(t, nil, []string{"AnalyticsTable", "BasicTable"}, store, nil)

	if !hasFinding(mixed.RecoveredFindings, FindingDead, ReasonSourcePlanIncompatible, "") {
		t.Fatalf("dead finding was not recovered after a compatible source appeared: %+v", mixed.RecoveredFindings)
	}
	if !hasFinding(dead.Findings, FindingDead, ReasonSourcePlanIncompatible, "") {
		t.Fatalf("initial dead finding missing: %+v", dead.Findings)
	}
	if !hasFinding(healthy.RecoveredFindings, FindingImpaired, ReasonSourcePlanIncompatible, "BasicTable") {
		t.Fatalf("impaired finding was not recovered after the source became compatible: %+v", healthy.RecoveredFindings)
	}

	deadStateless := incompatibleFixture(t, []string{"AnalyticsTable", "BasicTable"}, nil, nil, nil)
	mixedStateless := incompatibleFixture(t, []string{"BasicTable"}, []string{"AnalyticsTable"}, nil, nil)
	healthyStateless := incompatibleFixture(t, nil, []string{"AnalyticsTable", "BasicTable"}, nil, nil)
	deadToMixed, err := Diff(deadStateless, mixedStateless)
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(deadToMixed.RecoveredFindings, FindingDead, ReasonSourcePlanIncompatible, "") ||
		!hasFinding(deadToMixed.NewFindings, FindingImpaired, ReasonSourcePlanIncompatible, "BasicTable") {
		t.Fatalf("dead-to-impaired diff = %+v", deadToMixed)
	}
	mixedToHealthy, err := Diff(mixedStateless, healthyStateless)
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(mixedToHealthy.RecoveredFindings, FindingImpaired, ReasonSourcePlanIncompatible, "BasicTable") {
		t.Fatalf("impaired recovery diff = %+v", mixedToHealthy)
	}
}

func TestHTMLRendersIncompatibleInputEvidence(t *testing.T) {
	r := incompatibleFixture(t, []string{"BasicTable"}, []string{"AnalyticsTable"}, nil, nil)
	path := filepath.Join(t.TempDir(), "report.html")
	if err := r.WriteHTML(path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Detections with reduced visibility", "BasicTable", ">incompatible<"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("HTML report missing %q", want)
		}
	}
	if strings.Contains(string(data), ">source-plan-incompatible<") {
		t.Fatal("HTML report exposed a machine-only impairment reason")
	}

	dead := incompatibleFixture(t, []string{"BasicTable", "AnalyticsTable"}, nil, nil, nil)
	deadPath := filepath.Join(t.TempDir(), "dead.html")
	if err := dead.WriteHTML(deadPath); err != nil {
		t.Fatal(err)
	}
	deadHTML, err := os.ReadFile(deadPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(deadHTML), "source configuration is incompatible with this rule") ||
		strings.Contains(string(deadHTML), ">source-plan-incompatible<") {
		t.Fatalf("dead HTML reason is not human-readable:\n%s", deadHTML)
	}
}

func hasFinding(findings []Finding, class, reason, source string) bool {
	for _, finding := range findings {
		if finding.Class == class && finding.Reason == reason && finding.Source == source {
			return true
		}
	}
	return false
}
