package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/alephnull-sh/deadair/internal/backend"
	"github.com/alephnull-sh/deadair/internal/report"
)

func TestSentinelSignalsKeepGateResultHonest(t *testing.T) {
	generatedAt := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	runAt := generatedAt.Add(-18 * time.Minute)
	duration := int64(1200)
	rows := int64(0)
	r := &report.Report{
		Backend:     "sentinel",
		GeneratedAt: generatedAt,
		Scope:       report.ScanScope{Mode: "installed"},
		RuleSourceFreshness: []report.RuleSourceFreshness{{
			RuleID: "rule-1", RuleName: "Suspicious firewall traffic", Source: "CommonSecurityLog",
			Fields: []string{"DeviceVendor", "DeviceProduct"}, FreshnessStatus: "stale", AgeSeconds: 86400,
		}},
		SummaryRuleRuns: []report.SummaryRuleRun{{
			Rule: backend.DependencyRef{ID: "summary-1", Name: "Summarize sign-ins"},
			Output: backend.DependencyRef{
				ID: "SummarySignin_CL", Name: "SummarySignin_CL",
			},
			Status: backend.EvidenceAssessed, RunStatus: "Failed", RunAt: &runAt,
			ObservedAt: generatedAt, QueryDurationMillis: &duration, ResultCount: &rows,
		}},
	}
	for name, render := range map[string]func(*bytes.Buffer){
		"plain":  func(output *bytes.Buffer) { printPlainSummary(output, r) },
		"visual": func(output *bytes.Buffer) { printVisualSummary(output, r) },
	} {
		t.Run(name, func(t *testing.T) {
			var output bytes.Buffer
			render(&output)
			text := output.String()
			for _, want := range []string{
				"GATE PASSED", "SENTINEL SIGNALS",
				"Suspicious firewall traffic → CommonSecurityLog",
				"Summarize sign-ins → SummarySignin_CL", "Failed 18m ago", "1.2s", "0 rows",
			} {
				if !strings.Contains(text, want) {
					t.Errorf("%s output missing %q:\n%s", name, want, text)
				}
			}
			if !strings.Contains(strings.ToLower(text), "gate unchanged") {
				t.Errorf("%s output does not explain the advisory/gate boundary:\n%s", name, text)
			}
			if strings.Contains(text, "HEALTHY") || strings.Contains(text, "DeviceVendor=") {
				t.Fatalf("%s output gives an unqualified healthy result or exposes a predicate literal:\n%s", name, text)
			}
		})
	}
}

func TestGateFailureLeadsTheTerminalReport(t *testing.T) {
	r := &report.Report{
		Backend: "elastic",
		Summary: report.Summary{DeadDetections: 1},
		DeadDetections: []report.DeadDetection{{
			Name: "Dormant sign-in rule", Severity: "high", Reason: report.ReasonDisconnected,
		}},
	}
	for name, render := range map[string]func(*bytes.Buffer){
		"plain":  func(output *bytes.Buffer) { printPlainSummary(output, r) },
		"visual": func(output *bytes.Buffer) { printVisualSummary(output, r) },
	} {
		t.Run(name, func(t *testing.T) {
			var output bytes.Buffer
			render(&output)
			text := output.String()
			gate := strings.Index(text, "GATE FAILED")
			finding := strings.Index(text, "DEAD")
			if gate < 0 || finding < 0 || gate > finding {
				t.Fatalf("%s output does not lead with the failed gate:\n%s", name, text)
			}
		})
	}
}

func TestUnsafeCandidateAssessmentIsNotCalledAGateFailure(t *testing.T) {
	r := &report.Report{
		Backend: "sentinel",
		Scope:   report.ScanScope{Mode: "candidate"},
		Assessments: []report.RuntimeAssessment{{
			Name: report.AssessmentSourceResolution, Status: backend.EvidenceIncomplete,
		}},
	}
	for name, render := range map[string]func(*bytes.Buffer){
		"plain":  func(output *bytes.Buffer) { printPlainSummary(output, r) },
		"visual": func(output *bytes.Buffer) { printVisualSummary(output, r) },
	} {
		t.Run(name, func(t *testing.T) {
			var output bytes.Buffer
			render(&output)
			text := output.String()
			if !strings.Contains(text, "SCAN INCOMPLETE") || strings.Contains(text, "GATE FAILED") {
				t.Fatalf("%s output misstates an unsafe candidate assessment:\n%s", name, text)
			}
		})
	}
}

func TestCoverageHidesOnlyExpectedPredicateFreshnessDisablement(t *testing.T) {
	for _, detail := range []string{
		"no enabled, fully resolved rule exposed a supported closed source predicate",
		"no eligible fully resolved rule",
	} {
		r := &report.Report{Assessments: []report.RuntimeAssessment{
			{Name: report.AssessmentPredicateFreshness, Status: backend.EvidenceDisabled, Detail: detail},
			{Name: report.AssessmentCandidateParsing, Status: backend.EvidenceDisabled},
		}}
		if checks := unassessedChecks(r); len(checks) != 0 {
			t.Fatalf("expected not-applicable checks to be hidden, got %v", checks)
		}
	}
	r := &report.Report{Assessments: []report.RuntimeAssessment{{
		Name: report.AssessmentPredicateFreshness, Status: backend.EvidenceDisabled,
	}}}
	r.Assessments[0].Detail = "predicate freshness was disabled by configuration"
	checks := unassessedChecks(r)
	if len(checks) != 1 || checks[0] != "predicate freshness disabled" {
		t.Fatalf("unexpected predicate disablement should remain visible, got %v", checks)
	}
}

func TestCoverageChecksUseOneLineEach(t *testing.T) {
	r := &report.Report{Assessments: []report.RuntimeAssessment{
		{Name: report.AssessmentSourceResolution, Status: backend.EvidenceIncomplete},
		{Name: report.AssessmentRequiredFields, Status: backend.EvidenceDisabled},
		{Name: report.AssessmentIngestLag, Status: backend.EvidenceDisabled},
	}}
	for name, render := range map[string]func(*bytes.Buffer){
		"plain":  func(output *bytes.Buffer) { printPlainSummary(output, r) },
		"visual": func(output *bytes.Buffer) { printVisualSummary(output, r) },
	} {
		t.Run(name, func(t *testing.T) {
			var output bytes.Buffer
			render(&output)
			text := output.String()
			for _, check := range []string{
				"source resolution incomplete",
				"required fields disabled",
				"ingest lag disabled",
			} {
				if !strings.Contains(text, "\n  "+check+"\n") {
					t.Errorf("coverage check %q is not on its own line:\n%s", check, text)
				}
			}
		})
	}
}

func TestPrintSummaryUsesPlainLanguageReasons(t *testing.T) {
	r := &report.Report{
		Summary: report.Summary{DeadDetections: 2},
		DeadDetections: []report.DeadDetection{
			{Name: "Legacy netflow rule", Severity: "medium", Reason: report.ReasonDisconnected},
			{Name: "Winlog suspicious logon", Severity: "high", Reason: report.ReasonStarved, Sources: []string{"winlogbeat-2026.07"}},
		},
	}

	var output bytes.Buffer
	printSummary(&output, r)
	for _, want := range []string{
		"Legacy netflow rule — no matching source",
		"Winlog suspicious logon — all matching sources stale or empty (winlogbeat-2026.07)",
	} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("human report missing %q:\n%s", want, output.String())
		}
	}
	if strings.Contains(output.String(), " — disconnected") || strings.Contains(output.String(), " — starved") {
		t.Errorf("human report exposes machine reason codes:\n%s", output.String())
	}
}

func TestPrintSummaryShowsPartialInputWithoutCallingItDead(t *testing.T) {
	r := &report.Report{
		Backend: "elastic",
		Summary: report.Summary{PartialInputs: 1},
		PartialInputCoverage: []report.PartialInputCoverage{{
			RuleName: "Migrating input", Severity: "medium", Selector: "logs-legacy-*",
		}},
	}
	var output bytes.Buffer
	printSummary(&output, r)
	for _, want := range []string{"partial input coverage: 1 selector", "Migrating input — missing selector: logs-legacy-*"} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("summary missing %q:\n%s", want, output.String())
		}
	}
	if strings.Contains(output.String(), "DEAD") {
		t.Fatalf("partial input was presented as dead:\n%s", output.String())
	}
}

func TestUnavailableUnusedTelemetryKeepsUnresolvedInputFallback(t *testing.T) {
	r := &report.Report{
		Backend: "elastic",
		Summary: report.Summary{UnusedTelemetryAssessment: report.UnusedAssessmentUnavailable},
	}
	for name, render := range map[string]func(*bytes.Buffer){
		"plain":  func(output *bytes.Buffer) { printPlainSummary(output, r) },
		"visual": func(output *bytes.Buffer) { printVisualSummary(output, r) },
	} {
		t.Run(name, func(t *testing.T) {
			var output bytes.Buffer
			render(&output)
			if !strings.Contains(output.String(), "one or more enabled local rule inputs could not be resolved safely") {
				t.Fatalf("%s summary lost the legacy unavailable explanation:\n%s", name, output.String())
			}
		})
	}
}

func TestVisualSummaryUsesHierarchyAndHumanLabels(t *testing.T) {
	r := &report.Report{
		Backend: "elastic",
		Summary: report.Summary{
			Sources:        1,
			Rules:          1,
			EnabledRules:   1,
			DeadDetections: 1,
			InputResolution: report.InputResolutionSummary{
				Empty: 1,
			},
		},
		Sources: []report.SourceHealth{{Name: "logs-live", Status: "ok"}},
		InputResolutions: []backend.InputResolution{{
			RuleID: "candidate",
			Status: backend.ResolutionEmpty,
		}},
		DeadDetections: []report.DeadDetection{{
			Name:     "Candidate NetFlow rule",
			Severity: "high",
			Reason:   report.ReasonDisconnected,
			Patterns: []string{"netflow-*"},
		}},
	}

	var output bytes.Buffer
	printVisualSummary(&output, r)
	for _, want := range []string{
		"deadair",
		"ELASTIC",
		"1 source  ·  1 detection",
		"1 healthy",
		"1 missing input",
		"DEAD  1",
		"Candidate NetFlow rule",
		"HIGH  ·  no matching source  ·  netflow-*",
	} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("visual report missing %q:\n%s", want, output.String())
		}
	}
}

func TestSummariesRenderIncompatibleInputsAndSources(t *testing.T) {
	r := &report.Report{
		Backend: "sentinel",
		Summary: report.Summary{
			Rules: 1, EnabledRules: 1, ImpairedDetections: 1,
			InputResolution: report.InputResolutionSummary{Resolved: 1, Incompatible: 1},
		},
		InputResolutions: []backend.InputResolution{
			{RuleID: "rule-1", Status: backend.ResolutionResolved},
			{RuleID: "rule-1", Selector: "BasicTable", Status: backend.ResolutionIncompatible},
		},
		ImpairedDetections: []report.ImpairedDetection{{
			Name: "Mixed table rule", Severity: "high",
			Reasons:             []string{report.ReasonSourcePlanIncompatible},
			IncompatibleSources: []string{"BasicTable"},
		}},
	}

	var plain bytes.Buffer
	printPlainSummary(&plain, r)
	for _, want := range []string{
		"1 resolved, 0 empty, 1 incompatible",
		"source not usable by this rule: BasicTable",
	} {
		if !strings.Contains(plain.String(), want) {
			t.Errorf("plain summary missing %q:\n%s", want, plain.String())
		}
	}

	var visual bytes.Buffer
	printVisualSummary(&visual, r)
	for _, want := range []string{
		"1 resolved input", "1 incompatible input", "source not usable by this rule: BasicTable",
	} {
		if !strings.Contains(visual.String(), want) {
			t.Errorf("visual summary missing %q:\n%s", want, visual.String())
		}
	}
}

func TestVisualSummaryFitsEightyColumns(t *testing.T) {
	r := &report.Report{
		Backend: "elastic",
		Summary: report.Summary{
			Sources: 4, Rules: 5, EnabledRules: 4, DeadDetections: 2,
			ImpairedDetections: 1, UnusedSources: 1,
			UnusedTelemetryAssessment: report.UnusedAssessmentComplete,
			InputResolution:           report.InputResolutionSummary{Resolved: 3, Empty: 1},
		},
		Sources: []report.SourceHealth{
			{Name: "logs-live-default", Status: "ok"},
			{Name: "logs-stale-default", Status: "stale"},
			{Name: "logs-empty-default", Status: "empty"},
			{Name: "logs-unused-default", Status: "ok"},
		},
		DeadDetections: []report.DeadDetection{
			{Name: "Registry persistence", Severity: "high", Reason: report.ReasonDisconnected, Patterns: []string{"logs-endpoint.events.registry-*"}},
			{Name: "Dormant authentication source", Severity: "medium", Reason: report.ReasonStarved, Sources: []string{"logs-stale-default"}},
		},
		ImpairedDetections: []report.ImpairedDetection{{
			Name: "Custom parser field coverage", Severity: "medium",
			Reasons: []string{report.ReasonMissingFields}, MissingFields: []string{"process.command_line"},
		}},
		UnusedTelemetry: []report.UnusedSource{{Name: "logs-unused-default", SizeBytes: 4096}},
	}

	var output bytes.Buffer
	printVisualSummary(&output, r)
	for _, line := range strings.Split(output.String(), "\n") {
		if width := utf8.RuneCountInString(line); width > 80 {
			t.Errorf("visual output is %d columns wide:\n%s", width, line)
		}
	}
}
