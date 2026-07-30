package cli

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Big-Comfy/deadair/internal/backend"
	demodata "github.com/Big-Comfy/deadair/internal/demo"
	"github.com/Big-Comfy/deadair/internal/report"
)

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

func TestVisualDemoFitsEightyColumns(t *testing.T) {
	r, err := demodata.Build()
	if err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	printVisualSummary(&output, r)
	printVisualDemoNextSteps(&output)
	for _, line := range strings.Split(output.String(), "\n") {
		if width := utf8.RuneCountInString(line); width > 80 {
			t.Errorf("visual output is %d columns wide:\n%s", width, line)
		}
	}
}
