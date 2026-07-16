package cli

import (
	"bytes"
	"strings"
	"testing"

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
