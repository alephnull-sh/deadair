package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/alephnull-sh/deadair/internal/report"
	"github.com/alephnull-sh/deadair/internal/state"
)

type sourceAttention struct {
	name    string
	reasons []string
}

func sourceAttentionItems(r *report.Report) []sourceAttention {
	items := make([]sourceAttention, 0, r.Summary.DegradedSources+r.Summary.VolumeLowSources+r.Summary.SchemaDriftSources)
	for _, source := range r.Sources {
		var reasons []string
		switch source.Status {
		case "stale":
			reasons = append(reasons, "no recent events")
		case "empty":
			reasons = append(reasons, "no events in the measured window")
		}
		if source.Volume != nil && source.Volume.Status == state.VolumeLow {
			reasons = append(reasons, "volume below baseline")
		}
		if source.Schema != nil && source.Schema.Status == state.SchemaDrift {
			reasons = append(reasons, "field schema changed")
		}
		if len(reasons) > 0 {
			items = append(items, sourceAttention{name: source.Name, reasons: reasons})
		}
	}
	return items
}

func interactiveOutput(w io.Writer) bool {
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func printVisualSummary(w io.Writer, r *report.Report) {
	s := r.Summary
	visibleUnmapped := r.VisibleUnmappedRules()
	fmt.Fprintln(w, color(w, "1", "deadair"))
	context := []string{strings.ToUpper(r.Backend)}
	if r.Instance != "" && !strings.EqualFold(r.Instance, r.Backend) {
		context = append([]string{r.Instance}, context...)
	}
	context = append(context, r.GeneratedAt.UTC().Format("15:04 UTC"))
	fmt.Fprintln(w, color(w, "2", strings.Join(context, "  ·  ")))
	printVisualGateStatus(w, r)

	fmt.Fprintln(w)
	printMetricRow(w, []visualMetric{
		{text: countLabel(s.Sources, "source", "sources"), code: "1"},
		{text: countLabel(s.EnabledRules, "detection", "detections"), code: "1"},
	})

	var sourceHealth []visualMetric
	counts := map[string]int{}
	for _, src := range r.Sources {
		counts[src.Status]++
	}
	appendSource := func(n int, singular, plural, code string) {
		if n > 0 {
			sourceHealth = append(sourceHealth, visualMetric{
				text: countLabel(n, singular, plural),
				code: code,
			})
		}
	}
	appendSource(counts["ok"], "healthy", "healthy", "32")
	appendSource(counts["stale"], "stale", "stale", "33")
	appendSource(counts["empty"], "empty", "empty", "31")
	appendSource(counts["unknown"], "unknown", "unknown", "33")
	appendSource(counts["maintenance"], "in maintenance", "in maintenance", "36")
	if len(sourceHealth) > 0 {
		printMetricRow(w, sourceHealth)
	}

	var inputHealth []visualMetric
	appendInput := func(n int, singular, plural, code string) {
		if n > 0 {
			inputHealth = append(inputHealth, visualMetric{
				text: countLabel(n, singular, plural),
				code: code,
			})
		}
	}
	if len(r.InputResolutions) > 0 {
		resolution := humanInputResolution(r)
		appendInput(resolution.Resolved, "resolved input", "resolved inputs", "32")
		appendInput(resolution.Empty, "missing input", "missing inputs", "31")
		appendInput(resolution.Incompatible, "incompatible input", "incompatible inputs", "33")
		appendInput(resolution.Unsupported, "unsupported input", "unsupported inputs", "33")
		appendInput(resolution.Unavailable, "unavailable input", "unavailable inputs", "33")
		appendInput(resolution.Remote, "remote input", "remote inputs", "36")
		appendInput(resolution.Ambiguous, "ambiguous input", "ambiguous inputs", "33")
	}
	if disabled := s.Rules - s.EnabledRules; disabled > 0 {
		appendInput(disabled, "disabled detection", "disabled detections", "2")
	}
	if len(inputHealth) > 0 {
		printMetricRow(w, inputHealth)
	}
	if checks := unassessedChecks(r); len(checks) > 0 {
		fmt.Fprintln(w, color(w, "33;1", "CHECK COVERAGE"))
		for _, check := range checks {
			fmt.Fprintf(w, "  %s\n", color(w, "2", check))
		}
	}
	if r.Policy != nil {
		fmt.Fprintf(w, "%s  %d gated  ·  %d accepted  ·  %d expired\n",
			color(w, "36;1", "POLICY"), r.Summary.GatedFindings, r.Policy.AcceptedActive, r.Policy.AcceptedExpired)
	}

	if len(r.DeadDetections) > 0 {
		visualHeading(w, "31;1", "DEAD", len(r.DeadDetections))
		for i, d := range r.DeadDetections {
			if i >= 15 {
				visualMore(w, len(r.DeadDetections)-i)
				break
			}
			fmt.Fprintf(w, "  %s\n", color(w, "1", d.Name))
			printVisualFindingDetail(w, d.Severity, visualDeadEvidence(d)...)
		}
	}

	if len(r.ImpairedDetections) > 0 {
		visualHeading(w, "33;1", "IMPAIRED", len(r.ImpairedDetections))
		for i, d := range r.ImpairedDetections {
			if i >= 15 {
				visualMore(w, len(r.ImpairedDetections)-i)
				break
			}
			fmt.Fprintf(w, "  %s\n", color(w, "1", d.Name))
			printVisualFindingDetail(w, d.Severity, visualImpairmentEvidence(d)...)
		}
	}

	if len(r.SourceImpacts) > 0 || len(r.Producers) > 0 {
		printInvestigationSummary(w, r)
	}
	if sourceFindings := sourceAttentionItems(r); len(r.SourceImpacts) == 0 && len(sourceFindings) > 0 {
		visualHeading(w, "33;1", "SOURCE FINDINGS", len(sourceFindings))
		for i, item := range sourceFindings {
			if i >= 15 {
				visualMore(w, len(sourceFindings)-i)
				break
			}
			fmt.Fprintf(w, "  %s\n", color(w, "1", item.name))
			fmt.Fprintf(w, "  %s\n", color(w, "2", strings.Join(item.reasons, "  ·  ")))
		}
	}

	if len(r.PartialInputCoverage) > 0 {
		visualHeading(w, "33;1", "PARTIAL INPUT", len(r.PartialInputCoverage))
		for i, coverage := range r.PartialInputCoverage {
			if i >= 10 {
				visualMore(w, len(r.PartialInputCoverage)-i)
				break
			}
			fmt.Fprintf(w, "  %s\n", color(w, "1", coverage.RuleName))
			dependency := coverage.Selector
			if dependency == "" {
				dependency = coverage.Expression
			}
			printVisualFindingDetail(w, coverage.Severity, "missing selector", dependency)
		}
	}

	if len(visibleUnmapped) > 0 || len(r.RemoteRules) > 0 {
		visualHeading(w, "33;1", "NOT ASSESSED", len(visibleUnmapped)+len(r.RemoteRules))
		shown := 0
		for _, rule := range visibleUnmapped {
			if shown >= 10 {
				break
			}
			shown++
			fmt.Fprintf(w, "  %s\n", color(w, "1", rule.Name))
			detail := []string{strings.ReplaceAll(string(rule.AssessmentStatus), "-", " ")}
			if rule.Detail != "" {
				detail = append(detail, rule.Detail)
			}
			printVisualFindingDetail(w, rule.Severity, detail...)
		}
		for _, rule := range r.RemoteRules {
			if shown >= 10 {
				break
			}
			shown++
			fmt.Fprintf(w, "  %s\n", color(w, "1", rule.Name))
			printVisualFindingDetail(w, rule.Severity, "remote dependency")
		}
		if remaining := len(visibleUnmapped) + len(r.RemoteRules) - shown; remaining > 0 {
			visualMore(w, remaining)
		}
	}

	printVisualSentinelSignals(w, r)

	if s.UnusedTelemetryAssessment == report.UnusedAssessmentUnavailable && !strings.EqualFold(r.Backend, "sentinel") {
		visualHeading(w, "33;1", "UNUSED NOT ASSESSED", 0)
		fmt.Fprintf(w, "  %s\n", color(w, "2", s.UnusedTelemetryExplanation()))
	} else if len(r.UnusedTelemetry) > 0 {
		visualHeading(w, "36;1", "UNUSED", len(r.UnusedTelemetry))
		for i, u := range r.UnusedTelemetry {
			if i >= 5 {
				visualMore(w, len(r.UnusedTelemetry)-i)
				break
			}
			fmt.Fprintf(w, "  %s\n", color(w, "1", u.Name))
			detail := humanBytes(u.SizeBytes)
			if u.DisabledConsumers > 0 {
				detail += "  ·  " + countLabel(u.DisabledConsumers, "disabled detection", "disabled detections")
			}
			fmt.Fprintf(w, "  %s\n", color(w, "2", detail))
		}
	}

}

func printVisualGateStatus(w io.Writer, r *report.Report) {
	if headline := terminalFindingHeadline(r); headline != "" {
		fmt.Fprintf(w, "\n%s\n", color(w, "1", headline))
	}
	switch terminalGateExitCode(r) {
	case report.ExitHealthy:
		fmt.Fprintf(w, "\n%s\n", color(w, "2", "GATE PASSED · exit 0"))
		if count := sentinelSignalCount(r); count > 0 {
			fmt.Fprintln(w, color(w, "2", fmt.Sprintf("No gated findings. Review %s below.", countLabel(count, "Sentinel signal", "Sentinel signals"))))
			return
		}
		fmt.Fprintln(w, color(w, "2", "No findings matched the configured gate."))
	case report.ExitFindings:
		fmt.Fprintf(w, "\n%s\n", color(w, "2", "GATE FAILED · exit 1"))
		fmt.Fprintln(w, color(w, "2", "Findings matched the configured gate. The scan completed."))
	default:
		fmt.Fprintf(w, "\n%s\n", color(w, "33;1", "SCAN INCOMPLETE"))
		fmt.Fprintln(w, color(w, "2", "The gate could not be evaluated safely."))
	}
}

func printVisualSentinelSignals(w io.Writer, r *report.Report) {
	freshness := ruleSourceFreshnessWarnings(r)
	summaryRuns := summaryRuleRunWarnings(r)
	if len(freshness)+len(summaryRuns) == 0 {
		return
	}
	visualHeading(w, "33;1", "SENTINEL SIGNALS", len(freshness)+len(summaryRuns))
	fmt.Fprintln(w, color(w, "2", sentinelSignalNote(r)))
	shown := 0
	for _, item := range freshness {
		if shown >= 10 {
			visualMore(w, len(freshness)+len(summaryRuns)-shown)
			return
		}
		shown++
		fmt.Fprintf(w, "  %s\n", color(w, "1", "FILTERED DATA  "+ruleSourceLabel(item)))
		fmt.Fprintf(w, "  %s\n", color(w, "2", filteredFreshnessDetail(item)))
		fmt.Fprintln(w, color(w, "2", "  Review this rule's filter and matching connector."))
	}
	for _, item := range summaryRuns {
		if shown >= 10 {
			visualMore(w, len(freshness)+len(summaryRuns)-shown)
			return
		}
		shown++
		fmt.Fprintf(w, "  %s\n", color(w, "1", "SUMMARY PIPELINE  "+summaryRuleLabel(item)))
		fmt.Fprintf(w, "  %s\n", color(w, "2", summaryRunDetail(r, item)))
		fmt.Fprintln(w, color(w, "2", "  Open the summary rule run history in Sentinel."))
	}
}

func visualHeading(w io.Writer, code, label string, count int) {
	fmt.Fprintf(w, "\n%s", color(w, code, label))
	if count > 0 {
		fmt.Fprintf(w, "  %s", color(w, "2", fmt.Sprintf("%d", count)))
	}
	fmt.Fprintln(w)
}

func visualMore(w io.Writer, count int) {
	fmt.Fprintf(w, "  %s\n", color(w, "2", fmt.Sprintf("%d more in JSON", count)))
}

type visualMetric struct {
	text string
	code string
}

func printMetricRow(w io.Writer, metrics []visualMetric) {
	for i, metric := range metrics {
		if i > 0 {
			fmt.Fprint(w, color(w, "2", "  ·  "))
		}
		fmt.Fprint(w, color(w, metric.code, metric.text))
	}
	fmt.Fprintln(w)
}

func printVisualFindingDetail(w io.Writer, severity string, evidence ...string) {
	fmt.Fprintf(w, "  %s", color(w, severityColor(severity), strings.ToUpper(severity)))
	for _, item := range evidence {
		fmt.Fprint(w, color(w, "2", "  ·  "+item))
	}
	fmt.Fprintln(w)
}

func severityColor(severity string) string {
	switch strings.ToLower(severity) {
	case "critical", "high":
		return "31;1"
	case "medium":
		return "33;1"
	case "low":
		return "36;1"
	default:
		return "1"
	}
}

func visualDeadEvidence(d report.DeadDetection) []string {
	parts := []string{report.DeadReasonLabel(d.Reason)}
	if d.Reason == report.ReasonDisconnected && len(d.Patterns) > 0 {
		parts = append(parts, strings.Join(d.Patterns, ", "))
	} else if len(d.Sources) > 0 {
		parts = append(parts, strings.Join(d.Sources, ", "))
	}
	return parts
}

func visualImpairmentEvidence(d report.ImpairedDetection) []string {
	var parts []string
	if len(d.MissingFields) > 0 {
		parts = append(parts, "missing "+strings.Join(d.MissingFields, ", "))
	}
	if len(d.LagSources) > 0 {
		parts = append(parts,
			fmt.Sprintf("p95 ingest delay %s (max %s) exceeds the rule's lookback margin in %s",
				humanDuration(d.P95LagSeconds), humanDuration(d.MaxLagSeconds), strings.Join(d.LagSources, ", ")))
	}
	if len(d.IncompatibleSources) > 0 {
		parts = append(parts, incompatibleSourceDetail(d.IncompatibleSources))
	}
	if len(parts) == 0 {
		for _, reason := range d.Reasons {
			parts = append(parts, report.ImpairedReasonLabel(reason))
		}
	}
	return parts
}

func unassessedChecks(r *report.Report) []string {
	var checks []string
	for _, assessment := range r.Assessments {
		if assessment.Status == "assessed" ||
			(assessment.Name == report.AssessmentCandidateParsing && assessment.Status == "disabled") ||
			expectedHiddenSentinelFusionResolution(r, assessment) ||
			expectedPredicateFreshnessDisabled(assessment) ||
			expectedRequiredFieldsDisabled(assessment) {
			continue
		}
		checks = append(checks, strings.ReplaceAll(assessment.Name, "_", " ")+" "+string(assessment.Status))
	}
	return checks
}

func expectedHiddenSentinelFusionResolution(r *report.Report, assessment report.RuntimeAssessment) bool {
	return assessment.Name == report.AssessmentSourceResolution &&
		assessment.Status == "incomplete" &&
		strings.EqualFold(r.Backend, "sentinel") &&
		r.Scope.Mode != "candidate" &&
		len(r.UnmappedRules) > 0 &&
		len(r.VisibleUnmappedRules()) == 0 &&
		len(r.RemoteRules) == 0
}

func expectedRequiredFieldsDisabled(assessment report.RuntimeAssessment) bool {
	if assessment.Name != report.AssessmentRequiredFields || assessment.Status != "disabled" {
		return false
	}
	return strings.Contains(strings.ToLower(assessment.Detail), "did not declare required fields")
}

func expectedPredicateFreshnessDisabled(assessment report.RuntimeAssessment) bool {
	if assessment.Name != report.AssessmentPredicateFreshness || assessment.Status != "disabled" {
		return false
	}
	detail := strings.ToLower(assessment.Detail)
	return strings.Contains(detail, "no enabled, fully resolved rule") ||
		strings.Contains(detail, "no eligible fully resolved rule")
}

func ruleSourceFreshnessWarnings(r *report.Report) []report.RuleSourceFreshness {
	items := make([]report.RuleSourceFreshness, 0, len(r.RuleSourceFreshness))
	for _, item := range r.RuleSourceFreshness {
		if item.FreshnessStatus == "ok" || item.FreshnessStatus == "maintenance" {
			continue
		}
		items = append(items, item)
	}
	return items
}

func summaryRuleRunWarnings(r *report.Report) []report.SummaryRuleRun {
	items := make([]report.SummaryRuleRun, 0, len(r.SummaryRuleRuns))
	for _, item := range r.SummaryRuleRuns {
		if item.HealthStatus == "ok" || (item.HealthStatus == "" && item.Status == "assessed" && strings.EqualFold(item.RunStatus, "Succeeded")) {
			continue
		}
		items = append(items, item)
	}
	return items
}

func sentinelSignalNote(r *report.Report) string {
	if len(summaryRuleRunWarnings(r)) > 0 {
		return "Filtered activity is advisory. Summary findings follow the gate policy."
	}
	return "Filtered activity is advisory; gate unchanged."
}

func terminalFindingHeadline(r *report.Report) string {
	if terminalGateExitCode(r) == report.ExitError {
		return ""
	}
	if r.Summary.DeadDetections > 0 {
		return countLabel(r.Summary.DeadDetections, "detection can't fire", "detections can't fire")
	}
	quiet := 0
	for _, p := range r.Producers {
		if !p.Observation.ExpectedDowntime && (p.Observation.FreshnessStatus == "stale" || p.Observation.FreshnessStatus == "empty") {
			quiet++
		}
	}
	if quiet > 0 {
		return countLabel(quiet, "expected producer is quiet", "expected producers are quiet")
	}
	if r.Summary.ImpairedDetections > 0 {
		return countLabel(r.Summary.ImpairedDetections, "detection has reduced visibility", "detections have reduced visibility")
	}
	return ""
}

func countLabel(n int, singular, plural string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", singular)
	}
	return fmt.Sprintf("%d %s", n, plural)
}

func printVisualDiff(w io.Writer, d *report.DiffResult) {
	if len(d.NewFindings)+len(d.RecoveredFindings)+len(d.NewlyGatedFindings)+len(d.NoLongerGated)+len(d.NewSources)+len(d.RemovedSources) == 0 {
		fmt.Fprintln(w, color(w, "32;1", "NO CHANGE"))
		return
	}

	if len(d.NewlyDead) > 0 {
		visualHeading(w, "31;1", "NEWLY DEAD", len(d.NewlyDead))
		for _, x := range d.NewlyDead {
			fmt.Fprintf(w, "  %s\n", color(w, "1", x.Name))
			printVisualFindingDetail(w, x.Severity, visualDeadEvidence(x)...)
		}
	}
	if len(d.NewlyImpaired) > 0 {
		visualHeading(w, "33;1", "NEWLY IMPAIRED", len(d.NewlyImpaired))
		for _, x := range d.NewlyImpaired {
			fmt.Fprintf(w, "  %s\n", color(w, "1", x.Name))
			printVisualFindingDetail(w, x.Severity, visualImpairmentEvidence(x)...)
		}
	}
	if len(d.NewlyDegraded) > 0 {
		visualHeading(w, "33;1", "SOURCE DEGRADED", len(d.NewlyDegraded))
		for _, s := range d.NewlyDegraded {
			fmt.Fprintf(w, "  %s\n", color(w, "1", s.Name))
			fmt.Fprintf(w, "  %s\n", color(w, "2", s.Status))
		}
	}
	if len(d.NewlyUnused) > 0 {
		visualHeading(w, "36;1", "NEWLY UNUSED", len(d.NewlyUnused))
		for _, u := range d.NewlyUnused {
			fmt.Fprintf(w, "  %s\n", color(w, "1", u.Name))
			fmt.Fprintf(w, "  %s\n", color(w, "2", humanBytes(u.SizeBytes)))
		}
	}
	for _, finding := range d.NewFindings {
		switch finding.Class {
		case report.FindingVolumeLow, report.FindingSchemaDrift, report.FindingPartialInput, report.FindingProducerStale, report.FindingSummaryPipeline:
			name := findingSubject(finding)
			visualHeading(w, "33;1", strings.ToUpper(report.FindingClassLabel(finding.Class)), 1)
			fmt.Fprintf(w, "  %s\n", color(w, "1", name))
			fmt.Fprintf(w, "  %s\n", color(w, "2", report.FindingReasonLabel(finding.Class, finding.Reason)))
		}
	}
	if len(d.NewlyGatedFindings) > 0 {
		visualHeading(w, "31;1", "NEWLY GATED", len(d.NewlyGatedFindings))
		for _, finding := range d.NewlyGatedFindings {
			name := findingSubject(finding)
			fmt.Fprintf(w, "  %s\n", color(w, "1", name))
			fmt.Fprintf(w, "  %s\n", color(w, "2", report.FindingReasonLabel(finding.Class, finding.Reason)+"  ·  "+report.FindingClassLabel(finding.Class)))
		}
	}

	recovered := len(d.RecoveredDead) + len(d.RecoveredImpaired) + len(d.RecoveredSources)
	if recovered > 0 {
		visualHeading(w, "32;1", "RECOVERED", recovered)
		for _, x := range d.RecoveredDead {
			fmt.Fprintf(w, "  %s\n", x.Name)
		}
		for _, x := range d.RecoveredImpaired {
			fmt.Fprintf(w, "  %s\n", x.Name)
		}
		for _, s := range d.RecoveredSources {
			fmt.Fprintf(w, "  %s\n", s.Name)
		}
	}
	for _, finding := range d.RecoveredFindings {
		switch finding.Class {
		case report.FindingVolumeLow, report.FindingSchemaDrift, report.FindingPartialInput, report.FindingProducerStale, report.FindingSummaryPipeline:
			name := findingSubject(finding)
			fmt.Fprintf(w, "\n%s  %s — %s\n", color(w, "32;1", "RECOVERED"), name, report.FindingReasonLabel(finding.Class, finding.Reason))
		}
	}
	for _, finding := range d.NoLongerGated {
		name := findingSubject(finding)
		fmt.Fprintf(w, "\n%s  %s — %s\n", color(w, "32;1", "NO LONGER GATED"), name, report.FindingReasonLabel(finding.Class, finding.Reason))
	}
	for _, n := range d.NewSources {
		fmt.Fprintf(w, "\n%s  %s\n", color(w, "32;1", "SOURCE ADDED"), n)
	}
	for _, n := range d.RemovedSources {
		fmt.Fprintf(w, "\n%s  %s\n", color(w, "33;1", "SOURCE REMOVED"), n)
	}
}
