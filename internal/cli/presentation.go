package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Big-Comfy/deadair/internal/report"
)

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
	fmt.Fprintln(w, color(w, "1", "deadair"))
	context := []string{strings.ToUpper(r.Backend)}
	if r.Instance != "" && !strings.EqualFold(r.Instance, r.Backend) {
		context = append([]string{r.Instance}, context...)
	}
	context = append(context, r.GeneratedAt.UTC().Format("15:04 UTC"))
	fmt.Fprintln(w, color(w, "2", strings.Join(context, "  ·  ")))

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
		appendInput(s.InputResolution.Resolved, "resolved input", "resolved inputs", "32")
		appendInput(s.InputResolution.Empty, "missing input", "missing inputs", "31")
		appendInput(s.InputResolution.Unsupported, "unsupported input", "unsupported inputs", "33")
		appendInput(s.InputResolution.Unavailable, "unavailable input", "unavailable inputs", "33")
		appendInput(s.InputResolution.Remote, "remote input", "remote inputs", "36")
		appendInput(s.InputResolution.Ambiguous, "ambiguous input", "ambiguous inputs", "33")
	}
	if disabled := s.Rules - s.EnabledRules; disabled > 0 {
		appendInput(disabled, "disabled detection", "disabled detections", "2")
	}
	if len(inputHealth) > 0 {
		printMetricRow(w, inputHealth)
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

	if len(r.UnmappedRules) > 0 || len(r.RemoteRules) > 0 {
		visualHeading(w, "33;1", "NOT ASSESSED", len(r.UnmappedRules)+len(r.RemoteRules))
		shown := 0
		for _, rule := range r.UnmappedRules {
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
		if remaining := len(r.UnmappedRules) + len(r.RemoteRules) - shown; remaining > 0 {
			visualMore(w, remaining)
		}
	}

	if s.UnusedTelemetryAssessment == report.UnusedAssessmentUnavailable {
		visualHeading(w, "33;1", "UNUSED NOT ASSESSED", 0)
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

	if s.UnusedTelemetryAssessment == report.UnusedAssessmentNotApplicable &&
		r.CandidateExitCode() == report.ExitHealthy {
		fmt.Fprintf(w, "\n%s\n", color(w, "32;1", "PASS"))
		fmt.Fprintln(w, color(w, "2", "Candidate inputs are available."))
	} else if s.UnusedTelemetryAssessment != report.UnusedAssessmentNotApplicable &&
		r.ExitCode() == report.ExitHealthy && len(r.UnmappedRules)+len(r.RemoteRules) == 0 {
		fmt.Fprintf(w, "\n%s\n", color(w, "32;1", "HEALTHY"))
		fmt.Fprintln(w, color(w, "2", "No dead detections or degraded sources."))
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
			fmt.Sprintf("%s ingest lag exceeds window in %s",
				humanDuration(d.MaxLagSeconds), strings.Join(d.LagSources, ", ")))
	}
	if len(parts) == 0 {
		for _, reason := range d.Reasons {
			parts = append(parts, strings.ReplaceAll(reason, "-", " "))
		}
	}
	return parts
}

func countLabel(n int, singular, plural string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", singular)
	}
	return fmt.Sprintf("%d %s", n, plural)
}

func printVisualDemoNextSteps(w io.Writer) {
	fmt.Fprintf(w, "\n%s\n", color(w, "36;1", "DEMO DATA"))
	fmt.Fprintln(w, color(w, "2", "Embedded sample only. No SIEM connection was made."))
	fmt.Fprintf(w, "\n%s\n", color(w, "1", "Run it on your environment"))
	fmt.Fprintf(w, "  %s  %s\n", color(w, "1", "deadair setup"), color(w, "2", "create read-only access"))
	fmt.Fprintf(w, "  %s  %s\n", color(w, "1", "deadair check"), color(w, "2", "verify the connection"))
	fmt.Fprintf(w, "  %s  %s\n", color(w, "1", "deadair scan "), color(w, "2", "inspect detection coverage"))
}

func printVisualDiff(w io.Writer, d *report.DiffResult) {
	if d.Regressions() == 0 && len(d.RecoveredDead)+len(d.RecoveredImpaired)+len(d.RecoveredSources)+len(d.NewSources)+len(d.RemovedSources)+len(d.NewlyUnused) == 0 {
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
	for _, n := range d.NewSources {
		fmt.Fprintf(w, "\n%s  %s\n", color(w, "32;1", "SOURCE ADDED"), n)
	}
	for _, n := range d.RemovedSources {
		fmt.Fprintf(w, "\n%s  %s\n", color(w, "33;1", "SOURCE REMOVED"), n)
	}
}
