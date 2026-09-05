package exporter

import (
	"fmt"
	"io"

	"github.com/alephnull-sh/deadair/internal/report"
)

// Monitoring observations have explicit validity and suppression gauges.
// Missing evidence is never exported as a zero-age (fresh) observation.
func writeMonitoring(w io.Writer, reports []*report.Report) {
	fmt.Fprint(w, "# HELP deadair_producer_assessed Whether the producer freshness observation is conclusive.\n# TYPE deadair_producer_assessed gauge\n")
	fmt.Fprint(w, "# HELP deadair_producer_stale Whether an assessed producer has exceeded its expected interval.\n# TYPE deadair_producer_stale gauge\n")
	fmt.Fprint(w, "# HELP deadair_producer_suppressed Whether producer alerts are suppressed by maintenance.\n# TYPE deadair_producer_suppressed gauge\n")
	fmt.Fprint(w, "# HELP deadair_producer_last_event_timestamp_seconds Exact latest timestamp observed for the producer.\n# TYPE deadair_producer_last_event_timestamp_seconds gauge\n")
	fmt.Fprint(w, "# HELP deadair_producer_max_stale_seconds Configured maximum interval between producer events.\n# TYPE deadair_producer_max_stale_seconds gauge\n")
	fmt.Fprint(w, "# HELP deadair_summary_pipeline_assessed Whether summary runtime health is conclusive.\n# TYPE deadair_summary_pipeline_assessed gauge\n")
	fmt.Fprint(w, "# HELP deadair_summary_pipeline_unhealthy Whether the latest pipeline run failed or is overdue.\n# TYPE deadair_summary_pipeline_unhealthy gauge\n")
	fmt.Fprint(w, "# HELP deadair_summary_pipeline_suppressed Whether pipeline alerts are suppressed by maintenance.\n# TYPE deadair_summary_pipeline_suppressed gauge\n")
	fmt.Fprint(w, "# HELP deadair_summary_pipeline_last_run_timestamp_seconds Latest observed completed pipeline run.\n# TYPE deadair_summary_pipeline_last_run_timestamp_seconds gauge\n")
	for _, r := range reports {
		for _, p := range r.Producers {
			tags := fmt.Sprintf("instance=%s,producer=%s,source=%s,basis=%s", label(r.Instance), label(p.ID), label(p.Source), label(string(p.Observation.Basis)))
			assessed := p.Observation.Status == "assessed" && p.Observation.FreshnessStatus != "unknown"
			fmt.Fprintf(w, "deadair_producer_assessed{%s} %d\n", tags, boolNumber(assessed))
			fmt.Fprintf(w, "deadair_producer_suppressed{%s} %d\n", tags, boolNumber(p.Observation.ExpectedDowntime))
			fmt.Fprintf(w, "deadair_producer_max_stale_seconds{%s} %g\n", tags, p.MaxStaleSeconds)
			if assessed {
				fmt.Fprintf(w, "deadair_producer_stale{%s} %d\n", tags, boolNumber(p.Observation.FreshnessStatus == "stale" || p.Observation.FreshnessStatus == "empty"))
				if p.Observation.LastEvent != nil {
					fmt.Fprintf(w, "deadair_producer_last_event_timestamp_seconds{%s} %d\n", tags, p.Observation.LastEvent.Unix())
				}
			}
		}
		for _, p := range r.SummaryRuleRuns {
			if p.ID == "" {
				continue
			}
			tags := fmt.Sprintf("instance=%s,pipeline=%s,source=%s", label(r.Instance), label(p.ID), label(p.Output.Name))
			assessed := p.HealthStatus == "ok" || p.HealthStatus == "failed" || p.HealthStatus == "late"
			fmt.Fprintf(w, "deadair_summary_pipeline_assessed{%s} %d\n", tags, boolNumber(assessed))
			fmt.Fprintf(w, "deadair_summary_pipeline_suppressed{%s} %d\n", tags, boolNumber(p.ExpectedDowntime))
			if assessed {
				fmt.Fprintf(w, "deadair_summary_pipeline_unhealthy{%s} %d\n", tags, boolNumber(p.HealthStatus != "ok"))
			}
			if p.RunAt != nil {
				fmt.Fprintf(w, "deadair_summary_pipeline_last_run_timestamp_seconds{%s} %d\n", tags, p.RunAt.Unix())
			}
		}
	}
}

func boolNumber(value bool) int {
	if value {
		return 1
	}
	return 0
}
