package exporter

import (
	"strings"
	"testing"
	"time"

	"github.com/alephnull-sh/deadair/internal/backend"
	"github.com/alephnull-sh/deadair/internal/report"
)

func TestMonitoringMetricsDoNotTurnMissingEvidenceIntoHealth(t *testing.T) {
	now := time.Now().UTC()
	r := &report.Report{Instance: "london", Producers: []report.ProducerHealth{{ID: "edge-fw", Source: "CommonSecurityLog", MaxStaleSeconds: 900, Observation: report.SourceObservation{Basis: backend.FreshnessIngestionTime, Status: backend.EvidenceUnavailable, FreshnessStatus: "unknown"}}}, SummaryRuleRuns: []report.SummaryRuleRun{{ID: "network-hourly", Output: backend.DependencyRef{Name: "NetworkSummary_CL"}, HealthStatus: "unknown"}}}
	var b strings.Builder
	writeMonitoring(&b, []*report.Report{r})
	body := b.String()
	if !strings.Contains(body, `deadair_producer_assessed{instance="london",producer="edge-fw",source="CommonSecurityLog",basis="ingestion_time"} 0`) {
		t.Fatal(body)
	}
	for _, metric := range []string{"deadair_producer_stale{", "deadair_producer_last_event_timestamp_seconds{", "deadair_summary_pipeline_unhealthy{"} {
		if strings.Contains(body, metric) {
			t.Fatalf("unknown emitted a healthy measurement %q", metric)
		}
	}
	r.Producers[0].Observation = report.SourceObservation{Basis: backend.FreshnessIngestionTime, Status: backend.EvidenceAssessed, FreshnessStatus: "stale", LastEvent: &now, ExpectedDowntime: true}
	r.SummaryRuleRuns[0].HealthStatus = "late"
	b.Reset()
	writeMonitoring(&b, []*report.Report{r})
	body = b.String()
	for _, want := range []string{`deadair_producer_stale{instance="london",producer="edge-fw",source="CommonSecurityLog",basis="ingestion_time"} 1`, `deadair_producer_suppressed{instance="london",producer="edge-fw",source="CommonSecurityLog",basis="ingestion_time"} 1`, `deadair_summary_pipeline_unhealthy{instance="london",pipeline="network-hourly",source="NetworkSummary_CL"} 1`} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %s", want)
		}
	}
}
