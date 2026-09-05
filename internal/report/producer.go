package report

import (
	"sort"
	"time"

	"github.com/alephnull-sh/deadair/internal/backend"
	redactpkg "github.com/alephnull-sh/deadair/internal/redact"
)

type ProducerHealth struct {
	ID                  string            `json:"id"`
	Source              string            `json:"source"`
	Owner               string            `json:"owner,omitempty"`
	Runbook             string            `json:"runbook,omitempty"`
	MaxStaleSeconds     float64           `json:"max_stale_seconds"`
	Observation         SourceObservation `json:"observation"`
	ConfirmedDetections []SourceConsumer  `json:"confirmed_detections,omitempty"`
	OtherTableConsumers []SourceConsumer  `json:"other_table_consumers,omitempty"`
}

func buildProducerHealth(r *Report, opts BuildOptions) []ProducerHealth {
	if opts.Policy == nil || r.Scope.Mode == "candidate" {
		return nil
	}
	evidence := make(map[string]backend.ProducerEvidence)
	for _, item := range opts.ProducerEvidence {
		evidence[item.ID] = item
	}
	out := make([]ProducerHealth, 0, len(opts.Policy.Producers))
	for _, p := range opts.Policy.Producers {
		item, ok := evidence[p.ID]
		if !ok || item.Source != p.Source {
			item = backend.ProducerEvidence{ID: p.ID, Source: p.Source, Freshness: backend.FreshnessEvidence{Status: backend.EvidenceUnavailable, Detail: "producer measurement was not returned"}}
		}
		check := opts.Check
		check.MaxStale = p.duration
		// Keep the observed condition during maintenance; suppression is
		// separate from evidence and cannot establish a recovery.
		check.Downtime = nil
		observation := sourceObservation(backend.Source{Name: p.Source}, p.Basis, item.Freshness, check)
		now := r.GeneratedAt
		if opts.Check.Now != nil {
			now = opts.Check.Now()
		}
		observation.ExpectedDowntime = opts.Check.InDowntime("producer:"+p.ID, now) || opts.Check.InDowntime(p.Source, now)
		entry := ProducerHealth{ID: p.ID, Source: p.Source, Owner: p.Owner, Runbook: p.Runbook,
			MaxStaleSeconds: p.duration.Seconds(), Observation: observation}
		confirmed := make(map[string]bool)
		for _, id := range item.ConfirmedRules {
			confirmed[id] = true
		}
		for _, source := range r.SourceImpacts {
			if source.Source != p.Source {
				continue
			}
			for _, rule := range source.Detections {
				if confirmed[rule.RuleID] && rule.Status != "unassessed" {
					entry.ConfirmedDetections = append(entry.ConfirmedDetections, rule)
				} else {
					entry.OtherTableConsumers = append(entry.OtherTableConsumers, rule)
				}
			}
		}
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (r *Report) monitoringFindings() []Finding {
	var findings []Finding
	for _, p := range r.Producers {
		if p.Observation.Status != backend.EvidenceAssessed || (p.Observation.FreshnessStatus != "stale" && p.Observation.FreshnessStatus != "empty") {
			continue
		}
		findings = append(findings, Finding{ID: stableFindingID(r.TargetID, r.Instance, r.Backend, FindingProducerStale, "", "feed-quiet", p.Source, p.ID),
			Class: FindingProducerStale, Reason: "feed-quiet", Source: p.Source, Dependency: p.ID, Suppressed: p.Observation.ExpectedDowntime})
	}
	for _, pipeline := range r.SummaryRuleRuns {
		if pipeline.HealthStatus != "failed" && pipeline.HealthStatus != "late" {
			continue
		}
		findings = append(findings, Finding{ID: stableFindingID(r.TargetID, r.Instance, r.Backend, FindingSummaryPipeline, "", "pipeline-unhealthy", pipeline.Output.Name, pipeline.ID),
			Class: FindingSummaryPipeline, Reason: "pipeline-unhealthy", Source: pipeline.Output.Name, Dependency: pipeline.ID, Suppressed: pipeline.ExpectedDowntime})
	}
	return findings
}

func monitoringRecoveryConfirmed(r *Report, previous Finding) bool {
	if previous.Class == FindingProducerStale {
		for _, p := range r.Producers {
			o := p.Observation
			if p.ID == previous.Dependency && p.Source == previous.Source && !o.ExpectedDowntime && o.Status == backend.EvidenceAssessed && o.FreshnessStatus == "ok" && o.LastEvent != nil && o.ObservedAt.After(previous.LastSeen) {
				return true
			}
		}
	}
	if previous.Class == FindingSummaryPipeline {
		for _, p := range r.SummaryRuleRuns {
			if p.ID == previous.Dependency && p.Output.Name == previous.Source && p.HealthStatus == "ok" && !p.ExpectedDowntime && p.Status == backend.EvidenceAssessed && p.RunAt != nil && p.RunAt.After(previous.LastSeen) && p.ObservedAt.After(previous.LastSeen) {
				return true
			}
		}
	}
	return false
}

func (r *Report) redactProducers(redactor *redactpkg.Redactor) {
	for i := range r.Producers {
		p := &r.Producers[i]
		p.ID, p.Source = redactor.Value("dep", p.ID), redactor.Value("src", p.Source)
		if p.Owner != "" {
			p.Owner = redactor.Value("owner", p.Owner)
		}
		p.Runbook = ""
		if p.Observation.Detail != "" {
			p.Observation.Detail = "measurement detail withheld"
		}
		for _, consumers := range [][]SourceConsumer{p.ConfirmedDetections, p.OtherTableConsumers} {
			for j := range consumers {
				d := &consumers[j]
				d.RuleID, d.Name, d.URL = redactor.Value("rule", d.RuleID), redactor.Value("rule", d.Name), ""
				if d.BackendObjectID != "" {
					d.BackendObjectID = redactor.Value("obj", d.BackendObjectID)
				}
			}
		}
	}
}

func summaryHealth(item backend.SummaryRuleRunEvidence) string {
	if item.RunAt.IsZero() || item.ObservedAt.IsZero() || item.RunAt.After(item.ObservedAt.Add(5*time.Minute)) {
		return "unknown"
	}
	if item.Overdue && item.Status == backend.EvidenceIncomplete && item.RunStatus == "Succeeded" {
		return "late"
	}
	if item.Status != backend.EvidenceAssessed {
		return "unknown"
	}
	switch item.RunStatus {
	case "Succeeded":
		return "ok"
	case "Failed":
		return "failed"
	}
	return "unknown"
}
