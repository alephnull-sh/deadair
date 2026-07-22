// Package demo builds a deterministic report from embedded evidence. It uses
// the same graph, health, and report pipeline as a live scan without reading
// configuration or contacting a backend.
package demo

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Big-Comfy/deadair/internal/backend"
	"github.com/Big-Comfy/deadair/internal/graph"
	"github.com/Big-Comfy/deadair/internal/health"
	"github.com/Big-Comfy/deadair/internal/report"
)

//go:embed fixture.json
var fixtureJSON []byte

type fixture struct {
	Backend         string               `json:"backend"`
	ObservedAt      time.Time            `json:"observed_at"`
	MaxStaleSeconds int64                `json:"max_stale_seconds"`
	Rules           []ruleEvidence       `json:"rules"`
	Sources         []sourceEvidence     `json:"sources"`
	Schemas         []backend.Schema     `json:"schemas"`
	Resolutions     []resolutionEvidence `json:"resolutions"`
}

type ruleEvidence struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	Enabled           bool     `json:"enabled"`
	Severity          string   `json:"severity"`
	RiskScore         int      `json:"risk_score"`
	Patterns          []string `json:"patterns"`
	LookbackSeconds   int64    `json:"lookback_seconds"`
	IntervalSeconds   int64    `json:"interval_seconds"`
	RequiredFields    []string `json:"required_fields"`
	TimestampOverride string   `json:"timestamp_override"`
}

type sourceEvidence struct {
	Name             string    `json:"name"`
	Docs             int64     `json:"docs"`
	SizeBytes        int64     `json:"size_bytes"`
	LastEvent        time.Time `json:"last_event"`
	IngestLagSeconds *int64    `json:"ingest_lag_seconds"`
}

type resolutionEvidence struct {
	RuleID          string                   `json:"rule_id"`
	Expression      string                   `json:"expression"`
	Status          backend.ResolutionStatus `json:"status"`
	ResolvedSources []string                 `json:"resolved_sources"`
}

// Build parses the embedded evidence and assembles its report through the
// normal scan pipeline.
func Build() (*report.Report, error) {
	var in fixture
	if err := json.Unmarshal(fixtureJSON, &in); err != nil {
		return nil, fmt.Errorf("parsing embedded demo fixture: %w", err)
	}

	rules := make([]backend.Rule, 0, len(in.Rules))
	for _, rule := range in.Rules {
		rules = append(rules, backend.Rule{
			ID:                rule.ID,
			Name:              rule.Name,
			Enabled:           rule.Enabled,
			Severity:          rule.Severity,
			RiskScore:         rule.RiskScore,
			Patterns:          append([]string(nil), rule.Patterns...),
			Lookback:          time.Duration(rule.LookbackSeconds) * time.Second,
			Interval:          time.Duration(rule.IntervalSeconds) * time.Second,
			RequiredFields:    append([]string(nil), rule.RequiredFields...),
			TimestampOverride: rule.TimestampOverride,
		})
	}

	sources := make([]backend.Source, 0, len(in.Sources))
	for _, source := range in.Sources {
		var lag *time.Duration
		if source.IngestLagSeconds != nil {
			value := time.Duration(*source.IngestLagSeconds) * time.Second
			lag = &value
		}
		sources = append(sources, backend.Source{
			Name:      source.Name,
			Docs:      source.Docs,
			SizeBytes: source.SizeBytes,
			LastEvent: source.LastEvent,
			IngestLag: lag,
		})
	}

	sourceFields := make(map[string]map[string]bool, len(in.Schemas))
	for _, schema := range in.Schemas {
		fields := make(map[string]bool, len(schema.Fields))
		for _, field := range schema.Fields {
			fields[field.Name] = true
		}
		sourceFields[schema.Source] = fields
	}

	observedAt := in.ObservedAt.UTC()
	resolutions := make([]backend.InputResolution, 0, len(in.Resolutions))
	for _, resolution := range in.Resolutions {
		resolutions = append(resolutions, backend.InputResolution{
			RuleID:           resolution.RuleID,
			Expression:       resolution.Expression,
			SelectorKind:     "index_expression",
			ResolvedSources:  append([]string(nil), resolution.ResolvedSources...),
			ResolutionMethod: "embedded_fixture",
			ObservedAt:       observedAt,
			Status:           resolution.Status,
		})
	}
	g := graph.BuildResolved(rules, sources, resolutions)
	r := report.BuildWithOptions(in.Backend, g, report.BuildOptions{
		Check: health.Check{
			MaxStale: time.Duration(in.MaxStaleSeconds) * time.Second,
			Now:      func() time.Time { return observedAt },
		},
		SourceFields: sourceFields,
	})
	// Report construction timestamps itself. Pin the embedded report to the
	// evidence clock so JSON and HTML are stable across runs.
	r.GeneratedAt = observedAt
	return r, nil
}
