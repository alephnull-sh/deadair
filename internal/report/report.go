// Package report assembles scan results into the tool's primary artifact.
// A report is a literal blind-spot map of a SOC: treat it as sensitive by
// default — files are written 0600, and Redact produces a shareable variant
// with every source, rule, and pattern name replaced by a stable digest.
package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Big-Comfy/deadair/internal/backend"
	"github.com/Big-Comfy/deadair/internal/graph"
	"github.com/Big-Comfy/deadair/internal/health"
	"github.com/Big-Comfy/deadair/internal/state"
)

// Exit codes for `deadair scan`, designed as a CI gate.
const (
	ExitHealthy  = 0 // no findings
	ExitFindings = 1 // dead detections or degraded sources
	ExitError    = 2 // the scan itself failed
)

// Report is the full scan result.
type Report struct {
	GeneratedAt time.Time `json:"generated_at"`
	Backend     string    `json:"backend"`
	// Instance names the fleet member (tenant / deployment) this report
	// describes. Defaults to the backend name in single-instance mode.
	Instance           string              `json:"instance,omitempty"`
	Redacted           bool                `json:"redacted,omitempty"`
	Summary            Summary             `json:"summary"`
	Sources            []SourceHealth      `json:"sources"`
	DeadDetections     []DeadDetection     `json:"dead_detections"`
	ImpairedDetections []ImpairedDetection `json:"impaired_detections,omitempty"`
	UnmappedRules      []RuleRef           `json:"unmapped_rules,omitempty"`
	// RemoteRules query cross-cluster (cluster:pattern) inputs deadair cannot
	// verify from this deployment. Listed, never called dead.
	RemoteRules     []RuleRef      `json:"remote_rules,omitempty"`
	UnusedTelemetry []UnusedSource `json:"unused_telemetry"`
}

// Summary is the roll-up used for exit codes and exporter aggregates.
type Summary struct {
	Rules              int   `json:"rules"`
	EnabledRules       int   `json:"enabled_rules"`
	Sources            int   `json:"sources"`
	HealthySources     int   `json:"healthy_sources"`
	DegradedSources    int   `json:"degraded_sources"`
	DeadDetections     int   `json:"dead_detections"`
	ImpairedDetections int   `json:"impaired_detections,omitempty"`
	UnmappedRules      int   `json:"unmapped_rules"`
	RemoteRules        int   `json:"remote_rules,omitempty"`
	UnusedSources      int   `json:"unused_sources"`
	UnusedBytes        int64 `json:"unused_bytes"`
	VolumeLowSources   int   `json:"volume_low_sources,omitempty"`
	SchemaDriftSources int   `json:"schema_drift_sources,omitempty"`
}

// SourceHealth is one source with its verdict and blast-radius size.
type SourceHealth struct {
	Name       string  `json:"name"`
	Status     string  `json:"status"`
	AgeSeconds float64 `json:"age_seconds,omitempty"`
	Docs       int64   `json:"docs"`
	SizeBytes  int64   `json:"size_bytes"`
	// ExpectedDowntime is true when an expected downtime window suppressed a
	// stale or empty verdict for this source.
	ExpectedDowntime bool          `json:"expected_downtime,omitempty"`
	Volume           *VolumeHealth `json:"volume,omitempty"`
	Schema           *SchemaHealth `json:"schema,omitempty"`
	// Consumers is the number of enabled rules reading this source — the
	// blast radius if it dies.
	Consumers int `json:"consumers"`
}

// VolumeHealth is the stateful volume-baseline verdict for a source.
type VolumeHealth struct {
	Status       string   `json:"status"`
	RatePerHour  float64  `json:"rate_per_hour,omitempty"`
	BaselineMean float64  `json:"baseline_mean,omitempty"`
	BaselineStd  float64  `json:"baseline_std,omitempty"`
	ZScore       *float64 `json:"z_score,omitempty"`
	SampleCount  int      `json:"sample_count,omitempty"`
	Warmup       bool     `json:"warmup,omitempty"`
}

// SchemaHealth is the stateful schema-drift verdict for a source.
type SchemaHealth struct {
	Status      string            `json:"status"`
	FieldCount  int               `json:"field_count,omitempty"`
	Added       []string          `json:"added,omitempty"`
	Removed     []string          `json:"removed,omitempty"`
	TypeChanged []FieldTypeChange `json:"type_changed,omitempty"`
}

// FieldTypeChange records one field whose backend type set changed.
type FieldTypeChange struct {
	Name   string   `json:"name"`
	Before []string `json:"before"`
	After  []string `json:"after"`
}

// Dead-reason values are stable machine-readable codes used in JSON reports.
const (
	ReasonDisconnected = "disconnected"
	ReasonStarved      = "starved"
)

// DeadReasonLabel returns the plain-language label used in human reports.
func DeadReasonLabel(reason string) string {
	switch reason {
	case ReasonDisconnected:
		return "no matching source"
	case ReasonStarved:
		return "all matching sources stale or empty"
	default:
		return reason
	}
}

// DeadDetection is an enabled rule that cannot currently fire.
type DeadDetection struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Severity string `json:"severity"`
	// Reason is a stable machine-readable code. Use DeadReasonLabel in output
	// intended for people.
	Reason   string   `json:"reason"`
	Patterns []string `json:"patterns"`
	Sources  []string `json:"sources,omitempty"` // the degraded sources, when starved
}

// RuleRef identifies a rule whose inputs cannot be mapped from metadata.
type RuleRef struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Severity string `json:"severity"`
}

// Impairment reasons: the rule fires, but with degraded vision.
const (
	ReasonMissingFields  = "missing-fields"   // filters on fields no matched source provides
	ReasonLagBlindWindow = "lag-blind-window" // a source's ingest lag exceeds the query-window margin
)

// ImpairedDetection is an enabled rule whose sources are alive but whose
// effective visibility is reduced. Distinct from dead: it can still fire.
type ImpairedDetection struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Severity        string   `json:"severity"`
	Reasons         []string `json:"reasons"`
	MissingFields   []string `json:"missing_fields,omitempty"`
	LookbackSeconds float64  `json:"lookback_seconds,omitempty"`
	IntervalSeconds float64  `json:"interval_seconds,omitempty"`
	MaxLagSeconds   float64  `json:"max_lag_seconds,omitempty"`
	// LagSources names the specific matched sources whose ingest lag exceeds
	// the margin — a broad rule may read one laggy source and many healthy ones.
	LagSources []string `json:"lag_sources,omitempty"`
	Sources    []string `json:"sources,omitempty"`
}

// UnusedSource is telemetry ingested but read by no ENABLED detection — the
// ingest-cost question. At realistic rule counts almost every pattern is
// referenced by some installed-but-disabled rule, so disabled references are
// reported as context, not as consumption.
type UnusedSource struct {
	Name      string `json:"name"`
	Docs      int64  `json:"docs"`
	SizeBytes int64  `json:"size_bytes"`
	// DisabledConsumers counts installed-but-disabled rules whose patterns
	// match this source.
	DisabledConsumers int `json:"disabled_consumers,omitempty"`
}

var severityRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}

func rank(sev string) int {
	if r, ok := severityRank[sev]; ok {
		return r
	}
	return 4
}

// BuildOptions carries optional report inputs beyond fixed freshness health.
type BuildOptions struct {
	Check  health.Check
	Volume map[string]state.VolumeAssessment
	Schema map[string]state.SchemaAssessment
	// Scope, when non-nil, limits which sources are LISTED (sources section,
	// summary counts, unused telemetry, metrics). Verdicts are always computed
	// from the full inventory: scoping the report must never manufacture a
	// dead detection or hide a real one.
	Scope map[string]bool
	// SourceFields maps source name -> field set (from field_caps) for
	// missing-field checks. Nil when schemas were not fetched.
	SourceFields map[string]map[string]bool
	// SkipUnused suppresses the unused-telemetry section; used in candidate
	// mode where a single rule under test would mark everything unused.
	SkipUnused bool
}

// Build assembles the report from the dependency graph and a health check.
func Build(backendName string, g *graph.Graph, check health.Check) *Report {
	return BuildWithOptions(backendName, g, BuildOptions{Check: check})
}

// BuildWithOptions assembles the report from the dependency graph and L1
// health signals.
func BuildWithOptions(backendName string, g *graph.Graph, opts BuildOptions) *Report {
	r := &Report{GeneratedAt: time.Now().UTC(), Backend: backendName}

	rulesByID := make(map[string]int, len(g.Rules))
	for i, rule := range g.Rules {
		rulesByID[rule.ID] = i
	}
	srcByName := make(map[string]backend.Source, len(g.Sources))
	for _, s := range g.Sources {
		srcByName[s.Name] = s
	}

	inScope := func(name string) bool { return opts.Scope == nil || opts.Scope[name] }

	assess := make(map[string]health.Assessment, len(g.Sources))
	for _, s := range g.Sources {
		a := opts.Check.Evaluate(s)
		assess[s.Name] = a
		if !inScope(s.Name) {
			continue
		}
		consumers, disabledConsumers := 0, 0
		for _, id := range g.RulesFor(s.Name) {
			if g.Rules[rulesByID[id]].Enabled {
				consumers++
			} else {
				disabledConsumers++
			}
		}
		if consumers == 0 {
			r.UnusedTelemetry = append(r.UnusedTelemetry, UnusedSource{
				Name: s.Name, Docs: s.Docs, SizeBytes: s.SizeBytes,
				DisabledConsumers: disabledConsumers,
			})
			r.Summary.UnusedBytes += s.SizeBytes
		}
		src := SourceHealth{
			Name:             s.Name,
			Status:           string(a.Status),
			AgeSeconds:       a.Age.Seconds(),
			Docs:             s.Docs,
			SizeBytes:        s.SizeBytes,
			ExpectedDowntime: a.ExpectedDowntime,
			Consumers:        consumers,
		}
		if v, ok := opts.Volume[s.Name]; ok {
			src.Volume = &VolumeHealth{
				Status:       v.Status,
				RatePerHour:  v.RatePerHour,
				BaselineMean: v.BaselineMean,
				BaselineStd:  v.BaselineStd,
				ZScore:       v.ZScore,
				SampleCount:  v.SampleCount,
				Warmup:       v.Warmup,
			}
			if v.Status == state.VolumeLow {
				r.Summary.VolumeLowSources++
			}
		}
		if schema, ok := opts.Schema[s.Name]; ok {
			src.Schema = &SchemaHealth{
				Status:      schema.Status,
				FieldCount:  schema.FieldCount,
				Added:       append([]string(nil), schema.Added...),
				Removed:     append([]string(nil), schema.Removed...),
				TypeChanged: typeChanges(schema.TypeChanged),
			}
			if schema.Status == state.SchemaDrift {
				r.Summary.SchemaDriftSources++
			}
		}
		r.Sources = append(r.Sources, src)
		switch {
		case a.Status.Degraded():
			r.Summary.DegradedSources++
		case a.Status == health.StatusOK:
			r.Summary.HealthySources++
		}
	}
	r.Summary.Sources = len(r.Sources)

	for _, rule := range g.Rules {
		r.Summary.Rules++
		if !rule.Enabled {
			continue
		}
		r.Summary.EnabledRules++
		if len(rule.Patterns) == 0 {
			r.UnmappedRules = append(r.UnmappedRules, RuleRef{ID: rule.ID, Name: rule.Name, Severity: rule.Severity})
			continue
		}
		matched := g.SourcesFor(rule.ID)
		if len(matched) == 0 {
			// Cross-cluster patterns (cluster:index) can never match a local
			// source name; a rule with any remote input is unverifiable here,
			// not disconnected. Never report a false dead.
			remote := false
			for _, p := range rule.Patterns {
				if strings.Contains(p, ":") {
					remote = true
					break
				}
			}
			if remote {
				r.RemoteRules = append(r.RemoteRules, RuleRef{ID: rule.ID, Name: rule.Name, Severity: rule.Severity})
				continue
			}
			r.DeadDetections = append(r.DeadDetections, DeadDetection{
				ID: rule.ID, Name: rule.Name, Severity: rule.Severity,
				Reason: ReasonDisconnected, Patterns: rule.Patterns,
			})
			continue
		}
		// Starved only when every matched source is degraded. A source with
		// unknown freshness keeps the rule alive: never page on uncertainty.
		allDegraded := true
		var degraded []string
		for _, name := range matched {
			if assess[name].Status.Degraded() {
				degraded = append(degraded, name)
			} else {
				allDegraded = false
			}
		}
		if allDegraded {
			r.DeadDetections = append(r.DeadDetections, DeadDetection{
				ID: rule.ID, Name: rule.Name, Severity: rule.Severity,
				Reason: ReasonStarved, Patterns: rule.Patterns, Sources: degraded,
			})
			continue
		}
		if imp, ok := impairment(rule, matched, srcByName, opts.SourceFields); ok {
			r.ImpairedDetections = append(r.ImpairedDetections, imp)
		}
	}

	sort.Slice(r.UnusedTelemetry, func(i, j int) bool {
		if r.UnusedTelemetry[i].SizeBytes != r.UnusedTelemetry[j].SizeBytes {
			return r.UnusedTelemetry[i].SizeBytes > r.UnusedTelemetry[j].SizeBytes
		}
		return r.UnusedTelemetry[i].Name < r.UnusedTelemetry[j].Name
	})

	if opts.SkipUnused {
		r.UnusedTelemetry = nil
		r.Summary.UnusedBytes = 0
	}
	r.Summary.DeadDetections = len(r.DeadDetections)
	r.Summary.ImpairedDetections = len(r.ImpairedDetections)
	r.Summary.UnmappedRules = len(r.UnmappedRules)
	r.Summary.RemoteRules = len(r.RemoteRules)
	r.Summary.UnusedSources = len(r.UnusedTelemetry)

	sort.Slice(r.Sources, func(i, j int) bool { return r.Sources[i].Name < r.Sources[j].Name })
	sort.Slice(r.DeadDetections, func(i, j int) bool {
		a, b := r.DeadDetections[i], r.DeadDetections[j]
		if rank(a.Severity) != rank(b.Severity) {
			return rank(a.Severity) < rank(b.Severity)
		}
		return a.Name < b.Name
	})
	sort.Slice(r.ImpairedDetections, func(i, j int) bool {
		a, b := r.ImpairedDetections[i], r.ImpairedDetections[j]
		if rank(a.Severity) != rank(b.Severity) {
			return rank(a.Severity) < rank(b.Severity)
		}
		return a.Name < b.Name
	})
	sort.Slice(r.UnmappedRules, func(i, j int) bool { return r.UnmappedRules[i].Name < r.UnmappedRules[j].Name })
	return r
}

// windowsOnEventTime reports whether a rule's time range filters on event time
// (@timestamp), which is the only case ingest lag can blind. A rule with a
// timestamp override to the ingest-time field catches late events as they
// arrive, so lag cannot open a blind window; an override to any other field is
// not something the @timestamp-vs-event.ingested lag metric describes. Both are
// left out of the lag check rather than flagged on a guess.
func windowsOnEventTime(r backend.Rule) bool {
	switch r.TimestampOverride {
	case "", "@timestamp":
		return true
	default:
		return false
	}
}

// impairment evaluates the reduced-visibility checks for a live rule.
// Every check requires positive evidence and skips on any uncertainty.
func impairment(rule backend.Rule, matched []string, srcByName map[string]backend.Source, fields map[string]map[string]bool) (ImpairedDetection, bool) {
	imp := ImpairedDetection{ID: rule.ID, Name: rule.Name, Severity: rule.Severity, Sources: matched}

	// missing-fields: a declared field is missing when no matched source
	// with a fetched schema provides it. Requires at least one fetched schema.
	if fields != nil && len(rule.RequiredFields) > 0 {
		union := map[string]bool{}
		fetched := false
		for _, name := range matched {
			if fs, ok := fields[name]; ok {
				fetched = true
				for f := range fs {
					union[f] = true
				}
			}
		}
		if fetched {
			var missing []string
			for _, f := range rule.RequiredFields {
				if !union[f] {
					missing = append(missing, f)
				}
			}
			if len(missing) > 0 {
				sort.Strings(missing)
				imp.Reasons = append(imp.Reasons, ReasonMissingFields)
				imp.MissingFields = missing
			}
		}
	}

	// lag-blind-window: a source whose measured ingest lag exceeds the rule's
	// lookback-minus-interval margin can drop events between runs — an event
	// ingested that late is never inside a run's window while it is queryable.
	// Evaluated per source: a broad rule may read one laggy source and many
	// healthy ones, so the finding names the offending source(s) rather than
	// tainting the whole rule with a single stream's lag. Skipped entirely for
	// rules that window on ingest time, which the lag cannot blind.
	if windowsOnEventTime(rule) && rule.Lookback > 0 && rule.Interval > 0 && rule.Lookback > rule.Interval {
		margin := rule.Lookback - rule.Interval
		var lagSources []string
		var maxLag time.Duration
		for _, name := range matched {
			lag := srcByName[name].IngestLag
			if lag != nil && *lag > margin {
				lagSources = append(lagSources, name)
				if *lag > maxLag {
					maxLag = *lag
				}
			}
		}
		if len(lagSources) > 0 {
			sort.Strings(lagSources)
			imp.Reasons = append(imp.Reasons, ReasonLagBlindWindow)
			imp.LookbackSeconds = rule.Lookback.Seconds()
			imp.IntervalSeconds = rule.Interval.Seconds()
			imp.MaxLagSeconds = maxLag.Seconds()
			imp.LagSources = lagSources
		}
	}

	return imp, len(imp.Reasons) > 0
}

// CandidateExitCode gates on the rule under test only: pre-existing source
// degradation elsewhere in the environment must not fail a rule's CI check.
func (r *Report) CandidateExitCode() int {
	if r.Summary.DeadDetections > 0 || r.Summary.ImpairedDetections > 0 {
		return ExitFindings
	}
	return ExitHealthy
}

// ExitCode maps the report to the scan exit code.
func (r *Report) ExitCode() int {
	if r.Summary.DeadDetections > 0 || r.Summary.DegradedSources > 0 || r.Summary.VolumeLowSources > 0 || r.Summary.SchemaDriftSources > 0 || r.Summary.ImpairedDetections > 0 {
		return ExitFindings
	}
	return ExitHealthy
}

func typeChanges(changes []state.FieldTypeChange) []FieldTypeChange {
	out := make([]FieldTypeChange, 0, len(changes))
	for _, c := range changes {
		out = append(out, FieldTypeChange{
			Name:   c.Name,
			Before: append([]string(nil), c.Before...),
			After:  append([]string(nil), c.After...),
		})
	}
	return out
}

// Redact replaces every source, rule, and pattern name with a stable digest
// so the report can be shared without publishing the blind-spot map it
// describes. Digests are deterministic, so cross-references within a report
// (and across reports of the same deployment) still line up.
func (r *Report) Redact() {
	if r.Redacted {
		return
	}
	r.Redacted = true
	for i := range r.Sources {
		r.Sources[i].Name = redact("src", r.Sources[i].Name)
		if r.Sources[i].Schema != nil {
			redactSchema(r.Sources[i].Schema)
		}
	}
	for i := range r.DeadDetections {
		d := &r.DeadDetections[i]
		d.ID = redact("rule", d.ID)
		d.Name = redact("rule", d.Name)
		for j := range d.Patterns {
			d.Patterns[j] = redact("pat", d.Patterns[j])
		}
		for j := range d.Sources {
			d.Sources[j] = redact("src", d.Sources[j])
		}
	}
	for i := range r.ImpairedDetections {
		d := &r.ImpairedDetections[i]
		d.ID = redact("rule", d.ID)
		d.Name = redact("rule", d.Name)
		for j := range d.Sources {
			d.Sources[j] = redact("src", d.Sources[j])
		}
		for j := range d.LagSources {
			d.LagSources[j] = redact("src", d.LagSources[j])
		}
		for j := range d.MissingFields {
			d.MissingFields[j] = redact("field", d.MissingFields[j])
		}
	}
	for i := range r.UnmappedRules {
		r.UnmappedRules[i].ID = redact("rule", r.UnmappedRules[i].ID)
		r.UnmappedRules[i].Name = redact("rule", r.UnmappedRules[i].Name)
	}
	for i := range r.RemoteRules {
		r.RemoteRules[i].ID = redact("rule", r.RemoteRules[i].ID)
		r.RemoteRules[i].Name = redact("rule", r.RemoteRules[i].Name)
	}
	for i := range r.UnusedTelemetry {
		r.UnusedTelemetry[i].Name = redact("src", r.UnusedTelemetry[i].Name)
	}
}

func redactSchema(schema *SchemaHealth) {
	for i := range schema.Added {
		schema.Added[i] = redact("field", schema.Added[i])
	}
	for i := range schema.Removed {
		schema.Removed[i] = redact("field", schema.Removed[i])
	}
	for i := range schema.TypeChanged {
		schema.TypeChanged[i].Name = redact("field", schema.TypeChanged[i].Name)
	}
}

func redact(prefix, name string) string {
	sum := sha256.Sum256([]byte(name))
	return prefix + "-" + hex.EncodeToString(sum[:])[:12]
}

// Write writes the JSON report to path with 0600 permissions.
func (r *Report) Write(path string) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding report: %w", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("writing report: %w", err)
	}
	return nil
}
