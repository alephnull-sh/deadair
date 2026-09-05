package report

import (
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/alephnull-sh/deadair/internal/backend"
	"github.com/alephnull-sh/deadair/internal/graph"
	"github.com/alephnull-sh/deadair/internal/health"
	redactpkg "github.com/alephnull-sh/deadair/internal/redact"
)

// SourceImpact keeps confirmed consumers beside the observations that an
// operator needs to investigate. Consumption alone is not a failure verdict.
type SourceImpact struct {
	Source        string              `json:"source"`
	Status        string              `json:"status"`
	FirstCheck    string              `json:"first_check,omitempty"`
	Owner         string              `json:"owner,omitempty"`
	Runbook       string              `json:"runbook,omitempty"`
	URL           string              `json:"url,omitempty"`
	MissingFields []string            `json:"missing_fields,omitempty"`
	IngestLag     *IngestLagHealth    `json:"ingest_lag,omitempty"`
	Volume        *VolumeHealth       `json:"volume,omitempty"`
	Schema        *SchemaHealth       `json:"schema,omitempty"`
	Freshness     []SourceObservation `json:"freshness,omitempty"`
	Detections    []SourceConsumer    `json:"detections,omitempty"`
}

type SourceConsumer struct {
	RuleID          string                 `json:"rule_id"`
	BackendObjectID string                 `json:"backend_object_id,omitempty"`
	Name            string                 `json:"name"`
	Severity        string                 `json:"severity"`
	Basis           backend.FreshnessBasis `json:"basis"`
	Status          string                 `json:"status"`
	URL             string                 `json:"url,omitempty"`
}

type SourceObservation struct {
	Basis            backend.FreshnessBasis `json:"basis"`
	Status           backend.EvidenceStatus `json:"status"`
	FreshnessStatus  string                 `json:"freshness_status"`
	ObservedAt       time.Time              `json:"observed_at"`
	LastEvent        *time.Time             `json:"last_event,omitempty"`
	WindowSeconds    float64                `json:"window_seconds,omitempty"`
	AgeSeconds       float64                `json:"age_seconds,omitempty"`
	AgeLowerBound    bool                   `json:"age_lower_bound,omitempty"`
	ExpectedDowntime bool                   `json:"expected_downtime,omitempty"`
	Method           string                 `json:"method,omitempty"`
	Detail           string                 `json:"detail,omitempty"`
}

func ruleClock(rule backend.Rule) backend.FreshnessBasis {
	if strings.EqualFold(strings.TrimSpace(rule.TimestampOverride), "ingestion_time()") {
		return backend.FreshnessIngestionTime
	}
	return backend.FreshnessEventTime
}

func assessRuleClock(source backend.Source, rule backend.Rule, check health.Check, policy *Policy) health.Assessment {
	if len(source.Freshness.Clocks) > 0 {
		item, ok := source.Freshness.Clocks[ruleClock(rule)]
		if !ok || item.Status != backend.EvidenceAssessed {
			return health.Assessment{Status: health.StatusUnknown}
		}
		source.Freshness, source.LastEvent, source.Docs = item, item.LastEvent, -1
	}
	check.MaxStale = policy.MaxStaleFor(source.Name, check.MaxStale)
	return check.Evaluate(source)
}

func sourceObservation(source backend.Source, basis backend.FreshnessBasis, item backend.FreshnessEvidence, check health.Check) SourceObservation {
	if item.Status == "" {
		item.Status = backend.EvidenceUnavailable
	}
	out := SourceObservation{Basis: basis, Status: item.Status, ObservedAt: item.ObservedAt,
		WindowSeconds: item.Window.Seconds(), Method: item.Method, Detail: item.Detail, FreshnessStatus: "unknown"}
	if item.Status != backend.EvidenceAssessed {
		return out
	}
	if !item.LastEvent.IsZero() {
		last := item.LastEvent
		out.LastEvent = &last
	}
	source.Freshness, source.LastEvent = item, item.LastEvent
	if item.Method != "source-inventory" {
		source.Docs = -1
	}
	a := check.Evaluate(source)
	out.FreshnessStatus, out.AgeSeconds, out.AgeLowerBound, out.ExpectedDowntime = string(a.Status), a.Age.Seconds(), a.AgeLowerBound, a.ExpectedDowntime
	return out
}

func buildSourceImpacts(r *Report, g *graph.Graph, opts BuildOptions) []SourceImpact {
	rules := make(map[string]backend.Rule, len(g.Rules))
	for _, rule := range g.Rules {
		rules[rule.ID] = rule
	}
	statuses := make(map[string]string)
	for _, rule := range r.DeadDetections {
		statuses[logicalDetectionRuleID(rule.ID, rule.RuleID)] = "cannot_fire"
	}
	for _, rule := range r.ImpairedDetections {
		statuses[logicalDetectionRuleID(rule.ID, rule.RuleID)] = "impaired"
	}
	healthBySource := make(map[string]SourceHealth, len(r.Sources))
	for _, item := range r.Sources {
		healthBySource[item.Name] = item
	}
	missingBySource := make(map[string]map[string]bool)
	for _, evidence := range r.RequiredFieldEvidence {
		for _, fields := range evidence.Sources {
			if fields.Status != backend.EvidenceAssessed {
				continue
			}
			for _, field := range fields.Missing {
				if missingBySource[fields.Source] == nil {
					missingBySource[fields.Source] = make(map[string]bool)
				}
				missingBySource[fields.Source][field] = true
			}
		}
	}
	lagSources := make(map[string]bool)
	for _, rule := range r.ImpairedDetections {
		for _, source := range rule.LagSources {
			lagSources[source] = true
		}
	}
	producerSources := make(map[string]bool)
	if opts.Policy != nil {
		for _, producer := range opts.Policy.Producers {
			producerSources[producer.Source] = true
		}
	}
	var out []SourceImpact
	for _, source := range g.Sources {
		if opts.Scope != nil && !opts.Scope[source.Name] && !producerSources[source.Name] {
			continue
		}
		check := opts.Check
		check.MaxStale = opts.Policy.MaxStaleFor(source.Name, check.MaxStale)
		impact := SourceImpact{Source: source.Name, Status: string(check.Evaluate(source).Status)}
		if health, ok := healthBySource[source.Name]; ok {
			if health.IngestLag != nil {
				lag := *health.IngestLag
				impact.IngestLag = &lag
			}
			if health.Volume != nil {
				volume := *health.Volume
				impact.Volume = &volume
				if volume.Status == "low" {
					impact.FirstCheck = "Compare the feed's delivery rate with its normal weekday and hour."
				}
			}
			if health.Schema != nil {
				schema := *health.Schema
				schema.Added, schema.Removed, schema.TypeChanged = slices.Clone(schema.Added), slices.Clone(schema.Removed), slices.Clone(schema.TypeChanged)
				impact.Schema = &schema
				if schema.Status == "drift" {
					impact.FirstCheck = "Review the changed field mapping and recent integration updates."
				}
			}
		}
		if opts.SourceURL != nil {
			impact.URL = opts.SourceURL(source.Name)
		}
		if impact.Status == "empty" {
			impact.FirstCheck = "Check whether the sender is configured to deliver events to this source."
		}
		if opts.Policy != nil {
			for _, p := range opts.Policy.Sources {
				if graph.Match(p.Pattern, source.Name) {
					impact.Owner, impact.Runbook = p.Owner, p.Runbook
					break
				}
			}
		}
		for _, basis := range []backend.FreshnessBasis{backend.FreshnessEventTime, backend.FreshnessIngestionTime} {
			if item, ok := source.Freshness.Clocks[basis]; ok {
				impact.Freshness = append(impact.Freshness, sourceObservation(source, basis, item, check))
			}
		}
		for _, id := range g.RulesFor(source.Name) {
			rule := rules[id]
			if !rule.Enabled {
				continue
			}
			status := statuses[id]
			if status == "" {
				status = "consumes_source"
			}
			if ruleInputUncertain(r, id) {
				status = "unassessed"
			}
			impact.Detections = append(impact.Detections, SourceConsumer{RuleID: id,
				BackendObjectID: rule.BackendObjectID, Name: rule.Name, Severity: rule.Severity, Basis: ruleClock(rule), Status: status})
			if opts.RuleURL != nil {
				impact.Detections[len(impact.Detections)-1].URL = opts.RuleURL(rule)
			}
		}
		if len(impact.Freshness) == 0 {
			basis := backend.FreshnessEventTime
			if len(impact.Detections) > 0 {
				basis = impact.Detections[0].Basis
			}
			item := source.Freshness
			if item.Status == "" && (!source.LastEvent.IsZero() || source.Docs == 0) {
				item = backend.FreshnessEvidence{Status: backend.EvidenceAssessed, LastEvent: source.LastEvent, ObservedAt: r.GeneratedAt, Method: "source-inventory"}
			}
			impact.Freshness = append(impact.Freshness, sourceObservation(source, basis, item, check))
		}
		for _, observation := range impact.Freshness {
			if observation.FreshnessStatus == "stale" {
				impact.FirstCheck = "Check the sender and its collector for recent delivery errors."
			}
		}
		for field := range missingBySource[source.Name] {
			impact.MissingFields = append(impact.MissingFields, field)
		}
		if len(impact.MissingFields) > 0 {
			impact.FirstCheck = "Compare the missing fields with the source mapping and ingestion transform."
		}
		if source.IngestLag.Status == backend.EvidenceAssessed && lagSources[source.Name] {
			impact.FirstCheck = "Check collector queues and event timestamps against the rule's lookback window."
		}
		sort.Strings(impact.MissingFields)
		sort.Slice(impact.Detections, func(i, j int) bool {
			a, b := impact.Detections[i], impact.Detections[j]
			if rank(a.Severity) != rank(b.Severity) {
				return rank(a.Severity) < rank(b.Severity)
			}
			if a.Name != b.Name {
				return a.Name < b.Name
			}
			return a.RuleID < b.RuleID
		})
		out = append(out, impact)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if (a.FirstCheck != "") != (b.FirstCheck != "") {
			return a.FirstCheck != ""
		}
		ar, br := 5, 5
		if len(a.Detections) > 0 {
			ar = rank(a.Detections[0].Severity)
		}
		if len(b.Detections) > 0 {
			br = rank(b.Detections[0].Severity)
		}
		if ar != br {
			return ar < br
		}
		return a.Source < b.Source
	})
	return out
}

func (r *Report) redactSourceImpacts(redactor *redactpkg.Redactor) {
	for i := range r.SourceImpacts {
		s := &r.SourceImpacts[i]
		s.Source = redactor.Value("src", s.Source)
		if s.Owner != "" {
			s.Owner = redactor.Value("owner", s.Owner)
		}
		s.URL, s.Runbook = "", ""
		if s.Schema != nil {
			redactSchema(redactor, s.Schema)
		}
		for j := range s.MissingFields {
			s.MissingFields[j] = redactor.Value("field", s.MissingFields[j])
		}
		if s.IngestLag != nil && s.IngestLag.Detail != "" {
			s.IngestLag.Detail = "measurement detail withheld"
		}
		for j := range s.Freshness {
			if s.Freshness[j].Detail != "" {
				s.Freshness[j].Detail = "measurement detail withheld"
			}
		}
		for j := range s.Detections {
			d := &s.Detections[j]
			d.RuleID = redactor.Value("rule", d.RuleID)
			if d.BackendObjectID != "" {
				d.BackendObjectID = redactor.Value("obj", d.BackendObjectID)
			}
			d.Name, d.URL = redactor.Value("rule", d.Name), ""
		}
	}
}
