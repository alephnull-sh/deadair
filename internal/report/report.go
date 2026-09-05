// Package report assembles scan results into the tool's primary artifact.
// A report is a literal blind-spot map of a SOC: treat it as sensitive by
// default. Files are atomically replaced with mode 0600 on POSIX systems.
// Redact replaces identifiers with keyed HMAC pseudonyms, but the resulting
// finding counts and structure may still be sensitive.
package report

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/alephnull-sh/deadair/internal/backend"
	"github.com/alephnull-sh/deadair/internal/graph"
	"github.com/alephnull-sh/deadair/internal/health"
	redactpkg "github.com/alephnull-sh/deadair/internal/redact"
	"github.com/alephnull-sh/deadair/internal/securefile"
	"github.com/alephnull-sh/deadair/internal/state"
)

// Exit codes for `deadair scan`, designed as a CI gate.
const (
	ExitHealthy  = 0 // no findings that affect the default gate
	ExitFindings = 1 // dead detections or degraded sources
	ExitError    = 2 // the scan itself failed
)

// Report is the full scan result.
type Report struct {
	SchemaVersion   string          `json:"schema_version"`
	GeneratedAt     time.Time       `json:"generated_at"`
	Producer        Producer        `json:"producer"`
	Backend         string          `json:"backend"`
	BackendMetadata BackendMetadata `json:"backend_metadata"`
	// TargetID identifies the configured backend endpoint and namespace. Diff
	// requires it so reports from different deployments cannot be compared
	// accidentally; redaction pseudonymizes it before external use.
	TargetID string    `json:"target_id,omitempty"`
	Scope    ScanScope `json:"scope"`
	// Instance names the fleet member (tenant / deployment) this report
	// describes. Defaults to the backend name in single-instance mode.
	Instance           string              `json:"instance,omitempty"`
	Redacted           bool                `json:"redacted,omitempty"`
	Redaction          *RedactionMetadata  `json:"redaction,omitempty"`
	Summary            Summary             `json:"summary"`
	Assessments        []RuntimeAssessment `json:"assessments,omitempty"`
	Sources            []SourceHealth      `json:"sources"`
	DeadDetections     []DeadDetection     `json:"dead_detections"`
	ImpairedDetections []ImpairedDetection `json:"impaired_detections,omitempty"`
	UnmappedRules      []RuleRef           `json:"unmapped_rules,omitempty"`
	// InputResolutions retains the backend-native evidence used to connect
	// rule inputs to concrete sources. Only an empty authoritative result can
	// substantiate a disconnected finding; diagnostic empties describe partial
	// coverage and uncertainty stays visible here instead.
	InputResolutions []backend.InputResolution `json:"input_resolutions,omitempty"`
	// DependencyEvidence retains assessed non-telemetry dependencies alongside
	// the source graph. It is informational unless its corresponding input
	// resolution independently contributes to an existing rule verdict.
	DependencyEvidence []DependencyEvidence `json:"dependency_evidence,omitempty"`
	// RuleProvenance records template, package, or other origin metadata made
	// available by a backend. Provenance never creates a finding or gate.
	RuleProvenance []RuleProvenance `json:"rule_provenance,omitempty"`
	// SourceLineage records observed transformations such as raw table ->
	// summary rule -> output table. Detection health remains tied to the
	// concrete source read by the rule.
	SourceLineage []SourceLineage `json:"source_lineage,omitempty"`
	// RuleSourceFreshness keeps parser-proved, predicate-qualified observations
	// separate from table-wide source health. These records are informational
	// and do not create findings or gates.
	RuleSourceFreshness []RuleSourceFreshness `json:"rule_source_freshness,omitempty"`
	// SummaryRuleRuns records bounded LASummaryLogs observations for summary
	// rules whose outputs feed enabled detections. Native failures remain
	// informational evidence.
	SummaryRuleRuns []SummaryRuleRun `json:"summary_rule_runs,omitempty"`
	// RemoteRules query cross-cluster (cluster:pattern) inputs deadair cannot
	// verify from this deployment. Listed, never called dead.
	RemoteRules           []RuleRef                 `json:"remote_rules,omitempty"`
	PartialInputCoverage  []PartialInputCoverage    `json:"partial_input_coverage,omitempty"`
	UnusedTelemetry       []UnusedSource            `json:"unused_telemetry"`
	Findings              []Finding                 `json:"findings,omitempty"`
	RecoveredFindings     []Finding                 `json:"recovered_findings,omitempty"`
	Policy                *PolicySummary            `json:"policy,omitempty"`
	RequiredFieldEvidence []RequiredFieldAssessment `json:"required_field_evidence,omitempty"`
	SourceImpacts         []SourceImpact            `json:"source_impacts,omitempty"`
	Producers             []ProducerHealth          `json:"producers,omitempty"`
}

const (
	AssessmentSourceResolution   = "source_resolution"
	AssessmentSourceFreshness    = "source_freshness"
	AssessmentRequiredFields     = "required_fields"
	AssessmentIngestLag          = "ingest_lag"
	AssessmentPredicateFreshness = "predicate_freshness"
	AssessmentSchemaDrift        = "schema_drift"
	AssessmentCandidateParsing   = "candidate_parsing"
)

// RuntimeAssessment describes what this scan actually assessed. Static
// backend capability support remains in BackendMetadata.
type RuntimeAssessment struct {
	Name   string                 `json:"name"`
	Status backend.EvidenceStatus `json:"status"`
	Detail string                 `json:"detail,omitempty"`
}

// DependencyEvidence is the report form of one backend dependency
// observation. Dependencies that are not monitorable telemetry remain visible
// here without being coerced into source-health findings.
type DependencyEvidence struct {
	RuleID           string                   `json:"rule_id"`
	BackendObjectID  string                   `json:"backend_object_id,omitempty"`
	RuleName         string                   `json:"rule_name,omitempty"`
	Severity         string                   `json:"severity,omitempty"`
	Dependency       backend.DependencyRef    `json:"dependency"`
	Status           backend.ResolutionStatus `json:"status"`
	ResolutionMethod string                   `json:"resolution_method"`
	ObservedAt       time.Time                `json:"observed_at"`
	Detail           string                   `json:"detail,omitempty"`
}

// RuleProvenance records a backend-reported rule origin. It is deliberately
// evidence-only: a package or template mismatch is not a detection-health
// verdict.
type RuleProvenance struct {
	RuleID          string                 `json:"rule_id"`
	BackendObjectID string                 `json:"backend_object_id,omitempty"`
	RuleName        string                 `json:"rule_name,omitempty"`
	Provenance      backend.ProvenanceRef  `json:"provenance"`
	Status          backend.EvidenceStatus `json:"status"`
	Method          string                 `json:"method"`
	ObservedAt      time.Time              `json:"observed_at"`
	Detail          string                 `json:"detail,omitempty"`
}

// SourceLineage is the report form of an observed backend transformation.
// It intentionally does not feed the rule-to-source health graph.
type SourceLineage struct {
	ID         string                 `json:"id,omitempty"`
	Kind       string                 `json:"kind"`
	Name       string                 `json:"name,omitempty"`
	Input      backend.DependencyRef  `json:"input"`
	Output     backend.DependencyRef  `json:"output"`
	Status     backend.EvidenceStatus `json:"status"`
	Method     string                 `json:"method"`
	ObservedAt time.Time              `json:"observed_at"`
	Detail     string                 `json:"detail,omitempty"`
}

// RuleSourceFreshness is the report form of one rule/source slice observation.
// Predicate literal values and backend query text are deliberately omitted.
type RuleSourceFreshness struct {
	RuleID           string                 `json:"rule_id"`
	BackendObjectID  string                 `json:"backend_object_id,omitempty"`
	RuleName         string                 `json:"rule_name,omitempty"`
	Source           string                 `json:"source"`
	Fields           []string               `json:"fields,omitempty"`
	Status           backend.EvidenceStatus `json:"status"`
	Method           string                 `json:"method,omitempty"`
	ObservedAt       time.Time              `json:"observed_at"`
	WindowSeconds    float64                `json:"window_seconds,omitempty"`
	LastEvent        *time.Time             `json:"last_event,omitempty"`
	FreshnessStatus  string                 `json:"freshness_status"`
	AgeSeconds       float64                `json:"age_seconds,omitempty"`
	AgeLowerBound    bool                   `json:"age_lower_bound,omitempty"`
	ExpectedDowntime bool                   `json:"expected_downtime,omitempty"`
	Detail           string                 `json:"detail,omitempty"`
}

// SummaryRuleRun is the report form of the latest bounded completed runtime observation
// for one relevant Log Analytics summary rule.
type SummaryRuleRun struct {
	ID                  string                 `json:"id,omitempty"`
	Rule                backend.DependencyRef  `json:"rule"`
	Output              backend.DependencyRef  `json:"output"`
	Status              backend.EvidenceStatus `json:"status"`
	Method              string                 `json:"method"`
	ObservedAt          time.Time              `json:"observed_at"`
	WindowSeconds       float64                `json:"window_seconds,omitempty"`
	RunAt               *time.Time             `json:"run_at,omitempty"`
	RunStatus           string                 `json:"run_status,omitempty"`
	QueryDurationMillis *int64                 `json:"query_duration_millis,omitempty"`
	ResultCount         *int64                 `json:"result_count,omitempty"`
	RuleModifiedAt      *time.Time             `json:"rule_modified_at,omitempty"`
	Error               string                 `json:"error,omitempty"`
	Detail              string                 `json:"detail,omitempty"`
	HealthStatus        string                 `json:"health_status,omitempty"`
	ExpectedDowntime    bool                   `json:"expected_downtime,omitempty"`
}

// RedactionMetadata identifies the keyed pseudonymization applied to a
// report. KeyID contains no key material and lets consumers determine whether
// two redacted reports can be correlated. It assumes the caller supplied a
// high-entropy random key.
type RedactionMetadata struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
}

// Summary is the roll-up used for exit codes and exporter aggregates.
type Summary struct {
	Rules              int                    `json:"rules"`
	EnabledRules       int                    `json:"enabled_rules"`
	Sources            int                    `json:"sources"`
	HealthySources     int                    `json:"healthy_sources"`
	DegradedSources    int                    `json:"degraded_sources"`
	DeadDetections     int                    `json:"dead_detections"`
	ImpairedDetections int                    `json:"impaired_detections,omitempty"`
	UnmappedRules      int                    `json:"unmapped_rules"`
	RemoteRules        int                    `json:"remote_rules,omitempty"`
	PartialInputs      int                    `json:"partial_inputs,omitempty"`
	UnusedSources      int                    `json:"unused_sources"`
	UnusedBytes        int64                  `json:"unused_bytes"`
	VolumeLowSources   int                    `json:"volume_low_sources,omitempty"`
	SchemaDriftSources int                    `json:"schema_drift_sources,omitempty"`
	GatedFindings      int                    `json:"gated_findings,omitempty"`
	InputResolution    InputResolutionSummary `json:"input_resolution"`
	// UnusedTelemetryAssessment says whether zero-consumer source findings are
	// complete, based on legacy matching, unavailable, or intentionally skipped.
	UnusedTelemetryAssessment UnusedTelemetryAssessment `json:"unused_telemetry_assessment"`
	// UnusedTelemetryAssessmentDetail explains why the assessment is unavailable.
	// It is additive and omitted for complete, legacy, and not-applicable reports.
	UnusedTelemetryAssessmentDetail string `json:"unused_telemetry_assessment_detail,omitempty"`
}

// UnusedTelemetryAssessment describes the confidence behind unused telemetry.
type UnusedTelemetryAssessment string

const (
	UnusedAssessmentComplete      UnusedTelemetryAssessment = "complete"
	UnusedAssessmentLegacy        UnusedTelemetryAssessment = "legacy"
	UnusedAssessmentUnavailable   UnusedTelemetryAssessment = "unavailable"
	UnusedAssessmentNotApplicable UnusedTelemetryAssessment = "not-applicable"
)

const unresolvedUnusedTelemetryDetail = "one or more enabled local rule inputs could not be resolved safely"

// UnusedTelemetryExplanation returns the stored explanation, or the historical
// unresolved-input explanation when rendering an older unavailable report.
func (s Summary) UnusedTelemetryExplanation() string {
	if detail := strings.TrimSpace(s.UnusedTelemetryAssessmentDetail); detail != "" {
		return detail
	}
	return unresolvedUnusedTelemetryDetail
}

// InputResolutionSummary counts native selector outcomes across the rule
// inventory. Counts describe evidence, not findings or exit-code gates.
type InputResolutionSummary struct {
	Resolved    int `json:"resolved"`
	Empty       int `json:"empty"`
	Unsupported int `json:"unsupported"`
	Unavailable int `json:"unavailable"`
	Remote      int `json:"remote"`
	Ambiguous   int `json:"ambiguous"`
	// Incompatible counts concrete incompatible inputs when per-input
	// diagnostics are available, otherwise authoritative incompatible results.
	Incompatible int `json:"incompatible"`
}

// SourceHealth is one source with its verdict and known blast-radius size.
type SourceHealth struct {
	Name          string  `json:"name"`
	Status        string  `json:"status"`
	AgeSeconds    float64 `json:"age_seconds,omitempty"`
	AgeLowerBound bool    `json:"age_lower_bound,omitempty"`
	Docs          int64   `json:"docs"`
	SizeBytes     int64   `json:"size_bytes"`
	// ExpectedDowntime is true when an expected downtime window suppressed a
	// stale or empty verdict for this source.
	ExpectedDowntime bool             `json:"expected_downtime,omitempty"`
	Volume           *VolumeHealth    `json:"volume,omitempty"`
	Schema           *SchemaHealth    `json:"schema,omitempty"`
	IngestLag        *IngestLagHealth `json:"ingest_lag,omitempty"`
	// Consumers is the number of enabled rules positively resolved to this
	// source. It is a lower bound when unused_telemetry_assessment is unavailable.
	Consumers int `json:"consumers"`
}

// IngestLagHealth is paired same-event evidence from a bounded recent sample.
type IngestLagHealth struct {
	Status        backend.EvidenceStatus `json:"status"`
	Method        string                 `json:"method,omitempty"`
	ObservedAt    *time.Time             `json:"observed_at,omitempty"`
	WindowSeconds float64                `json:"window_seconds,omitempty"`
	SampleCount   int                    `json:"sample_count,omitempty"`
	P95Seconds    float64                `json:"p95_seconds,omitempty"`
	MaxSeconds    float64                `json:"max_seconds,omitempty"`
	Detail        string                 `json:"detail,omitempty"`
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
	ReasonDisconnected           = "disconnected"
	ReasonStarved                = "starved"
	ReasonSourcePlanIncompatible = "source-plan-incompatible"
)

// DeadReasonLabel returns the plain-language label used in human reports.
func DeadReasonLabel(reason string) string {
	switch reason {
	case ReasonDisconnected:
		return "no matching source"
	case ReasonStarved:
		return "all matching sources stale or empty"
	case ReasonSourcePlanIncompatible:
		return "source configuration is incompatible with this rule"
	default:
		return reason
	}
}

// DeadDetection is an enabled rule that cannot currently fire.
type DeadDetection struct {
	// ID keeps the v1 backend-object identifier. RuleID is the logical rule
	// identity used by findings and remains stable across Elastic re-imports.
	ID              string `json:"id"`
	RuleID          string `json:"rule_id,omitempty"`
	BackendObjectID string `json:"backend_object_id,omitempty"`
	Name            string `json:"name"`
	Severity        string `json:"severity"`
	// Reason is a stable machine-readable code. Use DeadReasonLabel in output
	// intended for people.
	Reason   string   `json:"reason"`
	Patterns []string `json:"patterns"`
	// Sources contains the affected concrete sources when the reason is tied
	// to known source state or configuration.
	Sources []string `json:"sources,omitempty"`
}

// RuleRef identifies a rule whose inputs cannot be mapped from metadata.
type RuleRef struct {
	// ID keeps the v1 backend-object identifier. RuleID is the logical rule
	// identity used by findings and comparisons.
	ID               string                   `json:"id"`
	RuleID           string                   `json:"rule_id,omitempty"`
	BackendObjectID  string                   `json:"backend_object_id,omitempty"`
	FindingID        string                   `json:"finding_id,omitempty"`
	Reason           string                   `json:"reason,omitempty"`
	Dependency       string                   `json:"dependency,omitempty"`
	Name             string                   `json:"name"`
	Severity         string                   `json:"severity"`
	AssessmentStatus backend.ResolutionStatus `json:"assessment_status,omitempty"`
	Detail           string                   `json:"detail,omitempty"`
}

// VisibleUnmappedRules returns coverage gaps that warrant space in the primary
// human report. Known non-query Sentinel rules stay in JSON and capability
// evidence without being presented as operator work.
func (r *Report) VisibleUnmappedRules() []RuleRef {
	visible := make([]RuleRef, 0, len(r.UnmappedRules))
	for _, rule := range r.UnmappedRules {
		if r.Scope.Mode != "candidate" && strings.EqualFold(r.Backend, "sentinel") &&
			strings.EqualFold(rule.RuleID, "BuiltInFusion") &&
			rule.AssessmentStatus == backend.ResolutionUnsupported &&
			rule.Detail == "Sentinel Fusion alert rules are not assessed" {
			continue
		}
		visible = append(visible, rule)
	}
	return visible
}

// Impairment reasons: the rule fires, but with degraded vision.
const (
	ReasonMissingFields  = "missing-fields"   // declared fields absent from one or more fully assessed sources
	ReasonLagBlindWindow = "lag-blind-window" // a source's ingest lag exceeds the query-window margin
	ReasonSelectorEmpty  = "selector-empty"   // one selector is empty while the combined input still resolves
)

// ImpairedReasonLabel returns the plain-language label used in human reports.
func ImpairedReasonLabel(reason string) string {
	switch reason {
	case ReasonMissingFields:
		return "required fields are missing"
	case ReasonLagBlindWindow:
		return "events may arrive too late for the rule"
	case ReasonSelectorEmpty:
		return "one input selector has no matching source"
	case ReasonSourcePlanIncompatible:
		return "one or more sources are incompatible with this rule"
	default:
		return reason
	}
}

// FindingClassLabel returns the plain-language label used in human diffs.
func FindingClassLabel(class string) string {
	switch class {
	case FindingDead:
		return "detection can't fire"
	case FindingImpaired:
		return "reduced visibility"
	case FindingSourceDegraded:
		return "source degraded"
	case FindingVolumeLow:
		return "low volume"
	case FindingSchemaDrift:
		return "schema changed"
	case FindingUnused:
		return "unused telemetry"
	case FindingPartialInput:
		return "partial input"
	case FindingProducerStale:
		return "expected feed is quiet"
	case FindingSummaryPipeline:
		return "summary pipeline needs attention"
	default:
		return strings.ReplaceAll(class, "-", " ")
	}
}

// FindingReasonLabel returns a plain-language reason while JSON keeps the
// stable machine code.
func FindingReasonLabel(class, reason string) string {
	switch class {
	case FindingProducerStale:
		return "producer has exceeded its reporting interval"
	case FindingSummaryPipeline:
		return "summary pipeline failed or fell behind its schedule"
	case FindingDead:
		return DeadReasonLabel(reason)
	case FindingImpaired, FindingPartialInput:
		return ImpairedReasonLabel(reason)
	case FindingSourceDegraded:
		switch reason {
		case "stale":
			return "source is stale"
		case "empty":
			return "source has no events"
		}
	case FindingVolumeLow:
		return "volume is below its baseline"
	case FindingSchemaDrift:
		return "field schema changed"
	case FindingUnused:
		return "no enabled detection uses this source"
	}
	return strings.ReplaceAll(reason, "-", " ")
}

// ImpairedDetection is an enabled rule whose sources are alive but whose
// effective visibility is reduced. Distinct from dead: it can still fire.
type ImpairedDetection struct {
	// ID keeps the v1 backend-object identifier. RuleID is the logical rule
	// identity used by findings and remains stable across Elastic re-imports.
	ID              string   `json:"id"`
	RuleID          string   `json:"rule_id,omitempty"`
	BackendObjectID string   `json:"backend_object_id,omitempty"`
	Name            string   `json:"name"`
	Severity        string   `json:"severity"`
	Reasons         []string `json:"reasons"`
	MissingFields   []string `json:"missing_fields,omitempty"`
	LookbackSeconds float64  `json:"lookback_seconds,omitempty"`
	IntervalSeconds float64  `json:"interval_seconds,omitempty"`
	MaxLagSeconds   float64  `json:"max_lag_seconds,omitempty"`
	P95LagSeconds   float64  `json:"p95_lag_seconds,omitempty"`
	// LagSources names the specific matched sources whose ingest lag exceeds
	// the margin — a broad rule may read one laggy source and many healthy ones.
	LagSources          []string `json:"lag_sources,omitempty"`
	IncompatibleSources []string `json:"incompatible_sources,omitempty"`
	Sources             []string `json:"sources,omitempty"`
}

// RequiredFieldAssessment preserves field evidence per concrete source. A
// source whose field_caps read failed remains incomplete; it is never folded
// into a missing-field conclusion.
type RequiredFieldAssessment struct {
	RuleID   string                        `json:"rule_id"`
	RuleName string                        `json:"rule_name"`
	Sources  []RequiredFieldSourceEvidence `json:"sources"`
}

type RequiredFieldSourceEvidence struct {
	Source  string                 `json:"source"`
	Status  backend.EvidenceStatus `json:"status"`
	Present []string               `json:"present,omitempty"`
	Missing []string               `json:"missing,omitempty"`
	Detail  string                 `json:"detail,omitempty"`
}

// PartialInputCoverage records a selector that resolved empty even though the
// rule's authoritative combined expression resolved at least one source. This
// is diagnostic migration evidence; policy decides whether it gates.
type PartialInputCoverage struct {
	RuleID          string    `json:"rule_id"`
	BackendObjectID string    `json:"backend_object_id,omitempty"`
	RuleName        string    `json:"rule_name"`
	Severity        string    `json:"severity"`
	Selector        string    `json:"selector,omitempty"`
	Expression      string    `json:"expression"`
	ObservedAt      time.Time `json:"observed_at"`
}

// UnusedSource is stored telemetry read by no ENABLED detection. At realistic
// rule counts almost every pattern is
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

func legacyRuleID(rule backend.Rule) string {
	if rule.BackendObjectID != "" {
		return rule.BackendObjectID
	}
	return rule.ID
}

func logicalDetectionRuleID(id, ruleID string) string {
	if ruleID != "" {
		return ruleID
	}
	return id
}

func logicalInputResolutionRuleID(resolution backend.InputResolution) string {
	if resolution.LogicalRuleID != "" {
		return resolution.LogicalRuleID
	}
	return resolution.RuleID
}

func resolutionInputNames(resolution backend.InputResolution) []string {
	if len(resolution.ResolvedSources) > 0 {
		return append([]string(nil), resolution.ResolvedSources...)
	}
	if name := strings.TrimSpace(resolution.Selector); name != "" {
		return []string{name}
	}
	if name := strings.TrimSpace(resolution.Expression); name != "" {
		return []string{name}
	}
	return nil
}

func sortedUniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	sort.Strings(values)
	out := values[:0]
	for _, value := range values {
		if value == "" || (len(out) > 0 && out[len(out)-1] == value) {
			continue
		}
		out = append(out, value)
	}
	return out
}

func incompatibleResolutionCount(resolutions []backend.InputResolution) int {
	type ruleCount struct {
		authoritative int
		diagnostics   map[string]bool
	}
	byRule := make(map[string]*ruleCount)
	for i, resolution := range resolutions {
		if resolution.Status != backend.ResolutionIncompatible {
			continue
		}
		ruleID := logicalInputResolutionRuleID(resolution)
		count := byRule[ruleID]
		if count == nil {
			count = &ruleCount{diagnostics: make(map[string]bool)}
			byRule[ruleID] = count
		}
		if !resolution.Diagnostic {
			count.authoritative++
			continue
		}
		names := resolutionInputNames(resolution)
		if len(names) == 0 {
			names = []string{fmt.Sprintf("diagnostic-%d", i)}
		}
		for _, name := range names {
			count.diagnostics[name] = true
		}
	}
	total := 0
	for _, count := range byRule {
		if len(count.diagnostics) > 0 {
			total += len(count.diagnostics)
		} else {
			total += count.authoritative
		}
	}
	return total
}

// BuildOptions carries optional report inputs beyond fixed freshness health.
type BuildOptions struct {
	Check                  health.Check
	Volume                 map[string]state.VolumeAssessment
	Schema                 map[string]state.SchemaAssessment
	ProducerVersion        string
	BackendObservedVersion string
	// Scope, when non-nil, limits which sources are LISTED (sources section,
	// summary counts, unused telemetry, metrics). Verdicts are always computed
	// from the full inventory: scoping the report must never manufacture a
	// dead detection or hide a real one.
	Scope map[string]bool
	// SourceFields maps source name -> field set (from field_caps) for
	// missing-field checks. Deprecated compatibility input; FieldEvidence
	// preserves incomplete reads explicitly.
	SourceFields  map[string]map[string]bool
	FieldEvidence map[string]backend.FieldEvidence
	Assessments   []RuntimeAssessment
	// DependencyEvidence, ProvenanceEvidence, LineageEvidence, predicate
	// freshness, and summary runs are optional
	// read-only backend observations. They are copied into additive report
	// sections and never participate in findings or exit codes.
	DependencyEvidence         []backend.DependencyEvidence
	ProvenanceEvidence         []backend.ProvenanceEvidence
	LineageEvidence            []backend.LineageEvidence
	PredicateFreshnessEvidence []backend.RulePredicateFreshnessEvidence
	SummaryRuleRunEvidence     []backend.SummaryRuleRunEvidence
	ProducerEvidence           []backend.ProducerEvidence
	// UnusedTelemetryUnavailableDetail forces installed zero-consumer findings
	// unavailable when a backend lacks the inventory needed to assess them.
	UnusedTelemetryUnavailableDetail string
	// SkipUnused suppresses the unused-telemetry section; used in candidate
	// mode where a single rule under test would mark everything unused.
	SkipUnused bool
	// ScanScope is the configured boundary used to produce the report. It is
	// compared by diff; concrete discovered source names are deliberately not
	// part of it.
	ScanScope ScanScope
	Policy    *Policy
	Store     *state.Store
	TargetID  string
	Instance  string
	SourceURL func(string) string
	RuleURL   func(backend.Rule) string
}

// Build assembles the report from the dependency graph and a health check.
func Build(backendName string, g *graph.Graph, check health.Check) *Report {
	return BuildWithOptions(backendName, g, BuildOptions{Check: check})
}

// BuildWithOptions assembles the report from the dependency graph and L1
// health signals.
func BuildWithOptions(backendName string, g *graph.Graph, opts BuildOptions) *Report {
	r := &Report{
		SchemaVersion:    ReportSchemaVersion,
		GeneratedAt:      time.Now().UTC(),
		Producer:         producer(opts.ProducerVersion),
		Backend:          backendName,
		BackendMetadata:  backendMetadata(backendName, opts.BackendObservedVersion),
		TargetID:         opts.TargetID,
		Instance:         opts.Instance,
		Scope:            opts.ScanScope,
		InputResolutions: append([]backend.InputResolution(nil), g.Resolutions...),
		Assessments:      append([]RuntimeAssessment(nil), opts.Assessments...),
	}
	if r.Scope.Mode == "" {
		r.Scope.Mode = "installed"
	}
	sort.Strings(r.Scope.Include)
	sort.Strings(r.Scope.Exclude)
	sort.Strings(r.Scope.CandidateRuleIDs)
	for _, resolution := range r.InputResolutions {
		if resolution.Diagnostic {
			continue
		}
		switch resolution.Status {
		case backend.ResolutionResolved:
			r.Summary.InputResolution.Resolved++
		case backend.ResolutionEmpty:
			r.Summary.InputResolution.Empty++
		case backend.ResolutionUnsupported:
			r.Summary.InputResolution.Unsupported++
		case backend.ResolutionUnavailable:
			r.Summary.InputResolution.Unavailable++
		case backend.ResolutionRemote:
			r.Summary.InputResolution.Remote++
		case backend.ResolutionAmbiguous:
			r.Summary.InputResolution.Ambiguous++
		}
	}
	r.Summary.InputResolution.Incompatible = incompatibleResolutionCount(r.InputResolutions)
	r.Summary.UnusedTelemetryAssessment = unusedTelemetryAssessment(g, opts.SkipUnused)
	if detail := strings.TrimSpace(opts.UnusedTelemetryUnavailableDetail); detail != "" && !opts.SkipUnused {
		r.Summary.UnusedTelemetryAssessment = UnusedAssessmentUnavailable
		r.Summary.UnusedTelemetryAssessmentDetail = detail
	} else if r.Summary.UnusedTelemetryAssessment == UnusedAssessmentUnavailable {
		r.Summary.UnusedTelemetryAssessmentDetail = unresolvedUnusedTelemetryDetail
	}
	r.DependencyEvidence = buildDependencyEvidence(g.Rules, r.InputResolutions, opts.DependencyEvidence)
	r.RuleProvenance = buildRuleProvenance(g.Rules, opts.ProvenanceEvidence, r.GeneratedAt)
	r.SourceLineage = buildSourceLineage(opts.LineageEvidence)
	r.RuleSourceFreshness = buildRuleSourceFreshness(g.Rules, opts.PredicateFreshnessEvidence, opts.Check, opts.Policy)
	r.SummaryRuleRuns = buildSummaryRuleRuns(opts.SummaryRuleRunEvidence)
	maintenanceNow := r.GeneratedAt
	if opts.Check.Now != nil {
		maintenanceNow = opts.Check.Now()
	}
	for i := range r.SummaryRuleRuns {
		r.SummaryRuleRuns[i].ExpectedDowntime = opts.Check.InDowntime(r.SummaryRuleRuns[i].Output.Name, maintenanceNow)
	}

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
		check := opts.Check
		check.MaxStale = opts.Policy.maxStale(s.Name, check.MaxStale)
		a := check.Evaluate(s)
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
		// Storage alone is not evidence of ingested telemetry: an empty index or
		// data stream still has metadata and shard overhead. Unknown document
		// counts remain conservative unless freshness proves an event exists.
		hasTelemetryEvidence := s.Docs > 0 || !s.LastEvent.IsZero()
		if consumers == 0 && hasTelemetryEvidence && (r.Summary.UnusedTelemetryAssessment == UnusedAssessmentComplete ||
			r.Summary.UnusedTelemetryAssessment == UnusedAssessmentLegacy) {
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
			AgeLowerBound:    a.AgeLowerBound,
			Docs:             s.Docs,
			SizeBytes:        s.SizeBytes,
			ExpectedDowntime: a.ExpectedDowntime,
			Consumers:        consumers,
		}
		if s.IngestLag.Status != "" {
			var observedAt *time.Time
			if !s.IngestLag.ObservedAt.IsZero() {
				observed := s.IngestLag.ObservedAt
				observedAt = &observed
			}
			src.IngestLag = &IngestLagHealth{
				Status:        s.IngestLag.Status,
				Method:        s.IngestLag.Method,
				ObservedAt:    observedAt,
				WindowSeconds: s.IngestLag.Window.Seconds(),
				SampleCount:   s.IngestLag.SampleCount,
				P95Seconds:    s.IngestLag.P95.Seconds(),
				MaxSeconds:    s.IngestLag.Max.Seconds(),
				Detail:        s.IngestLag.Detail,
			}
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
		matched := g.SourcesFor(rule.ID)
		resolutions := g.ResolutionsFor(rule.ID)
		var incompatibleSources []string
		if g.NativeResolution {
			if len(resolutions) == 0 {
				r.UnmappedRules = append(r.UnmappedRules, RuleRef{
					ID: legacyRuleID(rule), RuleID: rule.ID, BackendObjectID: rule.BackendObjectID, Name: rule.Name, Severity: rule.Severity,
					AssessmentStatus: backend.ResolutionUnsupported,
					Detail:           "no input-resolution evidence was returned",
				})
				continue
			}
			var hasResolved, hasEmpty, hasIncompatible, uncertain, remote bool
			var uncertainStatus backend.ResolutionStatus
			var uncertainDetail string
			var missingTargets []string
			var authoritativeIncompatibleSources, diagnosticIncompatibleSources []string
			var emptyDiagnostics []backend.InputResolution
			for _, resolution := range resolutions {
				if resolution.Diagnostic {
					switch resolution.Status {
					case backend.ResolutionEmpty:
						emptyDiagnostics = append(emptyDiagnostics, resolution)
					case backend.ResolutionIncompatible:
						hasIncompatible = true
						diagnosticIncompatibleSources = append(diagnosticIncompatibleSources, resolutionInputNames(resolution)...)
					case backend.ResolutionRemote:
						remote, uncertain = true, true
					case backend.ResolutionUnsupported, backend.ResolutionUnavailable, backend.ResolutionAmbiguous:
						uncertain = true
						if uncertainStatus == "" {
							uncertainStatus, uncertainDetail = resolution.Status, resolution.Detail
						}
					}
					continue
				}
				switch resolution.Status {
				case backend.ResolutionResolved:
					hasResolved = true
					for _, target := range resolution.ResolvedSources {
						if _, present := srcByName[target]; !present {
							missingTargets = append(missingTargets, target)
						}
					}
				case backend.ResolutionEmpty:
					hasEmpty = true
				case backend.ResolutionIncompatible:
					hasIncompatible = true
					authoritativeIncompatibleSources = append(authoritativeIncompatibleSources, resolutionInputNames(resolution)...)
				case backend.ResolutionRemote:
					remote, uncertain = true, true
				case backend.ResolutionUnsupported, backend.ResolutionUnavailable, backend.ResolutionAmbiguous:
					uncertain = true
					if uncertainStatus == "" {
						uncertainStatus, uncertainDetail = resolution.Status, resolution.Detail
					}
				}
			}
			if len(missingTargets) > 0 {
				uncertain = true
				if uncertainStatus == "" {
					uncertainStatus = backend.ResolutionAmbiguous
					uncertainDetail = "one or more resolved targets were not present in the source inventory"
				}
			}
			if hasResolved && !uncertain {
				for _, diagnostic := range emptyDiagnostics {
					r.PartialInputCoverage = append(r.PartialInputCoverage, PartialInputCoverage{
						RuleID: rule.ID, BackendObjectID: rule.BackendObjectID,
						RuleName: rule.Name, Severity: rule.Severity,
						Selector: diagnostic.Selector, Expression: diagnostic.Expression,
						ObservedAt: diagnostic.ObservedAt,
					})
				}
			}
			if len(diagnosticIncompatibleSources) > 0 {
				incompatibleSources = sortedUniqueStrings(diagnosticIncompatibleSources)
			} else {
				incompatibleSources = sortedUniqueStrings(authoritativeIncompatibleSources)
			}
			if remote {
				r.RemoteRules = append(r.RemoteRules, RuleRef{
					ID: legacyRuleID(rule), RuleID: rule.ID, BackendObjectID: rule.BackendObjectID, Name: rule.Name, Severity: rule.Severity,
					AssessmentStatus: backend.ResolutionRemote,
				})
			}
			if uncertainStatus != "" {
				r.UnmappedRules = append(r.UnmappedRules, RuleRef{
					ID: legacyRuleID(rule), RuleID: rule.ID, BackendObjectID: rule.BackendObjectID, Name: rule.Name, Severity: rule.Severity,
					AssessmentStatus: uncertainStatus, Detail: uncertainDetail,
				})
			}
			if len(matched) == 0 {
				switch {
				case uncertainStatus != "":
					continue
				case remote:
					continue
				case hasResolved:
					// The resolver returned targets that are absent from the
					// health inventory. Treat that disagreement as ambiguous.
					r.UnmappedRules = append(r.UnmappedRules, RuleRef{
						ID: legacyRuleID(rule), RuleID: rule.ID, BackendObjectID: rule.BackendObjectID, Name: rule.Name, Severity: rule.Severity,
						AssessmentStatus: backend.ResolutionAmbiguous,
						Detail:           "resolved targets were not present in the source inventory",
					})
					continue
				case hasIncompatible:
					r.DeadDetections = append(r.DeadDetections, DeadDetection{
						ID: legacyRuleID(rule), RuleID: rule.ID, BackendObjectID: rule.BackendObjectID, Name: rule.Name, Severity: rule.Severity,
						Reason: ReasonSourcePlanIncompatible, Patterns: rule.Patterns, Sources: incompatibleSources,
					})
					continue
				case hasEmpty:
					r.DeadDetections = append(r.DeadDetections, DeadDetection{
						ID: legacyRuleID(rule), RuleID: rule.ID, BackendObjectID: rule.BackendObjectID, Name: rule.Name, Severity: rule.Severity,
						Reason: ReasonDisconnected, Patterns: rule.Patterns,
					})
					continue
				default:
					r.UnmappedRules = append(r.UnmappedRules, RuleRef{
						ID: legacyRuleID(rule), RuleID: rule.ID, BackendObjectID: rule.BackendObjectID, Name: rule.Name, Severity: rule.Severity,
						AssessmentStatus: backend.ResolutionUnsupported,
						Detail:           "no input-resolution evidence was returned",
					})
					continue
				}
			}
			// Remote or otherwise uncertain secondary inputs mean the local
			// evidence is incomplete. Keep the rule visible without deriving a
			// starved or impaired verdict from a partial view.
			if uncertain {
				continue
			}
		} else if len(rule.Patterns) == 0 {
			status := rule.InputStatus
			if status == "" {
				status = backend.ResolutionUnsupported
			}
			r.UnmappedRules = append(r.UnmappedRules, RuleRef{
				ID: legacyRuleID(rule), RuleID: rule.ID, BackendObjectID: rule.BackendObjectID, Name: rule.Name, Severity: rule.Severity,
				AssessmentStatus: status, Detail: rule.InputDetail,
			})
			continue
		}
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
				r.RemoteRules = append(r.RemoteRules, RuleRef{
					ID: legacyRuleID(rule), RuleID: rule.ID, BackendObjectID: rule.BackendObjectID, Name: rule.Name, Severity: rule.Severity,
					AssessmentStatus: backend.ResolutionRemote,
				})
				continue
			}
			r.DeadDetections = append(r.DeadDetections, DeadDetection{
				ID: legacyRuleID(rule), RuleID: rule.ID, BackendObjectID: rule.BackendObjectID, Name: rule.Name, Severity: rule.Severity,
				Reason: ReasonDisconnected, Patterns: rule.Patterns,
			})
			continue
		}
		// Starved only when every matched source is degraded. A source with
		// unknown freshness keeps the rule alive: never page on uncertainty.
		allDegraded := true
		var degraded []string
		for _, name := range matched {
			a := assess[name]
			if len(srcByName[name].Freshness.Clocks) > 0 {
				a = assessRuleClock(srcByName[name], rule, opts.Check, opts.Policy)
			}
			if a.Status.Degraded() {
				degraded = append(degraded, name)
			} else {
				allDegraded = false
			}
		}
		if allDegraded {
			r.DeadDetections = append(r.DeadDetections, DeadDetection{
				ID: legacyRuleID(rule), RuleID: rule.ID, BackendObjectID: rule.BackendObjectID, Name: rule.Name, Severity: rule.Severity,
				Reason: ReasonStarved, Patterns: rule.Patterns, Sources: degraded,
			})
			continue
		}
		fieldEvidence := opts.FieldEvidence
		if fieldEvidence == nil && opts.SourceFields != nil {
			fieldEvidence = make(map[string]backend.FieldEvidence, len(opts.SourceFields))
			for source, fields := range opts.SourceFields {
				fieldEvidence[source] = backend.FieldEvidence{Status: backend.EvidenceAssessed, Fields: fields}
			}
		}
		if fieldAssessment := requiredFieldAssessment(rule, matched, fieldEvidence); fieldAssessment != nil {
			r.RequiredFieldEvidence = append(r.RequiredFieldEvidence, *fieldAssessment)
		}
		imp, impaired := impairment(rule, matched, srcByName, fieldEvidence)
		if len(incompatibleSources) > 0 {
			if !impaired {
				imp = ImpairedDetection{
					ID: legacyRuleID(rule), RuleID: rule.ID, BackendObjectID: rule.BackendObjectID,
					Name: rule.Name, Severity: rule.Severity, Sources: append([]string(nil), matched...),
				}
			}
			imp.Reasons = append(imp.Reasons, ReasonSourcePlanIncompatible)
			imp.IncompatibleSources = append([]string(nil), incompatibleSources...)
			impaired = true
		}
		if impaired {
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
	r.Summary.PartialInputs = len(r.PartialInputCoverage)
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
	sort.Slice(r.PartialInputCoverage, func(i, j int) bool {
		a, b := r.PartialInputCoverage[i], r.PartialInputCoverage[j]
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		return a.Expression < b.Expression
	})
	sort.Slice(r.InputResolutions, func(i, j int) bool {
		a, b := r.InputResolutions[i], r.InputResolutions[j]
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		if a.Status != b.Status {
			return a.Status < b.Status
		}
		return a.Expression+a.Selector < b.Expression+b.Selector
	})
	r.SourceImpacts = buildSourceImpacts(r, g, opts)
	r.Producers = buildProducerHealth(r, opts)
	// Display filters must not erase a producer's confirmed rule dependencies.
	if opts.Scope != nil {
		visible := r.SourceImpacts[:0]
		for _, source := range r.SourceImpacts {
			if opts.Scope[source.Source] {
				visible = append(visible, source)
			}
		}
		r.SourceImpacts = visible
	}
	r.buildFindings(opts.Store, opts.Policy)
	preserveLegacyInputResolutionIDs(r, g.Rules)
	return r
}

func preserveLegacyInputResolutionIDs(r *Report, rules []backend.Rule) {
	objectIDs := make(map[string]string, len(rules))
	for _, rule := range rules {
		if rule.BackendObjectID != "" {
			objectIDs[rule.ID] = rule.BackendObjectID
		}
	}
	for i := range r.InputResolutions {
		resolution := &r.InputResolutions[i]
		logicalID := logicalInputResolutionRuleID(*resolution)
		objectID := objectIDs[logicalID]
		if objectID == "" {
			continue
		}
		resolution.RuleID = objectID
		resolution.BackendObjectID = objectID
		if objectID != logicalID {
			resolution.LogicalRuleID = logicalID
		}
	}
}

func buildDependencyEvidence(rules []backend.Rule, resolutions []backend.InputResolution, supplied []backend.DependencyEvidence) []DependencyEvidence {
	ruleByID := make(map[string]backend.Rule, len(rules))
	for _, rule := range rules {
		ruleByID[rule.ID] = rule
	}
	out := make([]DependencyEvidence, 0, len(supplied)+len(resolutions))
	seen := make(map[string]bool, len(supplied)+len(resolutions))
	appendEvidence := func(item DependencyEvidence) {
		key := strings.Join([]string{item.RuleID, item.Dependency.ID, item.Dependency.Name,
			item.Dependency.Kind, item.Dependency.Scope, string(item.Status), item.ResolutionMethod}, "\x00")
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, item)
	}
	for _, item := range supplied {
		ruleID := logicalInputResolutionRuleID(backend.InputResolution{
			RuleID: item.RuleID, BackendObjectID: item.BackendObjectID,
		})
		rule := ruleByID[ruleID]
		if ruleID == "" {
			ruleID = item.RuleID
		}
		backendObjectID := item.BackendObjectID
		if backendObjectID == "" {
			backendObjectID = rule.BackendObjectID
		}
		appendEvidence(DependencyEvidence{
			RuleID: ruleID, BackendObjectID: backendObjectID, RuleName: rule.Name, Severity: rule.Severity,
			Dependency: item.Dependency, Status: item.Status, ResolutionMethod: item.ResolutionMethod,
			ObservedAt: item.ObservedAt, Detail: item.Detail,
		})
	}
	for _, resolution := range resolutions {
		if len(resolution.ResolvedDependencies) == 0 {
			continue
		}
		ruleID := logicalInputResolutionRuleID(resolution)
		rule := ruleByID[ruleID]
		for _, dependency := range resolution.ResolvedDependencies {
			appendEvidence(DependencyEvidence{
				RuleID: ruleID, BackendObjectID: firstNonEmpty(resolution.BackendObjectID, rule.BackendObjectID),
				RuleName: rule.Name, Severity: rule.Severity, Dependency: dependency,
				Status: resolution.Status, ResolutionMethod: resolution.ResolutionMethod,
				ObservedAt: resolution.ObservedAt, Detail: resolution.Detail,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		if a.Dependency.ID != b.Dependency.ID {
			return a.Dependency.ID < b.Dependency.ID
		}
		if a.Dependency.Name != b.Dependency.Name {
			return a.Dependency.Name < b.Dependency.Name
		}
		return a.ResolutionMethod < b.ResolutionMethod
	})
	return out
}

func buildRuleProvenance(rules []backend.Rule, supplied []backend.ProvenanceEvidence, observedAt time.Time) []RuleProvenance {
	ruleByID := make(map[string]backend.Rule, len(rules))
	for _, rule := range rules {
		ruleByID[rule.ID] = rule
	}
	out := make([]RuleProvenance, 0, len(supplied)+len(rules))
	seen := make(map[string]bool, len(supplied)+len(rules))
	appendEvidence := func(item RuleProvenance) {
		key := strings.Join([]string{item.RuleID, item.Provenance.ID, item.Provenance.Name,
			item.Provenance.Kind, item.Provenance.Scope, string(item.Status), item.Method}, "\x00")
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, item)
	}
	for _, item := range supplied {
		ruleID := logicalInputResolutionRuleID(backend.InputResolution{
			RuleID: item.RuleID, BackendObjectID: item.BackendObjectID,
		})
		rule := ruleByID[ruleID]
		if ruleID == "" {
			ruleID = item.RuleID
		}
		appendEvidence(RuleProvenance{
			RuleID: ruleID, BackendObjectID: firstNonEmpty(item.BackendObjectID, rule.BackendObjectID), RuleName: rule.Name,
			Provenance: item.Provenance, Status: item.Status, Method: item.Method, ObservedAt: item.ObservedAt, Detail: item.Detail,
		})
	}
	for _, rule := range rules {
		for _, provenance := range rule.Provenance {
			appendEvidence(RuleProvenance{
				RuleID: rule.ID, BackendObjectID: rule.BackendObjectID, RuleName: rule.Name,
				Provenance: provenance, Status: backend.EvidenceAssessed, Method: "rule_inventory", ObservedAt: observedAt,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		if a.Provenance.ID != b.Provenance.ID {
			return a.Provenance.ID < b.Provenance.ID
		}
		if a.Provenance.Name != b.Provenance.Name {
			return a.Provenance.Name < b.Provenance.Name
		}
		return a.Method < b.Method
	})
	return out
}

func buildSourceLineage(in []backend.LineageEvidence) []SourceLineage {
	out := make([]SourceLineage, 0, len(in))
	for _, item := range in {
		out = append(out, SourceLineage{
			ID: item.ID, Kind: item.Kind, Name: item.Name, Input: item.Input, Output: item.Output,
			Status: item.Status, Method: item.Method, ObservedAt: item.ObservedAt, Detail: item.Detail,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		if a.Input.ID != b.Input.ID {
			return a.Input.ID < b.Input.ID
		}
		return a.Output.ID < b.Output.ID
	})
	return out
}

func buildRuleSourceFreshness(rules []backend.Rule, in []backend.RulePredicateFreshnessEvidence, check health.Check, policy *Policy) []RuleSourceFreshness {
	ruleByID := make(map[string]backend.Rule, len(rules))
	for _, rule := range rules {
		ruleByID[rule.ID] = rule
	}
	out := make([]RuleSourceFreshness, 0, len(in))
	for _, item := range in {
		rule := ruleByID[item.RuleID]
		freshness := item.Freshness
		assessmentCheck := check
		if policy != nil {
			assessmentCheck.MaxStale = policy.maxStale(item.Source, check.MaxStale)
		}
		source := backend.Source{Name: item.Source, Docs: -1, Freshness: freshness, LastEvent: freshness.LastEvent}
		assessment := assessmentCheck.Evaluate(source)
		var lastEvent *time.Time
		if !freshness.LastEvent.IsZero() {
			observed := freshness.LastEvent
			lastEvent = &observed
		}
		out = append(out, RuleSourceFreshness{
			RuleID: item.RuleID, BackendObjectID: firstNonEmpty(item.BackendObjectID, rule.BackendObjectID),
			RuleName: rule.Name, Source: item.Source, Fields: append([]string(nil), item.Fields...),
			Status: freshness.Status, Method: freshness.Method, ObservedAt: freshness.ObservedAt,
			WindowSeconds: freshness.Window.Seconds(), LastEvent: lastEvent,
			FreshnessStatus: string(assessment.Status), AgeSeconds: assessment.Age.Seconds(),
			AgeLowerBound: assessment.AgeLowerBound, ExpectedDowntime: assessment.ExpectedDowntime,
			Detail: freshness.Detail,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].RuleID != out[j].RuleID {
			return out[i].RuleID < out[j].RuleID
		}
		if out[i].Source != out[j].Source {
			return out[i].Source < out[j].Source
		}
		return strings.Join(out[i].Fields, "\x00") < strings.Join(out[j].Fields, "\x00")
	})
	return out
}

func buildSummaryRuleRuns(in []backend.SummaryRuleRunEvidence) []SummaryRuleRun {
	out := make([]SummaryRuleRun, 0, len(in))
	for _, item := range in {
		var runAt, modifiedAt *time.Time
		var queryDurationMillis, resultCount *int64
		if !item.RunAt.IsZero() {
			value := item.RunAt
			runAt = &value
			durationValue := item.QueryDurationMillis
			resultValue := item.ResultCount
			queryDurationMillis = &durationValue
			resultCount = &resultValue
		}
		if !item.RuleModifiedAt.IsZero() {
			value := item.RuleModifiedAt
			modifiedAt = &value
		}
		out = append(out, SummaryRuleRun{
			HealthStatus: summaryHealth(item),
			ID:           item.ID, Rule: item.Rule, Output: item.Output, Status: item.Status,
			Method: item.Method, ObservedAt: item.ObservedAt, WindowSeconds: item.Window.Seconds(),
			RunAt: runAt, RunStatus: item.RunStatus, QueryDurationMillis: queryDurationMillis,
			ResultCount: resultCount, RuleModifiedAt: modifiedAt, Error: item.Error, Detail: item.Detail,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ID != out[j].ID {
			return out[i].ID < out[j].ID
		}
		if out[i].Rule.ID != out[j].Rule.ID {
			return out[i].Rule.ID < out[j].Rule.ID
		}
		return out[i].Output.ID < out[j].Output.ID
	})
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func unusedTelemetryAssessment(g *graph.Graph, skip bool) UnusedTelemetryAssessment {
	if skip {
		return UnusedAssessmentNotApplicable
	}
	enabled := 0
	inventory := make(map[string]struct{}, len(g.Sources))
	for _, source := range g.Sources {
		inventory[source.Name] = struct{}{}
	}
	for _, rule := range g.Rules {
		if !rule.Enabled {
			continue
		}
		enabled++
		if !g.NativeResolution {
			continue
		}
		resolutions := g.ResolutionsFor(rule.ID)
		if len(resolutions) == 0 {
			return UnusedAssessmentUnavailable
		}
		authoritative := 0
		for _, resolution := range resolutions {
			if resolution.Diagnostic {
				switch resolution.Status {
				case backend.ResolutionUnsupported, backend.ResolutionUnavailable, backend.ResolutionRemote, backend.ResolutionAmbiguous:
					return UnusedAssessmentUnavailable
				}
				continue
			}
			authoritative++
			switch resolution.Status {
			case backend.ResolutionResolved:
				if len(resolution.ResolvedSources) == 0 {
					return UnusedAssessmentUnavailable
				}
				for _, target := range resolution.ResolvedSources {
					if _, present := inventory[target]; !present {
						return UnusedAssessmentUnavailable
					}
				}
			case backend.ResolutionEmpty, backend.ResolutionRemote, backend.ResolutionIncompatible:
				// These inputs cannot consume a source in this local inventory.
			default:
				return UnusedAssessmentUnavailable
			}
		}
		if authoritative == 0 {
			return UnusedAssessmentUnavailable
		}
	}
	if enabled == 0 || g.NativeResolution {
		return UnusedAssessmentComplete
	}
	return UnusedAssessmentLegacy
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
func requiredFieldAssessment(rule backend.Rule, matched []string, evidence map[string]backend.FieldEvidence) *RequiredFieldAssessment {
	if len(rule.RequiredFields) == 0 || len(matched) == 0 {
		return nil
	}
	assessment := &RequiredFieldAssessment{RuleID: rule.ID, RuleName: rule.Name}
	fields := append([]string(nil), rule.RequiredFields...)
	sort.Strings(fields)
	for _, source := range matched {
		sourceEvidence, ok := evidence[source]
		if !ok {
			status := backend.EvidenceUnavailable
			detail := "required-field evidence was not collected"
			if evidence != nil {
				status = backend.EvidenceIncomplete
				detail = "field capabilities could not be read"
			}
			assessment.Sources = append(assessment.Sources, RequiredFieldSourceEvidence{
				Source: source, Status: status, Detail: detail,
			})
			continue
		}
		item := RequiredFieldSourceEvidence{Source: source, Status: sourceEvidence.Status, Detail: sourceEvidence.Detail}
		if sourceEvidence.Status == backend.EvidenceAssessed {
			for _, field := range fields {
				if sourceEvidence.Fields[field] {
					item.Present = append(item.Present, field)
				} else {
					item.Missing = append(item.Missing, field)
				}
			}
		}
		assessment.Sources = append(assessment.Sources, item)
	}
	sort.Slice(assessment.Sources, func(i, j int) bool { return assessment.Sources[i].Source < assessment.Sources[j].Source })
	return assessment
}

func impairment(rule backend.Rule, matched []string, srcByName map[string]backend.Source, fields map[string]backend.FieldEvidence) (ImpairedDetection, bool) {
	imp := ImpairedDetection{ID: legacyRuleID(rule), RuleID: rule.ID, BackendObjectID: rule.BackendObjectID, Name: rule.Name, Severity: rule.Severity, Sources: matched}

	// missing-fields: evaluate each concrete source independently. A failed or
	// absent field-capability read suppresses the rule-level conclusion; the
	// incomplete evidence remains in Report.RequiredFieldEvidence.
	if fields != nil && len(rule.RequiredFields) > 0 {
		complete := true
		missingSet := map[string]bool{}
		for _, name := range matched {
			evidence, ok := fields[name]
			if !ok || evidence.Status != backend.EvidenceAssessed {
				complete = false
				continue
			}
			for _, field := range rule.RequiredFields {
				if !evidence.Fields[field] {
					missingSet[field] = true
				}
			}
		}
		if complete && len(missingSet) > 0 {
			missing := make([]string, 0, len(missingSet))
			for field := range missingSet {
				missing = append(missing, field)
			}
			sort.Strings(missing)
			imp.Reasons = append(imp.Reasons, ReasonMissingFields)
			imp.MissingFields = missing
		}
	}

	// lag-blind-window: a source whose measured ingest lag exceeds the rule's
	// lookback-minus-interval margin can drop events between runs — an event
	// ingested that late is never inside a run's window while it is queryable.
	// Evaluated per source: a broad rule may read one laggy source and many
	// healthy ones, so the finding names the offending source(s) rather than
	// tainting the whole rule with a single stream's lag. Skipped entirely for
	// rules that window on ingest time, which the lag cannot blind.
	if windowsOnEventTime(rule) && rule.Lookback > 0 && rule.Interval > 0 && rule.Lookback >= rule.Interval {
		margin := rule.Lookback - rule.Interval
		var lagSources []string
		var p95Lag, maxLag time.Duration
		for _, name := range matched {
			evidence := srcByName[name].IngestLag
			if evidence.Status == backend.EvidenceAssessed && evidence.SampleCount > 0 && evidence.P95 > margin {
				lagSources = append(lagSources, name)
				if evidence.P95 > p95Lag {
					p95Lag = evidence.P95
				}
				if evidence.Max > maxLag {
					maxLag = evidence.Max
				}
			}
		}
		if len(lagSources) > 0 {
			sort.Strings(lagSources)
			imp.Reasons = append(imp.Reasons, ReasonLagBlindWindow)
			imp.LookbackSeconds = rule.Lookback.Seconds()
			imp.IntervalSeconds = rule.Interval.Seconds()
			imp.P95LagSeconds = p95Lag.Seconds()
			imp.MaxLagSeconds = maxLag.Seconds()
			imp.LagSources = lagSources
		}
	}

	return imp, len(imp.Reasons) > 0
}

// CandidateExitCode gates on the rule under test only: pre-existing source
// degradation elsewhere in the environment must not fail a rule's CI check.
func (r *Report) CandidateExitCode() int {
	resolvedSource := false
	for _, resolution := range r.InputResolutions {
		if !resolution.Diagnostic && resolution.Status == backend.ResolutionResolved && len(resolution.ResolvedSources) > 0 {
			resolvedSource = true
			break
		}
	}
	for _, assessment := range r.Assessments {
		switch assessment.Name {
		case AssessmentSourceResolution:
			if assessment.Status != backend.EvidenceAssessed {
				return ExitError
			}
		case AssessmentSourceFreshness:
			if resolvedSource && (assessment.Status == backend.EvidenceIncomplete || assessment.Status == backend.EvidenceUnavailable) {
				return ExitError
			}
		case AssessmentRequiredFields, AssessmentIngestLag:
			if assessment.Status == backend.EvidenceIncomplete {
				return ExitError
			}
		}
	}
	if r.Summary.UnmappedRules > 0 || r.Summary.RemoteRules > 0 {
		return ExitError
	}
	if r.Policy != nil {
		for _, finding := range r.Findings {
			if finding.RuleID != "" && finding.Gates {
				return ExitFindings
			}
		}
		return ExitHealthy
	}
	if r.Summary.DeadDetections > 0 || r.Summary.ImpairedDetections > 0 {
		return ExitFindings
	}
	return ExitHealthy
}

// ExitCode maps the report to the scan exit code.
func (r *Report) ExitCode() int {
	if r.Policy != nil {
		if r.Summary.GatedFindings > 0 {
			return ExitFindings
		}
		return ExitHealthy
	}
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

// Redact replaces sensitive names with process-local keyed pseudonyms. Values
// remain stable within the process. Use RedactWith with a caller-held key when
// identifiers must remain stable across process restarts.
func (r *Report) Redact() {
	r.RedactWith(redactpkg.Default())
}

// RedactWith replaces sensitive names with HMAC-SHA256 pseudonyms from the
// supplied redactor. The report records only the non-secret key identifier.
func (r *Report) RedactWith(redactor *redactpkg.Redactor) {
	if r.Redacted {
		return
	}
	r.Redacted = true
	r.redactSourceImpacts(redactor)
	r.redactProducers(redactor)
	r.Redaction = &RedactionMetadata{Algorithm: redactpkg.Algorithm, KeyID: redactor.KeyID()}
	if r.TargetID != "" {
		r.TargetID = redactor.Value("target", r.TargetID)
	}
	if r.Instance != "" {
		r.Instance = redactor.Value("ten", r.Instance)
	}
	for i := range r.Scope.Include {
		r.Scope.Include[i] = redactor.Value("pat", r.Scope.Include[i])
	}
	for i := range r.Scope.Exclude {
		r.Scope.Exclude[i] = redactor.Value("pat", r.Scope.Exclude[i])
	}
	for i := range r.Scope.CandidateRuleIDs {
		r.Scope.CandidateRuleIDs[i] = redactor.Value("rule", r.Scope.CandidateRuleIDs[i])
	}
	if r.Scope.ConfigurationID != "" {
		r.Scope.ConfigurationID = redactor.Value("config", r.Scope.ConfigurationID)
	}
	for i := range r.Sources {
		r.Sources[i].Name = redactor.Value("src", r.Sources[i].Name)
		if r.Sources[i].Schema != nil {
			redactSchema(redactor, r.Sources[i].Schema)
		}
		if r.Sources[i].IngestLag != nil && r.Sources[i].IngestLag.Detail != "" {
			r.Sources[i].IngestLag.Detail = redactor.Value("detail", r.Sources[i].IngestLag.Detail)
		}
	}
	for i := range r.DeadDetections {
		d := &r.DeadDetections[i]
		d.ID = redactor.Value("rule", d.ID)
		if d.RuleID != "" {
			d.RuleID = redactor.Value("rule", d.RuleID)
		}
		if d.BackendObjectID != "" {
			d.BackendObjectID = redactor.Value("obj", d.BackendObjectID)
		}
		d.Name = redactor.Value("rule", d.Name)
		for j := range d.Patterns {
			d.Patterns[j] = redactor.Value("pat", d.Patterns[j])
		}
		for j := range d.Sources {
			d.Sources[j] = redactor.Value("src", d.Sources[j])
		}
	}
	for i := range r.ImpairedDetections {
		d := &r.ImpairedDetections[i]
		d.ID = redactor.Value("rule", d.ID)
		if d.RuleID != "" {
			d.RuleID = redactor.Value("rule", d.RuleID)
		}
		if d.BackendObjectID != "" {
			d.BackendObjectID = redactor.Value("obj", d.BackendObjectID)
		}
		d.Name = redactor.Value("rule", d.Name)
		for j := range d.Sources {
			d.Sources[j] = redactor.Value("src", d.Sources[j])
		}
		for j := range d.LagSources {
			d.LagSources[j] = redactor.Value("src", d.LagSources[j])
		}
		for j := range d.IncompatibleSources {
			d.IncompatibleSources[j] = redactor.Value("src", d.IncompatibleSources[j])
		}
		for j := range d.MissingFields {
			d.MissingFields[j] = redactor.Value("field", d.MissingFields[j])
		}
	}
	for i := range r.UnmappedRules {
		r.UnmappedRules[i].ID = redactor.Value("rule", r.UnmappedRules[i].ID)
		if r.UnmappedRules[i].RuleID != "" {
			r.UnmappedRules[i].RuleID = redactor.Value("rule", r.UnmappedRules[i].RuleID)
		}
		if r.UnmappedRules[i].BackendObjectID != "" {
			r.UnmappedRules[i].BackendObjectID = redactor.Value("obj", r.UnmappedRules[i].BackendObjectID)
		}
		if r.UnmappedRules[i].FindingID != "" {
			r.UnmappedRules[i].FindingID = redactor.Value("finding", r.UnmappedRules[i].FindingID)
		}
		if r.UnmappedRules[i].Dependency != "" {
			r.UnmappedRules[i].Dependency = redactor.Value("dep", r.UnmappedRules[i].Dependency)
		}
		r.UnmappedRules[i].Name = redactor.Value("rule", r.UnmappedRules[i].Name)
		if r.UnmappedRules[i].Detail != "" {
			r.UnmappedRules[i].Detail = redactor.Value("detail", r.UnmappedRules[i].Detail)
		}
	}
	for i := range r.RemoteRules {
		r.RemoteRules[i].ID = redactor.Value("rule", r.RemoteRules[i].ID)
		if r.RemoteRules[i].RuleID != "" {
			r.RemoteRules[i].RuleID = redactor.Value("rule", r.RemoteRules[i].RuleID)
		}
		if r.RemoteRules[i].BackendObjectID != "" {
			r.RemoteRules[i].BackendObjectID = redactor.Value("obj", r.RemoteRules[i].BackendObjectID)
		}
		if r.RemoteRules[i].FindingID != "" {
			r.RemoteRules[i].FindingID = redactor.Value("finding", r.RemoteRules[i].FindingID)
		}
		if r.RemoteRules[i].Dependency != "" {
			r.RemoteRules[i].Dependency = redactor.Value("dep", r.RemoteRules[i].Dependency)
		}
		r.RemoteRules[i].Name = redactor.Value("rule", r.RemoteRules[i].Name)
		if r.RemoteRules[i].Detail != "" {
			r.RemoteRules[i].Detail = redactor.Value("detail", r.RemoteRules[i].Detail)
		}
	}
	for i := range r.UnusedTelemetry {
		r.UnusedTelemetry[i].Name = redactor.Value("src", r.UnusedTelemetry[i].Name)
	}
	for i := range r.InputResolutions {
		resolution := &r.InputResolutions[i]
		resolution.RuleID = redactor.Value("rule", resolution.RuleID)
		if resolution.LogicalRuleID != "" {
			resolution.LogicalRuleID = redactor.Value("rule", resolution.LogicalRuleID)
		}
		if resolution.BackendObjectID != "" {
			resolution.BackendObjectID = redactor.Value("obj", resolution.BackendObjectID)
		}
		if resolution.Selector != "" {
			resolution.Selector = redactor.Value("pat", resolution.Selector)
		}
		if resolution.Expression != "" {
			resolution.Expression = redactor.Value("pat", resolution.Expression)
		}
		for j := range resolution.ResolvedSources {
			resolution.ResolvedSources[j] = redactor.Value("src", resolution.ResolvedSources[j])
		}
		for j := range resolution.ResolvedDependencies {
			redactDependencyRef(redactor, &resolution.ResolvedDependencies[j])
		}
		for j := range resolution.Aliases {
			resolution.Aliases[j] = redactor.Value("alias", resolution.Aliases[j])
		}
		if resolution.Detail != "" {
			resolution.Detail = redactor.Value("detail", resolution.Detail)
		}
	}
	for i := range r.DependencyEvidence {
		evidence := &r.DependencyEvidence[i]
		evidence.RuleID = redactor.Value("rule", evidence.RuleID)
		if evidence.BackendObjectID != "" {
			evidence.BackendObjectID = redactor.Value("obj", evidence.BackendObjectID)
		}
		if evidence.RuleName != "" {
			evidence.RuleName = redactor.Value("rule", evidence.RuleName)
		}
		redactDependencyRef(redactor, &evidence.Dependency)
		if evidence.Detail != "" {
			evidence.Detail = redactor.Value("detail", evidence.Detail)
		}
	}
	for i := range r.RuleProvenance {
		provenance := &r.RuleProvenance[i]
		provenance.RuleID = redactor.Value("rule", provenance.RuleID)
		if provenance.BackendObjectID != "" {
			provenance.BackendObjectID = redactor.Value("obj", provenance.BackendObjectID)
		}
		if provenance.RuleName != "" {
			provenance.RuleName = redactor.Value("rule", provenance.RuleName)
		}
		redactProvenanceRef(redactor, &provenance.Provenance)
		if provenance.Detail != "" {
			provenance.Detail = redactor.Value("detail", provenance.Detail)
		}
	}
	for i := range r.SourceLineage {
		lineage := &r.SourceLineage[i]
		if lineage.ID != "" {
			lineage.ID = redactor.Value("lineage", lineage.ID)
		}
		if lineage.Name != "" {
			lineage.Name = redactor.Value("dep", lineage.Name)
		}
		redactDependencyRef(redactor, &lineage.Input)
		redactDependencyRef(redactor, &lineage.Output)
		if lineage.Detail != "" {
			lineage.Detail = redactor.Value("detail", lineage.Detail)
		}
	}
	for i := range r.RuleSourceFreshness {
		evidence := &r.RuleSourceFreshness[i]
		evidence.RuleID = redactor.Value("rule", evidence.RuleID)
		if evidence.BackendObjectID != "" {
			evidence.BackendObjectID = redactor.Value("obj", evidence.BackendObjectID)
		}
		if evidence.RuleName != "" {
			evidence.RuleName = redactor.Value("rule", evidence.RuleName)
		}
		evidence.Source = redactor.Value("src", evidence.Source)
		for j := range evidence.Fields {
			evidence.Fields[j] = redactor.Value("field", evidence.Fields[j])
		}
		if evidence.Detail != "" {
			evidence.Detail = redactor.Value("detail", evidence.Detail)
		}
	}
	for i := range r.SummaryRuleRuns {
		run := &r.SummaryRuleRuns[i]
		if run.ID != "" {
			run.ID = redactor.Value("summary-run", run.ID)
		}
		redactDependencyRef(redactor, &run.Rule)
		redactDependencyRef(redactor, &run.Output)
		if run.Error != "" {
			run.Error = redactor.Value("detail", run.Error)
		}
		if run.Detail != "" {
			run.Detail = redactor.Value("detail", run.Detail)
		}
	}
	for i := range r.PartialInputCoverage {
		coverage := &r.PartialInputCoverage[i]
		coverage.RuleID = redactor.Value("rule", coverage.RuleID)
		if coverage.BackendObjectID != "" {
			coverage.BackendObjectID = redactor.Value("obj", coverage.BackendObjectID)
		}
		coverage.RuleName = redactor.Value("rule", coverage.RuleName)
		if coverage.Selector != "" {
			coverage.Selector = redactor.Value("pat", coverage.Selector)
		}
		coverage.Expression = redactor.Value("pat", coverage.Expression)
	}
	for i := range r.RequiredFieldEvidence {
		assessment := &r.RequiredFieldEvidence[i]
		assessment.RuleID = redactor.Value("rule", assessment.RuleID)
		assessment.RuleName = redactor.Value("rule", assessment.RuleName)
		for j := range assessment.Sources {
			source := &assessment.Sources[j]
			source.Source = redactor.Value("src", source.Source)
			for k := range source.Present {
				source.Present[k] = redactor.Value("field", source.Present[k])
			}
			for k := range source.Missing {
				source.Missing[k] = redactor.Value("field", source.Missing[k])
			}
			if source.Detail != "" {
				source.Detail = redactor.Value("detail", source.Detail)
			}
		}
	}
	redactFindings(redactor, r.Findings)
	redactFindings(redactor, r.RecoveredFindings)
}

func redactFindings(redactor *redactpkg.Redactor, findings []Finding) {
	for i := range findings {
		finding := &findings[i]
		finding.ID = redactor.Value("finding", finding.ID)
		if finding.RuleID != "" {
			finding.RuleID = redactor.Value("rule", finding.RuleID)
		}
		if finding.BackendObjectID != "" {
			finding.BackendObjectID = redactor.Value("obj", finding.BackendObjectID)
		}
		if finding.RuleName != "" {
			finding.RuleName = redactor.Value("rule", finding.RuleName)
		}
		if finding.Source != "" {
			finding.Source = redactor.Value("src", finding.Source)
		}
		if finding.Dependency != "" {
			namespace := "dep"
			if finding.Reason == ReasonMissingFields {
				namespace = "field"
			} else if finding.Class == FindingPartialInput {
				namespace = "pat"
			}
			finding.Dependency = redactor.Value(namespace, finding.Dependency)
		}
		if finding.Accepted != nil && finding.Accepted.Reason != "" {
			finding.Accepted.Reason = redactor.Value("detail", finding.Accepted.Reason)
		}
	}
}

func redactDependencyRef(redactor *redactpkg.Redactor, dependency *backend.DependencyRef) {
	namespace := "dep"
	if dependency.Monitorable {
		// Monitorable dependencies are source identities. Keep their
		// pseudonyms joinable with resolved_sources and source health.
		namespace = "src"
	}
	if dependency.ID != "" {
		dependency.ID = redactor.Value(namespace, dependency.ID)
	}
	if dependency.Name != "" {
		dependency.Name = redactor.Value(namespace, dependency.Name)
	}
	if dependency.Scope != "" {
		dependency.Scope = redactor.Value("workspace", dependency.Scope)
	}
}

func redactProvenanceRef(redactor *redactpkg.Redactor, provenance *backend.ProvenanceRef) {
	if provenance.ID != "" {
		provenance.ID = redactor.Value("provenance", provenance.ID)
	}
	if provenance.Name != "" {
		provenance.Name = redactor.Value("provenance", provenance.Name)
	}
	if provenance.Scope != "" {
		provenance.Scope = redactor.Value("workspace", provenance.Scope)
	}
}

func redactSchema(redactor *redactpkg.Redactor, schema *SchemaHealth) {
	for i := range schema.Added {
		schema.Added[i] = redactor.Value("field", schema.Added[i])
	}
	for i := range schema.Removed {
		schema.Removed[i] = redactor.Value("field", schema.Removed[i])
	}
	for i := range schema.TypeChanged {
		schema.TypeChanged[i].Name = redactor.Value("field", schema.TypeChanged[i].Name)
	}
}

// Write writes the JSON report to path with 0600 permissions on POSIX.
func (r *Report) Write(path string) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding report: %w", err)
	}
	if err := securefile.Write(path, append(data, '\n')); err != nil {
		return fmt.Errorf("writing report: %w", err)
	}
	return nil
}
