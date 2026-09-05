// Package backend defines the read-only contract every SIEM backend
// implements. Backends may only observe: no call in this interface can be
// satisfied by anything other than reads.
package backend

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// FreshnessClockSkew allows small differences between producer and scanner
// clocks. Later timestamps cannot establish current telemetry freshness.
const FreshnessClockSkew = 5 * time.Minute

// Rule is a detection rule as inventoried from a SIEM.
type Rule struct {
	// ID is the backend's logical rule identifier. It is expected to survive
	// exports and re-imports, unlike a storage or saved-object identifier.
	ID string
	// BackendObjectID is the backend storage identifier when one is exposed.
	// Elastic, for example, assigns a new saved-object ID when a rule is
	// imported while preserving rule_id. Reports retain both so diffs can use
	// the logical identity without discarding useful backend evidence.
	BackendObjectID string
	Name            string
	Enabled         bool
	Severity        string // normalized lowercase: low|medium|high|critical
	RiskScore       int
	// RuleType is the backend-native detection type when the backend exposes
	// one (for example, query, esql, or machine_learning).
	RuleType string
	// ModifiedAt is the backend-reported last modification time when one is
	// available. It is internal scan evidence: reports retain their existing
	// rule identity fields and do not serialize this value directly.
	ModifiedAt time.Time
	// DataViewID identifies the Kibana data view used by a rule. It is kept
	// separately from Patterns so candidate rules can resolve the data view
	// without first being installed.
	DataViewID string
	// Patterns are the index / data-stream patterns the rule reads (for
	// data-view-backed rules, resolved via the data view when possible).
	// Empty when the inputs cannot be determined from metadata (e.g. ML
	// jobs); those rules are reported as "unmapped", never "dead".
	Patterns []string
	// OptionalPatterns are local inputs that the backend query explicitly
	// permits to be absent. Sentinel uses this only for operands of
	// `union isfuzzy=true`; ordinary unions, joins, lookups, and the leading
	// pipeline source remain required.
	OptionalPatterns []string
	// Lookback is how far back each execution queries (Elastic "from",
	// e.g. now-6m). Zero when unknown.
	Lookback time.Duration
	// Interval is the execution schedule. Zero when unknown.
	Interval time.Duration
	// RequiredFields lists field names the rule declares it needs
	// (Elastic required_fields metadata). Empty when undeclared.
	RequiredFields []string
	// TimestampOverride is the field the rule's time range filters on
	// (Elastic "timestamp_override", e.g. event.ingested). Empty means the
	// default @timestamp. When a rule windows on ingest time, late events are
	// caught as they arrive, so ingest lag cannot open a blind window and the
	// lag check is suppressed.
	TimestampOverride string
	// InputStatus and InputDetail preserve input-discovery failures that occur
	// while inventorying rules. Patterns remains available for callers that
	// use the legacy client-side matcher.
	InputStatus ResolutionStatus
	InputDetail string
	// InputMetadataIncomplete means discovered selectors may include unresolved
	// backend aliases. A resolver may still accept selectors confirmed by the
	// native source catalog, but catalog misses cannot become empty evidence.
	InputMetadataIncomplete bool
	// Dependencies records backend-native inputs that are not necessarily
	// monitorable log sources. Patterns remains the compatibility surface for
	// concrete telemetry sources used by the rule-to-source graph; callers must
	// not put lookups, packages, or transformations in Patterns.
	Dependencies []DependencyRef
	// Provenance records where a rule came from when the backend exposes that
	// information (for example, a Sentinel template or Content Hub package).
	// It is informational and never affects a rule verdict.
	Provenance []ProvenanceRef
	// PredicateFreshness contains parser-validated, backend-private source
	// slices whose freshness can be measured without executing the full rule.
	// Expressions are never serialized into reports.
	PredicateFreshness []PredicateFreshnessSelector
}

// ValidateRuleIDs rejects inventories that cannot be represented safely in
// the rule-to-source graph. Rule IDs are the graph key, so an empty or
// duplicate ID would merge otherwise independent detections and their input
// evidence.
func ValidateRuleIDs(rules []Rule) error {
	seen := make(map[string]bool, len(rules))
	for i, rule := range rules {
		id := strings.TrimSpace(rule.ID)
		if id == "" {
			return fmt.Errorf("rule %d has an empty ID", i+1)
		}
		if seen[id] {
			return fmt.Errorf("duplicate rule ID %q", id)
		}
		seen[id] = true
	}
	return nil
}

// ResolutionStatus describes the outcome of resolving a rule's backend input
// selector to concrete sources.
type ResolutionStatus string

const (
	ResolutionResolved    ResolutionStatus = "resolved"
	ResolutionEmpty       ResolutionStatus = "empty"
	ResolutionUnsupported ResolutionStatus = "unsupported"
	ResolutionUnavailable ResolutionStatus = "unavailable"
	ResolutionRemote      ResolutionStatus = "remote"
	ResolutionAmbiguous   ResolutionStatus = "ambiguous"
	// ResolutionIncompatible means the backend conclusively identified the
	// input, but its source configuration cannot be used by this rule type.
	// Unlike unsupported or unavailable evidence, this is an assessed result.
	ResolutionIncompatible ResolutionStatus = "incompatible"
)

// InputResolution is backend-native evidence for one rule input. Local
// selectors are combined in Expression; selectors that must not be sent to
// the local backend (such as cross-cluster selectors) are recorded separately
// in Selector.
type InputResolution struct {
	// RuleID remains the v1 report's backend rule identifier. Backends use the
	// logical identifier while building the graph; the report boundary restores
	// a saved-object ID here when one exists.
	RuleID string `json:"rule_id"`
	// LogicalRuleID survives an Elastic export and re-import even when the
	// saved-object ID changes. It is emitted when it differs from RuleID.
	LogicalRuleID string `json:"logical_rule_id,omitempty"`
	// BackendObjectID makes the storage identity explicit while RuleID keeps
	// its v1 JSON meaning for existing consumers.
	BackendObjectID string `json:"backend_object_id,omitempty"`
	Selector        string `json:"selector,omitempty"`
	Expression      string `json:"expression,omitempty"`
	// Diagnostic marks per-selector evidence that explains partial coverage.
	// It is never authoritative graph evidence and cannot create rule/source
	// edges or a disconnected verdict.
	Diagnostic      bool     `json:"diagnostic,omitempty"`
	SelectorKind    string   `json:"selector_kind"`
	ResolvedSources []string `json:"resolved_sources,omitempty"`
	// ResolvedDependencies is additive evidence for resolved non-telemetry
	// inputs such as watchlists, workspace functions, content packages, and
	// cross-workspace sources. ResolvedSources retains its v1 meaning: concrete
	// monitorable source names used by the dependency graph.
	ResolvedDependencies []DependencyRef  `json:"resolved_dependencies,omitempty"`
	Aliases              []string         `json:"aliases,omitempty"`
	ResolutionMethod     string           `json:"resolution_method"`
	ObservedAt           time.Time        `json:"observed_at"`
	Status               ResolutionStatus `json:"status"`
	Detail               string           `json:"detail,omitempty"`
}

// DependencyRef identifies one backend-native dependency. ID is the stable
// backend-qualified identity used for correlation; Name is display evidence
// and may be redacted. Only monitorable telemetry inputs participate in the
// existing source-health graph.
type DependencyRef struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name,omitempty"`
	Kind        string `json:"kind"`
	Scope       string `json:"scope,omitempty"`
	Monitorable bool   `json:"monitorable,omitempty"`
	Required    bool   `json:"required,omitempty"`
	// Expression is validated backend-private probe material. It is never
	// serialized into a report: queries can contain tenant-specific literals,
	// and the public dependency identity above is sufficient for correlation.
	Expression string `json:"-"`
}

// ProvenanceRef identifies the origin of a rule. It deliberately stays
// separate from DependencyRef because provenance is not an executable input.
type ProvenanceRef struct {
	ID    string `json:"id,omitempty"`
	Name  string `json:"name,omitempty"`
	Kind  string `json:"kind"`
	Scope string `json:"scope,omitempty"`
}

// DependencyEvidence records the observed status of one rule dependency.
// RuleID is the logical rule identity; it complements InputResolution when a
// backend needs to retain per-input evidence beyond concrete graph sources.
type DependencyEvidence struct {
	RuleID           string           `json:"rule_id"`
	BackendObjectID  string           `json:"backend_object_id,omitempty"`
	Dependency       DependencyRef    `json:"dependency"`
	Status           ResolutionStatus `json:"status"`
	ResolutionMethod string           `json:"resolution_method"`
	ObservedAt       time.Time        `json:"observed_at"`
	Detail           string           `json:"detail,omitempty"`
}

// ProvenanceEvidence records a read-only provenance observation for a rule.
// RuleID is the logical rule identity. Missing provenance is informational;
// it cannot create a health finding.
type ProvenanceEvidence struct {
	RuleID          string         `json:"rule_id"`
	BackendObjectID string         `json:"backend_object_id,omitempty"`
	Provenance      ProvenanceRef  `json:"provenance"`
	Status          EvidenceStatus `json:"status"`
	Method          string         `json:"method"`
	ObservedAt      time.Time      `json:"observed_at"`
	Detail          string         `json:"detail,omitempty"`
}

// LineageEvidence describes an observed transformation relationship between
// two dependencies, for example raw table -> summary rule -> output table.
// It is evidence only: downstream detection health remains based on the
// concrete source it reads unless a backend exposes a separate assessed rule
// dependency.
type LineageEvidence struct {
	ID         string         `json:"id,omitempty"`
	Kind       string         `json:"kind"`
	Name       string         `json:"name,omitempty"`
	Input      DependencyRef  `json:"input"`
	Output     DependencyRef  `json:"output"`
	Status     EvidenceStatus `json:"status"`
	Method     string         `json:"method"`
	ObservedAt time.Time      `json:"observed_at"`
	Detail     string         `json:"detail,omitempty"`
}

// Source is a concrete log source (data stream or index) with health stats.
type Source struct {
	Name      string
	Docs      int64 // -1 when unknown
	SizeBytes int64
	LastEvent time.Time // zero when freshness could not be determined
	// Freshness preserves the bounded observation behind LastEvent. An
	// assessed observation may have no exact LastEvent when its query window
	// contained no events; consumers can then use Window only as a proved
	// lower bound.
	Freshness FreshnessEvidence
	// IngestLag is paired event-time/ingest-time evidence collected from a
	// bounded recent sample. The zero value means the backend did not assess
	// lag for this source.
	IngestLag IngestLagEvidence
}

// EvidenceStatus describes whether a runtime measurement produced evidence.
// It is deliberately separate from the static backend capability contract.
type EvidenceStatus string

const (
	EvidenceAssessed    EvidenceStatus = "assessed"
	EvidenceDisabled    EvidenceStatus = "disabled"
	EvidenceIncomplete  EvidenceStatus = "incomplete"
	EvidenceUnavailable EvidenceStatus = "unavailable"
)

// IngestLagEvidence describes an exact paired sample of event.ingested and
// @timestamp values. Findings must only be derived from EvidenceAssessed.
type IngestLagEvidence struct {
	Status      EvidenceStatus
	Method      string
	ObservedAt  time.Time
	Window      time.Duration
	SampleCount int
	P95         time.Duration
	Max         time.Duration
	Detail      string
}

// Field is one observed field and the concrete backend field types reported
// by field_caps.
type Field struct {
	Name  string
	Types []string
}

// Schema is the current field-capability snapshot for a source.
type Schema struct {
	Source string
	Fields []Field
}

// FieldEvidence is the result of fetching a concrete source's field
// capabilities. Fields maps each requested name to whether it is mapped and
// searchable across every concrete index behind that source. It is meaningful
// only when Status is EvidenceAssessed.
type FieldEvidence struct {
	Status EvidenceStatus
	Fields map[string]bool
	Detail string
}

// FreshnessEvidence is a bounded runtime observation of a source's latest
// relevant timestamp. LastEvent is meaningful only when Status is
// EvidenceAssessed; it may remain zero when the bounded window contained no
// events.
type FreshnessEvidence struct {
	Status     EvidenceStatus
	Method     string
	ObservedAt time.Time
	Window     time.Duration
	LastEvent  time.Time
	Detail     string
}

// FreshnessBasis identifies the timestamp that determines whether a rule can
// see newly available data. Event-time rules and ingestion-time rules cannot
// safely share one freshness observation.
type FreshnessBasis string

const (
	FreshnessEventTime     FreshnessBasis = "event_time"
	FreshnessIngestionTime FreshnessBasis = "ingestion_time"
	FreshnessMixed         FreshnessBasis = "mixed"
)

// FreshnessRequest carries the timing model of enabled rules that consume one
// concrete source. Window is the effective stale threshold after source policy.
type FreshnessRequest struct {
	Source Source
	Basis  FreshnessBasis
	Window time.Duration
}

// PredicateFreshnessSelector identifies one exact local source plus a closed,
// parser-generated filter expression. Fields may be reported as context;
// Expression is backend-private query material and must never be serialized.
type PredicateFreshnessSelector struct {
	Source     string
	Expression string
	Fields     []string
}

// RulePredicateFreshnessRequest asks for one rule/source slice using the same
// event-time or ingestion-time clock as the consuming rule.
type RulePredicateFreshnessRequest struct {
	RuleID          string
	BackendObjectID string
	Source          Source
	Basis           FreshnessBasis
	Window          time.Duration
	Selector        PredicateFreshnessSelector
}

// RulePredicateFreshnessEvidence preserves a bounded observation separately
// from table-wide source freshness. It is informational and cannot by itself
// create a dead-detection finding.
type RulePredicateFreshnessEvidence struct {
	RuleID          string
	BackendObjectID string
	Source          string
	Fields          []string
	Freshness       FreshnessEvidence
}

// ReadinessEvidence records whether a harmless backend query was attempted.
// Attempted is false when the visible catalog has no query-eligible source.
type ReadinessEvidence struct {
	Status    EvidenceStatus
	Attempted bool
	// Limited means the read path was reached successfully, but the backend
	// could not establish every dependency's semantics. It must not be used
	// for credential, transport, or runtime evidence failures.
	Limited bool
	Detail  string
}

// Backend is a read-only client for one SIEM.
type Backend interface {
	Name() string
	Rules(ctx context.Context) ([]Rule, error)
	Sources(ctx context.Context) ([]Source, error)
	Schemas(ctx context.Context, sources []Source) (map[string]Schema, error)
}

// Resolver is an optional backend capability for resolving rule selectors
// with the backend's native index-expression semantics.
type Resolver interface {
	ResolveInputs(ctx context.Context, rules []Rule) ([]InputResolution, error)
}

// RequiredFieldProvider is an optional, targeted field-capability reader.
// Callers pass only fields declared by enabled rules, avoiding a full schema
// inventory when schema-history tracking is disabled.
type RequiredFieldProvider interface {
	RequiredFieldEvidence(ctx context.Context, sources []Source, fields []string) (map[string]FieldEvidence, error)
}

// IngestLagProvider is an optional paired timestamp sampler. It is separate
// from Sources so readiness checks stay cheap and scan scope can bound reads.
type IngestLagProvider interface {
	IngestLagEvidence(ctx context.Context, sources []Source) (map[string]IngestLagEvidence, error)
}

// FreshnessProvider is an optional targeted event-time reader. Callers pass
// only concrete sources used by enabled rules so connection checks and broad
// table inventories never issue one query per workspace table.
type FreshnessProvider interface {
	FreshnessEvidence(ctx context.Context, sources []Source) (map[string]FreshnessEvidence, error)
}

// FreshnessRequestProvider is an optional rule-aware freshness reader. The
// CLI prefers it over FreshnessProvider when a backend has different timing
// models for different rule types.
type FreshnessRequestProvider interface {
	FreshnessEvidenceFor(ctx context.Context, requests []FreshnessRequest) (map[string]FreshnessEvidence, error)
}

// RulePredicateFreshnessProvider measures parser-proved rule/source slices
// without replacing the table-wide freshness observation shared by rules.
type RulePredicateFreshnessProvider interface {
	RulePredicateFreshnessEvidenceFor(ctx context.Context, requests []RulePredicateFreshnessRequest) ([]RulePredicateFreshnessEvidence, error)
}

// ReadinessProvider proves the backend's runtime query path with zero-row
// reads against the eligible sources consumed by enabled rules. Inventory
// alone is not enough to establish that scan-time evidence can be collected.
type ReadinessProvider interface {
	ReadinessEvidence(ctx context.Context, rules []Rule, sources []Source) (ReadinessEvidence, error)
}

// ScanRefresher clears backend observations that must not survive between
// scans. Long-running callers invoke it once immediately before each scan.
type ScanRefresher interface {
	RefreshForScan(ctx context.Context) error
}

// VersionProvider is an optional, best-effort backend version capability.
type VersionProvider interface {
	Version(ctx context.Context) (string, error)
}

// CandidateParser is an optional backend capability for parsing a proposed
// detection without installing it. Candidate formats are backend-specific;
// callers must never silently feed one backend's format to another parser.
type CandidateParser interface {
	ParseCandidates(ctx context.Context, data []byte) ([]Rule, error)
}

// LineageProvider is an optional read-only backend capability for reporting
// transformations between dependencies consumed by the inventoried rules.
// Its results are informational.
type LineageProvider interface {
	LineageEvidence(ctx context.Context, rules []Rule) ([]LineageEvidence, error)
}

// SummaryRuleRunEvidence records the latest bounded LASummaryLogs observation
// for one summary rule whose output is consumed by an enabled detection. A
// native failed status is evidence, not a deadair finding or gate.
type SummaryRuleRunEvidence struct {
	ID                  string
	Rule                DependencyRef
	Output              DependencyRef
	Status              EvidenceStatus
	Method              string
	ObservedAt          time.Time
	Window              time.Duration
	RunAt               time.Time
	RunStatus           string
	QueryDurationMillis int64
	ResultCount         int64
	RuleModifiedAt      time.Time
	Error               string
	Detail              string
}

// SummaryRuleRunProvider is an optional read-only runtime evidence source for
// summary rules. It remains separate from structural LineageProvider output.
type SummaryRuleRunProvider interface {
	SummaryRuleRunEvidence(ctx context.Context, rules []Rule) ([]SummaryRuleRunEvidence, error)
}

// ProvenanceProvider is an optional read-only backend capability for
// enriching rule origins such as templates or content packages.
type ProvenanceProvider interface {
	ProvenanceEvidence(ctx context.Context, rules []Rule) ([]ProvenanceEvidence, error)
}
