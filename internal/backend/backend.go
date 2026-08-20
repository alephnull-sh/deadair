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
	// DataViewID identifies the Kibana data view used by a rule. It is kept
	// separately from Patterns so candidate rules can resolve the data view
	// without first being installed.
	DataViewID string
	// Patterns are the index / data-stream patterns the rule reads (for
	// data-view-backed rules, resolved via the data view when possible).
	// Empty when the inputs cannot be determined from metadata (e.g. ML
	// jobs); those rules are reported as "unmapped", never "dead".
	Patterns []string
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
	Diagnostic       bool             `json:"diagnostic,omitempty"`
	SelectorKind     string           `json:"selector_kind"`
	ResolvedSources  []string         `json:"resolved_sources,omitempty"`
	Aliases          []string         `json:"aliases,omitempty"`
	ResolutionMethod string           `json:"resolution_method"`
	ObservedAt       time.Time        `json:"observed_at"`
	Status           ResolutionStatus `json:"status"`
	Detail           string           `json:"detail,omitempty"`
}

// Source is a concrete log source (data stream or index) with health stats.
type Source struct {
	Name      string
	Docs      int64 // -1 when unknown
	SizeBytes int64
	LastEvent time.Time // zero when freshness could not be determined
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

// VersionProvider is an optional, best-effort backend version capability.
type VersionProvider interface {
	Version(ctx context.Context) (string, error)
}

// CandidateParser is an optional backend capability for parsing a proposed
// detection without installing it. Candidate formats are backend-specific;
// callers must never silently feed one backend's format to another parser.
type CandidateParser interface {
	ParseCandidates(data []byte) ([]Rule, error)
}
