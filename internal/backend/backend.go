// Package backend defines the read-only contract every SIEM backend
// implements. Backends may only observe: no call in this interface can be
// satisfied by anything other than reads.
package backend

import (
	"context"
	"time"
)

// Rule is a detection rule as inventoried from a SIEM.
type Rule struct {
	ID        string
	Name      string
	Enabled   bool
	Severity  string // normalized lowercase: low|medium|high|critical
	RiskScore int
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
}

// Source is a concrete log source (data stream or index) with health stats.
type Source struct {
	Name      string
	Docs      int64 // -1 when unknown
	SizeBytes int64
	LastEvent time.Time // zero when freshness could not be determined
	// IngestLag is the measured gap between event time and ingest time
	// (max(event.ingested) - max(@timestamp)). Nil when not measured.
	IngestLag *time.Duration
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

// Backend is a read-only client for one SIEM.
type Backend interface {
	Name() string
	Rules(ctx context.Context) ([]Rule, error)
	Sources(ctx context.Context) ([]Source, error)
	Schemas(ctx context.Context, sources []Source) (map[string]Schema, error)
}
