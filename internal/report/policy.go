package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/alephnull-sh/deadair/internal/graph"
)

const PolicyVersion = 1

// Finding classes are intentionally small and stable. Partial input is
// reserved for diagnostic per-selector coverage evidence; backends that do
// not emit that evidence simply never produce the class.
const (
	FindingDead           = "dead-detection"
	FindingImpaired       = "impaired-detection"
	FindingSourceDegraded = "source-degraded"
	FindingVolumeLow      = "volume-low"
	FindingSchemaDrift    = "schema-drift"
	FindingUnused         = "unused-telemetry"
	FindingPartialInput   = "partial-input"
)

var allowedFindingClasses = map[string]bool{
	FindingDead: true, FindingImpaired: true, FindingSourceDegraded: true,
	FindingVolumeLow: true, FindingSchemaDrift: true, FindingUnused: true,
	FindingPartialInput: true,
}

// Policy is a deliberately narrow local gate policy. It is data, not a rule
// language: source freshness, finding classes, a rule-severity floor, and
// time-bounded accepted findings are the only controls.
type Policy struct {
	Version           int               `json:"version"`
	SeverityThreshold string            `json:"severity_threshold,omitempty"`
	GateClasses       []string          `json:"gate_classes"`
	Sources           []SourcePolicy    `json:"sources,omitempty"`
	Accepted          []AcceptedFinding `json:"accepted,omitempty"`
	acceptedByID      map[string]AcceptedFinding
	expiredByID       map[string]AcceptedFinding
}

type SourcePolicy struct {
	Pattern  string `json:"pattern"`
	MaxStale string `json:"max_stale"`
	duration time.Duration
}

type AcceptedFinding struct {
	FindingID string    `json:"finding_id"`
	Reason    string    `json:"reason"`
	ExpiresAt time.Time `json:"expires_at"`
}

type PolicySummary struct {
	Version           int      `json:"version"`
	SeverityThreshold string   `json:"severity_threshold,omitempty"`
	GateClasses       []string `json:"gate_classes"`
	AcceptedActive    int      `json:"accepted_active"`
	AcceptedExpired   int      `json:"accepted_expired,omitempty"`
}

// LoadPolicy reads and validates a policy. Expired acceptances remain valid
// policy entries but no longer suppress their finding; the report marks them
// expired so a stale exception cannot silently turn a failing gate green.
func LoadPolicy(path string, now time.Time) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading policy file: %w", err)
	}
	var p Policy
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("parsing policy file: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			err = fmt.Errorf("multiple JSON values")
		}
		return nil, fmt.Errorf("parsing policy file: %w", err)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if err := p.validate(now.UTC()); err != nil {
		return nil, fmt.Errorf("invalid policy: %w", err)
	}
	return &p, nil
}

func (p *Policy) validate(now time.Time) error {
	if p.Version != PolicyVersion {
		return fmt.Errorf("version must be %d", PolicyVersion)
	}
	if p.SeverityThreshold != "" {
		p.SeverityThreshold = strings.ToLower(strings.TrimSpace(p.SeverityThreshold))
		if _, ok := severityRank[p.SeverityThreshold]; !ok {
			return fmt.Errorf("severity_threshold must be low, medium, high, or critical")
		}
	}
	if len(p.GateClasses) == 0 {
		return fmt.Errorf("gate_classes must list at least one finding class")
	}
	seenClasses := map[string]bool{}
	for i, class := range p.GateClasses {
		class = strings.ToLower(strings.TrimSpace(class))
		if !allowedFindingClasses[class] {
			return fmt.Errorf("gate_classes contains unknown class %q", class)
		}
		if seenClasses[class] {
			return fmt.Errorf("gate_classes contains duplicate class %q", class)
		}
		seenClasses[class] = true
		p.GateClasses[i] = class
	}
	seenPatterns := map[string]bool{}
	for i := range p.Sources {
		source := &p.Sources[i]
		source.Pattern = strings.TrimSpace(source.Pattern)
		if source.Pattern == "" {
			return fmt.Errorf("sources[%d].pattern is required", i)
		}
		if seenPatterns[source.Pattern] {
			return fmt.Errorf("sources contains duplicate pattern %q", source.Pattern)
		}
		seenPatterns[source.Pattern] = true
		d, err := time.ParseDuration(source.MaxStale)
		if err != nil || d <= 0 {
			return fmt.Errorf("sources[%d].max_stale must be a positive duration", i)
		}
		source.duration = d
	}
	p.acceptedByID = make(map[string]AcceptedFinding, len(p.Accepted))
	p.expiredByID = make(map[string]AcceptedFinding)
	seenAccepted := make(map[string]bool, len(p.Accepted))
	for i := range p.Accepted {
		a := &p.Accepted[i]
		a.FindingID = strings.TrimSpace(a.FindingID)
		a.Reason = strings.TrimSpace(a.Reason)
		if a.FindingID == "" || a.Reason == "" || a.ExpiresAt.IsZero() {
			return fmt.Errorf("accepted[%d] requires finding_id, reason, and expires_at", i)
		}
		if seenAccepted[a.FindingID] {
			return fmt.Errorf("accepted contains duplicate finding_id %q", a.FindingID)
		}
		seenAccepted[a.FindingID] = true
		if a.ExpiresAt.After(now) {
			p.acceptedByID[a.FindingID] = *a
		} else {
			p.expiredByID[a.FindingID] = *a
		}
	}
	return nil
}

func (p *Policy) maxStale(source string, fallback time.Duration) time.Duration {
	if p == nil {
		return fallback
	}
	for _, configured := range p.Sources {
		if graph.Match(configured.Pattern, source) {
			return configured.duration
		}
	}
	return fallback
}

func (p *Policy) apply(findings []Finding) PolicySummary {
	summary := PolicySummary{
		Version: p.Version, SeverityThreshold: p.SeverityThreshold,
		GateClasses: append([]string(nil), p.GateClasses...), AcceptedExpired: len(p.expiredByID),
	}
	classes := make(map[string]bool, len(p.GateClasses))
	for _, class := range p.GateClasses {
		classes[class] = true
	}
	for i := range findings {
		finding := &findings[i]
		if accepted, ok := p.acceptedByID[finding.ID]; ok {
			finding.Accepted = &FindingAcceptance{Status: "active", Reason: accepted.Reason, ExpiresAt: accepted.ExpiresAt}
			summary.AcceptedActive++
			continue
		}
		if expired, ok := p.expiredByID[finding.ID]; ok {
			finding.Accepted = &FindingAcceptance{Status: "expired", Reason: expired.Reason, ExpiresAt: expired.ExpiresAt}
		}
		if !classes[finding.Class] {
			continue
		}
		if p.SeverityThreshold != "" && finding.RuleID != "" {
			findingSeverity, known := severityRank[strings.ToLower(finding.Severity)]
			threshold := severityRank[p.SeverityThreshold]
			if known && findingSeverity > threshold {
				continue
			}
		}
		finding.Gates = true
	}
	sort.Strings(summary.GateClasses)
	return summary
}
