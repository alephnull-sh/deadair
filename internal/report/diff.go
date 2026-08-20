package report

import (
	"fmt"
	"slices"
	"sort"
)

// DiffResult is what changed between two comparable scan reports.
type DiffResult struct {
	NewFindings        []Finding           `json:"new_findings,omitempty"`
	RecoveredFindings  []Finding           `json:"recovered_findings,omitempty"`
	NewlyGatedFindings []Finding           `json:"newly_gated_findings,omitempty"`
	NoLongerGated      []Finding           `json:"no_longer_gated_findings,omitempty"`
	NewlyDead          []DeadDetection     `json:"newly_dead,omitempty"`
	RecoveredDead      []RuleRef           `json:"recovered_dead,omitempty"`
	NewlyImpaired      []ImpairedDetection `json:"newly_impaired,omitempty"`
	RecoveredImpaired  []RuleRef           `json:"recovered_impaired,omitempty"`
	NewlyDegraded      []SourceHealth      `json:"newly_degraded,omitempty"`
	RecoveredSources   []SourceHealth      `json:"recovered_sources,omitempty"`
	NewSources         []string            `json:"new_sources,omitempty"`
	RemovedSources     []string            `json:"removed_sources,omitempty"`
	NewlyUnused        []UnusedSource      `json:"newly_unused,omitempty"`
	RegressionFindings int                 `json:"regression_findings"`
}

// Regressions counts reason-level findings that should fail a gate.
func (d *DiffResult) Regressions() int { return d.RegressionFindings }

// ValidateComparable rejects report pairs whose findings do not describe the
// same assessment boundary. A diff across targets or scopes is misleading,
// not an empty or healthy result.
func ValidateComparable(older, newer *Report) error {
	if older == nil || newer == nil {
		return fmt.Errorf("both reports are required")
	}
	if older.SchemaVersion == "" || newer.SchemaVersion == "" || older.SchemaVersion != newer.SchemaVersion {
		return fmt.Errorf("schema versions differ or are missing (%q vs %q)", older.SchemaVersion, newer.SchemaVersion)
	}
	if older.Backend == "" || newer.Backend == "" || older.Backend != newer.Backend {
		return fmt.Errorf("backends differ or are missing (%q vs %q)", older.Backend, newer.Backend)
	}
	if older.Instance == "" || newer.Instance == "" || older.Instance != newer.Instance {
		return fmt.Errorf("instances differ or are missing (%q vs %q)", older.Instance, newer.Instance)
	}
	if older.TargetID == "" || newer.TargetID == "" || older.TargetID != newer.TargetID {
		return fmt.Errorf("target identities differ or are missing")
	}
	if older.Redacted != newer.Redacted {
		return fmt.Errorf("redaction modes differ")
	}
	if older.Redacted {
		if older.Redaction == nil || newer.Redaction == nil || older.Redaction.Algorithm == "" || older.Redaction.KeyID == "" ||
			older.Redaction.Algorithm != newer.Redaction.Algorithm || older.Redaction.KeyID != newer.Redaction.KeyID {
			return fmt.Errorf("redaction keys or algorithms differ or are missing")
		}
	}
	if err := validateFindingIDs(older); err != nil {
		return fmt.Errorf("older report: %w", err)
	}
	if err := validateFindingIDs(newer); err != nil {
		return fmt.Errorf("newer report: %w", err)
	}
	oldScope, newScope := normalizedScope(older.Scope), normalizedScope(newer.Scope)
	if oldScope.Mode == "" || newScope.Mode == "" || oldScope.ConfigurationID == "" || newScope.ConfigurationID == "" ||
		oldScope.Mode != newScope.Mode || oldScope.ConfigurationID != newScope.ConfigurationID ||
		oldScope.SchemaTracking != newScope.SchemaTracking || oldScope.Stateful != newScope.Stateful ||
		!slices.Equal(oldScope.Include, newScope.Include) || !slices.Equal(oldScope.Exclude, newScope.Exclude) ||
		!slices.Equal(oldScope.CandidateRuleIDs, newScope.CandidateRuleIDs) {
		return fmt.Errorf("scan scopes differ or are missing")
	}
	return nil
}

func normalizedScope(in ScanScope) ScanScope {
	out := in
	out.Include = append([]string(nil), in.Include...)
	out.Exclude = append([]string(nil), in.Exclude...)
	out.CandidateRuleIDs = append([]string(nil), in.CandidateRuleIDs...)
	sort.Strings(out.Include)
	sort.Strings(out.Exclude)
	sort.Strings(out.CandidateRuleIDs)
	return out
}

// Diff compares an older report with a newer report after checking that the
// pair is safe to compare.
func Diff(older, newer *Report) (*DiffResult, error) {
	if err := ValidateComparable(older, newer); err != nil {
		return nil, err
	}
	d := &DiffResult{}
	oldFindings := findingsByID(older)
	newFindings := findingsByID(newer)
	for id, finding := range newFindings {
		previous, existed := oldFindings[id]
		if existed {
			if finding.Gates && !previous.Gates {
				d.NewlyGatedFindings = append(d.NewlyGatedFindings, finding)
				d.RegressionFindings++
			}
			continue
		}
		d.NewFindings = append(d.NewFindings, finding)
		if findingRegresses(newer, finding) {
			d.RegressionFindings++
		}
		appendLegacyRegression(d, newer, finding)
	}
	for id, finding := range oldFindings {
		current, remains := newFindings[id]
		if remains {
			if finding.Gates && !current.Gates {
				d.NoLongerGated = append(d.NoLongerGated, current)
			}
			continue
		}
		if !findingRecoveryConfirmed(newer, finding) {
			continue
		}
		d.RecoveredFindings = append(d.RecoveredFindings, finding)
		appendLegacyRecovery(d, older, finding)
	}
	sort.Slice(d.NewFindings, func(i, j int) bool { return d.NewFindings[i].ID < d.NewFindings[j].ID })
	sort.Slice(d.RecoveredFindings, func(i, j int) bool { return d.RecoveredFindings[i].ID < d.RecoveredFindings[j].ID })
	sort.Slice(d.NewlyGatedFindings, func(i, j int) bool { return d.NewlyGatedFindings[i].ID < d.NewlyGatedFindings[j].ID })
	sort.Slice(d.NoLongerGated, func(i, j int) bool { return d.NoLongerGated[i].ID < d.NoLongerGated[j].ID })

	oldSources := map[string]SourceHealth{}
	for _, source := range older.Sources {
		oldSources[source.Name] = source
	}
	newSources := map[string]SourceHealth{}
	for _, source := range newer.Sources {
		newSources[source.Name] = source
		if _, existed := oldSources[source.Name]; !existed {
			d.NewSources = append(d.NewSources, source.Name)
		}
	}
	for _, source := range older.Sources {
		if _, remains := newSources[source.Name]; !remains {
			d.RemovedSources = append(d.RemovedSources, source.Name)
		}
	}
	sort.Strings(d.NewSources)
	sort.Strings(d.RemovedSources)
	return d, nil
}

func validateFindingIDs(r *Report) error {
	seen := make(map[string]bool, len(r.Findings))
	for _, finding := range r.Findings {
		if finding.ID == "" {
			return fmt.Errorf("finding ID is missing")
		}
		if seen[finding.ID] {
			return fmt.Errorf("duplicate finding ID %q", finding.ID)
		}
		seen[finding.ID] = true
	}
	return nil
}

func findingsByID(r *Report) map[string]Finding {
	out := make(map[string]Finding, len(r.Findings))
	for _, finding := range r.Findings {
		out[finding.ID] = finding
	}
	return out
}

func findingRegresses(r *Report, finding Finding) bool {
	if r.Policy != nil {
		return finding.Gates
	}
	switch finding.Class {
	case FindingDead, FindingImpaired, FindingSourceDegraded, FindingVolumeLow, FindingSchemaDrift:
		return true
	default:
		return false
	}
}

func appendLegacyRegression(d *DiffResult, r *Report, finding Finding) {
	switch finding.Class {
	case FindingDead:
		for _, dead := range r.DeadDetections {
			if logicalDetectionRuleID(dead.ID, dead.RuleID) == finding.RuleID && dead.Reason == finding.Reason {
				d.NewlyDead = append(d.NewlyDead, dead)
				return
			}
		}
	case FindingImpaired:
		for _, impaired := range r.ImpairedDetections {
			if logicalDetectionRuleID(impaired.ID, impaired.RuleID) != finding.RuleID {
				continue
			}
			impaired.Reasons = []string{finding.Reason}
			if finding.Reason == ReasonMissingFields {
				impaired.MissingFields = []string{finding.Dependency}
				impaired.LagSources = nil
				if finding.Source != "" {
					impaired.Sources = []string{finding.Source}
				}
			} else if finding.Reason == ReasonLagBlindWindow {
				impaired.LagSources = []string{finding.Source}
				impaired.MissingFields = nil
			}
			d.NewlyImpaired = append(d.NewlyImpaired, impaired)
			return
		}
	case FindingSourceDegraded:
		for _, source := range r.Sources {
			if source.Name == finding.Source && source.Status == finding.Reason {
				d.NewlyDegraded = append(d.NewlyDegraded, source)
				return
			}
		}
	case FindingUnused:
		for _, source := range r.UnusedTelemetry {
			if source.Name == finding.Source {
				d.NewlyUnused = append(d.NewlyUnused, source)
				return
			}
		}
	}
}

func appendLegacyRecovery(d *DiffResult, older *Report, finding Finding) {
	legacyID := finding.RuleID
	if finding.BackendObjectID != "" {
		legacyID = finding.BackendObjectID
	}
	for _, dead := range older.DeadDetections {
		if logicalDetectionRuleID(dead.ID, dead.RuleID) == finding.RuleID && dead.Reason == finding.Reason {
			legacyID = dead.ID
			break
		}
	}
	for _, impaired := range older.ImpairedDetections {
		if logicalDetectionRuleID(impaired.ID, impaired.RuleID) == finding.RuleID {
			legacyID = impaired.ID
			break
		}
	}
	ref := RuleRef{
		ID: legacyID, RuleID: finding.RuleID, BackendObjectID: finding.BackendObjectID,
		FindingID: finding.ID, Reason: finding.Reason, Dependency: finding.Dependency,
		Name: finding.RuleName, Severity: finding.Severity,
	}
	switch finding.Class {
	case FindingDead:
		d.RecoveredDead = append(d.RecoveredDead, ref)
	case FindingImpaired:
		d.RecoveredImpaired = append(d.RecoveredImpaired, ref)
	case FindingSourceDegraded:
		d.RecoveredSources = append(d.RecoveredSources, SourceHealth{Name: finding.Source, Status: "ok"})
	}
}
