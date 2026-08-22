package report

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"

	"github.com/alephnull-sh/deadair/internal/backend"
	"github.com/alephnull-sh/deadair/internal/state"
)

// ScanScope records the configured assessment boundary, not the concrete
// sources discovered during a scan. This lets diff reject reports produced
// with different filters while still reporting sources that appeared or
// disappeared inside the same scope.
type ScanScope struct {
	Mode             string   `json:"mode"` // installed | candidate
	Include          []string `json:"include,omitempty"`
	Exclude          []string `json:"exclude,omitempty"`
	SchemaTracking   bool     `json:"schema_tracking,omitempty"`
	Stateful         bool     `json:"stateful,omitempty"`
	ConfigurationID  string   `json:"configuration_id,omitempty"`
	CandidateRuleIDs []string `json:"candidate_rule_ids,omitempty"`
}

// Finding is the stable, reason-level representation used for lifecycle,
// policy, and safe diffs. The older finding arrays remain in reports for
// compatibility and terminal rendering.
type Finding struct {
	ID              string             `json:"id"`
	Class           string             `json:"class"`
	Reason          string             `json:"reason,omitempty"`
	RuleID          string             `json:"rule_id,omitempty"`
	BackendObjectID string             `json:"backend_object_id,omitempty"`
	RuleName        string             `json:"rule_name,omitempty"`
	Severity        string             `json:"severity,omitempty"`
	Source          string             `json:"source,omitempty"`
	Dependency      string             `json:"dependency,omitempty"`
	FirstSeen       time.Time          `json:"first_seen"`
	LastSeen        time.Time          `json:"last_seen"`
	Occurrences     int                `json:"occurrences"`
	RecoveredAt     *time.Time         `json:"recovered_at,omitempty"`
	Accepted        *FindingAcceptance `json:"accepted,omitempty"`
	Gates           bool               `json:"gates"`
}

type FindingAcceptance struct {
	Status    string    `json:"status"` // active | expired
	Reason    string    `json:"reason"`
	ExpiresAt time.Time `json:"expires_at"`
}

func stableFindingID(targetID, instance, backendName, class, ruleID, reason, source, dependency string) string {
	parts := []string{targetID, instance, backendName, class, ruleID, reason, source, dependency}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "finding-" + hex.EncodeToString(sum[:])[:20]
}

func (r *Report) buildFindings(store *state.Store, policy *Policy) {
	findings := make([]Finding, 0, len(r.DeadDetections)+len(r.ImpairedDetections)+len(r.Sources)+len(r.UnusedTelemetry)+len(r.PartialInputCoverage))
	for _, dead := range r.DeadDetections {
		ruleID := logicalDetectionRuleID(dead.ID, dead.RuleID)
		findings = append(findings, Finding{
			ID:    stableFindingID(r.TargetID, r.Instance, r.Backend, FindingDead, ruleID, dead.Reason, "", ""),
			Class: FindingDead, Reason: dead.Reason, RuleID: ruleID,
			BackendObjectID: dead.BackendObjectID, RuleName: dead.Name, Severity: dead.Severity,
		})
	}
	for _, impaired := range r.ImpairedDetections {
		ruleID := logicalDetectionRuleID(impaired.ID, impaired.RuleID)
		for _, reason := range impaired.Reasons {
			switch reason {
			case ReasonMissingFields:
				findings = append(findings, r.missingFieldFindings(impaired)...)
			case ReasonLagBlindWindow:
				for _, source := range impaired.LagSources {
					findings = append(findings, Finding{
						ID:    stableFindingID(r.TargetID, r.Instance, r.Backend, FindingImpaired, ruleID, reason, source, ""),
						Class: FindingImpaired, Reason: reason, RuleID: ruleID,
						BackendObjectID: impaired.BackendObjectID, RuleName: impaired.Name,
						Severity: impaired.Severity, Source: source,
					})
				}
			case ReasonSourcePlanIncompatible:
				if len(impaired.IncompatibleSources) == 0 {
					findings = append(findings, Finding{
						ID:    stableFindingID(r.TargetID, r.Instance, r.Backend, FindingImpaired, ruleID, reason, "", ""),
						Class: FindingImpaired, Reason: reason, RuleID: ruleID,
						BackendObjectID: impaired.BackendObjectID, RuleName: impaired.Name, Severity: impaired.Severity,
					})
					break
				}
				for _, source := range impaired.IncompatibleSources {
					findings = append(findings, Finding{
						ID:    stableFindingID(r.TargetID, r.Instance, r.Backend, FindingImpaired, ruleID, reason, source, ""),
						Class: FindingImpaired, Reason: reason, RuleID: ruleID,
						BackendObjectID: impaired.BackendObjectID, RuleName: impaired.Name,
						Severity: impaired.Severity, Source: source,
					})
				}
			default:
				findings = append(findings, Finding{
					ID:    stableFindingID(r.TargetID, r.Instance, r.Backend, FindingImpaired, ruleID, reason, "", ""),
					Class: FindingImpaired, Reason: reason, RuleID: ruleID,
					BackendObjectID: impaired.BackendObjectID, RuleName: impaired.Name, Severity: impaired.Severity,
				})
			}
		}
	}
	for _, source := range r.Sources {
		if source.Status == "stale" || source.Status == "empty" {
			findings = append(findings, Finding{
				ID:    stableFindingID(r.TargetID, r.Instance, r.Backend, FindingSourceDegraded, "", source.Status, source.Name, ""),
				Class: FindingSourceDegraded, Reason: source.Status, Source: source.Name,
			})
		}
		if source.Volume != nil && source.Volume.Status == state.VolumeLow {
			findings = append(findings, Finding{
				ID:    stableFindingID(r.TargetID, r.Instance, r.Backend, FindingVolumeLow, "", state.VolumeLow, source.Name, ""),
				Class: FindingVolumeLow, Reason: state.VolumeLow, Source: source.Name,
			})
		}
		if source.Schema != nil && source.Schema.Status == state.SchemaDrift {
			findings = append(findings, Finding{
				ID:    stableFindingID(r.TargetID, r.Instance, r.Backend, FindingSchemaDrift, "", state.SchemaDrift, source.Name, ""),
				Class: FindingSchemaDrift, Reason: state.SchemaDrift, Source: source.Name,
			})
		}
	}
	for _, unused := range r.UnusedTelemetry {
		findings = append(findings, Finding{
			ID:    stableFindingID(r.TargetID, r.Instance, r.Backend, FindingUnused, "", "unused", unused.Name, ""),
			Class: FindingUnused, Reason: "unused", Source: unused.Name,
		})
	}
	for _, partial := range r.PartialInputCoverage {
		dependency := partial.Expression
		if dependency == "" {
			dependency = partial.Selector
		}
		findings = append(findings, Finding{
			ID: stableFindingID(r.TargetID, r.Instance, r.Backend, FindingPartialInput,
				partial.RuleID, ReasonSelectorEmpty, "", dependency),
			Class: FindingPartialInput, Reason: ReasonSelectorEmpty, RuleID: partial.RuleID,
			BackendObjectID: partial.BackendObjectID, RuleName: partial.RuleName,
			Severity: partial.Severity, Dependency: dependency,
		})
	}

	sort.Slice(findings, func(i, j int) bool { return findings[i].ID < findings[j].ID })
	r.applyFindingLifecycle(findings, store)
	if policy != nil {
		summary := policy.apply(r.Findings)
		r.Policy = &summary
		for _, finding := range r.Findings {
			if finding.Gates {
				r.Summary.GatedFindings++
			}
		}
	}
}

func (r *Report) missingFieldFindings(impaired ImpairedDetection) []Finding {
	ruleID := logicalDetectionRuleID(impaired.ID, impaired.RuleID)
	wanted := make(map[string]bool, len(impaired.MissingFields))
	for _, field := range impaired.MissingFields {
		wanted[field] = true
	}
	seen := make(map[string]bool)
	var findings []Finding
	for _, assessment := range r.RequiredFieldEvidence {
		if assessment.RuleID != ruleID {
			continue
		}
		for _, source := range assessment.Sources {
			if source.Status != backend.EvidenceAssessed {
				continue
			}
			for _, field := range source.Missing {
				if !wanted[field] {
					continue
				}
				key := source.Source + "\x00" + field
				if seen[key] {
					continue
				}
				seen[key] = true
				findings = append(findings, Finding{
					ID: stableFindingID(r.TargetID, r.Instance, r.Backend, FindingImpaired,
						ruleID, ReasonMissingFields, source.Source, field),
					Class: FindingImpaired, Reason: ReasonMissingFields, RuleID: ruleID,
					BackendObjectID: impaired.BackendObjectID, RuleName: impaired.Name,
					Severity: impaired.Severity, Source: source.Source, Dependency: field,
				})
			}
		}
	}
	return findings
}

func (r *Report) applyFindingLifecycle(findings []Finding, store *state.Store) {
	now := r.GeneratedAt.UTC()
	if store == nil {
		for i := range findings {
			findings[i].FirstSeen = now
			findings[i].LastSeen = now
			findings[i].Occurrences = 1
		}
		r.Findings = findings
		return
	}
	if store.Findings == nil {
		store.Findings = map[string]state.FindingState{}
	}
	scopeID := findingLifecycleScopeID(r.Scope)
	current := make(map[string]bool, len(findings))
	for i := range findings {
		finding := &findings[i]
		current[finding.ID] = true
		stateKey := scopeID + "/" + finding.ID
		previous := store.Findings[stateKey]
		if previous.FirstSeen.IsZero() {
			previous.FirstSeen = now
		}
		previous.LastSeen = now
		previous.Occurrences++
		previous.Active = true
		copyFindingToState(finding, &previous, r, scopeID)
		finding.FirstSeen = previous.FirstSeen
		finding.LastSeen = previous.LastSeen
		finding.Occurrences = previous.Occurrences
		store.Findings[stateKey] = previous
	}
	for stateKey, previous := range store.Findings {
		if previous.ScopeID != scopeID || current[previous.FindingID] || !previous.Active ||
			previous.TargetID != r.TargetID || previous.Instance != r.Instance || previous.Backend != r.Backend {
			continue
		}
		previousFinding := findingFromState(previous.FindingID, previous)
		if !findingRecoveryConfirmed(r, previousFinding) {
			continue
		}
		recoveredAt := now
		recovered := previousFinding
		recovered.RecoveredAt = &recoveredAt
		r.RecoveredFindings = append(r.RecoveredFindings, recovered)
		previous.Active = false
		store.Findings[stateKey] = previous
	}
	sort.Slice(r.RecoveredFindings, func(i, j int) bool { return r.RecoveredFindings[i].ID < r.RecoveredFindings[j].ID })
	r.Findings = findings
}

func copyFindingToState(f *Finding, out *state.FindingState, r *Report, scopeID string) {
	out.FindingID, out.ScopeID = f.ID, scopeID
	out.Class, out.Reason = f.Class, f.Reason
	out.RuleID, out.BackendObjectID = f.RuleID, f.BackendObjectID
	out.RuleName, out.Severity = f.RuleName, f.Severity
	out.Source, out.Dependency = f.Source, f.Dependency
	out.TargetID, out.Instance, out.Backend = r.TargetID, r.Instance, r.Backend
}

func findingLifecycleScopeID(scope ScanScope) string {
	include := append([]string(nil), scope.Include...)
	exclude := append([]string(nil), scope.Exclude...)
	candidates := append([]string(nil), scope.CandidateRuleIDs...)
	sort.Strings(include)
	sort.Strings(exclude)
	sort.Strings(candidates)
	parts := []string{scope.Mode, scope.ConfigurationID}
	if scope.SchemaTracking {
		parts = append(parts, "schema=1")
	} else {
		parts = append(parts, "schema=0")
	}
	if scope.Stateful {
		parts = append(parts, "stateful=1")
	} else {
		parts = append(parts, "stateful=0")
	}
	for _, value := range include {
		parts = append(parts, "include="+value)
	}
	for _, value := range exclude {
		parts = append(parts, "exclude="+value)
	}
	for _, value := range candidates {
		parts = append(parts, "candidate="+value)
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "scope-" + hex.EncodeToString(sum[:])[:20]
}

// findingRecoveryConfirmed distinguishes a resolved finding from a finding
// that merely disappeared because the newer scan lost evidence. Recovery
// requires complete class-specific evidence and, where possible, a positive
// healthy measurement for the affected entity.
func findingRecoveryConfirmed(current *Report, previous Finding) bool {
	switch previous.Class {
	case FindingDead:
		if !assessmentSupportsRecovery(current, AssessmentSourceResolution) || ruleInputUncertain(current, previous.RuleID) {
			return false
		}
		switch previous.Reason {
		case ReasonDisconnected:
			return ruleHasAuthoritativeResolved(current, previous.RuleID)
		case ReasonStarved:
			return starvedRecoveryConfirmed(current, previous.RuleID)
		case ReasonSourcePlanIncompatible:
			return ruleHasAuthoritativeResolved(current, previous.RuleID)
		default:
			return false
		}
	case FindingImpaired:
		if ruleInputUncertain(current, previous.RuleID) {
			return false
		}
		switch previous.Reason {
		case ReasonMissingFields:
			return requiredFieldRecoveryConfirmed(current, previous)
		case ReasonLagBlindWindow:
			return ingestLagRecoveryConfirmed(current, previous)
		case ReasonSourcePlanIncompatible:
			return incompatibleSourceRecoveryConfirmed(current, previous)
		default:
			return false
		}
	case FindingSourceDegraded:
		return sourceHealthStatus(current, previous.Source) == "ok"
	case FindingVolumeLow:
		for i := range current.Sources {
			source := &current.Sources[i]
			if source.Name == previous.Source && source.Volume != nil {
				return source.Volume.Status == state.VolumeOK
			}
		}
		return false
	case FindingSchemaDrift:
		if !assessmentSupportsRecovery(current, AssessmentSchemaDrift) {
			return false
		}
		for i := range current.Sources {
			source := &current.Sources[i]
			if source.Name == previous.Source && source.Schema != nil {
				return source.Schema.Status == state.SchemaOK
			}
		}
		return false
	case FindingUnused:
		if current.Summary.UnusedTelemetryAssessment != UnusedAssessmentComplete &&
			current.Summary.UnusedTelemetryAssessment != UnusedAssessmentLegacy {
			return false
		}
		for _, source := range current.Sources {
			if source.Name == previous.Source {
				return source.Consumers > 0
			}
		}
		return false
	case FindingPartialInput:
		if !assessmentSupportsRecovery(current, AssessmentSourceResolution) || ruleInputUncertain(current, previous.RuleID) {
			return false
		}
		for _, resolution := range current.InputResolutions {
			if resolution.Diagnostic && logicalInputResolutionRuleID(resolution) == previous.RuleID &&
				resolution.Expression == previous.Dependency {
				return resolution.Status == backend.ResolutionResolved
			}
		}
		return false
	default:
		return false
	}
}

// assessmentSupportsRecovery requires an explicit successful assessment.
// Missing, disabled, incomplete, or unavailable evidence is not proof of
// recovery.
func assessmentSupportsRecovery(r *Report, name string) bool {
	found := false
	for _, assessment := range r.Assessments {
		if assessment.Name != name {
			continue
		}
		found = true
		if assessment.Status != backend.EvidenceAssessed {
			return false
		}
	}
	return found
}

func ruleInputUncertain(r *Report, ruleID string) bool {
	for _, rule := range r.UnmappedRules {
		if logicalDetectionRuleID(rule.ID, rule.RuleID) == ruleID {
			return true
		}
	}
	for _, rule := range r.RemoteRules {
		if logicalDetectionRuleID(rule.ID, rule.RuleID) == ruleID {
			return true
		}
	}
	return false
}

func ruleHasAuthoritativeResolved(r *Report, ruleID string) bool {
	for _, resolution := range r.InputResolutions {
		if logicalInputResolutionRuleID(resolution) == ruleID && !resolution.Diagnostic && resolution.Status == backend.ResolutionResolved &&
			len(resolution.ResolvedSources) > 0 {
			return true
		}
	}
	return false
}

func starvedRecoveryConfirmed(r *Report, ruleID string) bool {
	var resolvedSources []string
	for _, resolution := range r.InputResolutions {
		if logicalInputResolutionRuleID(resolution) == ruleID && !resolution.Diagnostic && resolution.Status == backend.ResolutionResolved {
			resolvedSources = append(resolvedSources, resolution.ResolvedSources...)
		}
	}
	for _, source := range resolvedSources {
		if sourceHealthStatus(r, source) == "ok" {
			return true
		}
	}
	return false
}

func incompatibleSourceRecoveryConfirmed(r *Report, previous Finding) bool {
	if !assessmentSupportsRecovery(r, AssessmentSourceResolution) || ruleInputUncertain(r, previous.RuleID) {
		return false
	}
	for _, resolution := range r.InputResolutions {
		if resolution.Diagnostic || logicalInputResolutionRuleID(resolution) != previous.RuleID ||
			resolution.Status != backend.ResolutionResolved {
			continue
		}
		for _, source := range resolution.ResolvedSources {
			if source == previous.Source {
				return true
			}
		}
	}
	return false
}

func requiredFieldRecoveryConfirmed(r *Report, previous Finding) bool {
	if !assessmentSupportsRecovery(r, AssessmentRequiredFields) {
		return false
	}
	foundRule := false
	foundSource := previous.Source == ""
	for _, assessment := range r.RequiredFieldEvidence {
		if assessment.RuleID != previous.RuleID {
			continue
		}
		foundRule = true
		if len(assessment.Sources) == 0 {
			return false
		}
		for _, source := range assessment.Sources {
			if previous.Source != "" && source.Source != previous.Source {
				continue
			}
			foundSource = true
			if source.Status != backend.EvidenceAssessed || recoverySliceContains(source.Missing, previous.Dependency) {
				return false
			}
		}
	}
	return foundRule && foundSource
}

func ingestLagRecoveryConfirmed(r *Report, previous Finding) bool {
	if !assessmentSupportsRecovery(r, AssessmentIngestLag) {
		return false
	}
	for _, source := range r.Sources {
		if source.Name == previous.Source && source.IngestLag != nil {
			return source.IngestLag.Status == backend.EvidenceAssessed
		}
	}
	return false
}

func sourceHealthStatus(r *Report, name string) string {
	for _, source := range r.Sources {
		if source.Name == name {
			return source.Status
		}
	}
	return ""
}

func recoverySliceContains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func findingFromState(id string, in state.FindingState) Finding {
	return Finding{
		ID: id, Class: in.Class, Reason: in.Reason, RuleID: in.RuleID,
		BackendObjectID: in.BackendObjectID, RuleName: in.RuleName, Severity: in.Severity,
		Source: in.Source, Dependency: in.Dependency, FirstSeen: in.FirstSeen,
		LastSeen: in.LastSeen, Occurrences: in.Occurrences,
	}
}
