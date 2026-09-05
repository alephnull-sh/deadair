package report

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	// ReportSchemaVersion identifies the additive JSON report contract.
	ReportSchemaVersion = "deadair.report.v1"
	// FleetReportSchemaVersion identifies the additive fleet JSON contract.
	FleetReportSchemaVersion = "deadair.fleet-report.v1"
	// DefaultProducerVersion is used when a caller does not supply the
	// build-stamped deadair version.
	DefaultProducerVersion = "dev"
)

// Producer identifies the program that emitted a report.
type Producer struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// CapabilityStatus describes how completely a backend supports one report
// input. These values are part of the versioned JSON contract.
type CapabilityStatus string

const (
	CapabilitySupported   CapabilityStatus = "supported"
	CapabilityPartial     CapabilityStatus = "partial"
	CapabilityUnavailable CapabilityStatus = "unavailable"
	CapabilityListedOnly  CapabilityStatus = "listed-only"
)

const (
	CapabilityRuleInventory        = "rule_inventory"
	CapabilitySourceResolution     = "source_resolution"
	CapabilityFreshness            = "freshness"
	CapabilityDocsStorage          = "docs_storage"
	CapabilitySchema               = "schema"
	CapabilityRequiredFields       = "required_fields"
	CapabilityIngestLag            = "ingest_lag"
	CapabilityCandidateParsing     = "candidate_parsing"
	CapabilityRemote               = "remote"
	CapabilityDependencyResolution = "dependency_resolution"
	CapabilityCrossWorkspace       = "cross_workspace"
	CapabilitySourceLineage        = "source_lineage"
	CapabilityRuleProvenance       = "rule_provenance"
)

// Capability records one backend feature and its support status.
type Capability struct {
	Name   string           `json:"name"`
	Status CapabilityStatus `json:"status"`
	Detail string           `json:"detail,omitempty"`
}

// BackendMetadata describes the backend product and the evidence available
// to the report builder. Backend on Report remains a string for compatibility.
type BackendMetadata struct {
	Name                  string       `json:"name"`
	Product               string       `json:"product"`
	ObservedVersion       string       `json:"observed_version,omitempty"`
	SupportedVersionLines []string     `json:"supported_version_lines"`
	Capabilities          []Capability `json:"capabilities"`
}

// BackendVersionStatus describes how an observed product version relates to
// the recognized and exact live-CI versions.
type BackendVersionStatus string

const (
	BackendVersionTested      BackendVersionStatus = "tested"
	BackendVersionBestEffort  BackendVersionStatus = "best-effort"
	BackendVersionUnsupported BackendVersionStatus = "unsupported"
)

// BackendVersionAssessment is the compatibility diagnosis printed by check.
type BackendVersionAssessment struct {
	Status BackendVersionStatus
	Detail string
}

type backendVersionPolicy struct {
	recognizedLines []string
	testedVersions  []string
}

var backendVersionPolicies = map[string]backendVersionPolicy{
	"elastic": {
		recognizedLines: []string{"8.x", "9.x"},
		testedVersions:  []string{"8.19.19", "9.4.4"},
	},
	"opensearch": {
		recognizedLines: []string{"2.x", "3.x"},
		testedVersions:  []string{"2.19.6", "3.7.0"},
	},
}

// AssessBackendVersion classifies an observed backend version against the
// version matrix used by trusted integration CI.
func AssessBackendVersion(name, version string) BackendVersionAssessment {
	policy, ok := backendVersionPolicies[name]
	if !ok {
		return BackendVersionAssessment{
			Status: BackendVersionUnsupported,
			Detail: "no published version policy for backend " + name,
		}
	}
	version = strings.TrimSpace(version)
	for _, tested := range policy.testedVersions {
		if version == tested {
			return BackendVersionAssessment{
				Status: BackendVersionTested,
				Detail: "exact version exercised by trusted live CI",
			}
		}
	}
	majorText := strings.SplitN(version, ".", 2)[0]
	major, err := strconv.Atoi(majorText)
	if err == nil {
		line := fmt.Sprintf("%d.x", major)
		for _, recognized := range policy.recognizedLines {
			if line == recognized {
				return BackendVersionAssessment{
					Status: BackendVersionBestEffort,
					Detail: fmt.Sprintf("recognized major %s; exact live-CI versions: %s",
						line, strings.Join(policy.testedVersions, ", ")),
				}
			}
		}
	}
	return BackendVersionAssessment{
		Status: BackendVersionUnsupported,
		Detail: fmt.Sprintf("recognized major lines: %s; exact live-CI versions: %s",
			strings.Join(policy.recognizedLines, ", "), strings.Join(policy.testedVersions, ", ")),
	}
}

func producer(version string) Producer {
	if version == "" {
		version = DefaultProducerVersion
	}
	return Producer{Name: "deadair", Version: version}
}

func backendMetadata(name, observedVersion string) BackendMetadata {
	metadata := BackendMetadata{Name: name, Product: name, ObservedVersion: observedVersion}
	statuses := map[string]CapabilityStatus{}
	details := map[string]string{}

	switch name {
	case "elastic":
		metadata.Product = "Elastic Security"
		metadata.SupportedVersionLines = append([]string(nil), backendVersionPolicies[name].recognizedLines...)
		for _, capability := range capabilityOrder() {
			statuses[capability] = CapabilitySupported
		}
		statuses[CapabilitySourceResolution] = CapabilityPartial
		details[CapabilitySourceResolution] = "index selectors, aliases, data streams, data views, and direct ES|QL FROM pipelines; indicator-match, lookup, enrichment, dynamic ES|QL and ML inputs are reported unsupported"
		statuses[CapabilityRemote] = CapabilityListedOnly
		details[CapabilityRemote] = "remote inputs are listed but not evaluated"
		for _, capability := range []string{CapabilityDependencyResolution, CapabilityCrossWorkspace, CapabilitySourceLineage, CapabilityRuleProvenance} {
			statuses[capability] = CapabilityUnavailable
			details[capability] = "backend does not expose this evidence"
		}
	case "opensearch":
		metadata.Product = "OpenSearch Security Analytics"
		metadata.SupportedVersionLines = append([]string(nil), backendVersionPolicies[name].recognizedLines...)
		for _, capability := range []string{
			CapabilityRuleInventory,
			CapabilitySourceResolution,
			CapabilityFreshness,
			CapabilityDocsStorage,
			CapabilitySchema,
		} {
			statuses[capability] = CapabilitySupported
		}
		statuses[CapabilityCandidateParsing] = CapabilitySupported
		for _, capability := range []string{
			CapabilityRequiredFields,
			CapabilityIngestLag,
		} {
			statuses[capability] = CapabilityUnavailable
		}
		details[CapabilityRequiredFields] = "detector metadata does not expose required fields"
		details[CapabilityIngestLag] = "ingest lag is not measured by this backend"
		details[CapabilityCandidateParsing] = "Security Analytics detector API objects can be assessed without installation"
		statuses[CapabilityRemote] = CapabilityListedOnly
		details[CapabilityRemote] = "remote inputs are listed but not evaluated"
		for _, capability := range []string{CapabilityDependencyResolution, CapabilityCrossWorkspace, CapabilitySourceLineage, CapabilityRuleProvenance} {
			statuses[capability] = CapabilityUnavailable
			details[capability] = "backend does not expose this evidence"
		}
	case "sentinel":
		metadata.Product = "Microsoft Sentinel"
		metadata.ObservedVersion = ""
		metadata.SupportedVersionLines = []string{}
		statuses[CapabilityRuleInventory] = CapabilitySupported
		details[CapabilityRuleInventory] = "enabled Scheduled analytics rules via the GA 2025-09-01 API and NRT rules via the 2025-10-01-preview API; non-query rule kinds are retained but not assessed"
		statuses[CapabilitySourceResolution] = CapabilityPartial
		details[CapabilitySourceResolution] = "direct local tables, parenthesized subqueries, union/join/lookup, simple tabular let aliases, recursively expanded workspace functions with closed scalar arguments, metadata-backed ASIM functions, native ASIM functions with positive table and permission evidence, and explicitly mapped literal workspace() tables; tabular or runtime function arguments, dynamic table names, external data, and unmapped or dynamic remote targets are unassessed"
		statuses[CapabilityFreshness] = CapabilityPartial
		details[CapabilityFreshness] = "resolved local or mapped remote Analytics tables retain separate TimeGenerated and ingestion_time() observations for Scheduled and NRT rules; eligible literal rule filters add activity context; explicit local vendor/product/device expectations produce independent producer findings"
		statuses[CapabilityDocsStorage] = CapabilityUnavailable
		details[CapabilityDocsStorage] = "Sentinel does not expose authoritative per-table document inventory and storage totals through the APIs used by this scan"
		statuses[CapabilitySchema] = CapabilityPartial
		details[CapabilitySchema] = "measured only for resolved local or explicitly mapped remote Analytics tables"
		statuses[CapabilityRequiredFields] = CapabilityUnavailable
		details[CapabilityRequiredFields] = "KQL column inference is not authoritative"
		statuses[CapabilityIngestLag] = CapabilityPartial
		details[CapabilityIngestLag] = "bounded paired TimeGenerated and ingestion_time() samples for eligible resolved local or explicitly mapped remote tables; missing or partial samples remain incomplete"
		statuses[CapabilityCandidateParsing] = CapabilitySupported
		details[CapabilityCandidateParsing] = "direct Scheduled or NRT JSON, ARM deployment JSON compiled from Bicep with literal values, parameter defaults, or simple variable references, and one Azure-Sentinel analytic-rule YAML document can be assessed without installation"
		statuses[CapabilityRemote] = CapabilityPartial
		details[CapabilityRemote] = "explicitly mapped literal workspace() tables are evaluated only after the remote workspace is verified and Sentinel-onboarded; unmapped or dynamic workspace targets and app(), resource(), ADX, and ARG inputs remain listed but unassessed"
		statuses[CapabilityDependencyResolution] = CapabilityPartial
		details[CapabilityDependencyResolution] = "literal _GetWatchlist() aliases and safely formed native ASIM calls receive bounded inventory, table, and permission evidence; dependency evidence is informational, and only concrete monitorable tables become source-health edges"
		statuses[CapabilityCrossWorkspace] = CapabilityPartial
		details[CapabilityCrossWorkspace] = "configured literal workspace() tables require an exact onboardingStates/default resource and are verified through ARM, table inventory, and scoped Logs evidence; textual aliases require a table-catalog read and successful original-literal Logs proof before canonical counting, while GUID and ARM-ID mappings do not; Microsoft's hard limit is 20 workspaces per analytics-rule query and deadair conservatively counts the home workspace, so at most 19 distinct remotes per rule are compatible; Azure Monitor blocks query scopes in 20 or more distinct normalized workspace regions, which deadair marks incompatible after any alias proof and before ordinary dependency and freshness probes; missing workspace location or onboarding evidence is unavailable; the platform warning at five regions is guidance rather than a deadair finding; same-subscription mapped source evidence is conclusive; for an eligible installed rule that references another subscription, only exact successful SentinelHealth evidence after the latest rule change and within its expected run cadence plus scheduling delay can corroborate its execution identity; candidate, absent, stale, ambiguous, mismatched, or non-successful execution evidence remains unassessed because scanner access does not prove the creator's credentials still work; tenant boundaries are not separately identified, and Azure Lighthouse or other cross-tenant topology is not live-validated"
		statuses[CapabilitySourceLineage] = CapabilityPartial
		details[CapabilitySourceLineage] = "ARM summary-rule inputs, transform, and Analytics output remain separate from latest-completed-run LASummaryLogs evidence; failed and overdue runs produce summary-pipeline findings, gated only by explicit policy; unavailable runtime evidence cannot establish recovery"
		statuses[CapabilityRuleProvenance] = CapabilityPartial
		details[CapabilityRuleProvenance] = "informational exact-ID joins from installed rules to native alert-rule templates and Content Hub template and package versions; display names are never used to guess provenance"
	default:
		metadata.SupportedVersionLines = []string{}
		for _, capability := range capabilityOrder() {
			statuses[capability] = CapabilityUnavailable
			details[capability] = "backend capability is not known"
		}
	}

	for _, name := range capabilityOrder() {
		metadata.Capabilities = append(metadata.Capabilities, Capability{
			Name: name, Status: statuses[name], Detail: details[name],
		})
	}
	return metadata
}

// MetadataForBackend returns the public capability contract used by reports
// and `deadair check` for a backend.
func MetadataForBackend(name, observedVersion string) BackendMetadata {
	return backendMetadata(name, observedVersion)
}

func capabilityOrder() []string {
	return []string{
		CapabilityRuleInventory,
		CapabilitySourceResolution,
		CapabilityFreshness,
		CapabilityDocsStorage,
		CapabilitySchema,
		CapabilityRequiredFields,
		CapabilityIngestLag,
		CapabilityCandidateParsing,
		CapabilityRemote,
		CapabilityDependencyResolution,
		CapabilityCrossWorkspace,
		CapabilitySourceLineage,
		CapabilityRuleProvenance,
	}
}
