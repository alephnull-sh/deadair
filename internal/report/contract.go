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
	CapabilityRuleInventory    = "rule_inventory"
	CapabilitySourceResolution = "source_resolution"
	CapabilityFreshness        = "freshness"
	CapabilityDocsStorage      = "docs_storage"
	CapabilitySchema           = "schema"
	CapabilityRequiredFields   = "required_fields"
	CapabilityIngestLag        = "ingest_lag"
	CapabilityCandidateParsing = "candidate_parsing"
	CapabilityRemote           = "remote"
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
// the maintained and exact live-CI versions.
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
	maintainedLines []string
	testedVersions  []string
}

var backendVersionPolicies = map[string]backendVersionPolicy{
	"elastic": {
		maintainedLines: []string{"8.x", "9.x"},
		testedVersions:  []string{"8.19.19", "9.4.4"},
	},
	"opensearch": {
		maintainedLines: []string{"2.x", "3.x"},
		testedVersions:  []string{"2.19.6", "3.7.0"},
	},
}

// AssessBackendVersion classifies an observed backend version against the
// support policy used by trusted integration CI.
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
		for _, maintained := range policy.maintainedLines {
			if line == maintained {
				return BackendVersionAssessment{
					Status: BackendVersionBestEffort,
					Detail: fmt.Sprintf("maintained major %s; exact live-CI versions: %s",
						line, strings.Join(policy.testedVersions, ", ")),
				}
			}
		}
	}
	return BackendVersionAssessment{
		Status: BackendVersionUnsupported,
		Detail: fmt.Sprintf("maintained major lines: %s; exact live-CI versions: %s",
			strings.Join(policy.maintainedLines, ", "), strings.Join(policy.testedVersions, ", ")),
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
		metadata.SupportedVersionLines = append([]string(nil), backendVersionPolicies[name].maintainedLines...)
		for _, capability := range capabilityOrder() {
			statuses[capability] = CapabilitySupported
		}
		statuses[CapabilitySourceResolution] = CapabilityPartial
		details[CapabilitySourceResolution] = "index selectors, aliases, data streams, and data views; query-derived and ML inputs are reported unsupported"
		statuses[CapabilityRemote] = CapabilityListedOnly
		details[CapabilityRemote] = "remote inputs are listed but not evaluated"
	case "opensearch":
		metadata.Product = "OpenSearch Security Analytics"
		metadata.SupportedVersionLines = append([]string(nil), backendVersionPolicies[name].maintainedLines...)
		for _, capability := range []string{
			CapabilityRuleInventory,
			CapabilitySourceResolution,
			CapabilityFreshness,
			CapabilityDocsStorage,
			CapabilitySchema,
		} {
			statuses[capability] = CapabilitySupported
		}
		for _, capability := range []string{
			CapabilityRequiredFields,
			CapabilityIngestLag,
			CapabilityCandidateParsing,
		} {
			statuses[capability] = CapabilityUnavailable
		}
		details[CapabilityRequiredFields] = "detector metadata does not expose required fields"
		details[CapabilityIngestLag] = "ingest lag is not measured by this backend"
		details[CapabilityCandidateParsing] = "candidate rule files are not parsed by this backend"
		statuses[CapabilityRemote] = CapabilityListedOnly
		details[CapabilityRemote] = "remote inputs are listed but not evaluated"
	case "demo":
		metadata.Product = "Embedded demo fixtures"
		metadata.SupportedVersionLines = []string{"fixture-v1"}
		for _, capability := range []string{
			CapabilityRuleInventory,
			CapabilityFreshness,
			CapabilityDocsStorage,
			CapabilitySchema,
			CapabilityRequiredFields,
			CapabilityIngestLag,
		} {
			statuses[capability] = CapabilitySupported
		}
		statuses[CapabilitySourceResolution] = CapabilitySupported
		details[CapabilitySourceResolution] = "deterministic embedded resolution evidence"
		statuses[CapabilityCandidateParsing] = CapabilityUnavailable
		statuses[CapabilityRemote] = CapabilityUnavailable
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
	}
}
