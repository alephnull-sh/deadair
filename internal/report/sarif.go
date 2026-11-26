package report

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/alephnull-sh/deadair/internal/securefile"
)

// SARIFSchemaURI is the canonical OASIS SARIF v2.1.0 JSON schema URI.
const SARIFSchemaURI = "https://json.schemastore.org/sarif-2.1.0.json"

// SARIFVersion is the SARIF specification version emitted by deadair.
const SARIFVersion = "2.1.0"

// SARIFOptions configures optional location mapping when rendering SARIF.
type SARIFOptions struct {
	// RuleLocations maps logical RuleID (or ID) to a workspace-relative
	// candidate rule path. Ignored automatically when Report.Redacted is true.
	RuleLocations map[string]string
	// DefaultURI is used for physicalLocation.artifactLocation.uri when a
	// finding does not map to a specific candidate rule file (GitHub Code
	// Scanning requires at least one physicalLocation per result).
	DefaultURI string
}

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string                     `json:"name"`
	Version        string                     `json:"version,omitempty"`
	InformationURI string                     `json:"informationUri"`
	Rules          []sarifReportingDescriptor `json:"rules"`
}

type sarifReportingDescriptor struct {
	ID               string              `json:"id"`
	Name             string              `json:"name"`
	ShortDescription sarifMessage        `json:"shortDescription"`
	FullDescription  *sarifMessage       `json:"fullDescription,omitempty"`
	DefaultConfig    *sarifConfiguration `json:"defaultConfiguration,omitempty"`
	Properties       map[string]any      `json:"properties,omitempty"`
}

type sarifConfiguration struct {
	Level string `json:"level"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string             `json:"ruleId"`
	Level               string             `json:"level"`
	Message             sarifMessage       `json:"message"`
	Locations           []sarifLocation    `json:"locations"`
	PartialFingerprints map[string]string  `json:"partialFingerprints,omitempty"`
	Suppressions        []sarifSuppression `json:"suppressions,omitempty"`
	Properties          map[string]any     `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation  `json:"physicalLocation"`
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations,omitempty"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

type sarifLogicalLocation struct {
	Name string `json:"name"`
	Kind string `json:"kind,omitempty"`
}

type sarifSuppression struct {
	Kind          string `json:"kind"`
	Status        string `json:"status,omitempty"`
	Justification string `json:"justification,omitempty"`
}

// SARIFBytes renders a single-instance Report as formatted SARIF v2.1.0 JSON.
func (r *Report) SARIFBytes(opts SARIFOptions) ([]byte, error) {
	if r == nil {
		return nil, fmt.Errorf("cannot render nil report as SARIF")
	}
	log := buildSARIFLog([]*Report{r}, r.Producer.Version, opts)
	data, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// WriteSARIF writes a single-instance Report as SARIF v2.1.0 JSON atomically (0600).
func (r *Report) WriteSARIF(path string) error {
	return r.WriteSARIFWithOptions(path, SARIFOptions{})
}

// WriteSARIFWithOptions writes a single-instance Report as SARIF v2.1.0 JSON with options.
func (r *Report) WriteSARIFWithOptions(path string, opts SARIFOptions) error {
	data, err := r.SARIFBytes(opts)
	if err != nil {
		return err
	}
	return securefile.Write(path, data)
}

// SARIFBytes renders a FleetReport across all succeeded instances as SARIF v2.1.0 JSON.
func (f *FleetReport) SARIFBytes(opts SARIFOptions) ([]byte, error) {
	if f == nil {
		return nil, fmt.Errorf("cannot render nil fleet report as SARIF")
	}
	log := buildSARIFLog(f.Instances, f.Producer.Version, opts)
	data, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// WriteSARIF writes a FleetReport as SARIF v2.1.0 JSON atomically (0600).
func (f *FleetReport) WriteSARIF(path string) error {
	return f.WriteSARIFWithOptions(path, SARIFOptions{})
}

// WriteSARIFWithOptions writes a FleetReport as SARIF v2.1.0 JSON with options.
func (f *FleetReport) WriteSARIFWithOptions(path string, opts SARIFOptions) error {
	data, err := f.SARIFBytes(opts)
	if err != nil {
		return err
	}
	return securefile.Write(path, data)
}

func buildSARIFLog(instances []*Report, version string, opts SARIFOptions) sarifLog {
	defaultURI := strings.TrimSpace(opts.DefaultURI)
	if defaultURI == "" {
		defaultURI = "deadair-report.json"
	}
	defaultURI = normalizeSARIFURI(defaultURI)

	descriptorsByID := make(map[string]sarifReportingDescriptor)
	results := make([]sarifResult, 0)

	multiInstance := len(instances) > 1
	for _, r := range instances {
		if r == nil {
			continue
		}
		if version == "" && r.Producer.Version != "" {
			version = r.Producer.Version
		}
		for _, finding := range r.Findings {
			ruleID := sarifRuleID(finding.Class, finding.Reason)
			if _, exists := descriptorsByID[ruleID]; !exists {
				descriptorsByID[ruleID] = buildSARIFDescriptor(ruleID, finding.Class, finding.Reason)
			}
			results = append(results, buildSARIFResult(r, finding, ruleID, defaultURI, multiInstance, opts))
		}
	}

	descriptorIDs := make([]string, 0, len(descriptorsByID))
	for id := range descriptorsByID {
		descriptorIDs = append(descriptorIDs, id)
	}
	sort.Strings(descriptorIDs)
	rules := make([]sarifReportingDescriptor, 0, len(descriptorIDs))
	for _, id := range descriptorIDs {
		rules = append(rules, descriptorsByID[id])
	}

	return sarifLog{
		Schema:  SARIFSchemaURI,
		Version: SARIFVersion,
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:           "deadair",
					Version:        version,
					InformationURI: "https://github.com/alephnull-sh/deadair",
					Rules:          rules,
				},
			},
			Results: results,
		}},
	}
}

func sarifRuleID(class, reason string) string {
	if reason == "" {
		return "deadair/" + class
	}
	return "deadair/" + class + "/" + reason
}

func sarifPascalName(class, reason string) string {
	parts := strings.FieldsFunc(class+"-"+reason, func(r rune) bool {
		return r == '-' || r == '_' || r == '/'
	})
	var b strings.Builder
	for _, p := range parts {
		if p == "" {
			continue
		}
		b.WriteString(strings.ToUpper(p[:1]))
		if len(p) > 1 {
			b.WriteString(strings.ToLower(p[1:]))
		}
	}
	if b.Len() == 0 {
		return "DeadairFinding"
	}
	return b.String()
}

func buildSARIFDescriptor(id, class, reason string) sarifReportingDescriptor {
	short := FindingClassLabel(class)
	if reason != "" {
		short = short + ": " + FindingReasonLabel(class, reason)
	}
	defaultLevel := "warning"
	switch class {
	case FindingDead:
		defaultLevel = "error"
	case FindingUnused, FindingSummaryPipeline:
		defaultLevel = "note"
	}
	return sarifReportingDescriptor{
		ID:               id,
		Name:             sarifPascalName(class, reason),
		ShortDescription: sarifMessage{Text: short},
		DefaultConfig:    &sarifConfiguration{Level: defaultLevel},
		Properties: map[string]any{
			"tags": []string{"security", "detection-engineering", "siem", class},
		},
	}
}

func buildSARIFResult(r *Report, f Finding, sarifRule, defaultURI string, includeInstance bool, opts SARIFOptions) sarifResult {
	acceptedActive := f.Accepted != nil && f.Accepted.Status == "active"
	level := sarifFindingLevel(f, acceptedActive)

	uri := defaultURI
	if !r.Redacted && len(opts.RuleLocations) > 0 && f.RuleID != "" {
		if candidatePath, ok := opts.RuleLocations[f.RuleID]; ok && strings.TrimSpace(candidatePath) != "" {
			uri = normalizeSARIFURI(candidatePath)
		}
	}

	var logical []sarifLogicalLocation
	if f.RuleName != "" {
		logical = append(logical, sarifLogicalLocation{Name: f.RuleName, Kind: "rule"})
	} else if f.RuleID != "" {
		logical = append(logical, sarifLogicalLocation{Name: f.RuleID, Kind: "rule"})
	}
	if f.Source != "" {
		logical = append(logical, sarifLogicalLocation{Name: f.Source, Kind: "source"})
	}
	if r.Instance != "" && includeInstance {
		logical = append(logical, sarifLogicalLocation{Name: r.Instance, Kind: "instance"})
	}

	var suppressions []sarifSuppression
	if acceptedActive {
		suppressions = append(suppressions, sarifSuppression{
			Kind:          "external",
			Status:        "accepted",
			Justification: f.Accepted.Reason,
		})
	} else if f.Suppressed {
		suppressions = append(suppressions, sarifSuppression{
			Kind:          "external",
			Status:        "accepted",
			Justification: "suppressed by expected downtime window",
		})
	}

	props := map[string]any{
		"backend": r.Backend,
		"class":   f.Class,
		"gates":   f.Gates,
	}
	if r.Instance != "" {
		props["instance"] = r.Instance
	}
	if f.Reason != "" {
		props["reason"] = f.Reason
	}
	if f.Severity != "" {
		props["ruleSeverity"] = f.Severity
	}
	if f.RuleID != "" {
		props["detectionRuleId"] = f.RuleID
	}
	if f.Source != "" {
		props["source"] = f.Source
	}
	if f.Dependency != "" {
		props["dependency"] = f.Dependency
	}

	return sarifResult{
		RuleID:  sarifRule,
		Level:   level,
		Message: sarifMessage{Text: sarifFindingMessage(r, f, includeInstance)},
		Locations: []sarifLocation{{
			PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: uri},
				Region:           &sarifRegion{StartLine: 1},
			},
			LogicalLocations: logical,
		}},
		PartialFingerprints: map[string]string{
			"deadairFindingId/v1": f.ID,
		},
		Suppressions: suppressions,
		Properties:   props,
	}
}

func sarifFindingLevel(f Finding, acceptedActive bool) string {
	if f.Suppressed || acceptedActive {
		return "note"
	}
	if !f.Gates {
		if f.Class == FindingImpaired || f.Class == FindingProducerStale {
			return "warning"
		}
		return "note"
	}
	if f.Class == FindingDead || f.Severity == "critical" || f.Severity == "high" {
		return "error"
	}
	return "warning"
}

func sarifFindingMessage(r *Report, f Finding, includeInstance bool) string {
	var parts []string
	if includeInstance && r.Instance != "" {
		parts = append(parts, "["+r.Instance+"]")
	}
	subject := f.RuleName
	if subject == "" {
		subject = f.RuleID
	}
	if subject == "" {
		subject = f.Source
	}
	if subject != "" {
		parts = append(parts, subject+":")
	}
	detail := FindingClassLabel(f.Class)
	if f.Reason != "" {
		detail += " (" + FindingReasonLabel(f.Class, f.Reason) + ")"
	}
	parts = append(parts, detail)
	var qualifiers []string
	if f.Source != "" && f.Source != subject {
		qualifiers = append(qualifiers, "source="+f.Source)
	}
	if f.Dependency != "" {
		qualifiers = append(qualifiers, "dependency="+f.Dependency)
	}
	if len(qualifiers) > 0 {
		parts = append(parts, "["+strings.Join(qualifiers, ", ")+"]")
	}
	return strings.Join(parts, " ")
}

func normalizeSARIFURI(p string) string {
	cleaned := filepath.ToSlash(filepath.Clean(p))
	cleaned = strings.TrimPrefix(cleaned, "./")
	// Prevent absolute or parent-traversal paths in SARIF artifact URIs.
	for strings.HasPrefix(cleaned, "../") {
		cleaned = strings.TrimPrefix(cleaned, "../")
	}
	cleaned = strings.TrimPrefix(cleaned, "/")
	if cleaned == "" || cleaned == "." {
		return "deadair-report.json"
	}
	return cleaned
}
