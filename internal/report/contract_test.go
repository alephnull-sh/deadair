package report

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/alephnull-sh/deadair/internal/backend"
	"github.com/alephnull-sh/deadair/internal/graph"
)

func TestBuildInitializesReportContract(t *testing.T) {
	tests := []struct {
		backend        string
		product        string
		observed       string
		supportedLines []string
		statuses       []CapabilityStatus
	}{
		{
			backend:        "elastic",
			product:        "Elastic Security",
			observed:       "observed-1",
			supportedLines: []string{"8.x", "9.x"},
			statuses: []CapabilityStatus{
				CapabilitySupported, CapabilityPartial, CapabilitySupported,
				CapabilitySupported, CapabilitySupported, CapabilitySupported,
				CapabilitySupported, CapabilitySupported, CapabilityListedOnly,
				CapabilityUnavailable, CapabilityUnavailable, CapabilityUnavailable, CapabilityUnavailable,
			},
		},
		{
			backend:        "opensearch",
			product:        "OpenSearch Security Analytics",
			observed:       "observed-1",
			supportedLines: []string{"2.x", "3.x"},
			statuses: []CapabilityStatus{
				CapabilitySupported, CapabilitySupported, CapabilitySupported,
				CapabilitySupported, CapabilitySupported, CapabilityUnavailable,
				CapabilityUnavailable, CapabilitySupported, CapabilityListedOnly,
				CapabilityUnavailable, CapabilityUnavailable, CapabilityUnavailable, CapabilityUnavailable,
			},
		},
		{
			backend:        "sentinel",
			product:        "Microsoft Sentinel",
			observed:       "",
			supportedLines: []string{},
			statuses: []CapabilityStatus{
				CapabilitySupported, CapabilityPartial, CapabilityPartial,
				CapabilityUnavailable, CapabilityPartial, CapabilityUnavailable,
				CapabilityPartial, CapabilitySupported, CapabilityPartial,
				CapabilityPartial, CapabilityPartial, CapabilityPartial, CapabilityPartial,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.backend, func(t *testing.T) {
			r := BuildWithOptions(tt.backend, emptyGraph(), BuildOptions{
				ProducerVersion:        "1.2.3",
				BackendObservedVersion: "observed-1",
			})
			if r.SchemaVersion != ReportSchemaVersion {
				t.Fatalf("schema version = %q, want %q", r.SchemaVersion, ReportSchemaVersion)
			}
			if r.Producer != (Producer{Name: "deadair", Version: "1.2.3"}) {
				t.Fatalf("producer = %+v", r.Producer)
			}
			if r.Backend != tt.backend {
				t.Fatalf("backend compatibility field = %q, want %q", r.Backend, tt.backend)
			}
			metadata := r.BackendMetadata
			if metadata.Name != tt.backend || metadata.Product != tt.product || metadata.ObservedVersion != tt.observed {
				t.Fatalf("backend metadata = %+v", metadata)
			}
			if !reflect.DeepEqual(metadata.SupportedVersionLines, tt.supportedLines) {
				t.Fatalf("supported version lines = %v, want %v", metadata.SupportedVersionLines, tt.supportedLines)
			}
			if len(metadata.Capabilities) != len(tt.statuses) {
				t.Fatalf("capabilities = %d, want %d", len(metadata.Capabilities), len(tt.statuses))
			}
			for i, name := range capabilityOrder() {
				got := metadata.Capabilities[i]
				if got.Name != name || got.Status != tt.statuses[i] {
					t.Errorf("capability %d = %+v, want %s=%s", i, got, name, tt.statuses[i])
				}
			}
		})
	}

	r := BuildWithOptions("elastic", emptyGraph(), BuildOptions{})
	if r.Producer.Version != DefaultProducerVersion {
		t.Fatalf("default producer version = %q, want %q", r.Producer.Version, DefaultProducerVersion)
	}
	if r.BackendMetadata.ObservedVersion != "" {
		t.Fatalf("default observed backend version = %q, want omitted", r.BackendMetadata.ObservedVersion)
	}
}

func TestSentinelCapabilityDetailsDescribeAssessmentBoundaries(t *testing.T) {
	metadata := MetadataForBackend("sentinel", "api-version-is-not-a-product-version")
	if metadata.ObservedVersion != "" || len(metadata.SupportedVersionLines) != 0 {
		t.Fatalf("Sentinel SaaS metadata exposes product versions: %+v", metadata)
	}

	details := make(map[string]Capability, len(metadata.Capabilities))
	for _, capability := range metadata.Capabilities {
		details[capability.Name] = capability
	}
	checks := map[string][]string{
		CapabilityRuleInventory:        {"Scheduled", "2025-09-01", "NRT", "2025-10-01-preview", "non-query rule kinds"},
		CapabilitySourceResolution:     {"direct local tables", "union/join/lookup", "tabular let aliases", "closed scalar arguments", "metadata-backed ASIM", "positive table and permission evidence", "mapped literal workspace()", "dynamic table names"},
		CapabilityFreshness:            {"resolved local or explicitly mapped remote Analytics tables", "informational rule-source freshness", "one parser-proved local Analytics table", "closed literal predicate"},
		CapabilityDocsStorage:          {"does not expose", "document inventory"},
		CapabilitySchema:               {"resolved local or explicitly mapped remote Analytics tables"},
		CapabilityRequiredFields:       {"not authoritative"},
		CapabilityIngestLag:            {"TimeGenerated", "ingestion_time()", "mapped remote", "incomplete"},
		CapabilityCandidateParsing:     {"Scheduled", "NRT", "ARM deployment JSON", "Azure-Sentinel", "without installation"},
		CapabilityRemote:               {"mapped literal workspace()", "Sentinel-onboarded", "unmapped or dynamic", "app()", "resource()", "unassessed"},
		CapabilityDependencyResolution: {"literal _GetWatchlist()", "native ASIM", "permission evidence", "informational", "concrete monitorable tables", "source-health edges"},
		CapabilityCrossWorkspace:       {"configured literal workspace()", "onboardingStates/default", "scoped Logs evidence", "textual aliases", "original-literal Logs proof", "canonical counting", "GUID and ARM-ID mappings", "20 workspaces per analytics-rule query", "conservatively counts the home workspace", "19 distinct remotes per rule", "20 or more distinct normalized workspace regions", "after any alias proof", "ordinary dependency and freshness probes", "missing workspace location", "warning at five regions", "guidance", "same-subscription mapped source evidence is conclusive", "eligible installed rule that references another subscription", "exact successful SentinelHealth", "latest rule change", "expected run cadence plus scheduling delay", "candidate", "absent", "stale", "ambiguous", "mismatched", "non-successful", "creator's credentials", "tenant boundaries are not separately identified", "Azure Lighthouse", "cross-tenant topology", "not live-validated", "compatible", "unavailable"},
		CapabilitySourceLineage:        {"ARM-only structural lineage", "summary-rule", "Analytics output table", "separate from bounded schedule-aware latest-completed-run LASummaryLogs evidence", "invalid runtime configuration", "overdue successes", "incomplete", "informational", "native runtime failures", "findings or gates"},
		CapabilityRuleProvenance:       {"informational exact-ID joins", "Content Hub", "display names", "guess provenance"},
	}
	wantPartial := map[string]bool{
		CapabilitySourceResolution: true, CapabilityFreshness: true, CapabilitySchema: true,
		CapabilityIngestLag: true, CapabilityRemote: true, CapabilityDependencyResolution: true,
		CapabilityCrossWorkspace: true, CapabilitySourceLineage: true, CapabilityRuleProvenance: true,
	}
	for name, fragments := range checks {
		capability, ok := details[name]
		if !ok {
			t.Fatalf("Sentinel capability %q is missing", name)
		}
		if wantPartial[name] && capability.Status != CapabilityPartial {
			t.Errorf("Sentinel %s status = %q, want %q", name, capability.Status, CapabilityPartial)
		}
		for _, fragment := range fragments {
			if !strings.Contains(capability.Detail, fragment) {
				t.Errorf("Sentinel %s detail %q does not contain %q", name, capability.Detail, fragment)
			}
		}
	}
}

func TestAssessBackendVersion(t *testing.T) {
	tests := []struct {
		backend string
		version string
		want    BackendVersionStatus
	}{
		{"elastic", "9.4.4", BackendVersionTested},
		{"elastic", "8.19.19", BackendVersionTested},
		{"elastic", "8.19.99", BackendVersionBestEffort},
		{"elastic", "7.17.0", BackendVersionUnsupported},
		{"opensearch", "3.7.0", BackendVersionTested},
		{"opensearch", "2.19.6", BackendVersionTested},
		{"opensearch", "2.20.0", BackendVersionBestEffort},
		{"opensearch", "future", BackendVersionUnsupported},
		{"unknown", "1.0.0", BackendVersionUnsupported},
	}
	for _, tt := range tests {
		t.Run(tt.backend+"-"+tt.version, func(t *testing.T) {
			got := AssessBackendVersion(tt.backend, tt.version)
			if got.Status != tt.want || got.Detail == "" {
				t.Fatalf("assessment = %+v, want %s with detail", got, tt.want)
			}
		})
	}
}

func TestRedactionPreservesContractMetadata(t *testing.T) {
	r := BuildWithOptions("elastic", emptyGraph(), BuildOptions{
		ProducerVersion:        "1.2.3",
		BackendObservedVersion: "8.17.4",
	})
	wantSchema, wantProducer, wantBackend, wantMetadata := r.SchemaVersion, r.Producer, r.Backend, r.BackendMetadata
	r.Redact()
	if r.SchemaVersion != wantSchema || r.Producer != wantProducer || r.Backend != wantBackend || !reflect.DeepEqual(r.BackendMetadata, wantMetadata) {
		t.Fatalf("redaction changed contract metadata: %+v", r)
	}
}

func TestReportContractSchemas(t *testing.T) {
	reportSchema := loadContractSchema(t, "report-v1.schema.json")
	fleetSchema := loadContractSchema(t, "fleet-report-v1.schema.json")
	registry := map[string]map[string]any{
		"report-v1.schema.json":       reportSchema,
		"fleet-report-v1.schema.json": fleetSchema,
	}

	assertSchemaHeader(t, reportSchema,
		"https://alephnull-sh.github.io/deadair/schemas/report-v1.schema.json",
		[]string{"schema_version", "generated_at", "producer", "backend", "backend_metadata", "summary", "sources", "dead_detections", "unused_telemetry"})
	assertSchemaHeader(t, fleetSchema,
		"https://alephnull-sh.github.io/deadair/schemas/fleet-report-v1.schema.json",
		[]string{"schema_version", "generated_at", "producer", "summary", "instances"})

	defs := objectAt(t, reportSchema, "$defs")
	metadata := objectAt(t, objectAt(t, defs, "backendMetadata"), "properties")
	capability := objectAt(t, defs, "capability")
	summary := objectAt(t, defs, "summary")
	assertRequired(t, objectAt(t, defs, "producer"), "name", "version")
	assertRequired(t, objectAt(t, defs, "backendMetadata"), "name", "product", "supported_version_lines", "capabilities")
	assertRequired(t, capability, "name", "status")
	if _, ok := metadata["observed_version"]; !ok {
		t.Fatal("backend metadata schema is missing optional observed_version")
	}
	status := objectAt(t, objectAt(t, capability, "properties"), "status")
	if got, want := stringsAt(t, status, "enum"), []string{"supported", "partial", "unavailable", "listed-only"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("capability status enum = %v, want %v", got, want)
	}
	capabilityNames := stringsAt(t, objectAt(t, objectAt(t, capability, "properties"), "name"), "enum")
	for _, name := range []string{CapabilityDependencyResolution, CapabilityCrossWorkspace, CapabilitySourceLineage, CapabilityRuleProvenance} {
		if !containsString(capabilityNames, name) {
			t.Fatalf("capability name enum = %v, want %s", capabilityNames, name)
		}
	}
	evidenceStatus := objectAt(t, defs, "evidenceStatus")
	if got, want := stringsAt(t, evidenceStatus, "enum"), []string{"assessed", "disabled", "incomplete", "unavailable"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("runtime evidence status enum = %v, want %v", got, want)
	}
	assertRequired(t, objectAt(t, defs, "runtimeAssessment"), "name", "status")
	runtimeAssessmentProperties := objectAt(t, objectAt(t, defs, "runtimeAssessment"), "properties")
	runtimeAssessmentNames := stringsAt(t, objectAt(t, runtimeAssessmentProperties, "name"), "enum")
	for _, name := range []string{
		AssessmentSourceResolution,
		AssessmentSourceFreshness,
		AssessmentPredicateFreshness,
		AssessmentRequiredFields,
		AssessmentIngestLag,
		AssessmentSchemaDrift,
		AssessmentCandidateParsing,
	} {
		if !containsString(runtimeAssessmentNames, name) {
			t.Fatalf("runtime assessment name enum = %v, want %s", runtimeAssessmentNames, name)
		}
	}
	assertRequired(t, objectAt(t, defs, "ingestLagHealth"), "status")
	assertRequired(t, objectAt(t, defs, "requiredFieldAssessment"), "rule_id", "rule_name", "sources")
	assertRequired(t, summary, "input_resolution", "unused_telemetry_assessment")
	if _, ok := objectAt(t, summary, "properties")["partial_inputs"]; !ok {
		t.Fatal("report summary schema is missing partial_inputs")
	}
	inputResolution := objectAt(t, defs, "inputResolution")
	if _, ok := objectAt(t, inputResolution, "properties")["diagnostic"]; !ok {
		t.Fatal("input resolution schema is missing diagnostic marker")
	}
	for _, field := range []string{"logical_rule_id", "backend_object_id"} {
		if _, ok := objectAt(t, inputResolution, "properties")[field]; !ok {
			t.Fatalf("input resolution schema is missing %s", field)
		}
	}
	for _, field := range []string{"resolved_dependencies"} {
		if _, ok := objectAt(t, inputResolution, "properties")[field]; !ok {
			t.Fatalf("input resolution schema is missing %s", field)
		}
	}
	for _, field := range []string{"dependency_evidence", "rule_provenance", "source_lineage", "rule_source_freshness", "summary_rule_runs"} {
		if _, ok := objectAt(t, reportSchema, "properties")[field]; !ok {
			t.Fatalf("report schema is missing %s", field)
		}
		if containsString(stringsAt(t, reportSchema, "required"), field) {
			t.Fatalf("additive report field %s must remain optional", field)
		}
	}
	for _, definition := range []string{"dependencyRef", "provenanceRef", "dependencyEvidence", "ruleProvenance", "sourceLineage", "ruleSourceFreshness", "summaryRuleRun"} {
		if _, ok := defs[definition]; !ok {
			t.Fatalf("report schema is missing %s definition", definition)
		}
	}
	assertRequired(t, objectAt(t, defs, "ruleSourceFreshness"), "rule_id", "source", "status", "observed_at", "freshness_status")
	assertRequired(t, objectAt(t, defs, "summaryRuleRun"), "rule", "output", "status", "method", "observed_at")
	inputSummary := objectAt(t, defs, "inputResolutionSummary")
	if _, ok := objectAt(t, inputSummary, "properties")["incompatible"]; !ok {
		t.Fatal("input resolution summary schema is missing incompatible")
	}
	if containsString(stringsAt(t, inputSummary, "required"), "incompatible") {
		t.Fatal("the additive incompatible count must not make older v1 reports invalid")
	}
	resolutionStatuses := stringsAt(t, objectAt(t, objectAt(t, inputResolution, "properties"), "status"), "enum")
	if !containsString(resolutionStatuses, string(backend.ResolutionIncompatible)) {
		t.Fatalf("input resolution status enum = %v, want incompatible", resolutionStatuses)
	}
	impaired := objectAt(t, defs, "impairedDetection")
	if _, ok := objectAt(t, impaired, "properties")["incompatible_sources"]; !ok {
		t.Fatal("impaired detection schema is missing incompatible_sources")
	}
	deadProperties := objectAt(t, objectAt(t, defs, "deadDetection"), "properties")
	deadReasons := stringsAt(t, objectAt(t, deadProperties, "reason"), "enum")
	if !containsString(deadReasons, ReasonSourcePlanIncompatible) {
		t.Fatalf("dead reason enum = %v, want %s", deadReasons, ReasonSourcePlanIncompatible)
	}
	impairedProperties := objectAt(t, impaired, "properties")
	impairedReasonItems := objectAt(t, objectAt(t, impairedProperties, "reasons"), "items")
	impairedReasons := stringsAt(t, impairedReasonItems, "enum")
	if !containsString(impairedReasons, ReasonSourcePlanIncompatible) {
		t.Fatalf("impaired reason enum = %v, want %s", impairedReasons, ReasonSourcePlanIncompatible)
	}
	if _, ok := objectAt(t, objectAt(t, defs, "sourceHealth"), "properties")["age_lower_bound"]; !ok {
		t.Fatal("source health schema is missing age_lower_bound")
	}
	assertRequired(t, objectAt(t, defs, "partialInputCoverage"), "rule_id", "rule_name", "severity", "expression", "observed_at")
	unusedAssessment := objectAt(t, objectAt(t, summary, "properties"), "unused_telemetry_assessment")
	if got, want := stringsAt(t, unusedAssessment, "enum"), []string{"complete", "legacy", "unavailable", "not-applicable"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("unused telemetry assessment enum = %v, want %v", got, want)
	}
	fleetSummary := objectAt(t, objectAt(t, fleetSchema, "$defs"), "fleetSummary")
	assertRequired(t, fleetSummary, "unused_telemetry_assessment")
	fleetUnusedAssessment := objectAt(t, objectAt(t, fleetSummary, "properties"), "unused_telemetry_assessment")
	if got, want := stringsAt(t, fleetUnusedAssessment, "enum"), []string{"complete", "legacy", "unavailable", "not-applicable"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("fleet unused telemetry assessment enum = %v, want %v", got, want)
	}

	r := fixtureReport(t)
	r.Producer = producer("1.2.3")
	r.BackendMetadata = backendMetadata("elastic", "8.17.4")
	r.Sources[0].Volume = &VolumeHealth{Status: "low", RatePerHour: 1.5}
	r.Sources[0].Schema = &SchemaHealth{
		Status:      "drift",
		FieldCount:  1,
		Added:       []string{"new.field"},
		Removed:     []string{"old.field"},
		TypeChanged: []FieldTypeChange{{Name: "typed.field", Before: []string{"keyword"}, After: []string{"long"}}},
	}
	r.ImpairedDetections = []ImpairedDetection{{
		ID: "impaired", Name: "Impaired", Severity: "medium",
		Reasons: []string{ReasonMissingFields}, MissingFields: []string{"missing.field"},
	}}
	r.UnmappedRules = []RuleRef{{ID: "unmapped", Name: "Unmapped", Severity: "low"}}
	r.RemoteRules = []RuleRef{{ID: "remote", Name: "Remote", Severity: "low"}}
	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	lastEvent := now.Add(-time.Minute)
	runAt := now.Add(-time.Minute)
	r.RuleSourceFreshness = []RuleSourceFreshness{{
		RuleID: "rule", Source: "SecurityEvent", Fields: []string{"EventID"},
		Status: backend.EvidenceAssessed, Method: "sentinel-predicate-max", ObservedAt: now,
		WindowSeconds: 86400, LastEvent: &lastEvent, FreshnessStatus: "ok", AgeSeconds: 60,
	}}
	r.SummaryRuleRuns = []SummaryRuleRun{{
		ID: "summary-run", Rule: backend.DependencyRef{ID: "summary-rule", Kind: "sentinel_summary_rule"},
		Output: backend.DependencyRef{ID: "Summary_CL", Kind: "telemetry_table", Monitorable: true},
		Status: backend.EvidenceAssessed, Method: "lasummarylogs-latest-7d", ObservedAt: now,
		WindowSeconds: 604800, RunAt: &runAt, RunStatus: "Succeeded",
	}}
	reportValue := marshalContractValue(t, r)
	reportValue.(map[string]any)["future_field"] = true
	objectAt(t, reportValue.(map[string]any), "backend_metadata")["future_metadata"] = "allowed"
	if err := validateContract(reportSchema, reportSchema, registry, reportValue, "report"); err != nil {
		t.Fatal(err)
	}

	r.Instance = "tenant-a"
	f := BuildFleet([]*Report{r}, []InstanceError{{Instance: "tenant-b", Error: "unreachable"}})
	fleetValue := marshalContractValue(t, f)
	fleetValue.(map[string]any)["future_field"] = true
	if err := validateContract(fleetSchema, fleetSchema, registry, fleetValue, "fleet report"); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{
		filepath.Join("..", "..", "docs", "examples", "sample-report.json"),
	} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var golden any
		if err := json.Unmarshal(data, &golden); err != nil {
			t.Fatalf("parsing golden report %s: %v", path, err)
		}
		if err := validateContract(reportSchema, reportSchema, registry, golden, path); err != nil {
			t.Fatalf("golden report contract: %v", err)
		}
	}
}

func emptyGraph() *graph.Graph {
	return graph.Build(nil, nil)
}

func loadContractSchema(t *testing.T, name string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "schemas", name))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatalf("parsing %s: %v", name, err)
	}
	return schema
}

func assertSchemaHeader(t *testing.T, schema map[string]any, id string, required []string) {
	t.Helper()
	if schema["$id"] != id {
		t.Fatalf("schema $id = %v, want %q", schema["$id"], id)
	}
	if schema["additionalProperties"] != true {
		t.Fatal("schema must allow additive properties")
	}
	assertRequired(t, schema, required...)
}

func assertRequired(t *testing.T, schema map[string]any, names ...string) {
	t.Helper()
	got := stringsAt(t, schema, "required")
	for _, name := range names {
		if !containsString(got, name) {
			t.Errorf("required fields %v do not contain %q", got, name)
		}
	}
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func objectAt(t *testing.T, value map[string]any, key string) map[string]any {
	t.Helper()
	got, ok := value[key].(map[string]any)
	if !ok {
		t.Fatalf("%q is %T, want object", key, value[key])
	}
	return got
}

func stringsAt(t *testing.T, value map[string]any, key string) []string {
	t.Helper()
	items, ok := value[key].([]any)
	if !ok {
		t.Fatalf("%q is %T, want array", key, value[key])
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		s, ok := item.(string)
		if !ok {
			t.Fatalf("%q item is %T, want string", key, item)
		}
		out = append(out, s)
	}
	return out
}

func marshalContractValue(t *testing.T, value any) any {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// validateContract implements only the draft-2020-12 structural keywords
// used by the checked-in schemas. Keeping this test stdlib-only avoids making
// report production depend on a JSON Schema library.
func validateContract(schema, root map[string]any, registry map[string]map[string]any, value any, path string) error {
	if ref, ok := schema["$ref"].(string); ok {
		resolved, resolvedRoot, err := resolveContractRef(ref, root, registry)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		return validateContract(resolved, resolvedRoot, registry, value, path)
	}
	if expected, ok := schema["const"]; ok && !reflect.DeepEqual(expected, value) {
		return fmt.Errorf("%s: value %v does not equal const %v", path, value, expected)
	}
	if values, ok := schema["enum"].([]any); ok {
		matched := false
		for _, allowed := range values {
			matched = matched || reflect.DeepEqual(allowed, value)
		}
		if !matched {
			return fmt.Errorf("%s: value %v is not in enum %v", path, value, values)
		}
	}
	if expected, ok := schema["type"]; ok && !contractTypeMatches(expected, value) {
		return fmt.Errorf("%s: value has type %T, want %v", path, value, expected)
	}

	if object, ok := value.(map[string]any); ok {
		if required, ok := schema["required"].([]any); ok {
			for _, item := range required {
				name := item.(string)
				if _, exists := object[name]; !exists {
					return fmt.Errorf("%s: missing required field %q", path, name)
				}
			}
		}
		if properties, ok := schema["properties"].(map[string]any); ok {
			for name, childValue := range object {
				childSchema, exists := properties[name].(map[string]any)
				if !exists {
					continue
				}
				if err := validateContract(childSchema, root, registry, childValue, path+"."+name); err != nil {
					return err
				}
			}
		}
	}
	if array, ok := value.([]any); ok {
		if itemSchema, ok := schema["items"].(map[string]any); ok {
			for i, item := range array {
				if err := validateContract(itemSchema, root, registry, item, fmt.Sprintf("%s[%d]", path, i)); err != nil {
					return err
				}
			}
		}
	}
	if schema["format"] == "date-time" {
		if s, ok := value.(string); ok {
			if _, err := time.Parse(time.RFC3339Nano, s); err != nil {
				return fmt.Errorf("%s: invalid date-time %q: %w", path, s, err)
			}
		}
	}
	return nil
}

func contractTypeMatches(expected any, value any) bool {
	types := []any{expected}
	if many, ok := expected.([]any); ok {
		types = many
	}
	for _, item := range types {
		name, _ := item.(string)
		switch name {
		case "null":
			if value == nil {
				return true
			}
		case "object":
			if _, ok := value.(map[string]any); ok {
				return true
			}
		case "array":
			if _, ok := value.([]any); ok {
				return true
			}
		case "string":
			if _, ok := value.(string); ok {
				return true
			}
		case "boolean":
			if _, ok := value.(bool); ok {
				return true
			}
		case "number":
			if _, ok := value.(float64); ok {
				return true
			}
		case "integer":
			if n, ok := value.(float64); ok && n == math.Trunc(n) {
				return true
			}
		}
	}
	return false
}

func resolveContractRef(ref string, root map[string]any, registry map[string]map[string]any) (map[string]any, map[string]any, error) {
	name, fragment, _ := strings.Cut(ref, "#")
	targetRoot := root
	if name != "" {
		var ok bool
		targetRoot, ok = registry[name]
		if !ok {
			return nil, nil, fmt.Errorf("unknown schema reference %q", name)
		}
	}
	var current any = targetRoot
	if fragment != "" {
		if !strings.HasPrefix(fragment, "/") {
			return nil, nil, fmt.Errorf("unsupported schema fragment %q", fragment)
		}
		for _, token := range strings.Split(strings.TrimPrefix(fragment, "/"), "/") {
			token = strings.ReplaceAll(strings.ReplaceAll(token, "~1", "/"), "~0", "~")
			object, ok := current.(map[string]any)
			if !ok {
				return nil, nil, fmt.Errorf("reference %q traverses non-object", ref)
			}
			current, ok = object[token]
			if !ok {
				return nil, nil, fmt.Errorf("reference %q does not exist", ref)
			}
		}
	}
	resolved, ok := current.(map[string]any)
	if !ok {
		return nil, nil, fmt.Errorf("reference %q is not a schema object", ref)
	}
	return resolved, targetRoot, nil
}
