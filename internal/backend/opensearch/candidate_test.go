package opensearch

import (
	"strings"
	"testing"

	"github.com/alephnull-sh/deadair/internal/backend"
)

func TestParseCandidatesDetectorAPIShapes(t *testing.T) {
	tests := []struct {
		name      string
		data      string
		wantID    string
		wantName  string
		wantType  string
		wantSev   string
		wantRisk  int
		wantInput []string
	}{
		{
			name: "create request",
			data: `{
				"name":"Windows candidate",
				"detector_type":"WINDOWS",
				"enabled":false,
				"inputs":[{"detector_input":{"indices":["winlogbeat-*","winlogbeat-*","logs-windows-*"]}}],
				"triggers":[{"severity":"2"}]
			}`,
			wantID:    "Windows candidate",
			wantName:  "Windows candidate",
			wantType:  "WINDOWS",
			wantSev:   "high",
			wantRisk:  73,
			wantInput: []string{"winlogbeat-*", "logs-windows-*"},
		},
		{
			name: "update request",
			data: `{
				"id":"logical-detector-id",
				"type":"detector",
				"name":"Audit candidate",
				"detector_type":"linux",
				"enabled":false,
				"inputs":[{"input":{"indices":["audit-*"]}}],
				"triggers":[{"sev_levels":["critical"]}]
			}`,
			wantID:    "logical-detector-id",
			wantName:  "Audit candidate",
			wantType:  "linux",
			wantSev:   "critical",
			wantRisk:  99,
			wantInput: []string{"audit-*"},
		},
		{
			name: "get response",
			data: `{
				"_id":"detector-object-id",
				"_version":1,
				"detector":{
					"name":"CloudTrail candidate",
					"detector_type":"cloudtrail",
					"enabled":false,
					"inputs":[{"detector_input":{"indices":["cloudtrail-*"]}}],
					"triggers":[{"severity":3}]
				}
			}`,
			wantID:    "detector-object-id",
			wantName:  "CloudTrail candidate",
			wantType:  "cloudtrail",
			wantSev:   "medium",
			wantRisk:  47,
			wantInput: []string{"cloudtrail-*"},
		},
		{
			name: "search hit",
			data: `{
				"_index":".opensearch-sap-detectors-config",
				"_id":"search-hit-id",
				"_source":{"detector":{
					"name":"DNS candidate",
					"detector_type":"dns",
					"enabled":false,
					"inputs":[{"detector_input":{"indices":["dns-*"]}}],
					"triggers":[{"sev_levels":[{"severity":"low"}]}]
				}}
			}`,
			wantID:    "search-hit-id",
			wantName:  "DNS candidate",
			wantType:  "dns",
			wantSev:   "low",
			wantRisk:  21,
			wantInput: []string{"dns-*"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, err := (&Client{}).ParseCandidates([]byte(tt.data))
			if err != nil {
				t.Fatal(err)
			}
			if len(rules) != 1 {
				t.Fatalf("rules = %d, want 1", len(rules))
			}
			got := rules[0]
			if got.ID != tt.wantID || got.Name != tt.wantName || got.RuleType != tt.wantType {
				t.Errorf("identity = %q/%q/%q, want %q/%q/%q", got.ID, got.Name, got.RuleType, tt.wantID, tt.wantName, tt.wantType)
			}
			if !got.Enabled {
				t.Error("candidate must be evaluated as enabled")
			}
			if got.Severity != tt.wantSev || got.RiskScore != tt.wantRisk {
				t.Errorf("severity = %q/%d, want %q/%d", got.Severity, got.RiskScore, tt.wantSev, tt.wantRisk)
			}
			if strings.Join(got.Patterns, ",") != strings.Join(tt.wantInput, ",") {
				t.Errorf("patterns = %v, want %v", got.Patterns, tt.wantInput)
			}
			if got.InputStatus != "" || got.InputDetail != "" {
				t.Errorf("input status = %q/%q, want supported selectors", got.InputStatus, got.InputDetail)
			}
		})
	}
}

func TestParseCandidatesArray(t *testing.T) {
	rules, err := (&Client{}).ParseCandidates([]byte(`[
		{"name":"First detector","detector_type":"linux","inputs":[{"detector_input":{"indices":["linux-*"]}}]},
		{"name":"Second detector","detector_type":"network","inputs":[{"input":{"indices":["network-*"]}}]}
	]`))
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 || rules[0].ID != "First detector" || rules[1].ID != "Second detector" {
		t.Fatalf("rules = %+v, want two name-keyed candidates", rules)
	}
}

func TestParseCandidatesRejectsDuplicateFallbackIDs(t *testing.T) {
	_, err := (&Client{}).ParseCandidates([]byte(`[
		{"name":"Duplicate detector","detector_type":"linux","inputs":[{"detector_input":{"indices":["linux-a-*"]}}]},
		{"name":"Duplicate detector","detector_type":"linux","inputs":[{"detector_input":{"indices":["linux-b-*"]}}]}
	]`))
	if err == nil || !strings.Contains(err.Error(), "duplicate rule ID") {
		t.Fatalf("duplicate candidate IDs error = %v", err)
	}
}

func TestParseCandidatesMissingSelectorIsUnsupported(t *testing.T) {
	rules, err := (&Client{}).ParseCandidates([]byte(`{
		"name":"Unmapped candidate",
		"detector_type":"windows",
		"enabled":false,
		"inputs":[{"detector_input":{"indices":["", "  "]}}]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(rules))
	}
	got := rules[0]
	if !got.Enabled || len(got.Patterns) != 0 || got.InputStatus != backend.ResolutionUnsupported {
		t.Fatalf("candidate = %+v, want enabled with unsupported input evidence", got)
	}
	if got.InputDetail != "detector does not expose an index selector" {
		t.Errorf("input detail = %q", got.InputDetail)
	}
}

func TestParseCandidatesRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name string
		data string
		want string
	}{
		{name: "empty", data: "  \n", want: "empty"},
		{name: "empty array", data: `[]`, want: "array is empty"},
		{name: "not json", data: `detector`, want: "JSON object or array"},
		{name: "malformed", data: `{"name":`, want: "parsing detector JSON"},
		{name: "generic object", data: `{"name":"not enough"}`, want: "not a recognized"},
		{name: "unknown object", data: `{"foo":"bar"}`, want: "not a recognized"},
		{name: "missing name", data: `{"detector_type":"windows","inputs":[]}`, want: "name is required"},
		{name: "get response missing name", data: `{"_id":"det-1","detector":{"detector_type":"windows"}}`, want: "name is required"},
		{name: "search hit missing name", data: `{"_id":"det-1","_source":{"detector_type":"windows"}}`, want: "name is required"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := (&Client{}).ParseCandidates([]byte(tt.data))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want substring %q", err, tt.want)
			}
		})
	}
}
