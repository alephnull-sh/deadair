package opensearch

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/alephnull-sh/deadair/internal/backend"
)

// detectorCandidate accepts the detector shapes exposed by the Security
// Analytics API: a create/update body, a get response, or a search hit.
type detectorCandidate struct {
	ID string `json:"_id"`
	detectorFields
	Detector *detectorFields `json:"detector"`
	Source   *detectorSource `json:"_source"`
}

func (d detectorCandidate) fields() detectorFields {
	if d.Source != nil {
		return d.Source.fields()
	}
	return (detectorSource{
		detectorFields: d.detectorFields,
		Detector:       d.Detector,
	}).fields()
}

// ParseCandidates implements backend.CandidateParser for OpenSearch Security
// Analytics detector request objects, get responses, and individual search
// hits. Candidate detectors are assessed as enabled without being installed.
func (c *Client) ParseCandidates(data []byte) ([]backend.Rule, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("detector file is empty")
	}

	var raw []json.RawMessage
	switch trimmed[0] {
	case '{':
		raw = []json.RawMessage{trimmed}
	case '[':
		if err := json.Unmarshal(trimmed, &raw); err != nil {
			return nil, fmt.Errorf("parsing detector array: %w", err)
		}
		if len(raw) == 0 {
			return nil, fmt.Errorf("detector array is empty")
		}
	default:
		return nil, fmt.Errorf("detector file must contain a JSON object or array")
	}

	rules := make([]backend.Rule, 0, len(raw))
	for i, item := range raw {
		rule, err := parseDetectorCandidate(item)
		if err != nil {
			if len(raw) == 1 {
				return nil, err
			}
			return nil, fmt.Errorf("parsing detector %d: %w", i+1, err)
		}
		rules = append(rules, rule)
	}
	if err := backend.ValidateRuleIDs(rules); err != nil {
		return nil, err
	}
	return rules, nil
}

func parseDetectorCandidate(data []byte) (backend.Rule, error) {
	var shape map[string]json.RawMessage
	if err := json.Unmarshal(data, &shape); err != nil {
		return backend.Rule{}, fmt.Errorf("parsing detector JSON: %w", err)
	}
	if shape == nil {
		return backend.Rule{}, fmt.Errorf("detector must be a JSON object")
	}
	if !recognizedDetectorShape(shape) {
		return backend.Rule{}, fmt.Errorf("JSON object is not a recognized Security Analytics detector")
	}

	var candidate detectorCandidate
	if err := json.Unmarshal(data, &candidate); err != nil {
		return backend.Rule{}, fmt.Errorf("parsing detector JSON: %w", err)
	}
	fields := candidate.fields()
	name := strings.TrimSpace(fields.Name)
	if name == "" {
		return backend.Rule{}, fmt.Errorf("detector name is required")
	}

	id := strings.TrimSpace(candidate.ID)
	if id == "" {
		id = strings.TrimSpace(fields.ID)
	}
	if id == "" {
		// Security Analytics requires detector names. Using it keeps a local
		// candidate stable without inventing a backend object identifier.
		id = name
	}

	severity := detectorSeverity(fields.Triggers)
	patterns := detectorPatterns(fields.Inputs)
	rule := backend.Rule{
		ID:        id,
		Name:      name,
		Enabled:   true,
		Severity:  severity,
		RiskScore: riskScore(severity),
		RuleType:  strings.TrimSpace(fields.DetectorType),
		Patterns:  patterns,
	}
	if len(patterns) == 0 {
		rule.InputStatus = backend.ResolutionUnsupported
		rule.InputDetail = "detector does not expose an index selector"
	}
	return rule, nil
}

func recognizedDetectorShape(shape map[string]json.RawMessage) bool {
	if _, ok := shape["detector"]; ok {
		return true
	}
	if _, ok := shape["_source"]; ok {
		return true
	}
	if _, ok := shape["detector_type"]; ok {
		return true
	}
	if _, ok := shape["inputs"]; ok {
		return true
	}
	// A create/update request is a direct detector object. Name alone is too
	// generic to identify that wire format, so require one detector-specific
	// field as well.
	if _, ok := shape["name"]; !ok {
		return false
	}
	for _, key := range []string{"enabled", "triggers", "schedule", "type"} {
		if _, ok := shape[key]; ok {
			return true
		}
	}
	return false
}

var _ backend.CandidateParser = (*Client)(nil)
