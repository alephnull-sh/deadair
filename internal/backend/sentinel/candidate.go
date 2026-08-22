package sentinel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/alephnull-sh/deadair/internal/backend"
	"gopkg.in/yaml.v3"
)

var armReferenceRE = regexp.MustCompile(`(?i)^\[\s*(parameters|variables)\(\s*'([^']+)'\s*\)\s*\]$`)

type candidateResolver struct {
	template   bool
	parameters map[string]any
	variables  map[string]any
	resolving  map[string]bool
}

// ParseCandidates parses a Sentinel rule without installing it. It accepts a
// direct Scheduled or NRT ARM body, a deployment-template JSON document, or
// one Azure-Sentinel analytic-rule YAML document.
func (c *Client) ParseCandidates(ctx context.Context, data []byte) ([]backend.Rule, error) {
	c.setRemoteReferences(nil)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, errors.New("Sentinel candidate file is empty")
	}

	// Parse and validate once before touching Azure. Typos, unsupported file
	// shapes, and duplicate identities must fail locally without asking for a
	// token or sending a request.
	rules, err := parseSentinelCandidateData(trimmed, nil, false)
	if err != nil {
		return nil, err
	}
	if err := validateSentinelCandidates(rules); err != nil {
		return nil, err
	}
	if !candidateNeedsFunctionMetadata(rules) {
		c.setRemoteReferences(rules)
		return rules, nil
	}

	functions, functionsAvailable := c.workspaceFunctions(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rules, err = parseSentinelCandidateData(trimmed, functions, functionsAvailable)
	if err != nil {
		return nil, err
	}
	if err := validateSentinelCandidates(rules); err != nil {
		return nil, err
	}
	c.setRemoteReferences(rules)
	return rules, nil
}

func parseSentinelCandidateData(trimmed []byte, functions map[string]WorkspaceFunction, functionsAvailable bool) ([]backend.Rule, error) {
	var rules []backend.Rule
	var err error
	if trimmed[0] == '{' || trimmed[0] == '[' {
		rules, err = parseSentinelCandidateJSON(trimmed, functions, functionsAvailable)
	} else {
		lower := strings.ToLower(string(trimmed))
		if strings.HasPrefix(lower, "param ") || strings.HasPrefix(lower, "resource ") ||
			strings.HasPrefix(lower, "targetscope ") || strings.HasPrefix(lower, "var ") {
			return nil, errors.New("raw Bicep is not supported; compile it to ARM JSON first")
		}
		rules, err = parseSentinelCandidateYAML(trimmed, functions, functionsAvailable)
	}
	if err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return nil, errors.New("Sentinel candidate file contains no alert rules")
	}
	return rules, nil
}

func validateSentinelCandidates(rules []backend.Rule) error {
	seen := make(map[string]bool, len(rules))
	for _, rule := range rules {
		key := strings.ToLower(strings.TrimSpace(rule.ID))
		if key == "" {
			return errors.New("Sentinel candidate has an empty identity")
		}
		if seen[key] {
			return fmt.Errorf("duplicate Sentinel candidate identity %q", rule.ID)
		}
		seen[key] = true
	}
	if err := backend.ValidateRuleIDs(rules); err != nil {
		return err
	}
	return nil
}

func candidateNeedsFunctionMetadata(rules []backend.Rule) bool {
	for _, rule := range rules {
		if rule.InputStatus == backend.ResolutionUnavailable && strings.Contains(rule.InputDetail, "query could not be resolved from static defaults") {
			continue
		}
		return true
	}
	return false
}

func parseSentinelCandidateJSON(data []byte, functions map[string]WorkspaceFunction, functionsAvailable bool) ([]backend.Rule, error) {
	value, err := decodeStrictJSON(data)
	if err != nil {
		return nil, fmt.Errorf("parsing Sentinel candidate JSON: %w", err)
	}
	root, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("Sentinel candidate JSON must contain an object")
	}
	if isARMTemplate(root) {
		return parseARMTemplate(root, functions, functionsAvailable)
	}
	if _, hasParameters := lookupMap(root, "parameters"); hasParameters {
		return nil, errors.New("ARM parameter-only documents are not Sentinel rule candidates")
	}
	if typeValue, hasType := lookupMap(root, "type"); hasType {
		typeName, resolved, _, err := (&candidateResolver{}).string(typeValue)
		if err != nil {
			return nil, fmt.Errorf("Sentinel candidate resource type: %w", err)
		}
		if !resolved {
			return nil, errors.New("Sentinel candidate resource type must be static")
		}
		normalized := normalizeResourceType(typeName)
		if isAlertRuleTemplateType(normalized) {
			return nil, errors.New("AlertRuleTemplate resources are templates, not installed rule candidates")
		}
		if !isAlertRuleType(normalized) {
			return nil, fmt.Errorf("unsupported Sentinel candidate resource type %q", typeName)
		}
	}
	rule, err := parseCandidateRule(root, &candidateResolver{}, "candidate", functions, functionsAvailable, false)
	if err != nil {
		return nil, err
	}
	return []backend.Rule{rule}, nil
}

func isARMTemplate(root map[string]any) bool {
	if _, ok := lookupMap(root, "$schema"); ok {
		return true
	}
	if _, ok := lookupMap(root, "resources"); ok {
		return true
	}
	if _, ok := lookupMap(root, "contentVersion"); ok {
		return true
	}
	if _, hasParameters := lookupMap(root, "parameters"); hasParameters {
		if _, hasVariables := lookupMap(root, "variables"); hasVariables {
			return true
		}
	}
	return false
}

func parseARMTemplate(root map[string]any, functions map[string]WorkspaceFunction, functionsAvailable bool) ([]backend.Rule, error) {
	resolver := &candidateResolver{
		template:   true,
		parameters: parameterDefaults(root),
		variables:  objectValue(root, "variables"),
		resolving:  make(map[string]bool),
	}
	resourcesValue, ok := lookupMap(root, "resources")
	if !ok {
		return nil, errors.New("ARM template contains no resources")
	}
	resources, ok := resourcesValue.([]any)
	if !ok {
		return nil, errors.New("ARM template resources must be an array")
	}
	if len(resources) == 0 {
		return nil, errors.New("ARM template contains no resources")
	}
	var rules []backend.Rule
	if err := walkARMResources(resources, "", resolver, functions, functionsAvailable, &rules); err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return nil, errors.New("ARM template contains no Sentinel alertRules resources")
	}
	return rules, nil
}

func walkARMResources(resources []any, parentType string, resolver *candidateResolver, functions map[string]WorkspaceFunction, functionsAvailable bool, out *[]backend.Rule) error {
	for i, value := range resources {
		resource, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("ARM resource %d must be an object", i+1)
		}
		typeValue, hasType := lookupMap(resource, "type")
		if !hasType {
			return fmt.Errorf("ARM resource %d has no type", i+1)
		}
		typeName, resolved, _, err := resolver.string(typeValue)
		if err != nil {
			return fmt.Errorf("ARM resource %d type: %w", i+1, err)
		}
		if !resolved || strings.TrimSpace(typeName) == "" {
			return fmt.Errorf("ARM resource %d type could not be resolved from static defaults", i+1)
		}
		fullType := joinResourceType(parentType, typeName)
		normalized := normalizeResourceType(fullType)
		if isAlertRuleTemplateType(normalized) {
			return errors.New("ARM template contains an AlertRuleTemplate resource, which is not an installed rule candidate")
		}
		if isAlertRuleType(normalized) {
			rule, err := parseCandidateRule(resource, resolver, fmt.Sprintf("ARM resource %d", i+1), functions, functionsAvailable, false)
			if err != nil {
				return err
			}
			*out = append(*out, rule)
		}
		if childrenValue, hasChildren := lookupMap(resource, "resources"); hasChildren {
			children, ok := childrenValue.([]any)
			if !ok {
				return fmt.Errorf("ARM resource %d nested resources must be an array", i+1)
			}
			if err := walkARMResources(children, fullType, resolver, functions, functionsAvailable, out); err != nil {
				return err
			}
		}
	}
	return nil
}

func joinResourceType(parent, child string) string {
	child = strings.TrimSpace(strings.SplitN(child, "@", 2)[0])
	if child == "" || parent == "" || strings.Contains(strings.SplitN(child, "/", 2)[0], ".") {
		return child
	}
	return strings.TrimSuffix(parent, "/") + "/" + strings.TrimPrefix(child, "/")
}

func normalizeResourceType(value string) string {
	return strings.ToLower(strings.Trim(strings.SplitN(strings.TrimSpace(value), "@", 2)[0], "/"))
}

func isAlertRuleType(value string) bool {
	switch value {
	case "microsoft.securityinsights/alertrules",
		"microsoft.operationalinsights/workspaces/providers/alertrules":
		return true
	default:
		return false
	}
}

func isAlertRuleTemplateType(value string) bool {
	return strings.HasSuffix(value, "/alertruletemplates")
}

func parameterDefaults(root map[string]any) map[string]any {
	out := make(map[string]any)
	for name, raw := range objectValue(root, "parameters") {
		definition, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if value, ok := lookupMap(definition, "defaultValue"); ok {
			out[name] = value
		}
	}
	return out
}

func (r *candidateResolver) string(value any) (string, bool, bool, error) {
	if value == nil {
		return "", false, false, nil
	}
	s, ok := value.(string)
	if !ok {
		return "", false, true, errors.New("value must be a string")
	}
	if !r.template {
		return strings.TrimSpace(s), true, true, nil
	}
	match := armReferenceRE.FindStringSubmatch(strings.TrimSpace(s))
	if match == nil {
		if strings.HasPrefix(strings.TrimSpace(s), "[") && strings.HasSuffix(strings.TrimSpace(s), "]") {
			return "", false, true, nil
		}
		return strings.TrimSpace(s), true, true, nil
	}
	kind, name := strings.ToLower(match[1]), match[2]
	resolutionKey := kind + ":" + strings.ToLower(name)
	if r.resolving[resolutionKey] {
		return "", false, true, nil
	}
	var resolved any
	var found bool
	if kind == "parameters" {
		resolved, found = lookupMap(r.parameters, name)
		if !found {
			return "", false, true, nil
		}
	} else {
		resolved, found = lookupMap(r.variables, name)
		if !found {
			return "", false, true, nil
		}
	}
	r.resolving[resolutionKey] = true
	valueString, valueResolved, present, err := r.string(resolved)
	delete(r.resolving, resolutionKey)
	return valueString, valueResolved, present, err
}

func parseCandidateRule(raw map[string]any, resolver *candidateResolver, location string, functions map[string]WorkspaceFunction, functionsAvailable, yamlTiming bool) (backend.Rule, error) {
	kind, resolved, present, err := resolver.stringValue(raw, "kind")
	if err != nil {
		return backend.Rule{}, fmt.Errorf("%s kind: %w", location, err)
	}
	if !present || !resolved || kind == "" {
		return backend.Rule{}, fmt.Errorf("%s kind is required and must be static", location)
	}
	if !strings.EqualFold(kind, "Scheduled") && !strings.EqualFold(kind, "NRT") {
		return backend.Rule{}, fmt.Errorf("%s has unsupported Sentinel rule kind %q", location, kind)
	}
	properties, ok := lookupMap(raw, "properties")
	if !ok {
		return backend.Rule{}, fmt.Errorf("%s properties are required", location)
	}
	props, ok := properties.(map[string]any)
	if !ok {
		return backend.Rule{}, fmt.Errorf("%s properties must be an object", location)
	}

	displayName, displayResolved, displayPresent, err := resolver.stringValue(props, "displayName")
	if err != nil {
		return backend.Rule{}, fmt.Errorf("%s properties.displayName: %w", location, err)
	}
	if !displayPresent {
		return backend.Rule{}, fmt.Errorf("%s properties.displayName is required", location)
	}
	query, queryResolved, queryPresent, err := resolver.stringValue(props, "query")
	if err != nil {
		return backend.Rule{}, fmt.Errorf("%s properties.query: %w", location, err)
	}
	if !queryPresent {
		return backend.Rule{}, fmt.Errorf("%s properties.query is required", location)
	}

	id := ""
	identityIssue := ""
	nameValue, namePresent := lookupMap(raw, "name")
	if resolver.template && !namePresent {
		return backend.Rule{}, fmt.Errorf("%s name is required", location)
	}
	if namePresent {
		value := nameValue
		name, resolved, _, err := resolver.string(value)
		if err != nil {
			return backend.Rule{}, fmt.Errorf("%s name: %w", location, err)
		}
		if resolved {
			if strings.TrimSpace(name) == "" {
				return backend.Rule{}, fmt.Errorf("%s has an empty identity", location)
			}
			id = resourceName(name)
		} else {
			identityIssue = "resource name could not be resolved from static defaults"
		}
	}
	backendObjectID := ""
	if value, ok := lookupMap(raw, "id"); ok {
		objectID, resolved, _, err := resolver.string(value)
		if err != nil {
			return backend.Rule{}, fmt.Errorf("%s id: %w", location, err)
		}
		if resolved {
			if strings.TrimSpace(objectID) == "" {
				return backend.Rule{}, fmt.Errorf("%s has an empty identity", location)
			}
			backendObjectID = objectID
			if id == "" {
				id = resourceName(objectID)
			}
		}
	}
	if id == "" && displayResolved {
		id = displayName
	}
	if strings.TrimSpace(id) == "" {
		return backend.Rule{}, fmt.Errorf("%s has an empty identity", location)
	}

	issues := make([]string, 0, 3)
	if identityIssue != "" {
		issues = append(issues, identityIssue)
	}
	if !displayResolved || displayName == "" {
		issues = append(issues, "display name could not be resolved from static defaults")
		displayName = id
	}
	if !queryResolved || query == "" {
		issues = append(issues, "query could not be resolved from static defaults")
	}

	var interval, lookback time.Duration
	if strings.EqualFold(kind, "NRT") {
		interval, lookback = time.Minute, time.Minute
	} else {
		frequency, frequencyResolved, frequencyPresent, frequencyErr := resolver.stringValue(props, "queryFrequency")
		period, periodResolved, periodPresent, periodErr := resolver.stringValue(props, "queryPeriod")
		if frequencyErr != nil {
			return backend.Rule{}, fmt.Errorf("%s queryFrequency: %w", location, frequencyErr)
		}
		if periodErr != nil {
			return backend.Rule{}, fmt.Errorf("%s queryPeriod: %w", location, periodErr)
		}
		if !frequencyPresent || !periodPresent {
			return backend.Rule{}, fmt.Errorf("%s Scheduled rule requires queryFrequency and queryPeriod", location)
		}
		if !frequencyResolved {
			issues = append(issues, "query frequency could not be resolved from static defaults")
		} else {
			var err error
			interval, err = parseCandidateDuration(frequency, yamlTiming)
			if err != nil {
				return backend.Rule{}, fmt.Errorf("%s queryFrequency: %w", location, err)
			}
		}
		if !periodResolved {
			issues = append(issues, "query period could not be resolved from static defaults")
		} else {
			var err error
			lookback, err = parseCandidateDuration(period, yamlTiming)
			if err != nil {
				return backend.Rule{}, fmt.Errorf("%s queryPeriod: %w", location, err)
			}
		}
	}

	severity, _, _, err := resolver.stringValue(props, "severity")
	if err != nil {
		return backend.Rule{}, fmt.Errorf("%s severity: %w", location, err)
	}
	severity = normalizeSeverity(severity)
	rule := backend.Rule{
		ID:                      id,
		BackendObjectID:         backendObjectID,
		Name:                    displayName,
		Enabled:                 true,
		Severity:                severity,
		RiskScore:               severityRiskScore(severity),
		RuleType:                strings.ToLower(kind),
		Lookback:                lookback,
		Interval:                interval,
		InputMetadataIncomplete: !functionsAvailable,
	}
	if strings.EqualFold(kind, "NRT") {
		rule.TimestampOverride = "ingestion_time()"
	}
	if len(issues) > 0 {
		rule.InputStatus = backend.ResolutionUnavailable
		rule.InputDetail = strings.Join(uniqueStrings(issues), "; ")
		return rule, nil
	}

	resolution := ResolveKQLDependencies(query)
	if functionsAvailable {
		resolution = ResolveKQLDependenciesWithFunctions(query, functions)
	} else if hasFunctionDependency(resolution.Dependencies) {
		resolution.Status = backend.ResolutionUnavailable
		resolution.Reason = "Log Analytics workspace function metadata could not be read"
	}
	if resolution.Status == backend.ResolutionEmpty {
		resolution.Status = backend.ResolutionUnsupported
		if resolution.Reason == "" {
			resolution.Reason = "KQL query did not expose a direct table dependency"
		}
	}
	applySentinelKQLResolution(&rule, resolution)
	if selector, ok := ExtractPredicateFreshness(query); ok {
		rule.PredicateFreshness = []backend.PredicateFreshnessSelector{selector}
	}
	return rule, nil
}

func parseCandidateDuration(value string, yamlTiming bool) (time.Duration, error) {
	if !yamlTiming || strings.HasPrefix(strings.ToUpper(strings.TrimSpace(value)), "P") {
		duration, err := parseISODuration(value)
		if err != nil || duration <= 0 {
			if err == nil {
				err = errors.New("duration must be greater than zero")
			}
			return 0, err
		}
		return duration, nil
	}
	duration := backend.ParseInterval(value)
	if duration <= 0 {
		return 0, fmt.Errorf("invalid KQL duration %q", value)
	}
	return duration, nil
}

func parseSentinelCandidateYAML(data []byte, functions map[string]WorkspaceFunction, functionsAvailable bool) ([]backend.Rule, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("parsing Sentinel analytic-rule YAML: %w", err)
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		if err != nil {
			return nil, fmt.Errorf("parsing Sentinel analytic-rule YAML: %w", err)
		}
		return nil, errors.New("Sentinel candidate YAML must contain exactly one document")
	}
	value, err := strictYAMLValue(&document)
	if err != nil {
		return nil, fmt.Errorf("parsing Sentinel analytic-rule YAML: %w", err)
	}
	root, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("Sentinel candidate YAML must contain one mapping, not a sequence")
	}
	if _, ok := lookupMap(root, "properties"); ok {
		return nil, errors.New("ARM rule bodies must be supplied as JSON")
	}

	props := make(map[string]any)
	for _, key := range []string{"name", "query", "severity", "queryFrequency", "queryPeriod"} {
		if value, ok := lookupMap(root, key); ok {
			propertyKey := key
			if key == "name" {
				propertyKey = "displayName"
			}
			props[propertyKey] = value
		}
	}
	wrapped := map[string]any{"properties": props}
	for _, key := range []string{"id", "kind"} {
		if value, ok := lookupMap(root, key); ok {
			wrapped[key] = value
		}
	}
	if _, hasID := lookupMap(wrapped, "id"); !hasID {
		return nil, errors.New("Sentinel analytic-rule YAML id is required")
	}
	rule, err := parseCandidateRule(wrapped, &candidateResolver{}, "Sentinel analytic-rule YAML", functions, functionsAvailable, true)
	if err != nil {
		return nil, err
	}
	return []backend.Rule{rule}, nil
}

func (r *candidateResolver) stringValue(object map[string]any, key string) (string, bool, bool, error) {
	value, ok := lookupMap(object, key)
	if !ok {
		return "", false, false, nil
	}
	return r.string(value)
}

func lookupMap(object map[string]any, key string) (any, bool) {
	for candidate, value := range object {
		if strings.EqualFold(candidate, key) {
			return value, true
		}
	}
	return nil, false
}

func objectValue(object map[string]any, key string) map[string]any {
	value, ok := lookupMap(object, key)
	if !ok {
		return nil
	}
	result, _ := value.(map[string]any)
	return result
}

func decodeStrictJSON(data []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	value, err := decodeJSONValue(decoder)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return nil, errors.New("JSON contains multiple top-level values")
		}
		return nil, err
	}
	return value, nil
}

func decodeJSONValue(decoder *json.Decoder) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delim, isDelim := token.(json.Delim)
	if !isDelim {
		return token, nil
	}
	switch delim {
	case '{':
		object := make(map[string]any)
		seenKeys := make(map[string]bool)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, errors.New("JSON object key is not a string")
			}
			if seenKeys[strings.ToLower(key)] {
				return nil, fmt.Errorf("duplicate JSON key %q", key)
			}
			seenKeys[strings.ToLower(key)] = true
			value, err := decodeJSONValue(decoder)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
			return nil, errors.New("unterminated JSON object")
		}
		return object, nil
	case '[':
		var array []any
		for decoder.More() {
			value, err := decodeJSONValue(decoder)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		if token, err := decoder.Token(); err != nil || token != json.Delim(']') {
			return nil, errors.New("unterminated JSON array")
		}
		return array, nil
	default:
		return nil, fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
}

func strictYAMLValue(node *yaml.Node) (any, error) {
	if node == nil {
		return nil, errors.New("empty YAML document")
	}
	if node.Kind == yaml.DocumentNode {
		if len(node.Content) != 1 {
			return nil, errors.New("empty YAML document")
		}
		return strictYAMLValue(node.Content[0])
	}
	switch node.Kind {
	case yaml.MappingNode:
		object := make(map[string]any, len(node.Content)/2)
		seenKeys := make(map[string]bool, len(node.Content)/2)
		for i := 0; i < len(node.Content); i += 2 {
			keyNode := node.Content[i]
			if keyNode.Kind != yaml.ScalarNode || keyNode.Tag != "!!str" {
				return nil, errors.New("YAML mapping keys must be strings")
			}
			if seenKeys[strings.ToLower(keyNode.Value)] {
				return nil, fmt.Errorf("duplicate YAML key %q", keyNode.Value)
			}
			seenKeys[strings.ToLower(keyNode.Value)] = true
			value, err := strictYAMLValue(node.Content[i+1])
			if err != nil {
				return nil, err
			}
			object[keyNode.Value] = value
		}
		return object, nil
	case yaml.SequenceNode:
		array := make([]any, len(node.Content))
		for i, child := range node.Content {
			value, err := strictYAMLValue(child)
			if err != nil {
				return nil, err
			}
			array[i] = value
		}
		return array, nil
	case yaml.ScalarNode:
		var value any
		if err := node.Decode(&value); err != nil {
			return nil, err
		}
		return value, nil
	case yaml.AliasNode:
		return nil, errors.New("YAML aliases are not supported in candidate rules")
	default:
		return nil, errors.New("unsupported YAML node")
	}
}

var _ backend.CandidateParser = (*Client)(nil)
