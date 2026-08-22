package sentinel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/alephnull-sh/deadair/internal/backend"
)

const summaryLogsAPIVersion = "2025-07-01"

const (
	summaryRuleRunWindow      = 7 * 24 * time.Hour
	summaryRuleRetryAllowance = 8 * time.Hour
	// ARM systemData can settle a few seconds after the first native timestamp
	// in LASummaryLogs. Later runs can advance RuleLastModifiedTime without an
	// ARM definition change, so the allowance applies only to older timestamps.
	summaryRuleTimestampTolerance = 30 * time.Second
	maxSummaryRuleRunRules        = 50
	maxSummaryRuleErrorRunes      = 512
	summaryRuleRunMethod          = "lasummarylogs-latest-7d"
	summaryRuleRunTable           = "LASummaryLogs"
)

type summaryLogsResponse struct {
	Value    []summaryLogJSON `json:"value"`
	NextLink string           `json:"nextLink"`
}

type summaryLogJSON struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	SystemData struct {
		LastModifiedAt string `json:"lastModifiedAt"`
	} `json:"systemData"`
	Properties struct {
		DisplayName       string `json:"displayName"`
		IsActive          *bool  `json:"isActive"`
		ProvisioningState string `json:"provisioningState"`
		StatusCode        string `json:"statusCode"`
		RuleDefinition    struct {
			Query            string `json:"query"`
			DestinationTable string `json:"destinationTable"`
			BinSize          int    `json:"binSize"`
			BinDelay         int    `json:"binDelay"` // minutes, as configured by Microsoft Sentinel
			BinStartTime     string `json:"binStartTime"`
			TimeSelector     string `json:"timeSelector"`
		} `json:"ruleDefinition"`
	} `json:"properties"`
}

type summaryRuleRunRow struct {
	RuleName            string
	RunAt               time.Time
	Status              string
	QueryDurationMillis int64
	ResultCount         int64
	RuleModifiedAt      time.Time
	Message             string
}

// SummaryRuleRunEvidence reads the latest bounded completed LASummaryLogs record for
// each summary rule whose output is consumed by an enabled detection. Native
// execution failures remain informational evidence and never create a finding.
func (c *Client) SummaryRuleRunEvidence(ctx context.Context, detections []backend.Rule) ([]backend.SummaryRuleRunEvidence, error) {
	consumedTables := enabledDetectionTables(detections)
	if len(consumedTables) == 0 {
		return nil, nil
	}
	observedAt := time.Now().UTC()
	inventory, err := c.listSummaryLogs(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return []backend.SummaryRuleRunEvidence{{
			ID:         "sentinel-summary-rule-runtime-inventory",
			Rule:       backend.DependencyRef{Kind: "sentinel_summary_rule_inventory"},
			Status:     backend.EvidenceUnavailable,
			Method:     "arm-summary-rule-list",
			ObservedAt: observedAt,
			Window:     summaryRuleRunWindow,
			Detail:     "summary-rule inventory could not be read for runtime evidence",
		}}, nil
	}

	relevant := consumedSummaryRules(inventory, consumedTables)
	if len(relevant) == 0 {
		return nil, nil
	}
	sortSummaryRules(relevant)

	// Match LASummaryLogs RuleName only to the exact ARM resource name. Build
	// uniqueness against the complete inventory so a filtered view cannot turn
	// an ambiguous native identity into an apparently conclusive observation.
	inventoryNames := make(map[string]int, len(inventory))
	for _, rule := range inventory {
		inventoryNames[strings.TrimSpace(rule.Name)]++
	}

	evidence := make([]backend.SummaryRuleRunEvidence, len(relevant))
	queried := make([]int, 0, min(len(relevant), maxSummaryRuleRunRules))
	for i, rule := range relevant {
		evidence[i] = c.baseSummaryRuleRunEvidence(rule, observedAt)
		switch {
		case rule.Properties.IsActive == nil:
			evidence[i].Status = backend.EvidenceIncomplete
			evidence[i].Detail = "summary rule active state is unavailable"
		case !*rule.Properties.IsActive:
			evidence[i].Status = backend.EvidenceDisabled
			evidence[i].Detail = "summary rule is inactive"
		case !strings.EqualFold(strings.TrimSpace(rule.Properties.ProvisioningState), "Succeeded"):
			state := strings.TrimSpace(rule.Properties.ProvisioningState)
			if state == "" {
				state = "unknown"
			}
			evidence[i].Status = backend.EvidenceIncomplete
			evidence[i].Detail = "summary rule provisioning state is " + state
		case strings.TrimSpace(rule.Properties.StatusCode) != "":
			evidence[i].Status = backend.EvidenceIncomplete
			evidence[i].Detail = "summary rule status is " + strings.TrimSpace(rule.Properties.StatusCode)
		case !validSummaryBinSize(rule.Properties.RuleDefinition.BinSize):
			evidence[i].Status = backend.EvidenceIncomplete
			evidence[i].Detail = fmt.Sprintf("summary rule bin size %dm is not supported", rule.Properties.RuleDefinition.BinSize)
		case rule.Properties.RuleDefinition.BinDelay < 0:
			evidence[i].Status = backend.EvidenceIncomplete
			evidence[i].Detail = "summary rule bin delay cannot be negative"
		case strings.TrimSpace(rule.Name) == "":
			evidence[i].Status = backend.EvidenceIncomplete
			evidence[i].Detail = "summary rule ARM name is missing"
		case inventoryNames[strings.TrimSpace(rule.Name)] != 1:
			evidence[i].Status = backend.EvidenceIncomplete
			evidence[i].Detail = "summary rule ARM name is not unique in the workspace inventory"
		case !validSummaryRuleModifiedAt(rule):
			evidence[i].Status = backend.EvidenceIncomplete
			evidence[i].Detail = "summary rule ARM modification time is missing or malformed"
		case len(queried) >= maxSummaryRuleRunRules:
			evidence[i].Status = backend.EvidenceIncomplete
			evidence[i].Detail = fmt.Sprintf("summary runtime query cap limited assessment to %d active rules", maxSummaryRuleRunRules)
		default:
			queried = append(queried, i)
		}
	}
	if len(queried) == 0 {
		return evidence, nil
	}

	names := make([]string, 0, len(queried))
	for _, index := range queried {
		names = append(names, strings.TrimSpace(relevant[index].Name))
	}
	table, err := c.queryLogs(ctx, summaryRuleRunsQuery(names), summaryRuleRunTable)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		status, detail := evidenceFailure(err)
		for _, index := range queried {
			evidence[index].Status = status
			evidence[index].Detail = detail
		}
		return evidence, nil
	}

	rows, malformed := parseSummaryRuleRunRows(table)
	if malformed != "" {
		for _, index := range queried {
			evidence[index].Status = backend.EvidenceIncomplete
			evidence[index].Detail = malformed
		}
		return evidence, nil
	}
	rowsByName := make(map[string][]summaryRuleRunRow, len(rows))
	for _, row := range rows {
		if inventoryNames[row.RuleName] == 1 {
			rowsByName[row.RuleName] = append(rowsByName[row.RuleName], row)
		}
	}
	for _, index := range queried {
		name := strings.TrimSpace(relevant[index].Name)
		matching := rowsByName[name]
		switch len(matching) {
		case 0:
			evidence[index].Status = backend.EvidenceIncomplete
			evidence[index].Detail = "no LASummaryLogs execution was observed in the bounded 7-day window"
		case 1:
			row := matching[0]
			armModifiedAt, ok := summaryRuleModifiedAt(relevant[index])
			if !ok || row.RunAt.Before(armModifiedAt) || row.RuleModifiedAt.After(row.RunAt) ||
				row.RuleModifiedAt.Add(summaryRuleTimestampTolerance).Before(armModifiedAt) {
				evidence[index].Status = backend.EvidenceIncomplete
				evidence[index].Detail = "latest LASummaryLogs execution could not be linked to the current ARM summary-rule definition"
				continue
			}
			evidence[index].Status = backend.EvidenceAssessed
			evidence[index].RunAt = row.RunAt
			evidence[index].RunStatus = row.Status
			evidence[index].QueryDurationMillis = row.QueryDurationMillis
			evidence[index].ResultCount = row.ResultCount
			evidence[index].RuleModifiedAt = row.RuleModifiedAt
			evidence[index].Error = normalizeSummaryRuleError(row.Message)
			evidence[index].Detail = "latest completed native summary-rule execution observed"
			if strings.EqualFold(row.Status, "Succeeded") && summaryRunIsOverdue(relevant[index], observedAt, row.RunAt) {
				evidence[index].Status = backend.EvidenceIncomplete
				evidence[index].Detail = "latest successful summary-rule execution is older than the configured schedule plus the documented 8-hour retry allowance"
			}
		default:
			evidence[index].Status = backend.EvidenceIncomplete
			evidence[index].Detail = "LASummaryLogs returned multiple latest rows for the exact summary rule name"
		}
	}
	return evidence, nil
}

func (c *Client) baseSummaryRuleRunEvidence(rule summaryLogJSON, observedAt time.Time) backend.SummaryRuleRunEvidence {
	return backend.SummaryRuleRunEvidence{
		ID: summaryRuleID(rule) + "#latest-run",
		Rule: backend.DependencyRef{
			ID:       summaryRuleID(rule),
			Name:     summaryRuleName(rule),
			Kind:     "sentinel_summary_rule",
			Scope:    c.workspaceResourcePath(),
			Required: true,
		},
		Output:     summaryOutput(c, rule),
		Method:     summaryRuleRunMethod,
		ObservedAt: observedAt,
		Window:     summaryRuleRunWindow,
	}
}

func sortSummaryRules(rules []summaryLogJSON) {
	sort.SliceStable(rules, func(i, j int) bool {
		left, right := strings.TrimSpace(rules[i].Name), strings.TrimSpace(rules[j].Name)
		if left != right {
			return left < right
		}
		return summaryRuleID(rules[i]) < summaryRuleID(rules[j])
	})
}

func summaryRuleRunsQuery(names []string) string {
	literals := make([]string, 0, len(names))
	for _, name := range names {
		literals = append(literals, kqlStringLiteral(name))
	}
	return summaryRuleRunTable + "\n" +
		"| where TimeGenerated between (ago(7d) .. now())\n" +
		"| where RuleName in (" + strings.Join(literals, ", ") + ")\n" +
		"| where Status in ('Succeeded', 'Failed')\n" +
		"| summarize arg_max(TimeGenerated, Status, QueryDurationMs, ResultsRecordCount, RuleLastModifiedTime, Message) by RuleName\n" +
		"| project RuleName, TimeGenerated, Status, QueryDurationMs, ResultsRecordCount, RuleLastModifiedTime, Message\n" +
		"| order by RuleName asc"
}

func validSummaryBinSize(minutes int) bool {
	switch minutes {
	case 20, 30, 60, 120, 180, 360, 720, 1440:
		return true
	default:
		return false
	}
}

func summaryRunIsOverdue(rule summaryLogJSON, observedAt, runAt time.Time) bool {
	definition := rule.Properties.RuleDefinition
	maximumAge := time.Duration(definition.BinSize)*time.Minute +
		time.Duration(definition.BinDelay)*time.Minute + summaryRuleRetryAllowance
	return observedAt.Sub(runAt) > maximumAge
}

func summaryRuleModifiedAt(rule summaryLogJSON) (time.Time, bool) {
	modifiedAt, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(rule.SystemData.LastModifiedAt))
	if err != nil || modifiedAt.IsZero() {
		return time.Time{}, false
	}
	return modifiedAt.UTC(), true
}

func validSummaryRuleModifiedAt(rule summaryLogJSON) bool {
	_, ok := summaryRuleModifiedAt(rule)
	return ok
}

func parseSummaryRuleRunRows(table logsTable) ([]summaryRuleRunRow, string) {
	required := []string{"RuleName", "TimeGenerated", "Status", "QueryDurationMs", "ResultsRecordCount", "RuleLastModifiedTime", "Message"}
	columns := make(map[string]int, len(table.Columns))
	for i, column := range table.Columns {
		if _, exists := columns[column.Name]; exists {
			return nil, "LASummaryLogs query returned duplicate column " + column.Name
		}
		columns[column.Name] = i
	}
	for _, name := range required {
		if _, ok := columns[name]; !ok {
			return nil, "LASummaryLogs query omitted required column " + name
		}
	}

	rows := make([]summaryRuleRunRow, 0, len(table.Rows))
	for rowIndex, values := range table.Rows {
		if len(values) != len(table.Columns) {
			return nil, fmt.Sprintf("LASummaryLogs query returned malformed row %d", rowIndex+1)
		}
		row, ok := parseSummaryRuleRunRow(values, columns)
		if !ok {
			return nil, fmt.Sprintf("LASummaryLogs query returned malformed row %d", rowIndex+1)
		}
		rows = append(rows, row)
	}
	return rows, ""
}

func parseSummaryRuleRunRow(values []json.RawMessage, columns map[string]int) (summaryRuleRunRow, bool) {
	var row summaryRuleRunRow
	if err := json.Unmarshal(values[columns["RuleName"]], &row.RuleName); err != nil || row.RuleName == "" {
		return summaryRuleRunRow{}, false
	}
	if parsed, ok := parseLogTime(values[columns["TimeGenerated"]]); ok {
		row.RunAt = parsed.UTC()
	} else {
		return summaryRuleRunRow{}, false
	}
	if err := json.Unmarshal(values[columns["Status"]], &row.Status); err != nil {
		return summaryRuleRunRow{}, false
	}
	row.Status = strings.TrimSpace(row.Status)
	if !summaryRunStatusKnown(row.Status) {
		return summaryRuleRunRow{}, false
	}
	if parsed, ok := parseSummaryRunInt(values[columns["QueryDurationMs"]]); ok && parsed >= 0 {
		row.QueryDurationMillis = parsed
	} else {
		return summaryRuleRunRow{}, false
	}
	if parsed, ok := parseSummaryRunInt(values[columns["ResultsRecordCount"]]); ok && parsed >= 0 {
		row.ResultCount = parsed
	} else {
		return summaryRuleRunRow{}, false
	}
	if parsed, ok := parseLogTime(values[columns["RuleLastModifiedTime"]]); ok {
		row.RuleModifiedAt = parsed.UTC()
	} else {
		return summaryRuleRunRow{}, false
	}
	message := values[columns["Message"]]
	if string(message) != "null" {
		if err := json.Unmarshal(message, &row.Message); err != nil {
			return summaryRuleRunRow{}, false
		}
	}
	return row, true
}

func parseSummaryRunInt(value json.RawMessage) (int64, bool) {
	var number json.Number
	if err := json.Unmarshal(value, &number); err != nil {
		return 0, false
	}
	parsed, err := strconv.ParseInt(number.String(), 10, 64)
	return parsed, err == nil
}

func summaryRunStatusKnown(status string) bool {
	return strings.EqualFold(status, "Succeeded") || strings.EqualFold(status, "Failed")
}

func normalizeSummaryRuleError(message string) string {
	normalized := strings.Join(strings.Fields(stripUnsafeSummaryRuleMessage(message)), " ")
	runes := []rune(normalized)
	if len(runes) <= maxSummaryRuleErrorRunes {
		return normalized
	}
	return string(runes[:maxSummaryRuleErrorRunes-3]) + "..."
}

func stripUnsafeSummaryRuleMessage(message string) string {
	runes := []rune(message)
	var clean strings.Builder
	clean.Grow(len(message))
	for i := 0; i < len(runes); {
		switch runes[i] {
		case '\x1b':
			i = consumeSummaryEscapeSequence(runes, i)
		case '\u009b': // C1 CSI
			i = consumeSummaryCSI(runes, i+1)
		case '\u0090', '\u0098', '\u009d', '\u009e', '\u009f': // C1 DCS, SOS, OSC, PM, APC
			i = consumeSummaryControlString(runes, i+1)
		default:
			r := runes[i]
			i++
			switch {
			case unicode.IsSpace(r):
				clean.WriteByte(' ')
			case unicode.IsControl(r), unicode.In(r, unicode.Cf):
				// Drop terminal controls and invisible format controls, including
				// bidi embeddings, overrides, isolates, and direction marks.
			default:
				clean.WriteRune(r)
			}
		}
	}
	return clean.String()
}

func consumeSummaryEscapeSequence(runes []rune, start int) int {
	if start+1 >= len(runes) {
		return len(runes)
	}
	switch runes[start+1] {
	case '[':
		return consumeSummaryCSI(runes, start+2)
	case 'P', 'X', ']', '^', '_':
		return consumeSummaryControlString(runes, start+2)
	default:
		// A two-byte escape sequence is terminal control even when it is
		// not one of the longer CSI or string forms.
		return start + 2
	}
}

func consumeSummaryCSI(runes []rune, start int) int {
	for i := start; i < len(runes); i++ {
		if runes[i] >= 0x40 && runes[i] <= 0x7e {
			return i + 1
		}
	}
	return len(runes)
}

func consumeSummaryControlString(runes []rune, start int) int {
	for i := start; i < len(runes); i++ {
		switch runes[i] {
		case '\a', '\u009c': // BEL and C1 ST
			return i + 1
		case '\x1b':
			if i+1 < len(runes) && runes[i+1] == '\\' {
				return i + 2
			}
		}
	}
	return len(runes)
}

// LineageEvidence inventories the structural data path through Log Analytics
// summary rules whose output is consumed by an enabled detection. It does not
// query raw Basic or Auxiliary tables and does not make any claim about the
// health of downstream detections.
func (c *Client) LineageEvidence(ctx context.Context, detections []backend.Rule) ([]backend.LineageEvidence, error) {
	consumedTables := enabledDetectionTables(detections)
	if len(consumedTables) == 0 {
		return nil, nil
	}
	observedAt := time.Now().UTC()
	rules, err := c.listSummaryLogs(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return []backend.LineageEvidence{unavailableSummaryInventory(observedAt)}, nil
	}
	rules = consumedSummaryRules(rules, consumedTables)
	if len(rules) == 0 {
		return nil, nil
	}
	catalog, err := c.tables(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return unavailableSummaryCatalog(c, rules, observedAt), nil
	}

	var evidence []backend.LineageEvidence
	for _, rule := range rules {
		resolution := ResolveKQLDependencies(rule.Properties.RuleDefinition.Query)
		inputs := summaryInputs(rule, resolution)
		for _, input := range inputs {
			status, detail := summaryLineageStatus(rule, input, resolution, catalog)
			evidence = append(evidence, backend.LineageEvidence{
				ID:         summaryLineageID(rule, input),
				Kind:       "sentinel_summary_rule",
				Name:       summaryRuleName(rule),
				Input:      input,
				Output:     summaryOutput(c, rule),
				Status:     status,
				Method:     "arm-summary-rule-kql",
				ObservedAt: observedAt,
				Detail:     detail,
			})
		}
	}
	sort.SliceStable(evidence, func(i, j int) bool {
		if evidence[i].ID != evidence[j].ID {
			return strings.ToLower(evidence[i].ID) < strings.ToLower(evidence[j].ID)
		}
		return strings.ToLower(evidence[i].Input.ID) < strings.ToLower(evidence[j].Input.ID)
	})
	return evidence, nil
}

func enabledDetectionTables(rules []backend.Rule) map[string]struct{} {
	tables := make(map[string]struct{})
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		for _, patterns := range [][]string{rule.Patterns, rule.OptionalPatterns} {
			for _, name := range patterns {
				name = strings.ToLower(strings.TrimSpace(name))
				if name != "" {
					tables[name] = struct{}{}
				}
			}
		}
	}
	return tables
}

func consumedSummaryRules(rules []summaryLogJSON, consumedTables map[string]struct{}) []summaryLogJSON {
	relevant := make([]summaryLogJSON, 0, len(rules))
	for _, rule := range rules {
		destination := strings.ToLower(strings.TrimSpace(rule.Properties.RuleDefinition.DestinationTable))
		if _, consumed := consumedTables[destination]; consumed {
			relevant = append(relevant, rule)
		}
	}
	return relevant
}

func unavailableSummaryInventory(observedAt time.Time) backend.LineageEvidence {
	return backend.LineageEvidence{
		ID:         "sentinel-summary-rule-inventory",
		Kind:       "sentinel_summary_rule_inventory",
		Input:      backend.DependencyRef{Kind: "unavailable_summary_input"},
		Output:     backend.DependencyRef{Kind: "unavailable_summary_output"},
		Status:     backend.EvidenceUnavailable,
		Method:     "arm-summary-rule-list",
		ObservedAt: observedAt,
		Detail:     "summary-rule inventory could not be read",
	}
}

func unavailableSummaryCatalog(c *Client, rules []summaryLogJSON, observedAt time.Time) []backend.LineageEvidence {
	var evidence []backend.LineageEvidence
	for _, rule := range rules {
		resolution := ResolveKQLDependencies(rule.Properties.RuleDefinition.Query)
		for _, input := range summaryInputs(rule, resolution) {
			evidence = append(evidence, backend.LineageEvidence{
				ID:         summaryLineageID(rule, input),
				Kind:       "sentinel_summary_rule",
				Name:       summaryRuleName(rule),
				Input:      input,
				Output:     summaryOutput(c, rule),
				Status:     backend.EvidenceUnavailable,
				Method:     "arm-summary-rule-kql",
				ObservedAt: observedAt,
				Detail:     "table catalog could not be read for summary-rule lineage",
			})
		}
	}
	sort.SliceStable(evidence, func(i, j int) bool {
		if evidence[i].ID != evidence[j].ID {
			return strings.ToLower(evidence[i].ID) < strings.ToLower(evidence[j].ID)
		}
		return strings.ToLower(evidence[i].Input.ID) < strings.ToLower(evidence[j].Input.ID)
	})
	return evidence
}

func (c *Client) listSummaryLogs(ctx context.Context) ([]summaryLogJSON, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.summaryLogsMu.Lock()
	defer c.summaryLogsMu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c.summaryLogsCached {
		return cloneSummaryLogs(c.summaryLogs), nil
	}

	target := c.armEndpoint() + c.workspaceResourcePath() +
		"/summaryLogs?api-version=" + url.QueryEscape(summaryLogsAPIVersion)
	seen := make(map[string]bool)
	var rules []summaryLogJSON
	for page := 0; ; page++ {
		if page >= maxRulePages {
			return nil, fmt.Errorf("listing Log Analytics summary rules: pagination exceeded %d pages", maxRulePages)
		}
		if seen[target] {
			return nil, fmt.Errorf("listing Log Analytics summary rules: pagination cycle detected")
		}
		seen[target] = true
		var response summaryLogsResponse
		if err := c.doARM(ctx, target, &response); err != nil {
			return nil, fmt.Errorf("listing Log Analytics summary rules: %w", err)
		}
		rules = append(rules, response.Value...)
		if strings.TrimSpace(response.NextLink) == "" {
			c.summaryLogs = cloneSummaryLogs(rules)
			c.summaryLogsCached = true
			return cloneSummaryLogs(c.summaryLogs), nil
		}
		next, err := c.nextARMPage(target, response.NextLink)
		if err != nil {
			return nil, fmt.Errorf("listing Log Analytics summary rules: %w", err)
		}
		target = next
	}
}

func cloneSummaryLogs(rules []summaryLogJSON) []summaryLogJSON {
	cloned := make([]summaryLogJSON, len(rules))
	copy(cloned, rules)
	for i := range cloned {
		if rules[i].Properties.IsActive != nil {
			active := *rules[i].Properties.IsActive
			cloned[i].Properties.IsActive = &active
		}
	}
	return cloned
}

func summaryInputs(rule summaryLogJSON, resolution KQLResolution) []backend.DependencyRef {
	inputs := make([]backend.DependencyRef, 0, len(resolution.Dependencies))
	for _, dependency := range resolution.Dependencies {
		kind := "kql_" + string(dependency.Kind)
		monitorable := false
		if dependency.Kind == KindTable {
			kind = "telemetry_table"
			monitorable = true
		}
		id := strings.TrimSpace(dependency.Name)
		if dependency.Scope != "" {
			id = dependency.Scope + ":" + id
		}
		inputs = append(inputs, backend.DependencyRef{
			ID:          id,
			Name:        strings.TrimSpace(dependency.Name),
			Kind:        kind,
			Scope:       strings.TrimSpace(dependency.Scope),
			Monitorable: monitorable,
			Required:    !dependency.Optional,
		})
	}
	if len(inputs) == 0 {
		inputs = append(inputs, backend.DependencyRef{
			ID:       summaryRuleID(rule) + "#unresolved-input",
			Kind:     "unresolved_kql_dependency",
			Required: true,
		})
	}
	return inputs
}

func summaryOutput(c *Client, rule summaryLogJSON) backend.DependencyRef {
	name := strings.TrimSpace(rule.Properties.RuleDefinition.DestinationTable)
	id := c.workspaceResourcePath() + "/tables/" + url.PathEscape(name)
	if name == "" {
		id = summaryRuleID(rule) + "#missing-destination"
	}
	return backend.DependencyRef{
		ID:          id,
		Name:        name,
		Kind:        "telemetry_table",
		Scope:       c.workspaceResourcePath(),
		Monitorable: true,
		Required:    true,
	}
}

func summaryRuleName(rule summaryLogJSON) string {
	if name := strings.TrimSpace(rule.Properties.DisplayName); name != "" {
		return name
	}
	return strings.TrimSpace(rule.Name)
}

func summaryRuleID(rule summaryLogJSON) string {
	if id := strings.TrimSpace(rule.ID); id != "" {
		return id
	}
	return strings.TrimSpace(rule.Name)
}

func summaryLineageID(rule summaryLogJSON, input backend.DependencyRef) string {
	key := input.Kind + ":" + input.ID
	return summaryRuleID(rule) + "#input=" + url.PathEscape(key)
}

func summaryLineageStatus(rule summaryLogJSON, input backend.DependencyRef, resolution KQLResolution, catalog map[string]tableInfo) (backend.EvidenceStatus, string) {
	if rule.Properties.IsActive == nil {
		return backend.EvidenceIncomplete, "summary rule active state is unavailable"
	}
	if !*rule.Properties.IsActive {
		return backend.EvidenceDisabled, "summary rule is inactive"
	}
	if state := strings.TrimSpace(rule.Properties.ProvisioningState); !strings.EqualFold(state, "Succeeded") {
		if state == "" {
			state = "unknown"
		}
		return backend.EvidenceIncomplete, "summary rule provisioning state is " + state
	}
	if code := strings.TrimSpace(rule.Properties.StatusCode); code != "" {
		return backend.EvidenceIncomplete, "summary rule status is " + code
	}
	if resolution.Status != backend.ResolutionResolved {
		return backend.EvidenceIncomplete, "summary rule KQL dependencies are " + string(resolution.Status)
	}
	destination := strings.TrimSpace(rule.Properties.RuleDefinition.DestinationTable)
	if destination == "" {
		return backend.EvidenceIncomplete, "summary rule destination table is missing"
	}
	output, ok := catalog[destination]
	if !ok {
		return backend.EvidenceIncomplete, "summary rule destination is absent from the table catalog"
	}
	if !strings.EqualFold(output.provisioning, "Succeeded") {
		state := output.provisioning
		if state == "" {
			state = "unknown"
		}
		return backend.EvidenceIncomplete, "summary destination provisioning state is " + state
	}
	if !strings.EqualFold(output.plan, "Analytics") {
		plan := output.plan
		if plan == "" {
			plan = "unknown"
		}
		return backend.EvidenceIncomplete, "summary destination table plan is " + plan
	}
	if input.Kind == "telemetry_table" && input.Scope == "" {
		source, ok := catalog[input.Name]
		if !ok {
			if input.Required {
				return backend.EvidenceIncomplete, "required summary input is absent from the table catalog"
			}
			return backend.EvidenceAssessed, "optional summary input is absent from the table catalog"
		}
		if !strings.EqualFold(source.provisioning, "Succeeded") {
			state := source.provisioning
			if state == "" {
				state = "unknown"
			}
			return backend.EvidenceIncomplete, "summary input provisioning state is " + state
		}
	}
	return backend.EvidenceAssessed, summaryScheduleDetail(rule)
}

func summaryScheduleDetail(rule summaryLogJSON) string {
	definition := rule.Properties.RuleDefinition
	parts := make([]string, 0, 2)
	if definition.BinSize > 0 {
		parts = append(parts, fmt.Sprintf("bin %dm", definition.BinSize))
	}
	if definition.BinDelay > 0 {
		parts = append(parts, fmt.Sprintf("delay %dm", definition.BinDelay))
	}
	return strings.Join(parts, "; ")
}
