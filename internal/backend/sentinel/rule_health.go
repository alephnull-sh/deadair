package sentinel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/alephnull-sh/deadair/internal/backend"
)

const (
	sentinelHealthWindow        = 7 * 24 * time.Hour
	sentinelHealthRulesPerBatch = 100
	maxSentinelHealthBatches    = 2
	sentinelHealthMethod        = "sentinel_health_rule_execution_diagnostic"
	minScheduledRuleInterval    = 5 * time.Minute
	maxScheduledRuleInterval    = 14 * 24 * time.Hour
	scheduledRuleExecutionDelay = 5 * time.Minute
	nrtRuleInterval             = time.Minute
	nrtRuleExecutionDelay       = 2 * time.Minute
)

type ruleHealthTarget struct {
	ruleID     string
	resourceID string
	kind       string
	modifiedAt time.Time
	interval   time.Duration
}

type ruleHealthRow struct {
	resourceID string
	kind       string
	status     string
	runAt      time.Time
}

type ruleHealthObservation struct {
	status backend.ResolutionStatus
	detail string
}

type ruleHealthParseError struct{}

func (*ruleHealthParseError) Error() string {
	return "SentinelHealth query returned malformed evidence"
}

func sentinelHealthKind(ruleType string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(ruleType)) {
	case "scheduled":
		return "Scheduled", true
	case "nrt":
		return "NRT", true
	default:
		return "", false
	}
}

func installedRuleKey(resourceID, kind string) (string, bool) {
	resourceID = strings.TrimSpace(resourceID)
	if resourceID == "" || (kind != "Scheduled" && kind != "NRT") {
		return "", false
	}
	return resourceID + "\x00" + kind, true
}

func (c *Client) setInstalledRules(rules []backend.Rule) {
	installed := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		kind, ok := sentinelHealthKind(rule.RuleType)
		if !ok {
			continue
		}
		key, ok := installedRuleKey(rule.BackendObjectID, kind)
		if ok {
			installed[key] = struct{}{}
		}
	}
	c.installedRulesMu.Lock()
	if len(installed) == 0 {
		c.installedRules = nil
	} else {
		c.installedRules = installed
	}
	c.installedRulesMu.Unlock()
}

func (c *Client) isInstalledRule(rule backend.Rule, kind string) bool {
	key, ok := installedRuleKey(rule.BackendObjectID, kind)
	if !ok {
		return false
	}
	c.installedRulesMu.Lock()
	_, ok = c.installedRules[key]
	c.installedRulesMu.Unlock()
	return ok
}

// applyRuleHealthEvidence correlates only enabled installed Scheduled/NRT
// rules that already carry a cross-subscription execution-identity
// uncertainty. Candidate rules, same-subscription rules, and rules without an
// ARM object ID never cause a SentinelHealth query.
func (c *Client) applyRuleHealthEvidence(ctx context.Context, rules []backend.Rule, outcomesByRule map[string][]sentinelSelectorOutcome) {
	targets := make([]ruleHealthTarget, 0, len(rules))
	for _, rule := range rules {
		if !rule.Enabled || strings.TrimSpace(rule.BackendObjectID) == "" {
			continue
		}
		outcomes := outcomesByRule[rule.ID]
		uncertain := false
		for _, outcome := range outcomes {
			if ruleHealthResolvableIdentity(outcome) {
				uncertain = true
				break
			}
		}
		if !uncertain {
			continue
		}
		kind, ok := sentinelHealthKind(rule.RuleType)
		if !ok || !c.isInstalledRule(rule, kind) {
			continue
		}
		targets = append(targets, ruleHealthTarget{
			ruleID:     rule.ID,
			resourceID: strings.TrimSpace(rule.BackendObjectID),
			kind:       kind,
			modifiedAt: rule.ModifiedAt,
			interval:   rule.Interval,
		})
	}
	if len(targets) == 0 {
		return
	}

	sort.Slice(targets, func(i, j int) bool {
		if targets[i].resourceID != targets[j].resourceID {
			return targets[i].resourceID < targets[j].resourceID
		}
		if targets[i].kind != targets[j].kind {
			return targets[i].kind < targets[j].kind
		}
		return targets[i].ruleID < targets[j].ruleID
	})
	observations := c.readRuleHealthEvidence(ctx, targets)
	for ruleID, observation := range observations {
		outcomes := outcomesByRule[ruleID]
		for i := range outcomes {
			if !ruleHealthResolvableIdentity(outcomes[i]) {
				continue
			}
			outcomes[i].method = sentinelHealthMethod
			outcomes[i].status = observation.status
			outcomes[i].detail = observation.detail
		}
		outcomesByRule[ruleID] = outcomes
	}
}

func ruleHealthResolvableIdentity(outcome sentinelSelectorOutcome) bool {
	if outcome.selectorKind != "sentinel_rule_execution_identity" ||
		outcome.status != backend.ResolutionUnavailable || outcome.optional || len(outcome.dependencies) == 0 {
		return false
	}
	for _, dependency := range outcome.dependencies {
		if dependency.Kind != "sentinel_rule_execution_identity" || !dependency.Required {
			return false
		}
	}
	return true
}

func (c *Client) readRuleHealthEvidence(ctx context.Context, targets []ruleHealthTarget) map[string]ruleHealthObservation {
	observations := make(map[string]ruleHealthObservation, len(targets))
	eligible := make([]ruleHealthTarget, 0, len(targets))
	for _, target := range targets {
		if target.modifiedAt.IsZero() {
			observations[target.ruleID] = ruleHealthObservation{
				status: backend.ResolutionUnavailable,
				detail: "the current rule modification time is unavailable, so SentinelHealth execution evidence cannot resolve its execution identity",
			}
			continue
		}
		if _, ok := sentinelHealthMaximumAge(target); !ok {
			observations[target.ruleID] = ruleHealthObservation{
				status: backend.ResolutionUnavailable,
				detail: "the current rule execution cadence is missing or invalid, so SentinelHealth execution evidence cannot resolve its execution identity",
			}
			continue
		}
		eligible = append(eligible, target)
	}
	targets = eligible
	limit := sentinelHealthRulesPerBatch * maxSentinelHealthBatches
	for i, target := range targets {
		if i >= limit {
			observations[target.ruleID] = ruleHealthObservation{
				status: backend.ResolutionUnavailable,
				detail: "SentinelHealth correlation was not attempted because the bounded per-scan rule limit was reached",
			}
		}
	}
	if len(targets) > limit {
		targets = targets[:limit]
	}

	for start := 0; start < len(targets); start += sentinelHealthRulesPerBatch {
		end := start + sentinelHealthRulesPerBatch
		if end > len(targets) {
			end = len(targets)
		}
		batch := targets[start:end]
		table, err := c.queryLogs(ctx, sentinelHealthQuery(batch), "SentinelHealth")
		if err != nil {
			detail := sentinelHealthFailureDetail(err)
			for _, target := range batch {
				observations[target.ruleID] = ruleHealthObservation{status: backend.ResolutionUnavailable, detail: detail}
			}
			continue
		}
		rows, err := parseRuleHealthRows(table, batch)
		if err != nil {
			detail := sentinelHealthFailureDetail(err)
			for _, target := range batch {
				observations[target.ruleID] = ruleHealthObservation{status: backend.ResolutionUnavailable, detail: detail}
			}
			continue
		}
		observedAt := time.Now().UTC()
		for _, target := range batch {
			key, _ := installedRuleKey(target.resourceID, target.kind)
			row, found := rows[key]
			observations[target.ruleID] = classifyRuleHealthObservation(target, row, found, observedAt)
		}
	}
	return observations
}

// sentinelHealthMaximumAge ties execution evidence to the rule's configured
// cadence. Microsoft documents a five-minute scheduling delay for Scheduled
// rules and a two-minute delay for NRT rules; those delays are the only grace
// added here. Unknown or out-of-contract cadence values fail closed.
func sentinelHealthMaximumAge(target ruleHealthTarget) (time.Duration, bool) {
	switch target.kind {
	case "Scheduled":
		if target.interval < minScheduledRuleInterval || target.interval > maxScheduledRuleInterval {
			return 0, false
		}
		return target.interval + scheduledRuleExecutionDelay, true
	case "NRT":
		if target.interval != nrtRuleInterval {
			return 0, false
		}
		return target.interval + nrtRuleExecutionDelay, true
	default:
		return 0, false
	}
}

func classifyRuleHealthObservation(target ruleHealthTarget, row ruleHealthRow, found bool, observedAt time.Time) ruleHealthObservation {
	maximumAge, cadenceValid := sentinelHealthMaximumAge(target)
	switch {
	case !found:
		return ruleHealthObservation{
			status: backend.ResolutionUnavailable,
			detail: "no exact SentinelHealth execution was observed for this rule and kind in the bounded 7-day window",
		}
	case !cadenceValid:
		return ruleHealthObservation{
			status: backend.ResolutionUnavailable,
			detail: "the current rule execution cadence is missing or invalid, so SentinelHealth execution evidence cannot resolve its execution identity",
		}
	case row.runAt.After(observedAt):
		return ruleHealthObservation{
			status: backend.ResolutionUnavailable,
			detail: "the latest exact SentinelHealth execution has a future timestamp and cannot resolve execution identity",
		}
	case row.status != "Success":
		return ruleHealthObservation{
			status: backend.ResolutionUnavailable,
			detail: "the latest exact SentinelHealth execution for this rule and kind did not succeed",
		}
	case row.runAt.Before(target.modifiedAt):
		return ruleHealthObservation{
			status: backend.ResolutionUnavailable,
			detail: "the latest exact successful SentinelHealth execution predates the current rule revision",
		}
	case row.runAt.Before(observedAt.Add(-maximumAge)):
		return ruleHealthObservation{
			status: backend.ResolutionUnavailable,
			detail: "the latest exact successful SentinelHealth execution is older than the configured cadence plus the documented platform delay",
		}
	default:
		return ruleHealthObservation{
			status: backend.ResolutionResolved,
			detail: "the latest exact SentinelHealth execution for this rule and kind succeeded after the current revision and within its configured cadence",
		}
	}
}

func sentinelHealthQuery(targets []ruleHealthTarget) string {
	clauses := make([]string, 0, len(targets))
	for _, target := range targets {
		clauses = append(clauses, "(SentinelResourceId == "+kqlStringLiteral(target.resourceID)+
			" and SentinelResourceKind == "+kqlStringLiteral(target.kind)+")")
	}
	return "_SentinelHealth()\n" +
		"| where TimeGenerated between (ago(7d) .. now())\n" +
		"| where SentinelResourceType == \"Analytics Rule\"\n" +
		"| where " + strings.Join(clauses, " or ") + "\n" +
		"| summarize arg_max(TimeGenerated, Status) by SentinelResourceId, SentinelResourceKind\n" +
		"| project SentinelResourceId, SentinelResourceKind, Status, TimeGenerated"
}

func parseRuleHealthRows(table logsTable, targets []ruleHealthTarget) (map[string]ruleHealthRow, error) {
	if len(table.Columns) != 4 {
		return nil, &ruleHealthParseError{}
	}
	indexes := make(map[string]int, len(table.Columns))
	for i, column := range table.Columns {
		if _, duplicate := indexes[column.Name]; duplicate {
			return nil, &ruleHealthParseError{}
		}
		indexes[column.Name] = i
	}
	wantTypes := map[string]string{
		"SentinelResourceId":   "string",
		"SentinelResourceKind": "string",
		"Status":               "string",
		"TimeGenerated":        "datetime",
	}
	for name, wantType := range wantTypes {
		index, found := indexes[name]
		if !found || !strings.EqualFold(table.Columns[index].Type, wantType) {
			return nil, &ruleHealthParseError{}
		}
	}
	requested := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		key, _ := installedRuleKey(target.resourceID, target.kind)
		requested[key] = struct{}{}
	}
	rows := make(map[string]ruleHealthRow, len(table.Rows))
	for _, raw := range table.Rows {
		if len(raw) != len(table.Columns) {
			return nil, &ruleHealthParseError{}
		}
		resourceID, ok := parseRuleHealthString(raw[indexes["SentinelResourceId"]])
		if !ok {
			return nil, &ruleHealthParseError{}
		}
		kind, ok := parseRuleHealthString(raw[indexes["SentinelResourceKind"]])
		if !ok {
			return nil, &ruleHealthParseError{}
		}
		status, ok := parseRuleHealthString(raw[indexes["Status"]])
		if !ok {
			return nil, &ruleHealthParseError{}
		}
		runAt, ok := parseLogTime(raw[indexes["TimeGenerated"]])
		if !ok {
			return nil, &ruleHealthParseError{}
		}
		key, ok := installedRuleKey(resourceID, kind)
		if !ok {
			return nil, &ruleHealthParseError{}
		}
		if _, expected := requested[key]; !expected {
			return nil, &ruleHealthParseError{}
		}
		if _, duplicate := rows[key]; duplicate {
			return nil, &ruleHealthParseError{}
		}
		rows[key] = ruleHealthRow{resourceID: resourceID, kind: kind, status: status, runAt: runAt}
	}
	return rows, nil
}

func parseRuleHealthString(value json.RawMessage) (string, bool) {
	var text string
	if err := json.Unmarshal(value, &text); err != nil || text == "" {
		return "", false
	}
	return text, true
}

func sentinelHealthFailureDetail(err error) string {
	var parseErr *ruleHealthParseError
	if errors.As(err, &parseErr) {
		return parseErr.Error()
	}
	var statusErr *statusError
	if errors.As(err, &statusErr) && (statusErr.code == http.StatusUnauthorized || statusErr.code == http.StatusForbidden) {
		return "SentinelHealth execution evidence could not be read with the scanner identity"
	}
	var evidenceErr *logsEvidenceError
	if errors.As(err, &evidenceErr) {
		switch evidenceErr.detail {
		case "per-scan Logs query budget was exhausted":
			return "the per-scan Logs query budget was exhausted before SentinelHealth correlation"
		case "Log Analytics returned a partial or failed query result":
			return "Log Analytics returned a partial or failed SentinelHealth query result"
		default:
			return "SentinelHealth query permission evidence was unavailable"
		}
	}
	return fmt.Sprintf("SentinelHealth execution evidence could not be read within the bounded %d-day window", int(sentinelHealthWindow.Hours()/24))
}
