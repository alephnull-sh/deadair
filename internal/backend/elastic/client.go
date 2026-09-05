// Package elastic implements the read-only backend for Elastic Security.
// It talks to two APIs: Kibana (detection rule inventory via the Detections
// API) and Elasticsearch (source stats and bounded evidence reads). Every call
// is read-only. Cheap stats APIs are preferred where they answer the question;
// targeted field and lag checks stay scoped to sources used by eligible rules.
package elastic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/alephnull-sh/deadair/internal/backend"
)

const defaultConcurrency = 4

// Client is a read-only client for one Elastic Security deployment.
type Client struct {
	ESURL     string
	KibanaURL string
	APIKey    string // optional; unauthenticated dev clusters are allowed
	HTTP      *http.Client
	// Concurrency bounds parallel native-resolution and per-source requests so
	// a scan stays SIEM-safe by default.
	Concurrency int
	// Space scopes Kibana API calls to a non-default Kibana space; rules
	// living outside the configured space are otherwise invisible.
	Space string
}

const (
	ingestLagWindow  = 24 * time.Hour
	ingestLagSamples = 500
)

func (c *Client) Name() string { return "elastic" }

// kibanaPath prefixes Kibana API paths with the space route when a
// non-default space is configured.
func (c *Client) kibanaPath(p string) string {
	if c.Space != "" && c.Space != "default" {
		return "/s/" + url.PathEscape(c.Space) + p
	}
	return p
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 60 * time.Second}
}

func (c *Client) concurrency() int {
	if c.Concurrency > 0 {
		return c.Concurrency
	}
	return defaultConcurrency
}

type statusError struct {
	method string
	path   string
	code   int
	status string
	body   string
}

func (e *statusError) Error() string {
	if e.body == "" {
		return fmt.Sprintf("%s %s: %s", e.method, e.path, e.status)
	}
	return fmt.Sprintf("%s %s: %s: %s", e.method, e.path, e.status, e.body)
}

func isStatus(err error, code int) bool {
	var se *statusError
	return errors.As(err, &se) && se.code == code
}

func (c *Client) do(ctx context.Context, method, base, path string, body io.Reader, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(base, "/")+path, body)
	if err != nil {
		return err
	}
	if c.APIKey != "" {
		req.Header.Set("Authorization", "ApiKey "+c.APIKey)
	}
	req.Header.Set("kbn-xsrf", "deadair")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return &statusError{
			method: method,
			path:   path,
			code:   resp.StatusCode,
			status: resp.Status,
			body:   strings.TrimSpace(string(msg)),
		}
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

type findResponse struct {
	Page    int        `json:"page"`
	PerPage int        `json:"perPage"`
	Total   int        `json:"total"`
	Data    []ruleJSON `json:"data"`
}

// ruleJSON is the wire shape shared by the Detections API and exported rule
// files (which makes it the parser for `scan --rule` candidates too).
type ruleJSON struct {
	ID             string   `json:"id"`
	RuleID         string   `json:"rule_id"`
	Name           string   `json:"name"`
	Enabled        bool     `json:"enabled"`
	Severity       string   `json:"severity"`
	RiskScore      int      `json:"risk_score"`
	Type           string   `json:"type"`
	Query          string   `json:"query"`
	Index          []string `json:"index"`
	DataViewID     string   `json:"data_view_id"`
	From           string   `json:"from"`
	Interval       string   `json:"interval"`
	RequiredFields []struct {
		Name string `json:"name"`
	} `json:"required_fields"`
	TimestampOverride string `json:"timestamp_override"`
}

func (d ruleJSON) toRule() backend.Rule {
	r := backend.Rule{
		ID:              d.RuleID,
		BackendObjectID: d.ID,
		Name:            d.Name,
		Enabled:         d.Enabled,
		Severity:        strings.ToLower(d.Severity),
		RiskScore:       d.RiskScore,
		RuleType:        d.Type,
		DataViewID:      d.DataViewID,
		Patterns:        d.Index,
		Lookback:        backend.ParseLookback(d.From),
		Interval:        backend.ParseInterval(d.Interval),

		TimestampOverride: d.TimestampOverride,
	}
	if r.ID == "" {
		r.ID = d.ID
	}
	isESQL := strings.EqualFold(d.Type, "esql")
	hasExplicitSource := len(d.Index) > 0 || d.DataViewID != ""
	if isESQL && hasExplicitSource {
		r.InputStatus = backend.ResolutionAmbiguous
		r.InputDetail = "ES|QL input cannot be inferred safely when explicit index or data view metadata is also present"
	} else if len(d.Index) > 0 && d.DataViewID != "" {
		r.InputStatus = backend.ResolutionAmbiguous
		r.InputDetail = "rule defines both explicit index selectors and a data view"
	} else if isESQL {
		patterns, err := esqlSourcePatterns(d.Query)
		if err != nil {
			r.InputStatus = backend.ResolutionUnsupported
			r.InputDetail = fmt.Sprintf("ES|QL source expression is unsupported: %v", err)
		} else {
			r.Patterns = patterns
		}
	} else if len(d.Index) == 0 && d.DataViewID == "" {
		r.InputStatus = backend.ResolutionUnsupported
		if d.Type == "" {
			r.InputDetail = "rule does not expose an index selector"
		} else {
			r.InputDetail = fmt.Sprintf("%s rule does not expose a supported index selector", d.Type)
		}
	}
	if strings.EqualFold(d.Type, "threat_match") {
		r.InputStatus = backend.ResolutionUnsupported
		r.InputDetail = "indicator-match rules require threat-index evidence that is not assessed"
	}
	for _, f := range d.RequiredFields {
		if f.Name != "" {
			r.RequiredFields = append(r.RequiredFields, f.Name)
		}
	}
	return r
}

// ParseRuleFile parses candidate rules for `scan --rule`: a single rule JSON
// object, a JSON array, or ndjson export lines. Candidates are evaluated as
// enabled regardless of the enabled flag in the file.
func ParseRuleFile(data []byte) ([]backend.Rule, error) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, fmt.Errorf("rule file is empty")
	}
	type entry struct {
		raw      json.RawMessage
		location string
	}
	var entries []entry
	if strings.HasPrefix(trimmed, "[") {
		var raw []json.RawMessage
		if err := json.Unmarshal([]byte(trimmed), &raw); err != nil {
			return nil, fmt.Errorf("parsing rule array: %w", err)
		}
		for i, object := range raw {
			entries = append(entries, entry{raw: object, location: fmt.Sprintf("array element %d", i+1)})
		}
	} else {
		parsedSingle := false
		if strings.HasPrefix(trimmed, "{") {
			var object json.RawMessage
			if err := json.Unmarshal([]byte(trimmed), &object); err == nil {
				entries = append(entries, entry{raw: object, location: "object"})
				parsedSingle = true
			}
		}
		if !parsedSingle {
			for i, line := range strings.Split(trimmed, "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				var object json.RawMessage
				if err := json.Unmarshal([]byte(line), &object); err != nil {
					return nil, fmt.Errorf("parsing rule (line %d): %w", i+1, err)
				}
				entries = append(entries, entry{raw: object, location: fmt.Sprintf("line %d", i+1)})
			}
		}
	}
	var rules []backend.Rule
	for _, candidate := range entries {
		exportDetails, err := isRuleExportDetails(candidate.raw)
		if err != nil {
			return nil, fmt.Errorf("parsing Elastic export details (%s): %w", candidate.location, err)
		}
		if exportDetails {
			continue
		}
		var d ruleJSON
		if err := json.Unmarshal(candidate.raw, &d); err != nil {
			return nil, fmt.Errorf("parsing rule (%s): %w", candidate.location, err)
		}
		if strings.TrimSpace(d.Name) == "" && strings.TrimSpace(d.RuleID) == "" && strings.TrimSpace(d.ID) == "" {
			return nil, fmt.Errorf("parsing rule (%s): object has no name, rule_id, or id", candidate.location)
		}
		r := d.toRule()
		r.Enabled = true
		if r.ID == "" {
			r.ID = r.Name
		}
		rules = append(rules, r)
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("no rules found in file")
	}
	if err := backend.ValidateRuleIDs(rules); err != nil {
		return nil, err
	}
	return rules, nil
}

// isRuleExportDetails recognizes the one non-rule object Elastic appends to
// rule exports. Requiring the documented discriminator and rejecting unknown
// keys prevents an arbitrary malformed candidate from being mistaken for
// harmless export metadata.
func isRuleExportDetails(raw json.RawMessage) (bool, error) {
	var shape map[string]json.RawMessage
	if err := json.Unmarshal(raw, &shape); err != nil || shape == nil {
		return false, nil
	}
	if _, ok := shape["exported_count"]; !ok {
		return false, nil
	}
	allowed := map[string]bool{
		"exported_count":                     true,
		"exported_rules_count":               true,
		"missing_rules":                      true,
		"missing_rules_count":                true,
		"exported_exception_list_count":      true,
		"exported_exception_list_item_count": true,
		"missing_exception_list_item_count":  true,
		"missing_exception_list_items":       true,
		"missing_exception_lists":            true,
		"missing_exception_lists_count":      true,
	}
	for key := range shape {
		if !allowed[key] {
			return false, nil
		}
	}
	var details struct {
		ExportedCount                  *int              `json:"exported_count"`
		ExportedRulesCount             *int              `json:"exported_rules_count"`
		MissingRules                   []json.RawMessage `json:"missing_rules"`
		MissingRulesCount              *int              `json:"missing_rules_count"`
		ExportedExceptionListCount     *int              `json:"exported_exception_list_count"`
		ExportedExceptionListItemCount *int              `json:"exported_exception_list_item_count"`
		MissingExceptionListItemCount  *int              `json:"missing_exception_list_item_count"`
		MissingExceptionListItems      []json.RawMessage `json:"missing_exception_list_items"`
		MissingExceptionLists          []json.RawMessage `json:"missing_exception_lists"`
		MissingExceptionListsCount     *int              `json:"missing_exception_lists_count"`
	}
	if err := json.Unmarshal(raw, &details); err != nil {
		return false, err
	}
	if details.ExportedCount == nil {
		return false, fmt.Errorf("exported_count must be an integer")
	}
	return true, nil
}

// ParseCandidates implements backend.CandidateParser for Elastic rule
// objects, arrays, and ndjson exports.

func (c *Client) ParseCandidates(_ context.Context, data []byte) ([]backend.Rule, error) {
	return ParseRuleFile(data)
}

// Rules inventories all detection rules via the Kibana Detections API.
// Rules backed by a data view instead of index patterns are resolved through
// the Data Views API; a missing or unreadable data view leaves the rule
// unmapped (visible in the report) rather than failing the scan.
func (c *Client) Rules(ctx context.Context) ([]backend.Rule, error) {
	var rules []backend.Rule
	dvPending := map[string][]int{} // data view ID -> indices into rules
	for page := 1; ; page++ {
		var fr findResponse
		path := c.kibanaPath(fmt.Sprintf("/api/detection_engine/rules/_find?page=%d&per_page=100", page))
		if err := c.do(ctx, http.MethodGet, c.KibanaURL, path, nil, &fr); err != nil {
			return nil, fmt.Errorf("listing detection rules: %w", err)
		}
		for _, d := range fr.Data {
			rules = append(rules, d.toRule())
			if len(d.Index) == 0 && d.DataViewID != "" {
				dvPending[d.DataViewID] = append(dvPending[d.DataViewID], len(rules)-1)
			}
		}
		if len(fr.Data) == 0 || fr.PerPage == 0 || page*fr.PerPage >= fr.Total {
			break
		}
	}
	for dvID, idxs := range dvPending {
		patterns, err := c.dataViewPatterns(ctx, dvID)
		if err != nil {
			for _, i := range idxs {
				rules[i].InputStatus = backend.ResolutionUnavailable
				rules[i].InputDetail = fmt.Sprintf("resolving data view %q: %v", dvID, err)
			}
			continue
		}
		if len(patterns) == 0 {
			for _, i := range idxs {
				rules[i].InputStatus = backend.ResolutionUnsupported
				rules[i].InputDetail = fmt.Sprintf("data view %q has no index selector", dvID)
			}
			continue
		}
		for _, i := range idxs {
			rules[i].Patterns = patterns
		}
	}
	return rules, nil
}

// dataViewPatterns resolves a Kibana data view to its index patterns (the
// data view title is a comma-separated pattern list).
func (c *Client) dataViewPatterns(ctx context.Context, id string) ([]string, error) {
	var out struct {
		DataView struct {
			Title string `json:"title"`
		} `json:"data_view"`
	}
	path := c.kibanaPath("/api/data_views/data_view/" + url.PathEscape(id))
	if err := c.do(ctx, http.MethodGet, c.KibanaURL, path, nil, &out); err != nil {
		return nil, err
	}
	var patterns []string
	for _, p := range strings.Split(out.DataView.Title, ",") {
		if p = strings.TrimSpace(p); p != "" {
			patterns = append(patterns, p)
		}
	}
	return patterns, nil
}

type resolveIndexResponse struct {
	Indices []struct {
		Name       string   `json:"name"`
		Aliases    []string `json:"aliases"`
		DataStream string   `json:"data_stream"`
	} `json:"indices"`
	Aliases []struct {
		Name    string   `json:"name"`
		Indices []string `json:"indices"`
	} `json:"aliases"`
	DataStreams []struct {
		Name           string   `json:"name"`
		BackingIndices []string `json:"backing_indices"`
	} `json:"data_streams"`
}

// Version returns the backend's native version from its read-only root API.
func (c *Client) Version(ctx context.Context) (string, error) {
	var out struct {
		Version struct {
			Number string `json:"number"`
		} `json:"version"`
	}
	if err := c.do(ctx, http.MethodGet, c.ESURL, "/", nil, &out); err != nil {
		return "", fmt.Errorf("reading Elasticsearch version: %w", err)
	}
	if out.Version.Number == "" {
		return "", fmt.Errorf("reading Elasticsearch version: response did not include version.number")
	}
	return out.Version.Number, nil
}

// ResolveInputs applies Elasticsearch's native index-expression semantics to
// every rule that has a safe local selector. Cross-cluster selectors are kept
// as separate evidence and are never sent to the local cluster.
func (c *Client) ResolveInputs(ctx context.Context, rules []backend.Rule) ([]backend.InputResolution, error) {
	type plannedResolution struct {
		resolution backend.InputResolution
		expression string
	}

	var plans []plannedResolution
	expressionIndex := make(map[string]int)
	var expressions []string
	var expressionObservedAt []time.Time
	registerExpression := func(expression string, observedAt time.Time) {
		if _, exists := expressionIndex[expression]; exists {
			return
		}
		expressionIndex[expression] = len(expressions)
		expressions = append(expressions, expression)
		expressionObservedAt = append(expressionObservedAt, observedAt)
	}
	for _, rule := range rules {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		observedAt := time.Now().UTC()
		patterns := rule.Patterns
		selector := ""
		selectorKind := "index_expression"
		resolutionMethod := "resolve_index"
		if rule.DataViewID != "" {
			selector = rule.DataViewID
			selectorKind = "data_view"
			resolutionMethod = "data_view+resolve_index"
		}
		if rule.InputStatus == "" && len(patterns) == 0 && rule.DataViewID != "" {
			var err error
			patterns, err = c.dataViewPatterns(ctx, rule.DataViewID)
			if err != nil {
				if ctxErr := ctx.Err(); ctxErr != nil {
					return nil, ctxErr
				}
				plans = append(plans, plannedResolution{resolution: backend.InputResolution{
					RuleID:           rule.ID,
					Selector:         rule.DataViewID,
					SelectorKind:     "data_view",
					ResolutionMethod: "data_view_lookup",
					ObservedAt:       observedAt,
					Status:           backend.ResolutionUnavailable,
					Detail:           fmt.Sprintf("resolving data view %q: %v", rule.DataViewID, err),
				}})
				continue
			}
			if len(patterns) == 0 {
				plans = append(plans, plannedResolution{resolution: backend.InputResolution{
					RuleID:           rule.ID,
					Selector:         rule.DataViewID,
					SelectorKind:     "data_view",
					ResolutionMethod: "data_view_lookup",
					ObservedAt:       observedAt,
					Status:           backend.ResolutionUnsupported,
					Detail:           fmt.Sprintf("data view %q has no index selector", rule.DataViewID),
				}})
				continue
			}
		}
		local, remote := splitSelectors(patterns)
		expression := strings.Join(local, ",")

		if rule.InputStatus != "" {
			plans = append(plans, plannedResolution{resolution: backend.InputResolution{
				RuleID:           rule.ID,
				Expression:       expression,
				SelectorKind:     "rule_metadata",
				ResolutionMethod: "rule_inventory",
				ObservedAt:       observedAt,
				Status:           rule.InputStatus,
				Detail:           rule.InputDetail,
			}})
		} else if expression == "" {
			if len(remote) == 0 {
				plans = append(plans, plannedResolution{resolution: backend.InputResolution{
					RuleID:           rule.ID,
					SelectorKind:     "rule_metadata",
					ResolutionMethod: "rule_inventory",
					ObservedAt:       observedAt,
					Status:           backend.ResolutionUnsupported,
					Detail:           "rule does not expose an index selector",
				}})
			}
		} else {
			registerExpression(expression, observedAt)
			plans = append(plans, plannedResolution{
				expression: expression,
				resolution: backend.InputResolution{
					RuleID:           rule.ID,
					Selector:         selector,
					SelectorKind:     selectorKind,
					ResolutionMethod: resolutionMethod,
				},
			})
			for _, diagnostic := range diagnosticInputExpressions(local) {
				registerExpression(diagnostic.expression, observedAt)
				plans = append(plans, plannedResolution{
					expression: diagnostic.expression,
					resolution: backend.InputResolution{
						RuleID:           rule.ID,
						Selector:         diagnostic.selector,
						Diagnostic:       true,
						SelectorKind:     "index_selector",
						ResolutionMethod: "resolve_index_diagnostic",
					},
				})
			}
		}

		for _, selector := range remote {
			plans = append(plans, plannedResolution{resolution: backend.InputResolution{
				RuleID:           rule.ID,
				Selector:         selector,
				SelectorKind:     "remote_index",
				ResolutionMethod: "remote_selector",
				ObservedAt:       observedAt,
				Status:           backend.ResolutionRemote,
				Detail:           "cross-cluster selector was not resolved against the local cluster",
			}})
		}
	}

	resolvedExpressions, err := c.resolveInputExpressions(ctx, expressions, expressionObservedAt)
	if err != nil {
		return nil, err
	}
	var resolutions []backend.InputResolution
	for _, plan := range plans {
		if plan.expression == "" {
			resolutions = append(resolutions, plan.resolution)
			continue
		}
		resolution := resolvedExpressions[expressionIndex[plan.expression]]
		resolution.ResolvedSources = append([]string(nil), resolution.ResolvedSources...)
		resolution.Aliases = append([]string(nil), resolution.Aliases...)
		resolution.RuleID = plan.resolution.RuleID
		resolution.Selector = plan.resolution.Selector
		resolution.Diagnostic = plan.resolution.Diagnostic
		resolution.SelectorKind = plan.resolution.SelectorKind
		resolution.ResolutionMethod = plan.resolution.ResolutionMethod
		resolutions = append(resolutions, resolution)
	}
	return resolutions, nil
}

type diagnosticInputExpression struct {
	selector   string
	expression string
}

// diagnosticInputExpressions isolates each positive selector while retaining
// every local exclusion. These reads explain migration fallbacks without
// changing the authoritative combined expression used by the graph.
func diagnosticInputExpressions(local []string) []diagnosticInputExpression {
	var positives, exclusions []string
	seenPositive := make(map[string]bool)
	for _, selector := range local {
		if strings.HasPrefix(selector, "-") {
			exclusions = append(exclusions, selector)
			continue
		}
		if !seenPositive[selector] {
			seenPositive[selector] = true
			positives = append(positives, selector)
		}
	}
	if len(positives) < 2 {
		return nil
	}
	out := make([]diagnosticInputExpression, 0, len(positives))
	seenExpression := make(map[string]bool, len(positives))
	for _, selector := range positives {
		parts := append([]string{selector}, exclusions...)
		expression := strings.Join(parts, ",")
		if seenExpression[expression] {
			continue
		}
		seenExpression[expression] = true
		out = append(out, diagnosticInputExpression{selector: selector, expression: expression})
	}
	return out
}

func (c *Client) resolveInputExpressions(ctx context.Context, expressions []string, observedAt []time.Time) ([]backend.InputResolution, error) {
	resolutions := make([]backend.InputResolution, len(expressions))
	sem := make(chan struct{}, c.concurrency())
	var wg sync.WaitGroup
	for i, expression := range expressions {
		i, expression := i, expression
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			resolution := backend.InputResolution{
				Expression:       expression,
				SelectorKind:     "index_expression",
				ResolutionMethod: "resolve_index",
				ObservedAt:       observedAt[i],
			}
			var response resolveIndexResponse
			path := "/_resolve/index/" + url.PathEscape(expression) + "?ignore_unavailable=true"
			if err := c.do(ctx, http.MethodGet, c.ESURL, path, nil, &response); err != nil {
				resolution.Status = backend.ResolutionUnavailable
				if isStatus(err, http.StatusBadRequest) {
					resolution.Status = backend.ResolutionUnsupported
				}
				resolution.Detail = err.Error()
			} else {
				resolution.ResolvedSources, resolution.Aliases = resolvedNames(response)
				if len(resolution.ResolvedSources) == 0 {
					resolution.Status = backend.ResolutionEmpty
				} else {
					resolution.Status = backend.ResolutionResolved
				}
			}
			resolutions[i] = resolution
		}()
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return resolutions, nil
}

func splitSelectors(selectors []string) (local, remote []string) {
	for _, selector := range selectors {
		selector = strings.TrimSpace(selector)
		if selector == "" {
			continue
		}
		if isRemoteSelector(selector) {
			remote = append(remote, selector)
		} else {
			local = append(local, selector)
		}
	}
	return local, remote
}

func isRemoteSelector(selector string) bool {
	braceDepth := 0
	for _, r := range selector {
		switch r {
		case '{':
			braceDepth++
		case '}':
			if braceDepth > 0 {
				braceDepth--
			}
		case ':':
			if braceDepth == 0 {
				return true
			}
		}
	}
	return false
}

func resolvedNames(response resolveIndexResponse) (sources, aliases []string) {
	backingStreams := make(map[string]string)
	for _, stream := range response.DataStreams {
		if stream.Name != "" {
			sources = append(sources, stream.Name)
		}
		for _, backing := range stream.BackingIndices {
			backingStreams[backing] = stream.Name
		}
	}
	addSource := func(name string) {
		if stream := backingStreams[name]; stream != "" {
			sources = append(sources, stream)
		} else if match := backingRe.FindStringSubmatch(name); match != nil {
			sources = append(sources, match[1])
		} else if name != "" {
			sources = append(sources, name)
		}
	}
	for _, index := range response.Indices {
		if index.DataStream != "" {
			sources = append(sources, index.DataStream)
		} else {
			addSource(index.Name)
		}
		aliases = append(aliases, index.Aliases...)
	}
	for _, alias := range response.Aliases {
		if alias.Name != "" {
			aliases = append(aliases, alias.Name)
		}
		for _, index := range alias.Indices {
			addSource(index)
		}
	}
	return sortedUnique(sources), sortedUnique(aliases)
}

func sortedUnique(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

type dsStatsResponse struct {
	DataStreams []struct {
		Name             string `json:"data_stream"`
		StoreSizeBytes   int64  `json:"store_size_bytes"`
		MaximumTimestamp int64  `json:"maximum_timestamp"` // epoch millis
	} `json:"data_streams"`
}

type catIndex struct {
	Index     string `json:"index"`
	DocsCount string `json:"docs.count"`
	StoreSize string `json:"store.size"`
}

// backingRe extracts the data-stream name from a backing index:
// .ds-<stream>-<yyyy.MM.dd>-<generation>
var backingRe = regexp.MustCompile(`^\.ds-(.+)-\d{4}\.\d{2}\.\d{2}-\d+$`)

// Sources inventories data streams and plain indices with their health stats.
// Data-stream freshness comes free from _data_stream/_stats; plain indices
// fall back to a bounded-concurrency size-0 max(@timestamp) aggregation.
func (c *Client) Sources(ctx context.Context) ([]backend.Source, error) {
	var ds dsStatsResponse
	if err := c.do(ctx, http.MethodGet, c.ESURL, "/_data_stream/_stats", nil, &ds); err != nil {
		return nil, fmt.Errorf("data stream stats: %w", err)
	}
	var cats []catIndex
	if err := c.do(ctx, http.MethodGet, c.ESURL, "/_cat/indices?format=json&h=index,docs.count,store.size&bytes=b", nil, &cats); err != nil {
		return nil, fmt.Errorf("listing indices: %w", err)
	}

	// Doc counts per data stream, summed from backing indices.
	streamDocs := make(map[string]int64)
	var sources []backend.Source
	for _, ci := range cats {
		if m := backingRe.FindStringSubmatch(ci.Index); m != nil {
			if n, err := strconv.ParseInt(ci.DocsCount, 10, 64); err == nil {
				streamDocs[m[1]] += n
			}
			continue
		}
		if strings.HasPrefix(ci.Index, ".") {
			continue // system indices are not telemetry sources
		}
		s := backend.Source{Name: ci.Index, Docs: -1}
		if n, err := strconv.ParseInt(ci.DocsCount, 10, 64); err == nil {
			s.Docs = n
		}
		if n, err := strconv.ParseInt(ci.StoreSize, 10, 64); err == nil {
			s.SizeBytes = n
		}
		sources = append(sources, s)
	}
	for _, d := range ds.DataStreams {
		s := backend.Source{Name: d.Name, SizeBytes: d.StoreSizeBytes, Docs: -1}
		if n, ok := streamDocs[d.Name]; ok {
			s.Docs = n
		}
		if d.MaximumTimestamp > 0 {
			s.LastEvent = time.UnixMilli(d.MaximumTimestamp)
		}
		sources = append(sources, s)
	}

	c.fillFreshness(ctx, sources)
	return sources, nil
}

// fillIngestLag calculates lag from paired timestamps on the same events.
// The bounded recent sample avoids the false result produced by subtracting
// independent maxima that may belong to different documents.
func (c *Client) fillIngestLag(ctx context.Context, sources []backend.Source) {
	sem := make(chan struct{}, c.concurrency())
	var wg sync.WaitGroup
	for i := range sources {
		if sources[i].Docs == 0 {
			sources[i].IngestLag = backend.IngestLagEvidence{
				Status: backend.EvidenceDisabled,
				Detail: "source has no documents",
			}
			continue
		}
		wg.Add(1)
		go func(s *backend.Source) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			s.IngestLag = backend.IngestLagEvidence{
				Status:     backend.EvidenceIncomplete,
				Method:     "paired-recent-events",
				ObservedAt: time.Now().UTC(),
				Window:     ingestLagWindow,
			}
			body := strings.NewReader(fmt.Sprintf(`{"size":%d,"track_total_hits":false,"_source":false,"query":{"bool":{"filter":[{"range":{"event.ingested":{"gte":"now-%dh"}}},{"exists":{"field":"event.ingested"}},{"exists":{"field":"@timestamp"}}]}},"sort":[{"event.ingested":{"order":"desc","unmapped_type":"date"}}],"fields":[{"field":"event.ingested","format":"epoch_millis"},{"field":"@timestamp","format":"epoch_millis"}]}`,
				ingestLagSamples, int(ingestLagWindow/time.Hour)))
			var out struct {
				Hits struct {
					Hits []struct {
						Fields map[string][]json.RawMessage `json:"fields"`
					} `json:"hits"`
				} `json:"hits"`
			}
			path := "/" + url.PathEscape(s.Name) + "/_search"
			if err := c.do(ctx, http.MethodPost, c.ESURL, path, body, &out); err != nil {
				s.IngestLag.Detail = "paired timestamp sample could not be read"
				return
			}
			lags := make([]time.Duration, 0, len(out.Hits.Hits))
			for _, hit := range out.Hits.Hits {
				eventTime, eventOK := firstMillis(hit.Fields["@timestamp"])
				ingestTime, ingestOK := firstMillis(hit.Fields["event.ingested"])
				if !eventOK || !ingestOK {
					continue
				}
				lag := time.Duration(ingestTime-eventTime) * time.Millisecond
				if lag < 0 {
					lag = 0
				}
				lags = append(lags, lag)
			}
			if len(lags) == 0 {
				s.IngestLag.Detail = "no recent events exposed both event.ingested and @timestamp"
				return
			}
			sort.Slice(lags, func(i, j int) bool { return lags[i] < lags[j] })
			p95Index := int(math.Ceil(float64(len(lags))*0.95)) - 1
			s.IngestLag.Status = backend.EvidenceAssessed
			s.IngestLag.SampleCount = len(lags)
			s.IngestLag.P95 = lags[p95Index]
			s.IngestLag.Max = lags[len(lags)-1]
			s.IngestLag.Detail = ""
		}(&sources[i])
	}
	wg.Wait()
}

// IngestLagEvidence samples only the sources selected by the caller. Keeping
// this separate from Sources prevents connection checks from issuing search
// requests and lets the CLI limit reads to sources used by eligible rules.
func (c *Client) IngestLagEvidence(ctx context.Context, sources []backend.Source) (map[string]backend.IngestLagEvidence, error) {
	selected := append([]backend.Source(nil), sources...)
	c.fillIngestLag(ctx, selected)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	out := make(map[string]backend.IngestLagEvidence, len(selected))
	for _, source := range selected {
		out[source.Name] = source.IngestLag
	}
	return out, nil
}

func firstMillis(values []json.RawMessage) (int64, bool) {
	if len(values) == 0 {
		return 0, false
	}
	var number float64
	if err := json.Unmarshal(values[0], &number); err == nil {
		return int64(number), true
	}
	var text string
	if err := json.Unmarshal(values[0], &text); err != nil {
		return 0, false
	}
	if millis, err := strconv.ParseInt(text, 10, 64); err == nil {
		return millis, true
	}
	parsed, err := time.Parse(time.RFC3339Nano, text)
	if err != nil {
		return 0, false
	}
	return parsed.UnixMilli(), true
}

// fillFreshness resolves LastEvent for sources that lack it, with bounded
// concurrency. Failures are tolerated: a source we cannot date reports as
// status "unknown" rather than failing the scan.
func (c *Client) fillFreshness(ctx context.Context, sources []backend.Source) {
	sem := make(chan struct{}, c.concurrency())
	var wg sync.WaitGroup
	for i := range sources {
		if sources[i].LastEvent.After(time.Now().Add(backend.FreshnessClockSkew)) {
			// An unbounded data-stream maximum must not hide older valid events.
			sources[i].LastEvent = time.Time{}
		}
		if !sources[i].LastEvent.IsZero() || sources[i].Docs == 0 {
			continue
		}
		wg.Add(1)
		go func(s *backend.Source) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if ts, err := c.maxTimestamp(ctx, s.Name); err == nil {
				s.LastEvent = ts
			}
		}(&sources[i])
	}
	wg.Wait()
}

func (c *Client) maxTimestamp(ctx context.Context, index string) (time.Time, error) {
	body := strings.NewReader(fmt.Sprintf(`{"size":0,"track_total_hits":false,"query":{"range":{"@timestamp":{"lte":"now+%ds"}}},"aggs":{"latest":{"max":{"field":"@timestamp"}}}}`, int(backend.FreshnessClockSkew/time.Second)))
	var out struct {
		Aggregations struct {
			Latest struct {
				Value *float64 `json:"value"`
			} `json:"latest"`
		} `json:"aggregations"`
	}
	path := "/" + url.PathEscape(index) + "/_search"
	if err := c.do(ctx, http.MethodPost, c.ESURL, path, body, &out); err != nil {
		return time.Time{}, err
	}
	if out.Aggregations.Latest.Value == nil {
		return time.Time{}, nil
	}
	stamp := time.UnixMilli(int64(*out.Aggregations.Latest.Value))
	if stamp.After(time.Now().Add(backend.FreshnessClockSkew)) {
		return time.Time{}, fmt.Errorf("freshness result exceeded the clock-skew limit")
	}
	return stamp, nil
}

type fieldCapability struct {
	Searchable           bool     `json:"searchable"`
	NonSearchableIndices []string `json:"non_searchable_indices"`
}

type fieldCapsResponse struct {
	Fields map[string]map[string]fieldCapability `json:"fields"`
}

// Schemas inventories field capabilities for the already-selected sources.
// It is opt-in at the CLI because it is one cheap metadata read per source.
func (c *Client) Schemas(ctx context.Context, sources []backend.Source) (map[string]backend.Schema, error) {
	out := make(map[string]backend.Schema, len(sources))
	sem := make(chan struct{}, c.concurrency())
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, src := range sources {
		src := src
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			schema, err := c.schema(ctx, src.Name)
			if err != nil {
				// Tolerated: a broken source must not kill the report; it
				// reports schema "unknown" this scan and its stored snapshot
				// stays untouched.
				return
			}
			mu.Lock()
			out[src.Name] = schema
			mu.Unlock()
		}()
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// RequiredFieldEvidence fetches only rule-declared fields. A missing source
// result is retained as incomplete evidence rather than being treated as an
// empty mapping.
func (c *Client) RequiredFieldEvidence(ctx context.Context, sources []backend.Source, fields []string) (map[string]backend.FieldEvidence, error) {
	out := make(map[string]backend.FieldEvidence, len(sources))
	if len(fields) == 0 {
		return out, nil
	}
	fields = append([]string(nil), fields...)
	sort.Strings(fields)
	body, err := json.Marshal(struct {
		Fields []string `json:"fields"`
	}{Fields: fields})
	if err != nil {
		return nil, fmt.Errorf("encoding required-field request: %w", err)
	}
	sem := make(chan struct{}, c.concurrency())
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, src := range sources {
		src := src
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			evidence := backend.FieldEvidence{Status: backend.EvidenceIncomplete, Detail: "field capabilities could not be read"}
			var fc fieldCapsResponse
			query := url.Values{"include_unmapped": []string{"true"}}
			path := "/" + url.PathEscape(src.Name) + "/_field_caps?" + query.Encode()
			if err := c.do(ctx, http.MethodPost, c.ESURL, path, bytes.NewReader(body), &fc); err == nil {
				evidence = backend.FieldEvidence{Status: backend.EvidenceAssessed, Fields: make(map[string]bool, len(fc.Fields))}
				for name, byType := range fc.Fields {
					available := len(byType) > 0
					for typ, capability := range byType {
						if typ == "unmapped" || !capability.Searchable || len(capability.NonSearchableIndices) > 0 {
							available = false
							break
						}
					}
					evidence.Fields[name] = available
				}
			}
			mu.Lock()
			out[src.Name] = evidence
			mu.Unlock()
		}()
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) schema(ctx context.Context, source string) (backend.Schema, error) {
	var fc fieldCapsResponse
	path := "/" + url.PathEscape(source) + "/_field_caps?fields=*"
	if err := c.do(ctx, http.MethodGet, c.ESURL, path, nil, &fc); err != nil {
		return backend.Schema{}, fmt.Errorf("field caps for %s: %w", source, err)
	}
	return schemaFromFieldCaps(source, fc), nil
}

func schemaFromFieldCaps(source string, fc fieldCapsResponse) backend.Schema {
	schema := backend.Schema{Source: source, Fields: make([]backend.Field, 0, len(fc.Fields))}
	for name, byType := range fc.Fields {
		types := make([]string, 0, len(byType))
		for typ := range byType {
			types = append(types, typ)
		}
		sort.Strings(types)
		schema.Fields = append(schema.Fields, backend.Field{Name: name, Types: types})
	}
	sort.Slice(schema.Fields, func(i, j int) bool { return schema.Fields[i].Name < schema.Fields[j].Name })
	return schema
}
