package sentinel

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/alephnull-sh/deadair/internal/backend"
)

const (
	maxPredicateConjuncts     = 8
	maxPredicateValues        = 32
	maxPredicateTokens        = 256
	maxPredicateExpressionLen = 2048
	maxPredicateQueries       = 20
)

var predicateFreshnessFields = map[string]struct{}{
	"DeviceProduct":      {},
	"DeviceVendor":       {},
	"DeviceName":         {},
	"DeviceAction":       {},
	"DeviceEventClassID": {},
	"EventID":            {},
	"OperationName":      {},
}

var _ backend.RulePredicateFreshnessProvider = (*Client)(nil)

// ExtractPredicateFreshness returns one canonical, backend-private selector
// only when a query starts at one direct local table and immediately narrows
// it with closed, AND-only predicates. It deliberately recognizes a small
// subset: an unsupported term discards the entire selector rather than
// weakening the filter that a rule actually applies.
func ExtractPredicateFreshness(query string) (backend.PredicateFreshnessSelector, bool) {
	tokens, err := lexKQL(query)
	if err != nil || len(tokens) == 0 || validateKQLParens(tokens) != nil {
		return backend.PredicateFreshnessSelector{}, false
	}
	statements := splitKQLTopLevel(tokens, ";")
	if len(statements) != 1 {
		return backend.PredicateFreshnessSelector{}, false
	}
	segments := splitKQLTopLevel(statements[0], "|")
	if len(segments) < 2 {
		return backend.PredicateFreshnessSelector{}, false
	}
	sourceTokens := trimKQLTokens(segments[0])
	if len(sourceTokens) != 1 || sourceTokens[0].kind != kqlIdentifier || sourceTokens[0].escaped ||
		(!sourceTokens[0].quoted && (isKQLNonSourceKeyword(sourceTokens[0].text) || strings.HasPrefix(sourceTokens[0].text, "$"))) {
		return backend.PredicateFreshnessSelector{}, false
	}
	source := strings.TrimSpace(sourceTokens[0].text)
	if source == "" {
		return backend.PredicateFreshnessSelector{}, false
	}
	if _, ok := kqlTableReference(source); !ok {
		return backend.PredicateFreshnessSelector{}, false
	}

	// Resolve the whole query as an independent guard against a remote,
	// dynamic, function-backed, unioned, or otherwise hidden second source.
	resolution := ResolveKQLDependencies(query)
	if resolution.Status != backend.ResolutionResolved || len(resolution.Dependencies) != 1 {
		return backend.PredicateFreshnessSelector{}, false
	}
	dependency := resolution.Dependencies[0]
	if dependency.Kind != KindTable || dependency.Optional || dependency.Name != source {
		return backend.PredicateFreshnessSelector{}, false
	}

	parser := predicateParser{fields: make(map[string]struct{})}
	canonical := make([]string, 0, 2)
	seenPredicate := false
	leadingPredicateEnded := false
	for _, rawSegment := range segments[1:] {
		segment := trimKQLTokens(rawSegment)
		if len(segment) == 0 || segment[0].kind != kqlIdentifier {
			return backend.PredicateFreshnessSelector{}, false
		}
		if kqlWord(segment[0], "where") || kqlWord(segment[0], "filter") {
			// A later predicate may depend on a projected or calculated column.
			// Once another operator appears, the original source slice is no
			// longer safe to reconstruct independently.
			if leadingPredicateEnded {
				return backend.PredicateFreshnessSelector{}, false
			}
			seenPredicate = true
			expression, ok := parser.parseConjunction(segment[1:])
			if !ok {
				return backend.PredicateFreshnessSelector{}, false
			}
			canonical = append(canonical, expression...)
			continue
		}
		if !seenPredicate {
			return backend.PredicateFreshnessSelector{}, false
		}
		leadingPredicateEnded = true
		if predicatePipelineCanSelectSource(segment[0]) {
			return backend.PredicateFreshnessSelector{}, false
		}
	}
	if !seenPredicate || len(canonical) == 0 || parser.conjuncts > maxPredicateConjuncts || parser.values > maxPredicateValues {
		return backend.PredicateFreshnessSelector{}, false
	}
	expression := strings.Join(canonical, " and ")
	if len(expression) > maxPredicateExpressionLen {
		return backend.PredicateFreshnessSelector{}, false
	}
	fields := make([]string, 0, len(parser.fields))
	for field := range parser.fields {
		fields = append(fields, field)
	}
	sort.Strings(fields)
	return backend.PredicateFreshnessSelector{Source: source, Expression: expression, Fields: fields}, true
}

func predicatePipelineCanSelectSource(token kqlToken) bool {
	for _, operator := range []string{
		"union", "join", "lookup", "search", "find", "invoke", "evaluate",
		"fork", "partition", "macro-expand",
	} {
		if kqlWord(token, operator) {
			return true
		}
	}
	return false
}

type predicateParser struct {
	conjuncts int
	values    int
	fields    map[string]struct{}
}

func (p *predicateParser) parseConjunction(tokens []kqlToken) ([]string, bool) {
	tokens = stripKQLOuterParens(trimKQLTokens(tokens))
	if len(tokens) == 0 || len(tokens) > maxPredicateTokens {
		return nil, false
	}
	parts := splitKQLTopLevelWord(tokens, "and")
	if len(parts) > 1 {
		out := make([]string, 0, len(parts))
		for _, part := range parts {
			parsed, ok := p.parseConjunction(part)
			if !ok {
				return nil, false
			}
			out = append(out, parsed...)
		}
		return out, true
	}
	if findKQLTopLevelWord(tokens, 0, "or") >= 0 {
		return nil, false
	}
	p.conjuncts++
	if p.conjuncts > maxPredicateConjuncts {
		return nil, false
	}
	return p.parseTerm(tokens)
}

func (p *predicateParser) parseTerm(tokens []kqlToken) ([]string, bool) {
	tokens = stripKQLOuterParens(trimKQLTokens(tokens))
	if len(tokens) < 4 || tokens[0].kind != kqlIdentifier {
		return nil, false
	}
	field := tokens[0].text
	if _, ok := predicateFreshnessFields[field]; !ok {
		return nil, false
	}
	p.fields[field] = struct{}{}

	if len(tokens) >= 3 && tokens[1].text == "=" && tokens[2].text == "=" {
		value, ok := canonicalPredicateLiteral(tokens[3:])
		if !ok {
			return nil, false
		}
		p.values++
		if p.values > maxPredicateValues {
			return nil, false
		}
		return []string{field + " == " + value}, true
	}
	if !kqlWord(tokens[1], "in") || tokens[2].text != "(" {
		return nil, false
	}
	close, ok := matchingKQLParen(tokens, 2)
	if !ok || close != len(tokens)-1 {
		return nil, false
	}
	parts := splitKQLTopLevel(tokens[3:close], ",")
	if len(parts) == 0 {
		return nil, false
	}
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		value, ok := canonicalPredicateLiteral(part)
		if !ok {
			return nil, false
		}
		values = append(values, value)
		p.values++
		if p.values > maxPredicateValues {
			return nil, false
		}
	}
	return []string{field + " in (" + strings.Join(values, ", ") + ")"}, true
}

func canonicalPredicateLiteral(tokens []kqlToken) (string, bool) {
	tokens = stripKQLOuterParens(trimKQLTokens(tokens))
	if len(tokens) == 1 {
		switch {
		case tokens[0].kind == kqlString && !tokens[0].escaped && predicateLiteralTextSafe(tokens[0].text):
			return quoteKQLString(tokens[0].text), true
		case tokens[0].kind == kqlOther && isPredicateNumber(tokens[0].text):
			return tokens[0].text, true
		}
	}
	if len(tokens) == 2 && (tokens[0].text == "+" || tokens[0].text == "-") &&
		tokens[1].kind == kqlOther && isPredicateNumber(tokens[1].text) {
		return tokens[0].text + tokens[1].text, true
	}
	return "", false
}

func predicateLiteralTextSafe(value string) bool {
	return strings.IndexFunc(value, unicode.IsControl) < 0
}

func isPredicateNumber(value string) bool {
	digits := 0
	dot := false
	for _, r := range value {
		switch {
		case r >= '0' && r <= '9':
			digits++
		case r == '.' && !dot:
			dot = true
		default:
			return false
		}
	}
	return digits > 0 && value != "."
}

func splitKQLTopLevelWord(tokens []kqlToken, word string) [][]kqlToken {
	parts := make([][]kqlToken, 0, 2)
	start := 0
	depth := 0
	for i, token := range tokens {
		switch token.text {
		case "(":
			depth++
		case ")":
			depth--
		default:
			if depth == 0 && kqlWord(token, word) {
				parts = append(parts, tokens[start:i])
				start = i + 1
			}
		}
	}
	return append(parts, tokens[start:])
}

// RulePredicateFreshnessEvidenceFor collects bounded rule/source-slice
// observations after the ordinary source-wide evidence pass. Results remain
// separate from source freshness and therefore cannot create a dead finding.
func (c *Client) RulePredicateFreshnessEvidenceFor(ctx context.Context, requests []backend.RulePredicateFreshnessRequest) ([]backend.RulePredicateFreshnessEvidence, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(requests) == 0 {
		return []backend.RulePredicateFreshnessEvidence{}, nil
	}
	catalog, err := c.tables(ctx)
	if err != nil {
		return nil, err
	}
	requests = append([]backend.RulePredicateFreshnessRequest(nil), requests...)
	sort.SliceStable(requests, func(i, j int) bool {
		return predicateRequestKey(requests[i]) < predicateRequestKey(requests[j])
	})
	out := make([]backend.RulePredicateFreshnessEvidence, 0, len(requests))
	seen := make(map[string]bool, len(requests))
	observations := make(map[string]backend.FreshnessEvidence)
	queries := 0
	for _, request := range requests {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		key := predicateRequestKey(request)
		if seen[key] {
			continue
		}
		seen[key] = true
		item, query, target := c.preparePredicateFreshness(ctx, catalog, request)
		if query == "" {
			out = append(out, item)
			continue
		}
		// The closed query includes the local table, filter and clock. Share
		// only this observation; each rule keeps its own identity and policy.
		if freshness, ok := observations[query]; ok {
			item.Freshness = freshness
			out = append(out, item)
			continue
		}
		if queries >= maxPredicateQueries {
			item.Freshness.Detail = fmt.Sprintf("per-scan predicate freshness query limit of %d was exhausted", maxPredicateQueries)
			out = append(out, item)
			continue
		}
		queries++
		result, queryErr := c.queryLogsForSource(ctx, query, target)
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if queryErr != nil {
			item.Freshness.Status, item.Freshness.Detail = evidenceFailure(queryErr)
		} else {
			item.Freshness = freshnessFromTable(result, item.Freshness)
		}
		observations[query] = item.Freshness
		out = append(out, item)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) preparePredicateFreshness(ctx context.Context, catalog map[string]tableInfo, request backend.RulePredicateFreshnessRequest) (backend.RulePredicateFreshnessEvidence, string, sentinelSourceTarget) {
	freshness := backend.FreshnessEvidence{
		Status:     backend.EvidenceIncomplete,
		Method:     predicateFreshnessMethod(request.Basis),
		ObservedAt: time.Now().UTC(),
		Window:     freshnessWindow,
		Detail:     "bounded predicate freshness query could not be read",
	}
	item := backend.RulePredicateFreshnessEvidence{
		RuleID:          request.RuleID,
		BackendObjectID: request.BackendObjectID,
		Source:          request.Source.Name,
		Fields:          append([]string(nil), request.Selector.Fields...),
		Freshness:       freshness,
	}
	selector, ok := validatedPredicateSelector(request)
	if !ok {
		item.Freshness.Detail = "predicate freshness selector is not a closed parser-generated local-table filter"
		return item, "", sentinelSourceTarget{}
	}
	item.Fields = append([]string(nil), selector.Fields...)
	if request.Basis != backend.FreshnessEventTime && request.Basis != backend.FreshnessIngestionTime {
		item.Freshness.Detail = "rule timing does not select one supported freshness clock"
		return item, "", sentinelSourceTarget{}
	}
	if _, _, remote := parseQualifiedRemoteSource(request.Source.Name); remote {
		item.Freshness.Detail = "predicate freshness is limited to the local Sentinel workspace"
		return item, "", sentinelSourceTarget{}
	}
	target, err := c.sourceTarget(ctx, request.Source.Name, catalog)
	if err != nil {
		item.Freshness.Status, item.Freshness.Detail = evidenceFailure(err)
		return item, "", target
	}
	if !target.found {
		item.Freshness.Detail = "source is absent from the workspace table inventory"
		return item, "", target
	}
	if !strings.EqualFold(target.info.provisioning, "Succeeded") {
		_, item.Freshness.Detail, _ = tableRuntimeLimitation(target.info)
		item.Freshness.Status = backend.EvidenceUnavailable
		return item, "", target
	}
	if !strings.EqualFold(target.info.plan, "Analytics") {
		item.Freshness.Status = backend.EvidenceUnavailable
		item.Freshness.Detail = "predicate freshness requires a local Analytics-plan table"
		return item, "", target
	}
	if !target.info.schemaComplete {
		item.Freshness.Status = backend.EvidenceUnavailable
		item.Freshness.Detail = "table schema is incomplete"
		return item, "", target
	}
	for _, field := range selector.Fields {
		if !catalogHasField(target.info, field) {
			item.Freshness.Status = backend.EvidenceUnavailable
			item.Freshness.Detail = "complete table schema does not expose predicate field " + field
			return item, "", target
		}
	}
	if request.Basis == backend.FreshnessEventTime && !catalogHasField(target.info, "TimeGenerated") {
		item.Freshness.Status = backend.EvidenceUnavailable
		item.Freshness.Detail = "table schema does not expose TimeGenerated"
		return item, "", target
	}
	if target.queryReference == "" {
		item.Freshness.Detail = "table name cannot be represented safely in KQL"
		return item, "", target
	}
	query := fmt.Sprintf("%s | where TimeGenerated >= ago(%dh) and TimeGenerated <= now() + %ds | where %s | summarize LastEvent=max(TimeGenerated)",
		target.queryReference, int(freshnessWindow/time.Hour), int(backend.FreshnessClockSkew/time.Second), selector.Expression)
	if request.Basis == backend.FreshnessIngestionTime {
		query = fmt.Sprintf("%s | extend IngestionTime=ingestion_time() | where IngestionTime >= ago(%dh) and IngestionTime <= now() + %ds | where %s | summarize LastEvent=max(IngestionTime)",
			target.queryReference, int(freshnessWindow/time.Hour), int(backend.FreshnessClockSkew/time.Second), selector.Expression)
	}
	return item, query, target
}

func validatedPredicateSelector(request backend.RulePredicateFreshnessRequest) (backend.PredicateFreshnessSelector, bool) {
	if request.Source.Name == "" || request.Selector.Source != request.Source.Name || request.Selector.Expression == "" {
		return backend.PredicateFreshnessSelector{}, false
	}
	ref, ok := kqlTableReference(request.Selector.Source)
	if !ok {
		return backend.PredicateFreshnessSelector{}, false
	}
	validated, ok := ExtractPredicateFreshness(ref + " | where " + request.Selector.Expression)
	if !ok || validated.Source != request.Selector.Source || validated.Expression != request.Selector.Expression ||
		!equalStrings(validated.Fields, request.Selector.Fields) {
		return backend.PredicateFreshnessSelector{}, false
	}
	return validated, true
}

func predicateFreshnessMethod(basis backend.FreshnessBasis) string {
	switch basis {
	case backend.FreshnessIngestionTime:
		return "bounded-predicate-max-ingestion-time"
	case backend.FreshnessEventTime:
		return "bounded-predicate-max-event-time"
	default:
		return "bounded-predicate-freshness"
	}
}

func predicateRequestKey(request backend.RulePredicateFreshnessRequest) string {
	return strings.Join([]string{
		request.RuleID,
		request.BackendObjectID,
		request.Source.Name,
		request.Selector.Source,
		request.Selector.Expression,
		strings.Join(request.Selector.Fields, "\x1f"),
		string(request.Basis),
	}, "\x00")
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
