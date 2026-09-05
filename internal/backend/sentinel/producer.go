package sentinel

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/alephnull-sh/deadair/internal/backend"
)

// ProducerSelector constructs a closed literal filter and then subjects it
// to the same parser as rule-qualified freshness queries.
func ProducerSelector(p backend.ProducerExpectation) (backend.PredicateFreshnessSelector, error) {
	if p.ID == "" || p.MaxStale <= 0 || p.MaxStale > 24*time.Hour {
		return backend.PredicateFreshnessSelector{}, fmt.Errorf("producer requires an ID and max_stale between 0 and 24h")
	}
	if p.Basis != backend.FreshnessEventTime && p.Basis != backend.FreshnessIngestionTime {
		return backend.PredicateFreshnessSelector{}, fmt.Errorf("producer clock must be event_time or ingestion_time")
	}
	ref, ok := kqlTableReference(p.Source)
	if !ok || len(p.Match) == 0 || len(p.Match) > 3 {
		return backend.PredicateFreshnessSelector{}, fmt.Errorf("producer requires one local table and identity fields")
	}
	fields := make([]string, 0, len(p.Match))
	for field, value := range p.Match {
		if field != "DeviceVendor" && field != "DeviceProduct" && field != "DeviceName" {
			return backend.PredicateFreshnessSelector{}, fmt.Errorf("producer match only supports DeviceVendor, DeviceProduct, and DeviceName")
		}
		if len(value) == 0 || len(value) > 256 || !predicateLiteralTextSafe(value) {
			return backend.PredicateFreshnessSelector{}, fmt.Errorf("producer identity must be a nonempty printable value of at most 256 bytes")
		}
		fields = append(fields, field)
	}
	sort.Strings(fields)
	var terms []string
	for _, field := range fields {
		terms = append(terms, field+" == "+strconv.Quote(p.Match[field]))
	}
	selector, ok := ExtractPredicateFreshness(ref + " | where " + strings.Join(terms, " and "))
	if !ok {
		return backend.PredicateFreshnessSelector{}, fmt.Errorf("producer identity cannot be represented as a literal filter")
	}
	return selector, nil
}

func (c *Client) ProducerFreshnessEvidence(ctx context.Context, producers []backend.ProducerExpectation, rules []backend.Rule) ([]backend.ProducerEvidence, error) {
	requests := make([]backend.RulePredicateFreshnessRequest, 0, len(producers))
	selectors := make(map[string]backend.PredicateFreshnessSelector)
	for _, p := range producers {
		selector, err := ProducerSelector(p)
		if err != nil {
			return nil, err
		}
		selectors[p.ID] = selector
		requests = append(requests, backend.RulePredicateFreshnessRequest{RuleID: p.ID, Source: backend.Source{Name: p.Source}, Basis: p.Basis, Window: p.MaxStale, Selector: selector})
	}
	evidence, err := c.RulePredicateFreshnessEvidenceFor(ctx, requests)
	if err != nil {
		return nil, err
	}
	out := make([]backend.ProducerEvidence, 0, len(evidence))
	for _, item := range evidence {
		result := backend.ProducerEvidence{ID: item.RuleID, Source: item.Source, Freshness: item.Freshness}
		selector := selectors[item.RuleID]
		for _, rule := range rules {
			if !rule.Enabled || rule.InputStatus == backend.ResolutionUnsupported {
				continue
			}
			for _, filter := range rule.PredicateFreshness {
				// Every configured identity equality must be required by the
				// rule's conjunction. Extra event conditions do not become
				// expectations of their own.
				if filter.Source == selector.Source && producerFilterRequires(filter.Expression, selector.Expression) {
					result.ConfirmedRules = append(result.ConfirmedRules, rule.ID)
					break
				}
			}
		}
		sort.Strings(result.ConfirmedRules)
		out = append(out, result)
	}
	return out, nil
}

func producerFilterRequires(rule, producer string) bool {
	parse := func(expression string) ([]string, bool) {
		tokens, err := lexKQL(expression)
		if err != nil {
			return nil, false
		}
		p := predicateParser{fields: make(map[string]struct{})}
		return p.parseConjunction(tokens)
	}
	terms, ok := parse(rule)
	if !ok {
		return false
	}
	wanted, ok := parse(producer)
	if !ok {
		return false
	}
	set := make(map[string]bool)
	for _, term := range terms {
		set[term] = true
	}
	for _, term := range wanted {
		if !set[term] {
			return false
		}
	}
	return len(wanted) > 0
}
