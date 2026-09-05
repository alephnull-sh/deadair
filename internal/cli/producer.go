package cli

import (
	"context"
	"fmt"

	"github.com/alephnull-sh/deadair/internal/backend"
	"github.com/alephnull-sh/deadair/internal/backend/sentinel"
	"github.com/alephnull-sh/deadair/internal/report"
)

func validateProducers(c backend.Backend, policy *report.Policy) error {
	expectations := policy.ProducerExpectations()
	if len(expectations) == 0 {
		return nil
	}
	if _, ok := c.(backend.ProducerFreshnessProvider); !ok {
		return fmt.Errorf("producer expectations require a Sentinel backend")
	}
	for _, p := range expectations {
		if _, err := sentinel.ProducerSelector(p); err != nil {
			return fmt.Errorf("producer %q: %w", p.ID, err)
		}
	}
	return nil
}

func collectProducers(ctx context.Context, c backend.Backend, policy *report.Policy, rules []backend.Rule) ([]backend.ProducerEvidence, error) {
	if err := validateProducers(c, policy); err != nil {
		return nil, err
	}
	expectations := policy.ProducerExpectations()
	if len(expectations) == 0 {
		return nil, nil
	}
	provider := c.(backend.ProducerFreshnessProvider)
	evidence, err := provider.ProducerFreshnessEvidence(ctx, expectations, rules)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		out := make([]backend.ProducerEvidence, 0, len(expectations))
		for _, p := range expectations {
			out = append(out, backend.ProducerEvidence{ID: p.ID, Source: p.Source, Freshness: backend.FreshnessEvidence{Status: backend.EvidenceUnavailable, Detail: "producer measurements could not be read"}})
		}
		return out, nil
	}
	return evidence, nil
}
