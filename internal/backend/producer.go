package backend

import (
	"context"
	"time"
)

// ProducerExpectation describes an operator-declared feed, not a detection
// predicate. Match contains literal identity fields only.
type ProducerExpectation struct {
	ID       string
	Source   string
	Match    map[string]string
	Basis    FreshnessBasis
	MaxStale time.Duration
}

type ProducerEvidence struct {
	ID        string
	Source    string
	Freshness FreshnessEvidence
	// ConfirmedRules have a parser-proved filter that requires this feed's
	// identity. Other consumers of the table are not producer dependencies.
	ConfirmedRules []string
}

type ProducerFreshnessProvider interface {
	ProducerFreshnessEvidence(context.Context, []ProducerExpectation, []Rule) ([]ProducerEvidence, error)
}
