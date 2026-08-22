package cli

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/alephnull-sh/deadair/internal/backend"
)

type aggregateDiagnosticBackend struct{}

func (aggregateDiagnosticBackend) Name() string { return "sentinel" }

func (aggregateDiagnosticBackend) Rules(context.Context) ([]backend.Rule, error) {
	return []backend.Rule{{ID: "rule-1", Name: "Rule 1", Enabled: true, Patterns: []string{"SecurityEvent"}}}, nil
}

func (aggregateDiagnosticBackend) Sources(context.Context) ([]backend.Source, error) {
	return []backend.Source{{Name: "SecurityEvent", Docs: -1}}, nil
}

func (aggregateDiagnosticBackend) Schemas(context.Context, []backend.Source) (map[string]backend.Schema, error) {
	return map[string]backend.Schema{"SecurityEvent": {Source: "SecurityEvent"}}, nil
}

func (aggregateDiagnosticBackend) ResolveInputs(_ context.Context, rules []backend.Rule) ([]backend.InputResolution, error) {
	if len(rules) == 0 || !rules[0].Enabled {
		return nil, nil
	}
	return []backend.InputResolution{
		{
			RuleID: rules[0].ID, Status: backend.ResolutionEmpty,
			ResolutionMethod: "kql+operational_insights_tables", ObservedAt: time.Now().UTC(),
		},
		{
			RuleID: rules[0].ID, Diagnostic: true, Selector: "MissingTable",
			Status: backend.ResolutionUnavailable, ResolutionMethod: "kql+operational_insights_tables", ObservedAt: time.Now().UTC(),
		},
	}, nil
}

func (aggregateDiagnosticBackend) ReadinessEvidence(context.Context, []backend.Rule, []backend.Source) (backend.ReadinessEvidence, error) {
	return backend.ReadinessEvidence{Status: backend.EvidenceAssessed, Attempted: true}, nil
}

type readinessProbeBackend struct {
	aggregateDiagnosticBackend
	evidence backend.ReadinessEvidence
	err      error
}

func (b readinessProbeBackend) ReadinessEvidence(context.Context, []backend.Rule, []backend.Source) (backend.ReadinessEvidence, error) {
	return b.evidence, b.err
}

func TestReadinessProbeIgnoresDiagnosticResolutionRows(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCheckWithTargets(nil, &stdout, &stderr, func(*connOpts, io.Writer) ([]fleetInstance, error) {
		return []fleetInstance{{name: "sentinel-lab", backend: aggregateDiagnosticBackend{}}}, nil
	})
	if code != 0 || !strings.HasPrefix(stdout.String(), "READY\n") {
		t.Fatalf("diagnostic evidence blocked readiness: exit %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "native input resolution readable (missing sources can be proved)") {
		t.Fatalf("authoritative probe result missing from readiness output:\n%s", stdout.String())
	}
}

func TestReadinessASIMQueryDenialBlocksCheck(t *testing.T) {
	var stdout, stderr bytes.Buffer
	probe := readinessProbeBackend{evidence: backend.ReadinessEvidence{
		Status: backend.EvidenceUnavailable, Attempted: true, Detail: "403 Sentinel ASIM parser query access is unavailable",
	}}
	code := runCheckWithTargets(nil, &stdout, &stderr, func(*connOpts, io.Writer) ([]fleetInstance, error) {
		return []fleetInstance{{name: "sentinel-lab", backend: probe}}, nil
	})
	if code != 2 || !strings.HasPrefix(stdout.String(), "BLOCKED\n") {
		t.Fatalf("denied runtime probe: exit %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "runtime query path not readable") {
		t.Fatalf("runtime probe failure missing:\n%s", stdout.String())
	}
}

func TestReadinessASIMSemanticLimitDoesNotBlockCheck(t *testing.T) {
	var stdout, stderr bytes.Buffer
	probe := readinessProbeBackend{evidence: backend.ReadinessEvidence{
		Status: backend.EvidenceAssessed, Attempted: true, Limited: true,
		Detail: "Sentinel ASIM parser read path was reached, but resolution is unsupported: partial result",
	}}
	code := runCheckWithTargets(nil, &stdout, &stderr, func(*connOpts, io.Writer) ([]fleetInstance, error) {
		return []fleetInstance{{name: "sentinel-lab", backend: probe}}, nil
	})
	if code != 0 || !strings.HasPrefix(stdout.String(), "READY WITH LIMITS\n") {
		t.Fatalf("limited ASIM runtime probe: exit %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "runtime query path readable with limits") ||
		strings.Contains(stdout.String(), "runtime query path not readable") {
		t.Fatalf("limited runtime probe was described incorrectly:\n%s", stdout.String())
	}
}

func TestReadinessWithoutEligibleTableIsLimited(t *testing.T) {
	var stdout, stderr bytes.Buffer
	probe := readinessProbeBackend{evidence: backend.ReadinessEvidence{
		Status: backend.EvidenceUnavailable, Detail: "no query-eligible Analytics table was visible",
	}}
	code := runCheckWithTargets(nil, &stdout, &stderr, func(*connOpts, io.Writer) ([]fleetInstance, error) {
		return []fleetInstance{{name: "sentinel-lab", backend: probe}}, nil
	})
	if code != 0 || !strings.HasPrefix(stdout.String(), "READY WITH LIMITS\n") {
		t.Fatalf("no eligible table: exit %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
}
