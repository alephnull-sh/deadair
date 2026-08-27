package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/alephnull-sh/deadair/internal/backend"
	"github.com/alephnull-sh/deadair/internal/state"
)

type stateIsolationBackend struct {
	source      backend.Source
	schema      backend.Schema
	schemaCalls int
}

func (b *stateIsolationBackend) Name() string { return "elastic" }

func (b *stateIsolationBackend) Rules(context.Context) ([]backend.Rule, error) {
	return []backend.Rule{{
		ID: "installed-rule", Name: "Installed rule", Enabled: true,
		Severity: "high", Patterns: []string{b.source.Name},
	}}, nil
}

func (b *stateIsolationBackend) Sources(context.Context) ([]backend.Source, error) {
	return []backend.Source{b.source}, nil
}

func (b *stateIsolationBackend) Schemas(context.Context, []backend.Source) (map[string]backend.Schema, error) {
	b.schemaCalls++
	return map[string]backend.Schema{b.source.Name: b.schema}, nil
}

func (b *stateIsolationBackend) ParseCandidates(context.Context, []byte) ([]backend.Rule, error) {
	return []backend.Rule{{
		ID: "candidate-rule", Name: "Candidate rule", Enabled: true,
		Severity: "high", Patterns: []string{"missing-*"},
	}}, nil
}

func (b *stateIsolationBackend) ResolveInputs(_ context.Context, rules []backend.Rule) ([]backend.InputResolution, error) {
	resolutions := make([]backend.InputResolution, 0, len(rules))
	for _, rule := range rules {
		resolution := backend.InputResolution{
			RuleID: rule.ID, Expression: strings.Join(rule.Patterns, ","),
			SelectorKind: "index_expression", ResolutionMethod: "test",
			ObservedAt: time.Now().UTC(), Status: backend.ResolutionResolved,
			ResolvedSources: []string{b.source.Name},
		}
		if len(rule.Patterns) == 1 && rule.Patterns[0] == "missing-*" {
			resolution.Status = backend.ResolutionEmpty
			resolution.ResolvedSources = nil
		}
		resolutions = append(resolutions, resolution)
	}
	return resolutions, nil
}

func TestCandidateStateDoesNotConsumeInstalledSourceHistory(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	const targetID = "target-prod"
	path := filepath.Join(t.TempDir(), "state.json")
	store := state.New()
	if err := store.BindTarget(targetID); err != nil {
		t.Fatal(err)
	}
	store.Sources["logs-app"] = state.SourceState{
		FirstSeen:       now.Add(-48 * time.Hour),
		LastSeen:        now.Add(-time.Hour),
		LastDocs:        100,
		VolumeLowStreak: 1,
		Buckets:         map[string][]float64{"baseline": {100, 101, 99, 100}},
		Schema: &state.SchemaState{
			LastSeen: now.Add(-time.Hour),
			Fields:   map[string][]string{"@timestamp": {"date"}},
		},
	}
	if err := store.Save(path); err != nil {
		t.Fatal(err)
	}
	before, err := state.Load(path)
	if err != nil {
		t.Fatal(err)
	}

	candidatePath := filepath.Join(t.TempDir(), "candidate.json")
	if err := os.WriteFile(candidatePath, []byte(`{"name":"candidate"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	probe := &stateIsolationBackend{
		source: backend.Source{Name: "logs-app", Docs: 150, LastEvent: now},
		schema: backend.Schema{Source: "logs-app", Fields: []backend.Field{
			{Name: "@timestamp", Types: []string{"date"}},
			{Name: "event.code", Types: []string{"keyword"}},
		}},
	}
	candidateOpts := connOpts{
		stateFile: path, schemaTrack: true, ruleFile: candidatePath,
		maxStale: time.Hour,
	}
	first, err := scanOnce(context.Background(), probe, candidateOpts, "prod", targetID)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.report.Findings) != 1 || first.report.Findings[0].Occurrences != 1 {
		t.Fatalf("first candidate lifecycle = %+v", first.report.Findings)
	}
	if first.report.Sources[0].Volume != nil || first.report.Sources[0].Schema != nil {
		t.Fatalf("candidate report contains installed source state: %+v", first.report.Sources[0])
	}
	if err := first.commitState(); err != nil {
		t.Fatal(err)
	}
	second, err := scanOnce(context.Background(), probe, candidateOpts, "prod", targetID)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.report.Findings) != 1 || second.report.Findings[0].Occurrences != 2 {
		t.Fatalf("second candidate lifecycle = %+v", second.report.Findings)
	}
	if err := second.commitState(); err != nil {
		t.Fatal(err)
	}
	if probe.schemaCalls != 0 {
		t.Fatalf("candidate scans read schema history %d time(s)", probe.schemaCalls)
	}
	afterCandidate, err := state.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(afterCandidate.Sources, before.Sources) {
		t.Fatalf("candidate changed source history:\nbefore=%+v\nafter=%+v", before.Sources, afterCandidate.Sources)
	}

	installedOpts := candidateOpts
	installedOpts.ruleFile = ""
	installed, err := scanOnce(context.Background(), probe, installedOpts, "prod", targetID)
	if err != nil {
		t.Fatal(err)
	}
	if probe.schemaCalls != 1 {
		t.Fatalf("installed scan schema calls = %d, want 1", probe.schemaCalls)
	}
	if len(installed.report.Sources) != 1 || installed.report.Sources[0].Schema == nil ||
		installed.report.Sources[0].Schema.Status != state.SchemaDrift {
		t.Fatalf("installed scan did not see preserved schema drift: %+v", installed.report.Sources)
	}
	if installed.report.Sources[0].Volume == nil || installed.store.Sources["logs-app"].LastDocs != 150 {
		t.Fatalf("installed scan did not advance its volume baseline: report=%+v state=%+v",
			installed.report.Sources[0].Volume, installed.store.Sources["logs-app"])
	}
}

func TestScanRejectsStateBoundToAnotherTarget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store := state.New()
	if err := store.BindTarget("target-a"); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(path); err != nil {
		t.Fatal(err)
	}
	probe := &stateIsolationBackend{
		source: backend.Source{Name: "logs-app", Docs: 1, LastEvent: time.Now().UTC()},
	}
	_, err := scanOnce(context.Background(), probe, connOpts{stateFile: path, maxStale: time.Hour}, "prod", "target-b")
	if err == nil || !strings.Contains(err.Error(), "belongs to target") {
		t.Fatalf("target mismatch error = %v", err)
	}
	loaded, loadErr := state.Load(path)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if loaded.TargetID != "target-a" {
		t.Fatalf("failed scan changed target binding to %q", loaded.TargetID)
	}
}

func TestScanRejectsUnsupportedStateVersionWithoutRewritingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	original := []byte("{\n  \"version\": 2,\n  \"sources\": [\"future-layout\"]\n}\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	probe := &stateIsolationBackend{
		source: backend.Source{Name: "logs-app", Docs: 1, LastEvent: time.Now().UTC()},
	}

	_, err := scanOnce(context.Background(), probe, connOpts{stateFile: path, maxStale: time.Hour}, "prod", "target-a")
	if err == nil || !strings.Contains(err.Error(), "unsupported state file version 2") ||
		!strings.Contains(err.Error(), "current version is 1") {
		t.Fatalf("scan state-version error = %v", err)
	}
	after, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(after) != string(original) {
		t.Fatalf("failed scan rewrote unsupported state:\nwant: %q\n got: %q", original, after)
	}
}

func TestScanRejectsNonObjectStateWithoutRewritingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	original := []byte(" \n null \t")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	probe := &stateIsolationBackend{
		source: backend.Source{Name: "logs-app", Docs: 1, LastEvent: time.Now().UTC()},
	}

	_, err := scanOnce(context.Background(), probe, connOpts{stateFile: path, maxStale: time.Hour}, "prod", "target-a")
	if err == nil || !strings.Contains(err.Error(), "malformed state file: top-level JSON value must be an object") {
		t.Fatalf("scan state-root error = %v", err)
	}
	after, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(after, original) {
		t.Fatalf("failed scan rewrote non-object state:\nwant: %q\n got: %q", original, after)
	}
}

var _ backend.Backend = (*stateIsolationBackend)(nil)
var _ backend.Resolver = (*stateIsolationBackend)(nil)
var _ backend.CandidateParser = (*stateIsolationBackend)(nil)
