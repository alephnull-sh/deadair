package report

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/alephnull-sh/deadair/internal/backend"
	"github.com/alephnull-sh/deadair/internal/graph"
	"github.com/alephnull-sh/deadair/internal/health"
	"github.com/alephnull-sh/deadair/internal/state"
)

func TestInvestigationGuidePoliciesLoad(t *testing.T) {
	data, err := os.ReadFile("../../docs/investigate.md")
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	for _, ending := range []string{"\n", "\r\n"} {
		t.Run(fmt.Sprintf("line ending %q", ending), func(t *testing.T) {
			blocks := regexp.MustCompile("(?s)```json\\r?\\n(.*?)\\r?\\n```").FindAllStringSubmatch(strings.ReplaceAll(text, "\n", ending), -1)
			count := 0
			for _, block := range blocks {
				body := block[1]
				if !strings.Contains(body, `"version"`) {
					continue // Downtime files have a separate format.
				}
				writePolicy(t, body, time.Now().UTC())
				count++
			}
			if count != 2 {
				t.Fatalf("checked %d policies, want 2", count)
			}
		})
	}
}

func writePolicy(t *testing.T, body string, now time.Time) *Policy {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := LoadPolicy(path, now)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func policyFixture(now time.Time, store *state.Store, p *Policy) *Report {
	g := graph.Build(
		[]backend.Rule{{ID: "logical-1", BackendObjectID: "saved-1", Name: "Rule", Enabled: true, Severity: "high", Patterns: []string{"logs-*"}}},
		[]backend.Source{{Name: "logs-prod", Docs: 10, LastEvent: now.Add(-45 * time.Minute)}},
	)
	return BuildWithOptions("elastic", g, BuildOptions{
		Check:  health.Check{MaxStale: 30 * time.Minute, Now: func() time.Time { return now }},
		Policy: p, Store: store, TargetID: "target-prod", Instance: "prod",
		ScanScope: ScanScope{Mode: "installed", Stateful: store != nil},
	})
}

func TestPolicySourceThresholdAndExpiredAcceptance(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	p := writePolicy(t, fmt.Sprintf(`{
  "version": 1,
  "severity_threshold": "high",
  "gate_classes": ["dead-detection", "source-degraded", "partial-input"],
  "sources": [{"pattern": "logs-*", "max_stale": "1h"}],
  "accepted": [{"finding_id": "unused-id", "reason": "migration", "expires_at": %q}]
}`, now.Add(-time.Hour).Format(time.RFC3339)), now)
	r := policyFixture(now, nil, p)
	if r.Summary.DegradedSources != 0 || r.Summary.DeadDetections != 0 {
		t.Fatalf("per-source max_stale was not applied: %+v", r.Summary)
	}
	if r.Policy == nil || r.Policy.AcceptedExpired != 1 {
		t.Fatalf("expired acceptance summary = %+v", r.Policy)
	}
}

func TestExpiredAcceptanceDoesNotSuppressGate(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	findingID := stableFindingID("target-prod", "prod", "elastic", FindingDead, "logical-1", ReasonStarved, "", "")
	p := writePolicy(t, fmt.Sprintf(`{
  "version": 1,
  "gate_classes": ["dead-detection"],
  "accepted": [{"finding_id": %q, "reason": "temporary migration", "expires_at": %q}]
}`, findingID, now.Add(-time.Minute).Format(time.RFC3339)), now)
	r := policyFixture(now, nil, p)
	var got *Finding
	for i := range r.Findings {
		if r.Findings[i].ID == findingID {
			got = &r.Findings[i]
		}
	}
	if got == nil || got.Accepted == nil || got.Accepted.Status != "expired" || !got.Gates {
		t.Fatalf("expired accepted finding = %+v", got)
	}
	if r.ExitCode() != ExitFindings {
		t.Fatalf("exit = %d, want findings", r.ExitCode())
	}
}

func TestActiveAcceptanceSuppressesGate(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	findingID := stableFindingID("target-prod", "prod", "elastic", FindingDead, "logical-1", ReasonStarved, "", "")
	p := writePolicy(t, fmt.Sprintf(`{
  "version": 1,
  "gate_classes": ["dead-detection"],
  "accepted": [{"finding_id": %q, "reason": "temporary migration", "expires_at": %q}]
}`, findingID, now.Add(time.Hour).Format(time.RFC3339)), now)
	r := policyFixture(now, nil, p)
	for _, finding := range r.Findings {
		if finding.ID == findingID {
			if finding.Accepted == nil || finding.Accepted.Status != "active" || finding.Gates {
				t.Fatalf("active accepted finding = %+v", finding)
			}
			if r.ExitCode() != ExitHealthy {
				t.Fatalf("exit = %d, want healthy", r.ExitCode())
			}
			return
		}
	}
	t.Fatal("accepted finding not found")
}

func TestFindingLifecycleAndIdentity(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	store := state.New()
	first := policyFixture(now, store, nil)
	second := policyFixture(now.Add(time.Minute), store, nil)
	if len(first.Findings) == 0 || len(second.Findings) == 0 {
		t.Fatal("expected findings")
	}
	byID := map[string]Finding{}
	for _, finding := range second.Findings {
		byID[finding.ID] = finding
	}
	for _, finding := range first.Findings {
		later, ok := byID[finding.ID]
		if !ok {
			t.Fatalf("finding ID changed across scans: %s", finding.ID)
		}
		if later.Occurrences != 2 || !later.FirstSeen.Equal(finding.FirstSeen) {
			t.Fatalf("lifecycle = %+v then %+v", finding, later)
		}
	}

	healthyGraph := graph.Build(
		[]backend.Rule{{ID: "logical-1", BackendObjectID: "saved-2", Name: "Rule", Enabled: true, Severity: "high", Patterns: []string{"logs-*"}}},
		[]backend.Source{{Name: "logs-prod", Docs: 10, LastEvent: now.Add(2 * time.Minute)}},
	)
	recovered := BuildWithOptions("elastic", healthyGraph, BuildOptions{
		Check: health.Check{MaxStale: 30 * time.Minute, Now: func() time.Time { return now.Add(2 * time.Minute) }},
		Store: store, TargetID: "target-prod", Instance: "prod",
		ScanScope: ScanScope{Mode: "installed", Stateful: true},
	})
	if len(recovered.RecoveredFindings) == 0 {
		t.Fatal("expected recovered findings")
	}
	for _, finding := range recovered.RecoveredFindings {
		if finding.RecoveredAt == nil {
			t.Fatalf("recovered finding lacks recovered_at: %+v", finding)
		}
	}
	// A new Elastic saved-object ID must not change logical finding identity.
	for _, finding := range first.Findings {
		if strings.Contains(finding.ID, "saved") {
			t.Fatalf("finding ID exposes storage identity: %s", finding.ID)
		}
	}
}

func TestFindingLifecycleIsolatedByScanScope(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	store := state.New()
	rule := backend.Rule{ID: "logical-1", Name: "Rule", Enabled: true, Severity: "high", Patterns: []string{"logs-*"}}
	stale := graph.Build([]backend.Rule{rule}, []backend.Source{{Name: "logs-prod", Docs: 10, LastEvent: now.Add(-time.Hour)}})
	installedScope := ScanScope{Mode: "installed", Stateful: true, ConfigurationID: "config-installed"}
	first := BuildWithOptions("elastic", stale, BuildOptions{
		Check: health.Check{MaxStale: 30 * time.Minute, Now: func() time.Time { return now }},
		Store: store, TargetID: "target-prod", Instance: "prod", ScanScope: installedScope,
	})
	if len(first.Findings) == 0 {
		t.Fatal("expected installed-scan findings")
	}

	candidate := BuildWithOptions("elastic", graph.Build([]backend.Rule{rule}, []backend.Source{{Name: "logs-prod", Docs: 10, LastEvent: now}}), BuildOptions{
		Check: health.Check{MaxStale: 30 * time.Minute, Now: func() time.Time { return now.Add(time.Minute) }},
		Store: store, TargetID: "target-prod", Instance: "prod", SkipUnused: true,
		ScanScope: ScanScope{Mode: "candidate", Stateful: true, ConfigurationID: "config-candidate", CandidateRuleIDs: []string{"logical-1"}},
	})
	if len(candidate.RecoveredFindings) != 0 {
		t.Fatalf("candidate scan recovered installed findings: %+v", candidate.RecoveredFindings)
	}

	recovered := BuildWithOptions("elastic", graph.Build([]backend.Rule{rule}, []backend.Source{{Name: "logs-prod", Docs: 10, LastEvent: now.Add(2 * time.Minute)}}), BuildOptions{
		Check: health.Check{MaxStale: 30 * time.Minute, Now: func() time.Time { return now.Add(2 * time.Minute) }},
		Store: store, TargetID: "target-prod", Instance: "prod", ScanScope: installedScope,
	})
	if len(recovered.RecoveredFindings) == 0 {
		t.Fatal("returning to the installed scope did not recover its prior findings")
	}
}

func TestPolicyRejectsMalformedInput(t *testing.T) {
	now := time.Now().UTC()
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"gate_classes":["unknown"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPolicy(path, now); err == nil {
		t.Fatal("unknown finding class was accepted")
	}
}
