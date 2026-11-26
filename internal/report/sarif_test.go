package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	redactpkg "github.com/alephnull-sh/deadair/internal/redact"
)

func TestWriteSARIFProducesValidV210AndHonorsRedaction(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	r := &Report{
		SchemaVersion: ReportSchemaVersion,
		GeneratedAt:   now,
		Producer:      Producer{Name: "deadair", Version: "v0.9.0-test"},
		Backend:       "elastic",
		Instance:      "prod-eu",
		TargetID:      "target-1234",
		Findings: []Finding{
			{
				ID:       "finding-dead-1",
				Class:    FindingDead,
				Reason:   ReasonDisconnected,
				RuleID:   "rule-secret-id",
				RuleName: "Secret Lateral Movement Rule",
				Severity: "high",
				Gates:    true,
			},
			{
				ID:         "finding-imp-1",
				Class:      FindingImpaired,
				Reason:     ReasonMissingFields,
				RuleID:     "rule-imp-id",
				RuleName:   "Impaired Process Rule",
				Severity:   "medium",
				Source:     "logs-secret-endpoint",
				Dependency: "process.command_line",
				Gates:      false,
				Accepted: &FindingAcceptance{
					Status:    "active",
					Reason:    "migration tracked in SEC-104",
					ExpiresAt: now.Add(24 * time.Hour),
				},
			},
		},
	}

	dir := t.TempDir()
	sarifPath := filepath.Join(dir, "unredacted.sarif")
	if err := r.WriteSARIFWithOptions(sarifPath, SARIFOptions{
		RuleLocations: map[string]string{"rule-secret-id": "./rules/windows/lateral.ndjson"},
	}); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(sarifPath)
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Fatalf("SARIF file mode = %o, want 0600", perm)
		}
	}

	raw, err := os.ReadFile(sarifPath)
	if err != nil {
		t.Fatal(err)
	}
	var parsed sarifLog
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("unmarshal SARIF: %v", err)
	}
	if parsed.Version != "2.1.0" || len(parsed.Runs) != 1 {
		t.Fatalf("unexpected SARIF header: %+v", parsed)
	}
	run := parsed.Runs[0]
	if run.Tool.Driver.Name != "deadair" || len(run.Tool.Driver.Rules) != 2 || len(run.Results) != 2 {
		t.Fatalf("unexpected SARIF run: %+v", run)
	}
	if run.Results[0].Level != "error" || run.Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI != "rules/windows/lateral.ndjson" {
		t.Fatalf("dead result = %+v", run.Results[0])
	}
	if run.Results[1].Level != "note" || len(run.Results[1].Suppressions) != 1 || run.Results[1].Suppressions[0].Status != "accepted" {
		t.Fatalf("accepted result = %+v", run.Results[1])
	}

	// Verify redaction strips raw names and suppresses local candidate file paths.
	r.RedactWith(redactpkg.Default())
	redactedBytes, err := r.SARIFBytes(SARIFOptions{
		RuleLocations: map[string]string{r.Findings[0].RuleID: "rules/secret-client/lateral.ndjson"},
	})
	if err != nil {
		t.Fatal(err)
	}
	text := string(redactedBytes)
	for _, secret := range []string{"Secret Lateral Movement Rule", "logs-secret-endpoint", "secret-client", "prod-eu"} {
		if strings.Contains(text, secret) {
			t.Fatalf("redacted SARIF leaked %q:\n%s", secret, text)
		}
	}
}
