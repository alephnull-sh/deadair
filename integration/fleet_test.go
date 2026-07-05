//go:build integration

// Fleet proof: one scan spanning BOTH live backends at once — the claim the
// single-backend suites cannot make — plus the tenant-failure path.
// Run: make fleet-integration (boots both stacks).
package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Big-Comfy/deadair/internal/cli"
	"github.com/Big-Comfy/deadair/internal/report"
)

func TestFleetCrossBackend(t *testing.T) {
	waitForStack(t)
	waitForOpenSearch(t)
	cleanup(t)
	cleanupOpenSearch(t)
	t.Cleanup(func() { cleanup(t); cleanupOpenSearch(t) })
	seed(t)
	provisionOpenSearchReadUser(t)
	seedOpenSearch(t)
	key := provision(t)

	dir := t.TempDir()
	keyFile := filepath.Join(dir, "es-key")
	os.WriteFile(keyFile, []byte(key), 0o600)
	t.Setenv("DEADAIR_IT_OS_PASSWORD", openSearchReadPass)

	cfg := filepath.Join(dir, "fleet.json")
	os.WriteFile(cfg, []byte(fmt.Sprintf(`{"instances":[
		{"name":"acme-elastic","backend":"elastic","es_url":%q,"kibana_url":%q,"api_key_file":%q},
		{"name":"beta-opensearch","backend":"opensearch","opensearch_url":%q,"username":%q,"password_env":"DEADAIR_IT_OS_PASSWORD"}
	]}`, esURL, kbURL, keyFile, openSearchURL, openSearchReadUser)), 0o600)

	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"scan", "--fleet", cfg, "--json", "--max-stale", "1h"}, &stdout, &stderr)
	if code != report.ExitFindings {
		t.Fatalf("fleet exit = %d, want 1; stderr: %s", code, stderr.String())
	}
	var f report.FleetReport
	if err := json.Unmarshal(stdout.Bytes(), &f); err != nil {
		t.Fatal(err)
	}
	if f.Summary.Instances != 2 || f.Summary.InstancesFailed != 0 {
		t.Fatalf("summary = %+v", f.Summary)
	}
	byName := map[string]*report.Report{}
	for _, r := range f.Instances {
		byName[r.Instance] = r
	}
	if byName["acme-elastic"] == nil || byName["acme-elastic"].Backend != "elastic" {
		t.Fatalf("elastic instance missing/wrong: %+v", f.Instances)
	}
	if byName["beta-opensearch"] == nil || byName["beta-opensearch"].Backend != "opensearch" {
		t.Fatalf("opensearch instance missing/wrong: %+v", f.Instances)
	}
	if byName["acme-elastic"].Summary.DeadDetections == 0 || byName["beta-opensearch"].Summary.DeadDetections == 0 {
		t.Fatalf("both tenants should have dead detections: %+v / %+v",
			byName["acme-elastic"].Summary, byName["beta-opensearch"].Summary)
	}

	// Tenant-failure path: an unreachable third tenant exits 2 but must not
	// hide the two healthy ones.
	cfgBad := filepath.Join(dir, "fleet-bad.json")
	os.WriteFile(cfgBad, []byte(fmt.Sprintf(`{"instances":[
		{"name":"acme-elastic","backend":"elastic","es_url":%q,"kibana_url":%q,"api_key_file":%q},
		{"name":"beta-opensearch","backend":"opensearch","opensearch_url":%q,"username":%q,"password_env":"DEADAIR_IT_OS_PASSWORD"},
		{"name":"gamma-down","backend":"elastic","es_url":"http://127.0.0.1:1","kibana_url":"http://127.0.0.1:1","api_key_file":%q}
	]}`, esURL, kbURL, keyFile, openSearchURL, openSearchReadUser, keyFile)), 0o600)

	stdout.Reset()
	stderr.Reset()
	code = cli.Run([]string{"scan", "--fleet", cfgBad, "--json", "--max-stale", "1h"}, &stdout, &stderr)
	if code != report.ExitError {
		t.Fatalf("fleet with dead tenant exit = %d, want 2", code)
	}
	var f2 report.FleetReport
	if err := json.Unmarshal(stdout.Bytes(), &f2); err != nil {
		t.Fatal(err)
	}
	if len(f2.Instances) != 2 || len(f2.Errors) != 1 || f2.Errors[0].Instance != "gamma-down" {
		t.Fatalf("failure isolation wrong: %d instances, errors %+v", len(f2.Instances), f2.Errors)
	}

	// Redacted fleet output leaks no tenant names.
	stdout.Reset()
	code = cli.Run([]string{"scan", "--fleet", cfg, "--json", "--redact", "--max-stale", "1h"}, &stdout, &stderr)
	if code != report.ExitFindings {
		t.Fatalf("redacted fleet exit = %d; stderr: %s", code, stderr.String())
	}
	for _, leak := range []string{"acme-elastic", "beta-opensearch", "deadairtest", "deadair-os"} {
		if strings.Contains(stdout.String(), leak) {
			t.Fatalf("redacted fleet output leaks %q", leak)
		}
	}
}
