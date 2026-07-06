//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Big-Comfy/deadair/internal/cli"
	"github.com/Big-Comfy/deadair/internal/report"
)

func TestMSSPLab(t *testing.T) {
	waitForStack(t)
	waitForOpenSearch(t)
	cleanup(t)
	cleanupOpenSearch(t)
	t.Cleanup(func() { cleanup(t); cleanupOpenSearch(t) })
	seed(t)
	provisionOpenSearchReadUser(t)
	seedOpenSearch(t)
	key := provision(t)

	outDir := envOr("DEADAIR_MSSP_LAB_OUT", filepath.Join("mssp-lab-out"))
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		t.Fatalf("creating lab output directory: %v", err)
	}
	cleanLabArtifacts(t, outDir)

	secretDir := filepath.Join(outDir, "secrets")
	if err := os.MkdirAll(secretDir, 0o700); err != nil {
		t.Fatalf("creating lab secret directory: %v", err)
	}
	keyFile := filepath.Join(secretDir, "acme-elastic-api-key")
	writeLabFile(t, keyFile, key)
	badKeyFile := filepath.Join(secretDir, "charlie-bad-api-key")
	writeLabFile(t, badKeyFile, "bad-api-key")
	osPassFile := filepath.Join(secretDir, "beta-opensearch-password")
	writeLabFile(t, osPassFile, openSearchReadPass)
	badOSPassFile := filepath.Join(secretDir, "echo-bad-opensearch-password")
	writeLabFile(t, badOSPassFile, "bad-password")

	fleetFile := filepath.Join(outDir, "fleet.json")
	fleet := fmt.Sprintf(`{"instances":[
  {"name":"acme-elastic","backend":"elastic","es_url":%q,"kibana_url":%q,"api_key_file":%q},
  {"name":"beta-opensearch","backend":"opensearch","opensearch_url":%q,"username":%q,"password_file":%q},
  {"name":"charlie-bad-key","backend":"elastic","es_url":%q,"kibana_url":%q,"api_key_file":%q},
  {"name":"delta-down","backend":"elastic","es_url":"http://127.0.0.1:1","kibana_url":"http://127.0.0.1:1","api_key_file":%q},
  {"name":"echo-bad-password","backend":"opensearch","opensearch_url":%q,"username":%q,"password_file":%q}
]}`, esURL, kbURL, keyFile, openSearchURL, openSearchReadUser, osPassFile, esURL, kbURL, badKeyFile, keyFile, openSearchURL, openSearchReadUser, badOSPassFile)
	writeLabFile(t, fleetFile, fleet)

	now := time.Now().UTC()
	downtimeFile := filepath.Join(outDir, "downtime.json")
	downtime := fmt.Sprintf(`{"windows":[{"name":"lab patch window","sources":["%s","%s"],"start":%q,"end":%q,"timezone":"UTC"}]}`,
		staleIndex, openSearchStaleIndex, now.Add(-time.Hour).Format("15:04"), now.Add(time.Hour).Format("15:04"))
	writeLabFile(t, downtimeFile, downtime)

	checkCode, checkOut, checkErr := runLabCLI([]string{"check", "--fleet", fleetFile, "--timeout", "10s"})
	writeLabFile(t, filepath.Join(outDir, "check.txt"), labCommandOutput(checkCode, checkOut, checkErr))
	if checkCode != report.ExitError {
		t.Fatalf("check --fleet exit = %d, want 2 for bad lab tenants", checkCode)
	}
	for _, want := range []string{"acme-elastic (elastic)", "beta-opensearch (opensearch)", "charlie-bad-key", "delta-down", "echo-bad-password"} {
		if !strings.Contains(checkOut, want) {
			t.Fatalf("check output missing %q:\n%s", want, checkOut)
		}
	}

	statePrefix := filepath.Join(outDir, "state.json")
	baselineFile := filepath.Join(outDir, "fleet-baseline-redacted.json")
	baselineCode, _, baselineErr := runLabCLI([]string{
		"scan", "--fleet", fleetFile,
		"--max-stale", "1h",
		"--state-file", statePrefix,
		"--schema",
		"--downtime-file", downtimeFile,
		"--redact",
		"--json",
		"--out", baselineFile,
	})
	if baselineCode != report.ExitError {
		t.Fatalf("baseline fleet scan exit = %d, want 2 for bad lab tenants; stderr: %s", baselineCode, baselineErr)
	}

	admin(t, http.MethodPost, esURL+"/"+liveStream+"/_doc",
		fmt.Sprintf(`{"@timestamp":%q,"message":"schema drift","lab_new_field":"new"}`, time.Now().UTC().Format(time.RFC3339)), http.StatusCreated)
	admin(t, http.MethodPost, esURL+"/_refresh", "", http.StatusOK)

	finalFile := filepath.Join(outDir, "fleet-redacted.json")
	finalCode, finalOut, finalErr := runLabCLI([]string{
		"scan", "--fleet", fleetFile,
		"--max-stale", "1h",
		"--state-file", statePrefix,
		"--schema",
		"--downtime-file", downtimeFile,
		"--redact",
		"--out", finalFile,
	})
	writeLabFile(t, filepath.Join(outDir, "fleet-summary.txt"), labCommandOutput(finalCode, finalOut, finalErr))
	if finalCode != report.ExitError {
		t.Fatalf("final fleet scan exit = %d, want 2 for bad lab tenants; stderr: %s", finalCode, finalErr)
	}
	finalData, err := os.ReadFile(finalFile)
	if err != nil {
		t.Fatalf("reading final fleet report: %v", err)
	}
	var fleetReport report.FleetReport
	if err := json.Unmarshal(finalData, &fleetReport); err != nil {
		t.Fatalf("parsing final fleet report: %v", err)
	}
	if !fleetReport.Redacted || fleetReport.Summary.Instances != 5 || fleetReport.Summary.InstancesFailed != 3 || len(fleetReport.Instances) != 2 || len(fleetReport.Errors) != 3 {
		t.Fatalf("unexpected final fleet shape: summary=%+v instances=%d errors=%d redacted=%v",
			fleetReport.Summary, len(fleetReport.Instances), len(fleetReport.Errors), fleetReport.Redacted)
	}
	if !fleetHasSchemaDrift(&fleetReport) {
		t.Fatalf("final fleet report did not show schema drift after lab_new_field mutation")
	}
	if !fleetHasMaintenance(&fleetReport) {
		t.Fatalf("final fleet report did not show expected downtime maintenance sources")
	}
	assertNoLabLeaks(t, finalData)

	writeLabReadme(t, outDir)
	runLabExporter(t, outDir, fleetFile, downtimeFile)
	t.Logf("MSSP lab artifacts written to %s", outDir)
}

func cleanLabArtifacts(t *testing.T, outDir string) {
	t.Helper()
	names := []string{
		"check.txt",
		"downtime.json",
		"exporter-stderr.txt",
		"fleet-baseline-redacted.json",
		"fleet-redacted.json",
		"fleet-summary.txt",
		"fleet.json",
		"lab-readme.md",
		"metrics.txt",
	}
	for _, name := range names {
		if err := os.Remove(filepath.Join(outDir, name)); err != nil && !os.IsNotExist(err) {
			t.Fatalf("removing old lab artifact %s: %v", name, err)
		}
	}
	for _, pattern := range []string{"state.json.*", "serve-state.json.*"} {
		matches, err := filepath.Glob(filepath.Join(outDir, pattern))
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range matches {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				t.Fatalf("removing old lab state %s: %v", path, err)
			}
		}
	}
}

func writeLabFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

func runLabCLI(args []string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := cli.Run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func labCommandOutput(code int, stdout, stderr string) string {
	return fmt.Sprintf("exit: %d\n\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
}

func fleetHasSchemaDrift(f *report.FleetReport) bool {
	for _, inst := range f.Instances {
		if inst.Summary.SchemaDriftSources > 0 {
			return true
		}
	}
	return false
}

func fleetHasMaintenance(f *report.FleetReport) bool {
	for _, inst := range f.Instances {
		for _, src := range inst.Sources {
			if src.ExpectedDowntime && src.Status == "maintenance" {
				return true
			}
		}
	}
	return false
}

func assertNoLabLeaks(t *testing.T, data []byte) {
	t.Helper()
	body := string(data)
	for _, leak := range []string{
		"acme-elastic",
		"beta-opensearch",
		"charlie-bad-key",
		"delta-down",
		"echo-bad-password",
		"deadairtest",
		"deadair-os",
		"Deadair IT",
		"Deadair OS",
		"lab_new_field",
		openSearchReadPass,
	} {
		if strings.Contains(body, leak) {
			t.Fatalf("redacted lab report leaks %q", leak)
		}
	}
}

func writeLabReadme(t *testing.T, outDir string) {
	t.Helper()
	body := `# deadair MSSP lab output

Generated by ` + "`make mssp-lab`" + `.

Files:

- ` + "`fleet.json`" + `: five-instance lab fleet: Elastic, OpenSearch, bad Elastic key, unreachable tenant, bad OpenSearch password.
- ` + "`downtime.json`" + `: active maintenance window for stale lab sources.
- ` + "`check.txt`" + `: ` + "`deadair check --fleet`" + ` output.
- ` + "`fleet-baseline-redacted.json`" + `: first redacted scan, used to warm schema snapshots.
- ` + "`fleet-redacted.json`" + `: second redacted scan after an Elastic schema mutation.
- ` + "`fleet-summary.txt`" + `: terminal fleet summary for the second scan.
- ` + "`metrics.txt`" + `: one scrape from ` + "`deadair serve --fleet --redact`" + `.
- ` + "`state.json.*`" + ` and ` + "`serve-state.json.*`" + `: per-instance state files for successful tenants.

The lab deliberately leaves three tenants failing so the report and metrics show partial-fleet
failure handling.
`
	writeLabFile(t, filepath.Join(outDir, "lab-readme.md"), body)
}

func runLabExporter(t *testing.T, outDir, fleetFile, downtimeFile string) {
	t.Helper()
	binary := envOr("DEADAIR_MSSP_LAB_BINARY", filepath.Join("..", "bin", "deadair"))
	if _, err := os.Stat(binary); err != nil {
		t.Fatalf("MSSP lab binary %q is not available: %v", binary, err)
	}
	addr := envOr("DEADAIR_MSSP_LAB_METRICS_ADDR", "127.0.0.1:19317")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, binary,
		"serve",
		"--fleet", fleetFile,
		"--max-stale", "1h",
		"--state-file", filepath.Join(outDir, "serve-state.json"),
		"--schema",
		"--downtime-file", downtimeFile,
		"--redact",
		"--interval", "1h",
		"--bind", addr,
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting exporter: %v", err)
	}
	metrics, err := waitForLabMetrics("http://" + addr + "/metrics")
	cancel()
	if waitErr := cmd.Wait(); waitErr != nil && ctx.Err() == nil {
		t.Fatalf("exporter exited unexpectedly: %v\nstderr:\n%s", waitErr, stderr.String())
	}
	assertNoLabLeaks(t, stderr.Bytes())
	writeLabFile(t, filepath.Join(outDir, "exporter-stderr.txt"), stderr.String())
	if err != nil {
		t.Fatalf("scraping lab exporter: %v\nstderr:\n%s", err, stderr.String())
	}
	for _, want := range []string{`deadair_up 0`, `deadair_instance_up`, `deadair_source_schema_drift`} {
		if !strings.Contains(metrics, want) {
			t.Fatalf("metrics missing %q:\n%s", want, metrics)
		}
	}
	assertNoLabLeaks(t, []byte(metrics))
	writeLabFile(t, filepath.Join(outDir, "metrics.txt"), metrics)
}

func waitForLabMetrics(url string) (string, error) {
	deadline := time.Now().Add(30 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err != nil {
			lastErr = err
			time.Sleep(500 * time.Millisecond)
			continue
		}
		data, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			return "", readErr
		}
		body := string(data)
		if resp.StatusCode == http.StatusOK && strings.Contains(body, "deadair_instance_up") {
			return body, nil
		}
		lastErr = fmt.Errorf("metrics not ready: status %d", resp.StatusCode)
		time.Sleep(500 * time.Millisecond)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("metrics not ready before timeout")
	}
	return "", lastErr
}
