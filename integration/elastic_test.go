//go:build integration

// These tests prove the least-privilege role manifest
// from docs/credentials/elastic.md must let a scan succeed against a live
// Elastic stack, verdicts must be correct on real data, and every write
// attempted with the deadair credential must be rejected.
//
// Run: make integration   (starts integration/docker-compose.yml first)
package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Big-Comfy/deadair/internal/cli"
	"github.com/Big-Comfy/deadair/internal/report"
)

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

var (
	esURL  = envOr("DEADAIR_IT_ES_URL", "http://localhost:9200")
	kbURL  = envOr("DEADAIR_IT_KIBANA_URL", "http://localhost:5601")
	esPass = envOr("DEADAIR_IT_PASSWORD", "changeme-deadair")
)

// deadairRole is the least-privilege manifest under proof — keep in sync with
// docs/credentials/elastic.md. feature_siem is the pre-8.17 privilege id,
// feature_siemV2 the granular replacement; granting both covers the 8.x line.
const deadairRole = `{
  "cluster": ["monitor"],
  "indices": [
    {"names": ["*"], "privileges": ["monitor", "view_index_metadata", "read"]}
  ],
  "applications": [
    {"application": "kibana-.kibana", "privileges": ["feature_siem.read", "feature_siemV2.read", "feature_indexPatterns.read"], "resources": ["space:default"]}
  ]
}`

const (
	liveStream = "logs-deadairtest-default"
	staleIndex = "deadairtest-stale"
	emptyIndex = "deadairtest-empty"
	driftIndex = "deadairtest-drift"
	dataViewID = "deadair-it-data-view"
)

type httpResult struct {
	status int
	body   []byte
}

func call(t *testing.T, method, url, body string, auth func(*http.Request)) httpResult {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	auth(req)
	req.Header.Set("kbn-xsrf", "deadair-it")
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("%s %s: reading body: %v", method, url, err)
	}
	return httpResult{resp.StatusCode, data}
}

func asAdmin(req *http.Request) { req.SetBasicAuth("elastic", esPass) }

func apiKeyAuth(key string) func(*http.Request) {
	return func(req *http.Request) { req.Header.Set("Authorization", "ApiKey "+key) }
}

// admin performs a request as the superuser and fails the test on an
// unexpected status.
func admin(t *testing.T, method, url, body string, wantStatus int) []byte {
	t.Helper()
	res := call(t, method, url, body, asAdmin)
	if res.status != wantStatus {
		t.Fatalf("%s %s: status %d (want %d): %s", method, url, res.status, wantStatus, res.body)
	}
	return res.body
}

func probe(url string) bool {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	asAdmin(req)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode == http.StatusOK
}

func waitForStack(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(4 * time.Minute)
	for {
		esUp := probe(esURL + "/_cluster/health")
		kbUp := probe(kbURL + "/api/status")
		if esUp && kbUp {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("stack not ready (elasticsearch=%v kibana=%v) — run `make integration-up` first", esUp, kbUp)
		}
		time.Sleep(3 * time.Second)
	}
}

// cleanup removes every fixture; statuses are ignored so it is safe to run
// against a clean cluster and as leftover-removal before seeding.
func cleanup(t *testing.T) {
	t.Helper()
	for _, ruleID := range []string{
		"deadair-it-live", "deadair-it-starved", "deadair-it-disconnected",
		"deadair-it-alias", "deadair-it-exclusion", "deadair-it-data-view",
	} {
		call(t, http.MethodDelete, kbURL+"/api/detection_engine/rules?rule_id="+ruleID, "", asAdmin)
	}
	call(t, http.MethodDelete, kbURL+"/api/data_views/data_view/"+dataViewID, "", asAdmin)
	call(t, http.MethodDelete, esURL+"/_data_stream/"+liveStream, "", asAdmin)
	call(t, http.MethodDelete, esURL+"/"+staleIndex, "", asAdmin)
	call(t, http.MethodDelete, esURL+"/"+emptyIndex, "", asAdmin)
	call(t, http.MethodDelete, esURL+"/_security/role/deadair_monitor", "", asAdmin)
	call(t, http.MethodDelete, esURL+"/_security/api_key", `{"name":"deadair-it","owner":false}`, asAdmin)
}

func seed(t *testing.T) {
	t.Helper()
	now := time.Now().UTC()

	// live data stream — created automatically by the built-in logs-*-* template
	admin(t, http.MethodPost, esURL+"/"+liveStream+"/_doc",
		fmt.Sprintf(`{"@timestamp":%q,"message":"live"}`, now.Format(time.RFC3339)), http.StatusCreated)
	// stale plain index — newest event three days old
	admin(t, http.MethodPut, esURL+"/"+staleIndex,
		`{"mappings":{"properties":{"@timestamp":{"type":"date"}}}}`, http.StatusOK)
	admin(t, http.MethodPost, esURL+"/"+staleIndex+"/_doc",
		fmt.Sprintf(`{"@timestamp":%q,"message":"old"}`, now.Add(-72*time.Hour).Format(time.RFC3339)), http.StatusCreated)
	admin(t, http.MethodPost, esURL+"/_aliases",
		fmt.Sprintf(`{"actions":[{"add":{"index":%q,"alias":"deadairtest-stale-alias"}}]}`, staleIndex), http.StatusOK)
	// empty index — exists, holds nothing
	admin(t, http.MethodPut, esURL+"/"+emptyIndex,
		`{"mappings":{"properties":{"@timestamp":{"type":"date"}}}}`, http.StatusOK)
	admin(t, http.MethodPost, esURL+"/_refresh", "", http.StatusOK)
	admin(t, http.MethodPost, kbURL+"/api/data_views/data_view",
		fmt.Sprintf(`{"data_view":{"id":%q,"name":"Deadair integration data view","title":"logs-deadairtest-*"},"override":true}`, dataViewID),
		http.StatusOK)

	rules := []struct{ id, name, severity, index string }{
		{"deadair-it-live", "Deadair IT live rule", "low", `["logs-deadairtest-*"]`},
		{"deadair-it-starved", "Deadair IT starved rule", "high", `["deadairtest-stale*"]`},
		{"deadair-it-disconnected", "Deadair IT disconnected rule", "medium", `["deadairtest-missing-*"]`},
		{"deadair-it-alias", "Deadair IT alias rule", "high", `["deadairtest-stale-alias"]`},
		{"deadair-it-exclusion", "Deadair IT exclusion rule", "low", `["logs-deadairtest-*","-logs-deadairtest-never-*"]`},
	}
	for _, r := range rules {
		body := fmt.Sprintf(
			`{"rule_id":%q,"name":%q,"description":"deadair integration fixture","risk_score":42,"severity":%q,"type":"query","query":"*:*","language":"kuery","index":%s,"interval":"5m","from":"now-6m","enabled":true}`,
			r.id, r.name, r.severity, r.index)
		admin(t, http.MethodPost, kbURL+"/api/detection_engine/rules", body, http.StatusOK)
	}
	admin(t, http.MethodPost, kbURL+"/api/detection_engine/rules",
		fmt.Sprintf(`{"rule_id":"deadair-it-data-view","name":"Deadair IT data view rule","description":"deadair integration fixture","risk_score":42,"severity":"low","type":"query","query":"*:*","language":"kuery","data_view_id":%q,"interval":"5m","from":"now-6m","enabled":true}`, dataViewID),
		http.StatusOK)
}

// provision validates the role manifest against the live cluster and mints an
// API key restricted to exactly that role.
func provision(t *testing.T) string {
	t.Helper()
	admin(t, http.MethodPut, esURL+"/_security/role/deadair_monitor", deadairRole, http.StatusOK)
	body := fmt.Sprintf(`{"name":"deadair-it","role_descriptors":{"deadair_monitor":%s}}`, deadairRole)
	resp := admin(t, http.MethodPost, esURL+"/_security/api_key", body, http.StatusOK)
	var out struct {
		Encoded string `json:"encoded"`
	}
	if err := json.Unmarshal(resp, &out); err != nil || out.Encoded == "" {
		t.Fatalf("api key response unusable: %v: %s", err, resp)
	}
	return out.Encoded
}

// cleanupDrift removes the schema-drift fixtures and the provisioned role/key.
func cleanupDrift(t *testing.T) {
	t.Helper()
	for _, id := range []string{"deadair-it-drift", "deadair-it-nodrift"} {
		call(t, http.MethodDelete, kbURL+"/api/detection_engine/rules?rule_id="+id, "", asAdmin)
	}
	call(t, http.MethodDelete, esURL+"/"+driftIndex, "", asAdmin)
	call(t, http.MethodDelete, esURL+"/_security/role/deadair_monitor", "", asAdmin)
	call(t, http.MethodDelete, esURL+"/_security/api_key", `{"name":"deadair-it","owner":false}`, asAdmin)
}

// TestElasticMissingFields validates the schema-drift check end to end against a
// live cluster: a source mapping that carries process.name but not
// process.command_line, and a rule that declares both as required_fields. The
// tool must flag the rule for exactly the missing field, proven through real
// field_caps rather than a mock. The control rule declares only a field that
// exists and must not be flagged, which also pins the honest limit that only
// declared required_fields are checked (the query body is never parsed).
func TestElasticMissingFields(t *testing.T) {
	waitForStack(t)
	cleanupDrift(t)
	t.Cleanup(func() { cleanupDrift(t) })

	now := time.Now().UTC()
	// mapping declares process.name but not process.command_line — the real
	// "a field the rule filters on quietly left the mapping" case.
	admin(t, http.MethodPut, esURL+"/"+driftIndex,
		`{"mappings":{"properties":{"@timestamp":{"type":"date"},"process":{"properties":{"name":{"type":"keyword"}}}}}}`, http.StatusOK)
	admin(t, http.MethodPost, esURL+"/"+driftIndex+"/_doc",
		fmt.Sprintf(`{"@timestamp":%q,"process":{"name":"bash"}}`, now.Format(time.RFC3339)), http.StatusCreated)
	admin(t, http.MethodPost, esURL+"/_refresh", "", http.StatusOK)

	// drift rule declares a field the mapping no longer carries -> must be flagged.
	admin(t, http.MethodPost, kbURL+"/api/detection_engine/rules",
		`{"rule_id":"deadair-it-drift","name":"Deadair IT drift rule","description":"deadair integration fixture","risk_score":42,"severity":"medium","type":"query","query":"*:*","language":"kuery","index":["deadairtest-drift*"],"interval":"5m","from":"now-6m","enabled":true,"required_fields":[{"name":"process.name","type":"keyword"},{"name":"process.command_line","type":"keyword"}]}`,
		http.StatusOK)
	// control rule declares only a field that exists -> must not be flagged.
	admin(t, http.MethodPost, kbURL+"/api/detection_engine/rules",
		`{"rule_id":"deadair-it-nodrift","name":"Deadair IT nodrift rule","description":"deadair integration fixture","risk_score":42,"severity":"medium","type":"query","query":"*:*","language":"kuery","index":["deadairtest-drift*"],"interval":"5m","from":"now-6m","enabled":true,"required_fields":[{"name":"process.name","type":"keyword"}]}`,
		http.StatusOK)

	key := provision(t)
	t.Setenv("DEADAIR_API_KEY", key)

	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{
		"scan", "--es-url", esURL, "--kibana-url", kbURL, "--json",
		"--max-stale", "1h", "--schema",
		"--state-file", filepath.Join(t.TempDir(), "state.json"),
	}, &stdout, &stderr)
	if code != report.ExitFindings {
		t.Fatalf("exit = %d, want %d\nstderr: %s", code, report.ExitFindings, stderr.String())
	}
	var rep report.Report
	if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
		t.Fatalf("parsing report: %v", err)
	}

	byName := map[string]report.ImpairedDetection{}
	for _, d := range rep.ImpairedDetections {
		byName[d.Name] = d
	}
	drift, ok := byName["Deadair IT drift rule"]
	if !ok {
		t.Fatalf("drift rule not impaired; impaired = %+v", rep.ImpairedDetections)
	}
	if len(drift.MissingFields) != 1 || drift.MissingFields[0] != "process.command_line" {
		t.Errorf("drift MissingFields = %v, want [process.command_line]", drift.MissingFields)
	}
	if d, ok := byName["Deadair IT nodrift rule"]; ok {
		for _, r := range d.Reasons {
			if r == report.ReasonMissingFields {
				t.Errorf("control rule wrongly flagged for missing fields: %+v", d)
			}
		}
	}
}

func TestElasticReadOnlyScan(t *testing.T) {
	waitForStack(t)
	cleanup(t) // clear leftovers from any previous run
	t.Cleanup(func() { cleanup(t) })
	seed(t)
	key := provision(t)
	t.Setenv("DEADAIR_API_KEY", key)

	var rep report.Report
	t.Run("scan succeeds with least-privilege key", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := cli.Run([]string{
			"scan",
			"--es-url", esURL,
			"--kibana-url", kbURL,
			"--json",
			"--max-stale", "1h",
			"--state-file", filepath.Join(t.TempDir(), "state.json"),
			"--schema",
		}, &stdout, &stderr)
		if code != report.ExitFindings {
			t.Fatalf("exit = %d, want %d\nstderr: %s\nstdout: %s", code, report.ExitFindings, stderr.String(), stdout.String())
		}
		if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
			t.Fatalf("parsing report: %v", err)
		}
	})

	t.Run("verdicts are correct on live data", func(t *testing.T) {
		if rep.GeneratedAt.IsZero() {
			t.Skip("scan did not produce a report")
		}
		statuses := map[string]string{}
		for _, s := range rep.Sources {
			statuses[s.Name] = s.Status
		}
		if statuses[liveStream] != "ok" {
			t.Errorf("%s = %q, want ok", liveStream, statuses[liveStream])
		}
		if statuses[staleIndex] != "stale" {
			t.Errorf("%s = %q, want stale", staleIndex, statuses[staleIndex])
		}
		if statuses[emptyIndex] != "empty" {
			t.Errorf("%s = %q, want empty", emptyIndex, statuses[emptyIndex])
		}
		reasons := map[string]string{}
		for _, d := range rep.DeadDetections {
			reasons[d.Name] = d.Reason
		}
		if reasons["Deadair IT starved rule"] != "starved" {
			t.Errorf("starved rule reason = %q, want starved", reasons["Deadair IT starved rule"])
		}
		if reasons["Deadair IT disconnected rule"] != "disconnected" {
			t.Errorf("disconnected rule reason = %q, want disconnected", reasons["Deadair IT disconnected rule"])
		}
		if reasons["Deadair IT alias rule"] != "starved" {
			t.Errorf("alias rule reason = %q, want starved through alias target", reasons["Deadair IT alias rule"])
		}
		if _, dead := reasons["Deadair IT live rule"]; dead {
			t.Error("live rule reported dead")
		}
		if _, dead := reasons["Deadair IT exclusion rule"]; dead {
			t.Error("ordered include/exclude rule reported dead")
		}
		if _, dead := reasons["Deadair IT data view rule"]; dead {
			t.Error("data-view-backed rule reported dead")
		}
		aliasObserved := false
		dataViewObserved := false
		for _, resolution := range rep.InputResolutions {
			if resolution.Selector == dataViewID && resolution.SelectorKind == "data_view" && resolution.Status == "resolved" {
				dataViewObserved = true
			}
			for _, alias := range resolution.Aliases {
				if alias == "deadairtest-stale-alias" {
					aliasObserved = true
				}
			}
		}
		if !aliasObserved {
			t.Error("native resolution evidence did not retain the live alias")
		}
		if !dataViewObserved {
			t.Error("native resolution evidence did not retain the data view")
		}
	})

	t.Run("writes are rejected", func(t *testing.T) {
		writes := []struct{ name, method, url, body string }{
			{"index a document", http.MethodPost, esURL + "/" + liveStream + "/_doc", `{"@timestamp":"2026-01-01T00:00:00Z"}`},
			{"create an index", http.MethodPut, esURL + "/deadairtest-should-not-exist", ""},
			{"delete an index", http.MethodDelete, esURL + "/" + staleIndex, ""},
			{"delete a data stream", http.MethodDelete, esURL + "/_data_stream/" + liveStream, ""},
			{"create a detection rule", http.MethodPost, kbURL + "/api/detection_engine/rules",
				`{"name":"nope","description":"x","risk_score":1,"severity":"low","type":"query","query":"*:*","index":["x"],"interval":"5m","from":"now-6m"}`},
			{"create a data view", http.MethodPost, kbURL + "/api/data_views/data_view",
				`{"data_view":{"title":"deadairtest-write-*"}}`},
			{"create an api key", http.MethodPost, esURL + "/_security/api_key", `{"name":"escalation"}`},
		}
		for _, wr := range writes {
			res := call(t, wr.method, wr.url, wr.body, apiKeyAuth(key))
			if res.status != http.StatusForbidden {
				t.Errorf("%s: status %d, want 403 — the deadair credential must not be able to write\n%s", wr.name, res.status, res.body)
			}
		}
	})
}
