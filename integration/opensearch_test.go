//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/Big-Comfy/deadair/internal/cli"
	"github.com/Big-Comfy/deadair/internal/report"
)

var openSearchURL = envOr("DEADAIR_IT_OPENSEARCH_URL", "http://localhost:9201")
var openSearchAdminPass = envOr("DEADAIR_IT_OPENSEARCH_ADMIN_PASSWORD", "DeadairAdmin123!")

const (
	openSearchReadUser = "deadair"
	openSearchReadPass = "MonitorRead123!"
)

const (
	openSearchTemplate    = "deadair-os-template"
	openSearchLiveStream  = "logs-deadair-os-default"
	openSearchUnused      = "logs-unused-os-default"
	openSearchStaleIndex  = "deadair-os-stale"
	openSearchEmptyIndex  = "deadair-os-empty"
	openSearchDetectorIdx = ".opensearch-sap-detectors-config"
)

var openSearchDetectorIDs = []string{
	"deadair-os-live",
	"deadair-os-stale",
	"deadair-os-empty",
	"deadair-os-disconnected",
	"deadair-os-unmapped",
}

func asOpenSearchAdmin(req *http.Request) { req.SetBasicAuth("admin", openSearchAdminPass) }

func asOpenSearchReadUser(req *http.Request) {
	req.SetBasicAuth(openSearchReadUser, openSearchReadPass)
}

func probeOpenSearch(url string) bool {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	asOpenSearchAdmin(req)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode == http.StatusOK
}

func waitForOpenSearch(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(4 * time.Minute)
	for {
		if probeOpenSearch(openSearchURL + "/_cluster/health") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("OpenSearch not ready — run `make opensearch-integration-up` first")
		}
		time.Sleep(3 * time.Second)
	}
}

func osAdmin(t *testing.T, method, url, body string, wantStatus int) []byte {
	t.Helper()
	res := call(t, method, url, body, asOpenSearchAdmin)
	if res.status != wantStatus {
		t.Fatalf("%s %s: status %d (want %d): %s", method, url, res.status, wantStatus, res.body)
	}
	return res.body
}

func cleanupOpenSearch(t *testing.T) {
	t.Helper()
	for _, detectorID := range openSearchDetectorIDs {
		call(t, http.MethodDelete, openSearchURL+"/"+openSearchDetectorIdx+"/_doc/"+detectorID+"?refresh=true", "", asOpenSearchAdmin)
	}
	call(t, http.MethodDelete, openSearchURL+"/_data_stream/"+openSearchLiveStream, "", asOpenSearchAdmin)
	call(t, http.MethodDelete, openSearchURL+"/_data_stream/"+openSearchUnused, "", asOpenSearchAdmin)
	call(t, http.MethodDelete, openSearchURL+"/"+openSearchStaleIndex, "", asOpenSearchAdmin)
	call(t, http.MethodDelete, openSearchURL+"/"+openSearchEmptyIndex, "", asOpenSearchAdmin)
	call(t, http.MethodDelete, openSearchURL+"/_index_template/"+openSearchTemplate, "", asOpenSearchAdmin)
	call(t, http.MethodDelete, openSearchURL+"/_plugins/_security/api/rolesmapping/security_analytics_read_access", "", asOpenSearchAdmin)
	call(t, http.MethodDelete, openSearchURL+"/_plugins/_security/api/rolesmapping/deadair_index_monitor", "", asOpenSearchAdmin)
	call(t, http.MethodDelete, openSearchURL+"/_plugins/_security/api/roles/deadair_index_monitor", "", asOpenSearchAdmin)
	call(t, http.MethodDelete, openSearchURL+"/_plugins/_security/api/internalusers/"+openSearchReadUser, "", asOpenSearchAdmin)
}

func provisionOpenSearchReadUser(t *testing.T) {
	t.Helper()
	osAdmin(t, http.MethodPut, openSearchURL+"/_plugins/_security/api/roles/deadair_index_monitor",
		`{"cluster_permissions":["cluster_monitor"],"index_permissions":[{"index_patterns":["*"],"allowed_actions":["read","indices_monitor"]}],"tenant_permissions":[]}`,
		http.StatusCreated)
	osAdmin(t, http.MethodPut, openSearchURL+"/_plugins/_security/api/internalusers/"+openSearchReadUser,
		fmt.Sprintf(`{"password":%q}`, openSearchReadPass), http.StatusCreated)
	osAdmin(t, http.MethodPut, openSearchURL+"/_plugins/_security/api/rolesmapping/deadair_index_monitor",
		fmt.Sprintf(`{"users":[%q],"backend_roles":[],"hosts":[]}`, openSearchReadUser), http.StatusCreated)
	osAdmin(t, http.MethodPut, openSearchURL+"/_plugins/_security/api/rolesmapping/security_analytics_read_access",
		fmt.Sprintf(`{"users":[%q],"backend_roles":[],"hosts":[]}`, openSearchReadUser), http.StatusCreated)
}

func seedOpenSearchDetector(t *testing.T, id, name, severity string, indices []string) {
	t.Helper()
	inputs := []map[string]any{}
	if len(indices) > 0 {
		inputs = append(inputs, map[string]any{
			"detector_input": map[string]any{
				"description":        "deadair integration fixture",
				"indices":            indices,
				"custom_rules":       []any{},
				"pre_packaged_rules": []any{},
			},
		})
	}
	body := map[string]any{
		"detector": map[string]any{
			"name":          name,
			"enabled":       true,
			"detector_type": "windows",
			"schedule": map[string]any{
				"period": map[string]any{
					"interval": 1,
					"unit":     "MINUTES",
				},
			},
			"inputs": inputs,
			"triggers": []map[string]any{
				{
					"id":              "tr-" + id,
					"name":            name + " trigger",
					"severity":        severity,
					"ids":             []any{},
					"tags":            []any{},
					"sev_levels":      []any{severity},
					"actions":         []any{},
					"detection_types": []any{"rules"},
				},
			},
		},
	}
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshaling detector seed: %v", err)
	}
	osAdmin(t, http.MethodPut, openSearchURL+"/"+openSearchDetectorIdx+"/_doc/"+id+"?refresh=true", string(data), http.StatusCreated)
}

func seedOpenSearch(t *testing.T) {
	t.Helper()
	now := time.Now().UTC()

	osAdmin(t, http.MethodPut, openSearchURL+"/_index_template/"+openSearchTemplate,
		`{"index_patterns":["logs-deadair-os-*","logs-unused-os-*"],"data_stream":{},"template":{"mappings":{"properties":{"@timestamp":{"type":"date"}}}}}`,
		http.StatusOK)
	osAdmin(t, http.MethodPost, openSearchURL+"/"+openSearchLiveStream+"/_doc",
		fmt.Sprintf(`{"@timestamp":%q,"message":"live"}`, now.Format(time.RFC3339)), http.StatusCreated)
	osAdmin(t, http.MethodPost, openSearchURL+"/"+openSearchUnused+"/_doc",
		fmt.Sprintf(`{"@timestamp":%q,"message":"unused"}`, now.Format(time.RFC3339)), http.StatusCreated)
	osAdmin(t, http.MethodPut, openSearchURL+"/"+openSearchStaleIndex,
		`{"mappings":{"properties":{"@timestamp":{"type":"date"}}}}`, http.StatusOK)
	osAdmin(t, http.MethodPost, openSearchURL+"/"+openSearchStaleIndex+"/_doc",
		fmt.Sprintf(`{"@timestamp":%q,"message":"old"}`, now.Add(-72*time.Hour).Format(time.RFC3339)), http.StatusCreated)
	osAdmin(t, http.MethodPut, openSearchURL+"/"+openSearchEmptyIndex,
		`{"mappings":{"properties":{"@timestamp":{"type":"date"}}}}`, http.StatusOK)
	osAdmin(t, http.MethodPost, openSearchURL+"/_refresh", "", http.StatusOK)

	seedOpenSearchDetector(t, "deadair-os-live", "Deadair OS live detector", "low", []string{"logs-deadair-os-*"})
	seedOpenSearchDetector(t, "deadair-os-stale", "Deadair OS stale detector", "high", []string{"deadair-os-stale*"})
	seedOpenSearchDetector(t, "deadair-os-empty", "Deadair OS empty detector", "medium", []string{openSearchEmptyIndex})
	seedOpenSearchDetector(t, "deadair-os-disconnected", "Deadair OS disconnected detector", "medium", []string{"deadair-os-missing-*"})
	seedOpenSearchDetector(t, "deadair-os-unmapped", "Deadair OS unmapped detector", "low", nil)
}

func TestOpenSearchReadOnlyScan(t *testing.T) {
	waitForOpenSearch(t)
	cleanupOpenSearch(t)
	t.Cleanup(func() { cleanupOpenSearch(t) })
	provisionOpenSearchReadUser(t)
	seedOpenSearch(t)
	t.Setenv("DEADAIR_API_KEY", "")
	t.Setenv("DEADAIR_OPENSEARCH_API_KEY", "")
	t.Setenv("DEADAIR_OPENSEARCH_USERNAME", openSearchReadUser)
	t.Setenv("DEADAIR_OPENSEARCH_PASSWORD", openSearchReadPass)

	var rep report.Report
	t.Run("scan succeeds with least-privilege user", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := cli.Run([]string{
			"scan",
			"--backend", "opensearch",
			"--opensearch-url", openSearchURL,
			"--json",
			"--max-stale", "1h",
			"--state-file", filepath.Join(t.TempDir(), "state.json"),
			"--schema",
			"--include", "logs-deadair-os-*",
			"--include", "logs-unused-os-*",
			"--include", "deadair-os-*",
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
		if rep.Backend != "opensearch" {
			t.Fatalf("backend = %q, want opensearch", rep.Backend)
		}
		if rep.Summary.Sources != 4 || rep.Summary.DeadDetections != 3 || rep.Summary.UnmappedRules != 1 || rep.Summary.UnusedSources != 1 {
			t.Fatalf("summary = %+v", rep.Summary)
		}

		statuses := map[string]string{}
		docs := map[string]int64{}
		for _, s := range rep.Sources {
			statuses[s.Name] = s.Status
			docs[s.Name] = s.Docs
		}
		if statuses[openSearchLiveStream] != "ok" {
			t.Errorf("%s = %q, want ok", openSearchLiveStream, statuses[openSearchLiveStream])
		}
		// Doc counts for data streams come from summing real backing-index
		// names (.ds-<stream>-<generation> on OpenSearch); -1 here means the
		// backing-index parser regressed and volume baselines are inert.
		if docs[openSearchLiveStream] <= 0 {
			t.Errorf("%s docs = %d, want > 0 (backing-index doc summation)", openSearchLiveStream, docs[openSearchLiveStream])
		}
		if statuses[openSearchStaleIndex] != "stale" {
			t.Errorf("%s = %q, want stale", openSearchStaleIndex, statuses[openSearchStaleIndex])
		}
		if statuses[openSearchEmptyIndex] != "empty" {
			t.Errorf("%s = %q, want empty", openSearchEmptyIndex, statuses[openSearchEmptyIndex])
		}

		reasons := map[string]string{}
		for _, d := range rep.DeadDetections {
			reasons[d.Name] = d.Reason
		}
		if reasons["Deadair OS stale detector"] != "starved" {
			t.Errorf("stale detector reason = %q, want starved", reasons["Deadair OS stale detector"])
		}
		if reasons["Deadair OS empty detector"] != "starved" {
			t.Errorf("empty detector reason = %q, want starved", reasons["Deadair OS empty detector"])
		}
		if reasons["Deadair OS disconnected detector"] != "disconnected" {
			t.Errorf("disconnected detector reason = %q, want disconnected", reasons["Deadair OS disconnected detector"])
		}
	})

	t.Run("writes are rejected", func(t *testing.T) {
		writes := []struct{ name, method, url, body string }{
			{"index a document", http.MethodPost, openSearchURL + "/" + openSearchLiveStream + "/_doc", `{"@timestamp":"2026-01-01T00:00:00Z"}`},
			{"create an index", http.MethodPut, openSearchURL + "/deadair-os-should-not-exist", ""},
			{"delete an index", http.MethodDelete, openSearchURL + "/" + openSearchStaleIndex, ""},
			{"delete a data stream", http.MethodDelete, openSearchURL + "/_data_stream/" + openSearchLiveStream, ""},
			{"create a detector", http.MethodPost, openSearchURL + "/_plugins/_security_analytics/detectors",
				`{"name":"deadair forbidden detector","detector_type":"windows","enabled":true,"schedule":{"period":{"interval":1,"unit":"MINUTES"}},"inputs":[{"detector_input":{"description":"forbidden","indices":["deadair-os-stale*"],"custom_rules":[],"pre_packaged_rules":[{"id":"06724a9a-52fc-11ed-bdc3-0242ac120002"}]}}],"triggers":[{"name":"forbidden trigger","severity":"1","ids":["06724a9a-52fc-11ed-bdc3-0242ac120002"],"types":["rules"],"sev_levels":["critical"],"actions":[]}]}`},
			{"update a security role", http.MethodPut, openSearchURL + "/_plugins/_security/api/roles/deadair_escalation",
				`{"cluster_permissions":["*"],"index_permissions":[],"tenant_permissions":[]}`},
		}
		for _, wr := range writes {
			res := call(t, wr.method, wr.url, wr.body, asOpenSearchReadUser)
			if res.status != http.StatusForbidden && res.status != http.StatusUnauthorized {
				t.Errorf("%s: status %d, want 401/403 — the deadair OpenSearch user must not be able to write\n%s", wr.name, res.status, res.body)
			}
		}
	})
}
