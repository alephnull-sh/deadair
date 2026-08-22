package sentinel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/alephnull-sh/deadair/internal/backend"
)

func TestSummaryRuleRunEvidenceReadsOneBoundedLatestRunQuery(t *testing.T) {
	credential := &recordingCredential{}
	recentRun := time.Now().UTC().Add(-30 * time.Minute).Truncate(time.Millisecond)
	failedRun := recentRun.Add(10 * time.Minute)
	successModified := recentRun.Add(-24 * time.Hour)
	failedModified := failedRun.Add(-24 * time.Hour)
	var query string
	var logsRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/summaryLogs"):
			fmt.Fprintf(w, `{"value":[
				{"id":"/summaryLogs/success-rule","name":"success-rule","systemData":{"lastModifiedAt":%q},"properties":{"displayName":"Successful producer","isActive":true,"provisioningState":"Succeeded","ruleDefinition":{"destinationTable":"SuccessSummary_CL","binSize":60,"binDelay":5}}},
				{"id":"/summaryLogs/failed-rule","name":"failed-rule","systemData":{"lastModifiedAt":%q},"properties":{"displayName":"Failed producer","isActive":true,"provisioningState":"Succeeded","ruleDefinition":{"destinationTable":"FailedSummary_CL","binSize":60,"binDelay":5}}},
				{"id":"/summaryLogs/inactive-rule","name":"inactive-rule","properties":{"isActive":false,"provisioningState":"Succeeded","ruleDefinition":{"destinationTable":"InactiveSummary_CL","binSize":60}}},
				{"id":"/summaryLogs/unused-rule","name":"unused-rule","properties":{"isActive":true,"provisioningState":"Succeeded","ruleDefinition":{"destinationTable":"UnusedSummary_CL","binSize":60}}}
			]}`, successModified.Format(time.RFC3339Nano), failedModified.Format(time.RFC3339Nano))
		case strings.HasSuffix(r.URL.Path, "/query"):
			logsRequests++
			if r.Method != http.MethodPost {
				t.Errorf("Logs method = %s", r.Method)
			}
			if prefer := r.Header.Get("Prefer"); prefer != "include-permissions=true,include-dataSources=true" {
				t.Errorf("Prefer header = %q", prefer)
			}
			var request logsQueryRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			query = request.Query
			result := fmt.Sprintf(`[{"name":"PrimaryResult","columns":[
				{"name":"Status","type":"string"},{"name":"RuleName","type":"string"},{"name":"Message","type":"string"},
				{"name":"TimeGenerated","type":"datetime"},{"name":"ResultsRecordCount","type":"long"},
				{"name":"QueryDurationMs","type":"long"},{"name":"RuleLastModifiedTime","type":"datetime"}
			],"rows":[
				["Succeeded","success-rule",null,%q,17,245,%q],
				["Failed","failed-rule","  failed   after\n retry  ",%q,0,9012,%q]
			]}]`, recentRun.Format(time.RFC3339Nano), successModified.Format(time.RFC3339Nano), failedRun.Format(time.RFC3339Nano), failedModified.Format(time.RFC3339Nano))
			writeAllowedLogsResult(w, summaryRuleRunTable, result)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	detections := []backend.Rule{{
		ID:       "detection",
		Enabled:  true,
		Patterns: []string{"SuccessSummary_CL", "FailedSummary_CL", "InactiveSummary_CL"},
	}}
	evidence, err := fixtureClient(server.URL, credential).SummaryRuleRunEvidence(context.Background(), detections)
	if err != nil {
		t.Fatal(err)
	}
	if logsRequests != 1 {
		t.Fatalf("Logs requests = %d, want 1", logsRequests)
	}
	if len(evidence) != 3 {
		t.Fatalf("summary run evidence = %+v", evidence)
	}
	byName := make(map[string]backend.SummaryRuleRunEvidence, len(evidence))
	for _, item := range evidence {
		byName[item.Rule.Name] = item
		if item.Method != summaryRuleRunMethod || item.Window != summaryRuleRunWindow || item.ObservedAt.IsZero() {
			t.Errorf("common summary evidence fields = %+v", item)
		}
	}
	success := byName["Successful producer"]
	if success.Status != backend.EvidenceAssessed || success.RunStatus != "Succeeded" ||
		success.QueryDurationMillis != 245 || success.ResultCount != 17 || success.Error != "" ||
		!success.RunAt.Equal(recentRun) || !success.RuleModifiedAt.Equal(successModified) ||
		success.Output.Name != "SuccessSummary_CL" || success.Rule.ID != "/summaryLogs/success-rule" {
		t.Fatalf("successful summary run = %+v", success)
	}
	failed := byName["Failed producer"]
	if failed.Status != backend.EvidenceAssessed || failed.RunStatus != "Failed" ||
		failed.Error != "failed after retry" || failed.ResultCount != 0 || failed.QueryDurationMillis != 9012 {
		t.Fatalf("failed native run was not retained as assessed evidence: %+v", failed)
	}
	inactive := byName["inactive-rule"]
	if inactive.Status != backend.EvidenceDisabled || inactive.Detail != "summary rule is inactive" {
		t.Fatalf("inactive summary run = %+v", inactive)
	}
	for _, fragment := range []string{
		"LASummaryLogs", "TimeGenerated between (ago(7d) .. now())",
		"RuleName in ('failed-rule', 'success-rule')", "Status in ('Succeeded', 'Failed')", "arg_max(TimeGenerated",
		"project RuleName, TimeGenerated, Status, QueryDurationMs, ResultsRecordCount, RuleLastModifiedTime, Message",
	} {
		if !strings.Contains(query, fragment) {
			t.Errorf("summary query missing %q:\n%s", fragment, query)
		}
	}
	if strings.Contains(query, "inactive-rule") || strings.Contains(query, "unused-rule") || strings.Contains(query, "Started") {
		t.Fatalf("summary query included inactive, unconsumed, or non-completed runtime state:\n%s", query)
	}
	if !credential.sawScope(armScope) || !credential.sawScope(logsScope) {
		t.Fatalf("credential scopes = %+v", credential)
	}
}

func TestSummaryRuleRunEvidencePreservesUnavailableAndIncompleteStates(t *testing.T) {
	tests := []struct {
		name       string
		logs       func(http.ResponseWriter)
		wantStatus backend.EvidenceStatus
		wantDetail string
	}{
		{
			name: "no rows",
			logs: func(w http.ResponseWriter) {
				writeAllowedLogsResult(w, summaryRuleRunTable, summaryRunResultTable(nil))
			},
			wantStatus: backend.EvidenceIncomplete,
			wantDetail: "no LASummaryLogs execution was observed in the bounded 7-day window",
		},
		{
			name: "absent table",
			logs: func(w http.ResponseWriter) {
				http.Error(w, `{"error":{"code":"BadArgument","message":"Failed to resolve table LASummaryLogs"}}`, http.StatusBadRequest)
			},
			wantStatus: backend.EvidenceIncomplete,
			wantDetail: "Logs query evidence could not be read",
		},
		{
			name: "explicit permission denial",
			logs: func(w http.ResponseWriter) {
				fmt.Fprint(w, `{"tables":[],"permissions":{"dataSources":[{"denyTables":["LASummaryLogs"]}]},"dataSources":[{"tables":["LASummaryLogs"]}]}`)
			},
			wantStatus: backend.EvidenceUnavailable,
			wantDetail: "Logs query permission evidence explicitly denied the requested table",
		},
		{
			name: "partial query",
			logs: func(w http.ResponseWriter) {
				fmt.Fprint(w, `{"error":{"code":"PartialError"},"tables":[],"permissions":{"dataSources":[{"allowTables":["LASummaryLogs"]}]},"dataSources":[{"tables":["LASummaryLogs"]}]}`)
			},
			wantStatus: backend.EvidenceIncomplete,
			wantDetail: "Log Analytics returned a partial or failed query result",
		},
		{
			name: "omitted data source proof",
			logs: func(w http.ResponseWriter) {
				fmt.Fprintf(w, `{"tables":%s,"permissions":{"dataSources":[{"allowTables":["LASummaryLogs"]}]}}`, summaryRunResultTable(nil))
			},
			wantStatus: backend.EvidenceIncomplete,
			wantDetail: "Logs query data-source evidence did not confirm the requested table",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, "/summaryLogs"):
					fmt.Fprint(w, `{"value":[{"id":"/summaryLogs/rule-a","name":"rule-a","systemData":{"lastModifiedAt":"2026-08-20T09:00:00Z"},"properties":{"isActive":true,"provisioningState":"Succeeded","ruleDefinition":{"destinationTable":"Summary_CL","binSize":60}}}]}`)
				case strings.HasSuffix(r.URL.Path, "/query"):
					tt.logs(w)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()

			evidence, err := fixtureClient(server.URL, &recordingCredential{}).SummaryRuleRunEvidence(context.Background(), []backend.Rule{{
				ID: "detection", Enabled: true, Patterns: []string{"Summary_CL"},
			}})
			if err != nil {
				t.Fatal(err)
			}
			if len(evidence) != 1 || evidence[0].Status != tt.wantStatus || evidence[0].Detail != tt.wantDetail {
				t.Fatalf("summary evidence = %+v", evidence)
			}
		})
	}
}

func TestSummaryRuleRunEvidenceFailsClosedOnInvalidActiveConfiguration(t *testing.T) {
	var logsRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/summaryLogs"):
			fmt.Fprint(w, `{"value":[
				{"id":"/summaryLogs/provisioning","name":"provisioning","properties":{"isActive":true,"provisioningState":"Updating","ruleDefinition":{"destinationTable":"Provisioning_CL","binSize":60}}},
				{"id":"/summaryLogs/status","name":"status","properties":{"isActive":true,"provisioningState":"Succeeded","statusCode":"DataPlaneError","ruleDefinition":{"destinationTable":"Status_CL","binSize":60}}},
				{"id":"/summaryLogs/bin-size","name":"bin-size","properties":{"isActive":true,"provisioningState":"Succeeded","ruleDefinition":{"destinationTable":"BinSize_CL","binSize":15}}},
				{"id":"/summaryLogs/bin-delay","name":"bin-delay","properties":{"isActive":true,"provisioningState":"Succeeded","ruleDefinition":{"destinationTable":"BinDelay_CL","binSize":60,"binDelay":-1}}}
			]}`)
		case strings.HasSuffix(r.URL.Path, "/query"):
			logsRequests++
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	evidence, err := fixtureClient(server.URL, &recordingCredential{}).SummaryRuleRunEvidence(context.Background(), []backend.Rule{{
		ID: "detection", Enabled: true, Patterns: []string{"Provisioning_CL", "Status_CL", "BinSize_CL", "BinDelay_CL"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if logsRequests != 0 || len(evidence) != 4 {
		t.Fatalf("invalid configuration evidence = %+v; Logs requests = %d", evidence, logsRequests)
	}
	wantDetails := map[string]string{
		"provisioning": "summary rule provisioning state is Updating",
		"status":       "summary rule status is DataPlaneError",
		"bin-size":     "summary rule bin size 15m is not supported",
		"bin-delay":    "summary rule bin delay cannot be negative",
	}
	for _, item := range evidence {
		if item.Status != backend.EvidenceIncomplete || item.Detail != wantDetails[item.Rule.Name] {
			t.Errorf("invalid active summary rule = %+v", item)
		}
	}
}

func TestSummaryRuleRunEvidenceWarnsWhenLatestSuccessExceedsScheduleAndRetryAllowance(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	recentRun := now.Add(-30 * time.Minute)
	oldRun := now.Add(-6 * 24 * time.Hour)
	modified := now.Add(-14 * 24 * time.Hour)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/summaryLogs"):
			fmt.Fprintf(w, `{"value":[
				{"id":"/summaryLogs/recent","name":"recent","systemData":{"lastModifiedAt":%q},"properties":{"isActive":true,"provisioningState":"Succeeded","ruleDefinition":{"destinationTable":"Recent_CL","binSize":60,"binDelay":10}}},
				{"id":"/summaryLogs/old","name":"old","systemData":{"lastModifiedAt":%q},"properties":{"isActive":true,"provisioningState":"Succeeded","ruleDefinition":{"destinationTable":"Old_CL","binSize":60,"binDelay":10}}}
			]}`, modified.Format(time.RFC3339Nano), modified.Format(time.RFC3339Nano))
		case strings.HasSuffix(r.URL.Path, "/query"):
			rows := []string{
				fmt.Sprintf(`[%q,%q,"Succeeded",120,4,%q,null]`, "recent", recentRun.Format(time.RFC3339Nano), modified.Format(time.RFC3339Nano)),
				fmt.Sprintf(`[%q,%q,"Succeeded",240,9,%q,null]`, "old", oldRun.Format(time.RFC3339Nano), modified.Format(time.RFC3339Nano)),
			}
			writeAllowedLogsResult(w, summaryRuleRunTable, summaryRunResultTable(rows))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	evidence, err := fixtureClient(server.URL, &recordingCredential{}).SummaryRuleRunEvidence(context.Background(), []backend.Rule{{
		ID: "detection", Enabled: true, Patterns: []string{"Recent_CL", "Old_CL"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	byName := make(map[string]backend.SummaryRuleRunEvidence, len(evidence))
	for _, item := range evidence {
		byName[item.Rule.Name] = item
	}
	if recent := byName["recent"]; recent.Status != backend.EvidenceAssessed || recent.RunStatus != "Succeeded" || !recent.RunAt.Equal(recentRun) {
		t.Fatalf("recent summary success = %+v", recent)
	}
	old := byName["old"]
	if old.Status != backend.EvidenceIncomplete || old.RunStatus != "Succeeded" || !old.RunAt.Equal(oldRun) ||
		old.ResultCount != 9 || old.QueryDurationMillis != 240 ||
		old.Detail != "latest successful summary-rule execution is older than the configured schedule plus the documented 8-hour retry allowance" {
		t.Fatalf("overdue summary success = %+v", old)
	}
}

func TestSummaryRuleRunEvidenceRejectsMalformedAndAmbiguousNativeEvidence(t *testing.T) {
	t.Run("malformed row", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.HasSuffix(r.URL.Path, "/summaryLogs"):
				fmt.Fprint(w, `{"value":[{"id":"/summaryLogs/rule-a","name":"rule-a","systemData":{"lastModifiedAt":"2026-08-20T09:00:00Z"},"properties":{"isActive":true,"provisioningState":"Succeeded","ruleDefinition":{"destinationTable":"Summary_CL","binSize":60}}}]}`)
			case strings.HasSuffix(r.URL.Path, "/query"):
				writeAllowedLogsResult(w, summaryRuleRunTable, summaryRunResultTable([]string{
					`["rule-a","not-a-time","Succeeded",1,2,"2026-08-20T09:00:00Z",null]`,
				}))
			default:
				http.NotFound(w, r)
			}
		}))
		defer server.Close()

		evidence, err := fixtureClient(server.URL, &recordingCredential{}).SummaryRuleRunEvidence(context.Background(), []backend.Rule{{
			ID: "detection", Enabled: true, Patterns: []string{"Summary_CL"},
		}})
		if err != nil {
			t.Fatal(err)
		}
		if len(evidence) != 1 || evidence[0].Status != backend.EvidenceIncomplete || evidence[0].Detail != "LASummaryLogs query returned malformed row 1" {
			t.Fatalf("malformed summary row = %+v", evidence)
		}
	})

	t.Run("ambiguous full ARM inventory", func(t *testing.T) {
		var logsRequests int
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.HasSuffix(r.URL.Path, "/summaryLogs"):
				fmt.Fprint(w, `{"value":[
					{"id":"/summaryLogs/one","name":"duplicate","properties":{"isActive":true,"provisioningState":"Succeeded","ruleDefinition":{"destinationTable":"Summary_CL","binSize":60}}},
					{"id":"/summaryLogs/two","name":"duplicate","properties":{"isActive":true,"provisioningState":"Succeeded","ruleDefinition":{"destinationTable":"Unconsumed_CL","binSize":60}}}
				]}`)
			case strings.HasSuffix(r.URL.Path, "/query"):
				logsRequests++
			default:
				http.NotFound(w, r)
			}
		}))
		defer server.Close()

		evidence, err := fixtureClient(server.URL, &recordingCredential{}).SummaryRuleRunEvidence(context.Background(), []backend.Rule{{
			ID: "detection", Enabled: true, Patterns: []string{"Summary_CL"},
		}})
		if err != nil {
			t.Fatal(err)
		}
		if logsRequests != 0 || len(evidence) != 1 || evidence[0].Status != backend.EvidenceIncomplete ||
			evidence[0].Detail != "summary rule ARM name is not unique in the workspace inventory" {
			t.Fatalf("ambiguous summary identity = %+v; Logs requests = %d", evidence, logsRequests)
		}
	})
}

func TestSummaryRuleRunEvidenceRequiresCurrentARMRevision(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	armModifiedAt := now.Add(-10 * time.Minute)
	tests := []struct {
		name               string
		armModified        string
		runAt              time.Time
		logRuleModifiedAt  time.Time
		wantLogsRequests   int
		wantStatus         backend.EvidenceStatus
		wantDetail         string
		wantRuntimeCleared bool
	}{
		{
			name:             "missing ARM modification time",
			wantStatus:       backend.EvidenceIncomplete,
			wantDetail:       "summary rule ARM modification time is missing or malformed",
			wantLogsRequests: 0,
		},
		{
			name:             "malformed ARM modification time",
			armModified:      "not-a-time",
			wantStatus:       backend.EvidenceIncomplete,
			wantDetail:       "summary rule ARM modification time is missing or malformed",
			wantLogsRequests: 0,
		},
		{
			name:               "recreated rule has only an old execution",
			armModified:        armModifiedAt.Format(time.RFC3339Nano),
			runAt:              armModifiedAt.Add(-time.Minute),
			logRuleModifiedAt:  armModifiedAt.Add(-time.Hour),
			wantLogsRequests:   1,
			wantStatus:         backend.EvidenceIncomplete,
			wantDetail:         "latest LASummaryLogs execution predates the current ARM summary-rule revision",
			wantRuntimeCleared: true,
		},
		{
			name:               "old revision logged after ARM update",
			armModified:        armModifiedAt.Format(time.RFC3339Nano),
			runAt:              armModifiedAt.Add(time.Minute),
			logRuleModifiedAt:  armModifiedAt.Add(-time.Minute),
			wantLogsRequests:   1,
			wantStatus:         backend.EvidenceIncomplete,
			wantDetail:         "latest LASummaryLogs execution predates the current ARM summary-rule revision",
			wantRuntimeCleared: true,
		},
		{
			name:              "current revision",
			armModified:       armModifiedAt.Format(time.RFC3339Nano),
			runAt:             armModifiedAt.Add(time.Minute),
			logRuleModifiedAt: armModifiedAt,
			wantLogsRequests:  1,
			wantStatus:        backend.EvidenceAssessed,
			wantDetail:        "latest completed native summary-rule execution observed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logsRequests int
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, "/summaryLogs"):
					fmt.Fprintf(w, `{"value":[{"id":"/summaryLogs/recreated","name":"recreated","systemData":{"lastModifiedAt":%q},"properties":{"isActive":true,"provisioningState":"Succeeded","ruleDefinition":{"destinationTable":"Summary_CL","binSize":60}}}]}`, tt.armModified)
				case strings.HasSuffix(r.URL.Path, "/query"):
					logsRequests++
					row := fmt.Sprintf(`[%q,%q,"Failed",1,0,%q,"native failure"]`, "recreated", tt.runAt.Format(time.RFC3339Nano), tt.logRuleModifiedAt.Format(time.RFC3339Nano))
					writeAllowedLogsResult(w, summaryRuleRunTable, summaryRunResultTable([]string{row}))
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()

			evidence, err := fixtureClient(server.URL, &recordingCredential{}).SummaryRuleRunEvidence(context.Background(), []backend.Rule{{
				ID: "detection", Enabled: true, Patterns: []string{"Summary_CL"},
			}})
			if err != nil {
				t.Fatal(err)
			}
			if logsRequests != tt.wantLogsRequests || len(evidence) != 1 || evidence[0].Status != tt.wantStatus || evidence[0].Detail != tt.wantDetail {
				t.Fatalf("revision evidence = %+v; Logs requests = %d", evidence, logsRequests)
			}
			if tt.wantRuntimeCleared && (!evidence[0].RunAt.IsZero() || !evidence[0].RuleModifiedAt.IsZero() || evidence[0].RunStatus != "" || evidence[0].Error != "") {
				t.Fatalf("stale revision runtime fields were retained: %+v", evidence[0])
			}
		})
	}
}

func TestSummaryRuleRunEvidenceHonorsQueryBudgetAndRuleCap(t *testing.T) {
	t.Run("shared Logs budget", func(t *testing.T) {
		var logsRequests int
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.HasSuffix(r.URL.Path, "/summaryLogs"):
				fmt.Fprint(w, `{"value":[{"id":"/summaryLogs/rule-a","name":"rule-a","systemData":{"lastModifiedAt":"2026-08-20T09:00:00Z"},"properties":{"isActive":true,"provisioningState":"Succeeded","ruleDefinition":{"destinationTable":"Summary_CL","binSize":60}}}]}`)
			case strings.HasSuffix(r.URL.Path, "/query"):
				logsRequests++
			default:
				http.NotFound(w, r)
			}
		}))
		defer server.Close()
		client := fixtureClient(server.URL, &recordingCredential{})
		client.logsQueryLimit = 1
		if !client.claimLogsQuery() {
			t.Fatal("could not reserve fixture Logs query budget")
		}

		evidence, err := client.SummaryRuleRunEvidence(context.Background(), []backend.Rule{{ID: "detection", Enabled: true, Patterns: []string{"Summary_CL"}}})
		if err != nil {
			t.Fatal(err)
		}
		if logsRequests != 0 || len(evidence) != 1 || evidence[0].Status != backend.EvidenceIncomplete ||
			evidence[0].Detail != "per-scan Logs query budget was exhausted" {
			t.Fatalf("budget evidence = %+v; Logs requests = %d", evidence, logsRequests)
		}
	})

	t.Run("deterministic active rule cap", func(t *testing.T) {
		const count = maxSummaryRuleRunRules + 1
		inventory := make([]map[string]any, 0, count)
		patterns := make([]string, 0, count)
		for i := count - 1; i >= 0; i-- {
			name := fmt.Sprintf("rule-%02d", i)
			destination := fmt.Sprintf("Summary%02d_CL", i)
			inventory = append(inventory, map[string]any{
				"id": "/summaryLogs/" + name, "name": name, "systemData": map[string]any{"lastModifiedAt": "2026-08-20T09:00:00Z"},
				"properties": map[string]any{"isActive": true, "provisioningState": "Succeeded", "ruleDefinition": map[string]any{"destinationTable": destination, "binSize": 60}},
			})
			patterns = append(patterns, destination)
		}
		var query string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.HasSuffix(r.URL.Path, "/summaryLogs"):
				if err := json.NewEncoder(w).Encode(map[string]any{"value": inventory}); err != nil {
					t.Fatal(err)
				}
			case strings.HasSuffix(r.URL.Path, "/query"):
				var request logsQueryRequest
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Fatal(err)
				}
				query = request.Query
				writeAllowedLogsResult(w, summaryRuleRunTable, summaryRunResultTable(nil))
			default:
				http.NotFound(w, r)
			}
		}))
		defer server.Close()

		evidence, err := fixtureClient(server.URL, &recordingCredential{}).SummaryRuleRunEvidence(context.Background(), []backend.Rule{{
			ID: "detection", Enabled: true, Patterns: patterns,
		}})
		if err != nil {
			t.Fatal(err)
		}
		if len(evidence) != count {
			t.Fatalf("evidence count = %d, want %d", len(evidence), count)
		}
		if !strings.Contains(query, "'rule-00'") || !strings.Contains(query, "'rule-49'") || strings.Contains(query, "'rule-50'") {
			t.Fatalf("query did not apply deterministic cap:\n%s", query)
		}
		if evidence[count-1].Rule.Name != "rule-50" || evidence[count-1].Status != backend.EvidenceIncomplete ||
			evidence[count-1].Detail != "summary runtime query cap limited assessment to 50 active rules" {
			t.Fatalf("capped evidence = %+v", evidence[count-1])
		}
	})
}

func TestSummaryRuleInventoryCachesOnlySuccessfulCompleteListsPerScan(t *testing.T) {
	t.Run("successful list is cloned and reset", func(t *testing.T) {
		var server *httptest.Server
		var firstPage, secondPage int
		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/subscriptions/sub-id/resourceGroups/rg-lab/providers/Microsoft.OperationalInsights/workspaces/law-lab/summaryLogs":
				firstPage++
				fmt.Fprintf(w, `{"value":[{"id":"/summaryLogs/a","name":"a","properties":{"isActive":true}}],"nextLink":%q}`, server.URL+"/summary-next")
			case "/summary-next":
				secondPage++
				fmt.Fprint(w, `{"value":[{"id":"/summaryLogs/b","name":"b","properties":{"isActive":false}}]}`)
			default:
				http.NotFound(w, r)
			}
		}))
		defer server.Close()
		client := fixtureClient(server.URL, &recordingCredential{})

		first, err := client.listSummaryLogs(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		first[0].Name = "mutated"
		*first[0].Properties.IsActive = false
		second, err := client.listSummaryLogs(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if firstPage != 1 || secondPage != 1 || len(second) != 2 || second[0].Name != "a" ||
			second[0].Properties.IsActive == nil || !*second[0].Properties.IsActive {
			t.Fatalf("cached cloned inventory = %+v; page calls = %d/%d", second, firstPage, secondPage)
		}
		if err := client.RefreshForScan(context.Background()); err != nil {
			t.Fatal(err)
		}
		if _, err := client.listSummaryLogs(context.Background()); err != nil {
			t.Fatal(err)
		}
		if firstPage != 2 || secondPage != 2 {
			t.Fatalf("refreshed inventory page calls = %d/%d, want 2/2", firstPage, secondPage)
		}
	})

	t.Run("failed list is not cached", func(t *testing.T) {
		var calls int
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls++
			if calls == 1 {
				http.Error(w, `{"error":{"code":"AuthorizationFailed"}}`, http.StatusForbidden)
				return
			}
			fmt.Fprint(w, `{"value":[{"id":"/summaryLogs/a","name":"a"}]}`)
		}))
		defer server.Close()
		client := fixtureClient(server.URL, &recordingCredential{})

		if _, err := client.listSummaryLogs(context.Background()); err == nil {
			t.Fatal("failed summary inventory unexpectedly succeeded")
		}
		inventory, err := client.listSummaryLogs(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if calls != 2 || len(inventory) != 1 || inventory[0].Name != "a" {
			t.Fatalf("retried summary inventory = %+v; calls = %d", inventory, calls)
		}
	})
}

func TestSummaryRunParserRejectsStartedRowsBecauseRuntimeEvidenceIsLatestCompleted(t *testing.T) {
	response := decodeLogsResponse(t, `{"tables":`+summaryRunResultTable([]string{
		`["rule-a","2026-08-22T10:00:00Z","Started",0,0,"2026-08-22T09:00:00Z",null]`,
	})+`}`)
	if _, detail := parseSummaryRuleRunRows(response.Tables[0]); detail != "LASummaryLogs query returned malformed row 1" {
		t.Fatalf("Started row parse detail = %q", detail)
	}
}

func TestSummaryRunParserRejectsMissingRuleRevisionTimestamp(t *testing.T) {
	response := decodeLogsResponse(t, `{"tables":`+summaryRunResultTable([]string{
		`["rule-a","2026-08-22T10:00:00Z","Failed",1,0,null,"failed"]`,
	})+`}`)
	if _, detail := parseSummaryRuleRunRows(response.Tables[0]); detail != "LASummaryLogs query returned malformed row 1" {
		t.Fatalf("missing RuleLastModifiedTime parse detail = %q", detail)
	}
}

func TestNormalizeSummaryRuleErrorCollapsesWhitespaceAndCapsRunes(t *testing.T) {
	message := "  first\n\tsecond  " + strings.Repeat("界", maxSummaryRuleErrorRunes)
	normalized := normalizeSummaryRuleError(message)
	if strings.ContainsAny(normalized, "\n\t") || !strings.HasPrefix(normalized, "first second ") || !strings.HasSuffix(normalized, "...") {
		t.Fatalf("normalized summary error = %q", normalized)
	}
	if got := len([]rune(normalized)); got != maxSummaryRuleErrorRunes {
		t.Fatalf("normalized summary error runes = %d, want %d", got, maxSummaryRuleErrorRunes)
	}
}

func TestNormalizeSummaryRuleErrorStripsTerminalAndDirectionControls(t *testing.T) {
	message := "visible \x1b[31mred\x1b[0m \x1b]0;forged title\a text " +
		"\u202ereversed\u202c \u2066isolate\u2069 \u200djoined \a done " +
		"\u009b32mgreen\u009b0m \u009dhidden\u009c end"
	normalized := normalizeSummaryRuleError(message)
	if normalized != "visible red text reversed isolate joined done green end" {
		t.Fatalf("sanitized summary error = %q", normalized)
	}
	for _, r := range normalized {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			t.Fatalf("sanitized summary error retained unsafe rune %U in %q", r, normalized)
		}
	}

	if got := normalizeSummaryRuleError("prefix \x1b]unterminated attacker text"); got != "prefix" {
		t.Fatalf("unterminated OSC sanitization = %q", got)
	}
}

func summaryRunResultTable(rows []string) string {
	if rows == nil {
		rows = []string{}
	}
	return `[{"name":"PrimaryResult","columns":[` +
		`{"name":"RuleName","type":"string"},{"name":"TimeGenerated","type":"datetime"},` +
		`{"name":"Status","type":"string"},{"name":"QueryDurationMs","type":"long"},` +
		`{"name":"ResultsRecordCount","type":"long"},{"name":"RuleLastModifiedTime","type":"datetime"},` +
		`{"name":"Message","type":"string"}],"rows":[` + strings.Join(rows, ",") + `]}]`
}

func TestLineageEvidenceIncludesOnlySummaryRulesConsumedByEnabledDetections(t *testing.T) {
	credential := &recordingCredential{}
	var server *httptest.Server
	var requests []string
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.RequestURI())
		switch r.URL.Path {
		case "/subscriptions/sub-id/resourceGroups/rg-lab/providers/Microsoft.OperationalInsights/workspaces/law-lab/summaryLogs":
			if got := r.URL.Query().Get("api-version"); got != summaryLogsAPIVersion {
				t.Errorf("summary api-version = %q", got)
			}
			fmt.Fprintf(w, `{"value":[{
				"id":"/subscriptions/sub-id/resourceGroups/rg-lab/providers/Microsoft.OperationalInsights/workspaces/law-lab/summaryLogs/raw-summary",
				"name":"raw-summary",
				"properties":{"displayName":"Raw summary","isActive":true,"provisioningState":"Succeeded","ruleDefinition":{"query":"RawBasic_CL | join kind=leftouter RawAux_CL on Key","destinationTable":"RawSummary_CL","binSize":60,"binDelay":10}}
			}],"nextLink":%q}`, server.URL+"/opaque/summary?cursor=a%2Fb")
		case "/opaque/summary":
			if r.URL.RawQuery != "cursor=a%2Fb" {
				t.Errorf("opaque summary query = %q", r.URL.RawQuery)
			}
			fmt.Fprint(w, `{"value":[{
				"id":"/subscriptions/sub-id/resourceGroups/rg-lab/providers/Microsoft.OperationalInsights/workspaces/law-lab/summaryLogs/stopped-summary",
				"name":"stopped-summary",
				"properties":{"isActive":false,"provisioningState":"Succeeded","statusCode":"UserAction","ruleDefinition":{"query":"RawBasic_CL | summarize count()","destinationTable":"StoppedSummary_CL","binSize":30}}
			},{
				"id":"/subscriptions/sub-id/resourceGroups/rg-lab/providers/Microsoft.OperationalInsights/workspaces/law-lab/summaryLogs/unused-summary",
				"name":"unused-summary",
				"properties":{"isActive":true,"provisioningState":"Succeeded","ruleDefinition":{"query":"UnusedRaw_CL | summarize count()","destinationTable":"UnusedSummary_CL","binSize":30}}
			}]}`)
		case "/subscriptions/sub-id/resourceGroups/rg-lab/providers/Microsoft.OperationalInsights/workspaces/law-lab/tables":
			if got := r.URL.Query().Get("api-version"); got != tablesAPIVersion {
				t.Errorf("tables api-version = %q", got)
			}
			fmt.Fprint(w, `{"value":[
				{"name":"RawBasic_CL","properties":{"plan":"Basic","provisioningState":"Succeeded","schema":{"columns":[]}}},
				{"name":"RawAux_CL","properties":{"plan":"Auxiliary","provisioningState":"Succeeded","schema":{"columns":[]}}},
				{"name":"RawSummary_CL","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"columns":[]}}},
				{"name":"StoppedSummary_CL","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"columns":[]}}},
				{"name":"UnusedRaw_CL","properties":{"plan":"Basic","provisioningState":"Succeeded","schema":{"columns":[]}}},
				{"name":"UnusedSummary_CL","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"columns":[]}}}
			]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	detections := []backend.Rule{
		{ID: "enabled-required", Enabled: true, Patterns: []string{"rawsummary_cl"}},
		{ID: "enabled-optional", Enabled: true, OptionalPatterns: []string{"StoppedSummary_CL"}},
		{ID: "disabled", Enabled: false, Patterns: []string{"UnusedSummary_CL"}},
	}
	evidence, err := fixtureClient(server.URL, credential).LineageEvidence(context.Background(), detections)
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence) != 3 {
		t.Fatalf("lineage = %+v", evidence)
	}
	for _, item := range evidence[:2] {
		if item.Kind != "sentinel_summary_rule" || item.Name != "Raw summary" ||
			item.Input.Kind != "telemetry_table" || item.Output.Name != "RawSummary_CL" ||
			item.Output.Kind != "telemetry_table" || !item.Output.Monitorable ||
			item.Status != backend.EvidenceAssessed || item.Method != "arm-summary-rule-kql" ||
			item.Detail != "bin 60m; delay 10s" {
			t.Errorf("assessed summary lineage = %+v", item)
		}
	}
	if evidence[0].ID == evidence[1].ID || !strings.Contains(evidence[0].ID, "/summaryLogs/raw-summary#input=") ||
		!strings.Contains(evidence[1].ID, "/summaryLogs/raw-summary#input=") {
		t.Fatalf("summary input edge IDs are not stable and distinct: %q / %q", evidence[0].ID, evidence[1].ID)
	}
	if evidence[2].Status != backend.EvidenceDisabled || evidence[2].Detail != "summary rule is inactive" {
		t.Fatalf("inactive summary lineage = %+v", evidence[2])
	}
	for _, item := range evidence {
		if item.Output.Name == "UnusedSummary_CL" {
			t.Fatalf("lineage included output consumed only by a disabled detection: %+v", item)
		}
	}
	for _, request := range requests {
		if !strings.HasPrefix(request, http.MethodGet+" ") || strings.Contains(request, "/query") || strings.Contains(request, "/search") {
			t.Fatalf("lineage made non-ARM read request: %s", request)
		}
	}
	if !credential.sawScope(armScope) {
		t.Fatalf("credential did not request ARM scope")
	}
}

func TestLineageEvidencePreservesUnresolvedKQLAndBadDestination(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/summaryLogs"):
			fmt.Fprint(w, `{"value":[{
				"id":"/summaryLogs/table-summary","name":"table-summary",
				"properties":{"isActive":true,"provisioningState":"Succeeded","ruleDefinition":{"query":"UnknownParser | summarize count()","destinationTable":"WrongPlan_CL","binSize":60}}
			},{
				"id":"/summaryLogs/function-summary","name":"function-summary",
				"properties":{"isActive":true,"provisioningState":"Succeeded","ruleDefinition":{"query":"UnknownParser() | summarize count()","destinationTable":"GoodSummary_CL","binSize":60}}
			}]}`)
		case strings.HasSuffix(r.URL.Path, "/tables"):
			fmt.Fprint(w, `{"value":[
				{"name":"WrongPlan_CL","properties":{"plan":"Basic","provisioningState":"Succeeded","schema":{"columns":[]}}},
				{"name":"GoodSummary_CL","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"columns":[]}}}
			]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	detections := []backend.Rule{{
		ID: "enabled", Enabled: true, Patterns: []string{"WrongPlan_CL", "GoodSummary_CL"},
	}}
	evidence, err := fixtureClient(server.URL, &recordingCredential{}).LineageEvidence(context.Background(), detections)
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence) != 2 || evidence[0].Status != backend.EvidenceIncomplete || evidence[1].Status != backend.EvidenceIncomplete {
		t.Fatalf("unresolved summary lineage = %+v", evidence)
	}
	var sawFunction, sawWrongPlan bool
	for _, item := range evidence {
		switch item.Input.Kind {
		case "kql_function":
			sawFunction = strings.Contains(item.Detail, "unsupported")
		case "telemetry_table":
			sawWrongPlan = item.Detail == "summary destination table plan is Basic"
		}
	}
	if !sawFunction || !sawWrongPlan {
		t.Fatalf("unresolved/wrong-plan lineage was not preserved: %+v", evidence)
	}
}

func TestLineageEvidenceRejectsCrossHostNextLink(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"value":[],"nextLink":"https://example.invalid/next"}`)
	}))
	defer server.Close()

	_, err := fixtureClient(server.URL, &recordingCredential{}).listSummaryLogs(context.Background())
	if err == nil || !strings.Contains(err.Error(), "outside the configured ARM endpoint") {
		t.Fatalf("cross-host nextLink error = %v", err)
	}
}

func TestLineageEvidencePreservesInventoryAndCatalogFailures(t *testing.T) {
	t.Run("summary inventory", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, `{"error":{"code":"AuthorizationFailed"}}`, http.StatusForbidden)
		}))
		defer server.Close()

		detections := []backend.Rule{{ID: "enabled", Enabled: true, Patterns: []string{"Summary_CL"}}}
		evidence, err := fixtureClient(server.URL, &recordingCredential{}).LineageEvidence(context.Background(), detections)
		if err != nil {
			t.Fatal(err)
		}
		if len(evidence) != 1 || evidence[0].Status != backend.EvidenceUnavailable ||
			evidence[0].Detail != "summary-rule inventory could not be read" {
			t.Fatalf("summary inventory failure = %+v", evidence)
		}
	})

	t.Run("table catalog", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.HasSuffix(r.URL.Path, "/summaryLogs"):
				fmt.Fprint(w, `{"value":[{"id":"/summaryLogs/a","name":"a","properties":{"isActive":true,"provisioningState":"Succeeded","ruleDefinition":{"query":"Raw_CL","destinationTable":"Summary_CL"}}}]}`)
			case strings.HasSuffix(r.URL.Path, "/tables"):
				http.Error(w, `{"error":{"code":"AuthorizationFailed"}}`, http.StatusForbidden)
			default:
				http.NotFound(w, r)
			}
		}))
		defer server.Close()

		detections := []backend.Rule{{ID: "enabled", Enabled: true, Patterns: []string{"Summary_CL"}}}
		evidence, err := fixtureClient(server.URL, &recordingCredential{}).LineageEvidence(context.Background(), detections)
		if err != nil {
			t.Fatal(err)
		}
		if len(evidence) != 1 || evidence[0].Status != backend.EvidenceUnavailable ||
			evidence[0].Detail != "table catalog could not be read for summary-rule lineage" {
			t.Fatalf("table catalog failure = %+v", evidence)
		}
	})
}

func TestLineageEvidenceSkipsWorkspaceInventoryWithoutEnabledTableConsumers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected request without an enabled local table consumer: %s %s", r.Method, r.URL.RequestURI())
	}))
	defer server.Close()

	detections := []backend.Rule{
		{ID: "disabled", Enabled: false, Patterns: []string{"Summary_CL"}},
		{ID: "non-table", Enabled: true, Dependencies: []backend.DependencyRef{{Kind: "sentinel_watchlist", Name: "VIP"}}},
	}
	evidence, err := fixtureClient(server.URL, &recordingCredential{}).LineageEvidence(context.Background(), detections)
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence) != 0 {
		t.Fatalf("lineage without enabled table consumers = %+v", evidence)
	}
}
