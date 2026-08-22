package sentinel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alephnull-sh/deadair/internal/backend"
)

const ruleHealthTestResourceID = "/subscriptions/home-sub/resourceGroups/home-rg/providers/Microsoft.OperationalInsights/workspaces/home-law/providers/Microsoft.SecurityInsights/alertRules/rule-a"

func writeRuleHealthResult(w http.ResponseWriter, rows string) {
	writeAllowedLogsResult(w, "SentinelHealth", `[{
		"name":"PrimaryResult",
		"columns":[
			{"name":"SentinelResourceId","type":"string"},
			{"name":"SentinelResourceKind","type":"string"},
			{"name":"Status","type":"string"},
			{"name":"TimeGenerated","type":"datetime"}
		],
		"rows":`+rows+`
	}]`)
}

func ruleHealthTargetFixture(modifiedAt time.Time) ruleHealthTarget {
	if modifiedAt.IsZero() {
		modifiedAt = time.Date(2026, 8, 21, 11, 0, 0, 0, time.UTC)
	}
	return ruleHealthTarget{
		ruleID: "rule-a", resourceID: ruleHealthTestResourceID,
		kind: "Scheduled", modifiedAt: modifiedAt, interval: time.Hour,
	}
}

func TestSentinelRuleCarriesCurrentModificationTime(t *testing.T) {
	raw := testAlertRule("rule-a", "SecurityEvent | take 1")
	raw.ID = ruleHealthTestResourceID
	raw.Properties.LastModifiedUTC = "2026-08-21T11:00:00Z"
	raw.SystemData.LastModifiedAt = "2026-08-21T10:00:00Z"
	rule := sentinelRule(raw, nil, true)
	if !rule.ModifiedAt.Equal(time.Date(2026, 8, 21, 11, 0, 0, 0, time.UTC)) {
		t.Fatalf("properties.lastModifiedUtc = %s", rule.ModifiedAt)
	}

	raw.Properties.LastModifiedUTC = "not-a-time"
	rule = sentinelRule(raw, nil, true)
	if !rule.ModifiedAt.Equal(time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)) {
		t.Fatalf("systemData.lastModifiedAt fallback = %s", rule.ModifiedAt)
	}
}

func TestReadRuleHealthEvidenceRequiresLatestExactPostModificationSuccess(t *testing.T) {
	now := time.Now().UTC()
	recentRun := now.Add(-30 * time.Minute).Format(time.RFC3339Nano)
	tests := []struct {
		name       string
		rows       string
		modifiedAt time.Time
		wantStatus backend.ResolutionStatus
		wantDetail string
	}{
		{
			name:       "exact success",
			rows:       fmt.Sprintf(`[[%q,"Scheduled","Success",%q]]`, ruleHealthTestResourceID, recentRun),
			modifiedAt: now.Add(-2 * time.Hour),
			wantStatus: backend.ResolutionResolved,
			wantDetail: "succeeded",
		},
		{
			name:       "resource ID mismatch",
			rows:       fmt.Sprintf(`[[%q,"Scheduled","Success",%q]]`, ruleHealthTestResourceID+"-other", recentRun),
			wantStatus: backend.ResolutionUnavailable,
			wantDetail: "malformed",
		},
		{
			name:       "kind mismatch",
			rows:       fmt.Sprintf(`[[%q,"NRT","Success",%q]]`, ruleHealthTestResourceID, recentRun),
			wantStatus: backend.ResolutionUnavailable,
			wantDetail: "malformed",
		},
		{
			name:       "latest failure",
			rows:       fmt.Sprintf(`[[%q,"Scheduled","Failure",%q]]`, ruleHealthTestResourceID, recentRun),
			wantStatus: backend.ResolutionUnavailable,
			wantDetail: "did not succeed",
		},
		{
			name:       "success before modification",
			rows:       fmt.Sprintf(`[[%q,"Scheduled","Success",%q]]`, ruleHealthTestResourceID, recentRun),
			modifiedAt: now.Add(-29 * time.Minute),
			wantStatus: backend.ResolutionUnavailable,
			wantDetail: "predates",
		},
		{
			name:       "success inside seven days but older than cadence",
			rows:       fmt.Sprintf(`[[%q,"Scheduled","Success",%q]]`, ruleHealthTestResourceID, now.Add(-6*24*time.Hour).Format(time.RFC3339Nano)),
			modifiedAt: now.Add(-7 * 24 * time.Hour),
			wantStatus: backend.ResolutionUnavailable,
			wantDetail: "configured cadence",
		},
		{
			name:       "no row",
			rows:       `[]`,
			wantStatus: backend.ResolutionUnavailable,
			wantDetail: "no exact",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var query string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var request logsQueryRequest
				if err := jsonNewDecoder(r).Decode(&request); err != nil {
					t.Fatal(err)
				}
				query = request.Query
				writeRuleHealthResult(w, tt.rows)
			}))
			defer server.Close()
			client := fixtureClient(server.URL, &recordingCredential{})
			got := client.readRuleHealthEvidence(context.Background(), []ruleHealthTarget{ruleHealthTargetFixture(tt.modifiedAt)})["rule-a"]
			if got.status != tt.wantStatus || !strings.Contains(got.detail, tt.wantDetail) {
				t.Fatalf("observation = %+v, want %s containing %q", got, tt.wantStatus, tt.wantDetail)
			}
			for _, fragment := range []string{"_SentinelHealth()", "TimeGenerated between (ago(7d) .. now())", "SentinelResourceId == " + kqlStringLiteral(ruleHealthTestResourceID), "SentinelResourceKind == 'Scheduled'"} {
				if !strings.Contains(query, fragment) {
					t.Fatalf("query omitted %q: %s", fragment, query)
				}
			}
			if strings.Contains(query, "SentinelResourceName") || strings.Contains(query, "Reason") || strings.Contains(query, "Description") {
				t.Fatalf("query used a forbidden fallback or raw error field: %s", query)
			}
		})
	}
}

func TestClassifyRuleHealthObservationCadenceBoundaries(t *testing.T) {
	observedAt := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name       string
		target     ruleHealthTarget
		runAt      time.Time
		wantStatus backend.ResolutionStatus
	}{
		{
			name:       "scheduled exact cadence and delay boundary",
			target:     ruleHealthTarget{kind: "Scheduled", interval: time.Hour, modifiedAt: observedAt.Add(-2 * time.Hour)},
			runAt:      observedAt.Add(-(time.Hour + scheduledRuleExecutionDelay)),
			wantStatus: backend.ResolutionResolved,
		},
		{
			name:       "scheduled one nanosecond past boundary",
			target:     ruleHealthTarget{kind: "Scheduled", interval: time.Hour, modifiedAt: observedAt.Add(-2 * time.Hour)},
			runAt:      observedAt.Add(-(time.Hour + scheduledRuleExecutionDelay)).Add(-time.Nanosecond),
			wantStatus: backend.ResolutionUnavailable,
		},
		{
			name:       "nrt exact cadence and delay boundary",
			target:     ruleHealthTarget{kind: "NRT", interval: time.Minute, modifiedAt: observedAt.Add(-time.Hour)},
			runAt:      observedAt.Add(-(time.Minute + nrtRuleExecutionDelay)),
			wantStatus: backend.ResolutionResolved,
		},
		{
			name:       "nrt one nanosecond past boundary",
			target:     ruleHealthTarget{kind: "NRT", interval: time.Minute, modifiedAt: observedAt.Add(-time.Hour)},
			runAt:      observedAt.Add(-(time.Minute + nrtRuleExecutionDelay)).Add(-time.Nanosecond),
			wantStatus: backend.ResolutionUnavailable,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyRuleHealthObservation(tt.target, ruleHealthRow{status: "Success", runAt: tt.runAt}, true, observedAt)
			if got.status != tt.wantStatus {
				t.Fatalf("observation = %+v, want %s", got, tt.wantStatus)
			}
		})
	}
}

func TestReadRuleHealthEvidenceRejectsMissingModificationTimeAndFutureRows(t *testing.T) {
	t.Run("missing modification time", func(t *testing.T) {
		var calls atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			writeRuleHealthResult(w, fmt.Sprintf(`[[%q,"Scheduled","Success","2026-08-21T12:00:00Z"]]`, ruleHealthTestResourceID))
		}))
		defer server.Close()
		client := fixtureClient(server.URL, &recordingCredential{})
		target := ruleHealthTargetFixture(time.Time{})
		target.modifiedAt = time.Time{}
		got := client.readRuleHealthEvidence(context.Background(), []ruleHealthTarget{target})["rule-a"]
		if got.status != backend.ResolutionUnavailable || !strings.Contains(got.detail, "modification time") {
			t.Fatalf("missing-modification observation = %+v", got)
		}
		if calls.Load() != 0 {
			t.Fatalf("SentinelHealth calls with missing modification time = %d, want 0", calls.Load())
		}
	})

	for _, tt := range []struct {
		name     string
		kind     string
		interval time.Duration
	}{
		{name: "missing scheduled cadence", kind: "Scheduled"},
		{name: "scheduled cadence below supported minimum", kind: "Scheduled", interval: minScheduledRuleInterval - time.Nanosecond},
		{name: "scheduled cadence above supported maximum", kind: "Scheduled", interval: maxScheduledRuleInterval + time.Nanosecond},
		{name: "nonstandard nrt cadence", kind: "NRT", interval: 2 * time.Minute},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				writeRuleHealthResult(w, fmt.Sprintf(`[[%q,%q,"Success","2026-08-21T12:00:00Z"]]`, ruleHealthTestResourceID, tt.kind))
			}))
			defer server.Close()
			client := fixtureClient(server.URL, &recordingCredential{})
			target := ruleHealthTargetFixture(time.Time{})
			target.kind = tt.kind
			target.interval = tt.interval
			got := client.readRuleHealthEvidence(context.Background(), []ruleHealthTarget{target})["rule-a"]
			if got.status != backend.ResolutionUnavailable || !strings.Contains(got.detail, "cadence") {
				t.Fatalf("invalid-cadence observation = %+v", got)
			}
			if calls.Load() != 0 {
				t.Fatalf("SentinelHealth calls with invalid cadence = %d, want 0", calls.Load())
			}
		})
	}

	t.Run("future row", func(t *testing.T) {
		future := time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			writeRuleHealthResult(w, fmt.Sprintf(`[[%q,"Scheduled","Success",%q]]`, ruleHealthTestResourceID, future))
		}))
		defer server.Close()
		client := fixtureClient(server.URL, &recordingCredential{})
		got := client.readRuleHealthEvidence(context.Background(), []ruleHealthTarget{ruleHealthTargetFixture(time.Time{})})["rule-a"]
		if got.status != backend.ResolutionUnavailable || !strings.Contains(got.detail, "future timestamp") {
			t.Fatalf("future-row observation = %+v", got)
		}
	})
}

// jsonNewDecoder keeps the fixture request parsing in one place without
// changing the production JSON contract under test.
func jsonNewDecoder(r *http.Request) *json.Decoder {
	return json.NewDecoder(r.Body)
}

func TestReadRuleHealthEvidenceKeepsDeniedPartialMalformedAndBudgetUnavailable(t *testing.T) {
	tests := []struct {
		name        string
		response    string
		statusCode  int
		primeBudget bool
		wantDetail  string
	}{
		{name: "forbidden", statusCode: http.StatusForbidden, response: `denied`, wantDetail: "scanner identity"},
		{name: "partial", response: `{"error":{"code":"PartialError","message":"private server text"},"tables":[{"name":"PrimaryResult","columns":[],"rows":[]}]}`, wantDetail: "partial or failed"},
		{name: "malformed", response: `{"tables":[{"name":"PrimaryResult","columns":[{"name":"Status","type":"string"}],"rows":[["Success"]]}],"permissions":{"dataSources":[{"allowTables":["SentinelHealth"]}]},"dataSources":[{"tables":["SentinelHealth"]}]}`, wantDetail: "malformed"},
		{name: "budget", primeBudget: true, wantDetail: "budget was exhausted"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tt.statusCode != 0 {
					http.Error(w, tt.response, tt.statusCode)
					return
				}
				fmt.Fprint(w, tt.response)
			}))
			defer server.Close()
			client := fixtureClient(server.URL, &recordingCredential{})
			if tt.primeBudget {
				client.logsQueryLimit = 1
				client.claimLogsQuery()
			}
			got := client.readRuleHealthEvidence(context.Background(), []ruleHealthTarget{ruleHealthTargetFixture(time.Time{})})["rule-a"]
			if got.status != backend.ResolutionUnavailable || !strings.Contains(got.detail, tt.wantDetail) || strings.Contains(got.detail, "private server text") {
				t.Fatalf("observation = %+v, want unavailable containing %q and no raw body", got, tt.wantDetail)
			}
		})
	}
}

func TestReadRuleHealthEvidenceCapsBatches(t *testing.T) {
	var queries atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		queries.Add(1)
		writeRuleHealthResult(w, `[]`)
	}))
	defer server.Close()
	client := fixtureClient(server.URL, &recordingCredential{})
	targets := make([]ruleHealthTarget, sentinelHealthRulesPerBatch*maxSentinelHealthBatches+1)
	for i := range targets {
		targets[i] = ruleHealthTarget{
			ruleID:     fmt.Sprintf("rule-%03d", i),
			resourceID: fmt.Sprintf("%s-%03d", ruleHealthTestResourceID, i),
			kind:       "Scheduled",
			modifiedAt: time.Date(2026, 8, 21, 11, 0, 0, 0, time.UTC),
			interval:   time.Hour,
		}
	}
	got := client.readRuleHealthEvidence(context.Background(), targets)
	if queries.Load() != maxSentinelHealthBatches {
		t.Fatalf("SentinelHealth queries = %d, want %d", queries.Load(), maxSentinelHealthBatches)
	}
	overflow := got[fmt.Sprintf("rule-%03d", len(targets)-1)]
	if overflow.status != backend.ResolutionUnavailable || !strings.Contains(overflow.detail, "bounded per-scan rule limit") {
		t.Fatalf("overflow evidence = %+v", overflow)
	}
}

type ruleHealthCountingTransport struct{ calls atomic.Int32 }

func (t *ruleHealthCountingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	t.calls.Add(1)
	return nil, fmt.Errorf("unexpected SentinelHealth request")
}

func TestApplyRuleHealthEvidenceSkipsCandidateMissingObjectDisabledAndSameSubscription(t *testing.T) {
	identityOutcome := sentinelSelectorOutcome{
		selectorKind: "sentinel_rule_execution_identity",
		status:       backend.ResolutionUnavailable,
		dependencies: []backend.DependencyRef{{Kind: "sentinel_rule_execution_identity", Required: true}},
	}
	tests := []struct {
		name         string
		rule         backend.Rule
		installed    bool
		withIdentity bool
	}{
		{name: "candidate", rule: backend.Rule{ID: "candidate", BackendObjectID: ruleHealthTestResourceID, Enabled: true, RuleType: "scheduled"}, withIdentity: true},
		{name: "missing object ID", rule: backend.Rule{ID: "missing", Enabled: true, RuleType: "scheduled"}, installed: true, withIdentity: true},
		{name: "disabled", rule: backend.Rule{ID: "disabled", BackendObjectID: ruleHealthTestResourceID, Enabled: false, RuleType: "scheduled"}, installed: true, withIdentity: true},
		{name: "same subscription", rule: backend.Rule{ID: "same-sub", BackendObjectID: ruleHealthTestResourceID, Enabled: true, RuleType: "scheduled"}, installed: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := &ruleHealthCountingTransport{}
			client := &Client{HTTP: &http.Client{Transport: transport}}
			if tt.installed {
				client.setInstalledRules([]backend.Rule{tt.rule})
			}
			outcomes := map[string][]sentinelSelectorOutcome{tt.rule.ID: nil}
			if tt.withIdentity {
				outcomes[tt.rule.ID] = []sentinelSelectorOutcome{identityOutcome}
			}
			client.applyRuleHealthEvidence(context.Background(), []backend.Rule{tt.rule}, outcomes)
			if transport.calls.Load() != 0 {
				t.Fatalf("SentinelHealth calls = %d, want 0", transport.calls.Load())
			}
		})
	}
}

func TestApplyRuleHealthEvidenceDoesNotResolveOptionalExecutionIdentity(t *testing.T) {
	transport := &ruleHealthCountingTransport{}
	client := &Client{HTTP: &http.Client{Transport: transport}}
	rule := backend.Rule{
		ID: "optional", BackendObjectID: ruleHealthTestResourceID, Enabled: true, RuleType: "scheduled",
		ModifiedAt: time.Date(2026, 8, 21, 11, 0, 0, 0, time.UTC),
	}
	client.setInstalledRules([]backend.Rule{rule})
	outcomes := map[string][]sentinelSelectorOutcome{rule.ID: {{
		selectorKind: "sentinel_rule_execution_identity",
		method:       "sentinel_rule_execution_identity_diagnostic",
		optional:     true,
		status:       backend.ResolutionUnavailable,
		dependencies: []backend.DependencyRef{{Kind: "sentinel_rule_execution_identity", Required: false}},
	}}}
	client.applyRuleHealthEvidence(context.Background(), []backend.Rule{rule}, outcomes)
	if transport.calls.Load() != 0 {
		t.Fatalf("SentinelHealth calls for optional identity = %d, want 0", transport.calls.Load())
	}
	got := outcomes[rule.ID][0]
	if got.status != backend.ResolutionUnavailable || !got.optional || got.method != "sentinel_rule_execution_identity_diagnostic" {
		t.Fatalf("optional execution identity was changed = %+v", got)
	}
}
