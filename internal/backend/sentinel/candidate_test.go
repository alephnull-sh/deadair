package sentinel

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/alephnull-sh/deadair/internal/backend"
)

type candidateCountingTransport struct {
	calls int
}

func (t *candidateCountingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	t.calls++
	return nil, errors.New("candidate test transport should not be called")
}

func sortedRuleIDs(rules []backend.Rule) []string {
	ids := make([]string, len(rules))
	for i, rule := range rules {
		ids[i] = rule.ID
	}
	sort.Strings(ids)
	return ids
}

func TestParseSentinelCandidateDirectScheduledAndNRT(t *testing.T) {
	functions := map[string]WorkspaceFunction{}
	scheduled, err := parseSentinelCandidateJSON([]byte(`{
  "kind":"Scheduled",
  "properties":{
    "displayName":"Failed sign-ins candidate",
    "enabled":false,
    "severity":"High",
    "query":"SigninLogs | where ResultType != 0",
    "queryFrequency":"PT5M",
    "queryPeriod":"PT15M"
  }
}`), functions, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(scheduled) != 1 {
		t.Fatalf("Scheduled candidates = %+v", scheduled)
	}
	got := scheduled[0]
	if got.ID != "Failed sign-ins candidate" || got.Name != got.ID || !got.Enabled ||
		got.RuleType != "scheduled" || got.Severity != "high" || got.RiskScore != 73 ||
		got.Interval != 5*time.Minute || got.Lookback != 15*time.Minute ||
		!reflect.DeepEqual(got.Patterns, []string{"SigninLogs"}) || got.InputStatus != "" {
		t.Fatalf("Scheduled candidate = %+v", got)
	}

	nrt, err := parseSentinelCandidateJSON([]byte(`{
  "id":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/law/providers/Microsoft.SecurityInsights/alertRules/nrt-one",
  "name":"nrt-one",
  "kind":"NRT",
  "properties":{"displayName":"NRT candidate","enabled":false,"query":"SecurityEvent | take 1"}
}`), functions, true)
	if err != nil {
		t.Fatal(err)
	}
	got = nrt[0]
	if got.ID != "nrt-one" || got.BackendObjectID == "" || !got.Enabled || got.RuleType != "nrt" ||
		got.Interval != time.Minute || got.Lookback != time.Minute || got.TimestampOverride != "ingestion_time()" ||
		!reflect.DeepEqual(got.Patterns, []string{"SecurityEvent"}) {
		t.Fatalf("NRT candidate = %+v", got)
	}
}

func TestParseSentinelCandidateSeparatesFuzzyUnionPatterns(t *testing.T) {
	rules, err := parseSentinelCandidateJSON([]byte(`{
  "name":"fuzzy-candidate",
  "kind":"Scheduled",
  "properties":{
    "displayName":"Fuzzy candidate",
    "query":"SecurityEvent | union isfuzzy=true SigninLogs, AuditLogs",
    "queryFrequency":"PT5M",
    "queryPeriod":"PT10M"
  }
}`), map[string]WorkspaceFunction{}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || !reflect.DeepEqual(rules[0].Patterns, []string{"SecurityEvent"}) ||
		!reflect.DeepEqual(rules[0].OptionalPatterns, []string{"SigninLogs", "AuditLogs"}) {
		t.Fatalf("fuzzy candidate = %+v", rules)
	}
}

func TestParseSentinelCandidateMapsZeroOneAndTwoASIMProbes(t *testing.T) {
	tests := []struct {
		name       string
		query      string
		wantStatus backend.ResolutionStatus
		wantNames  []string
	}{
		{name: "zero dynamic probes", query: `_Im_Dns(starttime=StartTime)`, wantStatus: backend.ResolutionUnsupported},
		{name: "one validated probe", query: `_Im_Dns()`, wantNames: []string{"_Im_Dns"}},
		{name: "two validated probes", query: `union _Im_Dns(), _Im_Authentication()`, wantNames: []string{"_Im_Dns", "_Im_Authentication"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := []byte(`{
  "name":"asim-candidate",
  "kind":"Scheduled",
  "properties":{
    "displayName":"ASIM candidate",
    "query":` + strconv.Quote(tt.query) + `,
    "queryFrequency":"PT5M",
    "queryPeriod":"PT10M"
  }
}`)
			rules, err := parseSentinelCandidateJSON(data, map[string]WorkspaceFunction{}, true)
			if err != nil {
				t.Fatal(err)
			}
			if len(rules) != 1 || rules[0].InputStatus != tt.wantStatus || len(rules[0].Dependencies) != len(tt.wantNames) {
				t.Fatalf("candidate = %#v", rules)
			}
			for i, name := range tt.wantNames {
				dependency := rules[0].Dependencies[i]
				if dependency.Kind != "sentinel_asim_parser" || dependency.Name != name || dependency.Expression == "" {
					t.Fatalf("dependency %d = %#v", i, dependency)
				}
			}
		})
	}
}

func TestParseSentinelCandidateMapsLiteralWatchlist(t *testing.T) {
	rules, err := parseSentinelCandidateJSON([]byte(`{
  "name":"watchlist-candidate",
  "kind":"Scheduled",
  "properties":{
    "displayName":"Watchlist candidate",
    "query":"SigninLogs | join (_GetWatchlist('VIPUsers')) on UserPrincipalName",
    "queryFrequency":"PT5M",
    "queryPeriod":"PT10M"
  }
}`), map[string]WorkspaceFunction{}, true)
	if err != nil {
		t.Fatal(err)
	}
	want := backend.DependencyRef{ID: "sentinel_watchlist:vipusers", Name: "VIPUsers", Kind: "sentinel_watchlist", Required: true}
	if len(rules) != 1 || rules[0].InputStatus != "" || len(rules[0].Dependencies) != 1 || !reflect.DeepEqual(rules[0].Dependencies[0], want) {
		t.Fatalf("watchlist candidate = %#v", rules)
	}
}

func TestParseSentinelCandidateARMCurrentLegacyAndNestedResources(t *testing.T) {
	data := []byte(`{
  "$schema":"https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion":"1.0.0.0",
  "parameters":{
    "ruleName":{"type":"string","defaultValue":"current-rule"},
    "ruleQuery":{"type":"string","defaultValue":"SecurityEvent | take 1"}
  },
  "variables":{"frequency":"PT5M"},
  "resources":[
    {
      "type":"Microsoft.SecurityInsights/alertRules@2025-09-01",
      "apiVersion":"2025-09-01",
      "scope":"[format('Microsoft.OperationalInsights/workspaces/{0}', 'law')]",
      "name":"[parameters('ruleName')]",
      "kind":"Scheduled",
      "properties":{
        "displayName":"Current rule",
        "enabled":false,
        "query":"[parameters('ruleQuery')]",
        "queryFrequency":"[variables('frequency')]",
        "queryPeriod":"PT10M"
      }
    },
    {
      "type":"Microsoft.OperationalInsights/workspaces/providers/alertRules",
      "name":"law/Microsoft.SecurityInsights/legacy-rule",
      "kind":"Scheduled",
      "properties":{
        "displayName":"Legacy rule",
        "query":"SigninLogs | take 1",
        "queryFrequency":"PT5M",
        "queryPeriod":"PT10M"
      }
    },
    {
      "type":"Microsoft.OperationalInsights/workspaces",
      "name":"law",
      "resources":[{
        "type":"providers/alertRules",
        "name":"Microsoft.SecurityInsights/nested-rule",
        "kind":"NRT",
        "properties":{"displayName":"Nested rule","query":"AuditLogs | take 1"}
      }]
    },
    {"type":"Microsoft.Insights/diagnosticSettings","name":"ignored","properties":{}}
  ]
}`)
	rules, err := parseSentinelCandidateJSON(data, map[string]WorkspaceFunction{}, true)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := sortedRuleIDs(rules), []string{"current-rule", "legacy-rule", "nested-rule"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ARM candidate IDs = %v, want %v", got, want)
	}
	byID := make(map[string]backend.Rule, len(rules))
	for _, rule := range rules {
		byID[rule.ID] = rule
	}
	if !reflect.DeepEqual(byID["current-rule"].Patterns, []string{"SecurityEvent"}) ||
		byID["current-rule"].Interval != 5*time.Minute || byID["current-rule"].Lookback != 10*time.Minute {
		t.Fatalf("compiled ARM candidate = %+v", byID["current-rule"])
	}
	if !reflect.DeepEqual(byID["legacy-rule"].Patterns, []string{"SigninLogs"}) {
		t.Fatalf("legacy ARM candidate = %+v", byID["legacy-rule"])
	}
	if !reflect.DeepEqual(byID["nested-rule"].Patterns, []string{"AuditLogs"}) || byID["nested-rule"].RuleType != "nrt" {
		t.Fatalf("nested ARM candidate = %+v", byID["nested-rule"])
	}
}

func TestParseSentinelCandidateAzureSentinelYAML(t *testing.T) {
	rules, err := parseSentinelCandidateYAML([]byte(`id: 03e8a895-b5ba-49a0-aed3-f9a997d92fbe
name: Root login
severity: Medium
requiredDataConnectors:
  - connectorId: CustomLogsAma
    dataTypes:
      - ConnectorMetadataOnly_CL
queryFrequency: 1h
queryPeriod: 14d
query: |
  let recent = vCenter_CL | where TimeGenerated > ago(1h);
  recent | take 1
kind: Scheduled
`), map[string]WorkspaceFunction{}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("YAML candidates = %+v", rules)
	}
	got := rules[0]
	if got.ID != "03e8a895-b5ba-49a0-aed3-f9a997d92fbe" || got.Name != "Root login" ||
		got.Interval != time.Hour || got.Lookback != 14*24*time.Hour ||
		!reflect.DeepEqual(got.Patterns, []string{"vCenter_CL"}) {
		t.Fatalf("YAML candidate = %+v", got)
	}
	for _, pattern := range got.Patterns {
		if pattern == "ConnectorMetadataOnly_CL" {
			t.Fatal("requiredDataConnectors created a graph edge")
		}
	}
}

func TestParseSentinelCandidateUnresolvedRequiredARMValuesStayUnassessed(t *testing.T) {
	rules, err := parseSentinelCandidateJSON([]byte(`{
  "$schema":"deploymentTemplate.json#",
  "parameters":{
    "query":{"type":"string"},
    "frequency":{"type":"string"}
  },
  "resources":[{
    "type":"Microsoft.SecurityInsights/alertRules",
    "name":"candidate-one",
    "kind":"Scheduled",
    "properties":{
      "displayName":"Candidate one",
      "query":"[parameters('query')]",
      "queryFrequency":"[parameters('frequency')]",
      "queryPeriod":"PT10M"
    }
  }]
}`), map[string]WorkspaceFunction{}, true)
	if err != nil {
		t.Fatal(err)
	}
	got := rules[0]
	if got.InputStatus != backend.ResolutionUnavailable || got.Interval != 0 || got.Lookback != 10*time.Minute || len(got.Patterns) != 0 {
		t.Fatalf("unresolved ARM candidate = %+v", got)
	}
	if !strings.Contains(got.InputDetail, "query could not be resolved") || !strings.Contains(got.InputDetail, "frequency could not be resolved") {
		t.Fatalf("unresolved candidate detail = %q", got.InputDetail)
	}
}

func TestParseSentinelCandidateUsesWorkspaceFunctions(t *testing.T) {
	functions := map[string]WorkspaceFunction{
		"DeadairSource": {Body: "SecurityEvent | take 1"},
	}
	rules, err := parseSentinelCandidateJSON([]byte(`{
  "name":"function-rule",
  "kind":"Scheduled",
  "properties":{
    "displayName":"Function rule",
    "query":"DeadairSource()",
    "queryFrequency":"PT5M",
    "queryPeriod":"PT10M"
  }
}`), functions, true)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(rules[0].Patterns, []string{"SecurityEvent"}) || rules[0].InputStatus != "" {
		t.Fatalf("function candidate = %+v", rules[0])
	}
}

func TestParseSentinelCandidateRejectsUnsafeOrMalformedInputs(t *testing.T) {
	tests := []struct {
		name string
		data string
		want string
	}{
		{name: "raw Bicep", data: `param workspace string
resource rule 'Microsoft.SecurityInsights/alertRules@2025-09-01' = {}`, want: "raw Bicep"},
		{name: "parameter file", data: `{"parameters":{"workspace":{"value":"law"}}}`, want: "parameter-only"},
		{name: "AlertRuleTemplate", data: `{"type":"Microsoft.SecurityInsights/alertRuleTemplates","name":"template","kind":"Scheduled","properties":{}}`, want: "AlertRuleTemplate"},
		{name: "duplicate JSON key", data: `{"kind":"Scheduled","Kind":"NRT","properties":{}}`, want: "duplicate JSON key"},
		{name: "JSON array", data: `[{"kind":"NRT"}]`, want: "must contain an object"},
		{name: "unknown kind", data: `{"name":"fusion","kind":"Fusion","properties":{"displayName":"Fusion","query":"SecurityEvent"}}`, want: "unsupported Sentinel rule kind"},
		{name: "missing query", data: `{"name":"missing","kind":"Scheduled","properties":{"displayName":"Missing","queryFrequency":"PT5M","queryPeriod":"PT10M"}}`, want: "properties.query is required"},
		{name: "wrong query type", data: `{"name":"wrong-type","kind":"NRT","properties":{"displayName":"Wrong type","query":42}}`, want: "value must be a string"},
		{name: "bad timing", data: `{"name":"timing","kind":"Scheduled","properties":{"displayName":"Timing","query":"SecurityEvent","queryFrequency":"five minutes","queryPeriod":"PT10M"}}`, want: "queryFrequency"},
		{name: "empty identity", data: `{"kind":"NRT","properties":{"displayName":"","query":"SecurityEvent"}}`, want: "empty identity"},
		{name: "ARM resource missing name", data: `{"resources":[{"type":"Microsoft.SecurityInsights/alertRules","kind":"NRT","properties":{"displayName":"No name","query":"SecurityEvent"}}]}`, want: "name is required"},
		{name: "duplicate identities", data: `{"resources":[{"type":"Microsoft.SecurityInsights/alertRules","name":"same","kind":"NRT","properties":{"displayName":"One","query":"SecurityEvent"}},{"type":"Microsoft.SecurityInsights/alertRules","name":"SAME","kind":"NRT","properties":{"displayName":"Two","query":"SigninLogs"}}]}`, want: "duplicate Sentinel candidate identity"},
		{name: "YAML duplicate key", data: "id: one\nname: First\nName: Second\nkind: NRT\nquery: SecurityEvent\n", want: "duplicate YAML key"},
		{name: "YAML multiple docs", data: "id: one\nname: One\nkind: NRT\nquery: SecurityEvent\n---\nid: two\nname: Two\nkind: NRT\nquery: SigninLogs\n", want: "exactly one document"},
		{name: "YAML sequence", data: "- id: one\n  name: One\n  kind: NRT\n  query: SecurityEvent\n", want: "one mapping"},
	}
	client := &Client{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := client.ParseCandidates(context.Background(), []byte(tt.data))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestParseSentinelCandidateParameterCycleStaysUnassessed(t *testing.T) {
	rules, err := parseSentinelCandidateJSON([]byte(`{
  "parameters":{"query":{"type":"string","defaultValue":"[parameters('query')]"}},
  "resources":[{
    "type":"Microsoft.SecurityInsights/alertRules",
    "name":"cyclic-rule",
    "kind":"NRT",
    "properties":{"displayName":"Cyclic rule","query":"[parameters('query')]"}
  }]
}`), map[string]WorkspaceFunction{}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].InputStatus != backend.ResolutionUnavailable || !strings.Contains(rules[0].InputDetail, "query could not be resolved") {
		t.Fatalf("cyclic candidate = %+v", rules)
	}
}

func TestParseSentinelCandidateHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := (&Client{}).ParseCandidates(ctx, []byte(`{"kind":"NRT","properties":{"displayName":"NRT","query":"SecurityEvent"}}`))
	if err == nil || !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("canceled parse error = %v", err)
	}
}

func TestParseSentinelCandidateRejectsInvalidFilesBeforeAzureAccess(t *testing.T) {
	invalid := []string{
		`{"kind":`,
		"id: one\nname: One\nName: Duplicate\nkind: NRT\nquery: SecurityEvent\n",
		"resource rule 'Microsoft.SecurityInsights/alertRules@2025-09-01' = {}",
		`{"parameters":{"workspace":{"value":"law"}}}`,
		`{"type":"Microsoft.SecurityInsights/alertRuleTemplates","name":"template","kind":"Scheduled","properties":{}}`,
	}
	for i, data := range invalid {
		transport := &candidateCountingTransport{}
		credential := &recordingCredential{}
		client := &Client{
			SubscriptionID: "sub", ResourceGroup: "rg", WorkspaceName: "law", WorkspaceID: "workspace-id",
			workspaceIDValidated: true,
			Credential:           credential,
			HTTP:                 &http.Client{Transport: transport},
		}
		if _, err := client.ParseCandidates(context.Background(), []byte(data)); err == nil {
			t.Fatalf("invalid candidate %d unexpectedly parsed", i+1)
		}
		credential.mu.Lock()
		tokenCalls := len(credential.scopes)
		credential.mu.Unlock()
		if transport.calls != 0 || tokenCalls != 0 {
			t.Fatalf("invalid candidate %d made %d transport and %d token calls", i+1, transport.calls, tokenCalls)
		}
	}
}

func TestParseSentinelCandidateLoadsWorkspaceFunctionsAfterValidation(t *testing.T) {
	credential := &recordingCredential{}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodPost || r.URL.Path != "/v1/workspaces/workspace-id/metadata" {
			t.Fatalf("function metadata request = %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"functions":[{"name":"DeadairSource","body":"SecurityEvent | take 1","parameters":""}]}`))
	}))
	defer server.Close()

	client := fixtureClient(server.URL, credential)
	rules, err := client.ParseCandidates(context.Background(), []byte(`{
  "name":"function-rule",
  "kind":"Scheduled",
  "properties":{
    "displayName":"Function rule",
    "query":"DeadairSource()",
    "queryFrequency":"PT5M",
    "queryPeriod":"PT10M"
  }
}`))
	if err != nil {
		t.Fatal(err)
	}
	if requests != 1 || len(rules) != 1 || !reflect.DeepEqual(rules[0].Patterns, []string{"SecurityEvent"}) || rules[0].InputStatus != "" {
		t.Fatalf("function metadata requests/rule = %d / %+v", requests, rules)
	}
}
