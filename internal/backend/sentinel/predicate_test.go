package sentinel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alephnull-sh/deadair/internal/backend"
)

func TestExtractPredicateFreshnessCanonicalizesClosedLeadingPredicates(t *testing.T) {
	t.Parallel()
	selector, ok := ExtractPredicateFreshness(`SecurityEvent
| where DeviceVendor == "Palo ' Alto" and (EventID in (4624, 4625))
| where OperationName == 'Create'
| project TimeGenerated, DeviceVendor`)
	if !ok {
		t.Fatal("ExtractPredicateFreshness() rejected a closed predicate")
	}
	want := backend.PredicateFreshnessSelector{
		Source:     "SecurityEvent",
		Expression: "DeviceVendor == 'Palo '' Alto' and EventID in (4624, 4625) and OperationName == 'Create'",
		Fields:     []string{"DeviceVendor", "EventID", "OperationName"},
	}
	if !reflect.DeepEqual(selector, want) {
		t.Fatalf("selector = %+v, want %+v", selector, want)
	}

	quoted, ok := ExtractPredicateFreshness(`['custom-table'] | WHERE DeviceProduct in ('one', 'two')`)
	if !ok || quoted.Source != "custom-table" || quoted.Expression != "DeviceProduct in ('one', 'two')" {
		t.Fatalf("quoted-table selector = %+v, %v", quoted, ok)
	}

	filtered, ok := ExtractPredicateFreshness(`SecurityEvent
| FILTER DeviceVendor == 'Contoso'
| where EventID in (4624, 4625)
| filter OperationName == 'Create'
| project TimeGenerated`)
	if !ok || filtered.Expression != "DeviceVendor == 'Contoso' and EventID in (4624, 4625) and OperationName == 'Create'" ||
		!reflect.DeepEqual(filtered.Fields, []string{"DeviceVendor", "EventID", "OperationName"}) {
		t.Fatalf("mixed where/filter selector = %+v, %v", filtered, ok)
	}

	for name, query := range map[string]string{
		"plain slash":   `SecurityEvent | where DeviceProduct == 'Contoso/Firewall'`,
		"doubled quote": `SecurityEvent | where DeviceVendor == 'Contoso''s'`,
	} {
		if selector, ok := ExtractPredicateFreshness(query); !ok || selector.Expression == "" {
			t.Errorf("%s safe literal selector = %+v, %v", name, selector, ok)
		}
	}
}

func TestExtractPredicateFreshnessRejectsAnyUnprovedSlice(t *testing.T) {
	t.Parallel()
	tooManyConjuncts := "SecurityEvent | where " + strings.TrimSuffix(strings.Repeat("DeviceVendor == 'x' and ", maxPredicateConjuncts+1), " and ")
	values := make([]string, maxPredicateValues+1)
	for i := range values {
		values[i] = fmt.Sprintf("%d", i)
	}
	tests := map[string]string{
		"no predicate":                `SecurityEvent | project DeviceVendor`,
		"predicate after projection":  `SecurityEvent | project DeviceVendor | where DeviceVendor == 'x'`,
		"later predicate":             `SecurityEvent | where DeviceVendor == 'x' | project DeviceVendor | where DeviceVendor == 'y'`,
		"filter after projection":     `SecurityEvent | project DeviceVendor | filter DeviceVendor == 'x'`,
		"later filter":                `SecurityEvent | where DeviceVendor == 'x' | project DeviceVendor | filter DeviceVendor == 'y'`,
		"unsupported filter":          `SecurityEvent | filter DeviceVendor == 'x' and TimeGenerated > ago(1h)`,
		"unsupported field":           `SecurityEvent | where Computer == 'host'`,
		"unsupported conjunct":        `SecurityEvent | where DeviceVendor == 'x' and TimeGenerated > ago(1h)`,
		"or expression":               `SecurityEvent | where DeviceVendor == 'x' or DeviceProduct == 'y'`,
		"predicate function":          `SecurityEvent | where tolower(DeviceVendor) == 'x'`,
		"dynamic predicate":           `SecurityEvent | where DeviceVendor in (dynamic(['x']))`,
		"row value":                   `SecurityEvent | where DeviceVendor == DeviceProduct`,
		"case-insensitive membership": `SecurityEvent | where DeviceVendor in~ ('x')`,
		"empty membership":            `SecurityEvent | where DeviceVendor in ()`,
		"invalid numeric literal":     `SecurityEvent | where EventID == .`,
		"escaped quote literal":       `SecurityEvent | where DeviceVendor == 'Contoso\'Sec'`,
		"escaped backslash literal":   `SecurityEvent | where DeviceProduct == 'C:\\Windows'`,
		"escaped slash literal":       `SecurityEvent | where DeviceProduct == 'Contoso\/Firewall'`,
		"escaped newline literal":     `SecurityEvent | where DeviceVendor == 'Contoso\nFirewall'`,
		"escaped tab literal":         `SecurityEvent | where DeviceVendor == 'Contoso\tFirewall'`,
		"literal newline":             "SecurityEvent | where DeviceVendor == 'Contoso\nFirewall'",
		"literal tab":                 "SecurityEvent | where DeviceVendor == 'Contoso\tFirewall'",
		"verbatim single quote":       `SecurityEvent | where DeviceProduct == @'C:\Windows'`,
		"verbatim double quote":       `SecurityEvent | where DeviceProduct == @"C:\Windows"`,
		"plain verbatim single quote": `SecurityEvent | where DeviceProduct == @'Contoso'`,
		"plain verbatim double quote": `SecurityEvent | where DeviceProduct == @"Contoso"`,
		"escaped quoted source":       `['custom\-table'] | where DeviceProduct == 'Contoso'`,
		"let source":                  `let T = SecurityEvent; T | where DeviceVendor == 'x'`,
		"workspace function":          `Parser() | where DeviceVendor == 'x'`,
		"remote source":               `workspace('other').SecurityEvent | where DeviceVendor == 'x'`,
		"leading union":               `union SecurityEvent | where DeviceVendor == 'x'`,
		"pipeline union same table":   `SecurityEvent | where DeviceVendor == 'x' | union SecurityEvent`,
		"join same table":             `SecurityEvent | where DeviceVendor == 'x' | join SecurityEvent on EventID`,
		"membership subquery":         `SecurityEvent | where EventID in (OtherTable | project EventID)`,
		"too many conjuncts":          tooManyConjuncts,
		"too many values":             `SecurityEvent | where EventID in (` + strings.Join(values, ",") + `)`,
	}
	for name, query := range tests {
		query := query
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if selector, ok := ExtractPredicateFreshness(query); ok {
				t.Fatalf("ExtractPredicateFreshness() = %+v, want rejected", selector)
			}
		})
	}
}

func TestSentinelRuleParsersAttachOnlyProvedPredicateFreshness(t *testing.T) {
	query := `SecurityEvent | where EventID in (4624, 4625) | project TimeGenerated`
	installed := sentinelRule(testAlertRule("predicate-rule", query), map[string]WorkspaceFunction{}, true)
	if len(installed.PredicateFreshness) != 1 || installed.PredicateFreshness[0].Source != "SecurityEvent" {
		t.Fatalf("installed predicate freshness = %+v", installed.PredicateFreshness)
	}

	candidate, err := parseCandidateRule(map[string]any{
		"name": "candidate-predicate", "kind": "Scheduled",
		"properties": map[string]any{
			"displayName": "Candidate predicate", "query": query,
			"queryFrequency": "PT5M", "queryPeriod": "PT10M", "severity": "Medium",
		},
	}, &candidateResolver{}, "predicate candidate", map[string]WorkspaceFunction{}, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(candidate.PredicateFreshness, installed.PredicateFreshness) {
		t.Fatalf("candidate predicate freshness = %+v, installed = %+v", candidate.PredicateFreshness, installed.PredicateFreshness)
	}

	unsupported := sentinelRule(testAlertRule("unsupported-predicate", `SecurityEvent | where Computer == 'host'`), nil, true)
	if len(unsupported.PredicateFreshness) != 0 {
		t.Fatalf("unsupported predicate attached freshness selector: %+v", unsupported.PredicateFreshness)
	}
}

func TestRulePredicateFreshnessEvidenceUsesRuleClockAndFailsClosed(t *testing.T) {
	credential := &recordingCredential{}
	var queries []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/tables"):
			fmt.Fprint(w, `{"value":[
				{"name":"ScheduledTable","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"standardColumns":[{"name":"TimeGenerated","type":"datetime"},{"name":"DeviceVendor","type":"string"}]}}},
				{"name":"NRTTable","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"columns":[{"name":"DeviceProduct","type":"string"}]}}},
				{"name":"MissingField","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"columns":[{"name":"TimeGenerated","type":"datetime"}]}}},
				{"name":"AuxTable","properties":{"plan":"Auxiliary","provisioningState":"Succeeded","schema":{"columns":[{"name":"TimeGenerated","type":"datetime"},{"name":"DeviceVendor","type":"string"}]}}},
				{"name":"IncompleteSchema","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{}}}
			]}`)
		case strings.HasSuffix(r.URL.Path, "/query"):
			var request logsQueryRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			queries = append(queries, request.Query)
			table := "ScheduledTable"
			if strings.HasPrefix(request.Query, "NRTTable ") {
				table = "NRTTable"
			}
			writeAllowedLogsResult(w, table, `[{"name":"PrimaryResult","columns":[{"name":"LastEvent","type":"datetime"}],"rows":[["2026-08-20T12:34:56Z"]]}]`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := fixtureClient(server.URL, credential)

	scheduled := mustPredicateSelector(t, `ScheduledTable | where DeviceVendor == 'Palo Alto'`)
	nrt := mustPredicateSelector(t, `NRTTable | where DeviceProduct in ('one', 'two')`)
	missing := mustPredicateSelector(t, `MissingField | where EventID == 4624`)
	aux := mustPredicateSelector(t, `AuxTable | where DeviceVendor == 'x'`)
	incomplete := mustPredicateSelector(t, `IncompleteSchema | where DeviceVendor == 'x'`)
	requests := []backend.RulePredicateFreshnessRequest{
		{RuleID: "z-mixed", Source: backend.Source{Name: "ScheduledTable"}, Basis: backend.FreshnessMixed, Selector: scheduled},
		{RuleID: "nrt", BackendObjectID: "/rules/nrt", Source: backend.Source{Name: "NRTTable"}, Basis: backend.FreshnessIngestionTime, Selector: nrt},
		{RuleID: "missing", Source: backend.Source{Name: "MissingField"}, Basis: backend.FreshnessEventTime, Selector: missing},
		{RuleID: "aux", Source: backend.Source{Name: "AuxTable"}, Basis: backend.FreshnessEventTime, Selector: aux},
		{RuleID: "incomplete", Source: backend.Source{Name: "IncompleteSchema"}, Basis: backend.FreshnessEventTime, Selector: incomplete},
		{RuleID: "invalid", Source: backend.Source{Name: "ScheduledTable"}, Basis: backend.FreshnessEventTime, Selector: backend.PredicateFreshnessSelector{Source: "ScheduledTable", Expression: "DeviceVendor == OtherColumn", Fields: []string{"DeviceVendor"}}},
		{RuleID: "scheduled", BackendObjectID: "/rules/scheduled", Source: backend.Source{Name: "ScheduledTable"}, Basis: backend.FreshnessEventTime, Selector: scheduled},
	}
	evidence, err := client.RulePredicateFreshnessEvidenceFor(context.Background(), requests)
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence) != len(requests) {
		t.Fatalf("evidence count = %d, want %d: %+v", len(evidence), len(requests), evidence)
	}
	byRule := make(map[string]backend.RulePredicateFreshnessEvidence, len(evidence))
	for _, item := range evidence {
		byRule[item.RuleID] = item
	}
	for _, id := range []string{"scheduled", "nrt"} {
		item := byRule[id]
		if item.Freshness.Status != backend.EvidenceAssessed || item.Freshness.Window != 24*time.Hour || item.Freshness.LastEvent.IsZero() {
			t.Errorf("%s evidence = %+v", id, item)
		}
	}
	if byRule["scheduled"].Freshness.Method != "bounded-predicate-max-event-time" ||
		byRule["nrt"].Freshness.Method != "bounded-predicate-max-ingestion-time" {
		t.Fatalf("predicate methods = scheduled %q, nrt %q", byRule["scheduled"].Freshness.Method, byRule["nrt"].Freshness.Method)
	}
	for _, id := range []string{"missing", "aux", "incomplete"} {
		if byRule[id].Freshness.Status != backend.EvidenceUnavailable {
			t.Errorf("%s evidence = %+v, want unavailable", id, byRule[id])
		}
	}
	for _, id := range []string{"invalid", "z-mixed"} {
		if byRule[id].Freshness.Status != backend.EvidenceIncomplete {
			t.Errorf("%s evidence = %+v, want incomplete", id, byRule[id])
		}
	}
	if len(queries) != 2 {
		t.Fatalf("Logs queries = %v, want two", queries)
	}
	for _, query := range queries {
		if !strings.Contains(query, "ago(24h)") || !strings.Contains(query, " | where Device") || !strings.Contains(query, "<= now() + 300s") {
			t.Errorf("predicate freshness query is not bounded/canonical: %q", query)
		}
	}
	var scheduledQuery, nrtQuery string
	for _, query := range queries {
		if strings.HasPrefix(query, "ScheduledTable ") {
			scheduledQuery = query
		} else if strings.HasPrefix(query, "NRTTable ") {
			nrtQuery = query
		}
	}
	if !strings.Contains(scheduledQuery, "max(TimeGenerated)") || strings.Contains(scheduledQuery, "IngestionTime") ||
		!strings.Contains(nrtQuery, "ingestion_time()") || !strings.Contains(nrtQuery, "max(IngestionTime)") {
		t.Fatalf("clock-specific queries = %v", queries)
	}
}

func TestRulePredicateFreshnessEvidenceHasDeterministicTwentyQueryCap(t *testing.T) {
	var queryCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/tables"):
			fmt.Fprint(w, `{"value":[{"name":"SecurityEvent","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"standardColumns":[{"name":"TimeGenerated","type":"datetime"},{"name":"EventID","type":"long"}]}}}]}`)
		case strings.HasSuffix(r.URL.Path, "/query"):
			queryCalls.Add(1)
			writeAllowedLogsResult(w, "SecurityEvent", `[{"name":"PrimaryResult","columns":[{"name":"LastEvent","type":"datetime"}],"rows":[[null]]}]`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := fixtureClient(server.URL, &recordingCredential{})
	requests := make([]backend.RulePredicateFreshnessRequest, maxPredicateQueries+2)
	for i := range requests {
		requests[i] = backend.RulePredicateFreshnessRequest{
			RuleID: fmt.Sprintf("rule-%02d", len(requests)-1-i),
			Source: backend.Source{Name: "SecurityEvent"}, Basis: backend.FreshnessEventTime,
			Selector: mustPredicateSelector(t, fmt.Sprintf("SecurityEvent | where EventID == %d", 4624+i)),
		}
	}
	evidence, err := client.RulePredicateFreshnessEvidenceFor(context.Background(), requests)
	if err != nil {
		t.Fatal(err)
	}
	if queryCalls.Load() != maxPredicateQueries || len(evidence) != len(requests) {
		t.Fatalf("query/evidence counts = %d/%d, want %d/%d", queryCalls.Load(), len(evidence), maxPredicateQueries, len(requests))
	}
	for i, item := range evidence {
		wantID := fmt.Sprintf("rule-%02d", i)
		if item.RuleID != wantID {
			t.Fatalf("evidence[%d].RuleID = %q, want %q", i, item.RuleID, wantID)
		}
		if i < maxPredicateQueries && item.Freshness.Status != backend.EvidenceAssessed {
			t.Errorf("evidence[%d] = %+v, want assessed", i, item)
		}
		if i >= maxPredicateQueries && (item.Freshness.Status != backend.EvidenceIncomplete || !strings.Contains(item.Freshness.Detail, "limit of 20")) {
			t.Errorf("evidence[%d] = %+v, want capped incomplete", i, item)
		}
	}
}

func TestRulePredicateFreshnessEvidenceHonorsExistingLogsBudget(t *testing.T) {
	var queryCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/tables") {
			fmt.Fprint(w, `{"value":[{"name":"SecurityEvent","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"standardColumns":[{"name":"TimeGenerated","type":"datetime"},{"name":"EventID","type":"long"}]}}}]}`)
			return
		}
		queryCalls.Add(1)
		http.NotFound(w, r)
	}))
	defer server.Close()
	client := fixtureClient(server.URL, &recordingCredential{})
	client.logsQueryLimit = 1
	client.claimLogsQuery() // Simulate the ordinary evidence pass consuming it.
	selector := mustPredicateSelector(t, `SecurityEvent | where EventID == 4624`)
	evidence, err := client.RulePredicateFreshnessEvidenceFor(context.Background(), []backend.RulePredicateFreshnessRequest{{
		RuleID: "rule", Source: backend.Source{Name: "SecurityEvent"}, Basis: backend.FreshnessEventTime, Selector: selector,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if queryCalls.Load() != 0 || len(evidence) != 1 || evidence[0].Freshness.Status != backend.EvidenceIncomplete ||
		!strings.Contains(evidence[0].Freshness.Detail, "budget") {
		t.Fatalf("budgeted evidence/calls = %+v/%d", evidence, queryCalls.Load())
	}
}

func TestRulePredicateFreshnessEvidencePropagatesContextAfterLastQuery(t *testing.T) {
	tests := []struct {
		name    string
		context func() (context.Context, context.CancelFunc)
		want    error
	}{
		{
			name: "canceled",
			context: func() (context.Context, context.CancelFunc) {
				return context.WithCancel(context.Background())
			},
			want: context.Canceled,
		},
		{
			name: "deadline",
			context: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 50*time.Millisecond)
			},
			want: context.DeadlineExceeded,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			queryStarted := make(chan struct{})
			releaseQuery := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, "/tables"):
					fmt.Fprint(w, `{"value":[{"name":"SecurityEvent","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"standardColumns":[{"name":"TimeGenerated","type":"datetime"},{"name":"EventID","type":"long"}]}}}]}`)
				case strings.HasSuffix(r.URL.Path, "/query"):
					close(queryStarted)
					<-releaseQuery
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()

			ctx, cancel := tt.context()
			defer cancel()
			go func() {
				<-ctx.Done()
				close(releaseQuery)
			}()
			client := fixtureClient(server.URL, &recordingCredential{})
			selector := mustPredicateSelector(t, `SecurityEvent | filter EventID == 4624`)
			done := make(chan error, 1)
			go func() {
				_, err := client.RulePredicateFreshnessEvidenceFor(ctx, []backend.RulePredicateFreshnessRequest{{
					RuleID: "last-rule", Source: backend.Source{Name: "SecurityEvent"},
					Basis: backend.FreshnessEventTime, Selector: selector,
				}})
				done <- err
			}()
			select {
			case <-queryStarted:
			case <-ctx.Done():
				t.Fatalf("context ended before the Logs query started: %v", ctx.Err())
			}
			if tt.want == context.Canceled {
				cancel()
			}
			select {
			case err := <-done:
				if !errors.Is(err, tt.want) {
					t.Fatalf("RulePredicateFreshnessEvidenceFor() error = %v, want %v", err, tt.want)
				}
			case <-time.After(time.Second):
				t.Fatal("RulePredicateFreshnessEvidenceFor() did not return after context ended")
			}
		})
	}
}

func mustPredicateSelector(t *testing.T, query string) backend.PredicateFreshnessSelector {
	t.Helper()
	selector, ok := ExtractPredicateFreshness(query)
	if !ok {
		t.Fatalf("ExtractPredicateFreshness(%q) failed", query)
	}
	return selector
}
