package sentinel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/alephnull-sh/deadair/internal/backend"
)

func TestPredicateFreshnessSharesOnlyIdenticalObservations(t *testing.T) {
	for _, denied := range []bool{false, true} {
		t.Run(fmt.Sprintf("denied=%t", denied), func(t *testing.T) {
			queries := make(map[string]int)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, "/tables"):
					fmt.Fprint(w, `{"value":[{"name":"CommonSecurityLog","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"standardColumns":[{"name":"TimeGenerated","type":"datetime"},{"name":"DeviceName","type":"string"}]}}}]}`)
				case strings.HasSuffix(r.URL.Path, "/query"):
					var request logsQueryRequest
					if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
						t.Error(err)
						return
					}
					queries[request.Query]++
					if denied {
						http.Error(w, `{"error":{"code":"InsufficientAccessError"}}`, http.StatusForbidden)
						return
					}
					writeAllowedLogsResult(w, "CommonSecurityLog", `[{"name":"PrimaryResult","columns":[{"name":"LastEvent","type":"datetime"}],"rows":[[null]]}]`)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			client := fixtureClient(server.URL, &recordingCredential{})
			selector := mustPredicateSelector(t, `CommonSecurityLog | where DeviceName == "fw-london-01"`)
			requests := make([]backend.RulePredicateFreshnessRequest, maxPredicateQueries+2)
			for i := range requests {
				requests[i] = backend.RulePredicateFreshnessRequest{
					RuleID: fmt.Sprintf("rule-%02d", i), BackendObjectID: fmt.Sprintf("/rules/%d", i),
					Source: backend.Source{Name: "CommonSecurityLog"}, Basis: backend.FreshnessEventTime,
					Selector: selector, Window: time.Duration(i+1) * time.Minute,
				}
			}
			// Another clock and another filter must not reuse the first observation.
			nrt := requests[0]
			nrt.RuleID = "rule-nrt"
			nrt.Basis = backend.FreshnessIngestionTime
			other := requests[0]
			other.RuleID = "rule-other"
			other.Selector = mustPredicateSelector(t, `CommonSecurityLog | where DeviceName == "fw-manchester-01"`)
			requests = append(requests, nrt, other)
			for pass := 1; pass <= 2; pass++ {
				evidence, err := client.RulePredicateFreshnessEvidenceFor(context.Background(), requests)
				if err != nil || len(evidence) != len(requests) {
					t.Fatalf("evidence = %+v, error = %v", evidence, err)
				}
				if len(queries) != 3 {
					t.Fatalf("distinct queries = %d; want three", len(queries))
				}
				for query, count := range queries {
					if count != pass {
						t.Errorf("query %q ran %d times after %d passes", query, count, pass)
					}
				}
				for i, item := range evidence {
					if item.RuleID != requests[i].RuleID || item.BackendObjectID != requests[i].BackendObjectID {
						t.Errorf("rule identity changed: %+v", item)
					}
					want := backend.EvidenceAssessed
					if denied {
						want = backend.EvidenceUnavailable
					}
					if item.Freshness.Status != want {
						t.Errorf("freshness = %+v; want %s", item.Freshness, want)
					}
					if i < maxPredicateQueries+2 && !reflect.DeepEqual(item.Freshness, evidence[0].Freshness) {
						t.Errorf("identical query produced a different observation: %+v", item)
					}
				}
			}
		})
	}
}
