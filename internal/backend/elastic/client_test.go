package elastic

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alephnull-sh/deadair/internal/backend"
	"github.com/alephnull-sh/deadair/internal/health"
)

func TestRulesPagination(t *testing.T) {
	var gotAuth string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/detection_engine/rules/_find", func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		switch page := r.URL.Query().Get("page"); page {
		case "1":
			fmt.Fprint(w, `{"page":1,"perPage":1,"total":2,"data":[{"id":"a","name":"Rule A","enabled":true,"severity":"High","risk_score":73,"index":["logs-*"]}]}`)
		case "2":
			fmt.Fprint(w, `{"page":2,"perPage":1,"total":2,"data":[{"id":"b","name":"Rule B","enabled":false,"severity":"low"}]}`)
		default:
			t.Errorf("unexpected page %q", page)
			http.Error(w, "bad page", http.StatusBadRequest)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := &Client{ESURL: srv.URL, KibanaURL: srv.URL, APIKey: "k"}
	rules, err := c.Rules(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 {
		t.Fatalf("got %d rules, want 2 (pagination)", len(rules))
	}
	if rules[0].Severity != "high" {
		t.Errorf("severity not normalized: %q", rules[0].Severity)
	}
	if len(rules[1].Patterns) != 0 {
		t.Errorf("rule without index must have no patterns: %v", rules[1].Patterns)
	}
	if gotAuth != "ApiKey k" {
		t.Errorf("Authorization = %q, want ApiKey k", gotAuth)
	}
}

func TestRuleMetadataParsing(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/detection_engine/rules/_find", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"page":1,"perPage":100,"total":1,"data":[
			{"id":"a","name":"R","enabled":true,"severity":"low","index":["logs-*"],
			 "from":"now-90d","interval":"5m","timestamp_override":"event.ingested",
			 "required_fields":[{"name":"process.name","type":"keyword"},{"name":"user.id","type":"keyword"}]}
		]}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := &Client{ESURL: srv.URL, KibanaURL: srv.URL}
	rules, err := c.Rules(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	r := rules[0]
	if r.Lookback != 90*24*time.Hour || r.Interval != 5*time.Minute {
		t.Errorf("lookback/interval = %v/%v, want 2160h/5m", r.Lookback, r.Interval)
	}
	if len(r.RequiredFields) != 2 || r.RequiredFields[0] != "process.name" {
		t.Errorf("required fields = %v", r.RequiredFields)
	}
	if r.TimestampOverride != "event.ingested" {
		t.Errorf("timestamp override = %q, want event.ingested", r.TimestampOverride)
	}
}

func TestRulesParsesDirectESQLSources(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/detection_engine/rules/_find", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"page":1,"perPage":100,"total":1,"data":[{
			"id":"saved-esql","rule_id":"logical-esql","name":"ESQL rule","enabled":true,
			"type":"esql","query":"FROM logs-endpoint.events.*, archive:audit-* | WHERE true"
		}]}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	rules, err := (&Client{ESURL: srv.URL, KibanaURL: srv.URL}).Rules(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("rules = %+v, want one", rules)
	}
	rule := rules[0]
	if got := fmt.Sprint(rule.Patterns); got != "[logs-endpoint.events.* archive:audit-*]" {
		t.Fatalf("ES|QL patterns = %s", got)
	}
	if rule.InputStatus != "" || rule.ID != "logical-esql" || rule.BackendObjectID != "saved-esql" {
		t.Fatalf("ES|QL rule = %+v", rule)
	}
}

func TestParseRuleFile(t *testing.T) {
	// ndjson export with a metadata line, enabled:false forced to true
	rules, err := ParseRuleFile([]byte(`
{"rule_id":"cand-1","name":"Candidate","severity":"high","enabled":false,"index":["netflow-*"],"from":"now-6m","interval":"5m"}
{"exported_count":1}
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || !rules[0].Enabled || rules[0].ID != "cand-1" || rules[0].Lookback != 6*time.Minute {
		t.Fatalf("ndjson parse = %+v", rules)
	}
	// single pretty-printed JSON object
	rules, err = ParseRuleFile([]byte(`{
  "rule_id": "cand-2",
  "name": "Pretty candidate",
  "severity": "medium",
  "enabled": false,
  "index": ["cloudtrail-*"],
  "from": "now-10m",
  "interval": "5m"
}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].ID != "cand-2" || !rules[0].Enabled || rules[0].Lookback != 10*time.Minute {
		t.Fatalf("single object parse = %+v", rules)
	}
	// array form
	rules, err = ParseRuleFile([]byte(`[{"name":"A","index":["x-*"]},{"name":"B","index":["y-*"]}]`))
	if err != nil || len(rules) != 2 {
		t.Fatalf("array parse = %v, %v", rules, err)
	}
	if _, err := ParseRuleFile([]byte("  ")); err == nil {
		t.Fatal("empty file must error")
	}
	if _, err := ParseRuleFile([]byte(`[
		{"rule_id":"duplicate","name":"First","index":["logs-a-*"]},
		{"rule_id":"duplicate","name":"Second","index":["logs-b-*"]}
	]`)); err == nil || !strings.Contains(err.Error(), "duplicate rule ID") {
		t.Fatalf("duplicate candidate IDs error = %v", err)
	}
}

func TestParseRuleFileRejectsMalformedObjectsInMixedBatches(t *testing.T) {
	tests := []struct {
		name string
		data string
		want string
	}{
		{
			name: "array",
			data: `[
				{"rule_id":"valid","name":"Valid","index":["logs-*"]},
				{"severity":"high","index":["audit-*"]}
			]`,
			want: "array element 2",
		},
		{
			name: "ndjson after valid export details",
			data: `{"rule_id":"valid","name":"Valid","index":["logs-*"]}
{"exported_count":1,"exported_rules_count":1,"missing_rules":[],"missing_rules_count":0,"exported_exception_list_count":0,"exported_exception_list_item_count":0,"missing_exception_list_item_count":0,"missing_exception_list_items":[],"missing_exception_lists":[],"missing_exception_lists_count":0}
{"severity":"low","index":["audit-*"]}`,
			want: "line 3",
		},
		{
			name: "export-like object with unknown key",
			data: `{"rule_id":"valid","name":"Valid","index":["logs-*"]}
{"exported_count":1,"unexpected":true}`,
			want: "line 2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseRuleFile([]byte(tt.data))
			if err == nil || !strings.Contains(err.Error(), tt.want) ||
				!strings.Contains(err.Error(), "no name, rule_id, or id") {
				t.Fatalf("ParseRuleFile() error = %v, want malformed candidate at %s", err, tt.want)
			}
		})
	}
}

func TestParseRuleFileESQLSources(t *testing.T) {
	rules, err := ParseRuleFile([]byte(`{
		"rule_id":"candidate-esql",
		"name":"Candidate ES|QL",
		"type":"esql",
		"query":"FROM logs-*, auditbeat-*, archive:logs-* METADATA _id | LIMIT 10"
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || fmt.Sprint(rules[0].Patterns) != "[logs-* auditbeat-* archive:logs-*]" || rules[0].InputStatus != "" {
		t.Fatalf("candidate ES|QL rule = %+v", rules)
	}
}

func TestESQLUnsupportedSourceProvenance(t *testing.T) {
	tests := []struct {
		name  string
		query string
	}{
		{name: "row", query: "ROW value = 1"},
		{name: "subquery", query: "FROM (FROM logs-* | LIMIT 1) | LIMIT 10"},
		{name: "dynamic", query: "FROM ?source | LIMIT 10"},
		{name: "invalid", query: "FROM logs-*, | LIMIT 10"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := (ruleJSON{ID: tt.name, Type: "esql", Query: tt.query}).toRule()
			if len(rule.Patterns) != 0 || rule.InputStatus != backend.ResolutionUnsupported || !strings.Contains(rule.InputDetail, "ES|QL") {
				t.Fatalf("rule = %+v, want unsupported ES|QL provenance", rule)
			}
		})
	}
}

func TestIngestLagMeasurement(t *testing.T) {
	now := time.Now().Truncate(time.Millisecond)
	mux := http.NewServeMux()
	mux.HandleFunc("/_data_stream/_stats", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"data_streams":[{"data_stream":"logs-app-default","store_size_bytes":10,"maximum_timestamp":%d}]}`, now.UnixMilli())
	})
	mux.HandleFunc("/_cat/indices", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `[{"index":".ds-logs-app-default-2026.07.01-000001","docs.count":"5","store.size":"10"}]`)
	})
	mux.HandleFunc("/logs-app-default/_search", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), `"aggs"`) || !strings.Contains(string(body), `"size":500`) {
			t.Errorf("lag request must use paired hits, not independent aggregations: %s", body)
		}
		fmt.Fprintf(w, `{"hits":{"hits":[
			{"fields":{"@timestamp":[%d],"event.ingested":[%d]}},
			{"fields":{"@timestamp":[%d],"event.ingested":[%d]}}
		]}}`, now.UnixMilli(), now.Add(10*time.Minute).UnixMilli(),
			now.UnixMilli(), now.Add(30*time.Minute).UnixMilli())
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := &Client{ESURL: srv.URL, KibanaURL: srv.URL}
	sources, err := c.Sources(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	evidenceBySource, err := c.IngestLagEvidence(context.Background(), sources)
	if err != nil {
		t.Fatal(err)
	}
	evidence := evidenceBySource[sources[0].Name]
	if evidence.Status != backend.EvidenceAssessed || evidence.SampleCount != 2 ||
		evidence.P95 != 30*time.Minute || evidence.Max != 30*time.Minute ||
		evidence.Method != "paired-recent-events" {
		t.Fatalf("ingest lag = %+v, want assessed paired sample with p95/max 30m", evidence)
	}
}

func TestSourcesDoesNotSampleLagByDefault(t *testing.T) {
	now := time.Now().Truncate(time.Millisecond)
	var searches atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/_data_stream/_stats", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"data_streams":[{"data_stream":"logs-app-default","store_size_bytes":10,"maximum_timestamp":%d}]}`, now.UnixMilli())
	})
	mux.HandleFunc("/_cat/indices", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `[{"index":".ds-logs-app-default-2026.07.01-000001","docs.count":"5","store.size":"10"}]`)
	})
	mux.HandleFunc("/logs-app-default/_search", func(w http.ResponseWriter, r *http.Request) {
		searches.Add(1)
		fmt.Fprint(w, `{"hits":{"hits":[]}}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := &Client{ESURL: srv.URL, KibanaURL: srv.URL}
	if _, err := c.Sources(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := searches.Load(); got != 0 {
		t.Fatalf("Sources issued %d lag search(es); readiness inventory must stay cheap", got)
	}
}

func TestRulesDataViewResolution(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/detection_engine/rules/_find", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"page":1,"perPage":100,"total":3,"data":[
			{"id":"a","name":"DV rule","enabled":true,"severity":"high","data_view_id":"dv-1"},
			{"id":"b","name":"Gone DV rule","enabled":true,"severity":"low","data_view_id":"dv-gone"},
			{"id":"c","name":"Explicit index wins","enabled":true,"severity":"low","index":["logs-x-*"],"data_view_id":"dv-1"}
		]}`)
	})
	mux.HandleFunc("/api/data_views/data_view/dv-1", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"data_view":{"id":"dv-1","title":"logs-dv-*, metrics-dv-*"}}`)
	})
	// dv-gone: no handler → 404, rule must stay unmapped
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := &Client{ESURL: srv.URL, KibanaURL: srv.URL}
	rules, err := c.Rules(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]backend.Rule{}
	for _, r := range rules {
		byID[r.ID] = r
	}
	if got := byID["a"].Patterns; len(got) != 2 || got[0] != "logs-dv-*" || got[1] != "metrics-dv-*" {
		t.Errorf("data view patterns = %v, want [logs-dv-* metrics-dv-*]", got)
	}
	if byID["a"].DataViewID != "dv-1" {
		t.Errorf("data view ID = %q, want dv-1", byID["a"].DataViewID)
	}
	if got := byID["b"].Patterns; len(got) != 0 {
		t.Errorf("missing data view must leave rule unmapped, got %v", got)
	}
	if byID["b"].InputStatus != backend.ResolutionUnavailable || byID["b"].InputDetail == "" {
		t.Errorf("missing data view provenance = %q/%q, want unavailable with detail", byID["b"].InputStatus, byID["b"].InputDetail)
	}
	if got := byID["c"].Patterns; len(got) != 1 || got[0] != "logs-x-*" {
		t.Errorf("explicit index patterns must win over data view, got %v", got)
	}
	if byID["c"].InputStatus != backend.ResolutionAmbiguous {
		t.Errorf("explicit index plus data view status = %q, want ambiguous", byID["c"].InputStatus)
	}
}

func TestRuleInputProvenance(t *testing.T) {
	identity := (ruleJSON{ID: "saved-object-1", RuleID: "logical-rule-1", Name: "Identity"}).toRule()
	if identity.ID != "logical-rule-1" || identity.BackendObjectID != "saved-object-1" {
		t.Fatalf("rule identity = %q/%q, want logical-rule-1/saved-object-1", identity.ID, identity.BackendObjectID)
	}

	unsupported := (ruleJSON{ID: "esql", Type: "esql"}).toRule()
	if unsupported.RuleType != "esql" || unsupported.InputStatus != backend.ResolutionUnsupported || unsupported.InputDetail == "" {
		t.Fatalf("query-derived rule provenance = %+v", unsupported)
	}

	ambiguous := (ruleJSON{ID: "both", Type: "query", Index: []string{"logs-*"}, DataViewID: "dv"}).toRule()
	if ambiguous.InputStatus != backend.ResolutionAmbiguous || len(ambiguous.Patterns) != 1 {
		t.Fatalf("ambiguous rule provenance = %+v", ambiguous)
	}

	for _, rule := range []ruleJSON{
		{ID: "esql-index", Type: "esql", Query: "FROM audit-* | LIMIT 10", Index: []string{"logs-*"}},
		{ID: "esql-data-view", Type: "esql", Query: "FROM audit-* | LIMIT 10", DataViewID: "dv"},
	} {
		got := rule.toRule()
		if got.InputStatus != backend.ResolutionAmbiguous || got.InputDetail == "" {
			t.Fatalf("ES|QL dual source provenance = %+v, want ambiguous", got)
		}
	}
}

func TestResolveInputs(t *testing.T) {
	var pathMu sync.Mutex
	paths := make(map[string]int)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		pathMu.Lock()
		paths[r.URL.EscapedPath()]++
		pathMu.Unlock()
		if got := r.URL.Query().Get("ignore_unavailable"); got != "true" {
			t.Errorf("ignore_unavailable = %q, want true", got)
		}
		expression := r.URL.Path[len("/_resolve/index/"):]
		switch expression {
		case "logs-*,-logs-old-*":
			fmt.Fprint(w, `{
				"indices":[
					{"name":"logs-z","aliases":["alias-extra"]},
					{"name":".ds-logs-app-default-2026.07.01-000001","data_stream":"logs-app-default"}
				],
				"aliases":[{"name":"logs-current","indices":["logs-z","logs-a"]}],
				"data_streams":[{"name":"logs-app-default","backing_indices":[".ds-logs-app-default-2026.07.01-000001"]}]
			}`)
		case "missing-*", "missing-exact":
			fmt.Fprint(w, `{"indices":[],"aliases":[],"data_streams":[]}`)
		case "secured-*":
			http.Error(w, "forbidden", http.StatusForbidden)
		case "bad[":
			http.Error(w, "invalid index expression", http.StatusBadRequest)
		default:
			http.Error(w, "unexpected expression "+expression, http.StatusInternalServerError)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := &Client{ESURL: srv.URL, KibanaURL: srv.URL}
	got, err := c.ResolveInputs(context.Background(), []backend.Rule{
		{ID: "resolved", Patterns: []string{"logs-*", " remote:logs-* ", "-logs-old-*"}},
		{ID: "resolved-duplicate", Patterns: []string{"logs-*", "-logs-old-*"}},
		{ID: "empty", Patterns: []string{"missing-*"}},
		{ID: "empty-exact", Patterns: []string{"missing-exact"}},
		{ID: "unavailable", Patterns: []string{"secured-*"}},
		{ID: "unsupported", Patterns: []string{"bad["}},
		{ID: "metadata", InputStatus: backend.ResolutionUnsupported, InputDetail: "esql input"},
	})
	if err != nil {
		t.Fatal(err)
	}
	byRule := map[string][]backend.InputResolution{}
	for _, resolution := range got {
		byRule[resolution.RuleID] = append(byRule[resolution.RuleID], resolution)
		if resolution.ObservedAt.IsZero() {
			t.Errorf("resolution has zero observed_at: %+v", resolution)
		}
	}
	resolved := byRule["resolved"]
	if len(resolved) != 2 {
		t.Fatalf("resolved evidence = %+v, want local and remote records", resolved)
	}
	if resolved[0].Expression != "logs-*,-logs-old-*" || resolved[0].Status != backend.ResolutionResolved {
		t.Errorf("local resolution = %+v", resolved[0])
	}
	wantSources := []string{"logs-a", "logs-app-default", "logs-z"}
	if fmt.Sprint(resolved[0].ResolvedSources) != fmt.Sprint(wantSources) {
		t.Errorf("resolved sources = %v, want %v", resolved[0].ResolvedSources, wantSources)
	}
	if gotAliases := resolved[0].Aliases; fmt.Sprint(gotAliases) != fmt.Sprint([]string{"alias-extra", "logs-current"}) {
		t.Errorf("aliases = %v, want sorted unique alias evidence", gotAliases)
	}
	if duplicate := byRule["resolved-duplicate"]; len(duplicate) != 1 || fmt.Sprint(duplicate[0].ResolvedSources) != fmt.Sprint(wantSources) {
		t.Errorf("duplicate expression did not reuse equivalent evidence: %+v", duplicate)
	}
	if resolved[1].Selector != "remote:logs-*" || resolved[1].Status != backend.ResolutionRemote {
		t.Errorf("remote resolution = %+v", resolved[1])
	}
	if byRule["empty"][0].Status != backend.ResolutionEmpty {
		t.Errorf("empty status = %q", byRule["empty"][0].Status)
	}
	if byRule["empty-exact"][0].Status != backend.ResolutionEmpty {
		t.Errorf("exact missing status = %q", byRule["empty-exact"][0].Status)
	}
	if byRule["unavailable"][0].Status != backend.ResolutionUnavailable {
		t.Errorf("auth failure status = %q", byRule["unavailable"][0].Status)
	}
	if byRule["unsupported"][0].Status != backend.ResolutionUnsupported {
		t.Errorf("malformed expression status = %q", byRule["unsupported"][0].Status)
	}
	if metadata := byRule["metadata"][0]; metadata.Status != backend.ResolutionUnsupported || metadata.Detail != "esql input" {
		t.Errorf("preset metadata resolution = %+v", metadata)
	}
	pathMu.Lock()
	defer pathMu.Unlock()
	requestCount := 0
	for _, count := range paths {
		requestCount += count
	}
	if requestCount != 5 || paths["/_resolve/index/logs-%2A%2C-logs-old-%2A"] != 1 {
		t.Errorf("resolve paths = %v, want escaped ordered local expression and no metadata request", paths)
	}
}

func TestResolveInputsAddsPerSelectorDiagnosticsWithExclusions(t *testing.T) {
	var mu sync.Mutex
	requests := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expression := r.URL.Path[len("/_resolve/index/"):]
		mu.Lock()
		requests[expression]++
		mu.Unlock()
		switch expression {
		case "logs-legacy-*,logs-current-*,-logs-old-*":
			fmt.Fprint(w, `{"indices":[{"name":"logs-current-default"}]}`)
		case "logs-legacy-*,-logs-old-*":
			fmt.Fprint(w, `{}`)
		case "logs-current-*,-logs-old-*":
			fmt.Fprint(w, `{"indices":[{"name":"logs-current-default"}]}`)
		default:
			http.Error(w, "unexpected expression "+expression, http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	rules := []backend.Rule{
		{ID: "migration", Patterns: []string{"logs-legacy-*", "logs-current-*", "-logs-old-*"}},
		{ID: "duplicate", Patterns: []string{"logs-legacy-*", "logs-current-*", "-logs-old-*"}},
	}
	got, err := (&Client{ESURL: srv.URL, KibanaURL: srv.URL}).ResolveInputs(context.Background(), rules)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 6 {
		t.Fatalf("resolutions = %d, want authoritative plus two diagnostics per rule: %+v", len(got), got)
	}
	for offset := 0; offset < len(got); offset += 3 {
		if got[offset].Diagnostic || got[offset].Status != backend.ResolutionResolved {
			t.Errorf("authoritative resolution = %+v", got[offset])
		}
		if !got[offset+1].Diagnostic || got[offset+1].Selector != "logs-legacy-*" ||
			got[offset+1].Expression != "logs-legacy-*,-logs-old-*" || got[offset+1].Status != backend.ResolutionEmpty {
			t.Errorf("legacy diagnostic = %+v", got[offset+1])
		}
		if !got[offset+2].Diagnostic || got[offset+2].Selector != "logs-current-*" ||
			got[offset+2].Expression != "logs-current-*,-logs-old-*" || got[offset+2].Status != backend.ResolutionResolved {
			t.Errorf("current diagnostic = %+v", got[offset+2])
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(requests) != 3 {
		t.Fatalf("native expressions were not deduplicated: %v", requests)
	}
	for expression, count := range requests {
		if count != 1 {
			t.Errorf("expression %q requested %d times, want once", expression, count)
		}
	}
}

func TestResolveInputsUsesBoundedConcurrencyAndPreservesOrder(t *testing.T) {
	const (
		concurrency      = 4
		uniqueExpression = 256
	)

	started := make(chan struct{}, concurrency)
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()

	var requests atomic.Int32
	var inFlight atomic.Int32
	var maxInFlight atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		current := inFlight.Add(1)
		defer inFlight.Add(-1)
		for {
			maximum := maxInFlight.Load()
			if current <= maximum || maxInFlight.CompareAndSwap(maximum, current) {
				break
			}
		}
		select {
		case started <- struct{}{}:
		default:
		}
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		fmt.Fprint(w, `{"indices":[{"name":"logs-resolved"}]}`)
	}))
	defer srv.Close()

	rules := make([]backend.Rule, 0, uniqueExpression+1)
	for i := 0; i < uniqueExpression; i++ {
		patterns := []string{fmt.Sprintf("logs-%03d-*", i)}
		if i == 0 {
			patterns = append(patterns, "remote-a:logs-*")
		}
		rules = append(rules, backend.Rule{ID: fmt.Sprintf("rule-%03d", i), Patterns: patterns})
	}
	rules = append(rules, backend.Rule{ID: "duplicate", Patterns: []string{"logs-003-*"}})

	type resolveResult struct {
		resolutions []backend.InputResolution
		err         error
	}
	done := make(chan resolveResult, 1)
	go func() {
		got, err := (&Client{ESURL: srv.URL, KibanaURL: srv.URL, Concurrency: concurrency}).ResolveInputs(context.Background(), rules)
		done <- resolveResult{resolutions: got, err: err}
	}()

	for i := 0; i < concurrency; i++ {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			unblock()
			t.Fatalf("only %d native requests started; resolver appears serialized", i)
		}
	}
	unblock()

	var result resolveResult
	select {
	case result = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("concurrent native resolution did not complete")
	}
	if result.err != nil {
		t.Fatal(result.err)
	}
	if got := requests.Load(); got != uniqueExpression {
		t.Errorf("native requests = %d, want %d unique expressions", got, uniqueExpression)
	}
	if got := maxInFlight.Load(); got != concurrency {
		t.Errorf("maximum concurrent requests = %d, want bounded budget %d", got, concurrency)
	}
	if len(result.resolutions) != len(rules)+1 {
		t.Fatalf("resolutions = %d, want %d including remote evidence", len(result.resolutions), len(rules)+1)
	}
	position := 0
	for i := 0; i < uniqueExpression; i++ {
		wantRule := fmt.Sprintf("rule-%03d", i)
		if got := result.resolutions[position]; got.RuleID != wantRule || got.Status != backend.ResolutionResolved {
			t.Fatalf("resolution[%d] = %+v, want resolved evidence for %s", position, got, wantRule)
		}
		position++
		if i == 0 {
			if got := result.resolutions[position]; got.RuleID != wantRule || got.Status != backend.ResolutionRemote {
				t.Fatalf("resolution[%d] = %+v, want ordered remote evidence for %s", position, got, wantRule)
			}
			position++
		}
	}
	if got := result.resolutions[position]; got.RuleID != "duplicate" || got.Expression != "logs-003-*" || got.Status != backend.ResolutionResolved {
		t.Fatalf("duplicate resolution = %+v", got)
	}
}

func TestResolveCandidateDataView(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/data_views/data_view/dv-candidate", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"data_view":{"id":"dv-candidate","title":"logs-*,-logs-old-*"}}`)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/_resolve/index/logs-*,-logs-old-*" {
			t.Errorf("resolve path = %q", r.URL.Path)
		}
		if got := r.URL.Query().Get("ignore_unavailable"); got != "true" {
			t.Errorf("ignore_unavailable = %q, want true", got)
		}
		fmt.Fprint(w, `{"indices":[{"name":"logs-current"}],"aliases":[],"data_streams":[]}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	rules, err := ParseRuleFile([]byte(`{
		"rule_id":"candidate",
		"name":"Candidate data view rule",
		"type":"query",
		"data_view_id":"dv-candidate"
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].DataViewID != "dv-candidate" || rules[0].InputStatus != "" {
		t.Fatalf("parsed candidate = %+v", rules)
	}

	got, err := (&Client{ESURL: srv.URL, KibanaURL: srv.URL}).ResolveInputs(context.Background(), rules)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("resolutions = %+v, want one", got)
	}
	resolution := got[0]
	if resolution.Status != backend.ResolutionResolved ||
		resolution.Selector != "dv-candidate" ||
		resolution.Expression != "logs-*,-logs-old-*" ||
		resolution.SelectorKind != "data_view" ||
		resolution.ResolutionMethod != "data_view+resolve_index" ||
		fmt.Sprint(resolution.ResolvedSources) != "[logs-current]" {
		t.Fatalf("candidate data-view resolution = %+v", resolution)
	}
}

func TestResolveInputsReturnsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := (&Client{}).ResolveInputs(ctx, []backend.Rule{{ID: "r", Patterns: []string{"logs-*"}}})
	if !errors.Is(err, context.Canceled) || got != nil {
		t.Fatalf("ResolveInputs() = %v, %v; want nil, context.Canceled", got, err)
	}
}

func TestResolveInputsCancelsInflightRequests(t *testing.T) {
	started := make(chan struct{})
	var startedOnce sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startedOnce.Do(func() { close(started) })
		<-r.Context().Done()
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := (&Client{ESURL: srv.URL, KibanaURL: srv.URL, Concurrency: 2}).ResolveInputs(ctx, []backend.Rule{
			{ID: "a", Patterns: []string{"logs-a-*"}},
			{ID: "b", Patterns: []string{"logs-b-*"}},
		})
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("native request did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("ResolveInputs() error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ResolveInputs did not stop after cancellation")
	}
}

func TestVersion(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/" {
				t.Errorf("request = %s %s, want GET /", r.Method, r.URL.Path)
			}
			fmt.Fprint(w, `{"version":{"number":"9.1.2"}}`)
		}))
		defer srv.Close()
		got, err := (&Client{ESURL: srv.URL}).Version(context.Background())
		if err != nil || got != "9.1.2" {
			t.Fatalf("Version() = %q, %v", got, err)
		}
	})
	t.Run("error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "no access", http.StatusForbidden)
		}))
		defer srv.Close()
		if _, err := (&Client{ESURL: srv.URL}).Version(context.Background()); err == nil {
			t.Fatal("Version() error = nil, want root API failure")
		}
	})
}

func TestSources(t *testing.T) {
	now := time.Now().Truncate(time.Millisecond)
	appTS := now.Add(-5 * time.Minute)
	plainTS := now.Add(-time.Hour)

	mux := http.NewServeMux()
	mux.HandleFunc("/_data_stream/_stats", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"data_streams":[
			{"data_stream":"logs-app-default","store_size_bytes":1234,"maximum_timestamp":%d},
			{"data_stream":"logs-empty-default","store_size_bytes":0,"maximum_timestamp":0}
		]}`, appTS.UnixMilli())
	})
	mux.HandleFunc("/_cat/indices", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `[
			{"index":".ds-logs-app-default-2026.07.01-000001","docs.count":"40","store.size":"600"},
			{"index":".ds-logs-app-default-2026.07.02-000002","docs.count":"2","store.size":"634"},
			{"index":".ds-logs-empty-default-2026.07.01-000001","docs.count":"0","store.size":"0"},
			{"index":"plain-index","docs.count":"7","store.size":"99"},
			{"index":".kibana_1","docs.count":"5","store.size":"1"}
		]`)
	})
	mux.HandleFunc("/plain-index/_search", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("freshness fallback used %s, want POST", r.Method)
		}
		fmt.Fprintf(w, `{"aggregations":{"latest_acceptable":{"latest":{"value":%d}},"latest_observed":{"value":%d}}}`, plainTS.UnixMilli(), plainTS.UnixMilli())
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := &Client{ESURL: srv.URL, KibanaURL: srv.URL}
	sources, err := c.Sources(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]backend.Source{}
	for _, s := range sources {
		byName[s.Name] = s
	}
	if len(sources) != 3 {
		t.Fatalf("got %d sources (%v), want 3 — system indices must be excluded", len(sources), byName)
	}

	app := byName["logs-app-default"]
	if app.Docs != 42 {
		t.Errorf("data stream docs = %d, want 42 (summed backing indices)", app.Docs)
	}
	if !app.LastEvent.Equal(appTS) {
		t.Errorf("data stream LastEvent = %v, want %v", app.LastEvent, appTS)
	}
	if app.SizeBytes != 1234 {
		t.Errorf("data stream size = %d, want 1234", app.SizeBytes)
	}

	empty := byName["logs-empty-default"]
	if empty.Docs != 0 || !empty.LastEvent.IsZero() {
		t.Errorf("empty stream = %+v, want 0 docs and zero LastEvent", empty)
	}

	plain := byName["plain-index"]
	if plain.Docs != 7 || plain.SizeBytes != 99 {
		t.Errorf("plain index = %+v", plain)
	}
	if !plain.LastEvent.Equal(plainTS) {
		t.Errorf("plain index LastEvent = %v, want %v (freshness fallback)", plain.LastEvent, plainTS)
	}
}

func TestSourcesHandlesFutureTimestampEvidence(t *testing.T) {
	now := time.Now().Truncate(time.Millisecond)
	futureTS := now.Add(backend.FreshnessFutureSkew + time.Hour)
	usableTS := now.Add(-10 * time.Minute)
	var searches atomic.Int32

	mux := http.NewServeMux()
	mux.HandleFunc("/_data_stream/_stats", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"data_streams":[
			{"data_stream":"logs-future","store_size_bytes":10,"maximum_timestamp":%d},
			{"data_stream":"logs-only-future","store_size_bytes":10,"maximum_timestamp":%d},
			{"data_stream":"logs-future-error","store_size_bytes":10,"maximum_timestamp":%d},
			{"data_stream":"logs-future-unmapped","store_size_bytes":10,"maximum_timestamp":%d}
		]}`, futureTS.UnixMilli(), futureTS.UnixMilli(), futureTS.UnixMilli(), futureTS.UnixMilli())
	})
	mux.HandleFunc("/_cat/indices", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `[
			{"index":".ds-logs-future-2026.08.27-000001","docs.count":"2","store.size":"10"},
			{"index":".ds-logs-only-future-2026.08.27-000001","docs.count":"1","store.size":"10"},
			{"index":".ds-logs-future-error-2026.08.27-000001","docs.count":"1","store.size":"10"},
			{"index":".ds-logs-future-unmapped-2026.08.27-000001","docs.count":"1","store.size":"10"},
			{"index":"plain-only-future","docs.count":"1","store.size":"10"}
		]`)
	})
	mux.HandleFunc("/logs-future/_search", func(w http.ResponseWriter, r *http.Request) {
		searches.Add(1)
		var body struct {
			Aggregations struct {
				LatestAcceptable struct {
					Filter struct {
						Range map[string]struct {
							LTE string `json:"lte"`
						} `json:"range"`
					} `json:"filter"`
				} `json:"latest_acceptable"`
			} `json:"aggs"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if got := body.Aggregations.LatestAcceptable.Filter.Range["@timestamp"].LTE; got != "now+5m" {
			t.Errorf("freshness upper bound = %q, want now+5m", got)
		}
		fmt.Fprintf(w, `{"aggregations":{"latest_acceptable":{"latest":{"value":%d}},"latest_observed":{"value":%d}}}`, usableTS.UnixMilli(), futureTS.UnixMilli())
	})
	mux.HandleFunc("/logs-only-future/_search", func(w http.ResponseWriter, r *http.Request) {
		searches.Add(1)
		fmt.Fprintf(w, `{"aggregations":{"latest_acceptable":{"latest":{"value":null}},"latest_observed":{"value":%d}}}`, futureTS.UnixMilli())
	})
	mux.HandleFunc("/logs-future-error/_search", func(w http.ResponseWriter, r *http.Request) {
		searches.Add(1)
		http.Error(w, "forbidden", http.StatusForbidden)
	})
	mux.HandleFunc("/logs-future-unmapped/_search", func(w http.ResponseWriter, r *http.Request) {
		searches.Add(1)
		fmt.Fprint(w, `{"aggregations":{"latest_acceptable":{"latest":{"value":null}},"latest_observed":{"value":null}}}`)
	})
	mux.HandleFunc("/plain-only-future/_search", func(w http.ResponseWriter, r *http.Request) {
		searches.Add(1)
		fmt.Fprintf(w, `{"aggregations":{"latest_acceptable":{"latest":{"value":null}},"latest_observed":{"value":%d}}}`, futureTS.UnixMilli())
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	sources, err := (&Client{ESURL: srv.URL, KibanaURL: srv.URL}).Sources(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	byName := make(map[string]backend.Source, len(sources))
	for _, source := range sources {
		byName[source.Name] = source
	}
	if searches.Load() != 5 || len(sources) != 5 || !byName["logs-future"].LastEvent.Equal(usableTS) ||
		!byName["logs-only-future"].LastEvent.Equal(futureTS) || !byName["plain-only-future"].LastEvent.Equal(futureTS) ||
		!byName["logs-future-error"].LastEvent.IsZero() || !byName["logs-future-unmapped"].LastEvent.IsZero() {
		t.Fatalf("future timestamp evidence = searches %d, sources %+v; want bounded recovery %v, retained all-future value %v, and unknown on query failure", searches.Load(), sources, usableTS, futureTS)
	}
	check := health.Check{MaxStale: time.Hour, Now: func() time.Time { return now }}
	if got := check.Evaluate(byName["plain-only-future"]); got.Status != health.StatusStale {
		t.Fatalf("plain all-future health = %+v, want stale", got)
	}
	for _, name := range []string{"logs-future-error", "logs-future-unmapped"} {
		if got := check.Evaluate(byName[name]); got.Status != health.StatusUnknown {
			t.Fatalf("%s health = %+v, want unknown", name, got)
		}
	}
}

func TestSchemasToleratesPerSourceFailure(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/logs-good/_field_caps", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"fields":{"@timestamp":{"date":{}}}}`)
	})
	mux.HandleFunc("/logs-broken/_field_caps", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := &Client{ESURL: srv.URL, KibanaURL: srv.URL}
	schemas, err := c.Schemas(context.Background(), []backend.Source{{Name: "logs-good"}, {Name: "logs-broken"}})
	if err != nil {
		t.Fatalf("one broken source must not kill the scan: %v", err)
	}
	if _, ok := schemas["logs-good"]; !ok {
		t.Fatal("healthy source's schema was discarded")
	}
	if _, ok := schemas["logs-broken"]; ok {
		t.Fatal("broken source must be absent from the result (reports unknown)")
	}
}

func TestRequiredFieldEvidenceIsTargetedAndPerSource(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/logs-good/_field_caps", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if got := r.URL.Query().Get("fields"); got != "" {
			t.Errorf("URL fields = %q, want request body", got)
		}
		if got := r.URL.Query().Get("include_unmapped"); got != "true" {
			t.Errorf("include_unmapped = %q, want true", got)
		}
		var request struct {
			Fields []string `json:"fields"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decoding field_caps body: %v", err)
		}
		if got := strings.Join(request.Fields, ","); got != "host.name,process.name" {
			t.Errorf("body fields = %q, want only declared fields", got)
		}
		fmt.Fprint(w, `{"fields":{"process.name":{"keyword":{"searchable":true}}}}`)
	})
	mux.HandleFunc("/logs-broken/_field_caps", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := &Client{ESURL: srv.URL, KibanaURL: srv.URL}
	evidence, err := c.RequiredFieldEvidence(context.Background(), []backend.Source{{Name: "logs-good"}, {Name: "logs-broken"}}, []string{"process.name", "host.name"})
	if err != nil {
		t.Fatal(err)
	}
	if evidence["logs-good"].Status != backend.EvidenceAssessed || !evidence["logs-good"].Fields["process.name"] || evidence["logs-good"].Fields["host.name"] {
		t.Fatalf("good evidence = %+v", evidence["logs-good"])
	}
	if evidence["logs-broken"].Status != backend.EvidenceIncomplete {
		t.Fatalf("broken evidence = %+v, want incomplete", evidence["logs-broken"])
	}
}

func TestRequiredFieldEvidenceKeepsLargeFieldListOutOfURL(t *testing.T) {
	fields := make([]string, 600)
	for i := range fields {
		fields[i] = fmt.Sprintf("very.long.required.field.%04d", i)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/logs-large/_field_caps", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if got := r.URL.Query().Get("fields"); got != "" {
			t.Errorf("large field list leaked into URL: %d bytes", len(got))
		}
		if got := r.URL.Query().Get("include_unmapped"); got != "true" {
			t.Errorf("include_unmapped = %q, want true", got)
		}
		var request struct {
			Fields []string `json:"fields"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decoding field_caps body: %v", err)
		}
		if len(request.Fields) != len(fields) {
			t.Errorf("body field count = %d, want %d", len(request.Fields), len(fields))
		} else {
			for i := range fields {
				if request.Fields[i] != fields[i] {
					t.Errorf("body field %d = %q, want %q", i, request.Fields[i], fields[i])
					break
				}
			}
		}
		fmt.Fprint(w, `{"fields":{}}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := &Client{ESURL: srv.URL, KibanaURL: srv.URL}
	evidence, err := c.RequiredFieldEvidence(context.Background(), []backend.Source{{Name: "logs-large"}}, fields)
	if err != nil {
		t.Fatal(err)
	}
	if got := evidence["logs-large"].Status; got != backend.EvidenceAssessed {
		t.Fatalf("evidence status = %q, want assessed", got)
	}
}

func TestRequiredFieldEvidenceRejectsBackingIndexGaps(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/logs-mixed/_field_caps", func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("include_unmapped"); got != "true" {
			t.Errorf("include_unmapped = %q, want true", got)
		}
		fmt.Fprint(w, `{
			"fields": {
				"event.code": {"keyword": {"searchable": true}},
				"host.name": {"keyword": {
					"searchable": false,
					"non_searchable_indices": [".ds-logs-mixed-000002"]
				}},
				"process.name": {
					"keyword": {"searchable": true},
					"unmapped": {"searchable": false, "indices": [".ds-logs-mixed-000003"]}
				}
			}
		}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := &Client{ESURL: srv.URL, KibanaURL: srv.URL}
	evidence, err := c.RequiredFieldEvidence(context.Background(), []backend.Source{{Name: "logs-mixed"}}, []string{"process.name", "host.name", "event.code"})
	if err != nil {
		t.Fatal(err)
	}
	got := evidence["logs-mixed"]
	if got.Status != backend.EvidenceAssessed {
		t.Fatalf("evidence status = %q, want assessed", got.Status)
	}
	if !got.Fields["event.code"] {
		t.Fatalf("fully searchable field was marked unavailable: %+v", got.Fields)
	}
	if got.Fields["host.name"] {
		t.Fatalf("non-searchable backing index was hidden: %+v", got.Fields)
	}
	if got.Fields["process.name"] {
		t.Fatalf("unmapped backing index was hidden: %+v", got.Fields)
	}
}

func TestSchemas(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/logs-app/_field_caps", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("fields") != "*" {
			t.Errorf("fields = %q, want *", r.URL.Query().Get("fields"))
		}
		fmt.Fprint(w, `{"fields":{
			"message":{"text":{}},
			"@timestamp":{"date":{}},
			"event.code":{"keyword":{},"long":{}}
		}}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := &Client{ESURL: srv.URL, KibanaURL: srv.URL}
	schemas, err := c.Schemas(context.Background(), []backend.Source{{Name: "logs-app"}})
	if err != nil {
		t.Fatal(err)
	}
	fields := schemas["logs-app"].Fields
	if len(fields) != 3 {
		t.Fatalf("fields = %+v, want 3", fields)
	}
	if fields[0].Name != "@timestamp" || fields[0].Types[0] != "date" {
		t.Fatalf("fields not sorted/parsed: %+v", fields)
	}
	if fields[1].Name != "event.code" || len(fields[1].Types) != 2 || fields[1].Types[0] != "keyword" || fields[1].Types[1] != "long" {
		t.Fatalf("multi-type field = %+v", fields[1])
	}
}
