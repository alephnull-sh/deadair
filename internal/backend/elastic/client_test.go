package elastic

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Big-Comfy/deadair/internal/backend"
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
			 "from":"now-90d","interval":"5m",
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
	// array form
	rules, err = ParseRuleFile([]byte(`[{"name":"A","index":["x-*"]},{"name":"B","index":["y-*"]}]`))
	if err != nil || len(rules) != 2 {
		t.Fatalf("array parse = %v, %v", rules, err)
	}
	if _, err := ParseRuleFile([]byte("  ")); err == nil {
		t.Fatal("empty file must error")
	}
}

func TestSourcesRetention(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/_data_stream/_stats", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"data_streams":[{"data_stream":"logs-dlm-default","store_size_bytes":10,"maximum_timestamp":1}]}`)
	})
	mux.HandleFunc("/_cat/indices", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `[
			{"index":".ds-logs-dlm-default-2026.07.01-000001","docs.count":"5","store.size":"10"},
			{"index":"plain-ilm","docs.count":"5","store.size":"10"}
		]`)
	})
	mux.HandleFunc("/_data_stream", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"data_streams":[{"name":"logs-dlm-default","lifecycle":{"data_retention":"30d"}}]}`)
	})
	mux.HandleFunc("/*/_ilm/explain", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"indices":{"plain-ilm":{"policy":"p45"}}}`)
	})
	mux.HandleFunc("/_ilm/policy/p45", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"p45":{"policy":{"phases":{"delete":{"min_age":"45d"}}}}}`)
	})
	mux.HandleFunc("/plain-ilm/_search", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"aggregations":{"latest":{"value":1}}}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := &Client{ESURL: srv.URL, KibanaURL: srv.URL}
	sources, err := c.Sources(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ret := map[string]time.Duration{}
	for _, s := range sources {
		ret[s.Name] = s.Retention
	}
	if ret["logs-dlm-default"] != 30*24*time.Hour {
		t.Errorf("DLM retention = %v, want 720h", ret["logs-dlm-default"])
	}
	if ret["plain-ilm"] != 45*24*time.Hour {
		t.Errorf("ILM retention = %v, want 1080h", ret["plain-ilm"])
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
		fmt.Fprintf(w, `{"aggregations":{"latest":{"value":%d},"ingested":{"value":%d}}}`,
			now.UnixMilli(), now.Add(30*time.Minute).UnixMilli())
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := &Client{ESURL: srv.URL, KibanaURL: srv.URL, MeasureLag: true}
	sources, err := c.Sources(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if sources[0].IngestLag == nil || *sources[0].IngestLag != 30*time.Minute {
		t.Fatalf("ingest lag = %v, want 30m", sources[0].IngestLag)
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
	if got := byID["b"].Patterns; len(got) != 0 {
		t.Errorf("missing data view must leave rule unmapped, got %v", got)
	}
	if got := byID["c"].Patterns; len(got) != 1 || got[0] != "logs-x-*" {
		t.Errorf("explicit index patterns must win over data view, got %v", got)
	}
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
		fmt.Fprintf(w, `{"aggregations":{"latest":{"value":%d}}}`, plainTS.UnixMilli())
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
