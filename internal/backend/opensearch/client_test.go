package opensearch

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Big-Comfy/deadair/internal/backend"
)

func TestRulesSearchDetectors(t *testing.T) {
	var gotAuth string
	mux := http.NewServeMux()
	mux.HandleFunc("/_plugins/_security_analytics/detectors/_search", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		gotAuth = r.Header.Get("Authorization")
		fmt.Fprint(w, `{"hits":{"total":{"value":3},"hits":[
			{"_id":"det-1","_source":{
				"name":"Windows detector",
				"enabled":true,
				"inputs":[{"detector_input":{"indices":["winlogbeat-*","winlogbeat-*","logs-windows-*"]}}],
				"triggers":[{"severity":"2"}]
			}},
			{"_id":"det-2","_source":{"detector":{
				"name":"Audit detector",
				"enabled":false,
				"inputs":[{"input":{"indices":["audit-*"]}}],
				"triggers":[{"sev_levels":[{"severity":"critical"}]}]
			}}},
			{"_id":"det-3","_source":{
				"name":"Unmapped detector"
			}}
		]}}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := &Client{URL: srv.URL, APIKey: "k"}
	rules, err := c.Rules(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth != "ApiKey k" {
		t.Errorf("Authorization = %q, want ApiKey k", gotAuth)
	}
	if len(rules) != 3 {
		t.Fatalf("got %d rules, want 3", len(rules))
	}
	byID := map[string]backend.Rule{}
	for _, r := range rules {
		byID[r.ID] = r
	}
	win := byID["det-1"]
	if !win.Enabled || win.Severity != "high" || win.RiskScore != 73 {
		t.Errorf("windows detector = %+v, want enabled high risk 73", win)
	}
	if got := win.Patterns; len(got) != 2 || got[0] != "winlogbeat-*" || got[1] != "logs-windows-*" {
		t.Errorf("patterns = %v, want de-duplicated detector indices", got)
	}
	audit := byID["det-2"]
	if audit.Enabled || audit.Severity != "critical" || audit.RiskScore != 99 {
		t.Errorf("audit detector = %+v, want disabled critical risk 99", audit)
	}
	if got := audit.Patterns; len(got) != 1 || got[0] != "audit-*" {
		t.Errorf("nested detector patterns = %v, want [audit-*]", got)
	}
	unmapped := byID["det-3"]
	if !unmapped.Enabled || unmapped.Severity != "medium" || len(unmapped.Patterns) != 0 {
		t.Errorf("unmapped detector = %+v, want enabled medium with no patterns", unmapped)
	}
}

func TestSources(t *testing.T) {
	now := time.Now().Truncate(time.Millisecond)
	streamTS := now.Add(-10 * time.Minute)
	plainTS := now.Add(-2 * time.Hour)

	mux := http.NewServeMux()
	mux.HandleFunc("/_data_stream/_stats", func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "admin" || pass != "secret" {
			t.Errorf("basic auth = %q/%q/%v, want admin/secret/true", user, pass, ok)
		}
		fmt.Fprintf(w, `{"data_streams":[
			{"data_stream":"logs-app-default","store_size_bytes":1234,"maximum_timestamp":%d},
			{"data_stream":"logs-dated-default","store_size_bytes":50,"maximum_timestamp":%d},
			{"data_stream":"logs-empty-default","total_store_size_bytes":0,"maximum_timestamp":0}
		]}`, streamTS.UnixMilli(), streamTS.UnixMilli())
	})
	mux.HandleFunc("/_cat/indices", func(w http.ResponseWriter, r *http.Request) {
		// OpenSearch names backing indices .ds-<stream>-<generation>; the
		// dated form appears only on Elasticsearch-lineage clusters. Both
		// must resolve to their stream.
		fmt.Fprint(w, `[
			{"index":".ds-logs-app-default-000001","docs.count":"30","store.size":"400"},
			{"index":".ds-logs-app-default-000002","docs.count":"10","store.size":"200"},
			{"index":".ds-logs-dated-default-2026.07.01-000001","docs.count":"5","store.size":"50"},
			{"index":".ds-logs-empty-default-000001","docs.count":"0","store.size":"0"},
			{"index":"plain-index","docs.count":"7","store.size":"99"},
			{"index":".opensearch-security","docs.count":"5","store.size":"1"}
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

	c := &Client{URL: srv.URL, Username: "admin", Password: "secret"}
	sources, err := c.Sources(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]backend.Source{}
	for _, s := range sources {
		byName[s.Name] = s
	}
	if len(sources) != 4 {
		t.Fatalf("got %d sources (%v), want 4", len(sources), byName)
	}
	app := byName["logs-app-default"]
	if app.Docs != 40 || app.SizeBytes != 1234 || !app.LastEvent.Equal(streamTS) {
		t.Errorf("data stream = %+v, want docs 40 (summed OpenSearch-style backing indices) size 1234 timestamp %v", app, streamTS)
	}
	dated := byName["logs-dated-default"]
	if dated.Docs != 5 {
		t.Errorf("dated-backing stream docs = %d, want 5", dated.Docs)
	}
	empty := byName["logs-empty-default"]
	if empty.Docs != 0 || !empty.LastEvent.IsZero() {
		t.Errorf("empty data stream = %+v, want 0 docs and zero LastEvent", empty)
	}
	plain := byName["plain-index"]
	if plain.Docs != 7 || plain.SizeBytes != 99 || !plain.LastEvent.Equal(plainTS) {
		t.Errorf("plain index = %+v, want docs 7 size 99 timestamp %v", plain, plainTS)
	}
}

func TestSourcesWithoutDataStreams(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/_data_stream/_stats", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	mux.HandleFunc("/_cat/indices", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `[{"index":"plain-index","docs.count":"0","store.size":"99"}]`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := &Client{URL: srv.URL}
	sources, err := c.Sources(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 1 || sources[0].Name != "plain-index" || sources[0].Docs != 0 {
		t.Fatalf("sources = %+v, want one zero-doc plain index", sources)
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

	c := &Client{URL: srv.URL}
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
