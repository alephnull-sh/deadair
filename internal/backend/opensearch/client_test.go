package opensearch

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
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
	if unmapped.InputStatus != backend.ResolutionUnsupported || unmapped.InputDetail == "" {
		t.Errorf("unmapped detector provenance = %q/%q, want unsupported with detail", unmapped.InputStatus, unmapped.InputDetail)
	}
}

func TestResolveInputs(t *testing.T) {
	var pathMu sync.Mutex
	paths := make(map[string]int)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		pathMu.Lock()
		paths[r.URL.EscapedPath()]++
		pathMu.Unlock()
		if got := r.URL.Query().Get("ignore_unavailable"); got != "true" {
			t.Errorf("ignore_unavailable = %q, want true", got)
		}
		expression := r.URL.Path[len("/_resolve/index/"):]
		switch expression {
		case "audit-*,logs-app-*":
			fmt.Fprint(w, `{
				"indices":[{"name":"audit-2026","aliases":["audit-live"]}],
				"aliases":[{"name":"audit-all","indices":["audit-2025","audit-2026"]}],
				"data_streams":[{"name":"logs-app-default","backing_indices":[".ds-logs-app-default-000001"]}]
			}`)
		case "none-*", "none-exact":
			fmt.Fprint(w, `{}`)
		case "denied-*":
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		case "bad[":
			http.Error(w, "bad selector", http.StatusBadRequest)
		default:
			http.Error(w, "unexpected expression "+expression, http.StatusInternalServerError)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := &Client{URL: srv.URL}
	got, err := c.ResolveInputs(context.Background(), []backend.Rule{
		{ID: "resolved", Patterns: []string{"audit-*", "cluster-b:audit-*", "logs-app-*"}},
		{ID: "resolved-duplicate", Patterns: []string{"audit-*", "logs-app-*"}},
		{ID: "empty", Patterns: []string{"none-*"}},
		{ID: "empty-exact", Patterns: []string{"none-exact"}},
		{ID: "denied", Patterns: []string{"denied-*"}},
		{ID: "bad", Patterns: []string{"bad["}},
		{ID: "preset", InputStatus: backend.ResolutionUnavailable, InputDetail: "input lookup failed"},
	})
	if err != nil {
		t.Fatal(err)
	}
	byRule := map[string][]backend.InputResolution{}
	for _, resolution := range got {
		byRule[resolution.RuleID] = append(byRule[resolution.RuleID], resolution)
	}
	resolved := byRule["resolved"]
	if len(resolved) != 2 || resolved[0].Expression != "audit-*,logs-app-*" || resolved[0].Status != backend.ResolutionResolved {
		t.Fatalf("resolved evidence = %+v", resolved)
	}
	wantSources := []string{"audit-2025", "audit-2026", "logs-app-default"}
	if fmt.Sprint(resolved[0].ResolvedSources) != fmt.Sprint(wantSources) {
		t.Errorf("resolved sources = %v, want %v", resolved[0].ResolvedSources, wantSources)
	}
	if fmt.Sprint(resolved[0].Aliases) != fmt.Sprint([]string{"audit-all", "audit-live"}) {
		t.Errorf("aliases = %v", resolved[0].Aliases)
	}
	if duplicate := byRule["resolved-duplicate"]; len(duplicate) != 1 || fmt.Sprint(duplicate[0].ResolvedSources) != fmt.Sprint(wantSources) {
		t.Errorf("duplicate expression did not reuse equivalent evidence: %+v", duplicate)
	}
	if resolved[1].Status != backend.ResolutionRemote || resolved[1].Selector != "cluster-b:audit-*" {
		t.Errorf("remote evidence = %+v", resolved[1])
	}
	if byRule["empty"][0].Status != backend.ResolutionEmpty {
		t.Errorf("positive empty status = %q", byRule["empty"][0].Status)
	}
	if byRule["empty-exact"][0].Status != backend.ResolutionEmpty {
		t.Errorf("exact missing status = %q", byRule["empty-exact"][0].Status)
	}
	if byRule["denied"][0].Status != backend.ResolutionUnavailable {
		t.Errorf("auth failure status = %q", byRule["denied"][0].Status)
	}
	if byRule["bad"][0].Status != backend.ResolutionUnsupported {
		t.Errorf("bad selector status = %q", byRule["bad"][0].Status)
	}
	if preset := byRule["preset"][0]; preset.Status != backend.ResolutionUnavailable || preset.Detail != "input lookup failed" {
		t.Errorf("preset evidence = %+v", preset)
	}
	pathMu.Lock()
	defer pathMu.Unlock()
	requestCount := 0
	for _, count := range paths {
		requestCount += count
	}
	if requestCount != 5 || paths["/_resolve/index/audit-%2A%2Clogs-app-%2A"] != 1 {
		t.Errorf("resolve paths = %v, want escaped ordered local expression", paths)
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
		got, err := (&Client{URL: srv.URL, Concurrency: concurrency}).ResolveInputs(context.Background(), rules)
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
		_, err := (&Client{URL: srv.URL, Concurrency: 2}).ResolveInputs(ctx, []backend.Rule{
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
			fmt.Fprint(w, `{"version":{"number":"3.2.0"}}`)
		}))
		defer srv.Close()
		got, err := (&Client{URL: srv.URL}).Version(context.Background())
		if err != nil || got != "3.2.0" {
			t.Fatalf("Version() = %q, %v", got, err)
		}
	})
	t.Run("error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		}))
		defer srv.Close()
		if _, err := (&Client{URL: srv.URL}).Version(context.Background()); err == nil {
			t.Fatal("Version() error = nil, want root API failure")
		}
	})
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
