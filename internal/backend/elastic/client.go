// Package elastic implements the read-only backend for Elastic Security.
// It talks to two APIs: Kibana (detection rule inventory via the Detections
// API) and Elasticsearch (source stats). Every call is a read: GETs against
// stats/cat endpoints and size-0 max-timestamp aggregations. Cheap stats APIs
// are preferred over ad-hoc aggregations so a scan never becomes load on the
// monitored cluster.
package elastic

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Big-Comfy/deadair/internal/backend"
)

const defaultConcurrency = 4

// Client is a read-only client for one Elastic Security deployment.
type Client struct {
	ESURL     string
	KibanaURL string
	APIKey    string // optional; unauthenticated dev clusters are allowed
	HTTP      *http.Client
	// Concurrency bounds the parallel freshness-fallback searches so a scan
	// stays SIEM-safe by default.
	Concurrency int
	// Space scopes Kibana API calls to a non-default Kibana space; rules
	// living outside the configured space are otherwise invisible.
	Space string
	// MeasureLag adds one size-0 aggregation per non-empty source to measure
	// ingest lag (event.ingested vs @timestamp). Off by default; the CLI
	// enables it with --state-file.
	MeasureLag bool
}

func (c *Client) Name() string { return "elastic" }

// kibanaPath prefixes Kibana API paths with the space route when a
// non-default space is configured.
func (c *Client) kibanaPath(p string) string {
	if c.Space != "" && c.Space != "default" {
		return "/s/" + url.PathEscape(c.Space) + p
	}
	return p
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 60 * time.Second}
}

func (c *Client) concurrency() int {
	if c.Concurrency > 0 {
		return c.Concurrency
	}
	return defaultConcurrency
}

func (c *Client) do(ctx context.Context, method, base, path string, body io.Reader, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(base, "/")+path, body)
	if err != nil {
		return err
	}
	if c.APIKey != "" {
		req.Header.Set("Authorization", "ApiKey "+c.APIKey)
	}
	req.Header.Set("kbn-xsrf", "deadair")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(msg)))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

type findResponse struct {
	Page    int        `json:"page"`
	PerPage int        `json:"perPage"`
	Total   int        `json:"total"`
	Data    []ruleJSON `json:"data"`
}

// ruleJSON is the wire shape shared by the Detections API and exported rule
// files (which makes it the parser for `scan --rule` candidates too).
type ruleJSON struct {
	ID             string   `json:"id"`
	RuleID         string   `json:"rule_id"`
	Name           string   `json:"name"`
	Enabled        bool     `json:"enabled"`
	Severity       string   `json:"severity"`
	RiskScore      int      `json:"risk_score"`
	Index          []string `json:"index"`
	DataViewID     string   `json:"data_view_id"`
	From           string   `json:"from"`
	Interval       string   `json:"interval"`
	RequiredFields []struct {
		Name string `json:"name"`
	} `json:"required_fields"`
}

func (d ruleJSON) toRule() backend.Rule {
	r := backend.Rule{
		ID:        d.ID,
		Name:      d.Name,
		Enabled:   d.Enabled,
		Severity:  strings.ToLower(d.Severity),
		RiskScore: d.RiskScore,
		Patterns:  d.Index,
		Lookback:  backend.ParseLookback(d.From),
		Interval:  backend.ParseInterval(d.Interval),
	}
	if r.ID == "" {
		r.ID = d.RuleID
	}
	for _, f := range d.RequiredFields {
		if f.Name != "" {
			r.RequiredFields = append(r.RequiredFields, f.Name)
		}
	}
	return r
}

// ParseRuleFile parses candidate rules for `scan --rule`: a single rule JSON
// object, a JSON array, or ndjson export lines. Candidates are evaluated as
// enabled regardless of the enabled flag in the file.
func ParseRuleFile(data []byte) ([]backend.Rule, error) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, fmt.Errorf("rule file is empty")
	}
	var raw []ruleJSON
	if strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal([]byte(trimmed), &raw); err != nil {
			return nil, fmt.Errorf("parsing rule array: %w", err)
		}
	} else {
		parsedSingle := false
		if strings.HasPrefix(trimmed, "{") {
			var d ruleJSON
			if err := json.Unmarshal([]byte(trimmed), &d); err == nil {
				raw = append(raw, d)
				parsedSingle = true
			}
		}
		if !parsedSingle {
			for i, line := range strings.Split(trimmed, "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				var d ruleJSON
				if err := json.Unmarshal([]byte(line), &d); err != nil {
					return nil, fmt.Errorf("parsing rule (line %d): %w", i+1, err)
				}
				raw = append(raw, d)
			}
		}
	}
	var rules []backend.Rule
	for _, d := range raw {
		if d.Name == "" && d.RuleID == "" && d.ID == "" {
			continue // export metadata lines
		}
		r := d.toRule()
		r.Enabled = true
		if r.ID == "" {
			r.ID = r.Name
		}
		rules = append(rules, r)
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("no rules found in file")
	}
	return rules, nil
}

// Rules inventories all detection rules via the Kibana Detections API.
// Rules backed by a data view instead of index patterns are resolved through
// the Data Views API; a missing or unreadable data view leaves the rule
// unmapped (visible in the report) rather than failing the scan.
func (c *Client) Rules(ctx context.Context) ([]backend.Rule, error) {
	var rules []backend.Rule
	dvPending := map[string][]int{} // data view ID -> indices into rules
	for page := 1; ; page++ {
		var fr findResponse
		path := c.kibanaPath(fmt.Sprintf("/api/detection_engine/rules/_find?page=%d&per_page=100", page))
		if err := c.do(ctx, http.MethodGet, c.KibanaURL, path, nil, &fr); err != nil {
			return nil, fmt.Errorf("listing detection rules: %w", err)
		}
		for _, d := range fr.Data {
			rules = append(rules, d.toRule())
			if len(d.Index) == 0 && d.DataViewID != "" {
				dvPending[d.DataViewID] = append(dvPending[d.DataViewID], len(rules)-1)
			}
		}
		if len(fr.Data) == 0 || fr.PerPage == 0 || page*fr.PerPage >= fr.Total {
			break
		}
	}
	for dvID, idxs := range dvPending {
		patterns, err := c.dataViewPatterns(ctx, dvID)
		if err != nil || len(patterns) == 0 {
			continue
		}
		for _, i := range idxs {
			rules[i].Patterns = patterns
		}
	}
	return rules, nil
}

// dataViewPatterns resolves a Kibana data view to its index patterns (the
// data view title is a comma-separated pattern list).
func (c *Client) dataViewPatterns(ctx context.Context, id string) ([]string, error) {
	var out struct {
		DataView struct {
			Title string `json:"title"`
		} `json:"data_view"`
	}
	path := c.kibanaPath("/api/data_views/data_view/" + url.PathEscape(id))
	if err := c.do(ctx, http.MethodGet, c.KibanaURL, path, nil, &out); err != nil {
		return nil, err
	}
	var patterns []string
	for _, p := range strings.Split(out.DataView.Title, ",") {
		if p = strings.TrimSpace(p); p != "" {
			patterns = append(patterns, p)
		}
	}
	return patterns, nil
}

type dsStatsResponse struct {
	DataStreams []struct {
		Name             string `json:"data_stream"`
		StoreSizeBytes   int64  `json:"store_size_bytes"`
		MaximumTimestamp int64  `json:"maximum_timestamp"` // epoch millis
	} `json:"data_streams"`
}

type catIndex struct {
	Index     string `json:"index"`
	DocsCount string `json:"docs.count"`
	StoreSize string `json:"store.size"`
}

// backingRe extracts the data-stream name from a backing index:
// .ds-<stream>-<yyyy.MM.dd>-<generation>
var backingRe = regexp.MustCompile(`^\.ds-(.+)-\d{4}\.\d{2}\.\d{2}-\d+$`)

// Sources inventories data streams and plain indices with their health stats.
// Data-stream freshness comes free from _data_stream/_stats; plain indices
// fall back to a bounded-concurrency size-0 max(@timestamp) aggregation.
func (c *Client) Sources(ctx context.Context) ([]backend.Source, error) {
	var ds dsStatsResponse
	if err := c.do(ctx, http.MethodGet, c.ESURL, "/_data_stream/_stats", nil, &ds); err != nil {
		return nil, fmt.Errorf("data stream stats: %w", err)
	}
	var cats []catIndex
	if err := c.do(ctx, http.MethodGet, c.ESURL, "/_cat/indices?format=json&h=index,docs.count,store.size&bytes=b", nil, &cats); err != nil {
		return nil, fmt.Errorf("listing indices: %w", err)
	}

	// Doc counts per data stream, summed from backing indices.
	streamDocs := make(map[string]int64)
	var sources []backend.Source
	for _, ci := range cats {
		if m := backingRe.FindStringSubmatch(ci.Index); m != nil {
			if n, err := strconv.ParseInt(ci.DocsCount, 10, 64); err == nil {
				streamDocs[m[1]] += n
			}
			continue
		}
		if strings.HasPrefix(ci.Index, ".") {
			continue // system indices are not telemetry sources
		}
		s := backend.Source{Name: ci.Index, Docs: -1}
		if n, err := strconv.ParseInt(ci.DocsCount, 10, 64); err == nil {
			s.Docs = n
		}
		if n, err := strconv.ParseInt(ci.StoreSize, 10, 64); err == nil {
			s.SizeBytes = n
		}
		sources = append(sources, s)
	}
	for _, d := range ds.DataStreams {
		s := backend.Source{Name: d.Name, SizeBytes: d.StoreSizeBytes, Docs: -1}
		if n, ok := streamDocs[d.Name]; ok {
			s.Docs = n
		}
		if d.MaximumTimestamp > 0 {
			s.LastEvent = time.UnixMilli(d.MaximumTimestamp)
		}
		sources = append(sources, s)
	}

	c.fillFreshness(ctx, sources)
	if c.MeasureLag {
		c.fillIngestLag(ctx, sources)
	}
	return sources, nil
}

// fillIngestLag measures max(event.ingested) - max(@timestamp) per non-empty
// source, bounded concurrency. Sources without event.ingested stay nil and
// are skipped by lag checks.
func (c *Client) fillIngestLag(ctx context.Context, sources []backend.Source) {
	sem := make(chan struct{}, c.concurrency())
	var wg sync.WaitGroup
	for i := range sources {
		if sources[i].Docs == 0 {
			continue
		}
		wg.Add(1)
		go func(s *backend.Source) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			body := strings.NewReader(`{"size":0,"track_total_hits":false,"aggs":{"latest":{"max":{"field":"@timestamp"}},"ingested":{"max":{"field":"event.ingested"}}}}`)
			var out struct {
				Aggregations struct {
					Latest struct {
						Value *float64 `json:"value"`
					} `json:"latest"`
					Ingested struct {
						Value *float64 `json:"value"`
					} `json:"ingested"`
				} `json:"aggregations"`
			}
			path := "/" + url.PathEscape(s.Name) + "/_search"
			if err := c.do(ctx, http.MethodPost, c.ESURL, path, body, &out); err != nil {
				return
			}
			if out.Aggregations.Latest.Value == nil || out.Aggregations.Ingested.Value == nil {
				return
			}
			lag := time.Duration(*out.Aggregations.Ingested.Value-*out.Aggregations.Latest.Value) * time.Millisecond
			if lag < 0 {
				lag = 0
			}
			s.IngestLag = &lag
		}(&sources[i])
	}
	wg.Wait()
}

// fillFreshness resolves LastEvent for sources that lack it, with bounded
// concurrency. Failures are tolerated: a source we cannot date reports as
// status "unknown" rather than failing the scan.
func (c *Client) fillFreshness(ctx context.Context, sources []backend.Source) {
	sem := make(chan struct{}, c.concurrency())
	var wg sync.WaitGroup
	for i := range sources {
		if !sources[i].LastEvent.IsZero() || sources[i].Docs == 0 {
			continue
		}
		wg.Add(1)
		go func(s *backend.Source) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if ts, err := c.maxTimestamp(ctx, s.Name); err == nil {
				s.LastEvent = ts
			}
		}(&sources[i])
	}
	wg.Wait()
}

func (c *Client) maxTimestamp(ctx context.Context, index string) (time.Time, error) {
	body := strings.NewReader(`{"size":0,"track_total_hits":false,"aggs":{"latest":{"max":{"field":"@timestamp"}}}}`)
	var out struct {
		Aggregations struct {
			Latest struct {
				Value *float64 `json:"value"`
			} `json:"latest"`
		} `json:"aggregations"`
	}
	path := "/" + url.PathEscape(index) + "/_search"
	if err := c.do(ctx, http.MethodPost, c.ESURL, path, body, &out); err != nil {
		return time.Time{}, err
	}
	if out.Aggregations.Latest.Value == nil {
		return time.Time{}, nil
	}
	return time.UnixMilli(int64(*out.Aggregations.Latest.Value)), nil
}

type fieldCapsResponse struct {
	Fields map[string]map[string]json.RawMessage `json:"fields"`
}

// Schemas inventories field capabilities for the already-selected sources.
// It is opt-in at the CLI because it is one cheap metadata read per source.
func (c *Client) Schemas(ctx context.Context, sources []backend.Source) (map[string]backend.Schema, error) {
	out := make(map[string]backend.Schema, len(sources))
	sem := make(chan struct{}, c.concurrency())
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, src := range sources {
		src := src
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			schema, err := c.schema(ctx, src.Name)
			if err != nil {
				// Tolerated: a broken source must not kill the report; it
				// reports schema "unknown" this scan and its stored snapshot
				// stays untouched.
				return
			}
			mu.Lock()
			out[src.Name] = schema
			mu.Unlock()
		}()
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) schema(ctx context.Context, source string) (backend.Schema, error) {
	var fc fieldCapsResponse
	path := "/" + url.PathEscape(source) + "/_field_caps?fields=*"
	if err := c.do(ctx, http.MethodGet, c.ESURL, path, nil, &fc); err != nil {
		return backend.Schema{}, fmt.Errorf("field caps for %s: %w", source, err)
	}
	return schemaFromFieldCaps(source, fc), nil
}

func schemaFromFieldCaps(source string, fc fieldCapsResponse) backend.Schema {
	schema := backend.Schema{Source: source, Fields: make([]backend.Field, 0, len(fc.Fields))}
	for name, byType := range fc.Fields {
		types := make([]string, 0, len(byType))
		for typ := range byType {
			types = append(types, typ)
		}
		sort.Strings(types)
		schema.Fields = append(schema.Fields, backend.Field{Name: name, Types: types})
	}
	sort.Slice(schema.Fields, func(i, j int) bool { return schema.Fields[i].Name < schema.Fields[j].Name })
	return schema
}
