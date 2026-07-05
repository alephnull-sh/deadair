// Package opensearch implements the read-only backend for OpenSearch Security
// Analytics. It inventories detectors through the Security Analytics API and
// log sources through OpenSearch stats APIs. All calls are reads.
package opensearch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

// Client is a read-only client for one OpenSearch deployment.
type Client struct {
	URL      string
	Username string
	Password string
	APIKey   string // optional; unauthenticated dev clusters are allowed
	HTTP     *http.Client
	// Concurrency bounds the parallel freshness-fallback searches so a scan
	// stays SIEM-safe by default.
	Concurrency int
}

func (c *Client) Name() string { return "opensearch" }

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

type statusError struct {
	method string
	path   string
	code   int
	status string
	body   string
}

func (e *statusError) Error() string {
	if e.body == "" {
		return fmt.Sprintf("%s %s: %s", e.method, e.path, e.status)
	}
	return fmt.Sprintf("%s %s: %s: %s", e.method, e.path, e.status, e.body)
}

func isStatus(err error, code int) bool {
	var se *statusError
	return errors.As(err, &se) && se.code == code
}

func (c *Client) do(ctx context.Context, method, path string, body io.Reader, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.URL, "/")+path, body)
	if err != nil {
		return err
	}
	if c.Username != "" || c.Password != "" {
		req.SetBasicAuth(c.Username, c.Password)
	} else if c.APIKey != "" {
		req.Header.Set("Authorization", "ApiKey "+c.APIKey)
	}
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
		return &statusError{
			method: method,
			path:   path,
			code:   resp.StatusCode,
			status: resp.Status,
			body:   strings.TrimSpace(string(msg)),
		}
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

type totalHits int

func (t *totalHits) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		*t = 0
		return nil
	}
	if data[0] == '{' {
		var out struct {
			Value int `json:"value"`
		}
		if err := json.Unmarshal(data, &out); err != nil {
			return err
		}
		*t = totalHits(out.Value)
		return nil
	}
	var n int
	if err := json.Unmarshal(data, &n); err != nil {
		return err
	}
	*t = totalHits(n)
	return nil
}

type detectorSearchResponse struct {
	Hits struct {
		Total totalHits `json:"total"`
		Hits  []struct {
			ID     string         `json:"_id"`
			Source detectorSource `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}

type detectorSource struct {
	detectorFields
	Detector *detectorFields `json:"detector"`
}

type detectorFields struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	DetectorType string                 `json:"detector_type"`
	Enabled      *bool                  `json:"enabled"`
	Inputs       []detectorInputWrapper `json:"inputs"`
	Triggers     []detectorTrigger      `json:"triggers"`
}

func (s detectorSource) fields() detectorFields {
	fields := s.detectorFields
	if s.Detector != nil {
		nested := *s.Detector
		if nested.ID == "" {
			nested.ID = fields.ID
		}
		if nested.Name == "" {
			nested.Name = fields.Name
		}
		if nested.DetectorType == "" {
			nested.DetectorType = fields.DetectorType
		}
		if nested.Enabled == nil {
			nested.Enabled = fields.Enabled
		}
		if len(nested.Inputs) == 0 {
			nested.Inputs = fields.Inputs
		}
		if len(nested.Triggers) == 0 {
			nested.Triggers = fields.Triggers
		}
		return nested
	}
	return fields
}

type detectorInputWrapper struct {
	DetectorInput detectorInput `json:"detector_input"`
	Input         detectorInput `json:"input"`
}

func (w detectorInputWrapper) indices() []string {
	var out []string
	out = append(out, w.DetectorInput.Indices...)
	out = append(out, w.Input.Indices...)
	return out
}

type detectorInput struct {
	Indices []string `json:"indices"`
}

type detectorTrigger struct {
	Severity  json.RawMessage `json:"severity"`
	SevLevels json.RawMessage `json:"sev_levels"`
}

// Rules inventories Security Analytics detectors. Detector inputs expose the
// index bindings deadair needs; trigger severity is folded into the common
// low/medium/high/critical scale.
func (c *Client) Rules(ctx context.Context) ([]backend.Rule, error) {
	const pageSize = 100
	var rules []backend.Rule
	for from := 0; ; from += pageSize {
		body := strings.NewReader(fmt.Sprintf(`{"from":%d,"size":%d,"query":{"match_all":{}}}`, from, pageSize))
		var sr detectorSearchResponse
		if err := c.do(ctx, http.MethodPost, "/_plugins/_security_analytics/detectors/_search", body, &sr); err != nil {
			return nil, fmt.Errorf("listing security analytics detectors: %w", err)
		}
		for _, hit := range sr.Hits.Hits {
			fields := hit.Source.fields()
			enabled := true
			if fields.Enabled != nil {
				enabled = *fields.Enabled
			}
			id := hit.ID
			if id == "" {
				id = fields.ID
			}
			name := fields.Name
			if name == "" {
				name = id
			}
			severity := detectorSeverity(fields.Triggers)
			rules = append(rules, backend.Rule{
				ID:        id,
				Name:      name,
				Enabled:   enabled,
				Severity:  severity,
				RiskScore: riskScore(severity),
				Patterns:  detectorPatterns(fields.Inputs),
			})
		}
		total := int(sr.Hits.Total)
		if len(sr.Hits.Hits) == 0 || len(sr.Hits.Hits) < pageSize || (total > 0 && from+len(sr.Hits.Hits) >= total) {
			break
		}
	}
	return rules, nil
}

func detectorPatterns(inputs []detectorInputWrapper) []string {
	seen := map[string]bool{}
	var patterns []string
	for _, input := range inputs {
		for _, p := range input.indices() {
			p = strings.TrimSpace(p)
			if p == "" || seen[p] {
				continue
			}
			seen[p] = true
			patterns = append(patterns, p)
		}
	}
	return patterns
}

func detectorSeverity(triggers []detectorTrigger) string {
	best := "medium"
	bestRank := severityRank(best)
	for _, t := range triggers {
		for _, sev := range triggerSeverities(t) {
			if r := severityRank(sev); r < bestRank {
				best = sev
				bestRank = r
			}
		}
	}
	return best
}

func triggerSeverities(t detectorTrigger) []string {
	var out []string
	if sev := normalizeSeverity(t.Severity); sev != "" {
		out = append(out, sev)
	}
	for _, raw := range rawArray(t.SevLevels) {
		if sev := normalizeSeverity(raw); sev != "" {
			out = append(out, sev)
			continue
		}
		var obj struct {
			Severity json.RawMessage `json:"severity"`
		}
		if err := json.Unmarshal(raw, &obj); err == nil {
			if sev := normalizeSeverity(obj.Severity); sev != "" {
				out = append(out, sev)
			}
		}
	}
	return out
}

func rawArray(raw json.RawMessage) []json.RawMessage {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err == nil {
		return arr
	}
	return []json.RawMessage{raw}
}

func normalizeSeverity(raw json.RawMessage) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return normalizeSeverityString(s)
	}
	var n int
	if err := json.Unmarshal(raw, &n); err == nil {
		return normalizeSeverityString(strconv.Itoa(n))
	}
	var f float64
	if err := json.Unmarshal(raw, &f); err == nil {
		return normalizeSeverityString(strconv.Itoa(int(f)))
	}
	return ""
}

func normalizeSeverityString(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "critical":
		return "critical"
	case "2", "high":
		return "high"
	case "3", "medium":
		return "medium"
	case "4", "5", "low", "informational", "info":
		return "low"
	default:
		return ""
	}
}

func severityRank(sev string) int {
	switch sev {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 2
	}
}

func riskScore(sev string) int {
	switch sev {
	case "critical":
		return 99
	case "high":
		return 73
	case "medium":
		return 47
	case "low":
		return 21
	default:
		return 47
	}
}

type dsStatsResponse struct {
	DataStreams []struct {
		Name                string `json:"data_stream"`
		StoreSizeBytes      int64  `json:"store_size_bytes"`
		TotalStoreSizeBytes int64  `json:"total_store_size_bytes"`
		MaximumTimestamp    int64  `json:"maximum_timestamp"` // epoch millis
	} `json:"data_streams"`
}

type catIndex struct {
	Index     string `json:"index"`
	DocsCount string `json:"docs.count"`
	StoreSize string `json:"store.size"`
}

// Backing-index naming differs across the family: OpenSearch names them
// .ds-<stream>-<generation>, while Elasticsearch-lineage and some managed
// distros use .ds-<stream>-<yyyy.MM.dd>-<generation>. The dated form must be
// tried first so a date can never be absorbed into the stream name.
var (
	backingReDated = regexp.MustCompile(`^\.ds-(.+)-\d{4}\.\d{2}\.\d{2}-\d+$`)
	backingRePlain = regexp.MustCompile(`^\.ds-(.+)-\d+$`)
)

func backingStream(index string) (string, bool) {
	if m := backingReDated.FindStringSubmatch(index); m != nil {
		return m[1], true
	}
	if m := backingRePlain.FindStringSubmatch(index); m != nil {
		return m[1], true
	}
	return "", false
}

// Sources inventories data streams and plain indices with their health stats.
// Data-stream freshness comes from _data_stream/_stats when available; plain
// indices fall back to a bounded-concurrency size-0 max(@timestamp) aggregation.
func (c *Client) Sources(ctx context.Context) ([]backend.Source, error) {
	var ds dsStatsResponse
	if err := c.do(ctx, http.MethodGet, "/_data_stream/_stats", nil, &ds); err != nil && !isStatus(err, http.StatusNotFound) {
		return nil, fmt.Errorf("data stream stats: %w", err)
	}
	var cats []catIndex
	if err := c.do(ctx, http.MethodGet, "/_cat/indices?format=json&h=index,docs.count,store.size&bytes=b", nil, &cats); err != nil {
		return nil, fmt.Errorf("listing indices: %w", err)
	}

	streamDocs := make(map[string]int64)
	var sources []backend.Source
	for _, ci := range cats {
		if stream, ok := backingStream(ci.Index); ok {
			if n, err := strconv.ParseInt(ci.DocsCount, 10, 64); err == nil {
				streamDocs[stream] += n
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
		size := d.StoreSizeBytes
		if size == 0 {
			size = d.TotalStoreSizeBytes
		}
		s := backend.Source{Name: d.Name, SizeBytes: size, Docs: -1}
		if n, ok := streamDocs[d.Name]; ok {
			s.Docs = n
		}
		if d.MaximumTimestamp > 0 {
			s.LastEvent = time.UnixMilli(d.MaximumTimestamp)
		}
		sources = append(sources, s)
	}

	c.fillFreshness(ctx, sources)
	return sources, nil
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
	if err := c.do(ctx, http.MethodPost, path, body, &out); err != nil {
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
	if err := c.do(ctx, http.MethodGet, path, nil, &fc); err != nil {
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
