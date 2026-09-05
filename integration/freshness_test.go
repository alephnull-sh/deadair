//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alephnull-sh/deadair/internal/backend"
	"github.com/alephnull-sh/deadair/internal/backend/elastic"
	"github.com/alephnull-sh/deadair/internal/backend/opensearch"
	"github.com/alephnull-sh/deadair/internal/cli"
	"github.com/alephnull-sh/deadair/internal/health"
)

func assertClockSkewSources(t *testing.T, sources []backend.Source, live, stale string) {
	t.Helper()
	seen := make(map[string]bool)
	for _, source := range sources {
		want := health.StatusOK
		if source.Name == stale {
			want = health.StatusStale
		} else if source.Name != live {
			continue
		}
		seen[source.Name] = true
		if got := (health.Check{MaxStale: time.Hour}).Evaluate(source); got.Status != want {
			t.Errorf("%s after future event: %+v, want %s", source.Name, got, want)
		}
	}
	if !seen[live] || !seen[stale] {
		t.Fatalf("sources missing: %v", seen)
	}
}

func TestElasticFutureTimestampsAndCandidateDependencies(t *testing.T) {
	waitForStack(t)
	cleanup(t)
	t.Cleanup(func() { cleanup(t) })
	seed(t)
	for _, name := range []string{liveStream, staleIndex} {
		admin(t, http.MethodPost, esURL+"/"+name+"/_doc", fmt.Sprintf(`{"@timestamp":%q,"message":"clock error"}`, time.Now().UTC().Add(24*time.Hour).Format(time.RFC3339)), http.StatusCreated)
	}
	admin(t, http.MethodPost, esURL+"/_refresh", "", http.StatusOK)
	key := provision(t)
	client := &elastic.Client{ESURL: esURL, KibanaURL: kbURL, APIKey: key, HTTP: &http.Client{Timeout: 30 * time.Second}, Concurrency: 2}
	sources, err := client.Sources(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	assertClockSkewSources(t, sources, liveStream, staleIndex)
	t.Setenv("DEADAIR_API_KEY", key)
	t.Setenv("DEADAIR_BACKEND", "elastic")
	for _, tc := range []struct {
		name, data string
		exit       int
	}{
		{"direct", fmt.Sprintf(`{"rule_id":"candidate","type":"esql","query":%q}`, "FROM "+liveStream+" | LIMIT 10"), 0},
		{"lookup", fmt.Sprintf(`{"rule_id":"candidate","type":"esql","query":%q}`, "FROM "+liveStream+" | LOOKUP JOIN missing_indicators ON message"), 2},
		{"indicator", fmt.Sprintf(`{"rule_id":"candidate","type":"threat_match","index":[%q],"threat_index":["missing_indicators"]}`, liveStream), 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "candidate.json")
			if err := os.WriteFile(path, []byte(tc.data), 0600); err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			code := cli.Run([]string{"scan", "--rule", path, "--es-url", esURL, "--kibana-url", kbURL, "--max-stale", "1h", "--json"}, &stdout, &stderr)
			if code != tc.exit || !json.Valid(stdout.Bytes()) {
				t.Fatalf("exit=%d want=%d stderr=%s stdout=%s", code, tc.exit, stderr.String(), stdout.String())
			}
		})
	}
}

func TestOpenSearchFutureTimestamps(t *testing.T) {
	waitForOpenSearch(t)
	cleanupOpenSearch(t)
	t.Cleanup(func() { cleanupOpenSearch(t) })
	provisionOpenSearchReadUser(t)
	seedOpenSearch(t)
	for _, name := range []string{openSearchLiveStream, openSearchStaleIndex} {
		osAdmin(t, http.MethodPost, openSearchURL+"/"+name+"/_doc", fmt.Sprintf(`{"@timestamp":%q,"message":"clock error"}`, time.Now().UTC().Add(24*time.Hour).Format(time.RFC3339)), http.StatusCreated)
	}
	osAdmin(t, http.MethodPost, openSearchURL+"/_refresh", "", http.StatusOK)
	client := &opensearch.Client{URL: openSearchURL, Username: openSearchReadUser, Password: openSearchReadPass, HTTP: &http.Client{Timeout: 30 * time.Second}, Concurrency: 2}
	sources, err := client.Sources(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	assertClockSkewSources(t, sources, openSearchLiveStream, openSearchStaleIndex)
}
