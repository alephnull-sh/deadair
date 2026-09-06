package sentinel

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/alephnull-sh/deadair/internal/backend"
)

func TestProvenanceRequestsWithoutTemplateLinks(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rules []backend.Rule
		want  int
	}{
		{name: "no rules"},
		{name: "unlinked rule", rules: []backend.Rule{{ID: "web-access"}}, want: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requests := 0
			server := provenanceFixtureServer(t, func(w http.ResponseWriter, r *http.Request, base string) {
				requests++
				if r.Method != http.MethodGet || r.URL.Path != base+"alertRules" {
					t.Errorf("unexpected provenance request: %s %s", r.Method, r.URL.Path)
				}
				fmt.Fprint(w, `{"value":[{"name":"web-access","kind":"Scheduled","properties":{}}]}`)
			})
			defer server.Close()
			evidence, err := fixtureClient(server.URL, &recordingCredential{}).ProvenanceEvidence(context.Background(), tc.rules)
			if err != nil || len(evidence) != 0 || requests != tc.want {
				t.Fatalf("evidence = %+v, error = %v, requests = %d; want %d", evidence, err, requests, tc.want)
			}
		})
	}
}

func TestProvenanceReadsSharedPackageOnce(t *testing.T) {
	requests := make(map[string]int)
	server := provenanceFixtureServer(t, func(w http.ResponseWriter, r *http.Request, base string) {
		requests[r.URL.Path]++
		if r.Method != http.MethodGet {
			t.Errorf("unexpected provenance method: %s", r.Method)
		}
		switch r.URL.Path {
		case base + "alertRules":
			fmt.Fprint(w, `{"value":[{"name":"web-access","properties":{"alertRuleTemplateName":"web-template","templateVersion":"1.0.0"}},{"name":"proxy-access","properties":{"alertRuleTemplateName":"proxy-template","templateVersion":"1.0.0"}}]}`)
		case base + "alertRuleTemplates":
			fmt.Fprint(w, `{"value":[{"name":"web-template","properties":{"version":"1.0.0"}},{"name":"proxy-template","properties":{"version":"1.0.0"}}]}`)
		case base + "contentTemplates":
			fmt.Fprint(w, `{"value":[{"properties":{"contentId":"web-template","packageId":"network","contentKind":"AnalyticsRuleTemplate"}},{"properties":{"contentId":"proxy-template","packageId":"network","contentKind":"AnalyticsRuleTemplate"}}]}`)
		case base + "contentPackages":
			fmt.Fprint(w, `{"value":[{"name":"network","properties":{"contentId":"network","version":"1.0.0"}}]}`)
		case base + "contentProductPackages/network":
			fmt.Fprint(w, `{"name":"network","properties":{"contentId":"network","version":"1.0.0","installedVersion":"1.0.0"}}`)
		default:
			t.Errorf("unexpected provenance path: %s", r.URL.Path)
			http.NotFound(w, r)
		}
	})
	defer server.Close()
	evidence, err := fixtureClient(server.URL, &recordingCredential{}).ProvenanceEvidence(context.Background(), []backend.Rule{{ID: "web-access"}, {ID: "proxy-access"}})
	if err != nil || len(evidence) != 4 {
		t.Fatalf("evidence = %+v, error = %v", evidence, err)
	}
	if len(requests) != 5 {
		t.Fatalf("requests = %+v; want five endpoint reads", requests)
	}
	for path, count := range requests {
		if count != 1 {
			t.Errorf("%s read %d times; want once", path, count)
		}
	}
}
