package sentinel

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alephnull-sh/deadair/internal/backend"
)

func TestProvenanceEvidenceLinksExactTemplateAndContentPackageVersions(t *testing.T) {
	credential := &recordingCredential{}
	var server *httptest.Server
	var requests []string
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.RequestURI())
		base := "/subscriptions/sub-id/resourceGroups/rg-lab/providers/Microsoft.OperationalInsights/workspaces/law-lab/providers/Microsoft.SecurityInsights/"
		switch r.URL.Path {
		case base + "alertRules":
			fmt.Fprintf(w, `{"value":[{
				"id":"%salertRules/rule-a","name":"rule-a","kind":"Scheduled",
				"properties":{"alertRuleTemplateName":"template-a","templateVersion":"1.0.0"}
			}],"nextLink":%q}`, base, server.URL+"/content/next?cursor=a%2Fb")
		case "/content/next":
			fmt.Fprint(w, `{"value":[{"id":"/alertRules/unrelated","name":"unrelated","kind":"Scheduled","properties":{}}]}`)
		case base + "alertRuleTemplates":
			fmt.Fprint(w, `{"value":[{
				"id":"/alertRuleTemplates/template-a","name":"template-a","kind":"Scheduled",
				"properties":{"displayName":"Template A","version":"2.0.0","status":"Available"}
			}]}`)
		case base + "contentTemplates":
			if r.URL.Query().Get("$expand") != "" {
				t.Errorf("content templates unexpectedly expanded packaged content")
			}
			fmt.Fprint(w, `{"value":[{
				"id":"/contentTemplates/template-a","name":"template-a",
				"properties":{"contentId":"template-a","displayName":"Template A","contentKind":"AnalyticsRuleTemplate","version":"2.0.0","packageId":"package-a","packageVersion":"1.0.0"}
			}]}`)
		case base + "contentPackages":
			fmt.Fprint(w, `{"value":[{
				"id":"/contentPackages/package-a","name":"package-a",
				"properties":{"contentId":"package-a","displayName":"Package A","version":"1.0.0"}
			}]}`)
		case base + "contentProductPackages/package-a":
			if r.URL.Query().Get("$expand") != "" {
				t.Errorf("product packages unexpectedly expanded packaged content")
			}
			fmt.Fprint(w, `{
				"id":"/contentProductPackages/package-a","name":"package-a",
				"properties":{"contentId":"package-a","displayName":"Package A","version":"2.0.0","installedVersion":"1.0.0"}
			}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	rules := []backend.Rule{{
		ID: "rule-a", BackendObjectID: "/subscriptions/sub-id/rules/rule-a", Name: "Rule A", Enabled: true,
	}}
	evidence, err := fixtureClient(server.URL, credential).ProvenanceEvidence(context.Background(), rules)
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence) != 2 {
		t.Fatalf("provenance = %+v", evidence)
	}
	template := evidence[1]
	packageEvidence := evidence[0]
	if template.Provenance.Kind != "sentinel_alert_rule_template" {
		template, packageEvidence = packageEvidence, template
	}
	if template.RuleID != "rule-a" || template.Provenance.ID != "template-a" ||
		template.Provenance.Name != "Template A" || template.Status != backend.EvidenceAssessed ||
		template.Detail != "installed version 1.0.0; current version 2.0.0" {
		t.Errorf("template provenance = %+v", template)
	}
	if packageEvidence.Provenance.Kind != "sentinel_content_package" ||
		packageEvidence.Provenance.ID != "package-a" || packageEvidence.Provenance.Name != "Package A" ||
		packageEvidence.Status != backend.EvidenceAssessed ||
		packageEvidence.Detail != "installed version 1.0.0; current version 2.0.0" {
		t.Errorf("package provenance = %+v", packageEvidence)
	}
	for _, request := range requests {
		if !strings.HasPrefix(request, http.MethodGet+" ") {
			t.Fatalf("provenance made non-GET request: %s", request)
		}
		if strings.Contains(request, "/contentProductPackages?") {
			t.Fatalf("provenance listed the full Content Hub catalog: %s", request)
		}
	}
	if !credential.sawScope(armScope) {
		t.Fatal("provenance did not request the ARM scope")
	}
}

func TestProvenanceEvidenceDoesNotGuessContentTemplateByDisplayName(t *testing.T) {
	server := provenanceFixtureServer(t, func(w http.ResponseWriter, r *http.Request, base string) {
		switch r.URL.Path {
		case base + "alertRules":
			fmt.Fprint(w, `{"value":[{"id":"/rules/rule-a","name":"rule-a","kind":"Scheduled","properties":{"alertRuleTemplateName":"template-a","templateVersion":"1.0.0"}}]}`)
		case base + "alertRuleTemplates":
			fmt.Fprint(w, `{"value":[{"id":"/templates/template-a","name":"template-a","properties":{"displayName":"Same display name","version":"1.0.0"}}]}`)
		case base + "contentTemplates":
			fmt.Fprint(w, `{"value":[{"id":"/contentTemplates/different-id","name":"different-id","properties":{"contentId":"different-id","displayName":"Same display name","packageId":"package-a"}}]}`)
		case base + "contentPackages":
			fmt.Fprint(w, `{"value":[]}`)
		default:
			http.NotFound(w, r)
		}
	})
	defer server.Close()

	evidence, err := fixtureClient(server.URL, &recordingCredential{}).ProvenanceEvidence(context.Background(), []backend.Rule{{ID: "rule-a"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence) != 1 || evidence[0].Provenance.Kind != "sentinel_alert_rule_template" {
		t.Fatalf("display-name guess produced package provenance: %+v", evidence)
	}
}

func TestProvenanceEvidencePreservesContentHubPermissionFailure(t *testing.T) {
	server := provenanceFixtureServer(t, func(w http.ResponseWriter, r *http.Request, base string) {
		switch r.URL.Path {
		case base + "alertRules":
			fmt.Fprint(w, `{"value":[{"id":"/rules/rule-a","name":"rule-a","kind":"Scheduled","properties":{"alertRuleTemplateName":"template-a","templateVersion":"1.0.0"}}]}`)
		case base + "alertRuleTemplates":
			fmt.Fprint(w, `{"value":[{"id":"/templates/template-a","name":"template-a","properties":{"version":"1.0.0"}}]}`)
		case base + "contentTemplates":
			http.Error(w, `{"error":{"code":"AuthorizationFailed"}}`, http.StatusForbidden)
		default:
			http.NotFound(w, r)
		}
	})
	defer server.Close()

	evidence, err := fixtureClient(server.URL, &recordingCredential{}).ProvenanceEvidence(context.Background(), []backend.Rule{{ID: "rule-a"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence) != 2 {
		t.Fatalf("permission failure provenance = %+v", evidence)
	}
	var unavailable bool
	for _, item := range evidence {
		if item.Provenance.Kind == "sentinel_content_hub" && item.Status == backend.EvidenceUnavailable &&
			item.Detail == "Content Hub template metadata could not be read" {
			unavailable = true
		}
	}
	if !unavailable {
		t.Fatalf("Content Hub permission failure was not preserved: %+v", evidence)
	}
}

func TestContentPaginationRejectsCrossHostAndCycles(t *testing.T) {
	t.Run("cross host", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `{"value":[],"nextLink":"https://example.invalid/next"}`)
		}))
		defer server.Close()
		_, err := fixtureClient(server.URL, &recordingCredential{}).listContentTemplates(context.Background())
		if err == nil || !strings.Contains(err.Error(), "outside the configured ARM endpoint") {
			t.Fatalf("cross-host content nextLink error = %v", err)
		}
	})

	t.Run("cycle", func(t *testing.T) {
		var server *httptest.Server
		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, `{"value":[],"nextLink":%q}`, server.URL+r.URL.RequestURI())
		}))
		defer server.Close()
		_, err := fixtureClient(server.URL, &recordingCredential{}).listContentTemplates(context.Background())
		if err == nil || !strings.Contains(err.Error(), "pagination cycle detected") {
			t.Fatalf("content pagination cycle error = %v", err)
		}
	})
}

func provenanceFixtureServer(t *testing.T, handler func(http.ResponseWriter, *http.Request, string)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := "/subscriptions/sub-id/resourceGroups/rg-lab/providers/Microsoft.OperationalInsights/workspaces/law-lab/providers/Microsoft.SecurityInsights/"
		handler(w, r, base)
	}))
}
