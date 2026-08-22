//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/alephnull-sh/deadair/internal/backend"
	"github.com/alephnull-sh/deadair/internal/backend/sentinel"
)

const (
	sentinelFreshRuleID         = "11111111-1111-4111-8111-111111111111"
	sentinelStaleRuleID         = "22222222-2222-4222-8222-222222222222"
	sentinelLagRuleID           = "33333333-3333-4333-8333-333333333333"
	sentinelMissingRuleID       = "44444444-4444-4444-8444-444444444444"
	sentinelPartialRuleID       = "55555555-5555-4555-8555-555555555555"
	sentinelLetJoinRuleID       = "66666666-6666-4666-8666-666666666666"
	sentinelFunctionBareID      = "71111111-1111-4111-8111-111111111111"
	sentinelFunctionCallID      = "72222222-2222-4222-8222-222222222222"
	sentinelParameterizedID     = "73333333-3333-4333-8333-333333333333"
	sentinelAuxiliaryRuleID     = "74444444-4444-4444-8444-444444444444"
	sentinelEmptyAnalyticsID    = "76666666-6666-4666-8666-666666666666"
	sentinelNRTRuleID           = "78888888-8888-4888-8888-888888888888"
	sentinelFreshTable          = "DeadairFresh_CL"
	sentinelStaleTable          = "DeadairStale_CL"
	sentinelLagTable            = "DeadairLag_CL"
	sentinelUnusedTable         = "DeadairUnused_CL"
	sentinelMissingTable        = "DeadairRemoved_CL"
	sentinelBasicTable          = "DeadairBasic_CL"
	sentinelAuxiliaryTable      = "DeadairAuxiliary_CL"
	sentinelEmptyAnalyticsTable = "DeadairEmptyAnalytics_CL"
	sentinelWatchlistAlias      = "DeadairVIPs"
	sentinelRemoteTable         = "DeadairRemote_CL"
	sentinelSummaryRule         = "deadair-basic-summary"
	sentinelSummaryTable        = "DeadairBasicSummary_CL"
	sentinelWatchlistRuleID     = "79911111-1111-4111-8111-111111111111"
	sentinelASIMRuleID          = "79922222-2222-4222-8222-222222222222"
	sentinelRemoteRuleID        = "79933333-3333-4333-8333-333333333333"
	sentinelSummaryRuleID       = "79944444-4444-4444-8444-444444444444"
)

// TestSentinelReadOnlyLab proves the Sentinel adapter against pre-seeded,
// disposable fixtures. It only performs ARM GETs and Log Analytics read/query
// calls. Fixture provisioning and write-denial checks stay outside this test.
func TestSentinelReadOnlyLab(t *testing.T) {
	if os.Getenv("DEADAIR_IT_SENTINEL") != "1" {
		t.Skip("set DEADAIR_IT_SENTINEL=1 to run the live Sentinel integration test")
	}

	credential := sentinelScannerCredential(t)
	subscriptionID := requiredSentinelEnv(t, "DEADAIR_AZURE_SUBSCRIPTION_ID")
	resourceGroup := requiredSentinelEnv(t, "DEADAIR_AZURE_RESOURCE_GROUP")
	remoteWorkspace := requiredSentinelEnv(t, "DEADAIR_SENTINEL_REMOTE_WORKSPACE")
	client, err := sentinel.NewClient(sentinel.Config{
		SubscriptionID: subscriptionID,
		ResourceGroup:  resourceGroup,
		WorkspaceName:  requiredSentinelEnv(t, "DEADAIR_SENTINEL_WORKSPACE"),
		WorkspaceID:    os.Getenv("DEADAIR_SENTINEL_WORKSPACE_ID"),
		RemoteWorkspaces: []sentinel.RemoteWorkspace{{
			Alias: remoteWorkspace, SubscriptionID: subscriptionID, ResourceGroup: resourceGroup,
			WorkspaceName: remoteWorkspace, WorkspaceID: os.Getenv("DEADAIR_SENTINEL_REMOTE_WORKSPACE_ID"),
		}},
		Credential: credential,
	})
	if err != nil {
		t.Fatalf("create Sentinel client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	assertSentinelRemoteOnboarding(ctx, t, credential, subscriptionID, resourceGroup, remoteWorkspace)
	if err := client.RefreshForScan(ctx); err != nil {
		t.Fatalf("refresh Sentinel observations: %v", err)
	}

	rules, err := client.Rules(ctx)
	if err != nil {
		t.Fatalf("inventory Sentinel rules: %v", err)
	}
	rulesByID := sentinelRulesByID(rules)
	assertSentinelRuleInventory(t, rulesByID, remoteWorkspace)
	remoteSource := fmt.Sprintf("azure-loganalytics:///subscriptions/%s/resourcegroups/%s/providers/microsoft.operationalinsights/workspaces/%s/tables/%s",
		strings.ToLower(subscriptionID), strings.ToLower(resourceGroup), strings.ToLower(remoteWorkspace), sentinelRemoteTable)
	nrtRule := requireSentinelRule(t, rulesByID, sentinelNRTRuleID)
	nrtRule.Enabled = true // Exercise the dependency without enabling the Azure fixture.
	watchlistRule := requireSentinelRule(t, rulesByID, sentinelWatchlistRuleID)
	watchlistRule.Enabled = true // Azure fixture remains disabled.
	asimRule := requireSentinelRule(t, rulesByID, sentinelASIMRuleID)
	asimRule.Enabled = true // Azure fixture remains disabled.
	remoteRule := requireSentinelRule(t, rulesByID, sentinelRemoteRuleID)
	remoteRule.Enabled = true // Azure fixture remains disabled.
	summaryConsumerRule := requireSentinelRule(t, rulesByID, sentinelSummaryRuleID)
	summaryConsumerRule.Enabled = true // Azure fixture remains disabled.
	resolutionRules := []backend.Rule{
		requireSentinelRule(t, rulesByID, sentinelFreshRuleID),
		requireSentinelRule(t, rulesByID, sentinelMissingRuleID),
		requireSentinelRule(t, rulesByID, sentinelPartialRuleID),
		requireSentinelRule(t, rulesByID, sentinelLetJoinRuleID),
		requireSentinelRule(t, rulesByID, sentinelFunctionBareID),
		requireSentinelRule(t, rulesByID, sentinelFunctionCallID),
		requireSentinelRule(t, rulesByID, sentinelParameterizedID),
		requireSentinelRule(t, rulesByID, sentinelAuxiliaryRuleID),
		requireSentinelRule(t, rulesByID, sentinelEmptyAnalyticsID),
		nrtRule,
		{ID: "deadair-live-basic-plan", Enabled: true, Patterns: []string{sentinelBasicTable}},
		watchlistRule,
		asimRule,
		remoteRule,
		summaryConsumerRule,
	}

	sources, err := client.Sources(ctx)
	if err != nil {
		t.Fatalf("inventory Log Analytics tables: %v", err)
	}
	sourcesByName := sentinelSourcesByName(sources)
	for _, name := range []string{
		sentinelFreshTable,
		sentinelStaleTable,
		sentinelLagTable,
		sentinelUnusedTable,
		sentinelBasicTable,
		sentinelAuxiliaryTable,
		sentinelEmptyAnalyticsTable,
	} {
		if _, ok := sourcesByName[name]; !ok {
			t.Errorf("table inventory does not contain %s", name)
		}
	}
	if _, ok := sourcesByName[sentinelMissingTable]; ok {
		t.Errorf("deleted fixture %s is still present", sentinelMissingTable)
	}
	remote, ok := sourcesByName[remoteSource]
	if !ok {
		t.Fatalf("configured remote table inventory does not contain %s", remoteSource)
	}
	remoteFreshness, err := client.FreshnessEvidenceFor(ctx, []backend.FreshnessRequest{{
		Source: remote, Basis: backend.FreshnessEventTime,
	}})
	if err != nil {
		t.Fatalf("read configured remote event-time freshness evidence: %v", err)
	}
	if evidence := remoteFreshness[remoteSource]; evidence.Status != backend.EvidenceAssessed ||
		!evidence.LastEvent.IsZero() || evidence.Window <= 0 || evidence.Method != "bounded-max-event-time" {
		t.Fatalf("configured remote freshness = %+v, want assessed bounded-empty evidence", evidence)
	}
	readiness, err := client.ReadinessEvidence(ctx, resolutionRules, sources)
	if err != nil {
		t.Fatalf("prove Sentinel dependency readiness: %v", err)
	}
	if readiness.Status != backend.EvidenceAssessed || !readiness.Attempted || !readiness.Limited ||
		!strings.Contains(readiness.Detail, "Sentinel ASIM parser read path was reached") {
		t.Fatalf("Sentinel dependency readiness = %+v, want assessed, limited native-ASIM evidence", readiness)
	}
	queryReadinessRules := make([]backend.Rule, 0, len(resolutionRules)-1)
	for _, rule := range resolutionRules {
		if rule.ID != sentinelASIMRuleID {
			queryReadinessRules = append(queryReadinessRules, rule)
		}
	}
	queryReadiness, err := client.ReadinessEvidence(ctx, queryReadinessRules, sources)
	if err != nil {
		t.Fatalf("prove Sentinel table, watchlist, and remote readiness: %v", err)
	}
	if queryReadiness.Status != backend.EvidenceAssessed || !queryReadiness.Attempted || queryReadiness.Limited {
		t.Fatalf("Sentinel table, watchlist, and remote readiness = %+v, want fully assessed evidence", queryReadiness)
	}
	resolutions, err := client.ResolveInputs(ctx, resolutionRules)
	if err != nil {
		t.Fatalf("resolve Sentinel rule inputs: %v", err)
	}
	assertSentinelResolutions(t, resolutions, remoteSource, remoteWorkspace)
	assertSentinelDependencyEvidence(t, resolutions, remoteSource)

	lineage, err := client.LineageEvidence(ctx, resolutionRules)
	if err != nil {
		t.Fatalf("read Sentinel summary-rule lineage: %v", err)
	}
	assertSentinelSummaryLineage(t, lineage, resolutions)

	provenanceExpectation := sentinelProvenancePrerequisites(ctx, t, credential, rulesByID)
	provenance, err := client.ProvenanceEvidence(ctx, rules)
	if err != nil {
		t.Fatalf("read Sentinel rule provenance: %v", err)
	}
	assertSentinelEmptyContentHubPath(t, provenance, provenanceExpectation)

	evidenceSources := requireSentinelSources(t, sourcesByName,
		sentinelFreshTable, sentinelStaleTable, sentinelLagTable, sentinelUnusedTable, sentinelEmptyAnalyticsTable)
	eventRequests := make([]backend.FreshnessRequest, 0, len(evidenceSources))
	for _, source := range evidenceSources {
		eventRequests = append(eventRequests, backend.FreshnessRequest{Source: source, Basis: backend.FreshnessEventTime})
	}
	freshness, err := client.FreshnessEvidenceFor(ctx, eventRequests)
	if err != nil {
		t.Fatalf("read Sentinel event-time freshness evidence: %v", err)
	}
	for _, name := range []string{sentinelFreshTable, sentinelStaleTable, sentinelLagTable, sentinelUnusedTable} {
		evidence := freshness[name]
		if evidence.Status != backend.EvidenceAssessed || evidence.LastEvent.IsZero() || evidence.Method != "bounded-max-event-time" {
			t.Errorf("%s freshness = %+v, want assessed bounded event-time evidence", name, evidence)
		}
	}
	empty := freshness[sentinelEmptyAnalyticsTable]
	if empty.Status != backend.EvidenceAssessed || !empty.LastEvent.IsZero() || empty.Window <= 0 {
		t.Errorf("%s freshness = %+v, want assessed empty bounded window", sentinelEmptyAnalyticsTable, empty)
	}
	ingestionFreshness, err := client.FreshnessEvidenceFor(ctx, []backend.FreshnessRequest{{
		Source: sourcesByName[sentinelFreshTable], Basis: backend.FreshnessIngestionTime,
	}})
	if err != nil {
		t.Fatalf("read Sentinel NRT freshness evidence: %v", err)
	}
	if evidence := ingestionFreshness[sentinelFreshTable]; evidence.Status != backend.EvidenceAssessed ||
		evidence.LastEvent.IsZero() || evidence.Method != "bounded-max-ingestion-time" {
		t.Errorf("NRT freshness = %+v, want assessed bounded ingestion-time evidence", evidence)
	}
	mixedFreshness, err := client.FreshnessEvidenceFor(ctx, []backend.FreshnessRequest{{
		Source: sourcesByName[sentinelFreshTable], Basis: backend.FreshnessMixed,
	}})
	if err != nil {
		t.Fatalf("read Sentinel mixed-timing freshness evidence: %v", err)
	}
	if evidence := mixedFreshness[sentinelFreshTable]; evidence.Status != backend.EvidenceIncomplete || evidence.Method != "mixed-rule-timing" {
		t.Errorf("mixed timing freshness = %+v, want explicit incomplete evidence", evidence)
	}

	lag, err := client.IngestLagEvidence(ctx, requireSentinelSources(t, sourcesByName,
		sentinelFreshTable, sentinelLagTable, sentinelStaleTable))
	if err != nil {
		t.Fatalf("read Sentinel ingest-lag evidence: %v", err)
	}
	for _, name := range []string{sentinelFreshTable, sentinelLagTable, sentinelStaleTable} {
		evidence := lag[name]
		if evidence.Status != backend.EvidenceAssessed || evidence.SampleCount < 1 {
			t.Fatalf("%s ingest lag = %+v, want at least one paired sample", name, evidence)
		}
	}
	if !(lag[sentinelFreshTable].P95 < lag[sentinelLagTable].P95 &&
		lag[sentinelLagTable].P95 < lag[sentinelStaleTable].P95) {
		t.Errorf("unexpected p95 lag ordering: fresh=%s delayed=%s stale=%s",
			lag[sentinelFreshTable].P95, lag[sentinelLagTable].P95, lag[sentinelStaleTable].P95)
	}
}

// TestSentinelWriteDenials sends three explicitly gated write-shaped requests
// as the scanner identity. Both DELETE targets are proven absent first, so a
// mistakenly write-capable identity still cannot remove a real fixture.
func TestSentinelWriteDenials(t *testing.T) {
	if os.Getenv("DEADAIR_IT_SENTINEL_WRITE_DENIALS") != "1" {
		t.Skip("set DEADAIR_IT_SENTINEL_WRITE_DENIALS=1 to run Sentinel write-denial checks")
	}
	credential := sentinelScannerCredential(t)
	subscriptionID := requiredSentinelEnv(t, "DEADAIR_AZURE_SUBSCRIPTION_ID")
	resourceGroup := requiredSentinelEnv(t, "DEADAIR_AZURE_RESOURCE_GROUP")
	workspace := requiredSentinelEnv(t, "DEADAIR_SENTINEL_WORKSPACE")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	token, err := credential.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{"https://management.azure.com/.default"}})
	if err != nil {
		t.Fatal("scanner EnvironmentCredential could not obtain an ARM token")
	}
	workspacePath := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.OperationalInsights/workspaces/%s",
		url.PathEscape(subscriptionID), url.PathEscape(resourceGroup), url.PathEscape(workspace))
	missingRule := "https://management.azure.com" + workspacePath +
		"/providers/Microsoft.SecurityInsights/alertRules/79999999-9999-4999-8999-999999999999?api-version=2025-09-01"
	missingTable := "https://management.azure.com" + workspacePath +
		"/tables/DeadairWriteDenialMissing_CL?api-version=2025-07-01"
	sharedKeys := "https://management.azure.com" + workspacePath + "/sharedKeys?api-version=2025-07-01"

	assertSentinelARMStatus(ctx, t, token.Token, http.MethodGet, missingRule, http.StatusNotFound,
		"nonexistent alert-rule preflight")
	assertSentinelARMStatus(ctx, t, token.Token, http.MethodGet, missingTable, http.StatusNotFound,
		"nonexistent table preflight")
	assertSentinelARMStatus(ctx, t, token.Token, http.MethodDelete, missingRule, http.StatusForbidden,
		"alert-rule DELETE denial")
	assertSentinelARMStatus(ctx, t, token.Token, http.MethodDelete, missingTable, http.StatusForbidden,
		"table DELETE denial")
	assertSentinelARMStatus(ctx, t, token.Token, http.MethodPost, sharedKeys, http.StatusForbidden,
		"shared-keys POST denial")
}

func sentinelScannerCredential(t *testing.T) *azidentity.DefaultAzureCredential {
	t.Helper()
	if os.Getenv("AZURE_TOKEN_CREDENTIALS") != "EnvironmentCredential" {
		t.Fatal("AZURE_TOKEN_CREDENTIALS must be exactly EnvironmentCredential")
	}
	if os.Getenv("AZURE_CLIENT_SECRET") != "" {
		t.Fatal("AZURE_CLIENT_SECRET must be unset for Sentinel conformance")
	}
	requiredSentinelEnv(t, "AZURE_TENANT_ID")
	clientID := requiredSentinelEnv(t, "AZURE_CLIENT_ID")
	requiredSentinelEnv(t, "AZURE_CLIENT_CERTIFICATE_PATH")
	scannerClientID := requiredSentinelEnv(t, "DEADAIR_SENTINEL_SCANNER_CLIENT_ID")
	if clientID != scannerClientID {
		t.Fatal("DEADAIR_SENTINEL_SCANNER_CLIENT_ID must equal AZURE_CLIENT_ID")
	}
	credential, err := azidentity.NewDefaultAzureCredential(&azidentity.DefaultAzureCredentialOptions{
		RequireAzureTokenCredentials: true,
	})
	if err != nil {
		t.Fatal("create scanner-only DefaultAzureCredential")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, scope := range []string{
		"https://management.azure.com/.default",
		"https://api.loganalytics.io/.default",
	} {
		if _, err := credential.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{scope}}); err != nil {
			t.Fatal("scanner EnvironmentCredential could not obtain required Azure tokens")
		}
	}
	return credential
}

func assertSentinelARMStatus(ctx context.Context, t *testing.T, token, method, target string, want int, label string) {
	t.Helper()
	request, err := http.NewRequestWithContext(ctx, method, target, nil)
	if err != nil {
		t.Fatalf("create %s request", label)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("send %s request", label)
	}
	response.Body.Close() // Deliberately never inspect a write-shaped response body.
	if response.StatusCode != want {
		t.Fatalf("%s returned HTTP %d, want %d", label, response.StatusCode, want)
	}
}

func assertSentinelRemoteOnboarding(ctx context.Context, t *testing.T, credential azcore.TokenCredential, subscriptionID, resourceGroup, workspace string) {
	t.Helper()
	token, err := credential.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{"https://management.azure.com/.default"}})
	if err != nil {
		t.Fatal("scanner EnvironmentCredential could not obtain an ARM token for onboarding verification")
	}
	resourcePath := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.OperationalInsights/workspaces/%s/providers/Microsoft.SecurityInsights/onboardingStates/default",
		url.PathEscape(subscriptionID), url.PathEscape(resourceGroup), url.PathEscape(workspace))
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://management.azure.com"+resourcePath+"?api-version=2025-09-01", nil)
	if err != nil {
		t.Fatalf("create remote Sentinel onboarding request: %v", err)
	}
	request.Header.Set("Authorization", "Bearer "+token.Token)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("read remote Sentinel onboarding state: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("remote Sentinel onboarding state returned HTTP %d", response.StatusCode)
	}
	payload, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("decode remote Sentinel onboarding state: %v", err)
	}
	if err := validateSentinelOnboardingState(payload, resourcePath); err != nil {
		t.Fatalf("remote Sentinel onboarding state is unexpected: %v", err)
	}
}

func validateSentinelOnboardingState(payload []byte, resourcePath string) error {
	var state struct {
		ID         string          `json:"id"`
		Name       string          `json:"name"`
		Type       string          `json:"type"`
		Properties json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(payload, &state); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	if !strings.EqualFold(state.ID, resourcePath) || state.Name != "default" ||
		!strings.EqualFold(state.Type, "Microsoft.SecurityInsights/onboardingStates") {
		return fmt.Errorf("resource identity does not match")
	}
	var properties map[string]json.RawMessage
	if len(state.Properties) == 0 || json.Unmarshal(state.Properties, &properties) != nil || properties == nil {
		return fmt.Errorf("properties must be an object")
	}
	if raw, ok := properties["customerManagedKey"]; ok {
		if strings.TrimSpace(string(raw)) == "null" {
			return fmt.Errorf("customerManagedKey must not be null")
		}
		var enabled bool
		if err := json.Unmarshal(raw, &enabled); err != nil {
			return fmt.Errorf("customerManagedKey must be boolean")
		}
		if enabled {
			return fmt.Errorf("customerManagedKey must not be true")
		}
	}
	return nil
}

func TestSentinelOnboardingStateContract(t *testing.T) {
	const resourcePath = "/subscriptions/s/resourceGroups/r/providers/Microsoft.OperationalInsights/workspaces/w/providers/Microsoft.SecurityInsights/onboardingStates/default"
	base := `"id":"` + resourcePath + `","name":"default","type":"Microsoft.SecurityInsights/onboardingStates"`
	tests := []struct {
		name    string
		payload string
		valid   bool
	}{
		{name: "omitted CMK", payload: `{` + base + `,"properties":{}}`, valid: true},
		{name: "explicit false CMK", payload: `{` + base + `,"properties":{"customerManagedKey":false}}`, valid: true},
		{name: "explicit true CMK", payload: `{` + base + `,"properties":{"customerManagedKey":true}}`},
		{name: "null CMK", payload: `{` + base + `,"properties":{"customerManagedKey":null}}`},
		{name: "string CMK", payload: `{` + base + `,"properties":{"customerManagedKey":"false"}}`},
		{name: "missing properties", payload: `{` + base + `}`},
		{name: "null properties", payload: `{` + base + `,"properties":null}`},
		{name: "wrong identity", payload: `{"id":"wrong","name":"default","type":"Microsoft.SecurityInsights/onboardingStates","properties":{}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSentinelOnboardingState([]byte(tt.payload), resourcePath)
			if tt.valid && err != nil {
				t.Fatalf("valid onboarding response rejected: %v", err)
			}
			if !tt.valid && err == nil {
				t.Fatal("malformed onboarding response accepted")
			}
		})
	}
}

func TestSentinelExpansionFixturePredicates(t *testing.T) {
	command := exec.Command("sh", "prepare-sentinel-expansion-lab.sh", "predicate-test")
	command.Env = []string{"PATH=" + os.Getenv("PATH")}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("Sentinel expansion fixture predicate tests failed: %v\n%s", err, output)
	}
}

type sentinelRawProvenance struct {
	templateID               string
	installedTemplateVersion string
	currentTemplateVersion   string
	templateReady            bool
	packageID                string
	productPackageFound      bool
}

type sentinelAlertTemplateIdentity struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Properties struct {
		Version string `json:"version"`
	} `json:"properties"`
}

type sentinelContentTemplateIdentity struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Properties struct {
		ContentID string `json:"contentId"`
		PackageID string `json:"packageId"`
	} `json:"properties"`
}

type sentinelContentPackageIdentity struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Properties struct {
		ContentID string `json:"contentId"`
		Version   string `json:"version"`
	} `json:"properties"`
}

type sentinelProductPackageIdentity struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Properties struct {
		ContentID        string `json:"contentId"`
		Version          string `json:"version"`
		InstalledVersion string `json:"installedVersion"`
	} `json:"properties"`
}

func sentinelProvenancePrerequisites(ctx context.Context, t *testing.T, credential azcore.TokenCredential, rules map[string]backend.Rule) sentinelRawProvenance {
	t.Helper()
	fusion := requireSentinelRule(t, rules, "BuiltInFusion")
	objectID := strings.TrimSpace(fusion.BackendObjectID)
	const ruleSegment = "/providers/Microsoft.SecurityInsights/alertRules/"
	segment := strings.LastIndex(strings.ToLower(objectID), strings.ToLower(ruleSegment))
	if segment < 0 || !strings.HasPrefix(strings.ToLower(objectID), "/subscriptions/") {
		t.Fatalf("Fusion backend object ID is not an exact Sentinel ARM resource ID: %q", objectID)
	}
	token, err := credential.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{"https://management.azure.com/.default"}})
	if err != nil {
		t.Fatal("scanner EnvironmentCredential could not obtain an ARM token for provenance verification")
	}
	var installed struct {
		Properties struct {
			AlertRuleTemplateName string `json:"alertRuleTemplateName"`
			TemplateVersion       string `json:"templateVersion"`
		} `json:"properties"`
	}
	armGetSentinelJSON(ctx, t, token.Token,
		"https://management.azure.com"+objectID+"?api-version=2025-09-01", &installed,
		"installed Fusion rule provenance")

	contentBase := objectID[:segment] + "/providers/Microsoft.SecurityInsights/"
	alertTemplates := readSentinelARMIdentities[sentinelAlertTemplateIdentity](ctx, t, token.Token,
		"https://management.azure.com"+contentBase+"alertRuleTemplates?api-version=2025-09-01",
		"alert-rule-template provenance inventory")
	contentTemplates := readSentinelARMIdentities[sentinelContentTemplateIdentity](ctx, t, token.Token,
		"https://management.azure.com"+contentBase+"contentTemplates?api-version=2025-09-01",
		"Content Hub template provenance inventory")
	installedPackages := readSentinelARMIdentities[sentinelContentPackageIdentity](ctx, t, token.Token,
		"https://management.azure.com"+contentBase+"contentPackages?api-version=2025-09-01",
		"installed Content Hub package provenance inventory")
	if len(installedPackages) != 0 {
		t.Fatalf("installed Content Hub package inventory contains %d identities, want the exact empty fixture", len(installedPackages))
	}

	expectation := sentinelRawProvenance{
		templateID:               strings.TrimSpace(installed.Properties.AlertRuleTemplateName),
		installedTemplateVersion: strings.TrimSpace(installed.Properties.TemplateVersion),
	}
	if expectation.templateID == "" || expectation.installedTemplateVersion == "" {
		t.Log("pending positive-provenance fixture: BuiltInFusion does not expose an exact native template ID and installed version")
		return expectation
	}
	matchingAlertTemplates := 0
	for _, item := range alertTemplates {
		if !sentinelIdentityMatches(expectation.templateID, item.ID, item.Name) {
			continue
		}
		matchingAlertTemplates++
		expectation.currentTemplateVersion = strings.TrimSpace(item.Properties.Version)
	}
	if matchingAlertTemplates > 1 {
		t.Fatalf("alert-rule-template inventory contains %d exact identities for the Fusion template", matchingAlertTemplates)
	}
	if matchingAlertTemplates != 1 || expectation.currentTemplateVersion == "" {
		t.Log("pending positive-provenance fixture: exact current BuiltInFusion template version metadata is absent")
	} else {
		expectation.templateReady = true
	}

	matchingContentTemplates := 0
	for _, item := range contentTemplates {
		if !sentinelIdentityMatches(expectation.templateID, item.ID, item.Name, item.Properties.ContentID) {
			continue
		}
		matchingContentTemplates++
		expectation.packageID = strings.TrimSpace(item.Properties.PackageID)
	}
	if matchingContentTemplates > 1 {
		t.Fatalf("Content Hub template inventory contains %d exact identities for the Fusion template", matchingContentTemplates)
	}
	if expectation.packageID != "" {
		var product sentinelProductPackageIdentity
		expectation.productPackageFound = armGetOptionalSentinelJSON(ctx, t, token.Token,
			"https://management.azure.com"+contentBase+"contentProductPackages/"+url.PathEscape(expectation.packageID)+"?api-version=2025-09-01",
			&product, "linked Content Hub product package")
		if expectation.productPackageFound &&
			!sentinelIdentityMatches(expectation.packageID, product.ID, product.Name, product.Properties.ContentID) {
			t.Fatal("linked Content Hub product package returned a mismatched identity")
		}
	}
	return expectation
}

func armGetSentinelJSON(ctx context.Context, t *testing.T, token, target string, output any, label string) {
	t.Helper()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		t.Fatalf("create %s request: %v", label, err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("read %s: %v", label, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("%s returned HTTP %d", label, response.StatusCode)
	}
	if err := json.NewDecoder(response.Body).Decode(output); err != nil {
		t.Fatalf("decode %s: %v", label, err)
	}
}

func armGetOptionalSentinelJSON(ctx context.Context, t *testing.T, token, target string, output any, label string) bool {
	t.Helper()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		t.Fatalf("create %s request: %v", label, err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("read %s: %v", label, err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return false
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("%s returned HTTP %d", label, response.StatusCode)
	}
	if err := json.NewDecoder(response.Body).Decode(output); err != nil {
		t.Fatalf("decode %s: %v", label, err)
	}
	return true
}

func readSentinelARMIdentities[T any](ctx context.Context, t *testing.T, token, target, label string) []T {
	t.Helper()
	seen := make(map[string]bool)
	identities := make([]T, 0)
	for page := 0; target != ""; page++ {
		if page >= 1000 {
			t.Fatalf("%s exceeded 1000 pages", label)
		}
		if seen[target] {
			t.Fatalf("%s returned a pagination cycle", label)
		}
		seen[target] = true
		var result struct {
			Value    []T    `json:"value"`
			NextLink string `json:"nextLink"`
		}
		armGetSentinelJSON(ctx, t, token, target, &result, label)
		if len(identities)+len(result.Value) > 10000 {
			t.Fatalf("%s exceeded 10000 identities", label)
		}
		identities = append(identities, result.Value...)
		next := strings.TrimSpace(result.NextLink)
		if next == "" {
			return identities
		}
		parsed, err := url.Parse(next)
		if err != nil || !strings.EqualFold(parsed.Scheme, "https") ||
			!strings.EqualFold(parsed.Host, "management.azure.com") {
			t.Fatalf("%s returned an invalid or cross-origin nextLink", label)
		}
		target = parsed.String()
	}
	return identities
}

func sentinelIdentityMatches(want string, values ...string) bool {
	want = strings.TrimSpace(want)
	for _, value := range values {
		value = strings.TrimSpace(value)
		if strings.EqualFold(want, value) || strings.EqualFold(want, sentinelResourceName(value)) {
			return true
		}
	}
	return false
}

func sentinelResourceName(id string) string {
	id = strings.TrimRight(strings.TrimSpace(id), "/")
	if index := strings.LastIndex(id, "/"); index >= 0 {
		return id[index+1:]
	}
	return id
}

func requiredSentinelEnv(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("%s is required for Sentinel integration tests", name)
	}
	return value
}

func sentinelRulesByID(rules []backend.Rule) map[string]backend.Rule {
	out := make(map[string]backend.Rule, len(rules))
	for _, rule := range rules {
		out[rule.ID] = rule
	}
	return out
}

func sentinelSourcesByName(sources []backend.Source) map[string]backend.Source {
	out := make(map[string]backend.Source, len(sources))
	for _, source := range sources {
		out[source.Name] = source
	}
	return out
}

func requireSentinelRule(t *testing.T, rules map[string]backend.Rule, id string) backend.Rule {
	t.Helper()
	rule, ok := rules[id]
	if !ok {
		t.Fatalf("Sentinel rule inventory does not contain fixture %s", id)
	}
	return rule
}

func requireSentinelSources(t *testing.T, sources map[string]backend.Source, names ...string) []backend.Source {
	t.Helper()
	out := make([]backend.Source, 0, len(names))
	for _, name := range names {
		source, ok := sources[name]
		if !ok {
			t.Fatalf("table inventory does not contain fixture %s", name)
		}
		out = append(out, source)
	}
	return out
}

func assertSentinelRuleInventory(t *testing.T, rules map[string]backend.Rule, remoteWorkspace string) {
	t.Helper()
	scheduled := requireSentinelRule(t, rules, sentinelFreshRuleID)
	if scheduled.RuleType != "scheduled" || fmt.Sprint(scheduled.Patterns) != "["+sentinelFreshTable+"]" {
		t.Errorf("scheduled rule = %+v", scheduled)
	}
	nrt := requireSentinelRule(t, rules, sentinelNRTRuleID)
	if nrt.RuleType != "nrt" || nrt.Interval != time.Minute || nrt.Lookback != time.Minute ||
		nrt.TimestampOverride != "ingestion_time()" || nrt.Enabled ||
		nrt.Name != "deadair lab - nrt dependency" || nrt.Severity != "low" {
		t.Errorf("NRT rule = %+v", nrt)
	}
	for _, id := range []string{sentinelFunctionBareID, sentinelFunctionCallID} {
		function := requireSentinelRule(t, rules, id)
		if fmt.Sprint(function.Patterns) != "["+sentinelFreshTable+"]" || function.InputStatus != "" {
			t.Errorf("workspace-function rule = %+v", function)
		}
	}
	parameterized := requireSentinelRule(t, rules, sentinelParameterizedID)
	if fmt.Sprint(parameterized.Patterns) != "["+sentinelFreshTable+"]" || parameterized.InputStatus != "" {
		t.Errorf("parameterized function rule = %+v, want resolved %s input", parameterized, sentinelFreshTable)
	}
	for _, id := range []string{sentinelStaleRuleID, sentinelLagRuleID, sentinelLetJoinRuleID, sentinelEmptyAnalyticsID} {
		requireSentinelRule(t, rules, id)
	}
	fusion := requireSentinelRule(t, rules, "BuiltInFusion")
	if fusion.RuleType != "fusion" || fusion.Name != "Advanced Multistage Attack Detection" || !fusion.Enabled {
		t.Errorf("BuiltInFusion rule = %+v, want exact enabled Fusion provenance fixture", fusion)
	}
	assertExpansion := func(id, name string) backend.Rule {
		t.Helper()
		rule := requireSentinelRule(t, rules, id)
		if rule.RuleType != "scheduled" || rule.Enabled || rule.Name != name || rule.Severity != "low" ||
			rule.Interval != 5*time.Minute || rule.Lookback != 30*time.Minute {
			t.Errorf("disabled expansion rule %s = %+v", id, rule)
		}
		return rule
	}
	watchlist := assertExpansion(sentinelWatchlistRuleID, "deadair expansion - literal watchlist dependency")
	if len(watchlist.Dependencies) != 1 || watchlist.InputStatus != "" ||
		watchlist.Dependencies[0].Kind != "sentinel_watchlist" ||
		watchlist.Dependencies[0].Name != sentinelWatchlistAlias || !watchlist.Dependencies[0].Required {
		t.Errorf("watchlist expansion inventory = %+v", watchlist)
	}
	asim := assertExpansion(sentinelASIMRuleID, "deadair expansion - native ASIM dependency")
	if len(asim.Dependencies) != 1 || asim.InputStatus != "" ||
		asim.Dependencies[0].Kind != "sentinel_asim_parser" || asim.Dependencies[0].Name != "_Im_Authentication" ||
		asim.Dependencies[0].Expression != `_Im_Authentication(starttime=ago(1d),endtime=now())` ||
		!asim.Dependencies[0].Required {
		t.Errorf("ASIM expansion inventory = %+v", asim)
	}
	remote := assertExpansion(sentinelRemoteRuleID, "deadair expansion - remote workspace dependency")
	if len(remote.Dependencies) != 1 || remote.InputStatus != "" ||
		remote.Dependencies[0].Kind != "sentinel_workspace_table" || remote.Dependencies[0].Name != sentinelRemoteTable ||
		remote.Dependencies[0].Scope != remoteWorkspace || !remote.Dependencies[0].Monitorable ||
		!remote.Dependencies[0].Required {
		t.Errorf("remote expansion inventory = %+v", remote)
	}
	summaryConsumer := assertExpansion(sentinelSummaryRuleID, "deadair expansion - summary table consumer")
	if summaryConsumer.InputStatus != "" || fmt.Sprint(summaryConsumer.Patterns) != "["+sentinelSummaryTable+"]" {
		t.Errorf("summary-consumer expansion inventory = %+v", summaryConsumer)
	}
}

func assertSentinelResolutions(t *testing.T, resolutions []backend.InputResolution, remoteSource, remoteScope string) {
	t.Helper()
	type evidenceKey struct {
		ruleID     string
		selector   string
		diagnostic bool
	}
	byKey := make(map[evidenceKey]backend.InputResolution, len(resolutions))
	for _, resolution := range resolutions {
		byKey[evidenceKey{resolution.RuleID, resolution.Selector, resolution.Diagnostic}] = resolution
	}
	assert := func(ruleID, selector string, diagnostic bool, status backend.ResolutionStatus, sources ...string) {
		t.Helper()
		got, ok := byKey[evidenceKey{ruleID, selector, diagnostic}]
		if !ok {
			t.Errorf("missing resolution for rule=%s selector=%s diagnostic=%t", ruleID, selector, diagnostic)
			return
		}
		if got.Status != status {
			t.Errorf("resolution for rule=%s selector=%s diagnostic=%t is %s, want %s: %s",
				ruleID, selector, diagnostic, got.Status, status, got.Detail)
		}
		gotSources := append([]string(nil), got.ResolvedSources...)
		sort.Strings(gotSources)
		sort.Strings(sources)
		if fmt.Sprint(gotSources) != fmt.Sprint(sources) {
			t.Errorf("resolved sources for rule=%s selector=%s = %v, want %v", ruleID, selector, gotSources, sources)
		}
	}

	assert(sentinelFreshRuleID, "", false, backend.ResolutionResolved, sentinelFreshTable)
	assert(sentinelMissingRuleID, "", false, backend.ResolutionEmpty)
	assert(sentinelMissingRuleID, sentinelMissingTable, true, backend.ResolutionEmpty)
	assert(sentinelPartialRuleID, "", false, backend.ResolutionResolved, sentinelFreshTable)
	assert(sentinelPartialRuleID, sentinelFreshTable, true, backend.ResolutionResolved, sentinelFreshTable)
	assert(sentinelPartialRuleID, sentinelMissingTable, true, backend.ResolutionEmpty)
	assert(sentinelLetJoinRuleID, "", false, backend.ResolutionResolved, sentinelFreshTable, sentinelLagTable)
	assert(sentinelFunctionBareID, "", false, backend.ResolutionResolved, sentinelFreshTable)
	assert(sentinelFunctionCallID, "", false, backend.ResolutionResolved, sentinelFreshTable)
	assert(sentinelParameterizedID, "", false, backend.ResolutionResolved, sentinelFreshTable)
	assert(sentinelNRTRuleID, "", false, backend.ResolutionResolved, sentinelFreshTable)
	assert(sentinelAuxiliaryRuleID, "", false, backend.ResolutionIncompatible)
	assert(sentinelAuxiliaryRuleID, sentinelAuxiliaryTable, true, backend.ResolutionIncompatible)
	assert(sentinelEmptyAnalyticsID, "", false, backend.ResolutionResolved, sentinelEmptyAnalyticsTable)
	assert("deadair-live-basic-plan", "", false, backend.ResolutionIncompatible)
	assert("deadair-live-basic-plan", sentinelBasicTable, true, backend.ResolutionIncompatible)
	assert(sentinelWatchlistRuleID, "", false, backend.ResolutionUnsupported)
	assert(sentinelWatchlistRuleID, sentinelWatchlistAlias, true, backend.ResolutionResolved)
	assert(sentinelASIMRuleID, "", false, backend.ResolutionUnsupported)
	assert(sentinelASIMRuleID, "_Im_Authentication", true, backend.ResolutionUnsupported)
	assert(sentinelRemoteRuleID, "", false, backend.ResolutionResolved, remoteSource)
	assert(sentinelRemoteRuleID, "workspace('"+remoteScope+"')."+sentinelRemoteTable, true, backend.ResolutionResolved, remoteSource)
	assert(sentinelSummaryRuleID, "", false, backend.ResolutionResolved, sentinelSummaryTable)
}

func assertSentinelDependencyEvidence(t *testing.T, resolutions []backend.InputResolution, remoteSource string) {
	t.Helper()
	var watchlist, remote bool
	for _, resolution := range resolutions {
		if !resolution.Diagnostic || resolution.Status != backend.ResolutionResolved {
			continue
		}
		for _, dependency := range resolution.ResolvedDependencies {
			switch {
			case resolution.RuleID == sentinelWatchlistRuleID && dependency.Kind == "sentinel_watchlist" &&
				dependency.Name == sentinelWatchlistAlias && dependency.Expression == "":
				watchlist = true
			case resolution.RuleID == sentinelRemoteRuleID && dependency.Kind == "sentinel_workspace_table" &&
				dependency.ID == remoteSource && dependency.Monitorable:
				remote = true
			}
		}
	}
	if !watchlist {
		t.Error("resolved watchlist dependency evidence is missing")
	}
	if !remote {
		t.Error("resolved remote-workspace dependency evidence is missing")
	}
}

func assertSentinelSummaryLineage(t *testing.T, evidence []backend.LineageEvidence, resolutions []backend.InputResolution) {
	t.Helper()
	for _, item := range evidence {
		if item.Kind == "sentinel_summary_rule" && item.Name == sentinelSummaryRule &&
			item.Input.Name == sentinelBasicTable && item.Output.Name == sentinelSummaryTable {
			if item.Status != backend.EvidenceAssessed || item.Input.Kind != "telemetry_table" ||
				item.Output.Kind != "telemetry_table" || item.Method != "arm-summary-rule-kql" {
				t.Fatalf("summary lineage = %+v, want assessed Basic-to-Analytics structural evidence", item)
			}
			for _, resolution := range resolutions {
				if resolution.RuleID == sentinelSummaryRuleID && !resolution.Diagnostic &&
					resolution.Status == backend.ResolutionResolved &&
					fmt.Sprint(resolution.ResolvedSources) == "["+item.Output.Name+"]" {
					return
				}
			}
			t.Fatalf("summary output %s is not the resolved input of downstream rule %s",
				item.Output.Name, sentinelSummaryRuleID)
		}
	}
	t.Fatalf("summary lineage does not contain %s -> %s: %+v", sentinelBasicTable, sentinelSummaryTable, evidence)
}

func assertSentinelEmptyContentHubPath(t *testing.T, evidence []backend.ProvenanceEvidence, expected sentinelRawProvenance) {
	t.Helper()
	templateSeen := false
	packageSeen := false
	for _, item := range evidence {
		if item.Provenance.Kind == "sentinel_content_hub" && item.Status == backend.EvidenceUnavailable {
			t.Fatalf("Content Hub inventory was unavailable, so an empty association is not proven: %+v", item)
		}
		if item.RuleID == "BuiltInFusion" && item.Provenance.Kind == "sentinel_content_package" {
			if expected.packageID == "" {
				t.Fatalf("raw Content Hub inventories contain no exact Fusion package link, but package provenance was produced: %+v", item)
			}
			if item.Provenance.ID != expected.packageID || item.Method != "arm-content-hub-package" ||
				item.Status != backend.EvidenceIncomplete || item.Detail != "linked Content Hub package is not installed" {
				t.Fatalf("Fusion package provenance does not match the raw uninstalled link %q: %+v", expected.packageID, item)
			}
			packageSeen = true
		}
		if item.RuleID != "BuiltInFusion" || item.Provenance.Kind != "sentinel_alert_rule_template" {
			continue
		}
		if item.Status == backend.EvidenceUnavailable {
			t.Fatalf("native Fusion template provenance was unavailable: %+v", item)
		}
		if !expected.templateReady {
			continue
		}
		expectedDetail := "installed version " + expected.installedTemplateVersion + "; current"
		if expected.installedTemplateVersion != expected.currentTemplateVersion {
			expectedDetail = "installed version " + expected.installedTemplateVersion + "; current version " + expected.currentTemplateVersion
		}
		if item.Method == "arm-alert-rule-template" && item.Status == backend.EvidenceAssessed &&
			item.Provenance.ID == expected.templateID && item.Detail == expectedDetail {
			templateSeen = true
		}
	}
	if expected.packageID != "" && !packageSeen {
		t.Fatalf("raw Content Hub template links Fusion to uninstalled package %q, but matching provenance is absent (product metadata present=%t): %+v",
			expected.packageID, expected.productPackageFound, evidence)
	}
	if !expected.templateReady {
		t.Log("positive native-template provenance remains pending; narrow raw Content Hub identities and the empty installed-package inventory were verified separately")
		return
	}
	if !templateSeen {
		t.Fatalf("native Fusion template provenance does not match exact template %q at installed version %q: %+v",
			expected.templateID, expected.installedTemplateVersion, evidence)
	}
}
