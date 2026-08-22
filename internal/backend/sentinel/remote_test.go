package sentinel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/alephnull-sh/deadair/internal/backend"
)

func TestParseRemoteWorkspacesIsStrict(t *testing.T) {
	data := []byte(`[{"alias":"soc","azure_subscription_id":"sub","azure_resource_group":"rg","sentinel_workspace":"law"}]`)
	remotes, err := ParseRemoteWorkspaces(data)
	if err != nil || len(remotes) != 1 || remotes[0].Alias != "soc" {
		t.Fatalf("ParseRemoteWorkspaces() = %+v, %v", remotes, err)
	}
	for _, malformed := range [][]byte{
		[]byte(`[{"alias":"soc","azure_subscription_id":"sub","azure_resource_group":"rg","sentinel_workspace":"law","typo":true}]`),
		[]byte(`[] {}`),
	} {
		if _, err := ParseRemoteWorkspaces(malformed); err == nil {
			t.Fatalf("ParseRemoteWorkspaces(%s) accepted malformed input", malformed)
		}
	}
}

func TestNormalizeRemoteWorkspacesRejectsAmbiguousMappings(t *testing.T) {
	base := RemoteWorkspace{Alias: "soc", SubscriptionID: "sub-remote", ResourceGroup: "rg", WorkspaceName: "law", WorkspaceID: "11111111-1111-1111-1111-111111111111"}
	if _, err := normalizeRemoteWorkspaces("sub-home", "rg", "home", []RemoteWorkspace{base, base}); err == nil {
		t.Fatal("duplicate remote mapping was accepted")
	}
	home := RemoteWorkspace{Alias: "home", SubscriptionID: "SUB-HOME", ResourceGroup: "RG", WorkspaceName: "HOME"}
	if _, err := normalizeRemoteWorkspaces("sub-home", "rg", "home", []RemoteWorkspace{home}); err == nil {
		t.Fatal("home workspace was accepted as a remote mapping")
	}
}

func TestQualifiedRemoteSourceKeepsLocalAndRemoteTablesDistinct(t *testing.T) {
	resourceID := canonicalWorkspaceResourceID("Sub-A", "RG-A", "LAW-A")
	qualified := qualifiedRemoteSource(resourceID, "SecurityEvent")
	if qualified == "SecurityEvent" {
		t.Fatal("qualified remote source collided with the local table name")
	}
	gotResource, gotTable, ok := parseQualifiedRemoteSource(qualified)
	if !ok || gotResource != resourceID || gotTable != "SecurityEvent" {
		t.Fatalf("parseQualifiedRemoteSource(%q) = %q, %q, %t", qualified, gotResource, gotTable, ok)
	}
}

func TestNormalizeWorkspaceLocation(t *testing.T) {
	for _, raw := range []string{"North Europe", " north  europe ", "NORTHEUROPE", "\tNorth Europe\n"} {
		if got, ok := normalizeWorkspaceLocation(raw); !ok || got != "northeurope" {
			t.Fatalf("normalizeWorkspaceLocation(%q) = %q, %t", raw, got, ok)
		}
	}
	if got, ok := normalizeWorkspaceLocation(" \t\n "); ok || got != "" {
		t.Fatalf("empty location = %q, %t", got, ok)
	}
}

func TestSentinelRuleDefersLiteralWorkspaceResolution(t *testing.T) {
	rule := sentinelRule(testAlertRule("remote-rule", `SecurityEvent | join (workspace('soc').SecurityEvent) on Computer`), nil, true)
	if rule.InputStatus != "" || len(rule.Dependencies) != 1 {
		t.Fatalf("literal workspace rule = %+v", rule)
	}
	dependency := rule.Dependencies[0]
	if dependency.Kind != "sentinel_workspace_table" || dependency.Scope != "soc" || dependency.Name != "SecurityEvent" || !dependency.Monitorable || !dependency.Required {
		t.Fatalf("literal workspace dependency = %+v", dependency)
	}

	unsupported := sentinelRule(testAlertRule("app-rule", `app('app-id').SecurityEvent | take 1`), nil, true)
	if unsupported.InputStatus != backend.ResolutionRemote || len(unsupported.Dependencies) != 1 || unsupported.Dependencies[0].Monitorable {
		t.Fatalf("app() dependency became assessable: %+v", unsupported)
	}
}

func TestResolveInputsAssessesMappedLiteralWorkspace(t *testing.T) {
	const remoteWorkspaceID = "11111111-1111-1111-1111-111111111111"
	remoteResourceID := canonicalWorkspaceResourceID("remote-sub", "remote-rg", "remote-law")
	credential := &recordingCredential{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == remoteResourceID:
			fmt.Fprintf(w, `{"id":%q,"location":"remote-region","properties":{"customerId":%q}}`, remoteResourceID, remoteWorkspaceID)
		case r.URL.Path == remoteOnboardingResourceID(remoteResourceID):
			writeRemoteOnboarding(w, remoteResourceID)
		case r.URL.Path == remoteResourceID+"/tables":
			fmt.Fprint(w, `{"value":[{"name":"SecurityEvent","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"standardColumns":[{"name":"TimeGenerated","type":"datetime"}]}}}]}`)
		case strings.HasSuffix(r.URL.Path, "/tables"):
			fmt.Fprint(w, `{"value":[{"name":"SecurityEvent","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"standardColumns":[{"name":"TimeGenerated","type":"datetime"}]}}}]}`)
		case strings.HasSuffix(r.URL.Path, "/query"):
			var request logsQueryRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if strings.HasPrefix(request.Query, "workspace(") {
				result := `{"name":"PrimaryResult","columns":[],"rows":[]}`
				switch {
				case strings.Contains(request.Query, "LastEvent"):
					result = `{"name":"PrimaryResult","columns":[{"name":"LastEvent","type":"datetime"}],"rows":[["2026-08-20T12:34:56Z"]]}`
				case strings.Contains(request.Query, "project TimeGenerated, IngestionTime"):
					result = `{"name":"PrimaryResult","columns":[{"name":"TimeGenerated","type":"datetime"},{"name":"IngestionTime","type":"datetime"}],"rows":[["2026-08-20T12:34:00Z","2026-08-20T12:35:00Z"]]}`
				}
				fmt.Fprintf(w, `{"tables":[%s],"permissions":{"dataSources":[{"resourceId":%q,"allowTables":["SecurityEvent"]}]},"dataSources":[{"resourceId":%q,"tables":["SecurityEvent"]}]}`, result, remoteResourceID, remoteResourceID)
				return
			}
			writeAllowedLogsResult(w, "SecurityEvent", `[{"name":"PrimaryResult","columns":[],"rows":[]}]`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := remoteFixtureClient(server.URL, credential)
	client.RemoteWorkspaces = []RemoteWorkspace{{
		Alias: "soc", SubscriptionID: "remote-sub", ResourceGroup: "remote-rg", WorkspaceName: "remote-law", WorkspaceID: remoteWorkspaceID,
	}}
	rule := sentinelRule(testAlertRule("remote-rule", `SecurityEvent | join (workspace('soc').SecurityEvent) on Computer`), nil, true)
	resolutions, err := client.ResolveInputs(context.Background(), []backend.Rule{rule})
	if err != nil {
		t.Fatal(err)
	}
	if len(resolutions) != 3 {
		t.Fatalf("resolutions = %+v", resolutions)
	}
	qualified := qualifiedRemoteSource(remoteResourceID, "SecurityEvent")
	if resolutions[0].Status != backend.ResolutionResolved || fmt.Sprint(resolutions[0].ResolvedSources) != fmt.Sprintf("[SecurityEvent %s]", qualified) {
		t.Fatalf("authoritative remote resolution = %+v", resolutions[0])
	}
	if len(resolutions[0].ResolvedDependencies) != 1 || resolutions[0].ResolvedDependencies[0].ID != qualified {
		t.Fatalf("resolved remote dependency = %+v", resolutions[0].ResolvedDependencies)
	}
	if resolutions[2].Selector == "SecurityEvent" || fmt.Sprint(resolutions[2].ResolvedSources) != "["+qualified+"]" {
		t.Fatalf("remote diagnostic collided with local source: %+v", resolutions[2])
	}
	schemas, err := client.Schemas(context.Background(), []backend.Source{{Name: qualified}})
	if err != nil || schemas[qualified].Source != qualified || len(schemas[qualified].Fields) != 1 {
		t.Fatalf("remote schema = %+v, %v", schemas[qualified], err)
	}
	freshness, err := client.FreshnessEvidence(context.Background(), []backend.Source{{Name: qualified}})
	if err != nil || freshness[qualified].Status != backend.EvidenceAssessed || freshness[qualified].LastEvent.IsZero() {
		t.Fatalf("remote freshness = %+v, %v", freshness[qualified], err)
	}
	lag, err := client.IngestLagEvidence(context.Background(), []backend.Source{{Name: qualified}})
	if err != nil || lag[qualified].Status != backend.EvidenceAssessed || lag[qualified].P95 != time.Minute {
		t.Fatalf("remote ingest lag = %+v, %v", lag[qualified], err)
	}
}

func TestSourcesInventoriesOnlyRemoteMappingsReferencedByActiveRules(t *testing.T) {
	const usedWorkspaceID = "11111111-1111-1111-1111-111111111111"
	const unusedWorkspaceID = "22222222-2222-2222-2222-222222222222"
	usedResourceID := canonicalWorkspaceResourceID("used-sub", "used-rg", "used-law")
	unusedResourceID := canonicalWorkspaceResourceID("unused-sub", "unused-rg", "unused-law")
	var usedWorkspaceCalls, usedOnboardingCalls, usedTableCalls atomic.Int32
	var unusedCalls, logsCalls atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/metadata"):
			fmt.Fprint(w, `{"functions":[]}`)
		case strings.HasSuffix(r.URL.Path, "/alertRules"):
			if r.URL.Query().Get("api-version") == alertRulesAPIVersion {
				fmt.Fprint(w, `{"value":[{"id":"/rules/remote","name":"remote","kind":"Scheduled","properties":{"enabled":true,"query":"workspace('used').RemoteTable | take 1","queryFrequency":"PT5M","queryPeriod":"PT10M"}}]}`)
				return
			}
			fmt.Fprint(w, `{"value":[]}`)
		case r.URL.Path == usedResourceID:
			usedWorkspaceCalls.Add(1)
			fmt.Fprintf(w, `{"id":%q,"location":"used-region","properties":{"customerId":%q}}`, usedResourceID, usedWorkspaceID)
		case r.URL.Path == remoteOnboardingResourceID(usedResourceID):
			usedOnboardingCalls.Add(1)
			writeRemoteOnboarding(w, usedResourceID)
		case r.URL.Path == usedResourceID+"/tables":
			usedTableCalls.Add(1)
			fmt.Fprint(w, `{"value":[{"name":"RemoteTable","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"standardColumns":[]}}}]}`)
		case r.URL.Path == unusedResourceID || r.URL.Path == remoteOnboardingResourceID(unusedResourceID) || r.URL.Path == unusedResourceID+"/tables":
			unusedCalls.Add(1)
			http.Error(w, "unused mapping was contacted", http.StatusInternalServerError)
		case strings.HasSuffix(r.URL.Path, "/tables"):
			fmt.Fprint(w, `{"value":[{"name":"LocalTable","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"standardColumns":[]}}}]}`)
		case strings.HasSuffix(r.URL.Path, "/query"):
			logsCalls.Add(1)
			http.Error(w, "Sources must not query Logs", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := fixtureClient(server.URL, &recordingCredential{})
	client.RemoteWorkspaces = []RemoteWorkspace{
		{Alias: "used", SubscriptionID: "used-sub", ResourceGroup: "used-rg", WorkspaceName: "used-law", WorkspaceID: usedWorkspaceID},
		{Alias: "unused", SubscriptionID: "unused-sub", ResourceGroup: "unused-rg", WorkspaceName: "unused-law", WorkspaceID: unusedWorkspaceID},
	}
	rules, err := client.Rules(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || !rules[0].Enabled || len(rules[0].Dependencies) != 1 || rules[0].Dependencies[0].Scope != "used" {
		t.Fatalf("remote rule inventory = %+v", rules)
	}
	sources, err := client.Sources(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	wantRemote := qualifiedRemoteSource(usedResourceID, "RemoteTable")
	if len(sources) != 2 || sources[0].Name != "LocalTable" || sources[1].Name != wantRemote {
		t.Fatalf("rule-scoped sources = %+v, want LocalTable and %s", sources, wantRemote)
	}
	if usedWorkspaceCalls.Load() != 1 || usedOnboardingCalls.Load() != 1 || usedTableCalls.Load() != 1 {
		t.Fatalf("used remote calls workspace/onboarding/tables = %d/%d/%d",
			usedWorkspaceCalls.Load(), usedOnboardingCalls.Load(), usedTableCalls.Load())
	}
	if unusedCalls.Load() != 0 || logsCalls.Load() != 0 {
		t.Fatalf("unused remote calls = %d, Logs calls = %d", unusedCalls.Load(), logsCalls.Load())
	}
}

func TestAmbiguousNativeWorkspaceIDDoesNotProbeRemoteMappings(t *testing.T) {
	const workspaceID = "33333333-3333-3333-3333-333333333333"
	var remoteCalls, logsCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/tables") && strings.Contains(r.URL.Path, "/workspaces/law-lab/"):
			fmt.Fprint(w, `{"value":[]}`)
		case strings.HasSuffix(r.URL.Path, "/query"):
			logsCalls.Add(1)
			http.Error(w, "unexpected query", http.StatusInternalServerError)
		default:
			remoteCalls.Add(1)
			http.Error(w, "ambiguous mapping was contacted", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	client := fixtureClient(server.URL, &recordingCredential{})
	client.RemoteWorkspaces = []RemoteWorkspace{
		{Alias: "one", SubscriptionID: "one-sub", ResourceGroup: "one-rg", WorkspaceName: "one-law"},
		{Alias: "two", SubscriptionID: "two-sub", ResourceGroup: "two-rg", WorkspaceName: "two-law"},
	}
	rule := backend.Rule{ID: "ambiguous", Enabled: true, Dependencies: []backend.DependencyRef{{
		Name: "SecurityEvent", Kind: "sentinel_workspace_table", Scope: workspaceID, Monitorable: true, Required: true,
	}}}
	resolutions, err := client.ResolveInputs(context.Background(), []backend.Rule{rule})
	if err != nil {
		t.Fatal(err)
	}
	if len(resolutions) != 2 || resolutions[0].Status != backend.ResolutionRemote ||
		resolutions[1].Status != backend.ResolutionRemote {
		t.Fatalf("ambiguous native workspace ID = %+v", resolutions)
	}
	if remoteCalls.Load() != 0 || logsCalls.Load() != 0 {
		t.Fatalf("ambiguous mapping calls remote/Logs = %d/%d", remoteCalls.Load(), logsCalls.Load())
	}
}

func TestResolveInputsKeepsCrossSubscriptionEvidenceButFailsClosedForExecutionIdentity(t *testing.T) {
	const remoteWorkspaceID = "11111111-1111-1111-1111-111111111111"
	remoteResourceID := canonicalWorkspaceResourceID("remote-sub", "remote-rg", "remote-law")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == remoteResourceID:
			fmt.Fprintf(w, `{"id":%q,"location":"remote-region","properties":{"customerId":%q}}`, remoteResourceID, remoteWorkspaceID)
		case r.URL.Path == remoteOnboardingResourceID(remoteResourceID):
			writeRemoteOnboarding(w, remoteResourceID)
		case r.URL.Path == remoteResourceID+"/tables":
			fmt.Fprint(w, `{"value":[{"name":"SecurityEvent","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"standardColumns":[]}}}]}`)
		case strings.HasSuffix(r.URL.Path, "/tables"):
			fmt.Fprint(w, `{"value":[]}`)
		case strings.HasSuffix(r.URL.Path, "/query"):
			fmt.Fprintf(w, `{"tables":[{"name":"PrimaryResult","columns":[],"rows":[]}],"permissions":{"dataSources":[{"resourceId":%q,"allowTables":["SecurityEvent"]}]},"dataSources":[{"resourceId":%q,"tables":["SecurityEvent"]}]}`, remoteResourceID, remoteResourceID)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := remoteFixtureClient(server.URL, &recordingCredential{})
	client.SubscriptionID = "home-sub"
	client.RemoteWorkspaces = []RemoteWorkspace{{
		Alias: "soc", SubscriptionID: "remote-sub", ResourceGroup: "remote-rg", WorkspaceName: "remote-law", WorkspaceID: remoteWorkspaceID,
	}}
	rule := backend.Rule{ID: "cross-sub", Enabled: true, Dependencies: []backend.DependencyRef{
		{Name: "SecurityEvent", Kind: "sentinel_workspace_table", Scope: "soc", Monitorable: true, Required: true},
		{Name: "SecurityEvent", Kind: "sentinel_workspace_table", Scope: remoteWorkspaceID, Monitorable: true, Required: true},
	}}
	resolutions, err := client.ResolveInputs(context.Background(), []backend.Rule{rule})
	if err != nil {
		t.Fatal(err)
	}
	if len(resolutions) != 4 {
		t.Fatalf("cross-subscription resolutions = %+v", resolutions)
	}
	if resolutions[0].Status != backend.ResolutionUnavailable || len(resolutions[0].ResolvedSources) != 0 {
		t.Fatalf("cross-subscription authoritative resolution = %+v", resolutions[0])
	}
	qualified := qualifiedRemoteSource(remoteResourceID, "SecurityEvent")
	for _, resolution := range resolutions[1:3] {
		if !resolution.Diagnostic || resolution.Status != backend.ResolutionResolved || fmt.Sprint(resolution.ResolvedSources) != "["+qualified+"]" {
			t.Fatalf("scanner-positive remote diagnostic = %+v", resolution)
		}
	}
	identity := resolutions[3]
	if !identity.Diagnostic || identity.Status != backend.ResolutionUnavailable ||
		identity.SelectorKind != "sentinel_rule_execution_identity" ||
		identity.ResolutionMethod != "sentinel_rule_execution_identity_diagnostic" ||
		!strings.Contains(identity.Detail, "creator's credentials") || !strings.Contains(identity.Detail, "SentinelHealth") {
		t.Fatalf("execution-identity diagnostic = %+v", identity)
	}
	if len(identity.ResolvedSources) != 0 || len(identity.ResolvedDependencies) != 1 {
		t.Fatalf("execution-identity evidence shape = %+v", identity)
	}
	dependency := identity.ResolvedDependencies[0]
	if dependency.ID != "sentinel_rule_execution_identity:"+remoteResourceID ||
		dependency.Scope != remoteResourceID || dependency.Kind != "sentinel_rule_execution_identity" ||
		dependency.Monitorable || !dependency.Required {
		t.Fatalf("execution-identity dependency = %+v", dependency)
	}
}

func TestResolveInputsUsesExactSentinelHealthSuccessForCrossSubscriptionExecutionIdentity(t *testing.T) {
	const remoteWorkspaceID = "11111111-1111-1111-1111-111111111111"
	remoteResourceID := canonicalWorkspaceResourceID("remote-sub", "remote-rg", "remote-law")
	now := time.Now().UTC()
	recentHealthRun := now.Add(-30 * time.Minute).Format(time.RFC3339Nano)
	var healthQueries atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == remoteResourceID:
			fmt.Fprintf(w, `{"id":%q,"location":"remote-region","properties":{"customerId":%q}}`, remoteResourceID, remoteWorkspaceID)
		case r.URL.Path == remoteOnboardingResourceID(remoteResourceID):
			writeRemoteOnboarding(w, remoteResourceID)
		case r.URL.Path == remoteResourceID+"/tables":
			fmt.Fprint(w, `{"value":[{"name":"SecurityEvent","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"standardColumns":[]}}}]}`)
		case strings.HasSuffix(r.URL.Path, "/tables"):
			fmt.Fprint(w, `{"value":[]}`)
		case strings.HasSuffix(r.URL.Path, "/query"):
			var request logsQueryRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(request.Query, "_SentinelHealth()") {
				healthQueries.Add(1)
				writeRuleHealthResult(w, fmt.Sprintf(`[[%q,"Scheduled","Success",%q]]`, ruleHealthTestResourceID, recentHealthRun))
				return
			}
			fmt.Fprintf(w, `{"tables":[{"name":"PrimaryResult","columns":[],"rows":[]}],"permissions":{"dataSources":[{"resourceId":%q,"allowTables":["SecurityEvent"]}]},"dataSources":[{"resourceId":%q,"tables":["SecurityEvent"]}]}`, remoteResourceID, remoteResourceID)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := remoteFixtureClient(server.URL, &recordingCredential{})
	client.SubscriptionID = "home-sub"
	client.RemoteWorkspaces = []RemoteWorkspace{{
		Alias: "soc", SubscriptionID: "remote-sub", ResourceGroup: "remote-rg", WorkspaceName: "remote-law", WorkspaceID: remoteWorkspaceID,
	}}
	rule := backend.Rule{
		ID: "cross-sub", BackendObjectID: ruleHealthTestResourceID, Enabled: true, RuleType: "scheduled",
		ModifiedAt: now.Add(-2 * time.Hour), Interval: time.Hour,
		Dependencies: []backend.DependencyRef{{
			Name: "SecurityEvent", Kind: "sentinel_workspace_table", Scope: remoteResourceID, Monitorable: true, Required: true,
		}},
	}
	client.setInstalledRules([]backend.Rule{rule})
	resolutions, err := client.ResolveInputs(context.Background(), []backend.Rule{rule})
	if err != nil {
		t.Fatal(err)
	}
	if healthQueries.Load() != 1 || len(resolutions) != 3 {
		t.Fatalf("health queries/resolutions = %d/%+v", healthQueries.Load(), resolutions)
	}
	if resolutions[0].Status != backend.ResolutionResolved || len(resolutions[0].ResolvedSources) != 1 {
		t.Fatalf("authoritative resolution = %+v", resolutions[0])
	}
	identity := resolutions[2]
	if identity.SelectorKind != "sentinel_rule_execution_identity" || identity.Status != backend.ResolutionResolved ||
		identity.ResolutionMethod != sentinelHealthMethod || !strings.Contains(identity.Detail, "succeeded") ||
		len(identity.ResolvedDependencies) != 1 {
		t.Fatalf("SentinelHealth identity resolution = %+v", identity)
	}
}

func TestRemoteExecutionIdentityOutcomesDeduplicateCanonicalWorkspace(t *testing.T) {
	const remoteWorkspaceID = "11111111-1111-1111-1111-111111111111"
	remote := RemoteWorkspace{
		Alias: "soc", SubscriptionID: "remote-sub", ResourceGroup: "remote-rg", WorkspaceName: "remote-law", WorkspaceID: remoteWorkspaceID,
	}
	resourceID := canonicalWorkspaceResourceID(remote.SubscriptionID, remote.ResourceGroup, remote.WorkspaceName)
	state := &remoteWorkspaceState{
		config: remote, resourceID: resourceID, validated: true, workspaceID: remoteWorkspaceID,
	}
	client := &Client{
		SubscriptionID: "home-sub",
		remoteStates: map[string]*remoteWorkspaceState{
			"alias:soc":                      state,
			"resource:" + resourceID:         state,
			"workspace:" + remoteWorkspaceID: state,
		},
	}
	rule := backend.Rule{Enabled: true, Dependencies: []backend.DependencyRef{
		{Name: "SecurityEvent", Kind: "sentinel_workspace_table", Scope: resourceID, Required: true},
		{Name: "SigninLogs", Kind: "sentinel_workspace_table", Scope: remoteWorkspaceID, Required: true},
	}}
	outcomes := client.remoteExecutionIdentityOutcomes(context.Background(), rule)
	if len(outcomes) != 1 || outcomes[0].status != backend.ResolutionUnavailable || outcomes[0].optional {
		t.Fatalf("cross-subscription execution outcomes = %+v", outcomes)
	}
	if len(outcomes[0].dependencies) != 1 || !outcomes[0].dependencies[0].Required || outcomes[0].dependencies[0].Monitorable {
		t.Fatalf("cross-subscription execution dependency = %+v", outcomes[0].dependencies)
	}
	status, _, sources := aggregateRuleResolution(append([]sentinelSelectorOutcome{{
		status: backend.ResolutionResolved, sources: []string{qualifiedRemoteSource(resourceID, "SecurityEvent")},
	}}, outcomes...))
	if status != backend.ResolutionUnavailable || len(sources) != 0 {
		t.Fatalf("execution uncertainty did not suppress authoritative graph sources: status=%s sources=%v", status, sources)
	}

	client.SubscriptionID = " REMOTE-SUB "
	if outcomes := client.remoteExecutionIdentityOutcomes(context.Background(), rule); len(outcomes) != 0 {
		t.Fatalf("same-subscription workspace was treated as execution-identity uncertainty: %+v", outcomes)
	}
}

func TestRemoteExecutionIdentityPreservesOptionalRequiredness(t *testing.T) {
	remote := RemoteWorkspace{
		SubscriptionID: "remote-sub", ResourceGroup: "remote-rg", WorkspaceName: "remote-law",
	}
	resourceID := canonicalWorkspaceResourceID(remote.SubscriptionID, remote.ResourceGroup, remote.WorkspaceName)
	state := &remoteWorkspaceState{config: remote, resourceID: resourceID, validated: true}
	client := &Client{
		SubscriptionID: "home-sub",
		remoteStates: map[string]*remoteWorkspaceState{
			"resource:" + resourceID: state,
		},
	}
	optionalRule := backend.Rule{Enabled: true, Dependencies: []backend.DependencyRef{{
		Name: "SecurityEvent", Kind: "sentinel_workspace_table", Scope: resourceID,
	}}}
	outcomes := client.remoteExecutionIdentityOutcomes(context.Background(), optionalRule)
	if len(outcomes) != 1 || !outcomes[0].optional || len(outcomes[0].dependencies) != 1 || outcomes[0].dependencies[0].Required {
		t.Fatalf("optional execution identity = %+v", outcomes)
	}

	mixedRule := optionalRule
	mixedRule.Dependencies = append(mixedRule.Dependencies, backend.DependencyRef{
		Name: "SigninLogs", Kind: "sentinel_workspace_table", Scope: resourceID, Required: true,
	})
	outcomes = client.remoteExecutionIdentityOutcomes(context.Background(), mixedRule)
	if len(outcomes) != 1 || outcomes[0].optional || !outcomes[0].dependencies[0].Required {
		t.Fatalf("mixed required execution identity = %+v", outcomes)
	}
}

func TestResolveInputsFailsClosedForUnmappedMissingAndDeniedRemote(t *testing.T) {
	const remoteWorkspaceID = "11111111-1111-1111-1111-111111111111"
	remoteResourceID := canonicalWorkspaceResourceID("remote-sub", "remote-rg", "remote-law")
	credential := &recordingCredential{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == remoteResourceID:
			fmt.Fprintf(w, `{"id":%q,"location":"remote-region","properties":{"customerId":%q}}`, remoteResourceID, remoteWorkspaceID)
		case r.URL.Path == remoteOnboardingResourceID(remoteResourceID):
			writeRemoteOnboarding(w, remoteResourceID)
		case r.URL.Path == remoteResourceID+"/tables":
			fmt.Fprint(w, `{"value":[{"name":"DeniedTable","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"standardColumns":[]}}}]}`)
		case strings.HasSuffix(r.URL.Path, "/tables"):
			fmt.Fprint(w, `{"value":[]}`)
		case strings.HasSuffix(r.URL.Path, "/query"):
			var request logsQueryRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if strings.HasPrefix(request.Query, "workspace('soc').DeniedTable") {
				fmt.Fprintf(w, `{"tables":[{"name":"PrimaryResult","columns":[],"rows":[]}],"permissions":{"dataSources":[{"resourceId":%q,"allowTables":["DeniedTable"]}]},"dataSources":[{"resourceId":%q,"tables":["DeniedTable"]}]}`, remoteResourceID, remoteResourceID)
				return
			}
			fmt.Fprintf(w, `{"tables":[{"name":"PrimaryResult","columns":[],"rows":[]}],"permissions":{"dataSources":[{"resourceId":%q,"allowTables":[],"denyTables":["DeniedTable"]}]},"dataSources":[{"resourceId":%q,"tables":["DeniedTable"]}]}`, remoteResourceID, remoteResourceID)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := remoteFixtureClient(server.URL, credential)
	client.RemoteWorkspaces = []RemoteWorkspace{{Alias: "soc", SubscriptionID: "remote-sub", ResourceGroup: "remote-rg", WorkspaceName: "remote-law"}}
	rules := []backend.Rule{
		{ID: "unmapped", Enabled: true, Dependencies: []backend.DependencyRef{{Name: "NoTable", Kind: "sentinel_workspace_table", Scope: "not-allowed", Monitorable: true, Required: true}}},
		{ID: "missing", Enabled: true, Dependencies: []backend.DependencyRef{{Name: "NoTable", Kind: "sentinel_workspace_table", Scope: "soc", Monitorable: true, Required: true}}},
		{ID: "denied", Enabled: true, Dependencies: []backend.DependencyRef{{Name: "DeniedTable", Kind: "sentinel_workspace_table", Scope: remoteWorkspaceID, Monitorable: true, Required: true}}},
	}
	resolutions, err := client.ResolveInputs(context.Background(), rules)
	if err != nil {
		t.Fatal(err)
	}
	authoritative := make(map[string]backend.InputResolution)
	for _, resolution := range resolutions {
		if !resolution.Diagnostic {
			authoritative[resolution.RuleID] = resolution
		}
	}
	if authoritative["unmapped"].Status != backend.ResolutionRemote {
		t.Fatalf("unmapped remote = %+v", authoritative["unmapped"])
	}
	if authoritative["missing"].Status != backend.ResolutionEmpty {
		t.Fatalf("verified missing remote = %+v", authoritative["missing"])
	}
	if authoritative["denied"].Status != backend.ResolutionUnavailable {
		t.Fatalf("denied remote = %+v", authoritative["denied"])
	}
}

func TestConfiguredAliasMustResolveToVerifiedWorkspace(t *testing.T) {
	const remoteWorkspaceID = "11111111-1111-1111-1111-111111111111"
	remoteResourceID := canonicalWorkspaceResourceID("remote-sub", "remote-rg", "remote-law")
	otherResourceID := canonicalWorkspaceResourceID("other-sub", "other-rg", "other-law")
	credential := &recordingCredential{}
	queryCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == remoteResourceID:
			fmt.Fprintf(w, `{"id":%q,"location":"remote-region","properties":{"customerId":%q}}`, remoteResourceID, remoteWorkspaceID)
		case r.URL.Path == remoteOnboardingResourceID(remoteResourceID):
			writeRemoteOnboarding(w, remoteResourceID)
		case r.URL.Path == remoteResourceID+"/tables":
			fmt.Fprint(w, `{"value":[{"name":"SecurityEvent","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"standardColumns":[]}}}]}`)
		case strings.HasSuffix(r.URL.Path, "/tables"):
			fmt.Fprint(w, `{"value":[]}`)
		case strings.HasSuffix(r.URL.Path, "/query"):
			queryCalls++
			fmt.Fprintf(w, `{"tables":[{"name":"PrimaryResult","columns":[],"rows":[]}],"permissions":{"dataSources":[{"resourceId":%q,"allowTables":["SecurityEvent"]}]},"dataSources":[{"resourceId":%q,"tables":["SecurityEvent"]}]}`, otherResourceID, otherResourceID)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := remoteFixtureClient(server.URL, credential)
	client.RemoteWorkspaces = []RemoteWorkspace{{Alias: "soc", SubscriptionID: "remote-sub", ResourceGroup: "remote-rg", WorkspaceName: "remote-law"}}
	rules := []backend.Rule{
		{ID: "one", Enabled: true, Dependencies: []backend.DependencyRef{{Name: "SecurityEvent", Kind: "sentinel_workspace_table", Scope: "soc", Monitorable: true, Required: true}}},
		{ID: "two", Enabled: true, Dependencies: []backend.DependencyRef{{Name: "SecurityEvent", Kind: "sentinel_workspace_table", Scope: "soc", Monitorable: true, Required: true}}},
	}
	resolutions, err := client.ResolveInputs(context.Background(), rules)
	if err != nil {
		t.Fatal(err)
	}
	for _, resolution := range resolutions {
		if !resolution.Diagnostic && resolution.Status != backend.ResolutionUnavailable {
			t.Fatalf("mismatched alias became evidence: %+v", resolution)
		}
	}
	if queryCalls != 1 {
		t.Fatalf("alias proof queries = %d, want one cached bounded query", queryCalls)
	}
}

func TestReadinessRejectsMismatchedOriginalWorkspaceAlias(t *testing.T) {
	const remoteWorkspaceID = "11111111-1111-1111-1111-111111111111"
	remoteResourceID := canonicalWorkspaceResourceID("remote-sub", "remote-rg", "remote-law")
	otherResourceID := canonicalWorkspaceResourceID("other-sub", "other-rg", "other-law")
	queryCalls := 0
	queryText := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == remoteResourceID:
			fmt.Fprintf(w, `{"id":%q,"location":"remote-region","properties":{"customerId":%q}}`, remoteResourceID, remoteWorkspaceID)
		case r.URL.Path == remoteOnboardingResourceID(remoteResourceID):
			writeRemoteOnboarding(w, remoteResourceID)
		case r.URL.Path == remoteResourceID+"/tables":
			fmt.Fprint(w, `{"value":[{"name":"SecurityEvent","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"standardColumns":[]}}}]}`)
		case strings.HasSuffix(r.URL.Path, "/tables"):
			fmt.Fprint(w, `{"value":[]}`)
		case strings.HasSuffix(r.URL.Path, "/query"):
			queryCalls++
			var request logsQueryRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			queryText = request.Query
			fmt.Fprintf(w, `{"tables":[{"name":"PrimaryResult","columns":[],"rows":[]}],"permissions":{"dataSources":[{"resourceId":%q,"allowTables":["SecurityEvent"]}]},"dataSources":[{"resourceId":%q,"tables":["SecurityEvent"]}]}`, otherResourceID, otherResourceID)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := remoteFixtureClient(server.URL, &recordingCredential{})
	client.RemoteWorkspaces = []RemoteWorkspace{{Alias: "soc", SubscriptionID: "remote-sub", ResourceGroup: "remote-rg", WorkspaceName: "remote-law"}}
	rules := []backend.Rule{{
		ID: "remote-rule", Enabled: true,
		Dependencies: []backend.DependencyRef{{Name: "SecurityEvent", Kind: "sentinel_workspace_table", Scope: "soc", Monitorable: true, Required: true}},
	}}
	sources := []backend.Source{{Name: qualifiedRemoteSource(remoteResourceID, "SecurityEvent")}}
	for range 2 {
		evidence, err := client.ReadinessEvidence(context.Background(), rules, sources)
		if err != nil {
			t.Fatal(err)
		}
		if evidence.Status == backend.EvidenceAssessed || !evidence.Attempted || !strings.Contains(evidence.Detail, "remote workspace") {
			t.Fatalf("mismatched original alias readiness = %+v", evidence)
		}
	}
	if queryCalls != 1 {
		t.Fatalf("cached readiness alias proof queries = %d, want one", queryCalls)
	}
	if !strings.HasPrefix(queryText, "workspace('soc').SecurityEvent | take 0") {
		t.Fatalf("readiness did not prove the original workspace literal: %q", queryText)
	}
}

func TestGUIDLookingAliasCannotRewriteNativeWorkspaceID(t *testing.T) {
	const aliasGUID = "22222222-2222-2222-2222-222222222222"
	const actualGUID = "11111111-1111-1111-1111-111111111111"
	remoteResourceID := canonicalWorkspaceResourceID("remote-sub", "remote-rg", "remote-law")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case remoteResourceID:
			fmt.Fprintf(w, `{"id":%q,"location":"remote-region","properties":{"customerId":%q}}`, remoteResourceID, actualGUID)
		case remoteOnboardingResourceID(remoteResourceID):
			writeRemoteOnboarding(w, remoteResourceID)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := remoteFixtureClient(server.URL, &recordingCredential{})
	client.RemoteWorkspaces = []RemoteWorkspace{{Alias: aliasGUID, SubscriptionID: "remote-sub", ResourceGroup: "remote-rg", WorkspaceName: "remote-law"}}
	state, err := client.resolveRemoteWorkspace(context.Background(), aliasGUID)
	if err != nil {
		t.Fatal(err)
	}
	if state != nil {
		t.Fatal("GUID-looking config alias rewrote a different native workspace customer ID")
	}
}

func TestRemoteWorkspaceRequiresDefaultSentinelOnboardingState(t *testing.T) {
	const remoteWorkspaceID = "11111111-1111-1111-1111-111111111111"
	remoteResourceID := canonicalWorkspaceResourceID("remote-sub", "remote-rg", "remote-law")
	tests := []struct {
		name       string
		onboarding func(http.ResponseWriter)
	}{
		{name: "not found", onboarding: func(w http.ResponseWriter) { http.Error(w, "missing", http.StatusNotFound) }},
		{name: "denied", onboarding: func(w http.ResponseWriter) { http.Error(w, "denied", http.StatusForbidden) }},
		{name: "malformed", onboarding: func(w http.ResponseWriter) { fmt.Fprint(w, `{`) }},
		{name: "wrong name", onboarding: func(w http.ResponseWriter) {
			fmt.Fprintf(w, `{"id":%q,"name":"other"}`, remoteOnboardingResourceID(remoteResourceID))
		}},
		{name: "wrong id", onboarding: func(w http.ResponseWriter) {
			fmt.Fprintf(w, `{"id":%q,"name":"default"}`, remoteOnboardingResourceID(canonicalWorkspaceResourceID("other", "rg", "law")))
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			remoteTableCalls, logsCalls := 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == remoteResourceID:
					fmt.Fprintf(w, `{"id":%q,"location":"remote-region","properties":{"customerId":%q}}`, remoteResourceID, remoteWorkspaceID)
				case r.URL.Path == remoteOnboardingResourceID(remoteResourceID):
					tt.onboarding(w)
				case r.URL.Path == remoteResourceID+"/tables":
					remoteTableCalls++
					fmt.Fprint(w, `{"value":[]}`)
				case strings.HasSuffix(r.URL.Path, "/tables"):
					fmt.Fprint(w, `{"value":[]}`)
				case strings.HasSuffix(r.URL.Path, "/query"):
					logsCalls++
					fmt.Fprint(w, `{"tables":[]}`)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()

			client := remoteFixtureClient(server.URL, &recordingCredential{})
			client.RemoteWorkspaces = []RemoteWorkspace{{
				Alias: "soc", SubscriptionID: "remote-sub", ResourceGroup: "remote-rg", WorkspaceName: "remote-law", WorkspaceID: remoteWorkspaceID,
			}}
			rule := backend.Rule{ID: "remote", Enabled: true, Dependencies: []backend.DependencyRef{{
				Name: "SecurityEvent", Kind: "sentinel_workspace_table", Scope: remoteResourceID, Monitorable: true, Required: true,
			}}}
			resolutions, err := client.ResolveInputs(context.Background(), []backend.Rule{rule})
			if err != nil {
				t.Fatal(err)
			}
			if len(resolutions) == 0 || resolutions[0].Status != backend.ResolutionUnavailable {
				t.Fatalf("remote onboarding failure = %+v", resolutions)
			}
			if len(resolutions) < 2 || resolutions[1].ResolutionMethod != "kql+sentinel_remote_preflight_diagnostic" ||
				!strings.Contains(resolutions[1].Detail, "onboarding") {
				t.Fatalf("remote onboarding diagnostic = %+v", resolutions)
			}
			if remoteTableCalls != 0 || logsCalls != 0 {
				t.Fatalf("remote evidence calls after onboarding failure: tables=%d logs=%d", remoteTableCalls, logsCalls)
			}
		})
	}
}

func TestRemoteWorkspaceLimitIncludesHomeAndMakesNoLogsProbe(t *testing.T) {
	remotes, dependencies, workspaceIDs := remoteWorkspaceLimitFixtures(20)
	remoteResources := make(map[string]string, len(remotes))
	for i, remote := range remotes {
		remoteResources[canonicalWorkspaceResourceID(remote.SubscriptionID, remote.ResourceGroup, remote.WorkspaceName)] = workspaceIDs[i]
	}
	remoteTableCalls, logsCalls := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if workspaceID, ok := remoteResources[path]; ok {
			fmt.Fprintf(w, `{"id":%q,"location":"remote-region","properties":{"customerId":%q}}`, path, workspaceID)
			return
		}
		for resourceID := range remoteResources {
			if path == remoteOnboardingResourceID(resourceID) {
				writeRemoteOnboarding(w, resourceID)
				return
			}
			if path == resourceID+"/tables" {
				remoteTableCalls++
				fmt.Fprint(w, `{"value":[]}`)
				return
			}
		}
		switch {
		case strings.HasSuffix(path, "/tables"):
			fmt.Fprint(w, `{"value":[]}`)
		case strings.HasSuffix(path, "/query"):
			logsCalls++
			fmt.Fprint(w, `{"tables":[]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := remoteFixtureClient(server.URL, &recordingCredential{})
	client.RemoteWorkspaces = remotes
	rule := backend.Rule{ID: "too-many", Enabled: true, Dependencies: dependencies}
	resolutions, err := client.ResolveInputs(context.Background(), []backend.Rule{rule})
	if err != nil {
		t.Fatal(err)
	}
	if len(resolutions) != len(dependencies)+1 || resolutions[0].Status != backend.ResolutionIncompatible {
		t.Fatalf("20 remotes plus home = %+v", resolutions)
	}
	for _, resolution := range resolutions[1:] {
		if !resolution.Diagnostic || resolution.Status != backend.ResolutionIncompatible {
			t.Fatalf("workspace-limit diagnostic = %+v", resolution)
		}
	}
	if remoteTableCalls != 0 || logsCalls != 0 {
		t.Fatalf("workspace-limit evidence calls: tables=%d logs=%d", remoteTableCalls, logsCalls)
	}
}

func TestRemoteWorkspaceLimitDeduplicatesAliasGUIDAndARMIdentity(t *testing.T) {
	remotes, dependencies, workspaceIDs := remoteWorkspaceLimitFixtures(19)
	firstResourceID := canonicalWorkspaceResourceID(remotes[0].SubscriptionID, remotes[0].ResourceGroup, remotes[0].WorkspaceName)
	dependencies = append(dependencies,
		backend.DependencyRef{Name: "SecurityEvent", Kind: "sentinel_workspace_table", Scope: remotes[0].Alias, Monitorable: true, Required: true},
		backend.DependencyRef{Name: "SecurityEvent", Kind: "sentinel_workspace_table", Scope: workspaceIDs[0], Monitorable: true, Required: true},
	)
	remoteResources := make(map[string]string, len(remotes))
	for i, remote := range remotes {
		remoteResources[canonicalWorkspaceResourceID(remote.SubscriptionID, remote.ResourceGroup, remote.WorkspaceName)] = workspaceIDs[i]
	}
	aliasProofCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if workspaceID, ok := remoteResources[path]; ok {
			fmt.Fprintf(w, `{"id":%q,"location":"remote-region","properties":{"customerId":%q}}`, path, workspaceID)
			return
		}
		for resourceID := range remoteResources {
			if path == remoteOnboardingResourceID(resourceID) {
				writeRemoteOnboarding(w, resourceID)
				return
			}
		}
		switch {
		case path == firstResourceID+"/tables":
			fmt.Fprint(w, `{"value":[{"name":"SecurityEvent","properties":{"plan":"Analytics","provisioningState":"Succeeded"}}]}`)
		case strings.HasSuffix(path, "/query"):
			aliasProofCalls++
			fmt.Fprintf(w, `{"tables":[{"name":"PrimaryResult","columns":[],"rows":[]}],"permissions":{"dataSources":[{"resourceId":%q,"allowTables":["SecurityEvent"]}]},"dataSources":[{"resourceId":%q,"tables":["SecurityEvent"]}]}`, firstResourceID, firstResourceID)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := remoteFixtureClient(server.URL, &recordingCredential{})
	client.RemoteWorkspaces = remotes
	if outcomes, exceeded := client.remoteWorkspaceLimitOutcomes(context.Background(), backend.Rule{Dependencies: dependencies}); exceeded || len(outcomes) != 0 {
		t.Fatalf("19 unique remotes were counted above the limit: %+v", outcomes)
	}
	if aliasProofCalls != 1 {
		t.Fatalf("alias identity proof calls = %d, want one", aliasProofCalls)
	}
}

func TestRemoteRegionLimitRejectsTwentyDistinctRegionsBeforeOrdinaryProbes(t *testing.T) {
	remotes, dependencies, workspaceIDs := remoteWorkspaceLimitFixtures(19)
	resources := make(map[string]remoteRegionWorkspace, len(remotes))
	for i, remote := range remotes {
		resources[canonicalWorkspaceResourceID(remote.SubscriptionID, remote.ResourceGroup, remote.WorkspaceName)] = remoteRegionWorkspace{
			workspaceID: workspaceIDs[i], location: fmt.Sprintf("region%02d", i+1),
		}
	}
	server, calls := newRemoteRegionServer(t, resources)
	client := remoteFixtureClient(server.URL, &recordingCredential{})
	client.workspaceLocation = "region00"
	client.RemoteWorkspaces = remotes

	resolutions, err := client.ResolveInputs(context.Background(), []backend.Rule{{
		ID: "twenty-regions", Enabled: true, Dependencies: dependencies,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(resolutions) != len(dependencies)+1 || resolutions[0].Status != backend.ResolutionIncompatible {
		t.Fatalf("20 distinct regions = %+v", resolutions)
	}
	for _, resolution := range resolutions[1:] {
		if !resolution.Diagnostic || resolution.Status != backend.ResolutionIncompatible ||
			resolution.ResolutionMethod != "kql+azure_monitor_region_limit_diagnostic" {
			t.Fatalf("region-limit diagnostic = %+v", resolution)
		}
	}
	if calls.remoteTableCalls != 0 || calls.logsCalls != 0 {
		t.Fatalf("region-limit evidence calls: remote tables=%d logs=%d", calls.remoteTableCalls, calls.logsCalls)
	}
}

func TestRemoteRegionLimitAllowsNineteenDistinctRegions(t *testing.T) {
	remotes, dependencies, workspaceIDs := remoteWorkspaceLimitFixtures(18)
	resources := make(map[string]remoteRegionWorkspace, len(remotes))
	for i, remote := range remotes {
		resources[canonicalWorkspaceResourceID(remote.SubscriptionID, remote.ResourceGroup, remote.WorkspaceName)] = remoteRegionWorkspace{
			workspaceID: workspaceIDs[i], location: fmt.Sprintf("region%02d", i+1),
		}
	}
	server, calls := newRemoteRegionServer(t, resources)
	client := remoteFixtureClient(server.URL, &recordingCredential{})
	client.workspaceLocation = "region00"
	client.RemoteWorkspaces = remotes

	if outcomes, blocked := client.remoteWorkspaceLimitOutcomes(context.Background(), backend.Rule{Dependencies: dependencies}); blocked || len(outcomes) != 0 {
		t.Fatalf("19 distinct regions were blocked: %+v", outcomes)
	}
	if calls.remoteTableCalls != 0 || calls.logsCalls != 0 {
		t.Fatalf("region-count evidence calls: remote tables=%d logs=%d", calls.remoteTableCalls, calls.logsCalls)
	}
}

func TestRemoteRegionLimitDeduplicatesCaseAndWhitespace(t *testing.T) {
	remotes, dependencies, workspaceIDs := remoteWorkspaceLimitFixtures(19)
	resources := make(map[string]remoteRegionWorkspace, len(remotes))
	for i, remote := range remotes {
		location := fmt.Sprintf("region%02d", i+1)
		if i == len(remotes)-1 {
			location = "\tNORTH   EUROPE\n"
		}
		resources[canonicalWorkspaceResourceID(remote.SubscriptionID, remote.ResourceGroup, remote.WorkspaceName)] = remoteRegionWorkspace{
			workspaceID: workspaceIDs[i], location: location,
		}
	}
	server, _ := newRemoteRegionServer(t, resources)
	client := remoteFixtureClient(server.URL, &recordingCredential{})
	client.workspaceLocation = " North Europe "
	client.RemoteWorkspaces = remotes

	if outcomes, blocked := client.remoteWorkspaceLimitOutcomes(context.Background(), backend.Rule{Dependencies: dependencies}); blocked || len(outcomes) != 0 {
		t.Fatalf("case/whitespace variants were counted as distinct regions: %+v", outcomes)
	}
}

func TestRemoteRegionLimitMissingLocationIsUnavailableWithoutDownstreamProbes(t *testing.T) {
	remotes, dependencies, workspaceIDs := remoteWorkspaceLimitFixtures(1)
	resourceID := canonicalWorkspaceResourceID(remotes[0].SubscriptionID, remotes[0].ResourceGroup, remotes[0].WorkspaceName)
	server, calls := newRemoteRegionServer(t, map[string]remoteRegionWorkspace{
		resourceID: {workspaceID: workspaceIDs[0]},
	})
	client := remoteFixtureClient(server.URL, &recordingCredential{})
	client.RemoteWorkspaces = remotes

	resolutions, err := client.ResolveInputs(context.Background(), []backend.Rule{{
		ID: "missing-location", Enabled: true, Dependencies: dependencies,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(resolutions) != 2 || resolutions[0].Status != backend.ResolutionUnavailable ||
		!resolutions[1].Diagnostic || resolutions[1].Status != backend.ResolutionUnavailable ||
		resolutions[1].ResolutionMethod != "kql+azure_monitor_region_limit_diagnostic" {
		t.Fatalf("missing remote location = %+v", resolutions)
	}
	if calls.remoteTableCalls != 0 || calls.logsCalls != 0 {
		t.Fatalf("evidence calls after missing remote location: remote tables=%d logs=%d", calls.remoteTableCalls, calls.logsCalls)
	}
}

func TestRemotePermissionEvidenceRequiresWorkspaceIdentity(t *testing.T) {
	resourceID := canonicalWorkspaceResourceID("remote-sub", "remote-rg", "remote-law")
	target := sentinelSourceTarget{
		table: "SecurityEvent", expectedResourceID: resourceID,
		expectedWorkspaceID: "11111111-1111-1111-1111-111111111111",
	}
	var response logsQueryResponse
	if err := json.Unmarshal([]byte(fmt.Sprintf(`{
		"permissions":{"dataSources":[{"allowTables":["SecurityEvent"]}]},
		"dataSources":[{"resourceId":%q,"tables":["SecurityEvent"]}]
	}`, resourceID)), &response); err != nil {
		t.Fatal(err)
	}
	if err := validateLogsEvidenceForSource(response, target); err == nil || !strings.Contains(err.Error(), "requested remote workspace") {
		t.Fatalf("unqualified remote permission evidence = %v", err)
	}

	if err := json.Unmarshal([]byte(fmt.Sprintf(`{
		"permissions":{"dataSources":[
			{"resourceId":%q,"allowTables":["SecurityEvent"]},
			{"resourceId":%q,"denyTables":["SecurityEvent"]}
		]},
		"dataSources":[{"resourceId":%q,"tables":["SecurityEvent"]}]
	}`, resourceID, canonicalWorkspaceResourceID("other", "rg", "law"), resourceID)), &response); err != nil {
		t.Fatal(err)
	}
	if err := validateLogsEvidenceForSource(response, target); err != nil {
		t.Fatalf("workspace-scoped remote permission evidence = %v", err)
	}
}

func testAlertRule(name, query string) alertRuleJSON {
	raw := alertRuleJSON{Name: name, Kind: "Scheduled"}
	enabled := true
	raw.Properties.Enabled = &enabled
	raw.Properties.Query = query
	return raw
}

func remoteOnboardingResourceID(workspaceResourceID string) string {
	return workspaceResourceID + "/providers/Microsoft.SecurityInsights/onboardingStates/default"
}

func writeRemoteOnboarding(w http.ResponseWriter, workspaceResourceID string) {
	fmt.Fprintf(w, `{"id":%q,"name":"default"}`, remoteOnboardingResourceID(workspaceResourceID))
}

func remoteFixtureClient(serverURL string, credential azcore.TokenCredential) *Client {
	client := fixtureClient(serverURL, credential)
	client.SubscriptionID = "remote-sub"
	client.workspaceLocation = "home-region"
	client.workspaceLocationValidated = true
	return client
}

type remoteRegionWorkspace struct {
	workspaceID string
	location    string
}

type remoteRegionCalls struct {
	remoteTableCalls int
	logsCalls        int
}

func newRemoteRegionServer(t *testing.T, resources map[string]remoteRegionWorkspace) (*httptest.Server, *remoteRegionCalls) {
	t.Helper()
	calls := &remoteRegionCalls{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if workspace, ok := resources[path]; ok {
			if workspace.location == "" {
				fmt.Fprintf(w, `{"id":%q,"properties":{"customerId":%q}}`, path, workspace.workspaceID)
			} else {
				fmt.Fprintf(w, `{"id":%q,"location":%q,"properties":{"customerId":%q}}`, path, workspace.location, workspace.workspaceID)
			}
			return
		}
		for resourceID := range resources {
			switch path {
			case remoteOnboardingResourceID(resourceID):
				writeRemoteOnboarding(w, resourceID)
				return
			case resourceID + "/tables":
				calls.remoteTableCalls++
				fmt.Fprint(w, `{"value":[]}`)
				return
			}
		}
		switch {
		case strings.HasSuffix(path, "/tables"):
			fmt.Fprint(w, `{"value":[]}`)
		case strings.HasSuffix(path, "/query"):
			calls.logsCalls++
			fmt.Fprint(w, `{"tables":[]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server, calls
}

func remoteWorkspaceLimitFixtures(count int) ([]RemoteWorkspace, []backend.DependencyRef, []string) {
	remotes := make([]RemoteWorkspace, 0, count)
	dependencies := make([]backend.DependencyRef, 0, count)
	workspaceIDs := make([]string, 0, count)
	for i := 0; i < count; i++ {
		workspaceID := fmt.Sprintf("%08x-0000-0000-0000-%012x", i+1, i+1)
		remote := RemoteWorkspace{
			Alias: fmt.Sprintf("soc-%02d", i+1), SubscriptionID: fmt.Sprintf("remote-sub-%02d", i+1),
			ResourceGroup: "remote-rg", WorkspaceName: fmt.Sprintf("remote-law-%02d", i+1), WorkspaceID: workspaceID,
		}
		resourceID := canonicalWorkspaceResourceID(remote.SubscriptionID, remote.ResourceGroup, remote.WorkspaceName)
		remotes = append(remotes, remote)
		workspaceIDs = append(workspaceIDs, workspaceID)
		dependencies = append(dependencies, backend.DependencyRef{
			Name: "SecurityEvent", Kind: "sentinel_workspace_table", Scope: resourceID, Monitorable: true, Required: true,
		})
	}
	return remotes, dependencies, workspaceIDs
}
