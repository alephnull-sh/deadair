package sentinel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/alephnull-sh/deadair/internal/backend"
	"github.com/alephnull-sh/deadair/internal/graph"
	"github.com/alephnull-sh/deadair/internal/health"
)

type recordingCredential struct {
	mu     sync.Mutex
	scopes []string
}

func (c *recordingCredential) GetToken(_ context.Context, options policy.TokenRequestOptions) (azcore.AccessToken, error) {
	c.mu.Lock()
	c.scopes = append(c.scopes, options.Scopes...)
	c.mu.Unlock()
	return azcore.AccessToken{Token: "fixture-token", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

func (c *recordingCredential) sawScope(want string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, got := range c.scopes {
		if got == want {
			return true
		}
	}
	return false
}

type scriptedCredential struct {
	mu      sync.Mutex
	calls   map[string]int
	acquire func(scope string, call int) (azcore.AccessToken, error)
}

func (c *scriptedCredential) GetToken(_ context.Context, options policy.TokenRequestOptions) (azcore.AccessToken, error) {
	if len(options.Scopes) != 1 {
		return azcore.AccessToken{}, fmt.Errorf("credential scopes = %v, want exactly one", options.Scopes)
	}
	scope := options.Scopes[0]
	c.mu.Lock()
	if c.calls == nil {
		c.calls = make(map[string]int)
	}
	c.calls[scope]++
	call := c.calls[scope]
	c.mu.Unlock()
	return c.acquire(scope, call)
}

func (c *scriptedCredential) callCount(scope string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls[scope]
}

func fixtureClient(serverURL string, credential azcore.TokenCredential) *Client {
	return &Client{
		SubscriptionID:       "sub-id",
		ResourceGroup:        "rg-lab",
		WorkspaceName:        "law-lab",
		WorkspaceID:          "workspace-id",
		Credential:           credential,
		ARMEndpoint:          serverURL,
		LogsEndpoint:         serverURL,
		workspaceIDValidated: true,
	}
}

func TestAccessTokenCacheSeparatesARMAndLogsScopes(t *testing.T) {
	credential := &scriptedCredential{acquire: func(scope string, _ int) (azcore.AccessToken, error) {
		return azcore.AccessToken{Token: scope, ExpiresOn: time.Now().Add(time.Hour)}, nil
	}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{}`)
	}))
	defer server.Close()
	client := fixtureClient(server.URL, credential)

	for i := 0; i < 20; i++ {
		if err := client.doARM(context.Background(), server.URL+"/resource", nil); err != nil {
			t.Fatal(err)
		}
		if err := client.doLogs(context.Background(), server.URL+"/query", []byte(`{}`), nil); err != nil {
			t.Fatal(err)
		}
	}
	if got := credential.callCount(armScope); got != 1 {
		t.Fatalf("ARM token acquisitions = %d, want 1", got)
	}
	if got := credential.callCount(logsScope); got != 1 {
		t.Fatalf("Logs token acquisitions = %d, want 1", got)
	}
}

func TestAccessTokenCacheCoalescesConcurrentAcquisitionsPerScope(t *testing.T) {
	armStarted := make(chan struct{})
	logsStarted := make(chan struct{})
	release := make(chan struct{})
	var armOnce sync.Once
	var logsOnce sync.Once
	credential := &scriptedCredential{acquire: func(scope string, _ int) (azcore.AccessToken, error) {
		switch scope {
		case armScope:
			armOnce.Do(func() { close(armStarted) })
		case logsScope:
			logsOnce.Do(func() { close(logsStarted) })
		default:
			return azcore.AccessToken{}, fmt.Errorf("unexpected scope %q", scope)
		}
		<-release
		return azcore.AccessToken{Token: scope, ExpiresOn: time.Now().Add(time.Hour)}, nil
	}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{}`)
	}))
	defer server.Close()
	client := fixtureClient(server.URL, credential)

	const requestsPerScope = 24
	start := make(chan struct{})
	errs := make(chan error, requestsPerScope*2)
	var ready sync.WaitGroup
	var requests sync.WaitGroup
	ready.Add(requestsPerScope * 2)
	requests.Add(requestsPerScope * 2)
	for i := 0; i < requestsPerScope; i++ {
		go func() {
			defer requests.Done()
			ready.Done()
			<-start
			errs <- client.doARM(context.Background(), server.URL+"/resource", nil)
		}()
		go func() {
			defer requests.Done()
			ready.Done()
			<-start
			errs <- client.doLogs(context.Background(), server.URL+"/query", []byte(`{}`), nil)
		}()
	}
	ready.Wait()
	close(start)
	for name, started := range map[string]<-chan struct{}{"ARM": armStarted, "Logs": logsStarted} {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatalf("%s token acquisition did not start independently", name)
		}
	}
	close(release)
	requests.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := credential.callCount(armScope); got != 1 {
		t.Fatalf("concurrent ARM token acquisitions = %d, want 1", got)
	}
	if got := credential.callCount(logsScope); got != 1 {
		t.Fatalf("concurrent Logs token acquisitions = %d, want 1", got)
	}
}

func TestAccessTokenCacheRefreshesNearExpiryToken(t *testing.T) {
	credential := &scriptedCredential{acquire: func(_ string, call int) (azcore.AccessToken, error) {
		if call == 1 {
			return azcore.AccessToken{Token: "near-expiry", ExpiresOn: time.Now().Add(accessTokenRefreshSkew / 2)}, nil
		}
		return azcore.AccessToken{Token: "fresh", ExpiresOn: time.Now().Add(time.Hour)}, nil
	}}
	var mu sync.Mutex
	var authorizations []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		authorizations = append(authorizations, r.Header.Get("Authorization"))
		mu.Unlock()
		fmt.Fprint(w, `{}`)
	}))
	defer server.Close()
	client := fixtureClient(server.URL, credential)

	for i := 0; i < 3; i++ {
		if err := client.doARM(context.Background(), server.URL+"/resource", nil); err != nil {
			t.Fatal(err)
		}
	}
	if got := credential.callCount(armScope); got != 2 {
		t.Fatalf("ARM token acquisitions = %d, want 2", got)
	}
	mu.Lock()
	defer mu.Unlock()
	want := []string{"Bearer near-expiry", "Bearer fresh", "Bearer fresh"}
	if !reflect.DeepEqual(authorizations, want) {
		t.Fatalf("Authorization headers = %v, want %v", authorizations, want)
	}
}

func TestAccessTokenCacheRetriesAcquisitionFailure(t *testing.T) {
	credential := &scriptedCredential{acquire: func(_ string, call int) (azcore.AccessToken, error) {
		if call == 1 {
			return azcore.AccessToken{}, fmt.Errorf("fixture acquisition failed")
		}
		return azcore.AccessToken{Token: "recovered", ExpiresOn: time.Now().Add(time.Hour)}, nil
	}}
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		fmt.Fprint(w, `{}`)
	}))
	defer server.Close()
	client := fixtureClient(server.URL, credential)

	if err := client.doARM(context.Background(), server.URL+"/resource", nil); err == nil || !strings.Contains(err.Error(), "fixture acquisition failed") {
		t.Fatalf("first ARM request error = %v", err)
	}
	if err := client.doARM(context.Background(), server.URL+"/resource", nil); err != nil {
		t.Fatal(err)
	}
	if got := credential.callCount(armScope); got != 2 {
		t.Fatalf("ARM token acquisitions = %d, want 2", got)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("HTTP requests = %d, want 1 after token recovery", got)
	}
}

func writeAllowedLogsResult(w http.ResponseWriter, table, resultTables string) {
	fmt.Fprintf(w, `{"tables":%s,"permissions":{"dataSources":[{"allowTables":[%q]}]},"dataSources":[{"tables":[%q]}]}`, resultTables, table, table)
}

func decodeLogsResponse(t *testing.T, raw string) logsQueryResponse {
	t.Helper()
	var response logsQueryResponse
	if err := json.Unmarshal([]byte(raw), &response); err != nil {
		t.Fatal(err)
	}
	return response
}

func liveASIMSemanticPartialResponse() string {
	return `{"error":{"code":"PartialError","message":"There were some errors when processing your query.","details":[
		{"code":"EngineError","message":"Something went wrong processing your query on the server.","innererror":{"code":"-2133196790","message":"Operator source expression should be table or column","severity":3,"severityName":"Warning"}},
		{"code":"EngineError","message":"Something went wrong processing your query on the server.","innererror":{"code":"-2133196790","message":"'union' operator: Failed to resolve tabular function named '_Im_WebSession'","severity":3,"severityName":"Warning"}},
		{"code":"EngineError","message":"Something went wrong processing your query on the server.","innererror":{"code":"-2133196790","message":"Internal error while analyzing lookup operator.","severity":3,"severityName":"Warning"}},
		{"code":"EngineError","message":"Something went wrong processing your query on the server.","innererror":{"code":"-2133196790","message":"let statement 'maaliciousdata' could not be analyzed","severity":3,"severityName":"Warning"}},
		{"code":"EngineError","message":"Something went wrong processing your query on the server.","innererror":{"code":"-2133196790","message":"'_ASIM_ResolveDvcFQDN'(): argument #1 could not be resolved","severity":3,"severityName":"Warning"}}
	]},"tables":[{"name":"PrimaryResult","columns":[],"rows":[]}]}`
}

func liveASIMAuthenticationSemanticPartialResponse() string {
	return `{"error":{"code":"PartialError","message":"There were some errors when processing your query.","details":[
		{"code":"EngineError","message":"Something went wrong processing your query on the server.","innererror":{"code":"-2133196790","message":"'union' operator: Failed to resolve table expression named 'barracuda_CL'","severity":3,"severityName":"Warning"}},
		{"code":"EngineError","message":"Something went wrong processing your query on the server.","innererror":{"code":"-2133196790","message":"'where' operator: Failed to resolve table or column expression named 'PostgreSQL_CL'","severity":3,"severityName":"Warning"}},
		{"code":"EngineError","message":"Something went wrong processing your query on the server.","innererror":{"code":"-2133196790","message":"union: must have at least one operand that can be evaluated successfully when running with 'Fuzzy' mode.","severity":3,"severityName":"Warning"}}
	]},"tables":[{"name":"PrimaryResult","columns":[],"rows":[]}]}`
}

func TestRecognizedASIMSemanticWarningRequiresObservedOperatorPrefixes(t *testing.T) {
	tests := []struct {
		message    string
		recognized bool
	}{
		{message: `'union' operator: Failed to resolve table expression named 'barracuda_CL'`, recognized: true},
		{message: `'where' operator: Failed to resolve table or column expression named 'PostgreSQL_CL'`, recognized: true},
		{message: `Failed to resolve table expression named 'barracuda_CL'`},
		{message: `Failed to resolve table or column expression named 'PostgreSQL_CL'`},
		{message: `'where' operator: Failed to resolve table expression named 'barracuda_CL'`},
		{message: `'union' operator: Failed to resolve table or column expression named 'PostgreSQL_CL'`},
	}
	for _, tt := range tests {
		recognized, unresolved := recognizedASIMSemanticWarning(tt.message)
		if recognized != tt.recognized || unresolved != tt.recognized {
			t.Fatalf("recognizedASIMSemanticWarning(%q) = %t/%t, want %t/%t", tt.message, recognized, unresolved, tt.recognized, tt.recognized)
		}
	}
}

func TestSentinelRuleMapsWatchlistAndASIMDependencies(t *testing.T) {
	enabled := true
	raw := alertRuleJSON{Name: "native-dependencies", Kind: "Scheduled"}
	raw.Properties.Enabled = &enabled
	raw.Properties.Query = `union SecurityEvent, _GetWatchlist("VIPUsers"), _Im_Dns(starttime=ago(1d))`
	raw.Properties.QueryFrequency = "PT5M"
	raw.Properties.QueryPeriod = "PT10M"

	rule := sentinelRule(raw, map[string]WorkspaceFunction{}, true)
	if rule.InputStatus != "" || !reflect.DeepEqual(rule.Patterns, []string{"SecurityEvent"}) {
		t.Fatalf("rule input = status %q patterns %#v detail %q", rule.InputStatus, rule.Patterns, rule.InputDetail)
	}
	want := []backend.DependencyRef{
		{ID: "sentinel_watchlist:vipusers", Name: "VIPUsers", Kind: "sentinel_watchlist", Required: true},
		{ID: "sentinel_asim_parser:_im_dns", Name: "_Im_Dns", Kind: "sentinel_asim_parser", Required: true, Expression: `_Im_Dns(starttime=ago(1d))`},
	}
	if !reflect.DeepEqual(rule.Dependencies, want) {
		t.Fatalf("dependencies = %#v, want %#v", rule.Dependencies, want)
	}
}

func TestSentinelRuleKeepsMixedDeferredAndUnresolvedBranches(t *testing.T) {
	enabled := true
	tests := []struct {
		name         string
		query        string
		functions    map[string]WorkspaceFunction
		wantPatterns []string
		wantKinds    []string
	}{
		{
			name:      "mapped workspace and dynamic table",
			query:     `workspace("mapped").SecurityEvent | union table(DynamicName)`,
			wantKinds: []string{"sentinel_workspace_table", sentinelKQLUnsupportedDependency},
		},
		{
			name:         "ASIM and missing function",
			query:        `SecurityEvent | union _Im_Dns(), UnknownFunction()`,
			functions:    map[string]WorkspaceFunction{},
			wantPatterns: []string{"SecurityEvent"},
			wantKinds:    []string{"sentinel_asim_parser", sentinelKQLUnsupportedDependency},
		},
		{
			name:         "watchlist and dynamic table",
			query:        `SecurityEvent | union _GetWatchlist("VIPs"), table(DynamicName)`,
			wantPatterns: []string{"SecurityEvent"},
			wantKinds:    []string{"sentinel_watchlist", sentinelKQLUnsupportedDependency},
		},
		{
			name:  "watchlist and ambiguous function metadata",
			query: `union _GetWatchlist("VIPs"), Broken("value")`,
			functions: map[string]WorkspaceFunction{
				"Broken": {Body: `SecurityEvent`, Parameters: []string{"value"}},
			},
			wantKinds: []string{"sentinel_watchlist", sentinelKQLAmbiguousDependency},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := alertRuleJSON{Name: "mixed-native", Kind: "Scheduled"}
			raw.Properties.Enabled = &enabled
			raw.Properties.Query = tt.query
			raw.Properties.QueryFrequency = "PT5M"
			raw.Properties.QueryPeriod = "PT10M"

			rule := sentinelRule(raw, tt.functions, true)
			if rule.InputStatus != "" || !reflect.DeepEqual(rule.Patterns, tt.wantPatterns) {
				t.Fatalf("rule input = status %q patterns %#v detail %q", rule.InputStatus, rule.Patterns, rule.InputDetail)
			}
			gotKinds := make([]string, 0, len(rule.Dependencies))
			for _, dependency := range rule.Dependencies {
				gotKinds = append(gotKinds, dependency.Kind)
			}
			if !reflect.DeepEqual(gotKinds, tt.wantKinds) {
				t.Fatalf("dependency kinds = %#v, want %#v", gotKinds, tt.wantKinds)
			}
			blocking := rule.Dependencies[len(rule.Dependencies)-1]
			if strings.TrimSpace(blocking.Expression) == "" || !blocking.Required {
				t.Fatalf("blocking dependency = %#v, want required private detail", blocking)
			}
		})
	}
}

func TestResolveInputsMixedNativeAndUnsupportedBranchesFailsClosed(t *testing.T) {
	t.Parallel()
	credential := &recordingCredential{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/tables"):
			fmt.Fprint(w, `{"value":[{"name":"SecurityEvent","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"standardColumns":[]}}}]}`)
		case strings.HasSuffix(r.URL.Path, "/watchlists"):
			fmt.Fprint(w, `{"value":[{"id":"/watchlists/vip","properties":{"watchlistAlias":"VIPs","provisioningState":"Succeeded","isDeleted":false}}]}`)
		case strings.HasSuffix(r.URL.Path, "/query"):
			var request logsQueryRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Error(err)
			}
			if strings.Contains(request.Query, "_GetWatchlist") {
				fmt.Fprint(w, `{"tables":[{"name":"PrimaryResult","columns":[],"rows":[]}],"permissions":{"dataSources":[{"allowTables":["Watchlist"]}]},"dataSources":[{"tables":["Watchlist"]}]}`)
			} else {
				writeAllowedLogsResult(w, "SecurityEvent", `[{"name":"PrimaryResult","columns":[],"rows":[]}]`)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	enabled := true
	raw := alertRuleJSON{Name: "mixed-native", Kind: "Scheduled"}
	raw.Properties.Enabled = &enabled
	raw.Properties.Query = `union SecurityEvent, _GetWatchlist("VIPs"), table(DynamicName)`
	raw.Properties.QueryFrequency = "PT5M"
	raw.Properties.QueryPeriod = "PT10M"
	rule := sentinelRule(raw, map[string]WorkspaceFunction{}, true)

	got, err := fixtureClient(server.URL, credential).ResolveInputs(context.Background(), []backend.Rule{rule})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 || got[0].Diagnostic || got[0].Status != backend.ResolutionUnsupported || len(got[0].ResolvedSources) != 0 || len(got[0].ResolvedDependencies) != 0 {
		t.Fatalf("authoritative resolution = %#v", got)
	}
	if !got[1].Diagnostic || got[1].Status != backend.ResolutionResolved || !reflect.DeepEqual(got[1].ResolvedSources, []string{"SecurityEvent"}) {
		t.Fatalf("table diagnostic = %#v", got[1])
	}
	if !got[2].Diagnostic || got[2].Status != backend.ResolutionResolved || len(got[2].ResolvedDependencies) != 1 || got[2].ResolvedDependencies[0].Kind != "sentinel_watchlist" {
		t.Fatalf("watchlist diagnostic = %#v", got[2])
	}
	if !got[3].Diagnostic || got[3].Status != backend.ResolutionUnsupported || got[3].SelectorKind != "kql_query" || !strings.Contains(got[3].Detail, "dynamic source function") {
		t.Fatalf("unsupported diagnostic = %#v", got[3])
	}
}

func TestValidateNativeLogsPermissionsTreatsOmittedAllowTablesAsFullAccess(t *testing.T) {
	client := fixtureClient("https://example.invalid", &recordingCredential{})
	resourceID := canonicalWorkspaceResourceID(client.SubscriptionID, client.ResourceGroup, client.WorkspaceName)
	response := decodeLogsResponse(t, fmt.Sprintf(`{
		"permissions":{"dataSources":[{"resourceId":%q}]},
		"dataSources":[{"resourceId":%q,"workspace":"workspace-id","tables":["SecurityEvent"]}]
	}`, resourceID, resourceID))
	tables, err := client.validateNativeLogsPermissions(response, true)
	if err != nil || !reflect.DeepEqual(tables, []string{"SecurityEvent"}) {
		t.Fatalf("full-access validation = %#v, %v", tables, err)
	}
	response.Permissions.DataSources[0].DenyTables = []string{"SecurityEvent"}
	if _, err := client.validateNativeLogsPermissions(response, true); err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("deny override error = %v", err)
	}
}

func TestValidateNativeLogsPermissionsRejectsContradictoryWorkspaceIdentity(t *testing.T) {
	t.Parallel()
	client := fixtureClient("https://example.invalid", &recordingCredential{})
	localResourceID := canonicalWorkspaceResourceID(client.SubscriptionID, client.ResourceGroup, client.WorkspaceName)
	remoteResourceID := canonicalWorkspaceResourceID(client.SubscriptionID, client.ResourceGroup, "other-workspace")
	tests := []struct {
		name       string
		resourceID string
		workspace  string
	}{
		{name: "local resource ID with foreign workspace GUID", resourceID: localResourceID, workspace: "other-workspace-id"},
		{name: "foreign resource ID with local workspace GUID", resourceID: remoteResourceID, workspace: client.WorkspaceID},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			response := decodeLogsResponse(t, fmt.Sprintf(`{
				"permissions":{"dataSources":[{"resourceId":%q,"allowTables":["SecurityEvent"]}]},
				"dataSources":[{"resourceId":%q,"workspace":%q,"tables":["SecurityEvent"]}]
			}`, localResourceID, tt.resourceID, tt.workspace))
			if _, err := client.validateNativeLogsPermissions(response, true); err == nil || !strings.Contains(err.Error(), "exact local workspace") {
				t.Fatalf("contradictory workspace identity error = %v", err)
			}
		})
	}
}

func TestSentinelWatchlistsPaginatesCachesAndGuardsHost(t *testing.T) {
	credential := &recordingCredential{}
	var server *httptest.Server
	var calls atomic.Int32
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodGet || (strings.HasSuffix(r.URL.Path, "/watchlists") && r.URL.Query().Get("api-version") != watchlistsAPIVersion) {
			t.Errorf("watchlist request = %s %s", r.Method, r.URL.RequestURI())
		}
		switch r.URL.Path {
		case "/subscriptions/sub-id/resourceGroups/rg-lab/providers/Microsoft.OperationalInsights/workspaces/law-lab/providers/Microsoft.SecurityInsights/watchlists":
			fmt.Fprintf(w, `{"value":[{"id":"/watchlists/vip","properties":{"watchlistAlias":"VIPUsers","provisioningState":"Succeeded","isDeleted":false}}],"nextLink":%q}`, server.URL+"/watchlists-page-2?cursor=opaque")
		case "/watchlists-page-2":
			fmt.Fprint(w, `{"value":[{"id":"/watchlists/ops","properties":{"watchlistAlias":"OpsUsers","provisioningState":"Succeeded","uploadStatus":"Complete","isDeleted":false}}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := fixtureClient(server.URL, credential)
	first, complete, err := client.sentinelWatchlists(context.Background())
	if err != nil || !complete || len(first) != 2 || !first["vipusers"].complete {
		t.Fatalf("watchlists = %#v, complete=%v, err=%v", first, complete, err)
	}
	if _, _, err := client.sentinelWatchlists(context.Background()); err != nil || calls.Load() != 2 {
		t.Fatalf("cached watchlists calls/error = %d/%v", calls.Load(), err)
	}

	badServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"value":[],"nextLink":"https://example.invalid/stolen"}`)
	}))
	defer badServer.Close()
	badClient := fixtureClient(badServer.URL, credential)
	if _, _, err := badClient.sentinelWatchlists(context.Background()); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("wrong-host nextLink error = %v", err)
	}
}

func TestResolveInputsWatchlistEvidence(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		watchlists     string
		logs           string
		withTable      bool
		wantStatus     backend.ResolutionStatus
		wantDiagnostic backend.ResolutionStatus
		wantQueries    int32
	}{
		{
			name: "missing after complete inventory", watchlists: `{"value":[]}`,
			wantStatus: backend.ResolutionEmpty, wantDiagnostic: backend.ResolutionEmpty,
		},
		{
			name: "present table cannot mask missing watchlist", watchlists: `{"value":[]}`,
			withTable: true, wantStatus: backend.ResolutionEmpty, wantDiagnostic: backend.ResolutionEmpty, wantQueries: 1,
		},
		{
			name: "deleted alias", watchlists: `{"value":[{"id":"/watchlists/vip","properties":{"watchlistAlias":"VIPUsers","provisioningState":"Succeeded","isDeleted":true}}]}`,
			wantStatus: backend.ResolutionEmpty, wantDiagnostic: backend.ResolutionEmpty,
		},
		{
			name: "deleted alias with incomplete identity", watchlists: `{"value":[{"properties":{"watchlistAlias":"VIPUsers","provisioningState":"Succeeded","isDeleted":true}}]}`,
			wantStatus: backend.ResolutionUnavailable, wantDiagnostic: backend.ResolutionUnavailable,
		},
		{
			name: "incomplete alias metadata", watchlists: `{"value":[{"properties":{"watchlistAlias":"VIPUsers","provisioningState":"Succeeded","isDeleted":false}}]}`,
			wantStatus: backend.ResolutionUnavailable, wantDiagnostic: backend.ResolutionUnavailable,
		},
		{
			name: "missing alias with incomplete inventory", watchlists: `{"value":[{"id":"/watchlists/unknown","properties":{"provisioningState":"Succeeded","isDeleted":false}}]}`,
			wantStatus: backend.ResolutionUnavailable, wantDiagnostic: backend.ResolutionUnavailable,
		},
		{
			name: "present watchlist only", watchlists: `{"value":[{"id":"/watchlists/vip","properties":{"watchlistAlias":"VIPUsers","provisioningState":"Succeeded","isDeleted":false}}]}`,
			logs:       `{"tables":[{"name":"PrimaryResult","columns":[],"rows":[]}],"permissions":{"dataSources":[{"allowTables":["Watchlist"]}]},"dataSources":[{"tables":["Watchlist"]}]}`,
			wantStatus: backend.ResolutionUnsupported, wantDiagnostic: backend.ResolutionResolved, wantQueries: 1,
		},
		{
			name: "official list sample omits lifecycle states", watchlists: `{"value":[{"id":"/subscriptions/sub-id/resourceGroups/rg-lab/providers/Microsoft.OperationalInsights/workspaces/law-lab/providers/Microsoft.SecurityInsights/watchlists/vip","name":"vip","properties":{"displayName":"VIP users","watchlistAlias":"VIPUsers","isDeleted":false}}]}`,
			logs:       `{"tables":[{"name":"PrimaryResult","columns":[],"rows":[]}],"permissions":{"dataSources":[{"allowTables":["Watchlist"]}]},"dataSources":[{"tables":["Watchlist"]}]}`,
			wantStatus: backend.ResolutionUnsupported, wantDiagnostic: backend.ResolutionResolved, wantQueries: 1,
		},
		{
			name: "explicit failed lifecycle state", watchlists: `{"value":[{"id":"/watchlists/vip","properties":{"watchlistAlias":"VIPUsers","provisioningState":"Failed","isDeleted":false}}]}`,
			wantStatus: backend.ResolutionUnavailable, wantDiagnostic: backend.ResolutionUnavailable,
		},
		{
			name: "table and watchlist both verified", watchlists: `{"value":[{"id":"/watchlists/vip","properties":{"watchlistAlias":"VIPUsers","provisioningState":"Succeeded","isDeleted":false}}]}`,
			logs:      `{"tables":[{"name":"PrimaryResult","columns":[],"rows":[]}],"permissions":{"dataSources":[{"allowTables":["Watchlist"]}]},"dataSources":[{"tables":["Watchlist"]}]}`,
			withTable: true, wantStatus: backend.ResolutionResolved, wantDiagnostic: backend.ResolutionResolved, wantQueries: 2,
		},
		{
			name: "permission evidence omitted", watchlists: `{"value":[{"id":"/watchlists/vip","properties":{"watchlistAlias":"VIPUsers","provisioningState":"Succeeded","isDeleted":false}}]}`,
			logs:       `{"tables":[{"name":"PrimaryResult","columns":[],"rows":[]}],"dataSources":[{"tables":["Watchlist"]}]}`,
			wantStatus: backend.ResolutionUnavailable, wantDiagnostic: backend.ResolutionUnavailable, wantQueries: 1,
		},
		{
			name: "permission explicitly denied", watchlists: `{"value":[{"id":"/watchlists/vip","properties":{"watchlistAlias":"VIPUsers","provisioningState":"Succeeded","isDeleted":false}}]}`,
			logs:       `{"tables":[{"name":"PrimaryResult","columns":[],"rows":[]}],"permissions":{"dataSources":[{"allowTables":["Watchlist"],"denyTables":["Watchlist"]}]},"dataSources":[{"tables":["Watchlist"]}]}`,
			wantStatus: backend.ResolutionUnavailable, wantDiagnostic: backend.ResolutionUnavailable, wantQueries: 1,
		},
		{
			name: "unrelated allowed table", watchlists: `{"value":[{"id":"/watchlists/vip","properties":{"watchlistAlias":"VIPUsers","provisioningState":"Succeeded","isDeleted":false}}]}`,
			logs:       `{"tables":[{"name":"PrimaryResult","columns":[],"rows":[]}],"permissions":{"dataSources":[{"allowTables":["SecurityEvent"]}]},"dataSources":[{"tables":["SecurityEvent"]}]}`,
			wantStatus: backend.ResolutionUnavailable, wantDiagnostic: backend.ResolutionUnavailable, wantQueries: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			credential := &recordingCredential{}
			var queries atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, "/tables"):
					if tt.withTable {
						fmt.Fprint(w, `{"value":[{"name":"SecurityEvent","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"standardColumns":[]}}}]}`)
					} else {
						fmt.Fprint(w, `{"value":[]}`)
					}
				case strings.HasSuffix(r.URL.Path, "/watchlists"):
					fmt.Fprint(w, tt.watchlists)
				case strings.HasSuffix(r.URL.Path, "/query"):
					queries.Add(1)
					var request logsQueryRequest
					if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
						t.Error(err)
					}
					if strings.Contains(request.Query, "_GetWatchlist") {
						fmt.Fprint(w, tt.logs)
					} else {
						writeAllowedLogsResult(w, "SecurityEvent", `[{"name":"PrimaryResult","columns":[],"rows":[]}]`)
					}
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			client := fixtureClient(server.URL, credential)
			rule := backend.Rule{ID: "watchlist-rule", Enabled: true, Dependencies: []backend.DependencyRef{{
				ID: "sentinel_watchlist:vipusers", Name: "VIPUsers", Kind: "sentinel_watchlist", Required: true,
			}}}
			if tt.withTable {
				rule.Patterns = []string{"SecurityEvent"}
			}
			got, err := client.ResolveInputs(context.Background(), []backend.Rule{rule})
			if err != nil {
				t.Fatal(err)
			}
			wantCount := 2
			if tt.withTable {
				wantCount = 3
			}
			if len(got) != wantCount || got[0].Status != tt.wantStatus {
				t.Fatalf("resolutions = %#v", got)
			}
			watchlistDiagnostic := got[len(got)-1]
			if watchlistDiagnostic.Status != tt.wantDiagnostic || watchlistDiagnostic.SelectorKind != "sentinel_watchlist" || !strings.Contains(watchlistDiagnostic.ResolutionMethod, "watchlists") {
				t.Fatalf("watchlist diagnostic identity = %#v", watchlistDiagnostic)
			}
			if len(watchlistDiagnostic.ResolvedDependencies) != 1 {
				t.Fatalf("watchlist diagnostic omitted dependency evidence: %#v", watchlistDiagnostic.ResolvedDependencies)
			}
			dependency := watchlistDiagnostic.ResolvedDependencies[0]
			if dependency.Expression != "" || dependency.Name != "VIPUsers" || dependency.Kind != "sentinel_watchlist" {
				t.Fatalf("watchlist diagnostic dependency was not sanitized: %#v", dependency)
			}
			if (tt.name == "missing after complete inventory" || tt.name == "permission explicitly denied") && dependency.ID != "sentinel_watchlist:vipusers" {
				t.Fatalf("missing/denied watchlist lost stable dependency identity: %#v", dependency)
			}
			if tt.wantStatus == backend.ResolutionResolved && len(got[0].ResolvedDependencies) != 1 {
				t.Fatalf("authoritative resolved dependencies = %#v", got[0].ResolvedDependencies)
			}
			if queries.Load() != tt.wantQueries {
				t.Fatalf("query count = %d, want %d", queries.Load(), tt.wantQueries)
			}
		})
	}
}

func TestResolveInputsASIMNativeProbe(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		expression  string
		response    func(string) string
		wantStatus  backend.ResolutionStatus
		wantQueries int32
	}{
		{
			name: "clean local dependency", expression: `_Im_Dns(starttime=ago(1d))`, wantStatus: backend.ResolutionResolved, wantQueries: 1,
			response: func(resourceID string) string {
				return fmt.Sprintf(`{"tables":[{"name":"PrimaryResult","columns":[],"rows":[]}],"permissions":{"dataSources":[{"resourceId":%q,"allowTables":["SecurityEvent"]}]},"dataSources":[{"resourceId":%q,"workspace":"workspace-id","tables":["SecurityEvent"]}]}`, resourceID, resourceID)
			},
		},
		{
			name: "known semantic partial result", expression: `_Im_Dns()`, wantStatus: backend.ResolutionUnsupported, wantQueries: 1,
			response: func(string) string { return liveASIMSemanticPartialResponse() },
		},
		{
			name: "semantic partial result with top-level inner error", expression: `_Im_Dns()`, wantStatus: backend.ResolutionUnavailable, wantQueries: 1,
			response: func(string) string {
				return `{"error":{"code":"PartialError","message":"There were some errors when processing your query.","innererror":{"code":"UnexpectedOuterError","message":"unexpected outer error"},"details":[{"code":"EngineError","message":"Something went wrong processing your query on the server.","innererror":{"code":"-2133196790","message":"'union' operator: Failed to resolve tabular function named '_Im_WebSession'","severity":3,"severityName":"Warning"}}]},"tables":[]}`
			},
		},
		{
			name: "arbitrary runtime partial result", expression: `_Im_Dns()`, wantStatus: backend.ResolutionUnavailable, wantQueries: 1,
			response: func(string) string {
				return `{"error":{"code":"PartialError","message":"one shard failed","details":[{"code":"EngineError","innererror":{"code":"RuntimeFailure","message":"one shard failed","severity":2,"severityName":"Error"}}]},"tables":[]}`
			},
		},
		{
			name: "unknown catalog table", expression: `_Im_Dns()`, wantStatus: backend.ResolutionUnsupported, wantQueries: 1,
			response: func(resourceID string) string {
				return fmt.Sprintf(`{"tables":[{"name":"PrimaryResult","columns":[],"rows":[]}],"permissions":{"dataSources":[{"resourceId":%q,"allowTables":["Unknown_CL"]}]},"dataSources":[{"resourceId":%q,"tables":["Unknown_CL"]}]}`, resourceID, resourceID)
			},
		},
		{
			name: "nonlocal data source", expression: `_Im_Dns()`, wantStatus: backend.ResolutionUnavailable, wantQueries: 1,
			response: func(string) string {
				return `{"tables":[{"name":"PrimaryResult","columns":[],"rows":[]}],"permissions":{"dataSources":[{"resourceId":"/subscriptions/other/resourcegroups/rg/providers/microsoft.operationalinsights/workspaces/remote","allowTables":["SecurityEvent"]}]},"dataSources":[{"resourceId":"/subscriptions/other/resourcegroups/rg/providers/microsoft.operationalinsights/workspaces/remote","tables":["SecurityEvent"]}]}`
			},
		},
		{
			name: "dynamic call rejected before query", expression: "", wantStatus: backend.ResolutionUnsupported,
			response: func(string) string { return "" },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			credential := &recordingCredential{}
			var queries atomic.Int32
			var client *Client
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, "/tables"):
					fmt.Fprint(w, `{"value":[{"name":"SecurityEvent","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"standardColumns":[]}}}]}`)
				case strings.HasSuffix(r.URL.Path, "/query"):
					queries.Add(1)
					fmt.Fprint(w, tt.response(canonicalWorkspaceResourceID(client.SubscriptionID, client.ResourceGroup, client.WorkspaceName)))
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			client = fixtureClient(server.URL, credential)
			rule := backend.Rule{ID: "asim-rule", Enabled: true, Dependencies: []backend.DependencyRef{{
				ID: "sentinel_asim_parser:_im_dns", Name: "_Im_Dns", Kind: "sentinel_asim_parser", Required: true, Expression: tt.expression,
			}}}
			got, err := client.ResolveInputs(context.Background(), []backend.Rule{rule})
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 2 || got[0].Status != tt.wantStatus || got[1].Status != tt.wantStatus {
				t.Fatalf("resolutions = %#v", got)
			}
			if got[1].SelectorKind != "sentinel_asim_parser" || !strings.Contains(got[1].ResolutionMethod, "asim_native_probe") {
				t.Fatalf("ASIM diagnostic identity = %#v", got[1])
			}
			if tt.wantStatus == backend.ResolutionResolved {
				if !reflect.DeepEqual(got[0].ResolvedSources, []string{"SecurityEvent"}) || len(got[0].ResolvedDependencies) != 1 || len(got[1].ResolvedDependencies) != 1 {
					t.Fatalf("resolved ASIM evidence = %#v", got)
				}
			} else if len(got[0].ResolvedSources) != 0 || len(got[0].ResolvedDependencies) != 0 || len(got[1].ResolvedSources) != 0 || len(got[1].ResolvedDependencies) != 1 {
				t.Fatalf("non-resolved ASIM outcome lost diagnostic identity or leaked authoritative evidence = %#v", got)
			}
			if got[1].ResolvedDependencies[0].Expression != "" || got[1].ResolvedDependencies[0].ID != "sentinel_asim_parser:_im_dns" {
				t.Fatalf("ASIM diagnostic dependency was not sanitized: %#v", got[1].ResolvedDependencies[0])
			}
			if queries.Load() != tt.wantQueries {
				t.Fatalf("query count = %d, want %d", queries.Load(), tt.wantQueries)
			}
		})
	}
}

func TestResolveInputsASIMProbeIsCachedAcrossRules(t *testing.T) {
	credential := &recordingCredential{}
	var queries atomic.Int32
	var client *Client
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/tables"):
			fmt.Fprint(w, `{"value":[{"name":"SecurityEvent","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"standardColumns":[]}}}]}`)
		case strings.HasSuffix(r.URL.Path, "/query"):
			queries.Add(1)
			resourceID := canonicalWorkspaceResourceID(client.SubscriptionID, client.ResourceGroup, client.WorkspaceName)
			fmt.Fprintf(w, `{"tables":[{"name":"PrimaryResult","columns":[],"rows":[]}],"permissions":{"dataSources":[{"resourceId":%q}]},"dataSources":[{"resourceId":%q,"tables":["SecurityEvent"]}]}`, resourceID, resourceID)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client = fixtureClient(server.URL, credential)
	dependency := backend.DependencyRef{ID: "sentinel_asim_parser:_im_dns", Name: "_Im_Dns", Kind: "sentinel_asim_parser", Required: true, Expression: `_Im_Dns()`}
	rules := []backend.Rule{
		{ID: "asim-a", Enabled: true, Dependencies: []backend.DependencyRef{dependency}},
		{ID: "asim-b", Enabled: true, Dependencies: []backend.DependencyRef{dependency}},
	}
	got, err := client.ResolveInputs(context.Background(), rules)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 || got[0].Status != backend.ResolutionResolved || got[2].Status != backend.ResolutionResolved || queries.Load() != 1 {
		t.Fatalf("cached probe resolutions/queries = %#v/%d", got, queries.Load())
	}
}

func TestWatchlistProbeIsCachedWithinScan(t *testing.T) {
	credential := &recordingCredential{}
	var inventoryCalls atomic.Int32
	var queryCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/watchlists"):
			inventoryCalls.Add(1)
			fmt.Fprint(w, `{"value":[{"id":"/watchlists/vip","properties":{"watchlistAlias":"VIPUsers","provisioningState":"Succeeded","isDeleted":false}}]}`)
		case strings.HasSuffix(r.URL.Path, "/query"):
			queryCalls.Add(1)
			fmt.Fprint(w, `{"tables":[{"name":"PrimaryResult","columns":[],"rows":[]}],"permissions":{"dataSources":[{}]},"dataSources":[{"tables":["Watchlist"]}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := fixtureClient(server.URL, credential)
	dependency := backend.DependencyRef{ID: "sentinel_watchlist:vipusers", Name: "VIPUsers", Kind: "sentinel_watchlist", Required: true}
	first := client.probeWatchlistDependency(context.Background(), dependency)
	second := client.probeWatchlistDependency(context.Background(), dependency)
	if first.status != backend.ResolutionResolved || second.status != backend.ResolutionResolved || inventoryCalls.Load() != 1 || queryCalls.Load() != 1 {
		t.Fatalf("cached watchlist probes = %#v/%#v, calls %d/%d", first, second, inventoryCalls.Load(), queryCalls.Load())
	}
}

func TestRulesFollowsOpaquePaginationAndPreservesUnknownKinds(t *testing.T) {
	credential := &recordingCredential{}
	var server *httptest.Server
	var requests []string
	var mu sync.Mutex
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests = append(requests, r.URL.RequestURI())
		mu.Unlock()
		if got := r.Header.Get("Authorization"); got != "Bearer fixture-token" {
			t.Errorf("Authorization = %q", got)
		}
		switch r.URL.Path {
		case "/v1/workspaces/workspace-id/metadata":
			if r.Method != http.MethodPost {
				t.Errorf("metadata method = %s, want POST", r.Method)
			}
			fmt.Fprint(w, `{"functions":[{"name":"NormalizedSecurityEvent","body":"SecurityEvent | where EventID != 0","parameters":""}]}`)
		case "/subscriptions/sub-id/resourceGroups/rg-lab/providers/Microsoft.OperationalInsights/workspaces/law-lab/providers/Microsoft.SecurityInsights/alertRules":
			if r.Method != http.MethodGet {
				t.Errorf("rules method = %s, want GET", r.Method)
			}
			switch got := r.URL.Query().Get("api-version"); got {
			case alertRulesAPIVersion:
				fmt.Fprintf(w, `{"value":[{"id":"/subscriptions/sub-id/rules/rule-a","name":"rule-a","kind":"Scheduled","properties":{"displayName":"Failed logon","enabled":true,"severity":"High","query":"NormalizedSecurityEvent | where EventID == 4625","queryFrequency":"PT5M","queryPeriod":"PT10M"}}],"nextLink":%q}`, server.URL+"/opaque/next?cursor=a%2Fb&api-version=2025-09-01")
			case alertRulesPreviewAPIVersion:
				fmt.Fprint(w, `{"value":[]}`)
			default:
				t.Errorf("api-version = %q", got)
			}
		case "/opaque/next":
			if r.Method != http.MethodGet {
				t.Errorf("rules page method = %s, want GET", r.Method)
			}
			if r.URL.RawQuery != "cursor=a%2Fb&api-version=2025-09-01" {
				t.Errorf("opaque nextLink query = %q", r.URL.RawQuery)
			}
			fmt.Fprint(w, `{"value":[{"id":"/subscriptions/sub-id/rules/rule-b","name":"rule-b","kind":"Fusion","properties":{"displayName":"Fusion incidents","severity":"Medium"}},{"id":"/subscriptions/sub-id/rules/rule-c","name":"rule-c","kind":"Scheduled","properties":{"displayName":"Disabled rule","enabled":false,"severity":"Informational","query":"SigninLogs | take 1","queryFrequency":"PT1H","queryPeriod":"P1DT30M"}}]}`)
		default:
			http.NotFound(w, r)
		}
	})
	server = httptest.NewServer(handler)
	defer server.Close()

	rules, err := fixtureClient(server.URL, credential).Rules(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 3 {
		t.Fatalf("rules = %+v", rules)
	}
	first := rules[0]
	if first.ID != "rule-a" || first.BackendObjectID != "/subscriptions/sub-id/rules/rule-a" || first.Name != "Failed logon" {
		t.Fatalf("scheduled rule identity = %+v", first)
	}
	if first.Severity != "high" || first.RiskScore != 73 || first.Interval != 5*time.Minute || first.Lookback != 10*time.Minute {
		t.Fatalf("scheduled rule metadata = %+v", first)
	}
	if fmt.Sprint(first.Patterns) != "[SecurityEvent]" || first.InputStatus != "" {
		t.Fatalf("scheduled rule dependencies = %+v", first)
	}
	unknown := rules[1]
	if !unknown.Enabled || unknown.RuleType != "fusion" || unknown.InputStatus != backend.ResolutionUnsupported || !strings.Contains(unknown.InputDetail, "Fusion") {
		t.Fatalf("unknown rule kind = %+v", unknown)
	}
	disabled := rules[2]
	if disabled.Enabled || disabled.Severity != "low" || disabled.Lookback != 24*time.Hour+30*time.Minute {
		t.Fatalf("disabled scheduled rule = %+v", disabled)
	}
	if !credential.sawScope(armScope) {
		t.Fatalf("credential scopes = %v, want %s", credential.scopes, armScope)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(requests) != 4 {
		t.Fatalf("requests = %v", requests)
	}
}

func TestRulesInventoriesPreviewNRTWithPaginationAndCaseFoldedDeduplication(t *testing.T) {
	credential := &recordingCredential{}
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/workspaces/workspace-id/metadata":
			fmt.Fprint(w, `{"functions":[]}`)
		case "/subscriptions/sub-id/resourceGroups/rg-lab/providers/Microsoft.OperationalInsights/workspaces/law-lab/providers/Microsoft.SecurityInsights/alertRules":
			switch r.URL.Query().Get("api-version") {
			case alertRulesAPIVersion:
				fmt.Fprint(w, `{"value":[
					{"id":"/rules/scheduled","name":"scheduled","kind":"Scheduled","properties":{"enabled":true,"query":"SigninLogs | take 1","queryFrequency":"PT5M","queryPeriod":"PT10M"}},
					{"id":"/rules/nrt-ignored-ga","name":"nrt-ignored-ga","kind":"NRT","properties":{"enabled":true,"query":"IgnoredTable | take 1"}}
				]}`)
			case alertRulesPreviewAPIVersion:
				fmt.Fprintf(w, `{"value":[
					{"id":"/RULES/NRT-A","name":"NRT-A","kind":"NRT","properties":{"displayName":"Near real time A","enabled":true,"severity":"High","query":"SecurityEvent | take 1"}},
					{"id":"/rules/preview-scheduled","name":"preview-scheduled","kind":"Scheduled","properties":{"enabled":true,"query":"IgnoredPreviewTable | take 1"}}
				],"nextLink":%q}`, server.URL+"/nrt/next?cursor=nrt%2Fa&api-version="+alertRulesPreviewAPIVersion)
			default:
				http.Error(w, "unexpected API version", http.StatusBadRequest)
			}
		case "/nrt/next":
			if got := r.URL.RawQuery; got != "cursor=nrt%2Fa&api-version="+alertRulesPreviewAPIVersion {
				t.Errorf("preview nextLink query = %q", got)
			}
			fmt.Fprint(w, `{"value":[
				{"id":"/rules/nrt-a","name":"nrt-a","kind":"NRT","properties":{"enabled":true,"query":"DuplicateTable | take 1"}},
				{"id":"/rules/nrt-b","name":"nrt-b","kind":"NRT","properties":{"enabled":true,"query":"CommonSecurityLog | take 1"}}
			]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	rules, err := fixtureClient(server.URL, credential).Rules(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 3 {
		t.Fatalf("rules = %+v", rules)
	}
	if rules[0].RuleType != "scheduled" || fmt.Sprint(rules[0].Patterns) != "[SigninLogs]" {
		t.Fatalf("GA scheduled rule = %+v", rules[0])
	}
	for i, want := range []string{"SecurityEvent", "CommonSecurityLog"} {
		rule := rules[i+1]
		if rule.RuleType != "nrt" || rule.Interval != time.Minute || rule.Lookback != time.Minute ||
			rule.TimestampOverride != "ingestion_time()" || fmt.Sprint(rule.Patterns) != "["+want+"]" {
			t.Fatalf("NRT rule %d = %+v", i, rule)
		}
	}
}

func TestRulesRejectMissingEnabledState(t *testing.T) {
	for _, tt := range []struct {
		name       string
		kind       string
		apiVersion string
		rule       string
	}{
		{name: "Scheduled", kind: "Scheduled", apiVersion: alertRulesAPIVersion, rule: "missing-scheduled"},
		{name: "NRT", kind: "NRT", apiVersion: alertRulesPreviewAPIVersion, rule: "missing-nrt"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, "/metadata"):
					fmt.Fprint(w, `{"functions":[]}`)
				case strings.HasSuffix(r.URL.Path, "/alertRules"):
					if r.URL.Query().Get("api-version") != tt.apiVersion {
						fmt.Fprint(w, `{"value":[]}`)
						return
					}
					fmt.Fprintf(w, `{"value":[{"id":"/rules/%s","name":%q,"kind":%q,"properties":{"displayName":"Missing enabled state","query":"SecurityEvent | take 1","queryFrequency":"PT5M","queryPeriod":"PT10M"}}]}`,
						tt.rule, tt.rule, tt.kind)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()

			rules, err := fixtureClient(server.URL, &recordingCredential{}).Rules(context.Background())
			if err == nil {
				t.Fatalf("missing enabled state returned rules: %+v", rules)
			}
			for _, want := range []string{"invalid Sentinel rule inventory", tt.kind, tt.rule, "properties.enabled"} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("inventory error %q does not contain %q", err, want)
				}
			}
		})
	}
}

func TestRulesFailsWhenPreviewNRTInventoryFails(t *testing.T) {
	credential := &recordingCredential{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/metadata"):
			fmt.Fprint(w, `{"functions":[]}`)
		case r.URL.Query().Get("api-version") == alertRulesAPIVersion:
			fmt.Fprint(w, `{"value":[]}`)
		case r.URL.Query().Get("api-version") == alertRulesPreviewAPIVersion:
			w.Header().Set("Retry-After", "0")
			http.Error(w, "preview unavailable", http.StatusServiceUnavailable)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	_, err := fixtureClient(server.URL, credential).Rules(context.Background())
	if err == nil || !strings.Contains(err.Error(), alertRulesPreviewAPIVersion) {
		t.Fatalf("Rules() error = %v, want preview inventory failure", err)
	}
}

func TestSentinelRuleSeparatesRequiredAndFuzzyUnionPatterns(t *testing.T) {
	raw := alertRuleJSON{Name: "fuzzy-rule", Kind: "Scheduled"}
	enabled := true
	raw.Properties.Enabled = &enabled
	raw.Properties.DisplayName = "Fuzzy rule"
	raw.Properties.Query = `SecurityEvent | union isfuzzy=true SigninLogs, AuditLogs`
	raw.Properties.QueryFrequency = "PT5M"
	raw.Properties.QueryPeriod = "PT10M"
	rule := sentinelRule(raw, map[string]WorkspaceFunction{}, true)
	if !reflect.DeepEqual(rule.Patterns, []string{"SecurityEvent"}) ||
		!reflect.DeepEqual(rule.OptionalPatterns, []string{"SigninLogs", "AuditLogs"}) ||
		rule.InputStatus != "" {
		t.Fatalf("fuzzy installed rule = %+v", rule)
	}
}

func TestRulesRejectsPaginationCycleAndForeignHost(t *testing.T) {
	credential := &recordingCredential{}
	t.Run("cycle", func(t *testing.T) {
		var server *httptest.Server
		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprintf(w, `{"value":[],"nextLink":%q}`, server.URL+"/subscriptions/sub-id/resourceGroups/rg-lab/providers/Microsoft.OperationalInsights/workspaces/law-lab/providers/Microsoft.SecurityInsights/alertRules?api-version="+alertRulesAPIVersion)
		}))
		defer server.Close()
		_, err := fixtureClient(server.URL, credential).Rules(context.Background())
		if err == nil || !strings.Contains(err.Error(), "cycle") {
			t.Fatalf("Rules() error = %v, want pagination cycle", err)
		}
	})
	t.Run("foreign nextLink", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprint(w, `{"value":[],"nextLink":"https://example.invalid/steal"}`)
		}))
		defer server.Close()
		_, err := fixtureClient(server.URL, credential).Rules(context.Background())
		if err == nil || !strings.Contains(err.Error(), "outside") {
			t.Fatalf("Rules() error = %v, want foreign nextLink rejection", err)
		}
	})
}

func TestARMRetryHonorsRetryAfterFor429And503(t *testing.T) {
	credential := &recordingCredential{}
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := calls.Add(1)
		if call <= 2 {
			w.Header().Set("Retry-After", "0")
			if call == 1 {
				http.Error(w, "slow down", http.StatusTooManyRequests)
			} else {
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
			}
			return
		}
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer server.Close()
	client := fixtureClient(server.URL, credential)
	var response struct {
		OK bool `json:"ok"`
	}
	if err := client.doARM(context.Background(), server.URL+"/resource", &response); err != nil {
		t.Fatal(err)
	}
	if !response.OK || calls.Load() != 3 {
		t.Fatalf("response/calls = %+v/%d", response, calls.Load())
	}
}

func TestTablesPaginationAndEligibility(t *testing.T) {
	credential := &recordingCredential{}
	var server *httptest.Server
	var requestsMu sync.Mutex
	var requests []string
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestsMu.Lock()
		requests = append(requests, r.URL.RequestURI())
		requestsMu.Unlock()
		switch r.URL.Path {
		case "/subscriptions/sub-id/resourceGroups/rg-lab/providers/Microsoft.OperationalInsights/workspaces/law-lab/tables":
			fmt.Fprintf(w, `{"value":[
				{"name":"SecurityEvent","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"standardColumns":[{"name":"TimeGenerated","type":"datetime"}]}}},
				{"name":"AuxiliaryTable","properties":{"plan":"Auxiliary","provisioningState":"Succeeded","schema":{"standardColumns":[{"name":"TimeGenerated","type":"datetime"}]}}},
				{"name":"BasicTable_CL","properties":{"plan":"Basic","provisioningState":"Succeeded","schema":{"standardColumns":[{"name":"TimeGenerated","type":"datetime"}]}}}
			],"nextLink":%q}`, server.URL+"/tables/next?cursor=a%2Fb&api-version="+tablesAPIVersion)
		case "/tables/next":
			if r.URL.RawQuery != "cursor=a%2Fb&api-version="+tablesAPIVersion {
				t.Errorf("opaque table nextLink query = %q", r.URL.RawQuery)
			}
			fmt.Fprint(w, `{"value":[
				{"name":"UpdatingTable","properties":{"plan":"Analytics","provisioningState":"Updating","schema":{"standardColumns":[{"name":"TimeGenerated","type":"datetime"}]}}}
			]}`)
		case "/v1/workspaces/workspace-id/query":
			if got := r.Header.Get("Prefer"); !strings.Contains(got, "include-permissions=true") || !strings.Contains(got, "include-dataSources=true") {
				t.Errorf("Prefer = %q", got)
			}
			var request logsQueryRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if request.Query != "SecurityEvent | take 0" {
				t.Errorf("permission probe = %q", request.Query)
			}
			writeAllowedLogsResult(w, "SecurityEvent", `[{"name":"PrimaryResult","columns":[],"rows":[]}]`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := fixtureClient(server.URL, credential)
	sources, err := client.Sources(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 4 {
		t.Fatalf("paginated sources = %+v", sources)
	}
	resolutions, err := client.ResolveInputs(context.Background(), []backend.Rule{{
		ID: "plans", Enabled: true, Patterns: []string{"SecurityEvent", "AuxiliaryTable", "BasicTable_CL", "UpdatingTable"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(resolutions) != 5 || resolutions[0].Diagnostic || resolutions[0].Status != backend.ResolutionUnavailable ||
		!resolutions[1].Diagnostic || resolutions[1].Status != backend.ResolutionResolved ||
		resolutions[2].Status != backend.ResolutionIncompatible ||
		resolutions[3].Status != backend.ResolutionIncompatible ||
		resolutions[4].Status != backend.ResolutionUnavailable {
		t.Fatalf("plan/provisioning resolutions = %+v", resolutions)
	}
	incompatible, err := client.ResolveInputs(context.Background(), []backend.Rule{{
		ID: "incompatible", Enabled: true, Patterns: []string{"AuxiliaryTable", "BasicTable_CL"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(incompatible) != 3 || incompatible[0].Diagnostic || incompatible[0].Status != backend.ResolutionIncompatible ||
		!incompatible[1].Diagnostic || incompatible[1].Status != backend.ResolutionIncompatible ||
		!incompatible[2].Diagnostic || incompatible[2].Status != backend.ResolutionIncompatible {
		t.Fatalf("all-incompatible resolution = %+v", incompatible)
	}
	requestsMu.Lock()
	defer requestsMu.Unlock()
	if len(requests) != 3 {
		t.Fatalf("table page requests = %v", requests)
	}
}

func TestTablesPaginationRejectsCyclesAndForeignHosts(t *testing.T) {
	credential := &recordingCredential{}
	t.Run("cycle", func(t *testing.T) {
		var server *httptest.Server
		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprintf(w, `{"value":[],"nextLink":%q}`, server.URL+"/subscriptions/sub-id/resourceGroups/rg-lab/providers/Microsoft.OperationalInsights/workspaces/law-lab/tables?api-version="+tablesAPIVersion)
		}))
		defer server.Close()
		_, err := fixtureClient(server.URL, credential).Sources(context.Background())
		if err == nil || !strings.Contains(err.Error(), "cycle") {
			t.Fatalf("Sources() error = %v, want table pagination cycle", err)
		}
	})
	t.Run("foreign nextLink", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprint(w, `{"value":[],"nextLink":"https://example.invalid/steal"}`)
		}))
		defer server.Close()
		_, err := fixtureClient(server.URL, credential).Sources(context.Background())
		if err == nil || !strings.Contains(err.Error(), "outside") {
			t.Fatalf("Sources() error = %v, want foreign nextLink rejection", err)
		}
	})
}

func TestSourcesSchemasFieldsAndResolution(t *testing.T) {
	credential := &recordingCredential{}
	var tableCalls atomic.Int32
	var logsCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fixture-token" {
			t.Errorf("missing bearer token")
		}
		if strings.HasSuffix(r.URL.Path, "/tables") {
			tableCalls.Add(1)
			if r.Method != http.MethodGet {
				t.Errorf("tables method = %s", r.Method)
			}
			fmt.Fprint(w, `{"value":[
				{"name":"SecurityEvent","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"columns":null,"standardColumns":[{"name":"TimeGenerated","type":"datetime"},{"name":"EventID","type":"int"},{"name":"Computer","type":"string"}]}}},
				{"name":"SigninLogs","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"columns":[{"name":"TimeGenerated","type":"datetime"},{"name":"UserPrincipalName","type":"string"}]}}},
				{"name":"MetadataOnly","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"columns":[{"name":"Name","type":"string"}]}}},
				{"name":"SchemaUnavailable","properties":{"plan":"Analytics","provisioningState":"Succeeded"}}
			]}`)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/query") {
			if got := r.Header.Get("Prefer"); !strings.Contains(got, "include-permissions=true") || !strings.Contains(got, "include-dataSources=true") {
				t.Errorf("Prefer = %q", got)
			}
			logsCalls.Add(1)
			var request logsQueryRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if request.Query != "SecurityEvent | take 0" {
				t.Errorf("unexpected query %q", request.Query)
			}
			writeAllowedLogsResult(w, "SecurityEvent", `[{"name":"PrimaryResult","columns":[],"rows":[]}]`)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	client := fixtureClient(server.URL, credential)

	sources, err := client.Sources(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := logsCalls.Load(); got != 0 {
		t.Fatalf("Sources issued %d Logs queries, want ARM metadata only", got)
	}
	if len(sources) != 4 || sources[0].Name != "MetadataOnly" || sources[3].Name != "SigninLogs" {
		t.Fatalf("sorted sources = %+v", sources)
	}
	byName := make(map[string]backend.Source, len(sources))
	for _, source := range sources {
		byName[source.Name] = source
		if source.Docs != -1 {
			t.Errorf("%s Docs = %d, want unknown", source.Name, source.Docs)
		}
	}
	for name, source := range byName {
		if !source.LastEvent.IsZero() {
			t.Errorf("ARM-only source %s has runtime freshness %v", name, source.LastEvent)
		}
	}

	schemas, err := client.Schemas(context.Background(), sources)
	if err != nil {
		t.Fatal(err)
	}
	if len(schemas) != 3 || len(schemas["SecurityEvent"].Fields) != 3 {
		t.Fatalf("schemas = %+v", schemas)
	}
	if _, ok := schemas["SchemaUnavailable"]; ok {
		t.Fatal("omitted ARM schema must remain unavailable")
	}

	fields, err := client.RequiredFieldEvidence(context.Background(), []backend.Source{{Name: "SecurityEvent"}, {Name: "SchemaUnavailable"}, {Name: "MissingTable"}}, []string{"Computer", "MissingField"})
	if err != nil {
		t.Fatal(err)
	}
	if got := fields["SecurityEvent"]; got.Status != backend.EvidenceAssessed || !got.Fields["Computer"] || got.Fields["MissingField"] {
		t.Fatalf("SecurityEvent fields = %+v", got)
	}
	for _, name := range []string{"SchemaUnavailable", "MissingTable"} {
		if fields[name].Status != backend.EvidenceIncomplete {
			t.Errorf("%s field evidence = %+v", name, fields[name])
		}
	}

	rules := []backend.Rule{
		{
			ID: "mixed", Enabled: true, Patterns: []string{"SecurityEvent", "SecurityEvent"},
			OptionalPatterns: []string{"MissingTable"},
		},
		{ID: "unknown", Enabled: true, InputStatus: backend.ResolutionUnsupported, InputDetail: "function call"},
	}
	resolutions, err := client.ResolveInputs(context.Background(), rules)
	if err != nil {
		t.Fatal(err)
	}
	if len(resolutions) != 4 || resolutions[0].Diagnostic || resolutions[0].Status != backend.ResolutionResolved ||
		fmt.Sprint(resolutions[0].ResolvedSources) != "[SecurityEvent]" || !resolutions[1].Diagnostic ||
		resolutions[1].Status != backend.ResolutionResolved || !resolutions[2].Diagnostic ||
		resolutions[2].Status != backend.ResolutionEmpty || resolutions[3].Status != backend.ResolutionUnsupported {
		t.Fatalf("resolutions = %+v", resolutions)
	}
	if resolutions[0].Expression != "SecurityEvent,MissingTable" {
		t.Fatalf("authoritative expression was not deduplicated: %+v", resolutions[0])
	}
	g := graph.BuildResolved(rules, sources, resolutions)
	if got := fmt.Sprint(g.SourcesFor("mixed")); got != "[SecurityEvent]" {
		t.Fatalf("mixed graph edges = %s, want only the resolved source", got)
	}
	if tableCalls.Load() != 1 {
		t.Fatalf("table inventory calls = %d, want cached single call", tableCalls.Load())
	}
	if logsCalls.Load() != 1 || !credential.sawScope(logsScope) {
		t.Fatalf("permission probe calls/scope = %d/%v", logsCalls.Load(), credential.sawScope(logsScope))
	}
}

func TestFunctionMetadataFailureMakesOnlyCatalogMissesUnavailable(t *testing.T) {
	credential := &recordingCredential{}
	var queryCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/metadata"):
			http.Error(w, "metadata forbidden", http.StatusForbidden)
		case strings.HasSuffix(r.URL.Path, "/alertRules") && r.URL.Query().Get("api-version") == alertRulesAPIVersion:
			fmt.Fprint(w, `{"value":[
				{"id":"/rules/known","name":"known","kind":"Scheduled","properties":{"enabled":true,"query":"KnownTable | take 1","queryFrequency":"PT5M","queryPeriod":"PT10M"}},
				{"id":"/rules/alias","name":"alias","kind":"Scheduled","properties":{"enabled":true,"query":"ParserAlias | take 1","queryFrequency":"PT5M","queryPeriod":"PT10M"}}
			]}`)
		case strings.HasSuffix(r.URL.Path, "/alertRules") && r.URL.Query().Get("api-version") == alertRulesPreviewAPIVersion:
			fmt.Fprint(w, `{"value":[]}`)
		case strings.HasSuffix(r.URL.Path, "/tables"):
			fmt.Fprint(w, `{"value":[{"name":"KnownTable","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"standardColumns":[]}}}]}`)
		case strings.HasSuffix(r.URL.Path, "/query"):
			queryCalls.Add(1)
			writeAllowedLogsResult(w, "KnownTable", `[{"name":"PrimaryResult","columns":[],"rows":[]}]`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := fixtureClient(server.URL, credential)
	rules, err := client.Rules(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 || !rules[0].InputMetadataIncomplete || !rules[1].InputMetadataIncomplete {
		t.Fatalf("rules did not preserve metadata failure: %+v", rules)
	}
	resolutions, err := client.ResolveInputs(context.Background(), rules)
	if err != nil {
		t.Fatal(err)
	}
	if len(resolutions) != 4 || resolutions[0].Status != backend.ResolutionResolved ||
		resolutions[2].Status != backend.ResolutionUnavailable || resolutions[3].Status != backend.ResolutionUnavailable {
		t.Fatalf("metadata-failure resolutions = %+v", resolutions)
	}
	if queryCalls.Load() != 1 {
		t.Fatalf("permission probes = %d, want only the catalog-confirmed table", queryCalls.Load())
	}
}

func TestResolveInputsHonorsRequiredAndFuzzyDependencies(t *testing.T) {
	credential := &recordingCredential{}
	var queryCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/tables"):
			fmt.Fprint(w, `{"value":[
				{"name":"PresentA","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"standardColumns":[]}}},
				{"name":"PresentB","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"standardColumns":[]}}},
				{"name":"PresentDenied","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"standardColumns":[]}}}
			]}`)
		case strings.HasSuffix(r.URL.Path, "/query"):
			queryCalls.Add(1)
			var request logsQueryRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			table := strings.TrimSuffix(request.Query, " | take 0")
			if table == "PresentDenied" {
				fmt.Fprint(w, `{"tables":[{"name":"PrimaryResult","columns":[],"rows":[]}],"permissions":{"dataSources":[{"allowTables":[],"denyTables":["PresentDenied"]}]},"dataSources":[{"tables":["PresentDenied"]}]}`)
				return
			}
			writeAllowedLogsResult(w, table, `[{"name":"PrimaryResult","columns":[],"rows":[]}]`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	rules := []backend.Rule{
		{ID: "required-missing", Enabled: true, Patterns: []string{"PresentA", "MissingRequired"}},
		{
			ID: "fuzzy-partial", Enabled: true,
			Patterns: []string{"PresentA", "PresentA"}, OptionalPatterns: []string{"PresentA", "MissingOptional"},
		},
		{ID: "fuzzy-only", Enabled: true, OptionalPatterns: []string{"PresentB", "MissingOptional"}},
		{ID: "fuzzy-uncertain", Enabled: true, OptionalPatterns: []string{"PresentB", "PresentDenied"}},
	}
	resolutions, err := fixtureClient(server.URL, credential).ResolveInputs(context.Background(), rules)
	if err != nil {
		t.Fatal(err)
	}
	byRule := make(map[string][]backend.InputResolution)
	for _, resolution := range resolutions {
		byRule[resolution.RuleID] = append(byRule[resolution.RuleID], resolution)
	}
	if got := byRule["required-missing"]; len(got) != 3 || got[0].Status != backend.ResolutionEmpty ||
		len(got[0].ResolvedSources) != 0 || got[1].Status != backend.ResolutionResolved || got[2].Status != backend.ResolutionEmpty {
		t.Fatalf("required missing dependency resolved: %+v", got)
	}
	if got := byRule["fuzzy-partial"]; len(got) != 3 || got[0].Status != backend.ResolutionResolved ||
		fmt.Sprint(got[0].ResolvedSources) != "[PresentA]" || got[0].Expression != "PresentA,MissingOptional" ||
		got[2].Status != backend.ResolutionEmpty {
		t.Fatalf("fuzzy partial dependencies = %+v", got)
	}
	if got := byRule["fuzzy-only"]; len(got) != 3 || got[0].Status != backend.ResolutionResolved ||
		fmt.Sprint(got[0].ResolvedSources) != "[PresentB]" || got[2].Status != backend.ResolutionEmpty {
		t.Fatalf("fuzzy-only dependencies = %+v", got)
	}
	if got := byRule["fuzzy-uncertain"]; len(got) != 3 || got[0].Status != backend.ResolutionUnavailable ||
		len(got[0].ResolvedSources) != 0 || got[2].Status != backend.ResolutionUnavailable {
		t.Fatalf("unavailable fuzzy dependency became resolved: %+v", got)
	}
	g := graph.BuildResolved(rules, []backend.Source{{Name: "PresentA"}, {Name: "PresentB"}, {Name: "PresentDenied"}}, resolutions)
	if len(g.SourcesFor("required-missing")) != 0 || fmt.Sprint(g.SourcesFor("fuzzy-partial")) != "[PresentA]" ||
		fmt.Sprint(g.SourcesFor("fuzzy-only")) != "[PresentB]" || len(g.SourcesFor("fuzzy-uncertain")) != 0 {
		t.Fatalf("required/fuzzy graph edges = required %v, partial %v, only %v, uncertain %v",
			g.SourcesFor("required-missing"), g.SourcesFor("fuzzy-partial"), g.SourcesFor("fuzzy-only"), g.SourcesFor("fuzzy-uncertain"))
	}
	if queryCalls.Load() != 3 {
		t.Fatalf("permission probes = %d, want three unique existing tables", queryCalls.Load())
	}
}

func TestFreshnessEvidenceQueriesOnlyRequestedSources(t *testing.T) {
	credential := &recordingCredential{}
	var active atomic.Int32
	var maxActive atomic.Int32
	var queriesMu sync.Mutex
	var queries []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/tables") {
			fmt.Fprint(w, `{"value":[
				{"name":"SecurityEvent","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"standardColumns":[{"name":"TimeGenerated","type":"datetime"}]}}},
				{"name":"SigninLogs","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"standardColumns":[{"name":"TimeGenerated","type":"datetime"}]}}},
				{"name":"EmptyTable","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"standardColumns":[{"name":"TimeGenerated","type":"datetime"}]}}},
				{"name":"MetadataOnly","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"standardColumns":[{"name":"Name","type":"string"}]}}},
				{"name":"UntargetedTable","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"standardColumns":[{"name":"TimeGenerated","type":"datetime"}]}}},
				{"name":"AuxiliaryTable","properties":{"plan":"Auxiliary","provisioningState":"Succeeded","schema":{"standardColumns":[{"name":"TimeGenerated","type":"datetime"}]}}},
				{"name":"BasicTable_CL","properties":{"plan":"Basic","provisioningState":"Succeeded","schema":{"standardColumns":[{"name":"TimeGenerated","type":"datetime"}]}}},
				{"name":"UpdatingTable","properties":{"plan":"Analytics","provisioningState":"Updating","schema":{"standardColumns":[{"name":"TimeGenerated","type":"datetime"}]}}}
			]}`)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/query") {
			if got := r.Header.Get("Prefer"); !strings.Contains(got, "include-permissions=true") || !strings.Contains(got, "include-dataSources=true") {
				t.Errorf("Prefer = %q", got)
			}
			current := active.Add(1)
			for {
				maximum := maxActive.Load()
				if current <= maximum || maxActive.CompareAndSwap(maximum, current) {
					break
				}
			}
			defer active.Add(-1)
			time.Sleep(15 * time.Millisecond)
			var request logsQueryRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			queriesMu.Lock()
			queries = append(queries, request.Query)
			queriesMu.Unlock()
			switch {
			case strings.HasPrefix(request.Query, "SecurityEvent "):
				writeAllowedLogsResult(w, "SecurityEvent", `[{"name":"PrimaryResult","columns":[{"name":"LastEvent","type":"datetime"}],"rows":[["2026-08-20T12:34:56Z"]]}]`)
			case strings.HasPrefix(request.Query, "SigninLogs "):
				fmt.Fprint(w, `{"error":{"code":"PartialError","message":"one shard failed"},"tables":[]}`)
			case strings.HasPrefix(request.Query, "EmptyTable "):
				writeAllowedLogsResult(w, "EmptyTable", `[{"name":"PrimaryResult","columns":[{"name":"LastEvent","type":"datetime"}],"rows":[[null]]}]`)
			case strings.HasPrefix(request.Query, "MetadataOnly "):
				writeAllowedLogsResult(w, "MetadataOnly", `[{"name":"PrimaryResult","columns":[{"name":"LastEvent","type":"datetime"}],"rows":[[null]]}]`)
			default:
				t.Errorf("unexpected freshness query %q", request.Query)
			}
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	client := fixtureClient(server.URL, credential)
	client.Concurrency = 99 // the adapter must still cap query concurrency at two.

	all, err := client.Sources(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 8 {
		t.Fatalf("Sources() = %+v", all)
	}
	evidence, err := client.FreshnessEvidence(context.Background(), []backend.Source{
		{Name: "SecurityEvent"}, {Name: "SigninLogs"}, {Name: "EmptyTable"}, {Name: "MetadataOnly"},
		{Name: "AuxiliaryTable"}, {Name: "BasicTable_CL"}, {Name: "UpdatingTable"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := maxActive.Load(); got > defaultConcurrency {
		t.Fatalf("maximum concurrent freshness queries = %d, want <= %d", got, defaultConcurrency)
	}
	good := evidence["SecurityEvent"]
	if good.Status != backend.EvidenceAssessed || !good.LastEvent.Equal(time.Date(2026, 8, 20, 12, 34, 56, 0, time.UTC)) || good.Window != freshnessWindow || good.Method != "bounded-max-ingestion-time" {
		t.Fatalf("SecurityEvent freshness = %+v", good)
	}
	if evidence["SigninLogs"].Status != backend.EvidenceIncomplete {
		t.Fatalf("failed query freshness = %+v", evidence["SigninLogs"])
	}
	if empty := evidence["EmptyTable"]; empty.Status != backend.EvidenceAssessed || !empty.LastEvent.IsZero() {
		t.Fatalf("empty bounded window freshness = %+v", empty)
	}
	if evidence["MetadataOnly"].Status != backend.EvidenceAssessed {
		t.Fatalf("ingestion-time freshness without TimeGenerated schema = %+v", evidence["MetadataOnly"])
	}
	for _, name := range []string{"AuxiliaryTable", "BasicTable_CL", "UpdatingTable"} {
		if evidence[name].Status != backend.EvidenceUnavailable {
			t.Fatalf("ineligible table %s freshness = %+v", name, evidence[name])
		}
	}
	queriesMu.Lock()
	defer queriesMu.Unlock()
	if len(queries) != 4 {
		t.Fatalf("freshness queries = %v, want only requested queryable sources", queries)
	}
	for _, query := range queries {
		if strings.Contains(query, "UntargetedTable") ||
			strings.Contains(query, "AuxiliaryTable") || strings.Contains(query, "BasicTable_CL") || strings.Contains(query, "UpdatingTable") ||
			!strings.Contains(query, "ago(24h)") || !strings.Contains(query, "max(IngestionTime)") || !strings.Contains(query, "IngestionTime <= now() + 300s") {
			t.Errorf("unexpected or unbounded freshness query %q", query)
		}
	}
}

func TestFreshnessRejectsFutureOutliers(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name   string
		offset time.Duration
		valid  bool
	}{
		{"recent", -time.Minute, true},
		{"small clock skew", time.Minute, true},
		{"clock skew boundary", backend.FreshnessClockSkew, true},
		{"future outlier", 24 * time.Hour, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lastEvent := now.Add(tc.offset)
			var table logsTable
			data := fmt.Sprintf(`{"columns":[{"name":"LastEvent","type":"datetime"}],"rows":[[%q]]}`, lastEvent.Format(time.RFC3339))
			if err := json.Unmarshal([]byte(data), &table); err != nil {
				t.Fatal(err)
			}
			got := freshnessFromTable(table, backend.FreshnessEvidence{ObservedAt: now, Status: backend.EvidenceIncomplete})
			if tc.valid {
				if got.Status != backend.EvidenceAssessed || !got.LastEvent.Equal(lastEvent) {
					t.Fatalf("valid timestamp rejected: %+v", got)
				}
			} else if got.Status != backend.EvidenceIncomplete || !got.LastEvent.IsZero() {
				t.Fatalf("future outlier accepted: %+v", got)
			}
		})
	}
}

func TestRuleAwareFreshnessUsesTheRuleClockAndLeavesSharedSourcesIncomplete(t *testing.T) {
	credential := &recordingCredential{}
	var queries []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/tables") {
			fmt.Fprint(w, `{"value":[
				{"name":"ScheduledTable","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"standardColumns":[{"name":"TimeGenerated","type":"datetime"}]}}},
				{"name":"NRTTable","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"standardColumns":[{"name":"TimeGenerated","type":"datetime"}]}}},
				{"name":"SharedTable","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"standardColumns":[{"name":"TimeGenerated","type":"datetime"}]}}}
			]}`)
			return
		}
		var request logsQueryRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		queries = append(queries, request.Query)
		switch {
		case strings.HasPrefix(request.Query, "ScheduledTable "):
			writeAllowedLogsResult(w, "ScheduledTable", `[{"name":"PrimaryResult","columns":[{"name":"LastEvent","type":"datetime"}],"rows":[["2026-08-10T12:00:00Z"]]}]`)
		case strings.HasPrefix(request.Query, "NRTTable "):
			writeAllowedLogsResult(w, "NRTTable", `[{"name":"PrimaryResult","columns":[{"name":"LastEvent","type":"datetime"}],"rows":[["2026-08-20T12:00:00Z"]]}]`)
		default:
			t.Errorf("unexpected query %q", request.Query)
		}
	}))
	defer server.Close()
	client := fixtureClient(server.URL, credential)
	client.Concurrency = 1
	evidence, err := client.FreshnessEvidenceFor(context.Background(), []backend.FreshnessRequest{
		{Source: backend.Source{Name: "ScheduledTable"}, Basis: backend.FreshnessEventTime},
		{Source: backend.Source{Name: "NRTTable"}, Basis: backend.FreshnessIngestionTime},
		{Source: backend.Source{Name: "SharedTable"}, Basis: backend.FreshnessMixed},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := evidence["ScheduledTable"]; got.Status != backend.EvidenceAssessed || got.Method != "bounded-max-event-time" || got.LastEvent.Day() != 10 {
		t.Fatalf("Scheduled freshness = %+v", got)
	}
	if got := evidence["NRTTable"]; got.Status != backend.EvidenceAssessed || got.Method != "bounded-max-ingestion-time" || got.LastEvent.Day() != 20 {
		t.Fatalf("NRT freshness = %+v", got)
	}
	if got := evidence["SharedTable"]; got.Status != backend.EvidenceIncomplete || got.Method != "mixed-rule-timing" {
		t.Fatalf("shared freshness = %+v", got)
	}
	now := time.Date(2026, 8, 20, 12, 10, 0, 0, time.UTC)
	check := health.Check{MaxStale: 30 * time.Minute, Now: func() time.Time { return now }}
	if got := check.Evaluate(backend.Source{Docs: -1, LastEvent: evidence["ScheduledTable"].LastEvent, Freshness: evidence["ScheduledTable"]}); got.Status != health.StatusStale {
		t.Fatalf("Scheduled source with old event time = %+v, want stale", got)
	}
	if got := check.Evaluate(backend.Source{Docs: -1, LastEvent: evidence["NRTTable"].LastEvent, Freshness: evidence["NRTTable"]}); got.Status != health.StatusOK {
		t.Fatalf("NRT source with recent ingestion time = %+v, want healthy", got)
	}
	if got := check.Evaluate(backend.Source{Docs: -1, Freshness: evidence["SharedTable"]}); got.Status != health.StatusUnknown {
		t.Fatalf("shared source timing = %+v, want unknown", got)
	}
	var scheduledQuery, nrtQuery string
	for _, query := range queries {
		if strings.HasPrefix(query, "ScheduledTable ") {
			scheduledQuery = query
		}
		if strings.HasPrefix(query, "NRTTable ") {
			nrtQuery = query
		}
	}
	if len(queries) != 2 || !strings.Contains(scheduledQuery, "max(TimeGenerated)") || strings.Contains(scheduledQuery, "max(IngestionTime)") ||
		!strings.Contains(nrtQuery, "max(IngestionTime)") || !strings.Contains(scheduledQuery, "TimeGenerated <= now() + 300s") || !strings.Contains(nrtQuery, "IngestionTime <= now() + 300s") {
		t.Fatalf("rule-aware freshness queries = %v", queries)
	}
}

func TestIngestLagUsesPairedBoundedSamplesAndKeepsPartialErrorsIncomplete(t *testing.T) {
	credential := &recordingCredential{}
	var queriesMu sync.Mutex
	var queries []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/tables") {
			fmt.Fprint(w, `{"value":[
				{"name":"SecurityEvent","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"standardColumns":[{"name":"TimeGenerated","type":"datetime"}]}}},
				{"name":"EmptyTable","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"standardColumns":[{"name":"TimeGenerated","type":"datetime"}]}}},
				{"name":"BrokenTable","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"standardColumns":[{"name":"TimeGenerated","type":"datetime"}]}}},
				{"name":"AuxiliaryTable","properties":{"plan":"Auxiliary","provisioningState":"Succeeded","schema":{"standardColumns":[{"name":"TimeGenerated","type":"datetime"}]}}},
				{"name":"BasicTable_CL","properties":{"plan":"Basic","provisioningState":"Succeeded","schema":{"standardColumns":[{"name":"TimeGenerated","type":"datetime"}]}}},
				{"name":"UpdatingTable","properties":{"plan":"Analytics","provisioningState":"Updating","schema":{"standardColumns":[{"name":"TimeGenerated","type":"datetime"}]}}}
			]}`)
			return
		}
		if got := r.Header.Get("Prefer"); !strings.Contains(got, "include-permissions=true") || !strings.Contains(got, "include-dataSources=true") {
			t.Errorf("Prefer = %q", got)
		}
		var request logsQueryRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		queriesMu.Lock()
		queries = append(queries, request.Query)
		queriesMu.Unlock()
		switch {
		case strings.HasPrefix(request.Query, "SecurityEvent "):
			writeAllowedLogsResult(w, "SecurityEvent", `[{"name":"PrimaryResult","columns":[{"name":"TimeGenerated","type":"datetime"},{"name":"IngestionTime","type":"datetime"}],"rows":[["2026-08-20T10:00:00Z","2026-08-20T10:01:00Z"],["2026-08-20T10:00:00Z","2026-08-20T10:05:00Z"],["2026-08-20T10:00:00Z","2026-08-20T09:59:00Z"],["2026-08-10T10:00:00Z","2026-08-20T10:05:00Z"]]}]`)
		case strings.HasPrefix(request.Query, "EmptyTable "):
			writeAllowedLogsResult(w, "EmptyTable", `[{"name":"PrimaryResult","columns":[{"name":"TimeGenerated","type":"datetime"},{"name":"IngestionTime","type":"datetime"}],"rows":[]}]`)
		case strings.HasPrefix(request.Query, "BrokenTable "):
			http.Error(w, "query failed", http.StatusInternalServerError)
		default:
			t.Errorf("unexpected query %q", request.Query)
		}
	}))
	defer server.Close()
	client := fixtureClient(server.URL, credential)
	evidence, err := client.IngestLagEvidence(context.Background(), []backend.Source{
		{Name: "SecurityEvent"}, {Name: "EmptyTable"}, {Name: "BrokenTable"}, {Name: "bad.table"},
		{Name: "AuxiliaryTable"}, {Name: "BasicTable_CL"}, {Name: "UpdatingTable"},
	})
	if err != nil {
		t.Fatal(err)
	}
	good := evidence["SecurityEvent"]
	if good.Status != backend.EvidenceAssessed || good.SampleCount != 4 || good.P95 != 240*time.Hour+5*time.Minute || good.Max != 240*time.Hour+5*time.Minute || good.Window != ingestLagWindow || good.Method != "paired-timegenerated-ingestion_time" {
		t.Fatalf("assessed lag = %+v", good)
	}
	if evidence["EmptyTable"].Status != backend.EvidenceDisabled {
		t.Fatalf("empty lag evidence = %+v", evidence["EmptyTable"])
	}
	for _, name := range []string{"BrokenTable", "bad.table"} {
		if evidence[name].Status != backend.EvidenceIncomplete {
			t.Errorf("%s lag evidence = %+v", name, evidence[name])
		}
	}
	for _, name := range []string{"AuxiliaryTable", "BasicTable_CL", "UpdatingTable"} {
		if evidence[name].Status != backend.EvidenceUnavailable {
			t.Errorf("%s lag evidence = %+v", name, evidence[name])
		}
	}
	queriesMu.Lock()
	defer queriesMu.Unlock()
	if len(queries) != 3 {
		t.Fatalf("queries = %v, want no query for invalid table name", queries)
	}
	for _, query := range queries {
		if strings.Contains(query, "TimeGenerated >= ago(") || !strings.Contains(query, "IngestionTime >= ago(24h)") ||
			!strings.Contains(query, "ingestion_time()") || !strings.Contains(query, "top 500 by IngestionTime desc") ||
			!strings.Contains(query, "project TimeGenerated, IngestionTime") {
			t.Errorf("unbounded or unpaired lag query: %q", query)
		}
	}
}

func TestQueryLogsRequiresPositivePermissionAndDataSourceEvidence(t *testing.T) {
	tests := []struct {
		name       string
		table      string
		response   func(string) string
		wantStatus backend.EvidenceStatus
	}{
		{
			name:  "valid allow",
			table: "SecurityEvent",
			response: func(table string) string {
				return fmt.Sprintf(`{"tables":[{"name":"PrimaryResult","columns":[],"rows":[]}],"permissions":{"dataSources":[{"allowTables":[%q]}]},"dataSources":[{"tables":[%q]}]}`, table, table)
			},
		},
		{
			name:  "documented full access without allow tables",
			table: "SecurityEvent",
			response: func(table string) string {
				return fmt.Sprintf(`{"tables":[{"name":"PrimaryResult","columns":[],"rows":[]}],"permissions":{"dataSources":[{}]},"dataSources":[{"tables":[%q]}]}`, table)
			},
		},
		{
			name:  "rows without permission evidence",
			table: "SensitiveTable",
			response: func(string) string {
				return `{"tables":[{"name":"PrimaryResult","columns":[{"name":"Value","type":"long"}],"rows":[[1]]}]}`
			},
			wantStatus: backend.EvidenceIncomplete,
		},
		{
			name:  "explicit table deny overrides data source confirmation",
			table: "SensitiveTable",
			response: func(table string) string {
				return fmt.Sprintf(`{"tables":[{"name":"PrimaryResult","columns":[],"rows":[]}],"permissions":{"dataSources":[{"allowTables":[],"denyTables":[%q]}]},"dataSources":[{"tables":[%q]}]}`, table, table)
			},
			wantStatus: backend.EvidenceUnavailable,
		},
		{
			name:  "custom table group deny overrides allow",
			table: "SensitiveTable_CL",
			response: func(table string) string {
				return fmt.Sprintf(`{"tables":[{"name":"PrimaryResult","columns":[],"rows":[]}],"permissions":{"dataSources":[{"allowTables":[%q],"denyTables":["Tables.Custom"]}]},"dataSources":[{"tables":[%q]}]}`, table, table)
			},
			wantStatus: backend.EvidenceUnavailable,
		},
		{
			name:  "missing data sources",
			table: "SensitiveTable",
			response: func(table string) string {
				return fmt.Sprintf(`{"tables":[{"name":"PrimaryResult","columns":[],"rows":[]}],"permissions":{"dataSources":[{"allowTables":[%q]}]}}`, table)
			},
			wantStatus: backend.EvidenceIncomplete,
		},
		{
			name:  "data source mismatch",
			table: "SensitiveTable",
			response: func(table string) string {
				return fmt.Sprintf(`{"tables":[{"name":"PrimaryResult","columns":[],"rows":[]}],"permissions":{"dataSources":[{"allowTables":[%q]}]},"dataSources":[{"tables":["DifferentTable"]}]}`, table)
			},
			wantStatus: backend.EvidenceIncomplete,
		},
		{
			name:  "partial error",
			table: "SensitiveTable",
			response: func(table string) string {
				return fmt.Sprintf(`{"error":{"code":"PartialError","message":"partial result"},"tables":[{"name":"PrimaryResult","columns":[],"rows":[]}],"permissions":{"dataSources":[{"allowTables":[%q]}]},"dataSources":[{"tables":[%q]}]}`, table, table)
			},
			wantStatus: backend.EvidenceIncomplete,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			credential := &recordingCredential{}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/query") {
					http.NotFound(w, r)
					return
				}
				if got := r.Header.Get("Prefer"); !strings.Contains(got, "include-permissions=true") || !strings.Contains(got, "include-dataSources=true") {
					t.Errorf("Prefer = %q", got)
				}
				fmt.Fprint(w, tt.response(tt.table))
			}))
			defer server.Close()

			_, err := fixtureClient(server.URL, credential).queryLogs(context.Background(), tt.table+" | take 0", tt.table)
			if tt.wantStatus == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil {
				t.Fatal("queryLogs() succeeded without complete permission evidence")
			}
			status, detail := evidenceFailure(err)
			if status != tt.wantStatus {
				t.Fatalf("evidence status = %q, want %q (error %v)", status, tt.wantStatus, err)
			}
			if strings.Contains(detail, tt.table) {
				t.Fatalf("generic evidence detail leaked table name: %q", detail)
			}
		})
	}
}

func TestReadinessEvidenceProvesOneEligibleTableQuery(t *testing.T) {
	tests := []struct {
		name      string
		tableJSON string
		ruleTable string
		queryCode int
		want      backend.EvidenceStatus
		attempted bool
		wantCalls int
	}{
		{name: "allowed", tableJSON: `{"value":[{"name":"SecurityEvent","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"standardColumns":[]}}}]}`, ruleTable: "SecurityEvent", queryCode: http.StatusOK, want: backend.EvidenceAssessed, attempted: true, wantCalls: 1},
		{name: "denied", tableJSON: `{"value":[{"name":"SecurityEvent","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"standardColumns":[]}}}]}`, ruleTable: "SecurityEvent", queryCode: http.StatusForbidden, want: backend.EvidenceUnavailable, attempted: true, wantCalls: 1},
		{name: "no eligible table", tableJSON: `{"value":[{"name":"BasicTable_CL","properties":{"plan":"Basic","provisioningState":"Succeeded","schema":{"standardColumns":[]}}}]}`, ruleTable: "BasicTable_CL", want: backend.EvidenceUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/tables") {
					fmt.Fprint(w, tt.tableJSON)
					return
				}
				calls++
				if tt.queryCode == http.StatusForbidden {
					http.Error(w, "forbidden", http.StatusForbidden)
					return
				}
				var request logsQueryRequest
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Fatal(err)
				}
				if request.Query != "SecurityEvent | take 0" {
					t.Errorf("readiness query = %q", request.Query)
				}
				writeAllowedLogsResult(w, "SecurityEvent", `[{"name":"PrimaryResult","columns":[],"rows":[]}]`)
			}))
			defer server.Close()
			client := fixtureClient(server.URL, &recordingCredential{})
			sources, err := client.Sources(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			rules := []backend.Rule{{ID: "enabled-rule", Enabled: true, Patterns: []string{tt.ruleTable}}}
			evidence, err := client.ReadinessEvidence(context.Background(), rules, sources)
			if err != nil {
				t.Fatal(err)
			}
			if evidence.Status != tt.want || evidence.Attempted != tt.attempted || calls != tt.wantCalls {
				t.Fatalf("readiness/calls = %+v/%d, want %s attempted=%t calls=%d", evidence, calls, tt.want, tt.attempted, tt.wantCalls)
			}
		})
	}
}

func TestReadinessEvidenceProbesConsumedTablesOnly(t *testing.T) {
	tests := []struct {
		name           string
		consumedStatus int
		want           backend.EvidenceStatus
	}{
		{name: "unused denied table does not block", consumedStatus: http.StatusOK, want: backend.EvidenceAssessed},
		{name: "allowed unused table does not mask denial", consumedStatus: http.StatusForbidden, want: backend.EvidenceUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var queried []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/tables") {
					fmt.Fprint(w, `{"value":[
						{"name":"TableA","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"standardColumns":[]}}},
						{"name":"TableB","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"standardColumns":[]}}}
					]}`)
					return
				}
				var request logsQueryRequest
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Fatal(err)
				}
				queried = append(queried, request.Query)
				if tt.consumedStatus == http.StatusForbidden {
					http.Error(w, "forbidden", http.StatusForbidden)
					return
				}
				writeAllowedLogsResult(w, "TableB", `[{"name":"PrimaryResult","columns":[],"rows":[]}]`)
			}))
			defer server.Close()

			client := fixtureClient(server.URL, &recordingCredential{})
			sources, err := client.Sources(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			rules := []backend.Rule{{ID: "enabled-rule", Enabled: true, Patterns: []string{"TableB"}}}
			evidence, err := client.ReadinessEvidence(context.Background(), rules, sources)
			if err != nil {
				t.Fatal(err)
			}
			if evidence.Status != tt.want || !evidence.Attempted {
				t.Fatalf("readiness = %+v, want %s attempted", evidence, tt.want)
			}
			if len(queried) != 1 || queried[0] != "TableB | take 0" {
				t.Fatalf("readiness queried %v, want only the consumed table", queried)
			}
		})
	}
}

func TestReadinessEvidenceProbesRequiredSentinelDependencies(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name               string
		dependency         backend.DependencyRef
		watchlistInventory string
		watchlistCode      int
		dependencyCode     int
		dependencyResponse string
		want               backend.EvidenceStatus
		wantLimited        bool
		wantDependency     int32
		wantDirect         int32
	}{
		{
			name: "watchlist inventory denied alongside allowed table",
			dependency: backend.DependencyRef{
				ID: "sentinel_watchlist:vipusers", Name: "VIPUsers", Kind: "sentinel_watchlist", Required: true,
			},
			watchlistCode: http.StatusForbidden, want: backend.EvidenceUnavailable,
		},
		{
			name: "watchlist Logs denied alongside allowed table",
			dependency: backend.DependencyRef{
				ID: "sentinel_watchlist:vipusers", Name: "VIPUsers", Kind: "sentinel_watchlist", Required: true,
			},
			watchlistInventory: `{"value":[{"id":"/watchlists/vip","properties":{"watchlistAlias":"VIPUsers","provisioningState":"Succeeded","isDeleted":false}}]}`,
			dependencyCode:     http.StatusForbidden, want: backend.EvidenceUnavailable, wantDependency: 1,
		},
		{
			name: "ASIM Logs denied alongside allowed table",
			dependency: backend.DependencyRef{
				ID: "sentinel_asim_parser:_im_dns", Name: "_Im_Dns", Kind: "sentinel_asim_parser", Required: true, Expression: `_Im_Dns()`,
			},
			dependencyCode: http.StatusForbidden, want: backend.EvidenceUnavailable, wantDependency: 1,
		},
		{
			name: "healthy watchlist and allowed table",
			dependency: backend.DependencyRef{
				ID: "sentinel_watchlist:vipusers", Name: "VIPUsers", Kind: "sentinel_watchlist", Required: true,
			},
			watchlistInventory: `{"value":[{"id":"/watchlists/vip","properties":{"watchlistAlias":"VIPUsers","provisioningState":"Succeeded","isDeleted":false}}]}`,
			dependencyResponse: `{"tables":[{"name":"PrimaryResult","columns":[],"rows":[]}],"permissions":{"dataSources":[{"allowTables":["Watchlist"]}]},"dataSources":[{"tables":["Watchlist"]}]}`,
			want:               backend.EvidenceAssessed, wantDependency: 1, wantDirect: 1,
		},
		{
			name: "absent watchlist proves inventory read without blocking",
			dependency: backend.DependencyRef{
				ID: "sentinel_watchlist:vipusers", Name: "VIPUsers", Kind: "sentinel_watchlist", Required: true,
			},
			watchlistInventory: `{"value":[]}`,
			want:               backend.EvidenceAssessed, wantDirect: 1,
		},
		{
			name: "deleted watchlist proves inventory read without blocking",
			dependency: backend.DependencyRef{
				ID: "sentinel_watchlist:vipusers", Name: "VIPUsers", Kind: "sentinel_watchlist", Required: true,
			},
			watchlistInventory: `{"value":[{"id":"/watchlists/vip","properties":{"watchlistAlias":"VIPUsers","provisioningState":"Succeeded","isDeleted":true}}]}`,
			want:               backend.EvidenceAssessed, wantDirect: 1,
		},
		{
			name: "healthy ASIM and allowed table",
			dependency: backend.DependencyRef{
				ID: "sentinel_asim_parser:_im_dns", Name: "_Im_Dns", Kind: "sentinel_asim_parser", Required: true, Expression: `_Im_Dns()`,
			},
			dependencyResponse: "asim-allowed", want: backend.EvidenceAssessed, wantDependency: 1, wantDirect: 1,
		},
		{
			name: "known ASIM semantic partial limits readiness without blocking",
			dependency: backend.DependencyRef{
				ID: "sentinel_asim_parser:_im_dns", Name: "_Im_Dns", Kind: "sentinel_asim_parser", Required: true, Expression: `_Im_Dns()`,
			},
			dependencyResponse: liveASIMSemanticPartialResponse(),
			want:               backend.EvidenceAssessed, wantLimited: true, wantDependency: 1, wantDirect: 1,
		},
		{
			name: "known ASIM Authentication semantic partial is allowlisted",
			dependency: backend.DependencyRef{
				ID: "sentinel_asim_parser:_im_authentication", Name: "_Im_Authentication", Kind: "sentinel_asim_parser", Required: true, Expression: `_Im_Authentication(starttime=ago(1d),endtime=now())`,
			},
			dependencyResponse: liveASIMAuthenticationSemanticPartialResponse(),
			want:               backend.EvidenceAssessed, wantLimited: true, wantDependency: 1, wantDirect: 1,
		},
		{
			name: "explicit deny in ASIM partial response blocks",
			dependency: backend.DependencyRef{
				ID: "sentinel_asim_parser:_im_dns", Name: "_Im_Dns", Kind: "sentinel_asim_parser", Required: true, Expression: `_Im_Dns()`,
			},
			dependencyResponse: `{"error":{"code":"PartialError","message":"Partial query failure","details":[{"code":"EngineError","innererror":{"code":"-2133196790","message":"'union' operator: Failed to resolve tabular function named '_Im_WebSession'","severity":3,"severityName":"Warning"}}]},"tables":[{"name":"PrimaryResult","columns":[],"rows":[]}],"permissions":{"dataSources":[{"allowTables":["SecurityEvent"],"denyTables":["SecurityEvent"]}]},"dataSources":[{"tables":["SecurityEvent"]}]}`,
			want:               backend.EvidenceUnavailable, wantDependency: 1,
		},
		{
			name: "authorization failure in ASIM partial response blocks",
			dependency: backend.DependencyRef{
				ID: "sentinel_asim_parser:_im_dns", Name: "_Im_Dns", Kind: "sentinel_asim_parser", Required: true, Expression: `_Im_Dns()`,
			},
			dependencyResponse: `{"error":{"code":"PartialError","message":"Authorization failed while evaluating the query","details":[{"code":"EngineError","innererror":{"code":"-2133196790","message":"'union' operator: Failed to resolve tabular function named '_Im_WebSession'","severity":3,"severityName":"Warning"}}]},"tables":[{"name":"PrimaryResult","columns":[],"rows":[]}]}`,
			want:               backend.EvidenceUnavailable, wantDependency: 1,
		},
		{
			name: "omitted ASIM permission evidence blocks a nominal result",
			dependency: backend.DependencyRef{
				ID: "sentinel_asim_parser:_im_dns", Name: "_Im_Dns", Kind: "sentinel_asim_parser", Required: true, Expression: `_Im_Dns()`,
			},
			dependencyResponse: `{"tables":[{"name":"PrimaryResult","columns":[],"rows":[]}],"dataSources":[{"tables":["SecurityEvent"]}]}`,
			want:               backend.EvidenceUnavailable, wantDependency: 1,
		},
		{
			name: "arbitrary ASIM runtime partial failure blocks",
			dependency: backend.DependencyRef{
				ID: "sentinel_asim_parser:_im_dns", Name: "_Im_Dns", Kind: "sentinel_asim_parser", Required: true, Expression: `_Im_Dns()`,
			},
			dependencyResponse: `{"error":{"code":"PartialError","message":"one shard failed","details":[{"code":"EngineError","innererror":{"code":"RuntimeFailure","message":"one shard failed","severity":2,"severityName":"Error"}}]},"tables":[]}`,
			want:               backend.EvidenceUnavailable, wantDependency: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var dependencyQueries atomic.Int32
			var directQueries atomic.Int32
			var client *Client
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, "/tables"):
					fmt.Fprint(w, `{"value":[{"name":"SecurityEvent","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"standardColumns":[]}}}]}`)
				case strings.HasSuffix(r.URL.Path, "/watchlists"):
					if tt.watchlistCode != 0 {
						http.Error(w, "forbidden", tt.watchlistCode)
						return
					}
					fmt.Fprint(w, tt.watchlistInventory)
				case strings.HasSuffix(r.URL.Path, "/query"):
					var request logsQueryRequest
					if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
						t.Error(err)
						return
					}
					if request.Query == "SecurityEvent | take 0" {
						directQueries.Add(1)
						writeAllowedLogsResult(w, "SecurityEvent", `[{"name":"PrimaryResult","columns":[],"rows":[]}]`)
						return
					}
					dependencyQueries.Add(1)
					if tt.dependencyCode != 0 {
						http.Error(w, "forbidden", tt.dependencyCode)
						return
					}
					if tt.dependencyResponse == "asim-allowed" {
						resourceID := canonicalWorkspaceResourceID(client.SubscriptionID, client.ResourceGroup, client.WorkspaceName)
						fmt.Fprintf(w, `{"tables":[{"name":"PrimaryResult","columns":[],"rows":[]}],"permissions":{"dataSources":[{"resourceId":%q,"allowTables":["SecurityEvent"]}]},"dataSources":[{"resourceId":%q,"workspace":"workspace-id","tables":["SecurityEvent"]}]}`, resourceID, resourceID)
						return
					}
					fmt.Fprint(w, tt.dependencyResponse)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			client = fixtureClient(server.URL, &recordingCredential{})
			rules := []backend.Rule{{
				ID: "enabled-rule", Enabled: true, Patterns: []string{"SecurityEvent"}, Dependencies: []backend.DependencyRef{tt.dependency},
			}}
			evidence, err := client.ReadinessEvidence(context.Background(), rules, []backend.Source{{Name: "SecurityEvent"}})
			if err != nil {
				t.Fatal(err)
			}
			if evidence.Status != tt.want || evidence.Limited != tt.wantLimited || !evidence.Attempted {
				t.Fatalf("readiness = %+v, want %s attempted limited=%t", evidence, tt.want, tt.wantLimited)
			}
			if dependencyQueries.Load() != tt.wantDependency || directQueries.Load() != tt.wantDirect {
				t.Fatalf("dependency/direct queries = %d/%d, want %d/%d", dependencyQueries.Load(), directQueries.Load(), tt.wantDependency, tt.wantDirect)
			}
		})
	}
}

func TestReadinessEvidenceMissingWatchlistOnlyDoesNotClaimLogsProbe(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		inventory string
	}{
		{name: "absent", inventory: `{"value":[]}`},
		{name: "deleted", inventory: `{"value":[{"id":"/watchlists/vip","properties":{"watchlistAlias":"VIPUsers","provisioningState":"Succeeded","isDeleted":true}}]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var logsQueries atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, "/tables"):
					fmt.Fprint(w, `{"value":[]}`)
				case strings.HasSuffix(r.URL.Path, "/watchlists"):
					fmt.Fprint(w, tt.inventory)
				case strings.HasSuffix(r.URL.Path, "/query"):
					logsQueries.Add(1)
					http.Error(w, "unexpected Logs query", http.StatusInternalServerError)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			client := fixtureClient(server.URL, &recordingCredential{})
			rules := []backend.Rule{{
				ID: "watchlist-only", Enabled: true, Dependencies: []backend.DependencyRef{{
					ID: "sentinel_watchlist:vipusers", Name: "VIPUsers", Kind: "sentinel_watchlist", Required: true,
				}},
			}}
			evidence, err := client.ReadinessEvidence(context.Background(), rules, nil)
			if err != nil {
				t.Fatal(err)
			}
			if evidence.Status != backend.EvidenceAssessed || evidence.Attempted || !evidence.Limited || !strings.Contains(evidence.Detail, "no runtime Logs query was attempted") {
				t.Fatalf("readiness = %+v, want assessed limited without a runtime attempt", evidence)
			}
			if logsQueries.Load() != 0 {
				t.Fatalf("Logs queries = %d, want 0", logsQueries.Load())
			}

			resolutions, err := client.ResolveInputs(context.Background(), rules)
			if err != nil {
				t.Fatal(err)
			}
			if len(resolutions) != 2 || resolutions[0].Status != backend.ResolutionEmpty || resolutions[1].Status != backend.ResolutionEmpty || len(resolutions[0].ResolvedSources) != 0 {
				t.Fatalf("watchlist scan evidence changed: %#v", resolutions)
			}
		})
	}
}

func TestReadinessEvidenceOptionalDependencyParity(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name               string
		dependency         backend.DependencyRef
		watchlistInventory string
		watchlistCode      int
		dependencyCode     int
		dependencyResponse string
		wantReadiness      backend.EvidenceStatus
		wantLimited        bool
		wantResolution     backend.ResolutionStatus
		wantDependency     int32
		wantDirect         int32
	}{
		{
			name: "optional ASIM denial",
			dependency: backend.DependencyRef{
				ID: "sentinel_asim_parser:_im_dns", Name: "_Im_Dns", Kind: "sentinel_asim_parser", Expression: `_Im_Dns()`,
			},
			dependencyCode: http.StatusForbidden, wantReadiness: backend.EvidenceUnavailable,
			wantResolution: backend.ResolutionUnavailable, wantDependency: 1,
		},
		{
			name: "optional watchlist inventory denial",
			dependency: backend.DependencyRef{
				ID: "sentinel_watchlist:vipusers", Name: "VIPUsers", Kind: "sentinel_watchlist",
			},
			watchlistCode: http.StatusForbidden, wantReadiness: backend.EvidenceUnavailable,
			wantResolution: backend.ResolutionUnavailable,
		},
		{
			name: "optional watchlist query denial",
			dependency: backend.DependencyRef{
				ID: "sentinel_watchlist:vipusers", Name: "VIPUsers", Kind: "sentinel_watchlist",
			},
			watchlistInventory: `{"value":[{"id":"/watchlists/vip","properties":{"watchlistAlias":"VIPUsers","provisioningState":"Succeeded","isDeleted":false}}]}`,
			dependencyCode:     http.StatusForbidden, wantReadiness: backend.EvidenceUnavailable,
			wantResolution: backend.ResolutionUnavailable, wantDependency: 1,
		},
		{
			name: "optional watchlist absence",
			dependency: backend.DependencyRef{
				ID: "sentinel_watchlist:vipusers", Name: "VIPUsers", Kind: "sentinel_watchlist",
			},
			watchlistInventory: `{"value":[]}`, wantReadiness: backend.EvidenceAssessed,
			wantResolution: backend.ResolutionResolved, wantDirect: 1,
		},
		{
			name: "optional deleted watchlist",
			dependency: backend.DependencyRef{
				ID: "sentinel_watchlist:vipusers", Name: "VIPUsers", Kind: "sentinel_watchlist",
			},
			watchlistInventory: `{"value":[{"id":"/watchlists/vip","properties":{"watchlistAlias":"VIPUsers","provisioningState":"Succeeded","isDeleted":true}}]}`,
			wantReadiness:      backend.EvidenceAssessed, wantResolution: backend.ResolutionResolved, wantDirect: 1,
		},
		{
			name: "optional known ASIM semantic partial result",
			dependency: backend.DependencyRef{
				ID: "sentinel_asim_parser:_im_dns", Name: "_Im_Dns", Kind: "sentinel_asim_parser", Expression: `_Im_Dns()`,
			},
			dependencyResponse: liveASIMSemanticPartialResponse(),
			wantReadiness:      backend.EvidenceAssessed, wantLimited: true, wantResolution: backend.ResolutionUnsupported,
			wantDependency: 1, wantDirect: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var dependencyQueries atomic.Int32
			var directQueries atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, "/tables"):
					fmt.Fprint(w, `{"value":[{"name":"SecurityEvent","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"standardColumns":[]}}}]}`)
				case strings.HasSuffix(r.URL.Path, "/watchlists"):
					if tt.watchlistCode != 0 {
						http.Error(w, "forbidden", tt.watchlistCode)
						return
					}
					fmt.Fprint(w, tt.watchlistInventory)
				case strings.HasSuffix(r.URL.Path, "/query"):
					var request logsQueryRequest
					if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
						t.Error(err)
						return
					}
					if request.Query == "SecurityEvent | take 0" {
						directQueries.Add(1)
						writeAllowedLogsResult(w, "SecurityEvent", `[{"name":"PrimaryResult","columns":[],"rows":[]}]`)
						return
					}
					dependencyQueries.Add(1)
					if tt.dependencyCode != 0 {
						http.Error(w, "forbidden", tt.dependencyCode)
						return
					}
					fmt.Fprint(w, tt.dependencyResponse)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			client := fixtureClient(server.URL, &recordingCredential{})
			rules := []backend.Rule{{
				ID: "optional", Enabled: true, Patterns: []string{"SecurityEvent"}, Dependencies: []backend.DependencyRef{tt.dependency},
			}}
			evidence, err := client.ReadinessEvidence(context.Background(), rules, []backend.Source{{Name: "SecurityEvent"}})
			if err != nil {
				t.Fatal(err)
			}
			if evidence.Status != tt.wantReadiness || evidence.Limited != tt.wantLimited || !evidence.Attempted || dependencyQueries.Load() != tt.wantDependency || directQueries.Load() != tt.wantDirect {
				t.Fatalf("readiness/queries = %+v dependency=%d direct=%d, want %s limited=%t/%d/%d", evidence, dependencyQueries.Load(), directQueries.Load(), tt.wantReadiness, tt.wantLimited, tt.wantDependency, tt.wantDirect)
			}
			resolutions, err := client.ResolveInputs(context.Background(), rules)
			if err != nil {
				t.Fatal(err)
			}
			if len(resolutions) == 0 || resolutions[0].Diagnostic || resolutions[0].Status != tt.wantResolution {
				t.Fatalf("authoritative resolution = %#v, want %s", resolutions, tt.wantResolution)
			}
		})
	}
}

func TestReadinessDependenciesRequiredUseWins(t *testing.T) {
	asim := backend.DependencyRef{
		ID: "sentinel_asim_parser:_im_dns", Name: "_Im_Dns", Kind: "sentinel_asim_parser", Expression: `_Im_Dns()`,
	}
	got := readinessDependencies([]backend.Rule{
		{ID: "optional", Enabled: true, Dependencies: []backend.DependencyRef{
			asim,
			{Name: "OpsUsers", Kind: "sentinel_watchlist"},
		}},
		{ID: "disabled", Enabled: false, Dependencies: []backend.DependencyRef{{Name: "Disabled", Kind: "sentinel_watchlist", Required: true}}},
		{ID: "required", Enabled: true, Dependencies: []backend.DependencyRef{
			{ID: asim.ID, Name: asim.Name, Kind: asim.Kind, Expression: asim.Expression, Required: true},
			{Name: "VIPUsers", Kind: "sentinel_watchlist", Required: true},
		}},
	})
	if len(got) != 3 || got[0].Kind != "sentinel_asim_parser" || !got[0].Required ||
		got[1].Name != "OpsUsers" || got[1].Required || got[2].Name != "VIPUsers" || !got[2].Required {
		t.Fatalf("readiness dependencies = %#v", got)
	}
}

func TestDependencyReadinessFailure(t *testing.T) {
	tests := []struct {
		name        string
		kind        string
		result      dependencyProbeResult
		wantStatus  backend.EvidenceStatus
		wantLimited bool
	}{
		{name: "resolved watchlist", kind: "sentinel_watchlist", result: dependencyProbeResult{status: backend.ResolutionResolved, attempted: true}},
		{name: "absent watchlist", kind: "sentinel_watchlist", result: dependencyProbeResult{status: backend.ResolutionEmpty, attempted: true}},
		{name: "unavailable watchlist", kind: "sentinel_watchlist", result: dependencyProbeResult{status: backend.ResolutionUnavailable, attempted: true}, wantStatus: backend.EvidenceUnavailable},
		{name: "resolved ASIM", kind: "sentinel_asim_parser", result: dependencyProbeResult{status: backend.ResolutionResolved, attempted: true}},
		{name: "partial ASIM", kind: "sentinel_asim_parser", result: dependencyProbeResult{status: backend.ResolutionUnsupported, attempted: true}, wantStatus: backend.EvidenceAssessed, wantLimited: true},
		{name: "incompatible ASIM", kind: "sentinel_asim_parser", result: dependencyProbeResult{status: backend.ResolutionIncompatible, attempted: true}, wantStatus: backend.EvidenceAssessed, wantLimited: true},
		{name: "ambiguous ASIM", kind: "sentinel_asim_parser", result: dependencyProbeResult{status: backend.ResolutionAmbiguous, attempted: true}, wantStatus: backend.EvidenceAssessed, wantLimited: true},
		{name: "remote ASIM", kind: "sentinel_asim_parser", result: dependencyProbeResult{status: backend.ResolutionRemote, attempted: true}, wantStatus: backend.EvidenceAssessed, wantLimited: true},
		{name: "empty ASIM", kind: "sentinel_asim_parser", result: dependencyProbeResult{status: backend.ResolutionEmpty, attempted: true}, wantStatus: backend.EvidenceAssessed, wantLimited: true},
		{name: "unavailable ASIM", kind: "sentinel_asim_parser", result: dependencyProbeResult{status: backend.ResolutionUnavailable, attempted: true}, wantStatus: backend.EvidenceUnavailable},
		{name: "locally rejected ASIM", kind: "sentinel_asim_parser", result: dependencyProbeResult{status: backend.ResolutionUnsupported}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dependencyReadinessFailure(backend.DependencyRef{Kind: tt.kind}, tt.result)
			if tt.wantStatus == "" {
				if got != nil {
					t.Fatalf("failure = %+v, want nil", got)
				}
				return
			}
			if got == nil || got.Status != tt.wantStatus || got.Limited != tt.wantLimited || !got.Attempted {
				t.Fatalf("failure = %+v, want %s attempted limited=%t", got, tt.wantStatus, tt.wantLimited)
			}
		})
	}
}

func TestReadinessEvidenceAttemptsEveryRequiredSentinelDependency(t *testing.T) {
	t.Parallel()
	var asimQueries atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/tables"):
			fmt.Fprint(w, `{"value":[{"name":"SecurityEvent","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"standardColumns":[]}}}]}`)
		case strings.HasSuffix(r.URL.Path, "/query"):
			asimQueries.Add(1)
			http.Error(w, "forbidden", http.StatusForbidden)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := fixtureClient(server.URL, &recordingCredential{})
	rules := []backend.Rule{{
		ID: "required-ASIM", Enabled: true, Patterns: []string{"SecurityEvent"}, Dependencies: []backend.DependencyRef{
			{ID: "sentinel_asim_parser:_im_dns:first", Name: "_Im_Dns", Kind: "sentinel_asim_parser", Required: true, Expression: `_Im_Dns()`},
			{ID: "sentinel_asim_parser:_im_dns:second", Name: "_Im_Dns", Kind: "sentinel_asim_parser", Required: true, Expression: `_Im_Dns(starttime=ago(1d))`},
		},
	}}
	evidence, err := client.ReadinessEvidence(context.Background(), rules, []backend.Source{{Name: "SecurityEvent"}})
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Status != backend.EvidenceUnavailable || !evidence.Attempted || asimQueries.Load() != 2 {
		t.Fatalf("readiness/ASIM queries = %+v/%d, want unavailable attempted and two probes", evidence, asimQueries.Load())
	}
}

func TestReadinessEvidenceDependencyDenialWinsOverEarlierSemanticLimit(t *testing.T) {
	t.Parallel()
	var asimQueries atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/tables"):
			fmt.Fprint(w, `{"value":[{"name":"SecurityEvent","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"standardColumns":[]}}}]}`)
		case strings.HasSuffix(r.URL.Path, "/query"):
			var request logsQueryRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Error(err)
				return
			}
			asimQueries.Add(1)
			if strings.HasPrefix(request.Query, "_Im_Authentication()") {
				fmt.Fprint(w, liveASIMSemanticPartialResponse())
				return
			}
			http.Error(w, "forbidden", http.StatusForbidden)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := fixtureClient(server.URL, &recordingCredential{})
	rules := []backend.Rule{{
		ID: "mixed-ASIM-readiness", Enabled: true, Patterns: []string{"SecurityEvent"}, Dependencies: []backend.DependencyRef{
			{ID: "sentinel_asim_parser:_im_authentication", Name: "_Im_Authentication", Kind: "sentinel_asim_parser", Required: true, Expression: `_Im_Authentication()`},
			{ID: "sentinel_asim_parser:_im_dns", Name: "_Im_Dns", Kind: "sentinel_asim_parser", Required: true, Expression: `_Im_Dns()`},
		},
	}}
	evidence, err := client.ReadinessEvidence(context.Background(), rules, []backend.Source{{Name: "SecurityEvent"}})
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Status != backend.EvidenceUnavailable || evidence.Limited || !evidence.Attempted || asimQueries.Load() != 2 {
		t.Fatalf("readiness/ASIM queries = %+v/%d, want unavailable attempted and two probes", evidence, asimQueries.Load())
	}
}

func TestReadinessEvidenceDoesNotClaimLocallyRejectedDependencyProbe(t *testing.T) {
	t.Parallel()
	var queryCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/tables"):
			fmt.Fprint(w, `{"value":[]}`)
		case strings.HasSuffix(r.URL.Path, "/query"):
			queryCalls.Add(1)
			http.Error(w, "unexpected query", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := fixtureClient(server.URL, &recordingCredential{})
	rules := []backend.Rule{{
		ID: "dynamic-ASIM", Enabled: true, Dependencies: []backend.DependencyRef{{
			ID: "sentinel_asim_parser:_im_dns", Name: "_Im_Dns", Kind: "sentinel_asim_parser", Required: true,
		}},
	}}
	evidence, err := client.ReadinessEvidence(context.Background(), rules, nil)
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Status != backend.EvidenceUnavailable || evidence.Attempted || queryCalls.Load() != 0 {
		t.Fatalf("readiness/query calls = %+v/%d, want unattempted local rejection", evidence, queryCalls.Load())
	}
}

func TestResolveInputsPermissionProbesAreDeduplicatedAndBounded(t *testing.T) {
	credential := &recordingCredential{}
	var active atomic.Int32
	var maximum atomic.Int32
	var queryCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/tables") {
			fmt.Fprint(w, `{"value":[
				{"name":"TableA","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"standardColumns":[]}}},
				{"name":"TableB","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"standardColumns":[]}}},
				{"name":"TableC","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"standardColumns":[]}}}
			]}`)
			return
		}
		if !strings.HasSuffix(r.URL.Path, "/query") {
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("Prefer"); !strings.Contains(got, "include-permissions=true") || !strings.Contains(got, "include-dataSources=true") {
			t.Errorf("Prefer = %q", got)
		}
		current := active.Add(1)
		defer active.Add(-1)
		for {
			seen := maximum.Load()
			if current <= seen || maximum.CompareAndSwap(seen, current) {
				break
			}
		}
		time.Sleep(15 * time.Millisecond)
		queryCount.Add(1)
		var request logsQueryRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		table := strings.TrimSuffix(request.Query, " | take 0")
		if table == request.Query || (table != "TableA" && table != "TableB" && table != "TableC") {
			t.Errorf("permission probe query = %q", request.Query)
		}
		writeAllowedLogsResult(w, table, `[{"name":"PrimaryResult","columns":[],"rows":[]}]`)
	}))
	defer server.Close()
	client := fixtureClient(server.URL, credential)
	client.Concurrency = 99

	resolutions, err := client.ResolveInputs(context.Background(), []backend.Rule{
		{ID: "first", Enabled: true, Patterns: []string{"TableA", "TableB"}},
		{ID: "second", Enabled: true, Patterns: []string{"TableB", "TableC"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(resolutions) != 6 {
		t.Fatalf("resolutions = %+v", resolutions)
	}
	for _, resolution := range resolutions {
		if resolution.Status != backend.ResolutionResolved {
			t.Fatalf("resolution = %+v", resolution)
		}
	}
	if got := queryCount.Load(); got != 3 {
		t.Fatalf("permission probe count = %d, want three unique tables", got)
	}
	if got := maximum.Load(); got > defaultConcurrency {
		t.Fatalf("maximum concurrent permission probes = %d, want <= %d", got, defaultConcurrency)
	}
}

func TestDisabledRulesDoNotSpendPermissionOrSourceBudget(t *testing.T) {
	credential := &recordingCredential{}
	var tablePayload strings.Builder
	tablePayload.WriteString(`{"value":[`)
	rules := make([]backend.Rule, 0, maxEvidenceSourcesPerScan+1)
	for i := 0; i < maxEvidenceSourcesPerScan; i++ {
		if i > 0 {
			tablePayload.WriteByte(',')
		}
		name := fmt.Sprintf("Disabled%02d", i)
		fmt.Fprintf(&tablePayload, `{"name":%q,"properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"standardColumns":[]}}}`, name)
		rules = append(rules, backend.Rule{ID: "disabled-" + name, Enabled: false, Patterns: []string{name}})
	}
	tablePayload.WriteString(`,{"name":"EnabledTable","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"standardColumns":[]}}}]}`)
	var queryCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/tables"):
			fmt.Fprint(w, tablePayload.String())
		case strings.HasSuffix(r.URL.Path, "/query"):
			queryCalls.Add(1)
			var request logsQueryRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if request.Query != "EnabledTable | take 0" {
				t.Errorf("permission query = %q", request.Query)
			}
			writeAllowedLogsResult(w, "EnabledTable", `[{"name":"PrimaryResult","columns":[],"rows":[]}]`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	rules = append(rules, backend.Rule{ID: "enabled", Enabled: true, Patterns: []string{"EnabledTable"}})
	client := fixtureClient(server.URL, credential)
	resolutions, err := client.ResolveInputs(context.Background(), rules)
	if err != nil {
		t.Fatal(err)
	}
	if len(resolutions) != 2 || resolutions[0].RuleID != "enabled" || resolutions[0].Status != backend.ResolutionResolved ||
		!resolutions[1].Diagnostic || resolutions[1].Status != backend.ResolutionResolved {
		t.Fatalf("enabled resolution = %+v", resolutions)
	}
	if queryCalls.Load() != 1 {
		t.Fatalf("permission queries = %d, want enabled rule only", queryCalls.Load())
	}
	client.budgetMu.Lock()
	usedSources, usedQueries := len(client.budgetSources), client.budgetQueries
	client.budgetMu.Unlock()
	if usedSources != 1 || usedQueries != 1 {
		t.Fatalf("budgets used = %d sources/%d queries, want 1/1", usedSources, usedQueries)
	}
}

func TestPerScanSourceAndQueryBudgetsReturnIncompleteEvidence(t *testing.T) {
	newFixture := func(t *testing.T) (*Client, *atomic.Int32) {
		t.Helper()
		credential := &recordingCredential{}
		calls := &atomic.Int32{}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/tables") {
				fmt.Fprint(w, `{"value":[
					{"name":"TableA","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"standardColumns":[]}}},
					{"name":"TableB","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"standardColumns":[]}}},
					{"name":"TableC","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"standardColumns":[]}}}
				]}`)
				return
			}
			if strings.HasSuffix(r.URL.Path, "/query") {
				calls.Add(1)
				var request logsQueryRequest
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Fatal(err)
				}
				table := strings.SplitN(request.Query, " ", 2)[0]
				writeAllowedLogsResult(w, table, `[{"name":"PrimaryResult","columns":[{"name":"LastEvent","type":"datetime"}],"rows":[["2026-08-20T12:34:56Z"]]}]`)
				return
			}
			if r.Method == http.MethodGet && r.URL.Path == "/subscriptions/sub-id/resourceGroups/rg-lab/providers/Microsoft.OperationalInsights/workspaces/law-lab" {
				fmt.Fprint(w, `{"properties":{"customerId":"workspace-id"}}`)
				return
			}
			http.NotFound(w, r)
		}))
		t.Cleanup(server.Close)
		return fixtureClient(server.URL, credential), calls
	}
	sources := []backend.Source{{Name: "TableA"}, {Name: "TableB"}, {Name: "TableC"}}

	t.Run("source budget", func(t *testing.T) {
		client, calls := newFixture(t)
		client.evidenceSourceLimit = 2
		evidence, err := client.FreshnessEvidence(context.Background(), sources)
		if err != nil {
			t.Fatal(err)
		}
		if calls.Load() != 2 || evidence["TableA"].Status != backend.EvidenceAssessed ||
			evidence["TableB"].Status != backend.EvidenceAssessed || evidence["TableC"].Status != backend.EvidenceIncomplete {
			t.Fatalf("source-budget evidence/calls = %+v/%d", evidence, calls.Load())
		}
	})

	t.Run("query budget resets per scan", func(t *testing.T) {
		client, calls := newFixture(t)
		client.evidenceSourceLimit = 10
		client.logsQueryLimit = 2
		evidence, err := client.FreshnessEvidence(context.Background(), sources)
		if err != nil {
			t.Fatal(err)
		}
		assessed, incomplete := 0, 0
		for _, item := range evidence {
			switch item.Status {
			case backend.EvidenceAssessed:
				assessed++
			case backend.EvidenceIncomplete:
				incomplete++
			}
		}
		if calls.Load() != 2 || assessed != 2 || incomplete != 1 {
			t.Fatalf("query-budget evidence/calls = %+v/%d", evidence, calls.Load())
		}
		if err := client.RefreshForScan(context.Background()); err != nil {
			t.Fatal(err)
		}
		refreshed, err := client.FreshnessEvidence(context.Background(), sources[:1])
		if err != nil {
			t.Fatal(err)
		}
		if calls.Load() != 3 || refreshed["TableA"].Status != backend.EvidenceAssessed {
			t.Fatalf("refreshed query budget evidence/calls = %+v/%d", refreshed, calls.Load())
		}
	})
}

func TestKQLTableReferenceQuotesValidAzureNames(t *testing.T) {
	tests := []struct {
		name string
		want string
		ok   bool
	}{
		{name: "SecurityEvent", want: "SecurityEvent", ok: true},
		{name: "custom-table", want: "['custom-table']", ok: true},
		{name: "1Table", want: "['1Table']", ok: true},
		{name: "bad.table", ok: false},
	}
	for _, tt := range tests {
		got, ok := kqlTableReference(tt.name)
		if got != tt.want || ok != tt.ok {
			t.Errorf("kqlTableReference(%q) = %q, %v; want %q, %v", tt.name, got, ok, tt.want, tt.ok)
		}
	}
}

func TestISODurationSubset(t *testing.T) {
	tests := []struct {
		input string
		want  time.Duration
	}{
		{input: "PT5M", want: 5 * time.Minute},
		{input: "P1DT30M", want: 24*time.Hour + 30*time.Minute},
		{input: "PT1H30M10S", want: time.Hour + 30*time.Minute + 10*time.Second},
	}
	for _, tt := range tests {
		got, err := parseISODuration(tt.input)
		if err != nil || got != tt.want {
			t.Errorf("parseISODuration(%q) = %v, %v; want %v", tt.input, got, err, tt.want)
		}
	}
	for _, invalid := range []string{"", "1H", "P1M", "PT", "P1H"} {
		if _, err := parseISODuration(invalid); err == nil {
			t.Errorf("parseISODuration(%q) unexpectedly succeeded", invalid)
		}
	}
}

func TestNewClientValidatesWorkspaceCoordinates(t *testing.T) {
	_, err := NewClient(Config{SubscriptionID: "sub", ResourceGroup: "rg", Credential: &recordingCredential{}})
	if err == nil || !strings.Contains(err.Error(), "workspace name") {
		t.Fatalf("NewClient() error = %v", err)
	}
}

func TestWorkspaceIDIsResolvedOnceFromARM(t *testing.T) {
	credential := &recordingCredential{}
	var workspaceCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/subscriptions/sub-id/resourceGroups/rg-lab/providers/Microsoft.OperationalInsights/workspaces/law-lab":
			workspaceCalls.Add(1)
			fmt.Fprint(w, `{"properties":{"customerId":"resolved-workspace-id"}}`)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/workspaces/resolved-workspace-id/query":
			fmt.Fprint(w, `{"tables":[{"name":"PrimaryResult","columns":[{"name":"Value","type":"long"}],"rows":[[1]]}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := fixtureClient(server.URL, credential)
	client.WorkspaceID = ""
	client.workspaceIDValidated = false
	if _, err := client.queryLogs(context.Background(), "print Value=1", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := client.queryLogs(context.Background(), "print Value=1", ""); err != nil {
		t.Fatal(err)
	}
	if workspaceCalls.Load() != 1 || client.WorkspaceID != "resolved-workspace-id" {
		t.Fatalf("workspace resolution calls/id = %d/%q", workspaceCalls.Load(), client.WorkspaceID)
	}
}

func TestWorkspaceIDOverrideMustMatchARMCustomerID(t *testing.T) {
	credential := &recordingCredential{}
	var queryCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/subscriptions/sub-id/resourceGroups/rg-lab/providers/Microsoft.OperationalInsights/workspaces/law-lab":
			fmt.Fprint(w, `{"properties":{"customerId":"actual-workspace-id"}}`)
		case strings.HasSuffix(r.URL.Path, "/query"):
			queryCalls.Add(1)
			fmt.Fprint(w, `{"tables":[]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := fixtureClient(server.URL, credential)
	client.WorkspaceID = "wrong-workspace-id"
	client.workspaceIDValidated = false
	_, err := client.queryLogs(context.Background(), "SecurityEvent | take 0", "SecurityEvent")
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("queryLogs() error = %v, want workspace ID mismatch", err)
	}
	if queryCalls.Load() != 0 {
		t.Fatalf("Logs queries = %d, want mismatch rejected before query", queryCalls.Load())
	}
}

func TestRefreshForScanClearsSentinelCachesAndBudgets(t *testing.T) {
	credential := &recordingCredential{}
	var tableCalls atomic.Int32
	var metadataCalls atomic.Int32
	var workspaceCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/tables"):
			call := tableCalls.Add(1)
			fmt.Fprintf(w, `{"value":[{"name":"Table%d","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"standardColumns":[]}}}]}`, call)
		case strings.HasSuffix(r.URL.Path, "/metadata"):
			call := metadataCalls.Add(1)
			fmt.Fprintf(w, `{"functions":[{"name":"Function%d","body":"Table%d","parameters":""}]}`, call, call)
		case r.Method == http.MethodGet && r.URL.Path == "/subscriptions/sub-id/resourceGroups/rg-lab/providers/Microsoft.OperationalInsights/workspaces/law-lab":
			workspaceCalls.Add(1)
			fmt.Fprint(w, `{"properties":{"customerId":"workspace-id"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := fixtureClient(server.URL, credential)

	firstTables, err := client.tables(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	firstFunctions, ok := client.workspaceFunctions(context.Background())
	if !ok {
		t.Fatal("initial function metadata unavailable")
	}
	client.claimEvidenceSource("Table1")
	client.claimLogsQuery()
	client.watchlistsLoaded = true
	client.watchlists = map[string]watchlistInfo{"vipusers": {alias: "VIPUsers", complete: true}}
	client.watchlistProbes = map[string]dependencyProbeResult{"vipusers": {status: backend.ResolutionResolved}}
	client.asimProbes = map[string]dependencyProbeResult{"_Im_Dns()": {status: backend.ResolutionResolved}}
	if err := client.RefreshForScan(context.Background()); err != nil {
		t.Fatal(err)
	}
	secondTables, err := client.tables(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	secondFunctions, ok := client.workspaceFunctions(context.Background())
	if !ok {
		t.Fatal("refreshed function metadata unavailable")
	}
	if _, ok := firstTables["Table1"]; !ok || firstFunctions["Function1"].Body != "Table1" ||
		secondTables["Table2"].schema.Source != "Table2" || secondFunctions["Function2"].Body != "Table2" {
		t.Fatalf("cache refresh = first tables/functions %v/%v; second %v/%v", firstTables, firstFunctions, secondTables, secondFunctions)
	}
	if tableCalls.Load() != 2 || metadataCalls.Load() != 2 || workspaceCalls.Load() != 1 {
		t.Fatalf("refresh calls tables/metadata/workspace = %d/%d/%d", tableCalls.Load(), metadataCalls.Load(), workspaceCalls.Load())
	}
	client.budgetMu.Lock()
	sources, queries := len(client.budgetSources), client.budgetQueries
	client.budgetMu.Unlock()
	if sources != 0 || queries != 0 {
		t.Fatalf("refreshed budgets = %d sources, %d queries", sources, queries)
	}
	if client.watchlistsLoaded || client.watchlists != nil || client.watchlistProbes != nil || client.asimProbes != nil {
		t.Fatalf("dependency caches survived refresh: loaded=%v watchlists=%#v watchlist probes=%#v ASIM probes=%#v", client.watchlistsLoaded, client.watchlists, client.watchlistProbes, client.asimProbes)
	}
}
