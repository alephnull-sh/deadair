// Package sentinel implements the read-only backend for Microsoft Sentinel.
// It reads analytic rules and table metadata through Azure Resource Manager,
// and uses bounded Log Analytics queries for runtime evidence. The only POST
// requests are queries; the adapter never calls a control-plane write API.
package sentinel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/alephnull-sh/deadair/internal/backend"
)

const (
	defaultARMEndpoint  = "https://management.azure.com"
	defaultLogsEndpoint = "https://api.loganalytics.azure.com"
	armScope            = "https://management.azure.com/.default"
	logsScope           = "https://api.loganalytics.io/.default"

	alertRulesAPIVersion        = "2025-09-01"
	alertRulesPreviewAPIVersion = "2025-10-01-preview"
	watchlistsAPIVersion        = "2025-09-01"
	tablesAPIVersion            = "2025-07-01"
	defaultConcurrency          = 2
	maxRulePages                = 1000
	maxTablePages               = 1000
	maxWatchlistPages           = 1000
	maxAttempts                 = 4
	freshnessWindow             = 24 * time.Hour
	ingestLagWindow             = 24 * time.Hour
	ingestLagSamples            = 500
	maxEvidenceSourcesPerScan   = 60
	maxLogsQueriesPerScan       = 180
	accessTokenRefreshSkew      = 5 * time.Minute
)

var (
	simpleTableNameRE             = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	azureTableNameRE              = regexp.MustCompile(`^[A-Za-z0-9_-]{1,63}$`)
	asimUnresolvedFunctionRE      = regexp.MustCompile(`^'union' operator: Failed to resolve tabular function named '[A-Za-z_][A-Za-z0-9_]*'$`)
	asimUnresolvedTableRE         = regexp.MustCompile(`^'union' operator: Failed to resolve table expression named '[A-Za-z_][A-Za-z0-9_]*'$`)
	asimUnresolvedTableOrColumnRE = regexp.MustCompile(`^'where' operator: Failed to resolve table or column expression named '[A-Za-z_][A-Za-z0-9_]*'$`)
	asimUnresolvedLetRE           = regexp.MustCompile(`^let statement '[A-Za-z_][A-Za-z0-9_]*' could not be analyzed$`)
	asimUnresolvedArgumentRE      = regexp.MustCompile(`^'[A-Za-z_][A-Za-z0-9_]*'\(\): argument #[0-9]+ could not be resolved$`)
)

// Config identifies one Sentinel workspace. WorkspaceName is the ARM
// resource name; WorkspaceID is the Log Analytics customer/workspace ID used
// by the query API.
type Config struct {
	SubscriptionID   string
	ResourceGroup    string
	WorkspaceName    string
	WorkspaceID      string
	RemoteWorkspaces []RemoteWorkspace
	Credential       azcore.TokenCredential
	HTTP             *http.Client
	ARMEndpoint      string
	LogsEndpoint     string
	Concurrency      int
}

// Client is a read-only Microsoft Sentinel client. Its endpoints, credential,
// and HTTP transport are injectable so contract tests do not need Azure.
type Client struct {
	SubscriptionID   string
	ResourceGroup    string
	WorkspaceName    string
	WorkspaceID      string
	RemoteWorkspaces []RemoteWorkspace
	Credential       azcore.TokenCredential
	HTTP             *http.Client
	ARMEndpoint      string
	LogsEndpoint     string
	Concurrency      int

	tokenMu                    sync.Mutex
	accessTokens               map[string]azcore.AccessToken
	accessTokenFlights         map[string]*accessTokenFlight
	workspaceIDMu              sync.Mutex
	workspaceIDValidated       bool
	workspaceLocation          string
	workspaceLocationValidated bool
	catalogMu                  sync.Mutex
	catalog                    map[string]tableInfo
	functionsMu                sync.Mutex
	functions                  map[string]WorkspaceFunction
	watchlistsMu               sync.Mutex
	watchlistsLoaded           bool
	watchlists                 map[string]watchlistInfo
	watchlistsComplete         bool
	watchlistsErr              error
	dependencyProbeMu          sync.Mutex
	watchlistProbes            map[string]dependencyProbeResult
	asimProbes                 map[string]dependencyProbeResult
	remoteMu                   sync.Mutex
	remoteStates               map[string]*remoteWorkspaceState
	remoteReferencesMu         sync.Mutex
	remoteReferences           []string
	installedRulesMu           sync.Mutex
	installedRules             map[string]struct{}
	summaryLogsMu              sync.Mutex
	summaryLogs                []summaryLogJSON
	summaryLogsCached          bool
	budgetMu                   sync.Mutex
	budgetSources              map[string]struct{}
	budgetQueries              int
	// Tests may lower these limits; production always uses the documented
	// constants above.
	evidenceSourceLimit int
	logsQueryLimit      int
}

type accessTokenFlight struct {
	done  chan struct{}
	token azcore.AccessToken
	err   error
}

// NewClient creates a Sentinel client using DefaultAzureCredential when a
// credential is not supplied. This supports Azure CLI login, workload
// identity, managed identity, and environment credentials without embedding
// secrets in deadair configuration.
func NewClient(cfg Config) (*Client, error) {
	for name, value := range map[string]string{
		"subscription ID": cfg.SubscriptionID,
		"resource group":  cfg.ResourceGroup,
		"workspace name":  cfg.WorkspaceName,
	} {
		if strings.TrimSpace(value) == "" {
			return nil, fmt.Errorf("Sentinel %s is required", name)
		}
	}
	remotes, err := normalizeRemoteWorkspaces(cfg.SubscriptionID, cfg.ResourceGroup, cfg.WorkspaceName, cfg.RemoteWorkspaces)
	if err != nil {
		return nil, err
	}
	credential := cfg.Credential
	if credential == nil {
		var err error
		credential, err = azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			return nil, fmt.Errorf("creating Azure default credential: %w", err)
		}
	}
	return &Client{
		SubscriptionID:   cfg.SubscriptionID,
		ResourceGroup:    cfg.ResourceGroup,
		WorkspaceName:    cfg.WorkspaceName,
		WorkspaceID:      cfg.WorkspaceID,
		RemoteWorkspaces: remotes,
		Credential:       credential,
		HTTP:             cfg.HTTP,
		ARMEndpoint:      cfg.ARMEndpoint,
		LogsEndpoint:     cfg.LogsEndpoint,
		Concurrency:      cfg.Concurrency,
	}, nil
}

func (c *Client) Name() string { return "sentinel" }

// RefreshForScan discards observations that must not survive between scans.
// It also resets the hard evidence budget that keeps one scan below Azure's
// 200 Logs queries per 30 seconds service limit.
func (c *Client) RefreshForScan(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.workspaceIDMu.Lock()
	c.workspaceIDValidated = false
	c.workspaceLocation = ""
	c.workspaceLocationValidated = false
	c.workspaceIDMu.Unlock()
	c.catalogMu.Lock()
	c.catalog = nil
	c.catalogMu.Unlock()
	c.functionsMu.Lock()
	c.functions = nil
	c.functionsMu.Unlock()
	c.watchlistsMu.Lock()
	c.watchlistsLoaded = false
	c.watchlists = nil
	c.watchlistsComplete = false
	c.watchlistsErr = nil
	c.watchlistsMu.Unlock()
	c.dependencyProbeMu.Lock()
	c.watchlistProbes = nil
	c.asimProbes = nil
	c.dependencyProbeMu.Unlock()
	c.resetRemoteState()
	c.setRemoteReferences(nil)
	c.setInstalledRules(nil)
	c.summaryLogsMu.Lock()
	c.summaryLogs = nil
	c.summaryLogsCached = false
	c.summaryLogsMu.Unlock()
	c.budgetMu.Lock()
	c.budgetSources = nil
	c.budgetQueries = 0
	c.budgetMu.Unlock()
	return nil
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 60 * time.Second}
}

func (c *Client) concurrency() int {
	if c.Concurrency > 0 && c.Concurrency < defaultConcurrency {
		return c.Concurrency
	}
	return defaultConcurrency
}

func (c *Client) evidenceSourceBudget() int {
	if c.evidenceSourceLimit > 0 && c.evidenceSourceLimit < maxEvidenceSourcesPerScan {
		return c.evidenceSourceLimit
	}
	return maxEvidenceSourcesPerScan
}

func (c *Client) logsQueryBudget() int {
	if c.logsQueryLimit > 0 && c.logsQueryLimit < maxLogsQueriesPerScan {
		return c.logsQueryLimit
	}
	return maxLogsQueriesPerScan
}

func (c *Client) claimEvidenceSource(name string) bool {
	c.budgetMu.Lock()
	defer c.budgetMu.Unlock()
	if c.budgetSources == nil {
		c.budgetSources = make(map[string]struct{})
	}
	if _, exists := c.budgetSources[name]; exists {
		return true
	}
	if len(c.budgetSources) >= c.evidenceSourceBudget() {
		return false
	}
	c.budgetSources[name] = struct{}{}
	return true
}

func (c *Client) claimLogsQuery() bool {
	c.budgetMu.Lock()
	defer c.budgetMu.Unlock()
	if c.budgetQueries >= c.logsQueryBudget() {
		return false
	}
	c.budgetQueries++
	return true
}

func (c *Client) armEndpoint() string {
	if strings.TrimSpace(c.ARMEndpoint) != "" {
		return strings.TrimRight(c.ARMEndpoint, "/")
	}
	return defaultARMEndpoint
}

func (c *Client) logsEndpoint() string {
	if strings.TrimSpace(c.LogsEndpoint) != "" {
		return strings.TrimRight(c.LogsEndpoint, "/")
	}
	return defaultLogsEndpoint
}

type statusError struct {
	method string
	target string
	code   int
	status string
	body   string
}

func (e *statusError) Error() string {
	if e.body == "" {
		return fmt.Sprintf("%s %s: %s", e.method, e.target, e.status)
	}
	return fmt.Sprintf("%s %s: %s: %s", e.method, e.target, e.status, e.body)
}

// doARM permits only GET. doLogs permits only POST to the query endpoint.
// Keeping this split makes the adapter's read-only boundary reviewable.
func (c *Client) doARM(ctx context.Context, target string, out any) error {
	return c.doJSON(ctx, http.MethodGet, target, armScope, nil, out)
}

func (c *Client) doLogs(ctx context.Context, target string, body []byte, out any) error {
	return c.doJSON(ctx, http.MethodPost, target, logsScope, body, out)
}

func (c *Client) accessToken(ctx context.Context, scope string) (azcore.AccessToken, error) {
	if err := ctx.Err(); err != nil {
		return azcore.AccessToken{}, err
	}

	c.tokenMu.Lock()
	if token, ok := c.accessTokens[scope]; ok && token.ExpiresOn.After(time.Now().Add(accessTokenRefreshSkew)) {
		c.tokenMu.Unlock()
		return token, nil
	}
	delete(c.accessTokens, scope)
	if flight := c.accessTokenFlights[scope]; flight != nil {
		c.tokenMu.Unlock()
		select {
		case <-ctx.Done():
			return azcore.AccessToken{}, ctx.Err()
		case <-flight.done:
			if err := ctx.Err(); err != nil {
				return azcore.AccessToken{}, err
			}
			return flight.token, flight.err
		}
	}
	if c.accessTokenFlights == nil {
		c.accessTokenFlights = make(map[string]*accessTokenFlight)
	}
	flight := &accessTokenFlight{done: make(chan struct{})}
	c.accessTokenFlights[scope] = flight
	c.tokenMu.Unlock()

	token, err := c.Credential.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{scope}})

	c.tokenMu.Lock()
	flight.token = token
	flight.err = err
	if err == nil && token.ExpiresOn.After(time.Now().Add(accessTokenRefreshSkew)) {
		if c.accessTokens == nil {
			c.accessTokens = make(map[string]azcore.AccessToken)
		}
		c.accessTokens[scope] = token
	}
	delete(c.accessTokenFlights, scope)
	close(flight.done)
	c.tokenMu.Unlock()
	return token, err
}

func (c *Client) doJSON(ctx context.Context, method, target, scope string, body []byte, out any) error {
	if c.Credential == nil {
		return errors.New("Azure credential is not configured")
	}
	if (scope == armScope && method != http.MethodGet) || (scope == logsScope && method != http.MethodPost) {
		return fmt.Errorf("unsupported Azure operation %s", method)
	}
	for attempt := 0; attempt < maxAttempts; attempt++ {
		token, err := c.accessToken(ctx, scope)
		if err != nil {
			return fmt.Errorf("acquiring Azure access token: %w", err)
		}
		req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token.Token)
		req.Header.Set("Accept", "application/json")
		if scope == logsScope {
			if parsed, parseErr := url.Parse(target); parseErr == nil && strings.HasSuffix(parsed.Path, "/query") {
				req.Header.Set("Prefer", "include-permissions=true,include-dataSources=true")
			}
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := c.httpClient().Do(req)
		if err != nil {
			return err
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			if out == nil {
				resp.Body.Close()
				return nil
			}
			err = json.NewDecoder(resp.Body).Decode(out)
			resp.Body.Close()
			return err
		}
		message, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		resp.Body.Close()
		statusErr := &statusError{
			method: method,
			target: target,
			code:   resp.StatusCode,
			status: resp.Status,
			body:   strings.TrimSpace(string(message)),
		}
		if (resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode != http.StatusServiceUnavailable) || attempt == maxAttempts-1 {
			return statusErr
		}
		delay := retryDelay(resp.Header.Get("Retry-After"), attempt, time.Now())
		if err := waitContext(ctx, delay); err != nil {
			return err
		}
	}
	return errors.New("Azure request retry limit reached")
}

func retryDelay(value string, attempt int, now time.Time) time.Duration {
	if seconds, err := strconv.Atoi(strings.TrimSpace(value)); err == nil && seconds >= 0 {
		return time.Duration(seconds) * time.Second
	}
	if at, err := http.ParseTime(strings.TrimSpace(value)); err == nil && at.After(now) {
		return at.Sub(now)
	}
	return time.Duration(1<<attempt) * 250 * time.Millisecond
}

func waitContext(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Client) workspaceResourcePath() string {
	return "/subscriptions/" + url.PathEscape(c.SubscriptionID) +
		"/resourceGroups/" + url.PathEscape(c.ResourceGroup) +
		"/providers/Microsoft.OperationalInsights/workspaces/" + url.PathEscape(c.WorkspaceName)
}

// workspaceID returns the Log Analytics customer ID. Callers may provide it
// directly, but ordinary CLI use only needs the ARM workspace coordinates.
func (c *Client) workspaceID(ctx context.Context) (string, error) {
	c.workspaceIDMu.Lock()
	defer c.workspaceIDMu.Unlock()
	if c.workspaceIDValidated {
		return strings.TrimSpace(c.WorkspaceID), nil
	}
	if err := c.loadWorkspaceIdentityLocked(ctx); err != nil {
		return "", err
	}
	return strings.TrimSpace(c.WorkspaceID), nil
}

// homeWorkspaceLocation returns the normalized ARM location used to enforce
// Azure Monitor's cross-region query limit. A configured workspace customer
// ID is not enough: the location is always verified through the workspace ARM
// resource before it contributes to a conclusive region count.
func (c *Client) homeWorkspaceLocation(ctx context.Context) (string, error) {
	c.workspaceIDMu.Lock()
	defer c.workspaceIDMu.Unlock()
	if !c.workspaceLocationValidated {
		if err := c.loadWorkspaceIdentityLocked(ctx); err != nil {
			return "", err
		}
	}
	location, ok := normalizeWorkspaceLocation(c.workspaceLocation)
	if !ok {
		return "", fmt.Errorf("reading Log Analytics workspace location: %w", errWorkspaceLocationMissing)
	}
	c.workspaceLocation = location
	return location, nil
}

// loadWorkspaceIdentityLocked reads identity and region in one request. The
// caller must hold workspaceIDMu.
func (c *Client) loadWorkspaceIdentityLocked(ctx context.Context) error {
	var response struct {
		Location   string `json:"location"`
		Properties struct {
			CustomerID string `json:"customerId"`
		} `json:"properties"`
	}
	target := c.armEndpoint() + c.workspaceResourcePath() + "?api-version=" + tablesAPIVersion
	if err := c.doARM(ctx, target, &response); err != nil {
		return fmt.Errorf("reading Log Analytics workspace ID: %w", err)
	}
	id := strings.TrimSpace(response.Properties.CustomerID)
	if id == "" {
		return errors.New("reading Log Analytics workspace ID: response omitted properties.customerId")
	}
	configured := strings.TrimSpace(c.WorkspaceID)
	if configured != "" && !strings.EqualFold(configured, id) {
		return errors.New("configured Log Analytics workspace ID does not match the ARM workspace customerId")
	}
	c.WorkspaceID = id
	c.workspaceIDValidated = true
	c.workspaceLocation, _ = normalizeWorkspaceLocation(response.Location)
	c.workspaceLocationValidated = true
	return nil
}

type alertRulesResponse struct {
	Value    []alertRuleJSON `json:"value"`
	NextLink string          `json:"nextLink"`
}

type alertRuleJSON struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	SystemData struct {
		LastModifiedAt string `json:"lastModifiedAt"`
	} `json:"systemData"`
	Properties struct {
		DisplayName           string `json:"displayName"`
		Enabled               *bool  `json:"enabled"`
		Severity              string `json:"severity"`
		Query                 string `json:"query"`
		QueryFrequency        string `json:"queryFrequency"`
		QueryPeriod           string `json:"queryPeriod"`
		AlertRuleTemplateName string `json:"alertRuleTemplateName"`
		LastModifiedUTC       string `json:"lastModifiedUtc"`
	} `json:"properties"`
}

// Rules inventories GA alert-rule kinds from the stable API and NRT rules
// from the preview contract where that kind is currently exposed. Preview
// failure is an inventory failure: silently omitting NRT rules would produce
// a false coverage view.
func (c *Client) Rules(ctx context.Context) ([]backend.Rule, error) {
	c.setRemoteReferences(nil)
	functions, functionsAvailable := c.workspaceFunctions(ctx)
	ga, err := c.listAlertRules(ctx, alertRulesAPIVersion)
	if err != nil {
		return nil, err
	}
	preview, err := c.listAlertRules(ctx, alertRulesPreviewAPIVersion)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	var rules []backend.Rule
	appendRule := func(raw alertRuleJSON) error {
		if err := validateAlertRuleEnabledState(raw); err != nil {
			return err
		}
		keys := alertRuleIdentityKeys(raw)
		for _, key := range keys {
			if seen[key] {
				return nil
			}
		}
		for _, key := range keys {
			seen[key] = true
		}
		rules = append(rules, sentinelRule(raw, functions, functionsAvailable))
		return nil
	}
	for _, raw := range ga {
		if !strings.EqualFold(raw.Kind, "NRT") {
			if err := appendRule(raw); err != nil {
				return nil, fmt.Errorf("invalid Sentinel rule inventory: %w", err)
			}
		}
	}
	for _, raw := range preview {
		if strings.EqualFold(raw.Kind, "NRT") {
			if err := appendRule(raw); err != nil {
				return nil, fmt.Errorf("invalid Sentinel rule inventory: %w", err)
			}
		}
	}
	if err := backend.ValidateRuleIDs(rules); err != nil {
		return nil, fmt.Errorf("invalid Sentinel rule inventory: %w", err)
	}
	c.setInstalledRules(rules)
	c.setRemoteReferences(rules)
	return rules, nil
}

func validateAlertRuleEnabledState(raw alertRuleJSON) error {
	if !strings.EqualFold(raw.Kind, "Scheduled") && !strings.EqualFold(raw.Kind, "NRT") {
		return nil
	}
	if raw.Properties.Enabled != nil {
		return nil
	}
	identity := strings.TrimSpace(raw.Name)
	if identity == "" {
		identity = resourceName(raw.ID)
	}
	if identity == "" {
		identity = "<unknown>"
	}
	return fmt.Errorf("%s alert rule %q omitted properties.enabled", raw.Kind, identity)
}

func (c *Client) listAlertRules(ctx context.Context, apiVersion string) ([]alertRuleJSON, error) {
	path := c.workspaceResourcePath() + "/providers/Microsoft.SecurityInsights/alertRules"
	target := c.armEndpoint() + path + "?api-version=" + url.QueryEscape(apiVersion)
	seen := make(map[string]bool)
	var rules []alertRuleJSON
	for page := 0; ; page++ {
		if page >= maxRulePages {
			return nil, fmt.Errorf("listing Sentinel alert rules (%s): pagination exceeded %d pages", apiVersion, maxRulePages)
		}
		if seen[target] {
			return nil, fmt.Errorf("listing Sentinel alert rules (%s): pagination cycle detected", apiVersion)
		}
		seen[target] = true
		var response alertRulesResponse
		if err := c.doARM(ctx, target, &response); err != nil {
			return nil, fmt.Errorf("listing Sentinel alert rules (%s): %w", apiVersion, err)
		}
		rules = append(rules, response.Value...)
		if strings.TrimSpace(response.NextLink) == "" {
			break
		}
		next, err := c.nextARMPage(target, response.NextLink)
		if err != nil {
			return nil, fmt.Errorf("listing Sentinel alert rules (%s): %w", apiVersion, err)
		}
		target = next
	}
	return rules, nil
}

func alertRuleIdentityKeys(raw alertRuleJSON) []string {
	var keys []string
	if id := strings.TrimSpace(raw.ID); id != "" {
		keys = append(keys, "id:"+strings.ToLower(id))
	}
	if name := strings.TrimSpace(raw.Name); name != "" {
		keys = append(keys, "name:"+strings.ToLower(name))
	}
	return keys
}

func (c *Client) nextARMPage(current, nextLink string) (string, error) {
	currentURL, err := url.Parse(current)
	if err != nil {
		return "", err
	}
	nextURL, err := url.Parse(nextLink)
	if err != nil {
		return "", fmt.Errorf("invalid nextLink: %w", err)
	}
	resolved := currentURL.ResolveReference(nextURL)
	armURL, err := url.Parse(c.armEndpoint())
	if err != nil {
		return "", err
	}
	if !strings.EqualFold(resolved.Scheme, armURL.Scheme) || !strings.EqualFold(resolved.Host, armURL.Host) {
		return "", errors.New("nextLink points outside the configured ARM endpoint")
	}
	return resolved.String(), nil
}

func sentinelRule(raw alertRuleJSON, functions map[string]WorkspaceFunction, functionsAvailable bool) backend.Rule {
	id := strings.TrimSpace(raw.Name)
	if id == "" {
		id = resourceName(raw.ID)
	}
	name := strings.TrimSpace(raw.Properties.DisplayName)
	if name == "" {
		name = id
	}
	enabled := true
	if raw.Properties.Enabled != nil {
		enabled = *raw.Properties.Enabled
	}
	severity := normalizeSeverity(raw.Properties.Severity)
	rule := backend.Rule{
		ID:                      id,
		BackendObjectID:         strings.TrimSpace(raw.ID),
		Name:                    name,
		Enabled:                 enabled,
		Severity:                severity,
		RiskScore:               severityRiskScore(severity),
		RuleType:                strings.ToLower(strings.TrimSpace(raw.Kind)),
		InputMetadataIncomplete: !functionsAvailable,
	}
	for _, modified := range []string{raw.Properties.LastModifiedUTC, raw.SystemData.LastModifiedAt} {
		modifiedAt, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(modified))
		if err == nil {
			rule.ModifiedAt = modifiedAt.UTC()
			break
		}
	}
	isScheduled := strings.EqualFold(raw.Kind, "Scheduled")
	isNRT := strings.EqualFold(raw.Kind, "NRT")
	if !isScheduled && !isNRT {
		rule.InputStatus = backend.ResolutionUnsupported
		if strings.TrimSpace(raw.Kind) == "" {
			rule.InputDetail = "Sentinel alert rule kind is missing"
		} else {
			rule.InputDetail = fmt.Sprintf("Sentinel %s alert rules are not assessed", raw.Kind)
		}
		return rule
	}
	if raw.Properties.Enabled == nil {
		rule.Enabled = false
		rule.InputStatus = backend.ResolutionUnavailable
		rule.InputDetail = fmt.Sprintf("Sentinel %s alert rule enabled state is missing from the ARM response", raw.Kind)
		return rule
	}
	if isNRT {
		rule.Lookback = time.Minute
		rule.Interval = time.Minute
		rule.TimestampOverride = "ingestion_time()"
	} else {
		rule.Lookback, _ = parseISODuration(raw.Properties.QueryPeriod)
		rule.Interval, _ = parseISODuration(raw.Properties.QueryFrequency)
	}
	resolution := ResolveKQLDependencies(raw.Properties.Query)
	if functionsAvailable {
		resolution = ResolveKQLDependenciesWithFunctions(raw.Properties.Query, functions)
	} else if hasFunctionDependency(resolution.Dependencies) {
		resolution.Status = backend.ResolutionUnavailable
		resolution.Reason = "Log Analytics workspace function metadata could not be read"
	}
	// Parser-level "no table" is not native proof that a configured table is
	// absent. Only the table-inventory join in ResolveInputs may emit Empty.
	if resolution.Status == backend.ResolutionEmpty {
		resolution.Status = backend.ResolutionUnsupported
		if strings.TrimSpace(resolution.Reason) == "" {
			resolution.Reason = "KQL query did not expose a direct table dependency"
		}
	}
	applySentinelKQLResolution(&rule, resolution)
	if selector, ok := ExtractPredicateFreshness(raw.Properties.Query); ok {
		rule.PredicateFreshness = []backend.PredicateFreshnessSelector{selector}
	}
	return rule
}

func applySentinelKQLResolution(rule *backend.Rule, resolution KQLResolution) {
	rule.Patterns, rule.OptionalPatterns = kqlTablePatterns(resolution.Dependencies)
	deferredNativeResolution := false
	unassessedDependency := false
	for _, dependency := range resolution.Dependencies {
		switch dependency.Kind {
		case KindWatchlist:
			alias := strings.TrimSpace(dependency.Name)
			if alias == "" {
				unassessedDependency = true
				continue
			}
			rule.Dependencies = append(rule.Dependencies, backend.DependencyRef{
				ID:       "sentinel_watchlist:" + strings.ToLower(alias),
				Name:     alias,
				Kind:     "sentinel_watchlist",
				Required: !dependency.Optional,
			})
			deferredNativeResolution = true
		case KindASIMBuiltin:
			name := strings.TrimSpace(dependency.Name)
			if name == "" || strings.TrimSpace(dependency.Call) == "" {
				unassessedDependency = true
				continue
			}
			rule.Dependencies = append(rule.Dependencies, backend.DependencyRef{
				ID:         "sentinel_asim_parser:" + strings.ToLower(name),
				Name:       name,
				Kind:       "sentinel_asim_parser",
				Required:   !dependency.Optional,
				Expression: dependency.Call,
			})
			deferredNativeResolution = true
		case KindRemoteTable:
			target := dependency.Target
			if target == "" {
				target = dependency.Name
			}
			kind := "sentinel_" + strings.ToLower(dependency.ScopeKind) + "_table"
			monitorable := strings.EqualFold(dependency.ScopeKind, "workspace")
			rule.Dependencies = append(rule.Dependencies, backend.DependencyRef{
				ID:          kind + ":" + canonicalRemoteScope(dependency.Scope) + ":" + target,
				Name:        target,
				Kind:        kind,
				Scope:       dependency.Scope,
				Monitorable: monitorable,
				Required:    !dependency.Optional,
			})
			if monitorable {
				deferredNativeResolution = true
			} else {
				unassessedDependency = true
			}
		case KindRemote:
			unassessedDependency = true
		}
	}
	// A native dependency probe can settle only the dependency it names. Keep
	// an independent unsupported or ambiguous query leg as its own resolver
	// outcome so the supported legs can still be inspected without allowing
	// their success to resolve the whole rule.
	if resolution.BlockingStatus != "" && (len(rule.Patterns) > 0 || len(rule.OptionalPatterns) > 0 || deferredNativeResolution) {
		rule.Dependencies = append(rule.Dependencies, backend.DependencyRef{
			Kind:       sentinelKQLBlockingDependencyKind(resolution.BlockingStatus),
			Required:   true,
			Expression: resolution.BlockingReason,
		})
		return
	}
	// The syntax pass deliberately reports every remote reference as Remote.
	// A literal workspace() dependency is assessable only after ResolveInputs
	// verifies its explicit allowlist mapping and remote ARM catalog.
	deferResolution := deferredNativeResolution && !unassessedDependency &&
		(resolution.Status == backend.ResolutionRemote || resolution.Status == backend.ResolutionUnsupported)
	if resolution.Status != backend.ResolutionResolved && !deferResolution {
		rule.InputStatus = resolution.Status
		rule.InputDetail = resolution.Reason
	}
}

const (
	sentinelKQLUnsupportedDependency = "sentinel_kql_unsupported"
	sentinelKQLAmbiguousDependency   = "sentinel_kql_ambiguous"
)

func sentinelKQLBlockingDependencyKind(status backend.ResolutionStatus) string {
	if status == backend.ResolutionAmbiguous {
		return sentinelKQLAmbiguousDependency
	}
	return sentinelKQLUnsupportedDependency
}

func hasFunctionDependency(dependencies []Dependency) bool {
	for _, dependency := range dependencies {
		if dependency.Kind == KindFunction {
			return true
		}
	}
	return false
}

func resourceName(id string) string {
	id = strings.TrimRight(strings.TrimSpace(id), "/")
	if i := strings.LastIndexByte(id, '/'); i >= 0 {
		return id[i+1:]
	}
	return id
}

func normalizeSeverity(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low", "informational":
		return "low"
	default:
		return ""
	}
}

func severityRiskScore(severity string) int {
	switch severity {
	case "critical":
		return 99
	case "high":
		return 73
	case "medium":
		return 47
	case "low":
		return 21
	default:
		return 0
	}
}

// parseISODuration accepts the day/time subset emitted by Sentinel schedule
// fields. Calendar years and months are deliberately rejected because they do
// not have a fixed duration.
func parseISODuration(value string) (time.Duration, error) {
	value = strings.TrimSpace(strings.ToUpper(value))
	if value == "" || !strings.HasPrefix(value, "P") {
		return 0, fmt.Errorf("invalid ISO 8601 duration %q", value)
	}
	value = strings.TrimPrefix(value, "P")
	var total time.Duration
	inTime := false
	consumed := false
	for len(value) > 0 {
		if value[0] == 'T' {
			if inTime {
				return 0, fmt.Errorf("invalid ISO 8601 duration")
			}
			inTime = true
			value = value[1:]
			continue
		}
		i := 0
		for i < len(value) && ((value[i] >= '0' && value[i] <= '9') || value[i] == '.') {
			i++
		}
		if i == 0 || i == len(value) {
			return 0, fmt.Errorf("invalid ISO 8601 duration")
		}
		number, err := strconv.ParseFloat(value[:i], 64)
		if err != nil || number < 0 {
			return 0, fmt.Errorf("invalid ISO 8601 duration")
		}
		unit := value[i]
		value = value[i+1:]
		var multiplier time.Duration
		switch unit {
		case 'D':
			if inTime {
				return 0, fmt.Errorf("invalid ISO 8601 duration")
			}
			multiplier = 24 * time.Hour
		case 'H':
			if !inTime {
				return 0, fmt.Errorf("invalid ISO 8601 duration")
			}
			multiplier = time.Hour
		case 'M':
			if !inTime {
				return 0, fmt.Errorf("calendar months are unsupported")
			}
			multiplier = time.Minute
		case 'S':
			if !inTime {
				return 0, fmt.Errorf("invalid ISO 8601 duration")
			}
			multiplier = time.Second
		default:
			return 0, fmt.Errorf("unsupported ISO 8601 duration unit %q", unit)
		}
		total += time.Duration(number * float64(multiplier))
		consumed = true
	}
	if !consumed {
		return 0, fmt.Errorf("invalid ISO 8601 duration")
	}
	return total, nil
}

type tableColumnJSON struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type tableJSON struct {
	Name       string `json:"name"`
	Properties struct {
		Plan              string `json:"plan"`
		ProvisioningState string `json:"provisioningState"`
		Schema            struct {
			Columns         []tableColumnJSON `json:"columns"`
			StandardColumns []tableColumnJSON `json:"standardColumns"`
		} `json:"schema"`
	} `json:"properties"`
}

type tablesResponse struct {
	Value    []tableJSON `json:"value"`
	NextLink string      `json:"nextLink"`
}

type tableInfo struct {
	schema         backend.Schema
	schemaComplete bool
	plan           string
	provisioning   string
}

type watchlistJSON struct {
	ID         string `json:"id"`
	Properties struct {
		Alias             string `json:"watchlistAlias"`
		ProvisioningState string `json:"provisioningState"`
		UploadStatus      string `json:"uploadStatus"`
		Deleted           *bool  `json:"isDeleted"`
	} `json:"properties"`
}

type watchlistsResponse struct {
	Value    []watchlistJSON `json:"value"`
	NextLink string          `json:"nextLink"`
}

type watchlistInfo struct {
	id           string
	alias        string
	provisioning string
	upload       string
	deleted      bool
	deletedKnown bool
	complete     bool
}

func (c *Client) sentinelWatchlists(ctx context.Context) (map[string]watchlistInfo, bool, error) {
	c.watchlistsMu.Lock()
	defer c.watchlistsMu.Unlock()
	if c.watchlistsLoaded {
		return cloneWatchlists(c.watchlists), c.watchlistsComplete, c.watchlistsErr
	}

	path := c.workspaceResourcePath() + "/providers/Microsoft.SecurityInsights/watchlists"
	target := c.armEndpoint() + path + "?api-version=" + url.QueryEscape(watchlistsAPIVersion)
	seenPages := make(map[string]bool)
	catalog := make(map[string]watchlistInfo)
	complete := true
	var inventoryErr error
	for page := 0; ; page++ {
		if page >= maxWatchlistPages {
			inventoryErr = fmt.Errorf("listing Sentinel watchlists: pagination exceeded %d pages", maxWatchlistPages)
			break
		}
		if seenPages[target] {
			inventoryErr = errors.New("listing Sentinel watchlists: pagination cycle detected")
			break
		}
		seenPages[target] = true
		var response watchlistsResponse
		if err := c.doARM(ctx, target, &response); err != nil {
			inventoryErr = fmt.Errorf("listing Sentinel watchlists: %w", err)
			break
		}
		for _, raw := range response.Value {
			alias := strings.TrimSpace(raw.Properties.Alias)
			if alias == "" {
				complete = false
				continue
			}
			key := strings.ToLower(alias)
			if _, duplicate := catalog[key]; duplicate {
				inventoryErr = fmt.Errorf("listing Sentinel watchlists: duplicate alias %q across pages", alias)
				break
			}
			info := watchlistInfo{
				id:           strings.TrimSpace(raw.ID),
				alias:        alias,
				provisioning: strings.TrimSpace(raw.Properties.ProvisioningState),
				upload:       strings.TrimSpace(raw.Properties.UploadStatus),
				deleted:      raw.Properties.Deleted != nil && *raw.Properties.Deleted,
				deletedKnown: raw.Properties.Deleted != nil,
			}
			// The Watchlists List contract can omit lifecycle fields even for a
			// usable watchlist. Identity and an explicit not-deleted value make the
			// inventory record complete; present lifecycle fields are negative
			// gates below, while the native query supplies current access evidence.
			info.complete = info.id != "" && info.deletedKnown
			if !info.complete {
				complete = false
			}
			catalog[key] = info
		}
		if inventoryErr != nil || strings.TrimSpace(response.NextLink) == "" {
			break
		}
		next, err := c.nextARMPage(target, response.NextLink)
		if err != nil {
			inventoryErr = fmt.Errorf("listing Sentinel watchlists: %w", err)
			break
		}
		target = next
	}
	c.watchlistsLoaded = true
	c.watchlists = cloneWatchlists(catalog)
	c.watchlistsComplete = complete && inventoryErr == nil
	c.watchlistsErr = inventoryErr
	return catalog, c.watchlistsComplete, inventoryErr
}

func cloneWatchlists(in map[string]watchlistInfo) map[string]watchlistInfo {
	out := make(map[string]watchlistInfo, len(in))
	for alias, info := range in {
		out[alias] = info
	}
	return out
}

func (c *Client) tables(ctx context.Context) (map[string]tableInfo, error) {
	c.catalogMu.Lock()
	if c.catalog != nil {
		catalog := cloneCatalog(c.catalog)
		c.catalogMu.Unlock()
		return catalog, nil
	}
	c.catalogMu.Unlock()

	path := c.workspaceResourcePath() + "/tables?api-version=" + tablesAPIVersion
	target := c.armEndpoint() + path
	seenPages := make(map[string]bool)
	catalog := make(map[string]tableInfo)
	for page := 0; ; page++ {
		if page >= maxTablePages {
			return nil, fmt.Errorf("listing Log Analytics tables: pagination exceeded %d pages", maxTablePages)
		}
		if seenPages[target] {
			return nil, errors.New("listing Log Analytics tables: pagination cycle detected")
		}
		seenPages[target] = true
		var response tablesResponse
		if err := c.doARM(ctx, target, &response); err != nil {
			return nil, fmt.Errorf("listing Log Analytics tables: %w", err)
		}
		for _, raw := range response.Value {
			name := strings.TrimSpace(raw.Name)
			if name == "" {
				continue
			}
			if _, duplicate := catalog[name]; duplicate {
				return nil, fmt.Errorf("listing Log Analytics tables: duplicate table %q across pages", name)
			}
			catalog[name] = tableInfoFromJSON(raw, name)
		}
		if strings.TrimSpace(response.NextLink) == "" {
			break
		}
		next, err := c.nextARMPage(target, response.NextLink)
		if err != nil {
			return nil, fmt.Errorf("listing Log Analytics tables: %w", err)
		}
		target = next
	}
	c.catalogMu.Lock()
	if c.catalog == nil {
		c.catalog = cloneCatalog(catalog)
	}
	c.catalogMu.Unlock()
	return catalog, nil
}

func tableInfoFromJSON(raw tableJSON, sourceName string) tableInfo {
	columns := append([]tableColumnJSON(nil), raw.Properties.Schema.StandardColumns...)
	columns = append(columns, raw.Properties.Schema.Columns...)
	schema := backend.Schema{Source: sourceName, Fields: make([]backend.Field, 0, len(columns))}
	seenFields := make(map[string]bool, len(columns))
	for _, column := range columns {
		fieldName := strings.TrimSpace(column.Name)
		if fieldName == "" || seenFields[fieldName] {
			continue
		}
		seenFields[fieldName] = true
		types := []string(nil)
		if fieldType := strings.TrimSpace(column.Type); fieldType != "" {
			types = []string{strings.ToLower(fieldType)}
		}
		schema.Fields = append(schema.Fields, backend.Field{Name: fieldName, Types: types})
	}
	sort.Slice(schema.Fields, func(i, j int) bool { return schema.Fields[i].Name < schema.Fields[j].Name })
	return tableInfo{
		schema:       schema,
		plan:         strings.TrimSpace(raw.Properties.Plan),
		provisioning: strings.TrimSpace(raw.Properties.ProvisioningState),
		schemaComplete: raw.Properties.Schema.Columns != nil ||
			raw.Properties.Schema.StandardColumns != nil,
	}
}

func cloneCatalog(in map[string]tableInfo) map[string]tableInfo {
	out := make(map[string]tableInfo, len(in))
	for name, info := range in {
		info.schema.Fields = append([]backend.Field(nil), info.schema.Fields...)
		for i := range info.schema.Fields {
			info.schema.Fields[i].Types = append([]string(nil), info.schema.Fields[i].Types...)
		}
		out[name] = info
	}
	return out
}

// tableResolutionLimitation explains table states that cannot be used as
// authoritative Sentinel rule-input evidence. Basic and Auxiliary tables do
// not support the analytics-rule query path used by this adapter; tables
// outside Succeeded may be transitional or failed and remain unavailable.
func tableResolutionLimitation(info tableInfo) (backend.ResolutionStatus, string, bool) {
	if !strings.EqualFold(info.provisioning, "Succeeded") {
		state := info.provisioning
		if state == "" {
			state = "unknown"
		}
		return backend.ResolutionUnavailable, fmt.Sprintf("table provisioning state is %s", state), true
	}
	if strings.EqualFold(info.plan, "Auxiliary") || strings.EqualFold(info.plan, "Basic") {
		return backend.ResolutionIncompatible, info.plan + "-plan tables are not eligible for Sentinel analytics-rule evidence", true
	}
	return "", "", false
}

func tableRuntimeLimitation(info tableInfo) (backend.EvidenceStatus, string, bool) {
	_, detail, limited := tableResolutionLimitation(info)
	if !limited {
		return "", "", false
	}
	return backend.EvidenceUnavailable, detail, true
}

// Sources inventories workspace tables using ARM metadata only. Azure does
// not expose a cheap exact total row count, so Docs remains -1. Runtime
// freshness is a separate targeted capability: a connection check or broad
// inventory must never issue one Logs query per workspace table.
func (c *Client) Sources(ctx context.Context) ([]backend.Source, error) {
	catalog, err := c.tables(ctx)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(catalog))
	for name := range catalog {
		names = append(names, name)
	}
	for _, state := range c.referencedRemoteStates() {
		remoteCatalog, remoteErr := c.remoteTables(ctx, state)
		if remoteErr != nil {
			// A configured remote target may be unreadable while local evidence
			// remains usable. ResolveInputs retains the target-specific failure;
			// omitting it here must never become proof that its table is absent.
			continue
		}
		for table := range remoteCatalog {
			names = append(names, qualifiedRemoteSource(state.resourceID, table))
		}
	}
	sort.Strings(names)
	sources := make([]backend.Source, len(names))
	for i, name := range names {
		sources[i] = backend.Source{Name: name, Docs: -1}
	}
	return sources, nil
}

// setRemoteReferences records only remote workspaces consumed by rules that
// can participate in this scan. The configured mapping file is an allowlist,
// not a request to inventory every listed workspace.
func (c *Client) setRemoteReferences(rules []backend.Rule) {
	seen := make(map[string]bool)
	var references []string
	for _, rule := range rules {
		if !rule.Enabled || rule.InputStatus != "" {
			continue
		}
		for _, dependency := range rule.Dependencies {
			if dependency.Kind != "sentinel_workspace_table" {
				continue
			}
			scope := canonicalRemoteScope(dependency.Scope)
			if scope == "" || seen[scope] {
				continue
			}
			seen[scope] = true
			references = append(references, scope)
		}
	}
	sort.Strings(references)
	c.remoteReferencesMu.Lock()
	c.remoteReferences = references
	c.remoteReferencesMu.Unlock()
}

// referencedRemoteStates resolves rule references against the explicit local
// mapping without making Azure calls. ARM validation and table inventory are
// then performed only for the selected mappings. A native workspace customer
// ID selects an exact configured WorkspaceID or the sole mapping that can
// still match; aliases and canonical ARM resource IDs are deterministic.
func (c *Client) referencedRemoteStates() []*remoteWorkspaceState {
	c.remoteReferencesMu.Lock()
	references := append([]string(nil), c.remoteReferences...)
	c.remoteReferencesMu.Unlock()

	states := c.remoteStateMap()
	selected := make(map[*remoteWorkspaceState]bool)
	for _, scope := range references {
		var state *remoteWorkspaceState
		switch {
		case strings.HasPrefix(scope, "/"):
			state = states["resource:"+strings.ToLower(scope)]
		case looksLikeWorkspaceID(scope):
			state = states["workspace:"+strings.ToLower(scope)]
			if state == nil {
				candidates := remoteWorkspaceIDCandidates(states, scope)
				if len(candidates) == 1 {
					state = candidates[0]
				}
			}
		default:
			state = states["alias:"+strings.ToLower(scope)]
		}
		if state != nil {
			selected[state] = true
		}
	}
	out := make([]*remoteWorkspaceState, 0, len(selected))
	for state := range selected {
		out = append(out, state)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].resourceID < out[j].resourceID })
	return out
}

// FreshnessEvidence preserves the source-only capability for callers that do
// not carry rule timing. Such callers get ingestion-time evidence.
func (c *Client) FreshnessEvidence(ctx context.Context, sources []backend.Source) (map[string]backend.FreshnessEvidence, error) {
	requests := make([]backend.FreshnessRequest, 0, len(sources))
	for _, source := range sources {
		requests = append(requests, backend.FreshnessRequest{Source: source, Basis: backend.FreshnessIngestionTime})
	}
	return c.FreshnessEvidenceFor(ctx, requests)
}

// FreshnessEvidenceFor keeps Scheduled rules on TimeGenerated and NRT rules
// on ingestion_time(). A source shared by both remains explicitly incomplete
// because one source-level LastEvent cannot represent both clocks safely.
func (c *Client) FreshnessEvidenceFor(ctx context.Context, requests []backend.FreshnessRequest) (map[string]backend.FreshnessEvidence, error) {
	if len(requests) == 0 {
		return map[string]backend.FreshnessEvidence{}, nil
	}
	catalog, err := c.tables(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string]backend.FreshnessEvidence, len(requests))
	sem := make(chan struct{}, c.concurrency())
	var wg sync.WaitGroup
	var mu sync.Mutex
	seen := make(map[string]bool, len(requests))
	tasks := make([]backend.FreshnessRequest, 0, len(requests))
	for _, request := range requests {
		source := request.Source
		if seen[source.Name] {
			continue
		}
		seen[source.Name] = true
		if request.Basis == backend.FreshnessMixed {
			out[source.Name] = backend.FreshnessEvidence{
				Status: backend.EvidenceIncomplete, Method: "mixed-rule-timing",
				ObservedAt: time.Now().UTC(), Window: freshnessWindow,
				Detail: "source is shared by Scheduled and NRT rules; source-level freshness cannot represent both clocks",
			}
			continue
		}
		if !c.claimEvidenceSource(source.Name) {
			method := freshnessMethod(request.Basis)
			out[source.Name] = backend.FreshnessEvidence{
				Status:     backend.EvidenceIncomplete,
				Method:     method,
				ObservedAt: time.Now().UTC(),
				Window:     freshnessWindow,
				Detail:     "per-scan source evidence budget was exhausted",
			}
			continue
		}
		tasks = append(tasks, request)
	}
	for _, request := range tasks {
		request := request
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			source := request.Source
			evidence := backend.FreshnessEvidence{
				Status:     backend.EvidenceIncomplete,
				Method:     freshnessMethod(request.Basis),
				ObservedAt: time.Now().UTC(),
				Window:     freshnessWindow,
				Detail:     "bounded freshness query could not be read",
			}
			target, targetErr := c.sourceTarget(ctx, source.Name, catalog)
			if targetErr != nil {
				evidence.Status, evidence.Detail = evidenceFailure(targetErr)
			} else if !target.found {
				evidence.Detail = "source is absent from the workspace table inventory"
			} else if status, detail, limited := tableRuntimeLimitation(target.info); limited {
				evidence.Status = status
				evidence.Detail = detail
			} else if request.Basis == backend.FreshnessEventTime && !catalogHasField(target.info, "TimeGenerated") {
				evidence.Status = backend.EvidenceUnavailable
				evidence.Detail = "table schema does not expose TimeGenerated"
			} else {
				if target.queryReference == "" {
					evidence.Detail = "table name cannot be represented safely in KQL"
				} else {
					query := fmt.Sprintf("%s | where TimeGenerated >= ago(%dh) | summarize LastEvent=max(TimeGenerated)", target.queryReference, int(freshnessWindow/time.Hour))
					if request.Basis == backend.FreshnessIngestionTime {
						query = fmt.Sprintf("%s | extend IngestionTime=ingestion_time() | where IngestionTime >= ago(%dh) | summarize LastEvent=max(IngestionTime)", target.queryReference, int(freshnessWindow/time.Hour))
					}
					result, queryErr := c.queryLogsForSource(ctx, query, target)
					if queryErr == nil {
						evidence = freshnessFromTable(result, evidence)
					} else {
						evidence.Status, evidence.Detail = evidenceFailure(queryErr)
					}
				}
			}
			mu.Lock()
			out[source.Name] = evidence
			mu.Unlock()
		}()
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func freshnessMethod(basis backend.FreshnessBasis) string {
	if basis == backend.FreshnessIngestionTime {
		return "bounded-max-ingestion-time"
	}
	return "bounded-max-event-time"
}

func freshnessFromTable(table logsTable, evidence backend.FreshnessEvidence) backend.FreshnessEvidence {
	columnIndex := -1
	for i, column := range table.Columns {
		if column.Name == "LastEvent" {
			columnIndex = i
			break
		}
	}
	if columnIndex < 0 {
		evidence.Detail = "bounded freshness result omitted LastEvent"
		return evidence
	}
	evidence.Status = backend.EvidenceAssessed
	evidence.Detail = "no events were found in the bounded freshness window"
	if len(table.Rows) == 0 || columnIndex >= len(table.Rows[0]) || bytes.Equal(bytes.TrimSpace(table.Rows[0][columnIndex]), []byte("null")) {
		return evidence
	}
	lastEvent, ok := parseLogTime(table.Rows[0][columnIndex])
	if !ok {
		evidence.Status = backend.EvidenceIncomplete
		evidence.Detail = "bounded freshness result contained an invalid LastEvent"
		return evidence
	}
	evidence.LastEvent = lastEvent
	evidence.Detail = ""
	return evidence
}

// Schemas returns current table schemas for the caller-selected sources.
// Tables whose schema was omitted by ARM are left absent, preserving unknown
// rather than recording an empty schema.
func (c *Client) Schemas(ctx context.Context, sources []backend.Source) (map[string]backend.Schema, error) {
	catalog, err := c.tables(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string]backend.Schema, len(sources))
	for _, source := range sources {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		target, targetErr := c.sourceTarget(ctx, source.Name, catalog)
		if targetErr != nil || !target.found || !target.info.schemaComplete {
			continue
		}
		out[source.Name] = target.info.schema
	}
	return out, nil
}

// RequiredFieldEvidence answers targeted field questions from ARM's complete
// schema for each concrete table. Missing table/schema evidence is incomplete,
// never evidence that every requested field is absent.
func (c *Client) RequiredFieldEvidence(ctx context.Context, sources []backend.Source, fields []string) (map[string]backend.FieldEvidence, error) {
	out := make(map[string]backend.FieldEvidence, len(sources))
	if len(fields) == 0 {
		return out, nil
	}
	catalog, err := c.tables(ctx)
	if err != nil {
		return nil, err
	}
	for _, source := range sources {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		evidence := backend.FieldEvidence{Status: backend.EvidenceIncomplete, Detail: "table schema could not be read"}
		target, targetErr := c.sourceTarget(ctx, source.Name, catalog)
		if targetErr == nil && target.found && target.info.schemaComplete {
			available := make(map[string]bool, len(target.info.schema.Fields))
			for _, field := range target.info.schema.Fields {
				available[field.Name] = true
			}
			evidence = backend.FieldEvidence{Status: backend.EvidenceAssessed, Fields: make(map[string]bool, len(fields))}
			for _, field := range fields {
				evidence.Fields[field] = available[field]
			}
		}
		out[source.Name] = evidence
	}
	return out, nil
}

func catalogHasField(info tableInfo, name string) bool {
	if !info.schemaComplete {
		return false
	}
	for _, field := range info.schema.Fields {
		if field.Name == name {
			return true
		}
	}
	return false
}

func kqlTableReference(name string) (string, bool) {
	if simpleTableNameRE.MatchString(name) {
		return name, true
	}
	if azureTableNameRE.MatchString(name) {
		return "['" + name + "']", true
	}
	return "", false
}

type tablePermissionEvidence struct {
	status backend.EvidenceStatus
	detail string
}

type sentinelSelectorOutcome struct {
	table              string
	selector           string
	selectorKind       string
	method             string
	optional           bool
	permissionVerified bool
	status             backend.ResolutionStatus
	detail             string
	sources            []string
	dependencies       []backend.DependencyRef
}

type dependencyProbeResult struct {
	status            backend.ResolutionStatus
	detail            string
	sources           []string
	dependencyID      string
	attempted         bool
	inventoryAssessed bool
}

func (c *Client) probeWatchlistDependency(ctx context.Context, dependency backend.DependencyRef) dependencyProbeResult {
	key := strings.ToLower(strings.TrimSpace(dependency.Name))
	c.dependencyProbeMu.Lock()
	defer c.dependencyProbeMu.Unlock()
	if cached, ok := c.watchlistProbes[key]; ok {
		cached.sources = append([]string(nil), cached.sources...)
		return cached
	}
	result := c.probeWatchlistDependencyUncached(ctx, dependency)
	if c.watchlistProbes == nil {
		c.watchlistProbes = make(map[string]dependencyProbeResult)
	}
	c.watchlistProbes[key] = result
	return result
}

func (c *Client) probeWatchlistDependencyUncached(ctx context.Context, dependency backend.DependencyRef) dependencyProbeResult {
	alias := strings.TrimSpace(dependency.Name)
	if alias == "" {
		return dependencyProbeResult{status: backend.ResolutionUnsupported, detail: "watchlist alias is empty"}
	}
	catalog, complete, err := c.sentinelWatchlists(ctx)
	if err != nil {
		return dependencyProbeResult{status: backend.ResolutionUnavailable, detail: "Sentinel watchlist inventory could not be read", attempted: true}
	}
	info, found := catalog[strings.ToLower(alias)]
	if !found {
		if !complete {
			return dependencyProbeResult{status: backend.ResolutionUnavailable, detail: "Sentinel watchlist inventory was incomplete, so absence is not authoritative", attempted: true}
		}
		return dependencyProbeResult{status: backend.ResolutionEmpty, detail: "watchlist alias is absent from the complete Sentinel inventory", inventoryAssessed: true}
	}
	if !info.complete {
		return dependencyProbeResult{status: backend.ResolutionUnavailable, detail: "watchlist inventory metadata is incomplete", attempted: true}
	}
	if info.deleted {
		return dependencyProbeResult{status: backend.ResolutionEmpty, detail: "watchlist is marked deleted in the Sentinel inventory", inventoryAssessed: true}
	}
	if info.provisioning != "" && !strings.EqualFold(info.provisioning, "Succeeded") {
		return dependencyProbeResult{status: backend.ResolutionUnavailable, detail: "watchlist provisioning is not complete", attempted: true}
	}
	if info.upload != "" && !strings.EqualFold(info.upload, "Complete") && !strings.EqualFold(info.upload, "Succeeded") {
		return dependencyProbeResult{status: backend.ResolutionUnavailable, detail: "watchlist upload is not complete", attempted: true}
	}
	response, err := c.queryLogsResponse(ctx, "_GetWatchlist("+kqlStringLiteral(alias)+") | take 0")
	if err != nil {
		return dependencyProbeResult{status: backend.ResolutionUnavailable, detail: dependencyQueryFailureDetail(err, "watchlist"), attempted: true}
	}
	if response.Error != nil {
		return dependencyProbeResult{status: backend.ResolutionUnavailable, detail: "watchlist query returned a partial or failed result", attempted: true}
	}
	tables, err := c.validateNativeLogsPermissions(response, false)
	if err != nil {
		return dependencyProbeResult{status: backend.ResolutionUnavailable, detail: err.Error(), attempted: true}
	}
	for _, table := range tables {
		if table != "Watchlist" && table != "ConfidentialWatchlist" {
			return dependencyProbeResult{status: backend.ResolutionUnavailable, detail: "watchlist query data-source evidence exposed an unrelated table", attempted: true}
		}
	}
	if len(response.Tables) == 0 {
		return dependencyProbeResult{status: backend.ResolutionUnavailable, detail: "watchlist query returned no result table", attempted: true}
	}
	return dependencyProbeResult{
		status: backend.ResolutionResolved, detail: "watchlist exists and bounded Logs access was verified",
		dependencyID: info.id, attempted: true,
	}
}

func (c *Client) probeASIMDependency(ctx context.Context, dependency backend.DependencyRef, catalog map[string]tableInfo) dependencyProbeResult {
	key := asimDependencyProbeKey(dependency)
	c.dependencyProbeMu.Lock()
	defer c.dependencyProbeMu.Unlock()
	if cached, ok := c.asimProbes[key]; ok {
		cached.sources = append([]string(nil), cached.sources...)
		return cached
	}
	result := c.probeASIMDependencyUncached(ctx, dependency, catalog)
	if c.asimProbes == nil {
		c.asimProbes = make(map[string]dependencyProbeResult)
	}
	c.asimProbes[key] = result
	result.sources = append([]string(nil), result.sources...)
	return result
}

func asimDependencyProbeKey(dependency backend.DependencyRef) string {
	return strings.ToLower(strings.TrimSpace(dependency.Name)) + "\x00" + strings.TrimSpace(dependency.Expression)
}

func (c *Client) probeASIMDependencyUncached(ctx context.Context, dependency backend.DependencyRef, catalog map[string]tableInfo) dependencyProbeResult {
	call := strings.TrimSpace(dependency.Expression)
	if !validatedASIMProbeCall(dependency.Name, call) {
		return dependencyProbeResult{status: backend.ResolutionUnsupported, detail: "ASIM parser call is dynamic or was not produced by the bounded KQL analyzer"}
	}
	response, err := c.queryLogsResponse(ctx, call+" | take 0")
	if err != nil {
		return dependencyProbeResult{status: backend.ResolutionUnavailable, detail: dependencyQueryFailureDetail(err, "ASIM parser"), attempted: true}
	}
	if response.Error != nil {
		if asimSemanticPartialError(response) {
			return dependencyProbeResult{
				status: backend.ResolutionUnsupported, attempted: true,
				detail: "ASIM parser query reported known unresolved semantic dependencies",
			}
		}
		return dependencyProbeResult{status: backend.ResolutionUnavailable, detail: "ASIM parser query returned an unverified partial or failed result", attempted: true}
	}
	if len(response.Tables) == 0 {
		return dependencyProbeResult{status: backend.ResolutionUnavailable, detail: "ASIM parser query returned no result table", attempted: true}
	}
	tables, err := c.validateNativeLogsPermissions(response, true)
	if err != nil {
		return dependencyProbeResult{status: backend.ResolutionUnavailable, detail: err.Error(), attempted: true}
	}
	if len(tables) == 0 {
		return dependencyProbeResult{status: backend.ResolutionUnsupported, detail: "ASIM parser query exposed no concrete local table dependency", attempted: true}
	}
	for _, table := range tables {
		info, found := catalog[table]
		if !found {
			return dependencyProbeResult{status: backend.ResolutionUnsupported, detail: "ASIM parser returned a table absent from the complete local ARM catalog", attempted: true}
		}
		if status, detail, limited := tableResolutionLimitation(info); limited {
			return dependencyProbeResult{status: status, detail: "ASIM parser table is not assessable: " + detail, attempted: true}
		}
	}
	return dependencyProbeResult{
		status: backend.ResolutionResolved, sources: tables,
		detail: "ASIM parser dependencies were verified through a bounded native query", attempted: true,
	}
}

// asimSemanticPartialError recognizes the narrow warning-only error shape
// returned when a built-in ASIM parser expands across parsers or tables that
// are not installed. Everything else remains a runtime evidence failure. In
// particular, an explicit permission denial wins even if semantic warnings
// are present in the same response.
func asimSemanticPartialError(response logsQueryResponse) bool {
	queryErr := response.Error
	if queryErr == nil || queryErr.Code != "PartialError" || queryErr.InnerError != nil || len(queryErr.Details) == 0 {
		return false
	}
	if logsQueryErrorHasAccessFailure(queryErr) {
		return false
	}
	if response.Permissions != nil {
		for _, permission := range response.Permissions.DataSources {
			if len(permission.DenyTables) > 0 {
				return false
			}
		}
	}
	unresolvedDependency := false
	for _, detail := range queryErr.Details {
		if detail.Code != "EngineError" || detail.InnerError == nil {
			return false
		}
		inner := detail.InnerError
		if inner.Code != "-2133196790" || inner.Severity != 3 || inner.SeverityName != "Warning" || len(inner.Details) > 0 || inner.InnerError != nil {
			return false
		}
		recognized, unresolved := recognizedASIMSemanticWarning(strings.TrimSpace(inner.Message))
		if !recognized {
			return false
		}
		unresolvedDependency = unresolvedDependency || unresolved
	}
	return unresolvedDependency
}

func logsQueryErrorHasAccessFailure(queryErr *logsQueryError) bool {
	if queryErr == nil {
		return false
	}
	code := strings.ToLower(strings.TrimSpace(queryErr.Code))
	switch code {
	case "accessdenied", "authenticationfailed", "authorizationfailed", "forbidden", "unauthorized":
		return true
	}
	message := strings.ToLower(queryErr.Message)
	for _, phrase := range []string{"access denied", "authentication failed", "authorization failed", "forbidden", "not authorized", "permission denied", "unauthorized"} {
		if strings.Contains(message, phrase) {
			return true
		}
	}
	if logsQueryErrorHasAccessFailure(queryErr.InnerError) {
		return true
	}
	for i := range queryErr.Details {
		if logsQueryErrorHasAccessFailure(&queryErr.Details[i]) {
			return true
		}
	}
	return false
}

func recognizedASIMSemanticWarning(message string) (recognized, unresolvedDependency bool) {
	switch message {
	case "Operator source expression should be table or column",
		"Internal error while analyzing lookup operator.",
		"union: must have at least one operand that can be evaluated successfully when running with 'Fuzzy' mode.":
		return true, false
	}
	if asimUnresolvedFunctionRE.MatchString(message) || asimUnresolvedTableRE.MatchString(message) || asimUnresolvedTableOrColumnRE.MatchString(message) {
		return true, true
	}
	if asimUnresolvedLetRE.MatchString(message) || asimUnresolvedArgumentRE.MatchString(message) {
		return true, false
	}
	return false, false
}

func validatedASIMProbeCall(name, call string) bool {
	if strings.TrimSpace(name) == "" || strings.TrimSpace(call) == "" {
		return false
	}
	resolution := ResolveKQLDependencies(call)
	if len(resolution.Dependencies) != 1 {
		return false
	}
	dependency := resolution.Dependencies[0]
	return dependency.Kind == KindASIMBuiltin && dependency.Name == name && dependency.Call == call
}

func dependencyQueryFailureDetail(err error, dependency string) string {
	var statusErr *statusError
	if errors.As(err, &statusErr) && (statusErr.code == http.StatusUnauthorized || statusErr.code == http.StatusForbidden) {
		return dependency + " query access is unavailable"
	}
	var evidenceErr *logsEvidenceError
	if errors.As(err, &evidenceErr) {
		return evidenceErr.detail
	}
	return dependency + " query evidence could not be read"
}

func (c *Client) validateNativeLogsPermissions(response logsQueryResponse, requireExactLocalScope bool) ([]string, error) {
	if response.Permissions == nil || len(response.Permissions.DataSources) == 0 {
		return nil, errors.New("Logs query permission evidence was omitted")
	}
	if len(response.DataSources) == 0 {
		return nil, errors.New("Logs query data-source evidence was omitted")
	}
	tableSet := make(map[string]bool)
	for _, source := range response.DataSources {
		if requireExactLocalScope && !c.isExactLocalLogsSource(source.ResourceID, source.Workspace) {
			return nil, errors.New("Logs query data-source evidence was not scoped to the exact local workspace")
		}
		if !requireExactLocalScope && (source.ResourceID != "" || source.Workspace != "") && !c.isExactLocalLogsSource(source.ResourceID, source.Workspace) {
			return nil, errors.New("Logs query data-source evidence referred to a nonlocal workspace")
		}
		for _, table := range source.Tables {
			table = strings.TrimSpace(table)
			if table == "" || !simpleTableNameRE.MatchString(table) {
				return nil, errors.New("Logs query exposed an invalid or dynamic table dependency")
			}
			tableSet[table] = true
		}
	}
	if len(tableSet) == 0 {
		return nil, errors.New("Logs query data-source evidence exposed no table")
	}
	for table := range tableSet {
		allowed := false
		permissionScopeSeen := !requireExactLocalScope
		for _, permission := range response.Permissions.DataSources {
			if requireExactLocalScope {
				if permission.ResourceID == "" || !c.isExactLocalLogsSource(permission.ResourceID, "") {
					continue
				}
				permissionScopeSeen = true
			} else if permission.ResourceID != "" && !c.isExactLocalLogsSource(permission.ResourceID, "") {
				continue
			}
			for _, denied := range permission.DenyTables {
				if permissionDenyMatches(denied, table) {
					return nil, fmt.Errorf("Logs query permission evidence explicitly denied table %s", table)
				}
			}
			for _, candidate := range permission.AllowTables {
				if candidate == table {
					allowed = true
				}
			}
			if permission.AllowTables == nil {
				// The Logs permissions contract omits allowTables for full table
				// access. An explicit empty list is different and proves nothing.
				allowed = true
			}
		}
		if !permissionScopeSeen {
			return nil, errors.New("Logs query permission evidence did not confirm the exact local workspace")
		}
		if !allowed {
			return nil, fmt.Errorf("Logs query permission evidence did not positively allow table %s", table)
		}
	}
	tables := make([]string, 0, len(tableSet))
	for table := range tableSet {
		tables = append(tables, table)
	}
	sort.Strings(tables)
	return tables, nil
}

func (c *Client) isExactLocalLogsSource(resourceID, workspace string) bool {
	localResourceID := canonicalWorkspaceResourceID(c.SubscriptionID, c.ResourceGroup, c.WorkspaceName)
	matched := false
	if strings.TrimSpace(resourceID) != "" {
		matched = true
		if canonicalRemoteScope(resourceID) != localResourceID {
			return false
		}
	}
	if strings.TrimSpace(workspace) != "" {
		matched = true
		if strings.TrimSpace(c.WorkspaceID) == "" || !strings.EqualFold(strings.TrimSpace(workspace), strings.TrimSpace(c.WorkspaceID)) {
			return false
		}
	}
	return matched
}

func (c *Client) probeTablePermissions(ctx context.Context, tables []string) (map[string]tablePermissionEvidence, error) {
	out := make(map[string]tablePermissionEvidence, len(tables))
	if len(tables) == 0 {
		return out, nil
	}
	sem := make(chan struct{}, c.concurrency())
	var wg sync.WaitGroup
	var mu sync.Mutex
	tasks := make([]string, 0, len(tables))
	for _, table := range tables {
		if !c.claimEvidenceSource(table) {
			out[table] = tablePermissionEvidence{
				status: backend.EvidenceIncomplete,
				detail: "per-scan source evidence budget was exhausted",
			}
			continue
		}
		tasks = append(tasks, table)
	}
	localCatalog, err := c.tables(ctx)
	if err != nil {
		return nil, err
	}
	for _, table := range tasks {
		table := table
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			evidence := tablePermissionEvidence{
				status: backend.EvidenceIncomplete,
				detail: "Logs query permission evidence could not be read",
			}
			target, targetErr := c.sourceTarget(ctx, table, localCatalog)
			if targetErr == nil && target.queryReference != "" {
				query := target.queryReference + " | take 0"
				if _, err := c.queryLogsForSource(ctx, query, target); err == nil {
					evidence.status = backend.EvidenceAssessed
					evidence.detail = ""
				} else {
					evidence.status, evidence.detail = evidenceFailure(err)
				}
			} else if targetErr != nil {
				evidence.status, evidence.detail = evidenceFailure(targetErr)
			} else {
				evidence.detail = "table name cannot be represented safely in KQL"
			}
			mu.Lock()
			out[table] = evidence
			mu.Unlock()
		}()
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func readinessDependencies(rules []backend.Rule) []backend.DependencyRef {
	byKey := make(map[string]backend.DependencyRef)
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		for _, dependency := range rule.Dependencies {
			var key string
			switch dependency.Kind {
			case "sentinel_watchlist":
				key = dependency.Kind + "\x00" + strings.ToLower(strings.TrimSpace(dependency.Name))
			case "sentinel_asim_parser":
				key = dependency.Kind + "\x00" + asimDependencyProbeKey(dependency)
			default:
				continue
			}
			current, found := byKey[key]
			if !found || (!current.Required && dependency.Required) {
				byKey[key] = dependency
			}
		}
	}
	keys := make([]string, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	targets := make([]backend.DependencyRef, 0, len(keys))
	for _, key := range keys {
		targets = append(targets, byKey[key])
	}
	return targets
}

func readinessDependencyKind(kind string) string {
	switch kind {
	case "sentinel_watchlist":
		return "Sentinel watchlist"
	case "sentinel_asim_parser":
		return "Sentinel ASIM parser"
	default:
		return "Sentinel dependency"
	}
}

func dependencyReadinessFailure(dependency backend.DependencyRef, result dependencyProbeResult) *backend.ReadinessEvidence {
	detail := result.detail
	if detail == "" {
		detail = "dependency resolution is " + string(result.status)
	}
	switch dependency.Kind {
	case "sentinel_watchlist":
		if result.status == backend.ResolutionUnavailable {
			return &backend.ReadinessEvidence{
				Status:    backend.EvidenceUnavailable,
				Attempted: true,
				Detail:    readinessDependencyKind(dependency.Kind) + " readiness could not be established: " + detail,
			}
		}
	case "sentinel_asim_parser":
		if !result.attempted {
			return nil
		}
		switch result.status {
		case backend.ResolutionResolved:
			return nil
		case backend.ResolutionUnavailable:
			return &backend.ReadinessEvidence{
				Status:    backend.EvidenceUnavailable,
				Attempted: true,
				Detail:    readinessDependencyKind(dependency.Kind) + " readiness could not be established: " + detail,
			}
		default:
			return &backend.ReadinessEvidence{
				Status:    backend.EvidenceAssessed,
				Attempted: true,
				Limited:   true,
				Detail:    readinessDependencyKind(dependency.Kind) + " read path was reached, but resolution is " + string(result.status) + ": " + detail,
			}
		}
	}
	return nil
}

// ReadinessEvidence proves the bounded read path for every watchlist, ASIM
// parser, and query-eligible table consumed by an enabled rule. A workspace
// with no attempted dependency or table probe is usable only with limits: ARM
// inventory works, but runtime query access is unproven.
func (c *Client) ReadinessEvidence(ctx context.Context, rules []backend.Rule, sources []backend.Source) (backend.ReadinessEvidence, error) {
	catalog, err := c.tables(ctx)
	if err != nil {
		return backend.ReadinessEvidence{}, err
	}
	c.primeRemoteAliasProofs(ctx, rules)
	dependencyAttempts := 0
	dependencyInventoryAssessments := 0
	var dependencyBlocker *backend.ReadinessEvidence
	var dependencyLimit *backend.ReadinessEvidence
	for _, dependency := range readinessDependencies(rules) {
		var result dependencyProbeResult
		switch dependency.Kind {
		case "sentinel_watchlist":
			result = c.probeWatchlistDependency(ctx, dependency)
		case "sentinel_asim_parser":
			result = c.probeASIMDependency(ctx, dependency, catalog)
		}
		if result.attempted {
			dependencyAttempts++
		}
		if result.inventoryAssessed {
			dependencyInventoryAssessments++
		}
		if outcome := dependencyReadinessFailure(dependency, result); outcome != nil {
			if outcome.Status != backend.EvidenceAssessed {
				if dependencyBlocker == nil {
					dependencyBlocker = outcome
				}
			} else if outcome.Limited && dependencyLimit == nil {
				dependencyLimit = outcome
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return backend.ReadinessEvidence{}, err
	}
	if dependencyBlocker != nil {
		return *dependencyBlocker, nil
	}
	visible := make(map[string]bool, len(sources))
	for _, source := range sources {
		visible[source.Name] = true
	}
	targetSet := make(map[string]bool)
	for _, rule := range rules {
		if !rule.Enabled || rule.InputStatus != "" {
			continue
		}
		required, optional := ruleDependencyPatterns(rule)
		candidateSources := append(append([]string(nil), required...), optional...)
		for _, dependency := range rule.Dependencies {
			if dependency.Kind != "sentinel_workspace_table" {
				continue
			}
			state, resolveErr := c.resolveRemoteWorkspace(ctx, dependency.Scope)
			if resolveErr != nil {
				return backend.ReadinessEvidence{Status: backend.EvidenceUnavailable, Attempted: true, Detail: "configured remote workspace could not be verified through ARM"}, nil
			}
			if state == nil {
				continue
			}
			if remoteScopeNeedsAliasProof(dependency.Scope) {
				remoteCatalog, catalogErr := c.remoteTables(ctx, state)
				if catalogErr != nil {
					return backend.ReadinessEvidence{Status: backend.EvidenceUnavailable, Attempted: true, Detail: "configured remote workspace table inventory could not be read"}, nil
				}
				_, proof := c.validateRemoteAlias(ctx, state, dependency.Scope, remoteCatalog, []string{dependency.Name})
				if proof.status != backend.EvidenceAssessed {
					return backend.ReadinessEvidence{Status: proof.status, Attempted: true, Detail: proof.detail}, nil
				}
			}
			candidateSources = append(candidateSources, qualifiedRemoteSource(state.resourceID, dependency.Name))
		}
		for _, sourceName := range candidateSources {
			if !visible[sourceName] {
				continue
			}
			target, targetErr := c.sourceTarget(ctx, sourceName, catalog)
			if targetErr != nil || !target.found {
				continue
			}
			if _, _, limited := tableResolutionLimitation(target.info); limited {
				continue
			}
			if target.queryReference == "" {
				continue
			}
			targetSet[sourceName] = true
		}
	}
	targets := make([]string, 0, len(targetSet))
	for table := range targetSet {
		targets = append(targets, table)
	}
	sort.Strings(targets)
	if len(targets) == 0 {
		if dependencyAttempts > 0 {
			if dependencyLimit != nil {
				return *dependencyLimit, nil
			}
			return backend.ReadinessEvidence{
				Status:    backend.EvidenceAssessed,
				Attempted: true,
				Detail:    fmt.Sprintf("bounded read evidence collected for %s", counted(dependencyAttempts, "Sentinel dependency path", "Sentinel dependency paths")),
			}, nil
		}
		if dependencyInventoryAssessments > 0 {
			return backend.ReadinessEvidence{
				Status:  backend.EvidenceAssessed,
				Limited: true,
				Detail:  fmt.Sprintf("ARM inventory evidence collected for %s, but no runtime Logs query was attempted", counted(dependencyInventoryAssessments, "Sentinel dependency path", "Sentinel dependency paths")),
			}, nil
		}
		return backend.ReadinessEvidence{
			Status: backend.EvidenceUnavailable,
			Detail: "no query-eligible Analytics table consumed by an enabled rule was visible",
		}, nil
	}
	proof, err := c.probeTablePermissions(ctx, targets)
	if err != nil {
		return backend.ReadinessEvidence{}, err
	}
	for _, table := range targets {
		item, found := proof[table]
		if !found {
			return backend.ReadinessEvidence{Status: backend.EvidenceIncomplete, Attempted: true, Detail: "Logs query probe returned no evidence"}, nil
		}
		if item.status != backend.EvidenceAssessed {
			return backend.ReadinessEvidence{Status: item.status, Attempted: true, Detail: item.detail}, nil
		}
	}
	if dependencyLimit != nil {
		return backend.ReadinessEvidence{
			Status:    backend.EvidenceAssessed,
			Attempted: true,
			Limited:   true,
			Detail:    dependencyLimit.Detail,
		}, nil
	}
	return backend.ReadinessEvidence{
		Status:    backend.EvidenceAssessed,
		Attempted: true,
		Detail:    fmt.Sprintf("zero-row permission evidence collected for %s and %s", counted(len(targets), "consumed table", "consumed tables"), counted(dependencyAttempts, "Sentinel dependency path", "Sentinel dependency paths")),
	}, nil
}

// ResolveInputs joins the direct table dependencies recovered from KQL to the
// workspace's current table inventory. Each table gets independent evidence,
// allowing mixed present/missing inputs to remain partial rather than being
// collapsed into a false all-or-nothing verdict.
func (c *Client) ResolveInputs(ctx context.Context, rules []backend.Rule) ([]backend.InputResolution, error) {
	c.setRemoteReferences(rules)
	catalog, err := c.tables(ctx)
	if err != nil {
		return nil, err
	}
	c.primeRemoteAliasProofs(ctx, rules)
	outcomesByRule := make(map[string][]sentinelSelectorOutcome, len(rules))
	probeSet := make(map[string]bool)
	for _, rule := range rules {
		if !rule.Enabled || rule.InputStatus != "" {
			continue
		}
		outcomes := c.initialRuleOutcomes(ctx, rule, catalog)
		outcomesByRule[rule.ID] = outcomes
		for _, outcome := range outcomes {
			if outcome.status == backend.ResolutionResolved && len(outcome.sources) == 1 && !outcome.permissionVerified {
				probeSet[outcome.sources[0]] = true
			}
		}
	}
	probeTables := make([]string, 0, len(probeSet))
	for table := range probeSet {
		probeTables = append(probeTables, table)
	}
	sort.Strings(probeTables)
	permissions, err := c.probeTablePermissions(ctx, probeTables)
	if err != nil {
		return nil, err
	}
	for ruleID, outcomes := range outcomesByRule {
		for i := range outcomes {
			if outcomes[i].status != backend.ResolutionResolved || len(outcomes[i].sources) != 1 || outcomes[i].permissionVerified {
				continue
			}
			permission, found := permissions[outcomes[i].sources[0]]
			if !found {
				outcomes[i].status = backend.ResolutionUnavailable
				outcomes[i].detail = "Logs query probe returned no evidence"
			} else if permission.status != backend.EvidenceAssessed {
				outcomes[i].status = backend.ResolutionUnavailable
				outcomes[i].detail = permission.detail
				outcomes[i].sources = nil
				outcomes[i].dependencies = nil
			}
		}
		outcomesByRule[ruleID] = outcomes
	}
	// Runtime rule-health correlation is lower priority than the ordinary
	// source permission probes above and shares their existing Logs budget.
	c.applyRuleHealthEvidence(ctx, rules, outcomesByRule)
	var out []backend.InputResolution
	for _, rule := range rules {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		observedAt := time.Now().UTC()
		if !rule.Enabled {
			continue
		}
		if rule.InputStatus != "" {
			required, optional := ruleDependencyPatterns(rule)
			out = append(out, backend.InputResolution{
				RuleID:           rule.ID,
				Expression:       strings.Join(append(required, optional...), ","),
				SelectorKind:     "kql_query",
				ResolutionMethod: "kql_dependency_analysis",
				ObservedAt:       observedAt,
				Status:           rule.InputStatus,
				Detail:           rule.InputDetail,
			})
			continue
		}
		outcomes := outcomesByRule[rule.ID]
		if len(outcomes) == 0 {
			out = append(out, backend.InputResolution{
				RuleID:           rule.ID,
				SelectorKind:     "kql_query",
				ResolutionMethod: "kql_dependency_analysis",
				ObservedAt:       observedAt,
				Status:           backend.ResolutionUnsupported,
				Detail:           "KQL query did not expose a direct table dependency",
			})
			continue
		}
		selectors := make([]string, 0, len(outcomes))
		for _, outcome := range outcomes {
			if outcome.selector != "" {
				selectors = append(selectors, outcome.selector)
			}
		}

		authoritative := backend.InputResolution{
			RuleID:           rule.ID,
			Expression:       strings.Join(selectors, ","),
			SelectorKind:     "kql_query",
			ResolutionMethod: "kql+operational_insights_tables",
			ObservedAt:       observedAt,
		}
		authoritative.Status, authoritative.Detail, authoritative.ResolvedSources = aggregateRuleResolution(outcomes)
		if authoritative.Status == backend.ResolutionResolved {
			authoritative.ResolvedDependencies = resolvedSelectorDependencies(outcomes)
		}
		out = append(out, authoritative)
		for _, outcome := range outcomes {
			selectorKind := outcome.selectorKind
			if selectorKind == "" {
				selectorKind = "log_analytics_table"
			}
			method := outcome.method
			if method == "" {
				method = "kql+operational_insights_tables_diagnostic"
			}
			out = append(out, backend.InputResolution{
				RuleID:               rule.ID,
				Selector:             outcome.selector,
				Expression:           outcome.selector,
				Diagnostic:           true,
				SelectorKind:         selectorKind,
				ResolutionMethod:     method,
				ObservedAt:           observedAt,
				Status:               outcome.status,
				Detail:               outcome.detail,
				ResolvedSources:      append([]string(nil), outcome.sources...),
				ResolvedDependencies: append([]backend.DependencyRef(nil), outcome.dependencies...),
			})
		}
	}
	return out, nil
}

func (c *Client) initialRuleOutcomes(ctx context.Context, rule backend.Rule, localCatalog map[string]tableInfo) []sentinelSelectorOutcome {
	if outcomes, exceeded := c.remoteWorkspaceLimitOutcomes(ctx, rule); exceeded {
		return outcomes
	}
	required, optional := ruleDependencyPatterns(rule)
	outcomes := make([]sentinelSelectorOutcome, 0, len(required)+len(optional)+len(rule.Dependencies))
	for i, table := range append(append([]string(nil), required...), optional...) {
		outcome := sentinelSelectorOutcome{
			table: table, selector: table, selectorKind: "log_analytics_table",
			method: "kql+operational_insights_tables_diagnostic", optional: i >= len(required),
		}
		if info, ok := localCatalog[table]; !ok {
			if rule.InputMetadataIncomplete {
				outcome.status = backend.ResolutionUnavailable
				outcome.detail = "workspace function metadata was unavailable, so a catalog miss is not proof that the dependency is absent"
			} else {
				outcome.status = backend.ResolutionEmpty
				outcome.detail = "table is absent from the workspace inventory"
			}
		} else if status, detail, limited := tableResolutionLimitation(info); limited {
			outcome.status = status
			outcome.detail = detail
		} else {
			outcome.status = backend.ResolutionResolved
			outcome.sources = []string{table}
		}
		outcomes = append(outcomes, outcome)
	}
	for _, dependency := range rule.Dependencies {
		switch dependency.Kind {
		case sentinelKQLUnsupportedDependency, sentinelKQLAmbiguousDependency:
			status := backend.ResolutionUnsupported
			detail := "KQL query contains an unsupported input"
			if dependency.Kind == sentinelKQLAmbiguousDependency {
				status = backend.ResolutionAmbiguous
				detail = "KQL query contains an ambiguous input"
			}
			if strings.TrimSpace(dependency.Expression) != "" {
				detail = dependency.Expression
			}
			outcomes = append(outcomes, sentinelSelectorOutcome{
				selectorKind: "kql_query", method: "kql_dependency_analysis",
				status: status, detail: detail,
			})
			continue
		case "sentinel_watchlist":
			outcome := sentinelSelectorOutcome{
				selector: dependency.Name, selectorKind: "sentinel_watchlist",
				method: "sentinel_watchlists+logs_permission_diagnostic", optional: !dependency.Required,
			}
			probe := c.probeWatchlistDependency(ctx, dependency)
			outcome.status, outcome.detail = probe.status, probe.detail
			outcome.sources = append([]string(nil), probe.sources...)
			resolved := dependency
			if probe.dependencyID != "" {
				resolved.ID = probe.dependencyID
			}
			resolved.Expression = ""
			outcome.dependencies = []backend.DependencyRef{resolved}
			outcomes = append(outcomes, outcome)
			continue
		case "sentinel_asim_parser":
			outcome := sentinelSelectorOutcome{
				selector: dependency.Name, selectorKind: "sentinel_asim_parser",
				method: "kql_asim_native_probe+operational_insights_tables_diagnostic", optional: !dependency.Required,
			}
			probe := c.probeASIMDependency(ctx, dependency, localCatalog)
			outcome.status, outcome.detail = probe.status, probe.detail
			outcome.sources = append([]string(nil), probe.sources...)
			resolved := dependency
			resolved.Expression = ""
			outcome.dependencies = []backend.DependencyRef{resolved}
			if probe.status == backend.ResolutionResolved {
				outcome.permissionVerified = true
			}
			outcomes = append(outcomes, outcome)
			continue
		case "sentinel_workspace_table":
		default:
			continue
		}
		outcome := sentinelSelectorOutcome{
			table: dependency.Name, selector: "workspace(" + kqlStringLiteral(dependency.Scope) + ")." + dependency.Name,
			selectorKind: "log_analytics_table", method: "kql+operational_insights_tables_diagnostic",
			optional: !dependency.Required,
		}
		state, err := c.resolveRemoteWorkspace(ctx, dependency.Scope)
		if err != nil {
			outcome.status = backend.ResolutionUnavailable
			outcome.detail = "configured remote workspace could not be verified through ARM"
			outcomes = append(outcomes, outcome)
			continue
		}
		if state == nil {
			outcome.status = backend.ResolutionRemote
			outcome.detail = "literal workspace() target is not in the configured remote-workspace allowlist"
			outcomes = append(outcomes, outcome)
			continue
		}
		catalog, err := c.remoteTables(ctx, state)
		if err != nil {
			outcome.status = backend.ResolutionUnavailable
			outcome.detail = "configured remote workspace table inventory could not be read"
			outcomes = append(outcomes, outcome)
			continue
		}
		aliasProofTable := ""
		if remoteScopeNeedsAliasProof(dependency.Scope) {
			var proof tablePermissionEvidence
			aliasProofTable, proof = c.validateRemoteAlias(ctx, state, dependency.Scope, catalog, []string{dependency.Name})
			if proof.status != backend.EvidenceAssessed {
				outcome.status = backend.ResolutionUnavailable
				outcome.detail = proof.detail
				outcomes = append(outcomes, outcome)
				continue
			}
		}
		info, found := catalog[dependency.Name]
		if !found {
			outcome.status = backend.ResolutionEmpty
			outcome.detail = "table is absent from the verified remote workspace inventory"
			outcomes = append(outcomes, outcome)
			continue
		}
		if status, detail, limited := tableResolutionLimitation(info); limited {
			outcome.status = status
			outcome.detail = detail
			outcomes = append(outcomes, outcome)
			continue
		}
		sourceName := qualifiedRemoteSource(state.resourceID, dependency.Name)
		outcome.status = backend.ResolutionResolved
		outcome.sources = []string{sourceName}
		outcome.permissionVerified = aliasProofTable == dependency.Name
		outcome.dependencies = []backend.DependencyRef{remoteDependencyRef(sourceName, dependency.Name, state.resourceID, dependency.Required)}
		outcomes = append(outcomes, outcome)
	}
	outcomes = append(outcomes, c.remoteExecutionIdentityOutcomes(ctx, rule)...)
	return outcomes
}

func resolvedSelectorDependencies(outcomes []sentinelSelectorOutcome) []backend.DependencyRef {
	var dependencies []backend.DependencyRef
	seen := make(map[string]bool)
	for _, outcome := range outcomes {
		if outcome.status != backend.ResolutionResolved {
			continue
		}
		for _, dependency := range outcome.dependencies {
			if seen[dependency.ID] {
				continue
			}
			seen[dependency.ID] = true
			dependencies = append(dependencies, dependency)
		}
	}
	return dependencies
}

func uniqueStrings(values []string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		if seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func ruleDependencyPatterns(rule backend.Rule) ([]string, []string) {
	required := uniqueStrings(rule.Patterns)
	requiredSet := make(map[string]bool, len(required))
	for _, table := range required {
		requiredSet[table] = true
	}
	optional := make([]string, 0, len(rule.OptionalPatterns))
	seenOptional := make(map[string]bool, len(rule.OptionalPatterns))
	for _, table := range rule.OptionalPatterns {
		if requiredSet[table] || seenOptional[table] {
			continue
		}
		seenOptional[table] = true
		optional = append(optional, table)
	}
	return required, optional
}

func aggregateRuleResolution(outcomes []sentinelSelectorOutcome) (backend.ResolutionStatus, string, []string) {
	// An uncertain dependency invalidates the whole rule view, even when a
	// sibling source resolved. Azure can silently filter denied tables from a
	// successful query, so partial permission evidence is never enough.
	for _, outcome := range outcomes {
		switch outcome.status {
		case backend.ResolutionUnavailable, backend.ResolutionUnsupported, backend.ResolutionAmbiguous, backend.ResolutionRemote:
			return outcome.status, outcome.detail, nil
		}
	}
	// Every ordinary dependency is required. Only an explicitly fuzzy union
	// leg may be absent while another source keeps the query executable.
	for _, outcome := range outcomes {
		if outcome.optional || outcome.status == backend.ResolutionResolved {
			continue
		}
		return outcome.status, outcome.detail, nil
	}
	// An existing but incompatible optional source is not the same as a fuzzy
	// leg that is proven absent; it can still make the native query unusable.
	for _, outcome := range outcomes {
		if outcome.optional && outcome.status == backend.ResolutionIncompatible {
			return outcome.status, outcome.detail, nil
		}
	}
	var resolved []string
	verifiedNonTelemetryDependency := false
	for _, outcome := range outcomes {
		if outcome.status == backend.ResolutionResolved {
			resolved = append(resolved, outcome.sources...)
			verifiedNonTelemetryDependency = verifiedNonTelemetryDependency || len(outcome.dependencies) > 0
		}
	}
	if len(resolved) > 0 {
		return backend.ResolutionResolved, "", uniqueStrings(resolved)
	}
	if verifiedNonTelemetryDependency {
		return backend.ResolutionUnsupported, "dependencies were verified, but the rule exposes no monitorable telemetry table", nil
	}
	status, detail := aggregateResolutionFailure(outcomes)
	return status, detail, nil
}

func aggregateResolutionFailure(outcomes []sentinelSelectorOutcome) (backend.ResolutionStatus, string) {
	for _, status := range []backend.ResolutionStatus{
		backend.ResolutionUnavailable,
		backend.ResolutionAmbiguous,
		backend.ResolutionUnsupported,
		backend.ResolutionIncompatible,
		backend.ResolutionRemote,
		backend.ResolutionEmpty,
	} {
		for _, outcome := range outcomes {
			if outcome.status == status {
				return status, outcome.detail
			}
		}
	}
	return backend.ResolutionUnavailable, "rule input evidence could not be resolved"
}

type logsQueryRequest struct {
	Query string `json:"query"`
}

type logsMetadataResponse struct {
	Functions []struct {
		Name       string `json:"name"`
		Body       string `json:"body"`
		Parameters string `json:"parameters"`
	} `json:"functions"`
}

// workspaceFunctions reads the v1 Log Analytics metadata contract. The API
// represents parameters as one string; the KQL analyzer parses that declaration
// before expanding calls whose scalar arguments are closed and deterministic.
func (c *Client) workspaceFunctions(ctx context.Context) (map[string]WorkspaceFunction, bool) {
	c.functionsMu.Lock()
	if c.functions != nil {
		functions := cloneFunctions(c.functions)
		c.functionsMu.Unlock()
		return functions, true
	}
	c.functionsMu.Unlock()

	workspaceID, err := c.workspaceID(ctx)
	if err != nil {
		return nil, false
	}
	target := c.logsEndpoint() + "/v1/workspaces/" + url.PathEscape(workspaceID) + "/metadata"
	var response logsMetadataResponse
	if err := c.doLogs(ctx, target, nil, &response); err != nil {
		return nil, false
	}
	functions := make(map[string]WorkspaceFunction, len(response.Functions))
	for _, raw := range response.Functions {
		name := strings.TrimSpace(raw.Name)
		if name == "" {
			continue
		}
		function := WorkspaceFunction{Body: raw.Body}
		if parameters := strings.TrimSpace(raw.Parameters); parameters != "" && parameters != "()" {
			function.Parameters = []string{parameters}
		}
		if _, duplicate := functions[name]; duplicate {
			function.Parameters = []string{"duplicate function metadata"}
		}
		functions[name] = function
	}
	c.functionsMu.Lock()
	if c.functions == nil {
		c.functions = cloneFunctions(functions)
	}
	c.functionsMu.Unlock()
	return functions, true
}

func cloneFunctions(in map[string]WorkspaceFunction) map[string]WorkspaceFunction {
	out := make(map[string]WorkspaceFunction, len(in))
	for name, function := range in {
		function.Parameters = append([]string(nil), function.Parameters...)
		out[name] = function
	}
	return out
}

type logsQueryError struct {
	Code         string           `json:"code"`
	Message      string           `json:"message"`
	Details      []logsQueryError `json:"details,omitempty"`
	InnerError   *logsQueryError  `json:"innererror,omitempty"`
	Severity     int              `json:"severity,omitempty"`
	SeverityName string           `json:"severityName,omitempty"`
}

type logsQueryResponse struct {
	Tables      []logsTable `json:"tables"`
	Permissions *struct {
		DataSources []struct {
			ResourceID  string   `json:"resourceId"`
			AllowTables []string `json:"allowTables"`
			DenyTables  []string `json:"denyTables"`
		} `json:"dataSources"`
	} `json:"permissions,omitempty"`
	DataSources []struct {
		ResourceID string   `json:"resourceId"`
		Workspace  string   `json:"workspace"`
		Tables     []string `json:"tables"`
	} `json:"dataSources,omitempty"`
	Error *logsQueryError `json:"error,omitempty"`
}

type logsTable struct {
	Name    string `json:"name"`
	Columns []struct {
		Name string `json:"name"`
		Type string `json:"type"`
	} `json:"columns"`
	Rows [][]json.RawMessage `json:"rows"`
}

func (c *Client) queryLogs(ctx context.Context, query, expectedTable string) (logsTable, error) {
	return c.queryLogsForSource(ctx, query, sentinelSourceTarget{table: expectedTable})
}

func (c *Client) queryLogsForSource(ctx context.Context, query string, expected sentinelSourceTarget) (logsTable, error) {
	response, err := c.queryLogsResponse(ctx, query)
	if err != nil {
		return logsTable{}, err
	}
	if response.Error != nil {
		return logsTable{}, &logsEvidenceError{
			status: backend.EvidenceIncomplete,
			detail: "Log Analytics returned a partial or failed query result",
		}
	}
	if expected.table != "" {
		if err := validateLogsEvidenceForSource(response, expected); err != nil {
			return logsTable{}, err
		}
	}
	if len(response.Tables) == 0 {
		return logsTable{}, errors.New("Log Analytics query returned no result table")
	}
	return response.Tables[0], nil
}

func (c *Client) queryLogsResponse(ctx context.Context, query string) (logsQueryResponse, error) {
	workspaceID, err := c.workspaceID(ctx)
	if err != nil {
		return logsQueryResponse{}, err
	}
	body, err := json.Marshal(logsQueryRequest{Query: query})
	if err != nil {
		return logsQueryResponse{}, err
	}
	if !c.claimLogsQuery() {
		return logsQueryResponse{}, &logsEvidenceError{
			status: backend.EvidenceIncomplete,
			detail: "per-scan Logs query budget was exhausted",
		}
	}
	target := c.logsEndpoint() + "/v1/workspaces/" + url.PathEscape(workspaceID) + "/query"
	var response logsQueryResponse
	if err := c.doLogs(ctx, target, body, &response); err != nil {
		return logsQueryResponse{}, err
	}
	return response, nil
}

type logsEvidenceError struct {
	status backend.EvidenceStatus
	detail string
}

func (e *logsEvidenceError) Error() string { return e.detail }

func validateLogsEvidence(response logsQueryResponse, expectedTable string) error {
	return validateLogsEvidenceForSource(response, sentinelSourceTarget{table: expectedTable})
}

func validateLogsEvidenceForSource(response logsQueryResponse, expected sentinelSourceTarget) error {
	expectedTable := expected.table
	if response.Permissions == nil || len(response.Permissions.DataSources) == 0 {
		return &logsEvidenceError{status: backend.EvidenceIncomplete, detail: "Logs query permission evidence was omitted"}
	}
	allowed := false
	hasAllowTables := false
	permissionScopeSeen := expected.expectedResourceID == ""
	for _, permission := range response.Permissions.DataSources {
		if expected.expectedResourceID != "" {
			// A remote table needs workspace-scoped permission evidence. An
			// unqualified allowTables entry can describe the home query scope and
			// must not be combined with a separate remote data-source record.
			if permission.ResourceID == "" || !remoteResourceMatches(permission.ResourceID, expected) {
				continue
			}
		}
		permissionScopeSeen = true
		for _, denied := range permission.DenyTables {
			if permissionDenyMatches(denied, expectedTable) {
				return &logsEvidenceError{status: backend.EvidenceUnavailable, detail: "Logs query permission evidence explicitly denied the requested table"}
			}
		}
		if permission.AllowTables != nil {
			hasAllowTables = true
		}
		for _, table := range permission.AllowTables {
			if table == expectedTable {
				allowed = true
			}
		}
	}
	if hasAllowTables && !allowed {
		return &logsEvidenceError{status: backend.EvidenceIncomplete, detail: "Logs query permission evidence did not positively allow the requested table"}
	}
	if !permissionScopeSeen {
		return &logsEvidenceError{status: backend.EvidenceIncomplete, detail: "Logs query permission evidence did not confirm the requested remote workspace"}
	}
	confirmed := false
	for _, source := range response.DataSources {
		if expected.expectedResourceID != "" && !remoteDataSourceMatches(source.ResourceID, source.Workspace, expected) {
			continue
		}
		for _, table := range source.Tables {
			if table == expectedTable {
				confirmed = true
			}
		}
	}
	if !confirmed {
		detail := "Logs query data-source evidence did not confirm the requested table"
		if expected.expectedResourceID != "" {
			detail = "Logs query data-source evidence did not confirm the requested remote workspace and table"
		}
		return &logsEvidenceError{status: backend.EvidenceIncomplete, detail: detail}
	}
	return nil
}

func remoteResourceMatches(value string, expected sentinelSourceTarget) bool {
	value = canonicalRemoteScope(value)
	return value == expected.expectedResourceID || (expected.expectedWorkspaceID != "" && strings.EqualFold(value, expected.expectedWorkspaceID))
}

func remoteDataSourceMatches(resourceID, workspace string, expected sentinelSourceTarget) bool {
	if resourceID != "" && remoteResourceMatches(resourceID, expected) {
		return true
	}
	return workspace != "" && (strings.EqualFold(workspace, expected.expectedWorkspaceID) || canonicalRemoteScope(workspace) == expected.expectedResourceID)
}

func permissionDenyMatches(denied, table string) bool {
	if denied == table {
		return true
	}
	switch {
	case strings.EqualFold(denied, "Tables.Custom"):
		return strings.HasSuffix(table, "_CL")
	case strings.EqualFold(denied, "Tables.Standard"):
		return !strings.HasSuffix(table, "_CL")
	case strings.EqualFold(denied, "Tables.All"), denied == "*":
		return true
	default:
		return false
	}
}

func evidenceFailure(err error) (backend.EvidenceStatus, string) {
	var evidenceErr *logsEvidenceError
	if errors.As(err, &evidenceErr) {
		return evidenceErr.status, evidenceErr.detail
	}
	var statusErr *statusError
	if errors.As(err, &statusErr) && (statusErr.code == http.StatusUnauthorized || statusErr.code == http.StatusForbidden) {
		return backend.EvidenceUnavailable, "Logs query access is unavailable"
	}
	return backend.EvidenceIncomplete, "Logs query evidence could not be read"
}

func parseLogTime(value json.RawMessage) (time.Time, bool) {
	var text string
	if err := json.Unmarshal(value, &text); err == nil {
		parsed, err := time.Parse(time.RFC3339Nano, text)
		return parsed, err == nil
	}
	var millis float64
	if err := json.Unmarshal(value, &millis); err == nil {
		return time.UnixMilli(int64(millis)), true
	}
	return time.Time{}, false
}

// IngestLagEvidence measures lag from timestamp pairs on the same event. The
// recent window and sample cap bound every query and every in-memory result.
func (c *Client) IngestLagEvidence(ctx context.Context, sources []backend.Source) (map[string]backend.IngestLagEvidence, error) {
	if len(sources) == 0 {
		return map[string]backend.IngestLagEvidence{}, nil
	}
	catalog, err := c.tables(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string]backend.IngestLagEvidence, len(sources))
	sem := make(chan struct{}, c.concurrency())
	var wg sync.WaitGroup
	var mu sync.Mutex
	seen := make(map[string]bool, len(sources))
	tasks := make([]backend.Source, 0, len(sources))
	for _, source := range sources {
		if seen[source.Name] {
			continue
		}
		seen[source.Name] = true
		if !c.claimEvidenceSource(source.Name) {
			out[source.Name] = backend.IngestLagEvidence{
				Status:     backend.EvidenceIncomplete,
				Method:     "paired-timegenerated-ingestion_time",
				ObservedAt: time.Now().UTC(),
				Window:     ingestLagWindow,
				Detail:     "per-scan source evidence budget was exhausted",
			}
			continue
		}
		tasks = append(tasks, source)
	}
	for _, source := range tasks {
		source := source
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			evidence := backend.IngestLagEvidence{
				Status:     backend.EvidenceIncomplete,
				Method:     "paired-timegenerated-ingestion_time",
				ObservedAt: time.Now().UTC(),
				Window:     ingestLagWindow,
				Detail:     "paired timestamp sample could not be read",
			}
			target, targetErr := c.sourceTarget(ctx, source.Name, catalog)
			if targetErr != nil {
				evidence.Status, evidence.Detail = evidenceFailure(targetErr)
			} else if !target.found {
				evidence.Detail = "source is absent from the workspace table inventory"
			} else if status, detail, limited := tableRuntimeLimitation(target.info); limited {
				evidence.Status = status
				evidence.Detail = detail
			} else if !catalogHasField(target.info, "TimeGenerated") {
				evidence.Status = backend.EvidenceUnavailable
				evidence.Detail = "table schema does not expose TimeGenerated"
			} else if target.queryReference != "" {
				query := fmt.Sprintf("%s | extend IngestionTime=ingestion_time() | where IngestionTime >= ago(%dh) and isnotnull(TimeGenerated) and isnotnull(IngestionTime) | top %d by IngestionTime desc | project TimeGenerated, IngestionTime", target.queryReference, int(ingestLagWindow/time.Hour), ingestLagSamples)
				result, err := c.queryLogsForSource(ctx, query, target)
				if err == nil {
					evidence = ingestLagFromTable(result, evidence)
				} else {
					evidence.Status, evidence.Detail = evidenceFailure(err)
				}
			} else {
				evidence.Detail = "table name cannot be represented safely in KQL"
			}
			mu.Lock()
			out[source.Name] = evidence
			mu.Unlock()
		}()
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func ingestLagFromTable(table logsTable, evidence backend.IngestLagEvidence) backend.IngestLagEvidence {
	if len(table.Rows) == 0 {
		evidence.Status = backend.EvidenceDisabled
		evidence.Detail = "no recent events were available in the bounded sample window"
		return evidence
	}
	eventIndex, ingestIndex := -1, -1
	for i, column := range table.Columns {
		switch column.Name {
		case "TimeGenerated":
			eventIndex = i
		case "IngestionTime":
			ingestIndex = i
		}
	}
	if eventIndex < 0 || ingestIndex < 0 {
		evidence.Detail = "paired timestamp result omitted a required column"
		return evidence
	}
	lags := make([]time.Duration, 0, len(table.Rows))
	for _, row := range table.Rows {
		if eventIndex >= len(row) || ingestIndex >= len(row) {
			continue
		}
		eventTime, eventOK := parseLogTime(row[eventIndex])
		ingestTime, ingestOK := parseLogTime(row[ingestIndex])
		if !eventOK || !ingestOK {
			continue
		}
		lag := ingestTime.Sub(eventTime)
		if lag < 0 {
			lag = 0
		}
		lags = append(lags, lag)
	}
	if len(lags) == 0 {
		evidence.Detail = "no sampled event exposed both timestamps"
		return evidence
	}
	sort.Slice(lags, func(i, j int) bool { return lags[i] < lags[j] })
	p95Index := int(math.Ceil(float64(len(lags))*0.95)) - 1
	evidence.Status = backend.EvidenceAssessed
	evidence.SampleCount = len(lags)
	evidence.P95 = lags[p95Index]
	evidence.Max = lags[len(lags)-1]
	evidence.Detail = ""
	return evidence
}

var (
	_ backend.Backend                  = (*Client)(nil)
	_ backend.Resolver                 = (*Client)(nil)
	_ backend.RequiredFieldProvider    = (*Client)(nil)
	_ backend.IngestLagProvider        = (*Client)(nil)
	_ backend.FreshnessProvider        = (*Client)(nil)
	_ backend.FreshnessRequestProvider = (*Client)(nil)
	_ backend.ReadinessProvider        = (*Client)(nil)
	_ backend.ScanRefresher            = (*Client)(nil)
)
