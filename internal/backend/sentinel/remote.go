package sentinel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
	"sync"

	"github.com/alephnull-sh/deadair/internal/backend"
)

const (
	remoteSourcePrefix                = "azure-loganalytics://"
	sentinelOnboardingAPIVersion      = "2025-09-01"
	maxSentinelAnalyticsWorkspaces    = 20
	maxSentinelAnalyticsRemoteTargets = maxSentinelAnalyticsWorkspaces - 1
	maxCrossWorkspaceRegions          = 20
)

var errWorkspaceLocationMissing = errors.New("workspace ARM response omitted or returned an empty location")

// RemoteWorkspace explicitly permits one workspace() target to be assessed.
// Alias is considered only when a rule uses that exact configured literal, and
// it becomes evidence only after a bounded query proves Azure resolves it to
// the configured workspace. The workspace customer ID and canonical ARM
// resource ID are accepted directly after ARM has verified the mapping.
type RemoteWorkspace struct {
	Alias          string `json:"alias"`
	SubscriptionID string `json:"azure_subscription_id"`
	ResourceGroup  string `json:"azure_resource_group"`
	WorkspaceName  string `json:"sentinel_workspace"`
	WorkspaceID    string `json:"sentinel_workspace_id,omitempty"`
}

type remoteWorkspaceState struct {
	config     RemoteWorkspace
	resourceID string

	mu           sync.Mutex
	validated    bool
	workspaceID  string
	location     string
	catalog      map[string]tableInfo
	err          error
	aliasChecked bool
	aliasTable   string
	aliasProof   tablePermissionEvidence
}

// ParseRemoteWorkspaces decodes the array accepted by --sentinel-remotes.
// Unknown fields are rejected so a misspelled allowlist coordinate cannot
// silently leave an intended target unassessed.
func ParseRemoteWorkspaces(data []byte) ([]RemoteWorkspace, error) {
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	var remotes []RemoteWorkspace
	if err := decoder.Decode(&remotes); err != nil {
		return nil, fmt.Errorf("parsing Sentinel remote-workspace file: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("parsing Sentinel remote-workspace file: multiple JSON values")
		}
		return nil, fmt.Errorf("parsing Sentinel remote-workspace file: trailing data: %w", err)
	}
	return remotes, nil
}

func normalizeRemoteWorkspaces(homeSubscription, homeResourceGroup, homeWorkspace string, remotes []RemoteWorkspace) ([]RemoteWorkspace, error) {
	normalized := make([]RemoteWorkspace, 0, len(remotes))
	seenAlias := make(map[string]bool, len(remotes))
	seenResource := make(map[string]bool, len(remotes))
	seenWorkspaceID := make(map[string]bool, len(remotes))
	homeID := canonicalWorkspaceResourceID(homeSubscription, homeResourceGroup, homeWorkspace)
	for i, remote := range remotes {
		remote.Alias = strings.TrimSpace(remote.Alias)
		remote.SubscriptionID = strings.TrimSpace(remote.SubscriptionID)
		remote.ResourceGroup = strings.TrimSpace(remote.ResourceGroup)
		remote.WorkspaceName = strings.TrimSpace(remote.WorkspaceName)
		remote.WorkspaceID = strings.TrimSpace(remote.WorkspaceID)
		for name, value := range map[string]string{
			"alias": remote.Alias, "subscription ID": remote.SubscriptionID,
			"resource group": remote.ResourceGroup, "workspace name": remote.WorkspaceName,
		} {
			if value == "" {
				return nil, fmt.Errorf("Sentinel remote workspace %d: %s is required", i+1, name)
			}
		}
		aliasKey := strings.ToLower(remote.Alias)
		if seenAlias[aliasKey] {
			return nil, fmt.Errorf("Sentinel remote workspace alias %q is duplicated", remote.Alias)
		}
		seenAlias[aliasKey] = true
		resourceID := canonicalWorkspaceResourceID(remote.SubscriptionID, remote.ResourceGroup, remote.WorkspaceName)
		if resourceID == homeID {
			return nil, fmt.Errorf("Sentinel remote workspace %q duplicates the home workspace", remote.Alias)
		}
		if seenResource[resourceID] {
			return nil, fmt.Errorf("Sentinel remote workspace resource %q is duplicated", resourceID)
		}
		seenResource[resourceID] = true
		if remote.WorkspaceID != "" {
			workspaceKey := strings.ToLower(remote.WorkspaceID)
			if seenWorkspaceID[workspaceKey] {
				return nil, fmt.Errorf("Sentinel remote workspace customer ID %q is duplicated", remote.WorkspaceID)
			}
			seenWorkspaceID[workspaceKey] = true
		}
		normalized = append(normalized, remote)
	}
	return normalized, nil
}

func canonicalWorkspaceResourceID(subscription, resourceGroup, workspace string) string {
	return strings.ToLower("/subscriptions/" + strings.TrimSpace(subscription) +
		"/resourcegroups/" + strings.TrimSpace(resourceGroup) +
		"/providers/microsoft.operationalinsights/workspaces/" + strings.TrimSpace(workspace))
}

func canonicalRemoteScope(scope string) string {
	canonical := strings.TrimRight(strings.TrimSpace(scope), "/")
	if strings.HasPrefix(canonical, "/") {
		return strings.ToLower(canonical)
	}
	if looksLikeWorkspaceID(canonical) {
		return canonical
	}
	// Textual aliases are rule literals, not native identifiers. Preserve their
	// exact spelling here so only case folding, not whitespace or slash cleanup,
	// can match a configured alias.
	return scope
}

func normalizeWorkspaceLocation(location string) (string, bool) {
	// ARM normally returns compact location names (for example, uksouth).
	// Removing whitespace also keeps display-style spellings from being counted
	// twice, while case folding makes the comparison stable across responses.
	location = strings.ToLower(strings.Join(strings.Fields(location), ""))
	return location, location != ""
}

// RemoteWorkspaceIdentitySet returns the normalized mapping set used in
// target and assessment identity. It contains no credentials. WorkspaceID is
// an optional ARM-verified shortcut for the same resource, so adding or
// removing it must not churn report, diff, or state identity.
func RemoteWorkspaceIdentitySet(remotes []RemoteWorkspace) []string {
	identities := make([]string, 0, len(remotes))
	for _, remote := range remotes {
		identities = append(identities, strings.ToLower(strings.TrimSpace(remote.Alias))+"\x00"+
			canonicalWorkspaceResourceID(remote.SubscriptionID, remote.ResourceGroup, remote.WorkspaceName))
	}
	sort.Strings(identities)
	return identities
}

func qualifiedRemoteSource(resourceID, table string) string {
	return remoteSourcePrefix + canonicalRemoteScope(resourceID) + "/tables/" + table
}

func parseQualifiedRemoteSource(name string) (resourceID, table string, ok bool) {
	if !strings.HasPrefix(name, remoteSourcePrefix) {
		return "", "", false
	}
	rest := strings.TrimPrefix(name, remoteSourcePrefix)
	marker := "/tables/"
	pos := strings.LastIndex(rest, marker)
	if pos <= 0 || pos+len(marker) == len(rest) {
		return "", "", false
	}
	resourceID = canonicalRemoteScope(rest[:pos])
	table = rest[pos+len(marker):]
	if !strings.HasPrefix(resourceID, "/subscriptions/") {
		return "", "", false
	}
	if _, valid := kqlTableReference(table); !valid {
		return "", "", false
	}
	return resourceID, table, true
}

func kqlStringLiteral(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func remoteTableReference(resourceID, table string) (string, bool) {
	tableRef, ok := kqlTableReference(table)
	if !ok {
		return "", false
	}
	return "workspace(" + kqlStringLiteral(canonicalRemoteScope(resourceID)) + ")." + tableRef, true
}

func (c *Client) resetRemoteState() {
	c.remoteMu.Lock()
	defer c.remoteMu.Unlock()
	c.remoteStates = nil
}

func (c *Client) remoteStateMap() map[string]*remoteWorkspaceState {
	c.remoteMu.Lock()
	defer c.remoteMu.Unlock()
	if c.remoteStates != nil {
		return c.remoteStates
	}
	states := make(map[string]*remoteWorkspaceState, len(c.RemoteWorkspaces))
	for _, remote := range c.RemoteWorkspaces {
		resourceID := canonicalWorkspaceResourceID(remote.SubscriptionID, remote.ResourceGroup, remote.WorkspaceName)
		state := &remoteWorkspaceState{config: remote, resourceID: resourceID}
		states["alias:"+strings.ToLower(remote.Alias)] = state
		states["resource:"+resourceID] = state
		if remote.WorkspaceID != "" {
			states["workspace:"+strings.ToLower(remote.WorkspaceID)] = state
		}
	}
	c.remoteStates = states
	return states
}

func uniqueRemoteStates(states map[string]*remoteWorkspaceState) []*remoteWorkspaceState {
	seen := make(map[*remoteWorkspaceState]bool)
	var out []*remoteWorkspaceState
	for _, state := range states {
		if seen[state] {
			continue
		}
		seen[state] = true
		out = append(out, state)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].resourceID < out[j].resourceID })
	return out
}

// remoteWorkspaceIDCandidates returns mappings that could match a native
// workspace customer ID without contacting Azure. A configured or previously
// verified non-matching ID rules a mapping out. More than one remaining
// candidate is intentionally ambiguous: probing the allowlist until one
// happens to match would contact mappings the rule does not use.
func remoteWorkspaceIDCandidates(states map[string]*remoteWorkspaceState, workspaceID string) []*remoteWorkspaceState {
	workspaceID = strings.TrimSpace(workspaceID)
	var candidates []*remoteWorkspaceState
	for _, state := range uniqueRemoteStates(states) {
		configuredID := strings.TrimSpace(state.config.WorkspaceID)
		if configuredID != "" && !strings.EqualFold(configuredID, workspaceID) {
			continue
		}
		state.mu.Lock()
		validated, observedID := state.validated, state.workspaceID
		state.mu.Unlock()
		if validated && !strings.EqualFold(observedID, workspaceID) {
			continue
		}
		candidates = append(candidates, state)
	}
	return candidates
}

func (c *Client) resolveRemoteWorkspace(ctx context.Context, scope string) (*remoteWorkspaceState, error) {
	scope = canonicalRemoteScope(scope)
	states := c.remoteStateMap()
	var state *remoteWorkspaceState
	switch {
	case strings.HasPrefix(scope, "/"):
		state = states["resource:"+strings.ToLower(scope)]
	case looksLikeWorkspaceID(scope):
		// A native customer ID is identity, not an arbitrary config alias. Do
		// not let an alias that merely looks like a GUID rewrite it.
		state = states["workspace:"+strings.ToLower(scope)]
	default:
		if scope != strings.TrimSpace(scope) || strings.HasSuffix(scope, "/") {
			return nil, nil
		}
		state = states["alias:"+strings.ToLower(scope)]
	}
	if state != nil {
		if err := c.validateRemoteWorkspace(ctx, state); err != nil {
			return state, err
		}
		return state, nil
	}
	// A configured customer ID may be omitted and discovered through ARM only
	// when one explicit mapping can possibly match. With multiple candidates,
	// probing until one matches would contact mappings this rule does not use.
	if looksLikeWorkspaceID(scope) {
		candidates := remoteWorkspaceIDCandidates(states, scope)
		if len(candidates) != 1 {
			return nil, nil
		}
		candidate := candidates[0]
		if err := c.validateRemoteWorkspace(ctx, candidate); err != nil {
			return nil, fmt.Errorf("verifying configured remote workspace customer ID: %w", err)
		}
		if strings.EqualFold(candidate.workspaceID, scope) {
			return candidate, nil
		}
	}
	return nil, nil
}

func remoteScopeNeedsAliasProof(scope string) bool {
	scope = canonicalRemoteScope(scope)
	return !strings.HasPrefix(scope, "/") && !looksLikeWorkspaceID(scope)
}

// validateRemoteAlias proves that Azure resolves the original literal alias
// to the configured workspace. A config alias is not identity by itself. The
// referenced tables are tried first because least-privilege scanners may not
// be able to query unrelated workspace tables. One unrelated eligible table
// is retained as a bounded fallback. A failed proof is cached only after the
// complete candidate set has been tried.
func (c *Client) validateRemoteAlias(ctx context.Context, state *remoteWorkspaceState, alias string,
	catalog map[string]tableInfo, referencedTables []string) (string, tablePermissionEvidence) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.aliasChecked {
		return state.aliasTable, state.aliasProof
	}
	proof := tablePermissionEvidence{
		status: backend.EvidenceIncomplete,
		detail: "configured workspace alias could not be verified by a workspace-scoped Logs query",
	}
	referenced := make(map[string]bool, len(referencedTables))
	for _, table := range referencedTables {
		referenced[table] = true
	}
	var tables []string
	for table := range referenced {
		info, found := catalog[table]
		if !found {
			continue
		}
		if _, _, limited := tableResolutionLimitation(info); limited {
			continue
		}
		if _, ok := kqlTableReference(table); ok {
			tables = append(tables, table)
		}
	}
	sort.Strings(tables)
	var fallbacks []string
	for table, info := range catalog {
		if referenced[table] {
			continue
		}
		if _, _, limited := tableResolutionLimitation(info); limited {
			continue
		}
		if _, ok := kqlTableReference(table); ok {
			fallbacks = append(fallbacks, table)
		}
	}
	if len(fallbacks) > 0 {
		sort.Strings(fallbacks)
		tables = append(tables, fallbacks[0])
	}
	if len(tables) == 0 {
		proof.detail = "configured workspace alias cannot be verified because its catalog has no query-eligible Analytics table"
		state.aliasChecked = true
		state.aliasProof = proof
		return "", proof
	}
	budgetExhausted := false
	var incompleteProof, unavailableProof *tablePermissionEvidence
	for _, table := range tables {
		if ctx.Err() != nil {
			return "", proof
		}
		sourceName := qualifiedRemoteSource(state.resourceID, table)
		if !c.claimEvidenceSource(sourceName) {
			budgetExhausted = true
			continue
		}
		tableRef, _ := kqlTableReference(table)
		target := sentinelSourceTarget{
			name: sourceName, table: table,
			expectedResourceID: state.resourceID, expectedWorkspaceID: state.workspaceID,
		}
		query := "workspace(" + kqlStringLiteral(alias) + ")." + tableRef + " | take 0"
		if _, err := c.queryLogsForSource(ctx, query, target); err != nil {
			status, detail := evidenceFailure(err)
			candidateProof := &tablePermissionEvidence{status: status, detail: detail}
			if status == backend.EvidenceUnavailable {
				unavailableProof = candidateProof
			} else {
				incompleteProof = candidateProof
			}
			continue
		}
		state.aliasChecked = true
		state.aliasTable = table
		state.aliasProof = tablePermissionEvidence{
			status: backend.EvidenceAssessed,
			detail: "original workspace() alias resolved to the configured remote workspace",
		}
		return table, state.aliasProof
	}
	if budgetExhausted {
		proof = tablePermissionEvidence{
			status: backend.EvidenceIncomplete,
			detail: "per-scan source evidence budget was exhausted before the workspace alias could be verified",
		}
	} else if incompleteProof != nil {
		proof = *incompleteProof
	} else if unavailableProof != nil {
		proof = *unavailableProof
	}
	state.aliasChecked = true
	state.aliasProof = proof
	return "", proof
}

type remoteAliasProofTarget struct {
	state  *remoteWorkspaceState
	alias  string
	tables map[string]bool
}

// primeRemoteAliasProofs gathers every enabled rule reference before any
// per-rule resolution can cache a failed alias proof from an incomplete view.
func (c *Client) primeRemoteAliasProofs(ctx context.Context, rules []backend.Rule) {
	targets := make(map[string]*remoteAliasProofTarget)
	for _, rule := range rules {
		if !rule.Enabled || rule.InputStatus != "" {
			continue
		}
		for _, dependency := range rule.Dependencies {
			if dependency.Kind != "sentinel_workspace_table" || !remoteScopeNeedsAliasProof(dependency.Scope) {
				continue
			}
			state, err := c.resolveRemoteWorkspace(ctx, dependency.Scope)
			if err != nil || state == nil {
				continue
			}
			key := state.resourceID + "\x00" + strings.ToLower(strings.TrimSpace(dependency.Scope))
			target := targets[key]
			if target == nil {
				target = &remoteAliasProofTarget{state: state, alias: dependency.Scope, tables: make(map[string]bool)}
				targets[key] = target
			}
			target.tables[dependency.Name] = true
		}
	}
	keys := make([]string, 0, len(targets))
	for key := range targets {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		target := targets[key]
		catalog, err := c.remoteTables(ctx, target.state)
		if err != nil {
			continue
		}
		tables := make([]string, 0, len(target.tables))
		for table := range target.tables {
			tables = append(tables, table)
		}
		sort.Strings(tables)
		c.validateRemoteAlias(ctx, target.state, target.alias, catalog, tables)
	}
}

func looksLikeWorkspaceID(value string) bool {
	parts := strings.Split(value, "-")
	if len(parts) != 5 || len(parts[0]) != 8 || len(parts[1]) != 4 || len(parts[2]) != 4 || len(parts[3]) != 4 || len(parts[4]) != 12 {
		return false
	}
	for _, part := range parts {
		for _, r := range part {
			if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
				return false
			}
		}
	}
	return true
}

func (c *Client) validateRemoteWorkspace(ctx context.Context, state *remoteWorkspaceState) error {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.validated || state.err != nil {
		return state.err
	}
	var response struct {
		ID         string `json:"id"`
		Location   string `json:"location"`
		Properties struct {
			CustomerID string `json:"customerId"`
		} `json:"properties"`
	}
	target := c.armEndpoint() + state.resourceID + "?api-version=" + url.QueryEscape(tablesAPIVersion)
	if err := c.doARM(ctx, target, &response); err != nil {
		state.err = fmt.Errorf("reading configured remote Log Analytics workspace: %w", err)
		return state.err
	}
	workspaceID := strings.TrimSpace(response.Properties.CustomerID)
	if workspaceID == "" {
		state.err = errors.New("reading configured remote Log Analytics workspace: response omitted properties.customerId")
		return state.err
	}
	if configured := strings.TrimSpace(state.config.WorkspaceID); configured != "" && !strings.EqualFold(configured, workspaceID) {
		state.err = errors.New("configured remote Log Analytics workspace ID does not match the ARM workspace customerId")
		return state.err
	}
	if response.ID != "" && canonicalRemoteScope(response.ID) != state.resourceID {
		state.err = errors.New("configured remote Log Analytics workspace resource ID does not match the ARM response")
		return state.err
	}
	location, ok := normalizeWorkspaceLocation(response.Location)
	if !ok {
		state.err = fmt.Errorf("reading configured remote Log Analytics workspace: %w", errWorkspaceLocationMissing)
		return state.err
	}
	var onboarding struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	onboardingResourceID := state.resourceID + "/providers/Microsoft.SecurityInsights/onboardingStates/default"
	target = c.armEndpoint() + onboardingResourceID + "?api-version=" + url.QueryEscape(sentinelOnboardingAPIVersion)
	if err := c.doARM(ctx, target, &onboarding); err != nil {
		state.err = fmt.Errorf("reading configured remote Microsoft Sentinel onboarding state: %w", err)
		return state.err
	}
	if !strings.EqualFold(strings.TrimSpace(onboarding.Name), "default") {
		state.err = errors.New("configured remote Microsoft Sentinel onboarding state did not return the default resource")
		return state.err
	}
	if canonicalRemoteScope(onboarding.ID) != canonicalRemoteScope(onboardingResourceID) {
		state.err = errors.New("configured remote Microsoft Sentinel onboarding state resource ID does not match the workspace")
		return state.err
	}
	state.workspaceID = workspaceID
	state.location = location
	state.validated = true
	return nil
}

// remoteWorkspaceLimitOutcomes enforces Sentinel's analytics-rule workspace
// ceiling before table or ordinary Logs evidence is collected. Canonical ARM
// resource IDs make multiple alias, customer-ID, and ARM spellings of one
// configured workspace count once. Unmapped targets remain remote; configured
// targets whose identity or region cannot be verified stop as unavailable.
func (c *Client) remoteWorkspaceLimitOutcomes(ctx context.Context, rule backend.Rule) ([]sentinelSelectorOutcome, bool) {
	type aliasTarget struct {
		state  *remoteWorkspaceState
		scope  string
		tables []string
	}
	var dependencies []backend.DependencyRef
	for _, dependency := range rule.Dependencies {
		if dependency.Kind == "sentinel_workspace_table" {
			dependencies = append(dependencies, dependency)
		}
	}
	if len(dependencies) == 0 {
		return nil, false
	}
	states := make(map[string]*remoteWorkspaceState)
	var aliases []aliasTarget
	aliasIndexes := make(map[string]int)
	for _, dependency := range dependencies {
		state, err := c.resolveRemoteWorkspace(ctx, dependency.Scope)
		if err != nil {
			method := "kql+sentinel_remote_preflight_diagnostic"
			detail := "remote workspace preflight is unavailable: " + err.Error()
			if errors.Is(err, errWorkspaceLocationMissing) {
				method = "kql+azure_monitor_region_limit_diagnostic"
				detail = "cross-workspace region evidence is unavailable: " + err.Error()
			}
			return remoteWorkspaceGuardOutcomes(dependencies, backend.ResolutionUnavailable,
				method, detail), true
		}
		if state == nil {
			return nil, false
		}
		states[state.resourceID] = state
		if remoteScopeNeedsAliasProof(dependency.Scope) {
			key := state.resourceID + "\x00" + strings.ToLower(strings.TrimSpace(dependency.Scope))
			index, found := aliasIndexes[key]
			if !found {
				index = len(aliases)
				aliasIndexes[key] = index
				aliases = append(aliases, aliasTarget{state: state, scope: dependency.Scope})
			}
			aliases[index].tables = append(aliases[index].tables, dependency.Name)
		}
	}
	// A configured alias is not Azure identity by itself. Prove each original
	// literal before allowing it to contribute to a conclusive workspace count.
	for _, alias := range aliases {
		catalog, err := c.remoteTables(ctx, alias.state)
		if err != nil {
			return nil, false
		}
		_, proof := c.validateRemoteAlias(ctx, alias.state, alias.scope, catalog, alias.tables)
		if proof.status != backend.EvidenceAssessed {
			return nil, false
		}
	}
	if len(states) > maxSentinelAnalyticsRemoteTargets {
		detail := fmt.Sprintf(
			"Sentinel analytics rules support at most %d workspaces total; this rule references %d verified remote workspaces plus the home workspace",
			maxSentinelAnalyticsWorkspaces, len(states),
		)
		return remoteWorkspaceGuardOutcomes(dependencies, backend.ResolutionIncompatible,
			"kql+sentinel_workspace_limit_diagnostic", detail), true
	}

	homeLocation, err := c.homeWorkspaceLocation(ctx)
	if err != nil {
		return remoteWorkspaceGuardOutcomes(dependencies, backend.ResolutionUnavailable,
			"kql+azure_monitor_region_limit_diagnostic",
			"cross-workspace region evidence is unavailable: "+err.Error()), true
	}
	regions := map[string]struct{}{homeLocation: {}}
	for _, state := range states {
		// validateRemoteWorkspace has already normalized and positively verified
		// every configured workspace location above.
		if state.location == "" {
			return remoteWorkspaceGuardOutcomes(dependencies, backend.ResolutionUnavailable,
				"kql+azure_monitor_region_limit_diagnostic",
				"cross-workspace region evidence is unavailable: a configured remote workspace omitted its ARM location"), true
		}
		regions[state.location] = struct{}{}
	}
	if len(regions) < maxCrossWorkspaceRegions {
		return nil, false
	}
	detail := fmt.Sprintf(
		"Azure Monitor cross-workspace queries cannot span %d or more regions; this rule spans %d verified regions",
		maxCrossWorkspaceRegions, len(regions),
	)
	return remoteWorkspaceGuardOutcomes(dependencies, backend.ResolutionIncompatible,
		"kql+azure_monitor_region_limit_diagnostic", detail), true
}

func remoteWorkspaceGuardOutcomes(dependencies []backend.DependencyRef, status backend.ResolutionStatus, method, detail string) []sentinelSelectorOutcome {
	outcomes := make([]sentinelSelectorOutcome, 0, len(dependencies))
	for _, dependency := range dependencies {
		outcomes = append(outcomes, sentinelSelectorOutcome{
			table:        dependency.Name,
			selector:     "workspace(" + kqlStringLiteral(dependency.Scope) + ")." + dependency.Name,
			selectorKind: "log_analytics_table",
			method:       method,
			optional:     !dependency.Required,
			status:       status,
			detail:       detail,
		})
	}
	return outcomes
}

// remoteExecutionIdentityOutcomes keeps scanner access separate from the
// identity Sentinel uses when an analytics rule crosses a subscription
// boundary. Sentinel runs those queries with the rule creator's credentials;
// an ARM/table/Logs probe made by deadair cannot prove that identity still has
// access. Keep the ordinary source diagnostics, but add one non-monitorable
// uncertainty per verified canonical workspace. Its requiredness follows the
// query branches for that workspace. A later exact SentinelHealth success may
// resolve only a required uncertainty for an installed rule.
func (c *Client) remoteExecutionIdentityOutcomes(ctx context.Context, rule backend.Rule) []sentinelSelectorOutcome {
	if !rule.Enabled {
		return nil
	}
	homeSubscription := strings.TrimSpace(c.SubscriptionID)
	seen := make(map[string]int)
	var outcomes []sentinelSelectorOutcome
	for _, dependency := range rule.Dependencies {
		if dependency.Kind != "sentinel_workspace_table" {
			continue
		}
		state, err := c.resolveRemoteWorkspace(ctx, dependency.Scope)
		if err != nil || state == nil || strings.EqualFold(strings.TrimSpace(state.config.SubscriptionID), homeSubscription) {
			continue
		}
		if remoteScopeNeedsAliasProof(dependency.Scope) {
			state.mu.Lock()
			aliasVerified := state.aliasChecked && state.aliasProof.status == backend.EvidenceAssessed
			state.mu.Unlock()
			if !aliasVerified {
				continue
			}
		}
		if index, exists := seen[state.resourceID]; exists {
			// Multiple query branches can name the same workspace. The execution
			// identity is required only when at least one of those branches is
			// itself required; an entirely optional remote branch stays optional.
			if dependency.Required && outcomes[index].optional {
				outcomes[index].optional = false
				outcomes[index].dependencies[0].Required = true
			}
			continue
		}
		seen[state.resourceID] = len(outcomes)
		identityDependency := backend.DependencyRef{
			ID:       "sentinel_rule_execution_identity:" + state.resourceID,
			Name:     state.config.WorkspaceName,
			Kind:     "sentinel_rule_execution_identity",
			Scope:    state.resourceID,
			Required: dependency.Required,
		}
		outcomes = append(outcomes, sentinelSelectorOutcome{
			selector:     "workspace(" + kqlStringLiteral(state.resourceID) + ")",
			selectorKind: "sentinel_rule_execution_identity",
			method:       "sentinel_rule_execution_identity_diagnostic",
			optional:     !dependency.Required,
			status:       backend.ResolutionUnavailable,
			detail: "the workspace is in a different subscription, where Sentinel runs the analytics rule with its creator's credentials; " +
				"scanner access does not prove that execution identity still has access, and no SentinelHealth execution evidence was collected",
			dependencies: []backend.DependencyRef{identityDependency},
		})
	}
	return outcomes
}

func (c *Client) remoteTables(ctx context.Context, state *remoteWorkspaceState) (map[string]tableInfo, error) {
	if err := c.validateRemoteWorkspace(ctx, state); err != nil {
		return nil, err
	}
	state.mu.Lock()
	if state.catalog != nil {
		catalog := cloneCatalog(state.catalog)
		state.mu.Unlock()
		return catalog, nil
	}
	state.mu.Unlock()

	target := c.armEndpoint() + state.resourceID + "/tables?api-version=" + url.QueryEscape(tablesAPIVersion)
	seenPages := make(map[string]bool)
	catalog := make(map[string]tableInfo)
	for page := 0; ; page++ {
		if page >= maxTablePages {
			return nil, fmt.Errorf("listing configured remote Log Analytics tables: pagination exceeded %d pages", maxTablePages)
		}
		if seenPages[target] {
			return nil, errors.New("listing configured remote Log Analytics tables: pagination cycle detected")
		}
		seenPages[target] = true
		var response tablesResponse
		if err := c.doARM(ctx, target, &response); err != nil {
			return nil, fmt.Errorf("listing configured remote Log Analytics tables: %w", err)
		}
		for _, raw := range response.Value {
			name := strings.TrimSpace(raw.Name)
			if name == "" {
				continue
			}
			if _, duplicate := catalog[name]; duplicate {
				return nil, fmt.Errorf("listing configured remote Log Analytics tables: duplicate table %q across pages", name)
			}
			catalog[name] = tableInfoFromJSON(raw, qualifiedRemoteSource(state.resourceID, name))
		}
		if strings.TrimSpace(response.NextLink) == "" {
			break
		}
		next, err := c.nextARMPage(target, response.NextLink)
		if err != nil {
			return nil, fmt.Errorf("listing configured remote Log Analytics tables: %w", err)
		}
		target = next
	}
	state.mu.Lock()
	if state.catalog == nil {
		state.catalog = cloneCatalog(catalog)
	}
	state.mu.Unlock()
	return catalog, nil
}

type sentinelSourceTarget struct {
	name                string
	table               string
	queryReference      string
	expectedResourceID  string
	expectedWorkspaceID string
	info                tableInfo
	found               bool
}

func (c *Client) sourceTarget(ctx context.Context, sourceName string, localCatalog map[string]tableInfo) (sentinelSourceTarget, error) {
	resourceID, table, remote := parseQualifiedRemoteSource(sourceName)
	if !remote {
		ref, ok := kqlTableReference(sourceName)
		if !ok {
			return sentinelSourceTarget{name: sourceName, table: sourceName}, errors.New("table name cannot be represented safely in KQL")
		}
		info, found := localCatalog[sourceName]
		return sentinelSourceTarget{name: sourceName, table: sourceName, queryReference: ref, info: info, found: found}, nil
	}
	state := c.remoteStateMap()["resource:"+resourceID]
	if state == nil {
		return sentinelSourceTarget{name: sourceName, table: table}, errors.New("remote source is not in the configured allowlist")
	}
	catalog, err := c.remoteTables(ctx, state)
	if err != nil {
		return sentinelSourceTarget{name: sourceName, table: table, expectedResourceID: resourceID}, err
	}
	ref, ok := remoteTableReference(resourceID, table)
	if !ok {
		return sentinelSourceTarget{name: sourceName, table: table, expectedResourceID: resourceID}, errors.New("remote table name cannot be represented safely in KQL")
	}
	info, found := catalog[table]
	return sentinelSourceTarget{
		name: sourceName, table: table, queryReference: ref,
		expectedResourceID: resourceID, expectedWorkspaceID: state.workspaceID,
		info: info, found: found,
	}, nil
}

func remoteDependencyRef(sourceName, table, resourceID string, required bool) backend.DependencyRef {
	return backend.DependencyRef{
		ID: sourceName, Name: table, Kind: "sentinel_workspace_table",
		Scope: canonicalRemoteScope(resourceID), Monitorable: true, Required: required,
	}
}
