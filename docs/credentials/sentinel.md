# Microsoft Sentinel read-only credentials

The core Sentinel scan needs read access to three things:

1. Microsoft Sentinel analytics-rule metadata.
2. Log Analytics workspace and table metadata.
3. The local tables used by enabled rules, for bounded permission, freshness, and ingest-lag
   queries.

Some rules and optional report sections need more access:

- Sentinel watchlist metadata and a bounded `_GetWatchlist()` query when a rule names a literal
  watchlist alias;
- ARM metadata, Sentinel onboarding state, and Logs access on every explicitly mapped
  `workspace()` target;
- Log Analytics summary-rule metadata when an enabled detection consumes a summary destination;
- `SentinelHealth` and `LASummaryLogs` table reads for the optional execution-identity and summary
  runtime sections; and
- alert-rule-template and Content Hub metadata for exact-ID provenance.

It does not need rule writes, table writes, workspace keys, data collection permissions, or incident
permissions. A candidate scan does not install the rule. It uses the same read-only metadata and
bounded table and dependency-evidence calls as an installed-rule scan, but skips summary-lineage
and Content Hub enrichment.

## What has been tested

The disposable UK South lab used a workspace-scoped custom role limited to the read and query
operations below. Rule deletion, table deletion, and shared-key retrieval all returned `403`. The
[validation record](../validation.md#sentinel-live-conformance) lists the exact live and contract
coverage.

## Assign the roles

For the simplest setup, assign these built-in roles to the identity that runs deadair:

- `Microsoft Sentinel Reader`
- `Log Analytics Reader`

Use workspace scope unless one identity needs to scan several workspaces in the same resource
group. These built-in roles are broader than the custom role used in the lab, but they avoid a
separate role definition. For a service principal, assign them like this:

```sh
sentinel_scope=/subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.OperationalInsights/workspaces/<workspace-resource-name>

az role assignment create \
  --assignee-object-id <service-principal-object-id> \
  --assignee-principal-type ServicePrincipal \
  --role "Microsoft Sentinel Reader" \
  --scope "$sentinel_scope"

az role assignment create \
  --assignee-object-id <service-principal-object-id> \
  --assignee-principal-type ServicePrincipal \
  --role "Log Analytics Reader" \
  --scope "$sentinel_scope"
```

The adapter can use these Azure operations:

| Operation | Scope | Why deadair needs it |
|---|---|---|
| `Microsoft.SecurityInsights/alertRules/read` | core | read Scheduled and NRT analytics rules |
| `Microsoft.OperationalInsights/workspaces/read` | core and each mapped remote | discover and verify the Log Analytics workspace customer ID and normalized location |
| `Microsoft.OperationalInsights/workspaces/tables/read` | core and each mapped remote | read table catalogs, plans, provisioning state, and schema |
| `Microsoft.OperationalInsights/workspaces/query/read` | core and each queried remote | run Log Analytics queries |
| `Microsoft.OperationalInsights/workspaces/query/*/read` | core and each queried remote | read tables used by enabled rules; this can be narrowed to individual table actions |
| `Microsoft.OperationalInsights/workspaces/query/Watchlist/read` | home workspace, rules with literal watchlists | narrow table action for the ordinary Watchlist table used by bounded watchlist proof |
| `Microsoft.OperationalInsights/workspaces/query/ConfidentialWatchlist/read` | home workspace, rules with literal watchlists | narrow table action for the ConfidentialWatchlist table used by bounded watchlist proof |
| `Microsoft.OperationalInsights/workspaces/query/SentinelHealth/read` | optional different-subscription execution evidence | read exact current rule-health records when Sentinel auditing and health monitoring is enabled |
| `Microsoft.OperationalInsights/workspaces/query/LASummaryLogs/read` | optional summary runtime evidence | read bounded latest-completed-run records when the summary-rule diagnostic setting is enabled |
| `Microsoft.SecurityInsights/onboardingStates/read` | each mapped remote | prove that Sentinel is deployed on the referenced workspace before table or Logs assessment |
| `Microsoft.SecurityInsights/Watchlists/read` | rules with literal watchlists | inventory watchlist aliases before a bounded Logs proof |
| `Microsoft.OperationalInsights/workspaces/summarylogs/read` | optional scan enrichment | read structural summary-rule definitions |
| `Microsoft.SecurityInsights/ContentTemplates/read` | optional scan enrichment | link an exact installed content template ID to its package ID |
| `Microsoft.SecurityInsights/ContentPackages/read` | optional scan enrichment | read installed Content Hub package versions |
| `Microsoft.SecurityInsights/ContentProductPackages/read` | optional scan enrichment | read currently available Content Hub package versions |

The `query/*/read` action is simpler, but broader than feature-specific grants. Narrow roles can use
`query/Watchlist/read`, `query/ConfidentialWatchlist/read`, `query/SentinelHealth/read`, and
`query/LASummaryLogs/read` for the optional paths they enable. Tables used by enabled rules still
need their own query actions. With granular Log Analytics RBAC, you may instead grant the
corresponding `Microsoft.OperationalInsights/workspaces/tables/data/read` data action with table or
row conditions.

Whatever scope you choose, deadair treats a table it cannot query as unavailable. A permission gap
never becomes a dead-rule finding.

Microsoft documents the current permission names under
[Microsoft Sentinel roles](https://learn.microsoft.com/en-us/azure/sentinel/roles) and
[Log Analytics workspace access](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/manage-access).
Azure does not publish a separate `alertRuleTemplates/read` operation, and its documentation for
the summary-rule action varies. In the recorded lab,
`Microsoft.SecurityInsights/alertRules/read` authorized the alert-rule-template GET. If you use a
custom role, confirm the optional summary, template, and package sections in the first report.
Missing optional rights leave those sections unavailable without blocking the core scan.

## Authenticate and scan

For a local interactive scan, sign in with Azure CLI. `DefaultAzureCredential` will use that login:

```sh
az login --tenant <tenant-id>
az account set --subscription <subscription-id>

export DEADAIR_BACKEND=sentinel
export DEADAIR_AZURE_SUBSCRIPTION_ID=<subscription-id>
export DEADAIR_AZURE_RESOURCE_GROUP=<resource-group>
export DEADAIR_SENTINEL_WORKSPACE=<workspace-resource-name>

deadair check
deadair scan --json-out report.json --html-out report.html
```

For CI or a service, use a workload identity, managed identity, or the standard
`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, and either `AZURE_CLIENT_SECRET` or
`AZURE_CLIENT_CERTIFICATE_PATH` variables understood by `DefaultAzureCredential`. Keep credentials
in the runner's secret store. Tenant, client, and subscription IDs are identifiers rather than
secrets. Keep them in protected environment variables so an untrusted change cannot redirect the
workflow to another Azure target.

The GitHub Action supports a caller-owned OIDC login. Configure an Entra federated credential for a
protected GitHub Environment or a tightly scoped branch, grant its identity only the read roles
above, and run [`azure/login`](https://github.com/Azure/login/) before the deadair step. Azure Login
exchanges GitHub's OIDC token and signs the runner into Azure CLI. deadair then reaches that session
through the `AzureCLICredential` member of
[`DefaultAzureCredential`](https://learn.microsoft.com/en-us/azure/developer/go/sdk/authentication/credential-chains).
This is Azure CLI credential reuse, not direct `AZURE_FEDERATED_TOKEN_FILE` passthrough. The Action
does not define Azure credential inputs or choose a credential type. See the
[Sentinel gate example](../usage.md#gate-detection-changes) and Microsoft's
[OIDC setup guide](https://learn.microsoft.com/en-us/azure/developer/github/connect-from-azure-openid-connect).

Match the federated credential to the repository's actual OIDC subject. New GitHub.com repositories
created after July 15, 2026 include immutable owner and repository IDs, for example
`repo:OWNER@OWNER-ID/REPO@REPO-ID:ref:refs/heads/main`. Older repositories may still use the name-only
form. An environment-bound job uses an environment subject instead of a branch subject. Check
[GitHub's subject formats](https://docs.github.com/en/actions/reference/security/oidc#immutable-subject-claims)
when setting up the trust. If Azure reports `AADSTS700213`, compare the subject, issuer and audience
shown by Azure Login with the Entra federated credential; don't broaden workspace permissions to fix
a trust mismatch.

`DEADAIR_SENTINEL_WORKSPACE` is the ARM resource name. deadair reads its Log Analytics customer ID
through ARM. `DEADAIR_SENTINEL_WORKSPACE_ID` is an optional override; when present, it still has to
match the customer ID returned by ARM.

For cross-workspace rules, pass `--sentinel-remotes FILE` or set `DEADAIR_SENTINEL_REMOTES` to the
JSON allowlist described in the [usage guide](../usage.md#microsoft-sentinel). The Azure identity
needs ARM read, table metadata, and Logs query access on every mapped workspace that an enabled
rule references.

Textual aliases require a remote table-catalog read and one bounded zero-row query using the
original literal. GUID and canonical ARM-ID mappings skip that alias check. Every referenced
workspace must return its exact `onboardingStates/default` resource before deadair reads tables or
runs a Logs query there.

Use separate runners when customers require different Azure identities. Cross-subscription rules
also need `SentinelHealth` access because Sentinel runs them with the rule creator's credentials,
not the scanner's. The [usage guide](../usage.md#cross-workspace-rules) covers identity evidence,
workspace and region limits, and Azure Lighthouse.

## Calls deadair makes

- `GET` the Log Analytics workspace through Azure Resource Manager
- `GET` the workspace table catalog through Azure Resource Manager
- `GET` the Sentinel alert-rule collection using the stable API and the NRT preview API
- `POST /v1/workspaces/<workspace-id>/metadata` to read saved workspace-function definitions
- `POST /v1/workspaces/<workspace-id>/query` with `Prefer: include-permissions=true,include-dataSources=true`
- when an enabled rule needs them, `GET` the Sentinel watchlist collection and run bounded zero-row
  `_GetWatchlist()` or native ASIM queries
- for an eligible parser-proved predicate over one direct local Analytics table, run a bounded
  rule-specific freshness query; the literal predicate and query text are never serialized
- for referenced, configured remote workspaces, `GET` the workspace and table catalog and run
  bounded queries whose permission and data-source evidence must identify that workspace
- before those remote catalog/query calls, `GET` the GA 2025-09-01 Sentinel
  `onboardingStates/default` resource and require an exact matching ARM ID
- as optional scan enrichment, `GET` Log Analytics `summaryLogs` and Sentinel
  `alertRuleTemplates`, `contentTemplates`, `contentPackages`, and `contentProductPackages`
- as optional scan enrichment, query the latest completed runs from seven days of `LASummaryLogs` for the exact ARM
  names of relevant active summary rules, capped at 50 rules per scan
- for eligible installed rules that reference another subscription, query current `SentinelHealth`
  evidence and accept only an exact successful match to the rule identity

All Logs requests are read-only queries. Each resolved table gets a zero-row permission probe before
freshness or lag is measured. The source pass is capped at 60 tables and 180 Logs queries; filtered
source activity is capped at 20 queries, and summary runtime at 50 rules. The
[usage guide](../usage.md#microsoft-sentinel) explains the freshness clocks and evidence model.

Watchlist responses can contain content and creator metadata. deadair keeps only the identity and
status fields it needs and never serializes watchlist content, creator email, or dependency-probe
KQL.

The Sentinel adapter permits only Azure Resource Manager `GET` requests and Log Analytics query
`POST` requests. If an audit shows a control-plane write or a request for shared workspace keys,
treat that as a bug.

<span id="current-limits"></span>

## Coverage

deadair assesses enabled Scheduled and NRT rules with direct tables, joins, unions, `let` aliases,
saved functions with closed scalar arguments, literal watchlists, supported ASIM calls, and mapped
literal `workspace()` tables. Every ordinary join or union leg is required; `union isfuzzy=true`
can retain partial coverage when one leg is absent.

It does not assess tabular function parameters, row-derived arguments, parameter-driven `table()`,
dynamic watchlist or workspace targets, external data, `app()`, `resource()`, ADX/cluster, or ARG.
Basic and Auxiliary tables are incompatible with Sentinel Scheduled and NRT analytics rules.

`SentinelHealth` and `LASummaryLogs` require their Azure monitoring settings and table permissions.
`SentinelHealth` corroborates rule execution. Failed or overdue summary runs produce
`summary-pipeline` findings; add that class to your policy to gate on them. Sentinel also lacks the
authoritative field and per-table inventory needed for required-field and unused-telemetry findings.
The CLI targets Azure public cloud endpoints.

See the [Sentinel usage guide](../usage.md#microsoft-sentinel) for report behavior and
[validation status](../validation.md#microsoft-sentinel) for the live and fixture-tested paths.
