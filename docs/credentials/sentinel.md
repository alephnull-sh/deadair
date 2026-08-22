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
The Azure permission catalog lists `Watchlists/read`, `ContentPackages/read`, and
`ContentProductPackages/read`, but no separate `alertRuleTemplates/read` operation. In the recorded
tenant, `Microsoft.SecurityInsights/alertRules/read` authorized the exact alert-rule-template GET.
Do not add a made-up template action to a custom role. Provider documentation is also inconsistent
about the summary-rule action, so test a custom role in your tenant before relying on optional
enrichment. Missing summary or Content Hub permissions make those report sections unavailable;
they do not make `deadair check` fail or change a health verdict.

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
secrets, but protected environment variables are a useful way to keep the workflow's Azure target
under review.

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

`DEADAIR_SENTINEL_WORKSPACE` is the ARM resource name. deadair reads its Log Analytics customer ID
through ARM. `DEADAIR_SENTINEL_WORKSPACE_ID` is an optional override; when present, it still has to
match the customer ID returned by ARM.

For cross-workspace rules, pass `--sentinel-remotes FILE` or set `DEADAIR_SENTINEL_REMOTES` to the
JSON allowlist described in the [usage guide](../usage.md#microsoft-sentinel). The Azure identity
needs ARM read, table metadata, and Logs query access on every mapped workspace that an enabled
rule references.

Before deadair trusts a textual alias, it reads the remote table catalog and runs one bounded
zero-row query using the original literal. GUID and canonical ARM-ID mappings do not need that
alias-identity Logs proof. Each referenced workspace must also have Sentinel deployed and allow
`Microsoft.SecurityInsights/onboardingStates/read`. deadair requires an exact
`onboardingStates/default` result before it reads the remote table catalog or runs a Logs query. A
`403`, `404`, malformed response, or mismatched onboarding resource makes the rule input
unavailable; it is not reported as a missing table.

Cross-tenant access through Azure Lighthouse has not been tested in a live lab. Use separate
runners when customers require different identities.

Within the scanner's visible scope, same-subscription source evidence is conclusive.
Cross-subscription analytics rules behave differently: Microsoft applies the creator's credentials,
so a rule can stop when that user loses access even if the scanner can still query the workspace.
For an eligible installed rule that references another subscription, deadair accepts only exact,
successful `SentinelHealth` evidence matching that rule identity, newer than the latest rule change
and still current for the rule's cadence, as runtime corroboration.
Candidate, absent, stale, ambiguous, mismatched, and non-successful execution evidence remains
unassessed. deadair does not identify tenant boundaries separately; Azure Lighthouse and other
cross-tenant topologies are not live-validated. Scanner access is not a substitute for
execution-health evidence. This path has fixture coverage but has not been tested live. See
Microsoft's
[analytics-rule access model](https://learn.microsoft.com/en-us/azure/sentinel/threat-detection#access-permissions-for-analytics-rules).

Microsoft limits a Sentinel analytics-rule query to 20 workspaces and recommends no more than five
for performance. deadair counts the home workspace, leaving at most 19 distinct remotes in one
rule. After any required textual-alias identity proof, a verified rule above the hard limit is
incompatible before ordinary dependency and freshness probes. The five-workspace recommendation is
operational guidance, not a deadair finding.

Azure Monitor also warns at five workspace regions and blocks a query scope at 20 regions. The
existing workspace ARM read supplies each location, so this needs no additional permission.
deadair normalizes the home and verified remote locations. A missing location is unavailable; 20
or more distinct regions is incompatible after any required alias proof but before ordinary
dependency and freshness probes. deadair does not emit a separate non-gating finding for the
five-region warning. See Microsoft's
[query-scope limits](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/scope#query-scope-limits).

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

All Logs requests are read-only queries. For each resolved table, deadair first runs a zero-row
permission probe. Freshness uses a bounded 24-hour `TimeGenerated` query for Scheduled-only sources
and a bounded `ingestion_time()` query for NRT-only sources. A source shared by both rule types stays
incomplete rather than being judged with the wrong clock. Eligible Scheduled rules use up to 500
paired `TimeGenerated` and `ingestion_time()` values from a bounded recent window for lag evidence.
The core source-evidence pass is capped at 60 tables and 180 Logs queries; anything beyond those
limits stays incomplete. Filtered source activity has a separate limit of 20 bounded
queries per scan. Summary runtime uses one bounded query covering no more than 50 relevant rules.

Summary lineage is read only when an enabled detection consumes the destination table, and that
structural path uses only ARM `GET`. It does not query Basic or Auxiliary input data or prove that a
summary rule ran. The separate bounded `LASummaryLogs` path reports the latest completed native run, including
failures, as informational evidence. It ignores in-progress `Started` rows, fails closed on invalid
rule provisioning or schedule metadata, and marks an overdue success incomplete using the configured
cadence and delay plus Microsoft's documented eight-hour retry allowance. It does not turn lineage
into a finding or gate. Provenance also
uses only ARM `GET`; it does not request expanded template or package content, and it joins exact
native IDs rather than display names. Watchlist responses can contain content and creator metadata.
deadair keeps only the bounded identity and status fields it needs, and never serializes watchlist
content, creator email, or dependency-probe KQL.

The Sentinel adapter permits only Azure Resource Manager `GET` requests and Log Analytics query
`POST` requests. If an audit shows a control-plane write or a request for shared workspace keys,
treat that as a bug.

## Current limits

Only enabled Scheduled and NRT rules whose dependencies can be resolved with complete evidence are
assessed. Supported dependencies include direct tables, joins, unions, `let` aliases, saved
workspace functions with closed scalar arguments, literal watchlists, metadata-backed ASIM
functions with complete evidence, native ASIM calls with positive table and permission evidence,
and explicitly mapped literal `workspace()` tables. Join and ordinary union inputs are required;
only explicit `union isfuzzy=true` inputs may be absent without making the rule unusable.

For a cross-workspace input, missing or unreadable Sentinel onboarding evidence is `unavailable`,
and no table or Logs probe follows. A verified rule referencing more than 20 total workspaces,
including its home workspace, is `incompatible`. A missing home or remote workspace location is
also `unavailable`; 20 or more distinct normalized regions is `incompatible`. `deadair check`
exercises remote onboarding and readiness for configured remotes referenced by enabled rules;
unused mappings are not touched. Summary and provenance permissions remain optional and are
not part of readiness. Same-subscription mapped sources can resolve conclusively. An eligible
installed rule that references another subscription needs an exact successful matching
`SentinelHealth` event after the latest rule change and within its expected run cadence to
corroborate execution identity. Candidate scans and absent, old, mismatched, or non-successful
evidence remain unassessed. Tenant topology is not identified
separately.

Filtered source activity is limited to one direct local Analytics table followed by a closed,
parser-supported literal filter. Remote, joined, unioned, dynamic, escaped-literal, and function-backed
sources do not qualify. The bounded result is informational and cannot create a finding. Summary
runtime evidence is likewise informational, bounded to seven days, and capped at 50 relevant active
summary rules per scan. Predicate freshness and summary runtime were exercised by the recorded live
lab. Cross-subscription `SentinelHealth` corroboration remains fixture-tested.

Enable [Sentinel auditing and health monitoring](https://learn.microsoft.com/en-us/azure/sentinel/enable-monitoring)
before using the `_SentinelHealth()` path. For summary runtime, enable the
[Summary Logs diagnostic category](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/summary-rules#monitor-summary-rules);
`LASummaryLogs` only appears after a summary event is emitted. Missing tables or rows stay
unavailable or incomplete and never create findings or gates.
The existing Logs query permission covers both tables unless table-level RBAC is in use. A custom
role under table-level RBAC needs
`Microsoft.OperationalInsights/workspaces/query/SentinelHealth/read` and
`Microsoft.OperationalInsights/workspaces/query/LASummaryLogs/read`, or the broader
`Microsoft.OperationalInsights/workspaces/query/*/read` action.

deadair leaves these inputs unassessed: tabular function parameters, row/runtime arguments,
parameter-driven `table()`, dynamic watchlist or workspace targets, external data, `app()` and
`resource()` targets, ADX/cluster, and ARG. A native ASIM response containing `PartialError`, no
concrete table, or incomplete permission evidence also stays unassessed. Basic and Auxiliary tables
are incompatible with the analytics-rule evidence path.

The live lab accepted Basic-table Scheduled and NRT rules while they were disabled, then rejected
both when enabling them because their queries could not execute. Azure Monitor's
[Simple Log Alerts](https://learn.microsoft.com/en-us/azure/azure-monitor/alerts/alerts-create-simple-alert)
can query Basic tables, but those are separate from Sentinel Scheduled and NRT analytics rules.

Sentinel does not expose authoritative rule-required fields or a bounded, authoritative per-table
event and storage inventory for this scan. Required-field and unused-telemetry findings therefore
remain unavailable.
Dependency evidence explains resolution outcomes, and a required dependency can affect the rule
verdict. Summary-lineage and provenance evidence is informational and cannot create a finding or
change a gate. The CLI currently targets Azure public cloud endpoints.
