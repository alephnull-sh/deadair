# Integration tests

The integration suite runs backend checks against live Docker stacks:

- least-privilege credentials can scan successfully
- representative writes are rejected
- verdicts are correct on real indexed data
- schema reads and stateful checks work with the documented roles
- mixed-backend fleet scans work

These tests need Docker or a compatible container runtime.

## Elastic

```sh
make integration-up
make integration-test
make integration-down
```

The compose default is Elasticsearch and Kibana 9.4.4 with security enabled. Trusted CI runs this
same suite against 8.19.19 and 9.4.4. The suite provisions role `deadair_monitor`, creates API key
`deadair-it`, seeds live/stale/empty sources and test rules, scans with the deadair key, asserts
rejected writes, then cleans up.

## OpenSearch

```sh
make opensearch-integration-up
make opensearch-integration-test
make opensearch-integration-down
```

The compose default is OpenSearch 3.7.0 with the security plugin. Trusted CI runs the suite against
2.19.6 and 3.7.0. The suite provisions user `deadair`, maps it to
`security_analytics_read_access` and `deadair_index_monitor`, seeds detector documents as admin,
scans as the least-privilege user, and asserts rejected writes.

## Microsoft Sentinel

This section is for maintainers reproducing the disposable Sentinel lab. To configure a normal
read-only scan, use the [Sentinel credential guide](../docs/credentials/sentinel.md).

### Run against an existing fixture lab

The Sentinel read-only test reads a pre-seeded disposable workspace. It does not provision fixtures
or call Azure write APIs. It accepts only a certificate-backed scanner service principal through
`EnvironmentCredential`; Azure CLI and the rest of the default credential chain are rejected. Set
`AZURE_TOKEN_CREDENTIALS` to exactly `EnvironmentCredential`, set `AZURE_TENANT_ID`,
`AZURE_CLIENT_ID`, and `AZURE_CLIENT_CERTIFICATE_PATH`, and leave `AZURE_CLIENT_SECRET` unset. Set
`DEADAIR_SENTINEL_SCANNER_CLIENT_ID` to the same value as `AZURE_CLIENT_ID`. The test checks that
identity contract before contacting the workspace and never prints credential values or certificate
paths.

The full base and expansion setup, scanner test, and denial test ran in disposable UK South
workspaces on 2026-08-22. That result applies to the named workspaces and identity. It does
not cover every tenant, region, RBAC layout, or KQL construct.

```sh
DEADAIR_IT_SENTINEL=1 \
DEADAIR_AZURE_SUBSCRIPTION_ID=... \
DEADAIR_AZURE_RESOURCE_GROUP=... \
DEADAIR_SENTINEL_WORKSPACE=... \
DEADAIR_SENTINEL_REMOTE_WORKSPACE=... \
go test -tags=integration ./integration -run '^TestSentinelReadOnlyLab$' -v
```

Write denials are a separate, explicit run using the same scanner credential:

```sh
DEADAIR_IT_SENTINEL_WRITE_DENIALS=1 \
DEADAIR_AZURE_SUBSCRIPTION_ID=... \
DEADAIR_AZURE_RESOURCE_GROUP=... \
DEADAIR_SENTINEL_WORKSPACE=... \
go test -tags=integration ./integration -run '^TestSentinelWriteDenials$' -v
```

It first proves that the fixed alert-rule and table DELETE targets do not exist, then requires exact
HTTP 403 responses for both DELETE requests and the workspace shared-keys POST. It never reads a
successful shared-keys response body. A 2xx response fails the test.

The home workspace must contain the `DeadairFresh_CL`, `DeadairLag_CL`,
`DeadairStale_CL`, `DeadairUnused_CL`, `DeadairPredicate_CL`, `DeadairBasic_CL`,
`DeadairAuxiliary_CL`, and `DeadairEmptyAnalytics_CL` tables; the saved `DeadairLabSource` and
closed-scalar `DeadairLabParameterized` functions; and the matching deadair lab rules. The
removed-table fixture must stay absent. The disabled NRT rule
`78888888-8888-4888-8888-888888888888` is part of the base fixture and remains disabled throughout
the test. The expansion fixtures add the `DeadairVIPs` watchlist, a second workspace with
`DeadairRemote_CL`, and the `deadair-basic-summary` summary rule whose pre-created, independently
marked Analytics destination is `DeadairBasicSummary_CL`. Its workspace diagnostic setting routes
only the Summary Logs category to `LASummaryLogs`. Four owned, disabled Scheduled rules
consume the literal watchlist, native ASIM parser, remote table, and summary destination. The live
test reads their KQL dependencies through the normal Sentinel inventory and enables only in-memory
copies for evidence collection; the Azure rules remain disabled. Sentinel must be deployed on the
second workspace through its exact `onboardingStates/default` resource before the test will assess
it. The test covers GA and preview NRT inventory, table-plan
compatibility, saved-function expansion, literal-watchlist proof, configured literal `workspace()`
proof, an intentionally unassessed native-ASIM `PartialError`, structural summary lineage, mixed
present/missing inputs, Scheduled event-time freshness, NRT ingestion-time freshness, mixed timing,
predicate-qualified freshness, a successful native summary execution, the matching
Basic-to-Analytics bin and count, and paired ingest-lag evidence. Readiness runs once with the
literal watchlist, native ASIM, remote workspace, and the in-memory enabled copy of the NRT rule. A
second pass without the intentionally limited ASIM result covers the watchlist, local-table, NRT,
and remote-table read paths without the known ASIM limitation.
The Azure NRT rule stays disabled. Summary `binDelay` is measured in minutes, matching Azure
Monitor's summary-rule scheduling model and the Sentinel portal.

### Prepare a disposable lab

Start with an existing dedicated resource group and Log Analytics workspace that is
already onboarded to Sentinel. Register `Microsoft.OperationalInsights`,
`Microsoft.SecurityInsights`, and `Microsoft.Insights`, and put a small subscription budget and
alert in place before provisioning fixtures. The provisioner needs permission to manage workspace
tables and saved searches, Sentinel alert rules, and a resource-group-scoped data collection rule.
It also needs `Monitoring Metrics Publisher` at the resource-group scope for the six Logs
Ingestion API calls; assign that before `apply`, because the DCR does not exist yet. The script also
runs a bounded `print ... | take 1` capability probe before its first write, so the provisioner must
be allowed to execute Log Analytics queries on the workspace.

#### Base fixtures

`integration/prepare-sentinel-base-lab.sh plan` is offline. `apply` first verifies the existing
workspace name and independently supplied customer UUID, verifies Sentinel onboarding, reads the
relevant ARM inventories, and rejects collisions in resource IDs, function names, or rule
inventory. It waits for owned tables and the DCR to reach a successful stable state, then checks
their full definitions again before using them. It creates only the named child fixtures and adds
six rows on every apply, including current predicate and Basic summary-source rows. It also creates
`DeadairEmptyAnalytics_CL` as an empty Analytics table and
removes `DeadairRemoved_CL` after the DCR and missing/partial rules exist. Row evidence expires after
24 hours. Running `apply` again refreshes it by adding six more rows. The empty Analytics table
receives no rows and validates assessed-empty freshness for a resolved rule input.

Azure retains deleted Log Analytics tables and their data for 15 days for name reservation and
recovery. Treat base cleanup as a terminal or cooling-off operation. For an immediate clean rerun,
use a fresh workspace; otherwise, wait for the retention window to expire. Cleanup does not
immediately purge the retained rows. An interrupted apply can resume only while visible owned
resources still match their exact definitions. The full create, ingest, and exact cleanup path ran
through this script on 2026-08-21.

Before each deletion, cleanup re-reads the target and checks its full fixture definition. This is
not a transaction: another writer could still change a resource between the final GET and DELETE.
Do not run fixture writers concurrently. Cleanup leaves the resource group, workspace, Sentinel
onboarding, budget, and role assignments intact.

```sh
DEADAIR_AZURE_SUBSCRIPTION_ID=... \
DEADAIR_AZURE_RESOURCE_GROUP=... \
DEADAIR_SENTINEL_WORKSPACE=... \
DEADAIR_SENTINEL_WORKSPACE_ID=00000000-0000-0000-0000-000000000000 \
integration/prepare-sentinel-base-lab.sh plan

DEADAIR_SENTINEL_BASE_LAB_CONFIRM=deadair-sentinel-base-validation:WORKSPACE:WORKSPACE-CUSTOMER-UUID \
DEADAIR_AZURE_SUBSCRIPTION_ID=... \
DEADAIR_AZURE_RESOURCE_GROUP=... \
DEADAIR_SENTINEL_WORKSPACE=WORKSPACE \
DEADAIR_SENTINEL_WORKSPACE_ID=WORKSPACE-CUSTOMER-UUID \
integration/prepare-sentinel-base-lab.sh apply

DEADAIR_SENTINEL_BASE_LAB_CONFIRM=deadair-sentinel-base-validation:WORKSPACE:WORKSPACE-CUSTOMER-UUID \
DEADAIR_AZURE_SUBSCRIPTION_ID=... \
DEADAIR_AZURE_RESOURCE_GROUP=... \
DEADAIR_SENTINEL_WORKSPACE=WORKSPACE \
DEADAIR_SENTINEL_WORKSPACE_ID=WORKSPACE-CUSTOMER-UUID \
integration/prepare-sentinel-base-lab.sh cleanup
```

#### Expansion fixtures

Run the expansion script second, then run the read-only Go test. Tear down in reverse order:
expansion fixtures first, then base fixtures. Both scripts require their own explicit confirmation
values for `apply` and `cleanup`.

`integration/prepare-sentinel-expansion-lab.sh verify` runs a strict, read-only preflight of the
base lab. The default `plan` mode runs the same preflight, then prints the exact targets, test
environment, and confirmation value. `apply` completes the preflight and every collision check
before its first write.

The preflight checks exact table plans and schemas, exact base rule and function definitions,
`BuiltInFusion`, a current predicate row, a current Basic summary-source row through the Basic Logs
search endpoint, and a bounded aggregate proving recent nonempty Fresh, Lag, Stale, and Unused rows
with Fresh < Lag < Stale paired ingest lag. It returns aggregate flags and lag seconds, never source
records. After waiting for a native summary run, `apply` checks the current base rows again before
calling the lab ready. It does not create or repair base fixtures. `apply` and `cleanup` touch only
the named disposable expansion fixtures and require the explicit confirmation value printed by the
script. Authenticate with Azure CLI first, then run:

```sh
DEADAIR_AZURE_SUBSCRIPTION_ID=... \
DEADAIR_AZURE_RESOURCE_GROUP=... \
DEADAIR_SENTINEL_WORKSPACE=... \
DEADAIR_SENTINEL_REMOTE_WORKSPACE=... \
integration/prepare-sentinel-expansion-lab.sh verify

DEADAIR_AZURE_SUBSCRIPTION_ID=... \
DEADAIR_AZURE_RESOURCE_GROUP=... \
DEADAIR_SENTINEL_WORKSPACE=... \
DEADAIR_SENTINEL_REMOTE_WORKSPACE=... \
integration/prepare-sentinel-expansion-lab.sh plan

DEADAIR_SENTINEL_LAB_CONFIRM=deadair-sentinel-expansion-validation \
DEADAIR_AZURE_SUBSCRIPTION_ID=... \
DEADAIR_AZURE_RESOURCE_GROUP=... \
DEADAIR_SENTINEL_WORKSPACE=... \
DEADAIR_SENTINEL_REMOTE_WORKSPACE=... \
integration/prepare-sentinel-expansion-lab.sh apply

DEADAIR_SENTINEL_LAB_CONFIRM=deadair-sentinel-expansion-validation \
DEADAIR_AZURE_SUBSCRIPTION_ID=... \
DEADAIR_AZURE_RESOURCE_GROUP=... \
DEADAIR_SENTINEL_WORKSPACE=... \
DEADAIR_SENTINEL_REMOTE_WORKSPACE=... \
integration/prepare-sentinel-expansion-lab.sh cleanup
```

#### Expansion safeguards

Watchlist apply uses `FixtureID` as the source search-key column because Sentinel reserves and
generates `SearchKey`. It waits for lifecycle fields returned by Azure to settle and tolerates fields
that the API omits. Cleanup refuses an explicitly in-progress watchlist. It accepts an omitted
response `contentType` only when every other identity and ownership field matches exactly. Remote
onboarding likewise accepts an omitted default `customerManagedKey`, but rejects explicit `true`.

The summary destination includes mandatory `TimeGenerated` and is created before the rule with an
exact schema-description ownership marker. The Summary Logs diagnostic setting is matched by exact
workspace destination and category; `apply` waits for a successful one-result execution after the
ARM definition became visible. Cleanup checks each resource again immediately before deletion,
deletes the rule first, and can resume with only the table left after an interrupted deletion. The
four disabled Scheduled rules are checked for collisions before the first write, polled until their
exact definitions are readable, and deleted before their watchlist, remote-workspace, or summary
dependencies. A missing or changed marker always fails closed. Every mode rejects identical home
and remote workspace names.

### What the live test proves

The Go conformance test itself remains read-only. It parses bounded identity and version fields from
the alert-rule-template, Content Hub template, and installed-package inventories so a permission
denial cannot masquerade as an empty Content Hub association. The current fixture requires an exact
zero installed-package count. If an exact Content Hub template link exists, the test also reads that
one product-package identity and requires deadair to report the linked package as not installed.
When `BuiltInFusion` exposes an exact native template ID and installed version, the test requires
assessed evidence for that template and version. If the tenant does not expose those fields, the test
records positive native-template provenance as pending rather than claiming live validation.

The 2026-08-22 run also proved a current literal vendor predicate and a Basic-plan source row flowing
through a successful summary execution to the matching Analytics destination bin and count.
`LASummaryLogs.RuleLastModifiedTime` advanced between completed bins while the ARM definition stayed
unchanged, so deadair treats it as a timestamp sanity check and lower bound. It does not claim that
the field identifies the exact ARM revision.

A successful run proves only the named workspaces and scanner identity. It does not prove:

- cross-tenant Azure Lighthouse;
- cross-subscription or cross-tenant creator-credential execution;
- a positive installed Content Hub package association.

Same-subscription mapped evidence remains conclusive for source availability. Cross-subscription
and cross-tenant execution stays unassessed without recent per-rule `SentinelHealth` evidence. The
current Content Hub fixture covers a readable, empty installed-package inventory, not a positive
installed package association.

The same-subscription fixture does not reproduce unreadable onboarding or the 20-workspace
incompatibility path; local fixtures cover those cases. Microsoft limits an analytics-rule query to
20 workspaces, and deadair counts the home workspace. Microsoft recommends no more than five for
performance. The single-region lab also does not reproduce Azure Monitor's region-scope boundary:
a missing location is unavailable, while 20 or more distinct normalized workspace regions is
incompatible after any required alias proof. Azure Monitor warns at five regions, but deadair does
not emit a separate finding for that guidance threshold.

## Full integration pass

```sh
make integration
```

This runs the Elastic, OpenSearch, and mixed-backend fleet tests in sequence using the Compose
defaults. Trusted CI runs the fleet test with Elastic 9.4.4 and OpenSearch 3.7.0. The
[trusted integration workflow](../.github/workflows/integration.yml) is the source of truth for
the exact versions tested.

Environment overrides:

- `ELASTIC_VERSION`
- `OPENSEARCH_VERSION`
- `DEADAIR_IT_ES_URL`
- `DEADAIR_IT_KIBANA_URL`
- `DEADAIR_IT_PASSWORD`
- `DEADAIR_IT_OPENSEARCH_URL`
- `DEADAIR_IT_OPENSEARCH_ADMIN_PASSWORD`

Defaults match the compose files. Version overrides select both Elasticsearch and Kibana for the
Elastic stack. Use versions from the trusted CI matrix when reproducing a version-specific issue.

## MSSP lab

```sh
make mssp-lab
```

The lab starts both throwaway stacks, seeds them, runs a five-instance fleet, scrapes the exporter,
writes redacted artifacts to `integration/mssp-lab-out/`, and tears everything down.

The MSSP guide uses [docs/assets/mssp-lab.gif](../docs/assets/mssp-lab.gif), recorded from these
generated artifacts.

Lab instances:

| Instance | Purpose |
|---|---|
| `acme-elastic` | healthy Elastic credential |
| `beta-opensearch` | healthy OpenSearch credential |
| `charlie-bad-key` | Elastic with an invalid API key |
| `delta-down` | unreachable tenant |
| `echo-bad-password` | OpenSearch with a bad password |

The lab also warms schema snapshots, changes one Elastic source, runs a second scan so schema
drift is visible, and applies an active downtime window to stale lab sources.

Generated files:

- `check.txt`
- `fleet-summary.txt`
- `fleet-baseline-redacted.json`
- `fleet-redacted.json`
- `metrics.txt`
- `downtime.json`
- generated `fleet.json`
- per-instance state files

Useful variants:

```sh
make mssp-lab
make mssp-lab-up
make mssp-lab-run
make mssp-lab-down
MSSP_LAB_OUT=/tmp/deadair-lab make mssp-lab
```

The lab validates the MSSP operator path in Docker. It does not replace testing against real client
fleets.

## Notes

- Kibana can take a minute or two on first boot. The tests poll `/api/status` before failing.
- The compose passwords are for throwaway stacks only.
- Both backend suites run with `--schema --state-file` so field-capability permissions
  are part of the least-privilege proof.
- Do not point these tests at a cluster you care about. They seed and remove test fixtures.

## Trusted CI boundary

Live integration jobs run only on pushes to `main`, merge queues, the weekly schedule, or manual
dispatch. They do not run on the `pull_request` event, so code from an untrusted fork is never given
a live integration environment or repository secrets. Pull requests still compile and run the
secret-free unit, race, vet, formatting, static-build, module, cross-compile, and Windows checks.

## CI naming convention

CI partitions integration tests by function prefix:

- `TestElastic*`
- `TestOpenSearch*`
- `TestFleet*`

`TestMSSPLab` is intentionally separate because it writes durable lab artifacts and runs only
through `make mssp-lab`.

Any new CI integration test must use one of the CI prefixes above, or it will compile without
running in CI.
