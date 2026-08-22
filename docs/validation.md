# Validation status

deadair is tested against live Elastic, OpenSearch, and Microsoft Sentinel APIs, with local contract
fixtures covering paths that are unsafe or impractical to reproduce live. This page says what runs
in CI, what was checked manually, and what remains unproven. For finding terminology and triage, see
[Read the findings](usage.md#read-the-findings).

## Test coverage

The live CI matrix covers Elastic Security 8.19.19 and 9.4.4, plus OpenSearch Security Analytics
2.19.6 and 3.7.0. Sentinel unit and contract tests run with the normal Go suite. The live Sentinel
conformance test is opt-in and does not run on a schedule.

| Area | Evidence |
|---|---|
| core graph logic | unit and race tests |
| Elastic backend | live integration tests using the documented read-only role |
| OpenSearch backend | live integration tests using the documented read-only role |
| Sentinel backend | local parser, API-contract, permission-evidence, report, and CLI tests |
| Sentinel live path | opt-in read-only conformance test against a pre-seeded disposable workspace |
| Sentinel GitHub Action | local wrapper tests cover input mapping, argument ownership, environment isolation, report production, job-summary content, and gate behavior; the GitHub-hosted OIDC path has not yet had a live conformance run |
| native input resolution | index/alias/data-stream cases plus Sentinel KQL table, closed scalar function, literal watchlist, ASIM, remote workspace, plan, and permission outcomes |
| Sentinel enrichment | the live lab covers narrow filtered source activity, structural summary lineage, a bounded successful `LASummaryLogs` run, and its matching Basic-to-Analytics output bin; exact-ID native template and Content Hub provenance also has fixture coverage; advisory evidence does not change findings or gates |
| Sentinel execution identity | fixture tests require an exact successful `SentinelHealth` event after the latest rule change and no older than the rule cadence plus the documented scheduling delay; other execution-identity cases remain unassessed |
| write safety | live Elastic and OpenSearch tests require representative writes to be rejected; separate Sentinel lab probes confirmed its scan identity could not delete rules or tables or retrieve shared keys |
| candidate-rule checks | backend-native `scan --rule` parser and gate tests; Sentinel covers direct ARM JSON, one Azure-Sentinel analytic-rule YAML document, and deployment templates whose rule values resolve from literals, defaults, or simple variables |
| fleet behavior | mixed-backend integration tests and a five-instance MSSP lab |
| reports | terminal, JSON, HTML, redacted JSON, and Prometheus output |

The MSSP lab includes healthy, failed, and unreachable tenants. It exercises partial failures,
per-instance state, schema drift, downtime suppression, redaction, and exporter labels.

## Sentinel live conformance

The Sentinel adapter was exercised against a disposable workspace in UK South using a custom
workspace-scoped reader limited to the operations in the
[Sentinel credential guide](credentials/sentinel.md). The read-only conformance test is gated by
`DEADAIR_IT_SENTINEL=1`; it expects pre-seeded fixtures and never creates or changes Azure
resources.

The live workspace covers:

- enabled Scheduled rules from the stable API and an NRT rule from the preview API;
- direct local tables, `join`, `union`, `let`, and mixed present/missing inputs;
- bare and called zero-parameter saved workspace functions plus a closed scalar parameterized
  function;
- a literal watchlist, a configured same-subscription workspace, and exact remote Sentinel
  onboarding before remote table or Logs evidence;
- a native ASIM call whose semantic `PartialError` remains deliberately unassessed;
- structural Basic-table to Analytics-summary-table to analytics-rule lineage;
- a closed literal vendor filter with current predicate-qualified freshness evidence;
- a successful native summary run after the current ARM definition became visible, plus an exact
  20-minute Basic-source to Analytics-output bin and count match;
- rule-aware zero-row table permission probes;
- Scheduled event-time freshness, NRT ingestion-time freshness, and paired
  `TimeGenerated`/`ingestion_time()` lag samples;
- explicit incomplete evidence when Scheduled and NRT rules share one source;
- missing, stale, bounded-empty, Basic-plan, and Auxiliary-plan table cases; and
- the exact empty installed-package and no-positive-template-link provenance path.

This is the scope of the recorded 2026-08-22 live pass. The certificate-backed scanner also passed
separate exact `403` checks for alert-rule DELETE, table DELETE, and shared-key POST. The native ASIM
case intentionally remains unassessed on `PartialError`. The empty Content Hub inventory proves the
no-link path only; it does not prove a positive installed-package association.

Separate manual lab checks used a restricted identity that could query one table but not another.
The permitted scan stayed partial instead of treating the denied table as missing.
The same lab also exercised candidate gates for Scheduled JSON, NRT JSON, and Azure-Sentinel YAML,
covering healthy, missing, and deliberately unassessed inputs without installing a rule. Those
one-off checks are not executed by `TestSentinelReadOnlyLab`. Basic-table Scheduled and NRT rules
were also accepted while disabled but rejected when enabling them because their queries could not
execute; the temporary rules were removed without creating an incident.

Run the same read-only conformance test with your own pre-seeded disposable workspace. The test
requires a certificate-backed scanner identity and deliberately rejects Azure CLI credentials:

```sh
unset AZURE_CLIENT_SECRET
AZURE_TOKEN_CREDENTIALS=EnvironmentCredential \
AZURE_TENANT_ID=<tenant-id> \
AZURE_CLIENT_ID=<scanner-app-client-id> \
AZURE_CLIENT_CERTIFICATE_PATH=/restricted/path/scanner.pem \
DEADAIR_SENTINEL_SCANNER_CLIENT_ID=<same-scanner-app-client-id> \
DEADAIR_IT_SENTINEL=1 \
DEADAIR_AZURE_SUBSCRIPTION_ID=<subscription-id> \
DEADAIR_AZURE_RESOURCE_GROUP=<resource-group> \
DEADAIR_SENTINEL_WORKSPACE=<workspace-resource-name> \
DEADAIR_SENTINEL_REMOTE_WORKSPACE=<remote-workspace-resource-name> \
go test -tags=integration ./integration -run '^TestSentinelReadOnlyLab$' -v
```

See [integration/README.md](../integration/README.md) for the scanner identity contract and required
fixture names. Authentication uses the `EnvironmentCredential` path in `DefaultAzureCredential`;
no tenant, subscription, workspace ID, or credential is embedded in the test.

## Current limits

### Microsoft Sentinel

- Sentinel live conformance is manual. A successful run proves the tested workspace and identity,
  not every Sentinel cloud, region, RBAC layout, or KQL construct.
- The Sentinel GitHub Action reuses a caller-established Azure CLI login through
  `DefaultAzureCredential`. Its wrapper and failure paths are locally tested, but a GitHub-hosted
  OIDC job has not yet proved the complete login, ARM, Logs query, artifact, and cleanup path.
- The Sentinel CLI currently targets Azure public cloud endpoints.
- Sentinel assesses direct local Analytics tables, saved workspace functions with closed scalar
  arguments, literal watchlists, metadata-backed ASIM functions with complete evidence, native ASIM
  calls with positive table and permission evidence, and configured literal `workspace()` tables.
  Tabular or runtime parameters, dynamic table/watchlist/workspace selection, external data,
  `app()`, `resource()`, ADX/cluster, and ARG remain unassessed. A native ASIM `PartialError` is
  unassessed.
- Filtered source activity was exercised against a current row in the live lab. It requires one direct local Analytics table
  followed by a closed, parser-supported literal filter. Escaped and verbatim literals fail closed
  because their exact KQL value cannot be reconstructed safely. The bounded result is
  informational and does not replace table-wide health or create a finding. The per-scan query cap
  is 20.
- Summary-rule lineage remains structural ARM metadata. A separate path reads the
  latest completed `LASummaryLogs` run in a bounded seven-day window for relevant active summary
  rules, capped at 50 rules per scan. Fixtures reject missing or malformed ARM modification times,
  runs that predate the current ARM definition, inconsistent native timestamps, invalid
  provisioning, and invalid schedules. A successful run
  becomes incomplete once it exceeds its cadence and delay plus the documented eight-hour retry
  allowance. Native failed runs stay informational. The live lab proved structural lineage, a
  successful bounded runtime record, and the matching source/output bin under the scanner identity.
  Azure advanced `LASummaryLogs.RuleLastModifiedTime` between bins while the ARM definition stayed
  unchanged, so deadair does not present that field as an exact revision ID. It requires the run to
  start after the ARM modification time and rejects native timestamps that are too old or later
  than the run.
  `binDelay` is measured in minutes, matching Azure Monitor's summary-rule scheduling model and
  the Sentinel portal.
- Native-template and Content Hub provenance uses exact IDs and versions and is informational.
  A positive installed-package association has not been tested in a live lab.
- The configured cross-workspace lab uses two workspaces in one subscription. Cross-tenant Azure
  Lighthouse behavior has not been proven. Same-subscription source evidence remains conclusive,
  but scanner access alone cannot prove the creator credential still works across subscriptions.
  A fixture-tested path accepts only an exact successful `SentinelHealth` event after the latest
  rule change and within the expected run cadence plus scheduling delay for an eligible installed
  rule that references another subscription. Candidate, absent, old,
  ambiguous, mismatched, and non-successful evidence remains unassessed. deadair does not identify
  tenant boundaries separately, so Azure Lighthouse and other cross-tenant topologies remain
  unidentified and have not been live-tested. The corroboration path itself has not been tested
  live.
- Cross-workspace fixture tests require an exact GA `onboardingStates/default` resource before any
  remote table or Logs probe. Missing, denied, malformed, or mismatched onboarding evidence is
  unavailable. Microsoft's hard limit is 20 workspaces per analytics-rule query; the fixtures pin
  deadair's conservative choice to count the home workspace, so a verified rule with more than 19
  distinct remotes is incompatible. Microsoft recommends no more than five total for performance.
  Azure Monitor separately warns at five workspace regions and blocks a scope spanning 20 or more;
  fixtures require every workspace location, normalize distinct regions, leave missing location
  unavailable, and make 20 or more regions incompatible after any alias proof. deadair has no
  separate five-region finding. Exact onboarding and the two-workspace same-subscription path were
  tested live; high workspace-count and region-count thresholds remain fixture-tested.
- Basic and Auxiliary tables are reported as incompatible. Required-field and unused-telemetry
  findings are unavailable because Sentinel does not provide authoritative rule field metadata or
  a cheap exact source document and storage inventory for this scan.

### All backends

- The version matrix does not cover every hosted service, SIEM topology, or parser convention.
- Fleet behavior is lab-tested, but production scan time and API limits depend on the number and
  size of the connected tenants.
- Low-volume and cadence checks need enough local scan history to establish a useful baseline.
- Redaction hides rule, source, dependency, lineage, provenance, workspace, watchlist, template, and
  package identifiers but does not remove sensitive counts, versions, timing, severity, lag, or
  coverage information. Dependency probe expressions are not serialized.
- Results are limited to the rules, sources, fields, and metadata visible to the scan credential.
  A known-good rule and source pair should be checked after changing credentials or scope.

## Verify a deployment

Create the documented read-only credential, then run:

```sh
deadair check
deadair scan --redact --json --json-out deadair-redacted.json --html-out deadair-report.html
```

When schema visibility and persistent local state are approved:

```sh
deadair scan \
  --redact \
  --schema \
  --state-file deadair-state.json \
  --json \
  --json-out deadair-redacted.json \
  --html-out deadair-report.html
```

Start with one enabled rule whose expected source you know. Check its declared input, resolution,
source state, and available runtime evidence. If that rule-source pair is wrong, fix credential
scope, namespace selection, or source visibility before relying on the rest of the report.

The exporter binds to `127.0.0.1:9317` by default. Put it behind authenticated scraping before
exposing it to shared infrastructure. Review redacted output before sharing it; do not put
unredacted rule, source, field, tenant, workspace, watchlist, parser, summary-rule, template,
package, or customer names in a public issue.
