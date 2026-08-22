# Architecture

deadair is a read-only client. It installs nothing in the SIEM and does not create SIEM objects or
write events.

Each scan reads:

1. detection rule metadata
2. source inventory and freshness
3. backend-native input resolution evidence
4. optional source schema and history data
5. optional non-telemetry dependency, lineage, and provenance metadata

Then it builds a dependency graph:

```text
enabled rule -> declared input -> native resolver -> index, data stream, or table -> health evidence
```

Backends can also attach informational branches that never become health edges by themselves:

```text
enabled rule -> non-telemetry dependency -> bounded dependency evidence
enabled rule -> exact native template or package provenance
raw table -> summary rule -> Analytics output table -> enabled rule
```

The graph answers two questions at the same time:

- If this source dies, which enabled detections go blind?
- If this source is being ingested, which enabled detections use it?

## Data model

deadair normalizes every backend into a small set of objects.

| Object | Meaning |
|---|---|
| rule | SIEM detection metadata: id, name, enabled state, query type, index patterns, lookback, interval, required fields |
| source | credential-visible index, data stream, or table with the count, freshness, ingest-lag, and schema evidence that the backend can authoritatively provide |
| input resolution | evidence that a declared selector resolved, resolved empty, or could not be safely assessed |
| edge | rule-to-source relationship created only from a successful backend-native resolution |
| dependency evidence | status of a backend prerequisite such as a literal Sentinel watchlist or native ASIM call; only concrete monitorable tables create source-health edges |
| provenance evidence | informational exact-ID relationship between a rule and a native template or content package |
| lineage evidence | informational structural relationship between a source, transform, and output table |
| report | versioned rule findings, source findings, resolution evidence, capabilities, and summary counts |
| fleet report | per-instance reports plus cross-tenant rollups and instance errors |

The source inventory and native resolver are an evidence boundary. A permission or API failure is
recorded as `unavailable`; it is not collapsed into an absent source. Least-privilege roles should
include every source pattern the operator intends to assess plus the metadata privilege required by
the backend's resolve-index API.

Reports declare `schema_version`, producer metadata, backend capabilities, and observed resolution
methods. The format is additive once released: existing JSON field names and reason codes are not
renamed or removed. Checked-in JSON Schemas describe the single-instance and fleet contracts.

## Rule verdicts

| JSON code | Human wording | Evidence retained in the report |
|---|---|---|
| `live` | no rule finding | at least one matched source is healthy or has unknown freshness |
| `disconnected` | no matching source | the native resolver understood the input and positively returned an empty result |
| `starved` | all matching sources stale or empty | degraded source names are retained with source age, document count, and status |
| `source-plan-incompatible` | source configuration is incompatible with the rule | affected source names and native resolution evidence are retained |
| `missing-fields` | missing fields | declared missing fields and matched sources are retained when schema was fetched |
| `lag-blind-window` | lag blind window | affected sources, measured lag, rule lookback, and interval are retained |
| `unsupported` | not assessed | deadair does not yet understand the rule input or query type |
| `unavailable` | not assessed | permissions, transport, or a backend API prevented resolution |
| `remote` | remote dependency | the input belongs to another deployment and was not explicitly mapped or could not be assessed; a verified mapped Sentinel workspace table can resolve normally |
| `ambiguous` | not assessed | the rule exposes competing input declarations without enough evidence to choose safely |
| `incompatible` | assessed | the input names a known source whose configuration cannot be used by the rule type |

The terminal report is intentionally concise. JSON is the diagnostic artifact: dead detections
include `patterns` and, when matched sources exist, `sources`; impaired detections include their
field or timing evidence.

Impaired findings require positive evidence. If schema cannot be fetched, deadair does not invent
a missing-field finding. If lag cannot be measured, it does not invent a lag finding. Unknown
source freshness does not make a rule dead. Likewise, only `empty` resolution evidence can support
a disconnected verdict; `unsupported`, `unavailable`, `remote`, and `ambiguous` cannot. An
`incompatible` result is assessed evidence: all-incompatible rules are dead, while mixed
resolved/incompatible rules are impaired.
Unused-telemetry findings are also withheld when an enabled local input is unsupported,
unavailable, or ambiguous, because zero consumers cannot be proved from incomplete coverage.

## Source health

| Status | Meaning |
|---|---|
| `ok` | source has data inside the stale threshold |
| `stale` | source has docs but no recent events |
| `empty` | source exists but has zero docs |
| `unknown` | freshness could not be measured |
| `maintenance` | source is currently inside a declared downtime window |

Volume baselines are stateful. They compare a source against its own weekday/hour history after
warmup, minimum samples, and consecutive low scans. This keeps low-volume alerts quiet until there
is enough local history to make the comparison meaningful.

## API usage

Scans are built around cheap metadata calls first. Per-source queries are bounded.

| Need | Elastic API | Cost |
|---|---|---|
| rule inventory | Kibana `GET /api/detection_engine/rules/_find` | paginated metadata read |
| rule input resolution | Elasticsearch `GET /_resolve/index/<expression>` | per distinct rule expression; read-only metadata |
| data stream stats | `GET /_data_stream/_stats` | one call |
| index inventory | `GET /_cat/indices` | one call |
| freshness fallback | size-0 `max(@timestamp)` aggregation | per undated source, bounded concurrency |
| declared-field check | targeted `POST /<index>/_field_caps?include_unmapped=true` | sources used by rules that declare required fields, bounded concurrency |
| schema snapshots | `GET /<index>/_field_caps` | opt-in, per source, bounded concurrency |
| ingest lag | paired `event.ingested` and `@timestamp` values from up to 500 recent events | only sources used by an applicable event-time rule, bounded concurrency |

OpenSearch uses the Security Analytics detector search API for rule metadata and the same style
of source stats, native resolve-index, freshness, and field-capability reads.

Sentinel uses ARM metadata plus bounded Logs queries:

| Need | Sentinel API | Boundary |
|---|---|---|
| rule and local source inventory | Sentinel alert-rule GETs; Log Analytics workspace and table GETs | core read path |
| function, watchlist, ASIM, and table proof | Logs metadata plus zero-row queries with permission and data-source evidence; Sentinel watchlist GETs when referenced | bounded per dependency; `PartialError` is unassessed |
| filtered source activity | bounded Logs query over one parser-proved local Analytics table and closed literal predicate | informational and separate from table-wide health; no finding or gate |
| remote Sentinel onboarding | exact GA `onboardingStates/default` resource | missing, denied, malformed, or mismatched evidence is unavailable; no table or Logs probe follows |
| configured literal `workspace()` table | remote workspace/table GETs and workspace-scoped Logs evidence | textual aliases require catalog plus original-literal Logs proof; verified GUID and canonical ARM-ID mappings do not |
| cross-workspace limits | verified workspace IDs and ARM locations | home workspace is counted; more than 20 workspaces or 20 or more regions is incompatible; missing location evidence is unavailable; Microsoft's lower performance warnings remain guidance |
| summary lineage | Log Analytics `summaryLogs` and table GETs for outputs consumed by enabled detections | ARM-only structure; `binDelay` follows Azure Monitor's minute-based schedule |
| summary-rule runtime | bounded seven-day `LASummaryLogs` latest-completed-run query for relevant active, successfully provisioned summary rules, capped at 50 rules per scan | accepts only runs observed after the current ARM definition became visible; failures stay informational, and old successes become incomplete against cadence, delay, and retry allowance; separate from lineage and gates |
| native template and Content Hub provenance | exact-ID Sentinel template/package GETs | informational; no display-name guessing or expanded package content |

Summary-lineage, summary-runtime, and provenance rights are optional scan enrichment. `check` does
not require them; permission or list failures become unavailable informational evidence rather than
a blocked scan.

For same-subscription Sentinel mappings, positive source evidence can resolve the dependency. For
cross-subscription analytics rules, Microsoft uses the creator's credentials rather than an
independent access token. Scanner-positive evidence therefore does not prove execution. Only an
exact successful `SentinelHealth` record for an eligible installed rule can corroborate its
execution identity. The record must follow the latest rule change and still be current for the
rule's cadence plus scheduling delay. Candidate, absent, old, mismatched, or non-successful evidence
remains unassessed. deadair does not separately identify tenant boundaries; this path, Azure
Lighthouse, and other cross-tenant topologies are not claimed as live-validated support.

A failed source-level read should degrade that source to `unknown`; it should not fail the whole
scan.

## Commands

| Command | Role |
|---|---|
| `setup` | print least-privilege credential setup for a backend |
| `check` | verify connectivity, required privileges, and optional capabilities |
| `scan` | produce a terminal, JSON, or HTML report |
| `scan --rule` | evaluate candidate rule JSON or ndjson without installing it |
| `diff` | compare two reports and fail on regressions |
| `serve` | run periodic scans and expose cached Prometheus metrics |
| `tune` | suggest baseline settings from accumulated state |

Exit codes are part of the compatibility contract: `0` passed the configured gate, `1` gated findings, `2` error.

## State

State is a local JSON file written `0600` on POSIX systems. It stores:

- source volume buckets by weekday and hour
- last successful schema snapshot per source
- active and recovered finding lifecycle state
- timestamps used for pruning old inactive sources

State is local by design. deadair does not create indices, tables, or hidden objects in the SIEM.

## Fleet model

A fleet is a list of SIEM instances. An instance is usually a tenant, customer, environment, or
deployment.

Fleet behavior:

- instances scan sequentially
- every metric carries an `instance` label
- state files are separated per instance
- failed instances are reported without hiding successful ones
- cross-tenant rollups key on rule name because rule IDs can differ by tenant
- `--redact` treats instance names as sensitive

## Backend test matrix

| Backend | Live validation |
|---|---|
| Elastic Security | trusted CI on 8.19.19 and 9.4.4 |
| OpenSearch Security Analytics | trusted CI on 2.19.6 and 3.7.0 |
| Microsoft Sentinel | recorded opt-in conformance in disposable UK South workspaces |

The Sentinel run is not part of scheduled CI and has narrower proof boundaries than the trusted
Elastic and OpenSearch matrix. See [validation status](validation.md) for the exact live cases and
unproved paths. Other backend versions may work but are not covered by the current matrix.

## Security properties

- The backend interface has no write methods.
- Disposable Elastic and OpenSearch integration tests provision the documented scoped read-only
  roles and assert representative writes are rejected. The Sentinel conformance lab uses its own
  workspace-scoped reader and separate write-denial probes.
- Reports, HTML output, and state files atomically replace their destination with a `0600` file on
  POSIX systems.
- `--redact` replaces tenant, source, rule, pattern, field, dependency, lineage, provenance,
  workspace, watchlist, template, and package identifiers with HMAC-SHA256 pseudonyms. Validated
  dependency probe expressions are never serialized. A caller-held key file enables controlled
  cross-run correlation.
- The exporter binds `127.0.0.1` by default.
- deadair has no phone-home behavior and no usage telemetry.

## Requirements

The client is a static binary for macOS, Linux, and Windows on amd64 and arm64. It needs network
reach to the SIEM HTTP(S) APIs and nothing else.

On Windows, POSIX file modes do not apply. Protect report and state directories with ACLs.

## Non-goals

deadair does not provide:

- rule authoring
- rule tuning advice
- event replay or inline event evaluation
- ingest pipeline management
- built-in dashboards or alert delivery
- a UI
- a Splunk backend
