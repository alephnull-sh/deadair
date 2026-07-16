# Architecture

deadair is a read-only client. It does not install an agent, create SIEM objects, write documents,
or run a service inside the monitored SIEM.

Each scan reads:

1. detection rule metadata
2. source inventory and freshness
3. optional source schema and history data

Then it builds a dependency graph:

```text
enabled rule -> index pattern -> index or data stream -> health evidence
```

The graph answers two questions at the same time:

- If this source dies, which enabled detections go blind?
- If this source is being ingested, which enabled detections use it?

## Data model

deadair normalizes every backend into a small set of objects.

| Object | Meaning |
|---|---|
| rule | SIEM detection metadata: id, name, enabled state, query type, index patterns, lookback, interval, required fields |
| source | index or data stream with doc count, last-event time, ingest-lag evidence, and optional schema |
| edge | rule-to-source match created from the rule's index patterns |
| report | rule findings, source findings, unused telemetry, unmapped rules, remote rules, and summary counts |
| fleet report | per-instance reports plus cross-tenant rollups and instance errors |

The report format is additive once released. Existing JSON field names should not be renamed or
removed.

## Rule verdicts

| Verdict | Meaning |
|---|---|
| `live` | at least one matched source is healthy or unknown |
| `disconnected` | the rule's patterns match no source; terminal and HTML reports show `no matching source` |
| `starved` | every matched source is stale or empty; terminal and HTML reports spell this out |
| `missing-fields` | required fields are absent from every matched source with fetched schema |
| `lag-blind-window` | a matched source's ingest lag exceeds the rule's lookback-minus-interval margin |
| `unmapped` | deadair cannot derive data inputs from the metadata, such as some ML rules |

Impaired findings require positive evidence. If schema cannot be fetched, deadair does not invent
a missing-field finding. If lag cannot be measured, it does not invent a lag finding. Unknown
source freshness does not make a rule dead.

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
| data stream stats | `GET /_data_stream/_stats` | one call |
| index inventory | `GET /_cat/indices` | one call |
| freshness fallback | size-0 `max(@timestamp)` aggregation | per undated source, bounded concurrency |
| schema snapshots | `GET /<index>/_field_caps` | opt-in, per source, bounded concurrency |
| ingest lag | size-0 `max(@timestamp)` and `max(event.ingested)` aggregation | with `--state-file`, per source, bounded concurrency |

OpenSearch uses the Security Analytics detector search API for rule metadata and the same style
of source stats, freshness, and field-capability reads.

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

Exit codes are part of the compatibility contract: `0` healthy, `1` findings, `2` error.

## State

State is a local JSON file written `0600` on POSIX systems. It stores:

- source volume buckets by weekday and hour
- ingest-lag history
- last successful schema snapshot per source
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

This is the main reason future backend work matters: the graph becomes more useful when a team can
ask whether the same detection is blind across many SIEM instances.

## Backend support

Support tiers:

| Tier | Meaning |
|---|---|
| supported | backend code, credential docs, live integration proof, rejected-write proof, and stable report compatibility |
| preview | real backend proof exists, but field dogfooding is still pending |
| experimental | parser or adapter work only; no support claim |

Current backends:

| Backend | Status |
|---|---|
| Elastic Security 8.x | supported |
| OpenSearch Security Analytics 2.x | supported |

No preview or experimental backend ships today. Microsoft Sentinel is the first planned preview
target. Splunk is out of scope.

## Security properties

- The backend interface has no write methods.
- Integration tests provision the documented least-privilege roles and assert representative
  writes are rejected.
- Reports, HTML output, and state files are written `0600` on POSIX systems.
- `--redact` replaces tenant, source, rule, pattern, and field names with stable digests.
- The exporter binds `127.0.0.1` by default.
- deadair has no phone-home behavior and no usage telemetry.

## Requirements

The client is a static binary for macOS, Linux, and Windows on amd64 and arm64. It needs network
reach to the SIEM HTTP(S) APIs and nothing else.

On Windows, POSIX file modes do not apply. Protect report and state directories with ACLs.

CI tests the supported backend paths against pinned Elastic 8.17.x and OpenSearch 2.19.x
containers. The MSSP lab also exercises mixed-backend fleet behavior in Docker.

## Non-goals

deadair does not provide:

- rule authoring
- rule tuning advice
- event replay or inline event evaluation
- ingest pipeline management
- built-in dashboards or alert delivery
- a UI
- a Splunk backend
