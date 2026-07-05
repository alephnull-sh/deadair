# Architecture

deadair runs outside the SIEM and reads two things over its APIs: the detection rule inventory
and stats about the indices those rules query. It joins them into a graph and pushes source
health through it.

```
rules (SIEM rule metadata) ──index patterns──▶ sources (data streams / indices)
                                               └─ health: freshness, volume, schema
```

The join works in both directions: a degraded source exposes every detection depending on it
(the blast radius of a dead connector), and a source with no enabled consumers is ingest cost
with no detection value. The failure modes it catches are the usual suspects — agent death,
connector breakage, parser/mapping drift after an integration upgrade, retention clipping a
long lookback, and batch-delivery lag.

## Rule verdicts

| Verdict | Meaning |
|---|---|
| live | at least one matched source is healthy or unknown |
| `disconnected` | index patterns match no existing source |
| `starved` | every matched source is stale or empty |
| impaired: `truncated-lookback` | rule queries further back than every matched source's configured retention (ILM delete phase or data-stream lifecycle) |
| impaired: `missing-fields` | rule-declared `required_fields` that no matched source's field_caps provides (with `--schema`) |
| impaired: `lag-blind-window` | measured ingest lag (`event.ingested` vs `@timestamp`) exceeds the rule's lookback-minus-interval margin (with `--state-file`) |
| unmapped | inputs not derivable from metadata (e.g. ML rules); listed, never called dead |

Impaired means the rule still fires but with reduced vision. Each impairment check requires
positive evidence: unknown retention, unfetched schemas, or unmeasurable lag suppress the
finding.

Verdicts err toward silence. Unknown freshness never marks a detection dead; volume checks
require warmup, minimum samples, and consecutive confirmations; declared downtime windows
suppress findings. A monitor that produces false positives gets disabled, so these checks are
built to miss a real problem rather than report one that isn't there.

## SIEM API usage

Scans must not become load on the monitored cluster:

| Need | Elastic API | Cost |
|---|---|---|
| rule inventory | Kibana `GET /api/detection_engine/rules/_find` | paginated metadata read |
| data-stream freshness/size | `GET /_data_stream/_stats` | one call |
| index inventory | `GET /_cat/indices` | one call |
| freshness fallback | size-0 `max(@timestamp)` aggregation | per undated source, bounded concurrency |
| retention | `GET /_data_stream`, `GET /*/_ilm/explain`, `GET /_ilm/policy/<name>` | two or three metadata reads per scan |
| schema snapshots (opt-in) | `GET /<index>/_field_caps` | per source, bounded concurrency |
| ingest lag (with `--state-file`) | size-0 `max(@timestamp)` + `max(event.ingested)` aggregation | per non-empty source, bounded concurrency |

OpenSearch uses the Security Analytics detector API plus the same stats endpoints. A failure on
one source degrades that source to `unknown`; it never fails the scan.

## Modes

1. `check` — connectivity and privilege verification; no report.
2. `scan` — one shot; terminal, JSON, or HTML output; exit codes `0`/`1`/`2` for CI gates.
3. `scan --rule` — evaluates a candidate rule file against the environment without installing
   it; the exit code reflects only the rule under test.
4. `serve` — Prometheus exporter; periodic scans, cached snapshots.
5. `diff` — compares two saved reports; exit `1` on regressions (newly dead, impaired, or
   degraded).
6. `tune` — summarizes accumulated state to suggest baseline settings.

State (volume history, schema snapshots) is a local JSON file, `0600`, pruned after 30 days of
source inactivity.

## Fleet model

The instance (tenant / deployment) is a first-class dimension, not a wrapper. Each report
carries its instance name; fleet scans emit per-instance reports plus rollups keyed by rule
*name* (rule IDs differ per tenant), answering "dead in 3 of 12 tenants". Exporter metrics all
carry an `instance` label. Per-instance state files keep tenants' baselines apart. Instance
names are treated as sensitive (MSSP client identities): `--redact` digests them.

Two backends (Elastic, OpenSearch) are deliberate: one backend cannot demonstrate that the
graph spans a fleet. The backend interface is the extension point; the graph schema is
backend-neutral. Sentinel note for single-tenant users: Microsoft's native SOC Optimization
covers that case — the value of a future Sentinel backend here is the cross-fleet view.

Backend support is tiered. `supported` means code, credential docs, live integration proof, and
rejected-write proof exist. `preview` means a real backend proof exists but field dogfooding is
still pending. `experimental` means parser/replay or early adapter work with no support claim.
Elastic and OpenSearch are `supported`; no preview or experimental backend ships today.

## Security properties

- The backend interface has no write methods. CI provisions the documented least-privilege role
  against live Elastic and OpenSearch containers and asserts every write attempt is rejected.
- Reports, HTML output, and state files are created `0600`.
- `--redact` replaces all source/rule/pattern names with stable digests; leak tests assert no
  original names survive.
- Exporter binds `127.0.0.1` by default. No outbound connections except the configured SIEM.

## Non-goals

Rule authoring or tuning advice, ingest pipelines, built-in alerting or dashboards, UI, Splunk.

## Requirements and compatibility

The client is a static binary for macOS, Linux, and Windows (amd64 and arm64). It needs
network reach to the SIEM's HTTP(S) API and nothing else — no agents, no local services, no
runtime dependencies, single-digit-MB memory. Release binaries and checksums are on the
releases page.

On Windows, POSIX permission bits do not apply, so the `0600` hardening on report and state
files is not enforced there; protect those paths with directory ACLs. ANSI color is enabled
only under capable hosts (Windows Terminal, ConEmu, or a set `TERM`).

Server side: CI-tested against pinned Elastic 8.17.x and OpenSearch 2.19.x. Report JSON is
additive-only once released; exit codes are stable.
