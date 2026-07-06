# Validation and dogfooding

This page explains what deadair can claim today, what still needs field proof, and how to run a
useful dogfood test without sharing sensitive SOC data.

## What is proven today

Current supported backends are Elastic Security 8.x and OpenSearch Security Analytics 2.x.

The public test and lab coverage proves these paths:

| Area | Evidence |
|---|---|
| core graph logic | unit tests and race tests in CI |
| Elastic backend | live Elastic integration test with the documented read-only role |
| OpenSearch backend | live OpenSearch integration test with the documented read-only role |
| write safety | integration tests assert representative writes are rejected |
| candidate-rule checks | `scan --rule` tests, including pretty-printed JSON rules |
| fleet behavior | mixed-backend fleet integration test |
| MSSP operator path | Docker-backed five-instance MSSP lab with healthy, failed, and unreachable tenants |
| report formats | terminal, JSON, HTML, redacted JSON, Prometheus metrics |

The CI and lab coverage are useful because they run real backend APIs. They do not prove every
customer cadence, SIEM topology, parser convention, or tenant pattern.

## What still needs field proof

These claims need outside dogfood before they should be described as proven:

| Area | Current status |
|---|---|
| large real fleets | lab validated only; no production 10, 50, or 100 tenant result yet |
| real source cadence tuning | stateful baselines exist, but thresholds need real scan history |
| hosted/backend edge cases | needs more Elastic and OpenSearch environments |
| MSSP client reporting | redaction and fleet reports exist, but no real client-book run yet |
| Microsoft Sentinel | not implemented; design partner needed before preview support |
| Google SecOps and other SIEMs | not started |

The right public claim today is: Elastic Security and OpenSearch Security Analytics are supported
with live integration proof. MSSP/fleet mode is controlled-pilot ready. Broader backend coverage
and large-fleet production proof are still open.

## Dogfood levels

Start with the lowest level that your environment allows.

| Level | Run | Goal |
|---|---|---|
| 0 - review | read the README and sample reports | decide whether the model makes sense for your team |
| 1 - lab | `make mssp-lab` | verify the local operator workflow in throwaway containers |
| 2 - test SIEM | one `check` and one redacted `scan` against a test/dev SIEM | validate privileges and report shape |
| 3 - production one-shot | one read-only redacted scan against a production SIEM | compare findings to known telemetry state |
| 4 - history | scheduled scans with `--state-file` for 7-14 days | validate volume baselines, hysteresis, and lag checks |
| 5 - fleet pilot | `check --fleet`, `scan --fleet`, then `serve --fleet` | validate tenant separation, partial failures, metrics, and runtime |

Do not start with alerting. Start with a manual report, read it with detection engineering and
pipeline owners, then decide which findings are actionable.

## Safe one-shot run

Use a read-only credential from `deadair setup`, then run:

```sh
deadair check
deadair scan --redact --json --out deadair-redacted.json --html-out deadair-report.html
```

If schema visibility is approved:

```sh
deadair scan \
  --redact \
  --schema \
  --state-file deadair-state.json \
  --json \
  --out deadair-redacted.json \
  --html-out deadair-report.html
```

For a short history run:

```sh
deadair serve \
  --redact \
  --schema \
  --state-file deadair-state.json \
  --interval 30m
```

The exporter binds `127.0.0.1:9317` by default. Put it behind authenticated scraping before
exposing it to shared infrastructure.

## What to check

During review, capture whether deadair was correct about:

- rules whose patterns matched no source
- rules backed only by stale or empty sources
- missing required fields after parser or package changes
- sources where ingest lag exceeds the rule lookback margin
- sources with data but no enabled detection reading them
- sources suppressed by downtime windows
- source volume findings after baseline warmup
- scan duration and API load
- failed tenant behavior in fleet mode

False positives are useful. False negatives are more useful. If deadair misses a real coverage
gap, open an issue with the smallest redacted example you can share.

## What to share publicly

Use `--redact` before sharing anything outside the restricted SOC workspace.

Useful public details:

- deadair version
- backend and backend version
- command shape, with secrets removed
- number of enabled rules
- number of sources
- scan duration
- whether `--schema` and `--state-file` were enabled
- whether the findings matched operator expectations
- redacted report excerpts
- one or two examples of findings that were correct or wrong

Do not share unredacted rule names, source names, tenant names, index patterns, customer names, or
blind spots.

## Reporting a dogfood result

Use the dogfood report issue template:

```text
https://github.com/Big-Comfy/deadair/issues/new?template=dogfood_report.md
```

If the result contains sensitive details, keep the issue high level and say what kind of private
evidence exists. Do not paste unredacted SOC artifacts into a public issue.

## Sentinel design partners

Microsoft Sentinel is not implemented yet. The open design-partner issue is here:

```text
https://github.com/Big-Comfy/deadair/issues/3
```

Useful Sentinel input includes real analytic-rule patterns, KQL table dependencies, custom tables,
functions, ASIM parsers, watchlists, cross-workspace queries, and read-only permissions that a SOC
or MSSP would approve.
