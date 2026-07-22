# Validation and dogfooding

This page explains what deadair can claim today, what still needs field proof, and how to run a
useful dogfood test without sharing sensitive SOC data. For report terminology and finding-level
triage, start with [Read the findings](usage.md#read-the-findings).

## What is proven today

The trusted integration matrix targets Elastic Security 8.19.19 and 9.4.4, plus OpenSearch
Security Analytics 2.19.6 and 3.7.0. See the [support policy](support-policy.md) for how exact tested
versions relate to current/previous-major support.

The public test and lab coverage proves these paths:

| Area | Evidence |
|---|---|
| core graph logic | unit tests and race tests in CI |
| credential-free evaluation | deterministic embedded `deadair demo` fixture through terminal, JSON, and HTML output |
| Elastic backend | live Elastic integration test with the documented read-only role |
| OpenSearch backend | live OpenSearch integration test with the documented read-only role |
| native input resolution | alias, data-stream, exclusion, empty, and unavailable outcomes in backend tests and the live matrix |
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
| 0 - demo | `deadair demo` | inspect every core finding without credentials, Docker, or a SIEM |
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

Do not validate summary counts alone. Pick individual findings and compare the report evidence with
what an operator can verify in the SIEM.

| Finding | Evidence to compare | Useful confirmation |
|---|---|---|
| no matching source | rule name, declared selector, native `empty` resolution evidence | confirm the backend understood the selector; check role scope before calling it absent |
| unassessed input | `unsupported`, `unavailable`, `remote`, or `ambiguous` resolution evidence | fix permissions/API access, scan the remote deployment, or report an unsupported rule type; do not classify it as dead |
| all matching sources stale or empty | matched source names, status, document count, last-event age | compare with the source's expected cadence and upstream pipeline state |
| missing fields | declared fields, `field_caps` result, matched sources | compare mappings after a known parser, package, or pipeline change |
| lag blind window | affected source, measured lag, rule interval and lookback | compare with observed delivery delay and the rule's timestamp behavior |
| unused telemetry | source name, document count, known resolved enabled and disabled consumers, plus `unused_telemetry_assessment=complete` | confirm whether collection is intentional and whether relevant rules are disabled or missing |
| downtime suppression | source and matched downtime window | confirm the window matches the real operating schedule and timezone |
| low volume | current rate, baseline, sample count, warmup and hysteresis state | compare with known business cycles after enough history exists |
| fleet failure | instance error plus successful instance reports | confirm one bad credential or unreachable tenant does not hide the rest of the fleet |

Before reviewing failures, verify one known-good enabled rule whose pattern and live source you know.
If deadair cannot connect that pair, fix permissions, space selection, or source visibility before
judging the rest of the report.

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
- one or two examples with finding class, evidence checked, expected state, and whether deadair was correct

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
