# Usage guide

This guide covers the day-to-day workflows: first scan, triage, CI gates, stateful checks,
fleets, exporter mode, and report sharing. For credential setup, run `deadair setup` or use the
backend guides under [credentials/](credentials/).

## First scan

Start with a manual scan. Do not wire alerts before a detection engineer has read the first
report.

```sh
deadair setup
deadair check
deadair scan
```

`setup` prints the least-privilege role and credential commands for the selected backend.
`check` verifies the connection, required privileges, and optional capabilities such as schema
visibility. `scan` prints the terminal report.

Common output formats:

```sh
deadair scan --json
deadair scan --out report.json
deadair scan --out report.json --html-out report.html
```

Exit codes:

| Code | Meaning |
|---:|---|
| `0` | scan completed and no findings were present |
| `1` | scan completed and found dead, impaired, degraded, or unused coverage |
| `2` | scan failed or the fleet scan was incomplete |

Useful connection flags:

| Flag | Use |
|---|---|
| `--ca-cert ca.pem` | trust a private CA |
| `--insecure-skip-verify` | lab use only; skip TLS verification |
| `--kibana-space soc` | read Elastic rules from a non-default Kibana space |
| `--timeout 90s` | raise the per-scan timeout |

## Read the findings

Start from rule findings, then pivot to source findings.

| Finding | Meaning | First triage step |
|---|---|---|
| dead rule: `disconnected` | enabled rule patterns match no index or data stream | check for pattern typos, missing integrations, disabled data streams, or rules copied from another environment |
| dead rule: `starved` | every matched source is stale or empty | inspect the listed sources; the detection is blind because the data path stopped |
| impaired rule: `missing-fields` | declared `required_fields` are absent from every matched source's `field_caps` | check parser or integration changes; update mappings or fix the rule fields |
| impaired rule: `lag-blind-window` | ingest lag on a matched source is wider than the rule's lookback margin | widen `from`, shorten delivery lag, or treat the source as batch-delivered |
| source `stale` | no recent events within `--max-stale` | check agent, connector, forwarder, ingest pipeline, and upstream source health |
| source `empty` | source exists but has zero docs | finish onboarding or remove the unused template/source |
| source `unknown` | deadair cannot measure freshness | fix `@timestamp` mappings or read privileges; unknown does not page by itself |
| unused telemetry | source has data but no enabled rule reads it | write coverage, enable relevant rules, or stop ingesting the source |
| `remote_rules` | rule uses cross-cluster patterns such as `cluster:index-*` | scan the remote cluster as its own fleet instance |
| `unmapped` | deadair cannot derive inputs from metadata, such as some ML rules | informational; deadair does not guess |

`--include` and `--exclude` only change what the report lists. They do not change the verdicts.

## Gate detection changes

Use `scan --rule` in detection-as-code pull requests:

```sh
deadair scan --rule candidate-rule.json
```

The candidate file can be a single JSON rule object or an ndjson export. deadair evaluates that
rule against the live environment without installing it. The exit code reflects only the
candidate rule, so an existing backlog does not block unrelated pull requests.

Use `diff` for scheduled checks while the backlog is still being worked down:

```sh
deadair scan --json --out today.json
deadair diff yesterday.json today.json
```

`diff` exits `1` only for regressions: newly dead rules, newly impaired rules, or newly degraded
sources. Recoveries are shown but do not fail the command.

## Add history-based checks

Stateful checks need a local state file:

```sh
deadair scan --state-file deadair-state.json
```

With a state file, deadair records source history for:

- volume baselines by weekday and hour
- warmup before low-volume findings can fire
- hysteresis, so one low scan does not page by itself
- ingest-lag measurements used by `lag-blind-window`

Defaults are conservative:

| Flag | Default | Meaning |
|---|---:|---|
| `--volume-warmup` | `24h` | minimum observation time before volume findings can fire |
| `--volume-hysteresis` | `2` | consecutive low scans required |
| `--volume-min-samples` | `4` | same weekday/hour samples required before evaluation |
| `--volume-z-threshold` | `3` | low-volume z-score threshold |

After you have real history, ask deadair for tuning suggestions:

```sh
deadair tune --state-file deadair-state.json
```

## Track schema drift

Schema drift uses `field_caps` snapshots over time:

```sh
deadair scan --state-file deadair-state.json --schema
```

The first scan records a snapshot. Later scans report fields added, removed, or changed in type.
This is useful after agent upgrades, package upgrades, parser changes, and pipeline releases.

Schema drift is source-level evidence. It does not automatically prove a rule is broken. Rule
impairment is reported when required fields are missing from every matched source with fetched
schema data.

## Declare maintenance windows

Use downtime windows for expected source quiet periods. This keeps the source visible, suppresses
the finding during the window, and prevents the quiet period from poisoning volume baselines.

```json
{"windows": [
  {
    "name": "weekly patch window",
    "sources": ["winlogbeat-*"],
    "days": ["sat"],
    "start": "22:00",
    "end": "02:00",
    "timezone": "Europe/London"
  }
]}
```

Run with:

```sh
deadair scan --state-file deadair-state.json --downtime-file downtime.json
```

Prefer downtime windows over exclusions. Exclusions hide sources from the listing, which can hide
real coverage gaps.

## Scan fleets

Use `--fleet` for multiple SIEM instances:

```sh
deadair check --fleet fleet.json
deadair scan --fleet fleet.json
deadair serve --fleet fleet.json
```

Fleet scans are sequential. One failed tenant is recorded as an instance error and the command
exits `2`; successful tenants still appear in the same report. With `--state-file`, deadair writes
one state file per instance.

Use `check --fleet` after onboarding a tenant or rotating a tenant secret.

For MSSP operating guidance, including secret layout, redaction, Alertmanager routing, retention,
and fleet sizing, see [mssp.md](mssp.md).

## Run the exporter

```sh
deadair serve --interval 5m --state-file deadair-state.json
```

Metrics are exposed on `127.0.0.1:9317` by default. Prometheus scrapes the cached last scan; a
scrape does not trigger a SIEM API call. Grafana and Alertmanager examples are in
[contrib/](../contrib/).

For fleets, route failed scans by `deadair_instance_up`. Dead detections should usually go to the
detection engineering queue. Stale, empty, or low-volume sources usually belong to telemetry
pipeline owners.

## Share reports safely

Use `--redact` for anything leaving the restricted SOC workspace:

```sh
deadair scan --json --redact --out redacted-report.json
deadair serve --redact
deadair tune --state-file deadair-state.json --redact
```

Redaction replaces tenant, source, rule, pattern, and field names with stable digests. Redacted
reports still diff across runs.

Unredacted reports map blind detections and unused telemetry. Treat them like sensitive SOC
artifacts.
