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

A finding states what deadair observed. It does not guess the root cause. Start with the rule,
inspect the evidence behind its verdict, then decide whether the condition is expected coverage
scope, a regression, or incomplete visibility for the deadair credential.

Terms used in reports:

| Term | Meaning |
|---|---|
| rule pattern | index or data-stream expression configured on the detection, such as `winlogbeat-*` |
| source | concrete index or data stream visible to deadair, such as `winlogbeat-2026.07` |
| matched source | concrete source matched by at least one rule pattern |
| dead detection | enabled rule with no matched source, or with only stale/empty matched sources |
| impaired detection | enabled rule with live input but positive evidence of reduced field or timing coverage |

The source inventory is credential-scoped. If the read role cannot see an expected index, deadair
cannot distinguish that index from one that does not exist. Check role scope before treating a
first-run no-match finding as a production outage.

### No matching source

Human reports say `no matching source`; JSON uses the stable reason code `disconnected`. It means
none of the enabled rule's configured patterns resolved to a concrete index or data stream in the
inventory visible to deadair.

It does not mean the SIEM, agent, or network connection is disconnected. A connection or
authentication failure makes the scan or fleet instance fail and returns exit `2`; it is not a rule
verdict.

A finding from the checked-in lab report:

| Evidence | Value |
|---|---|
| Rule | `Persistence via WMI Standard Registry Provider` |
| Configured patterns | `logs-endpoint.events.registry-*`, `endgame-*` |
| Matched sources | none |
| Impact | the rule currently has no source to query |
| Lab explanation | the lab did not seed Endpoint registry or Endgame telemetry |

That is an expected coverage gap in the lab. A production regression looks similar but has a change
behind it: a Windows rule still queries `winlogbeat-*`, telemetry moves to
`logs-windows.sysmon_operational-*`, and the old Winlogbeat indices age out. The rule remains enabled,
but its configured input no longer names the source carrying the events.

Common explanations:

| Situation | What to verify |
|---|---|
| integration not onboarded | whether the rule is intentionally enabled before its data source is available |
| source renamed or migrated | current data-stream names after an agent, package, or pipeline change |
| rule copied from another tenant | whether that tenant has the same integrations and naming conventions |
| pattern typo or stale override | the rule's configured index patterns or data view |
| credential cannot see the source | index permissions and Kibana space for the deadair credential |

First response:

1. Read `dead_detections[].patterns` in the JSON report.
2. Confirm whether any expected concrete index or data stream currently matches those patterns.
3. Confirm the deadair credential can see that source.
4. Classify the finding as expected scope, onboarding work, or regression.
5. Update the rule pattern, restore the integration, or disable the intentionally out-of-scope rule.

```sh
deadair scan --json --out report.json
jq '.dead_detections[] | select(.reason == "disconnected") | {name, patterns}' report.json
```

### All matching sources stale or empty

Human reports spell this out; JSON uses `starved`. The rule patterns resolve correctly, but every
matched source is degraded. A source is `stale` when it has documents but no recent event inside
`--max-stale`; it is `empty` when it exists with zero documents.

For example, a rule queries `logs-system.auth-*` and resolves to
`logs-system.auth-default`, but the newest event is three days old. The pattern is not the problem.
The ingest path stopped, the source is intentionally quiet, or the stale threshold does not match
its cadence.

Inspect `dead_detections[].sources`, then find those names under `sources[]` for document count,
age, status, and consumer count. Check the agent or connector, forwarder, ingest pipeline, upstream
system, expected cadence, and downtime configuration.

### Impaired detections

Impaired rules still have live input. deadair has evidence that part of their effective coverage is
reduced.

| Finding | Evidence | Example | First response |
|---|---|---|---|
| `missing-fields` | best-effort rule-declared fields are absent from every matched source mapping fetched with `field_caps` | a parser upgrade stops mapping `process.command_line` while a rule declares it as required | compare rule metadata, package version, pipeline, and mapping |
| `lag-blind-window` | measured ingest lag exceeds the rule's lookback-minus-interval margin | cloud audit events arrive 12 minutes late while a five-minute rule looks back six minutes | reduce delivery lag, widen lookback, or use the appropriate ingest timestamp |

`required_fields` is informational metadata, and `field_caps` proves mapping/searchability rather
than field population in recent events. Treat `missing-fields` as strong triage evidence, not proof
that every event is missing the value. Lag findings are also a timing model; validate them against
the source's real delivery behavior and the rule type.

### Source findings

| Finding | What deadair observed | First response |
|---|---|---|
| `stale` | source has documents but no recent event inside `--max-stale` | compare expected cadence, then check collector, connector, forwarder, and pipeline health |
| `empty` | source exists with zero documents | finish onboarding, fix routing, or remove an unused template/source |
| `unknown` | freshness could not be measured | check `@timestamp` mapping and read privileges; unknown does not make rules dead |
| `maintenance` | a downtime window currently suppresses stale/empty classification | confirm the declared window still matches the operating schedule |
| low volume | source is below its own weekday/hour baseline after warmup and hysteresis | compare known business cycles and upstream volume before paging |
| schema drift | fields were added, removed, or changed type since the prior snapshot | correlate with package, parser, and pipeline releases |
| unused telemetry | source has data but no enabled rule pattern resolves to it | confirm intentional collection, disabled rules, and planned coverage before changing ingest |

`remote_rules` contains cross-cluster patterns such as `cluster:index-*`; scan the remote cluster as
its own fleet instance. `unmapped` contains rules whose inputs cannot be derived from available
metadata, such as some ML rules. Both are informational because deadair does not guess.

`--include` and `--exclude` only change what the report lists. They do not change verdicts.

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

For fleets, route failed scans by `deadair_instance_up`. No-match findings usually go to detection
engineering or onboarding after credential scope is checked. Findings where all matched sources are
stale or empty usually belong to telemetry pipeline owners.

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
