# Usage guide

Task-oriented walkthrough. For the data model see [architecture.md](architecture.md); for
credential setup run `deadair setup` or see [credentials/](credentials/).

## First scan

```sh
deadair setup            # prints role JSON, key command, env exports
deadair check            # verifies each privilege; failures name the missing piece
deadair scan             # terminal summary
deadair scan --json      # full report; every section below is in here
```

`check` reports required capabilities (rule inventory, source stats) and optional ones
(retention for truncated-lookback checks, field mappings for `--schema`) separately, per
instance. It exits `0` when everything a scan needs is in place.

Exit codes: `0` healthy, `1` findings, `2` scan failed. TLS with a private CA: `--ca-cert
ca.pem`. Rules in a non-default Kibana space: `--kibana-space soc`.

## Reading the report

Each finding class means something different and has a different fix:

| Finding | Meaning | Usual cause and fix |
|---|---|---|
| dead: `disconnected` | index patterns match no existing index or data stream | pattern typo, the source was never onboarded, or the rule came from a rule repo written for a different environment. Fix the pattern, onboard the source, or disable the rule and record why |
| dead: `starved` | every matched source is stale or empty | whatever feeds those sources stopped: agent down, connector dead, Logstash/ingest pipeline dropping output. The listed sources tell you where to start |
| source `stale` | no events within `--max-stale` (default 30m) | either a real outage or a source with a slow natural cadence. For the latter, raise `--max-stale` or declare a downtime window — do not exclude it, exclusions hide the source entirely |
| source `empty` | index exists, zero docs | onboarding that never finished, or a template matched and created the index but nothing ever shipped |
| source `unknown` | freshness can't be determined | no `@timestamp` mapping, or the deadair role can't read the index. Unknown never pages — but a mostly-unknown estate means the role or mappings need fixing |
| impaired: `truncated-lookback` | rule's `from` reaches further back than ILM/lifecycle keeps data | the rule queries 90d, retention deletes at 30d: every run silently covers a third of its intended window. Shorten the lookback or extend retention |
| impaired: `missing-fields` | `required_fields` absent from every matched source's field_caps | integration or agent upgrade changed the ECS mapping, or a custom pipeline stopped enriching. Fix the mapping or update the rule |
| impaired: `lag-blind-window` | measured ingest lag exceeds `from` minus `interval` | batch-delivered sources (cloud audit logs are the usual case): events land after the window that should have caught them was already queried. Widen `from` past interval + lag |
| `unmapped` | inputs not derivable from rule metadata (ML jobs, some ESQL) | informational — deadair won't guess, and never calls these dead |
| `remote_rules` | CCS patterns (`cluster:index-*`) | can't be verified from this cluster. Add the remote as its own fleet instance |
| unused telemetry | ingested, but no enabled rule reads it | either coverage you should build, a disabled rule worth enabling (the report counts those), or ingest spend to reclaim |

`--include`/`--exclude` scope what the report lists; they never change verdicts.

## Gating changes (CI)

```sh
deadair scan --rule candidate.json    # exit 1 if the rule can't see data here
deadair diff last-week.json today.json  # exit 1 on regressions only
```

`--rule` takes the rule JSON or ndjson export straight from your detection-as-code repo and
answers whether that rule would have data in this environment — before it merges. Its exit code
ignores pre-existing findings, so an unrelated backlog never blocks a PR. `diff` fails only on
regressions (newly dead, impaired, or degraded), which makes it the right scheduled gate while
a backlog is still being worked down.

## Stateful checks

```sh
deadair scan --state-file deadair-state.json --schema
```

`--state-file` enables volume baselines (same weekday/hour history; findings only after
`--volume-warmup` 24h and `--volume-hysteresis` 2 consecutive low scans) and ingest-lag
measurement. `--schema` adds field_caps drift tracking. Declare expected outages in a
`--downtime-file` so maintenance neither pages nor poisons baselines:

```json
{"windows": [{"name": "patch window", "sources": ["winlogbeat-*"],
  "days": ["sat"], "start": "22:00", "end": "02:00", "timezone": "Europe/London"}]}
```

After a week of history, `deadair tune --state-file deadair-state.json` suggests threshold
settings from your actual variance.

## Fleets

```sh
deadair check --fleet fleet.json
deadair scan --fleet fleet.json
deadair serve --fleet fleet.json
```

See the README's fleet section for the config format. Instances scan sequentially; per-instance
state files are automatic; one unreachable tenant exits `2` without hiding the rest. Rollups
("dead in 3 of 12") key on rule name across tenants.

Use `check --fleet` after onboarding or rotating tenant credentials. For MSSP operating details
around secret layout, redaction, Alertmanager routing, retention, and fleet sizing, see
[mssp.md](mssp.md).

## Continuous monitoring

```sh
deadair serve --interval 5m --state-file deadair-state.json
```

Prometheus metrics on `127.0.0.1:9317`; import the dashboard and alert rules from
[contrib/](../contrib/). Scrapes read a cached snapshot — scrape load never reaches the SIEM.

## Sharing reports

`--redact` (scan, serve, tune) replaces every source, rule, pattern, field, and tenant name with
a stable digest. Digests are deterministic, so redacted reports still diff and correlate across
runs. Unredacted reports map your blind spots: treat them like credentials.
