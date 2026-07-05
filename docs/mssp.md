# MSSP deployment guide

This guide is for running deadair across multiple client SIEMs from one operator-owned host.
Elastic Security and OpenSearch Security Analytics are supported and ready for controlled MSSP
pilots. A broad real-client dogfood run is still the remaining proof before using
"production-proven across MSSP fleets" language.

## Deployment shape

Run deadair from a hardened host that has outbound HTTPS reach to each client SIEM API. Do not
install anything on the client SIEM side. Give each tenant its own least-privilege credential and
put only references to those secrets in the fleet file.

```text
/etc/deadair/
  fleet.json                 # no inline secrets; still treat as sensitive
  secrets/
    acme-api-key             # 0600, Elastic API key
    beta-opensearch-password # 0600, OpenSearch password

/var/lib/deadair/
  state/
    fleet-state.json.acme-prod
    fleet-state.json.beta-corp
  reports/
    latest-redacted.json
    latest-internal.json
```

Example fleet file:

```json
{"instances": [
  {
    "name": "acme-prod",
    "backend": "elastic",
    "es_url": "https://es.acme.example:9200",
    "kibana_url": "https://kibana.acme.example:5601",
    "api_key_file": "/etc/deadair/secrets/acme-api-key",
    "ca_cert": "/etc/deadair/ca/acme.pem"
  },
  {
    "name": "beta-corp",
    "backend": "opensearch",
    "opensearch_url": "https://os.beta.example:9200",
    "username": "deadair",
    "password_file": "/etc/deadair/secrets/beta-opensearch-password"
  }
]}
```

Preflight the whole fleet before the first scan:

```sh
deadair check --fleet /etc/deadair/fleet.json --timeout 90s
```

Then take a one-shot redacted report:

```sh
deadair scan \
  --fleet /etc/deadair/fleet.json \
  --state-file /var/lib/deadair/state/fleet-state.json \
  --schema \
  --redact \
  --json \
  --out /var/lib/deadair/reports/latest-redacted.json
```

For continuous monitoring:

```sh
deadair serve \
  --fleet /etc/deadair/fleet.json \
  --state-file /var/lib/deadair/state/fleet-state.json \
  --schema \
  --redact \
  --interval 30m
```

With `--fleet`, one shared `--state-file` prefix becomes one state file per instance. Keep
instance names stable; renaming a tenant starts a new baseline.

## Redaction defaults

Use `--redact` by default for client-facing reports, shared Prometheus, demos, support tickets,
and anything that leaves the SOC. Redaction covers tenant names, source names, rules, patterns,
and fields with stable digests, so diffs and trends still work.

Keep unredacted reports only for restricted internal triage. They map which detections are blind
and which telemetry has no consumers.

## Alert routing

The exporter emits both a fleet-wide health metric and per-instance metrics. In shared MSSP
monitoring, group and route by `instance`; with `serve --redact`, that value is a stable digest.

Suggested ownership:

| Signal | Route |
|---|---|
| `deadair_up == 0` | monitoring platform owner |
| `deadair_instance_up == 0` | tenant onboarding / credential owner |
| dead or impaired detections | detection engineering queue |
| stale, empty, or low-volume sources | telemetry pipeline owner |
| schema drift | content engineering or parser owner |

Alertmanager sketch:

```yaml
route:
  group_by: ["alertname", "instance"]
  receiver: deadair-platform
  routes:
    - matchers: ['alertname=~"DeadairScanFailing|DeadairInstanceScanFailing"']
      receiver: deadair-platform
    - matchers: ['alertname=~"DeadairDeadDetections|DeadairImpairedDetections"']
      receiver: detection-engineering
    - matchers: ['alertname=~"DeadairSourceStale|DeadairVolumeLow"']
      receiver: telemetry-pipelines
    - matchers: ['alertname="DeadairSchemaDrift"']
      receiver: content-engineering
```

## Retention

Reports and state files are written `0600` on POSIX systems. Treat them like credentials.

Starting policy:

| Artifact | Suggested retention | Notes |
|---|---:|---|
| unredacted one-shot reports | 14-30 days | restricted SOC storage only |
| redacted reports | 90-180 days | useful for client trend reporting |
| state files | long-lived | needed for volume baselines, hysteresis, schema drift |
| exporter metrics | match normal monitoring retention | use `serve --redact` for shared Prometheus |

Back up state files if baseline continuity matters. Losing state is safe, but it restarts warmup
and schema drift history.

## Fleet sizing

Fleet scans are sequential: one tenant is scanned at a time so deadair does not fan out load
across every client SIEM at once. The cycle time is roughly:

```text
fleet scan time ~= sum(per-tenant scan time) + network/auth overhead
```

Measure your own p95 with `time deadair scan --fleet fleet.json --json --out /tmp/deadair.json`
before wiring pages. As a starting point:

| Tenants | If p95 tenant scan is 15s | Starting interval |
|---:|---:|---:|
| 10 | about 2.5m | 15m |
| 50 | about 12.5m | 45-60m |
| 100 | about 25m | 90-120m |

Keep `serve --interval` comfortably above observed fleet scan time. If a fleet grows too large,
split it by customer segment, region, or backend. Raise `--concurrency` only after checking SIEM
API load; the default is deliberately conservative.

## Failure modes

One tenant failing does not hide the rest. Fleet reports include successful instances plus an
error entry for the failed instance, and the process exits `2`. In exporter mode,
`deadair_instance_up{instance=...}` flips to `0`.

Common causes:

| Failure | What happens | Operator action |
|---|---|---|
| expired or revoked credential | that instance fails with 401/403 | rotate the tenant secret, then run `deadair check --fleet` |
| missing optional privilege | scan succeeds but retention or schema stays unavailable | add the optional read privilege only if you need that check |
| tenant SIEM unreachable | that instance is reported failed; others still scan | check network path, DNS, proxy, and client allowlists |
| API throttling or timeouts | instance may fail or sources may become unknown | increase interval, lower concurrency, or split the fleet |
| planned maintenance | stale/empty findings can fire after the window | declare `--downtime-file` windows instead of excluding sources |
| tenant rename | baselines restart under the new name | keep names stable or copy the old state file deliberately |

Before routing pages, run at least one manual scan with human review, then gate on
`deadair diff` regressions while the initial backlog is worked down.
