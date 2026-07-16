# MSSP deployment guide

This guide is for running deadair across multiple client SIEMs from an operator-owned host. In this
guide, a source is a concrete index or data stream visible to the tenant credential. See
[Read the findings](usage.md#read-the-findings) for the evidence and triage model.

Current support status:

| Backend | MSSP status |
|---|---|
| Elastic Security 8.x | controlled pilot-ready |
| OpenSearch Security Analytics 2.x | controlled pilot-ready |

That means the fleet path, redaction, per-instance metrics, least-privilege credentials, and
partial-failure behavior are implemented and tested. It does not mean the tool has completed a
large real-client dogfood run across a production MSSP book.

## Run the lab first

```sh
make mssp-lab
```

The lab starts throwaway Elastic and OpenSearch stacks, seeds two working tenants plus three
failure cases, runs `check --fleet`, runs redacted scans with schema and downtime enabled,
scrapes `serve --fleet --redact`, and writes artifacts to `integration/mssp-lab-out/`.

<p align="center">
  <img alt="deadair MSSP lab output showing lab context, redacted fleet scan, and metrics" src="assets/mssp-lab.gif" width="860">
</p>

The generated files show the operator surfaces you will use in a real deployment:

| File | What to inspect |
|---|---|
| `check.txt` | fleet preflight, including bad credentials and an unreachable tenant |
| `fleet-summary.txt` | terminal fleet scan output |
| `fleet-redacted.json` | shareable redacted fleet report |
| `metrics.txt` | Prometheus metrics with per-instance health |
| `downtime.json` | expected downtime config |
| `state.json.*` | per-instance state files |

The lab proves the Docker workflow, config shape, redaction, partial failures, schema drift,
downtime suppression, exporter labels, and per-instance state. It does not prove customer source
cadence or hosted-SIEM edge cases.

## Deployment shape

Run deadair from a hardened host with outbound HTTPS access to each client SIEM API. Nothing is
installed in the client SIEM.

Use one least-privilege credential per tenant. Store only secret references in the fleet file.

```text
/etc/deadair/
  fleet.json
  secrets/
    acme-api-key
    beta-opensearch-password
  ca/
    acme.pem

/var/lib/deadair/
  state/
    fleet-state.json.acme-prod
    fleet-state.json.beta-corp
  reports/
    latest-redacted.json
    latest-internal.json
```

Recommended permissions:

- `/etc/deadair/fleet.json`: readable by the deadair service user only
- `/etc/deadair/secrets/*`: `0600`
- `/var/lib/deadair/state/*`: `0600`
- `/var/lib/deadair/reports/*`: `0600`

## Fleet config

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

Keep `name` stable. It keys metrics, per-instance state files, redacted digests, and historical
baselines. Renaming a tenant starts a new baseline unless you deliberately migrate the state file.

## Preflight

Run preflight after onboarding a tenant, rotating a credential, changing network paths, or
upgrading a backend.

```sh
deadair check --fleet /etc/deadair/fleet.json --timeout 90s
```

`check` verifies required read paths and reports optional schema visibility separately.

## One-shot reports

Use a redacted JSON report for client-facing or shared reporting:

```sh
deadair scan \
  --fleet /etc/deadair/fleet.json \
  --state-file /var/lib/deadair/state/fleet-state.json \
  --schema \
  --redact \
  --json \
  --out /var/lib/deadair/reports/latest-redacted.json
```

Keep an unredacted internal report only where analysts need exact source and rule names:

```sh
deadair scan \
  --fleet /etc/deadair/fleet.json \
  --state-file /var/lib/deadair/state/fleet-state.json \
  --schema \
  --json \
  --out /var/lib/deadair/reports/latest-internal.json
```

With `--fleet`, one `--state-file` prefix becomes one state file per instance.

## Review findings per tenant

Fleet rollups are useful for prioritization, but the evidence is tenant-local. The same enabled rule
can be healthy for one customer, intentionally out of scope for another, and broken for a third.

For example, three tenants inherit a rule that queries `netflow-*`:

| Tenant state | Evidence | Disposition |
|---|---|---|
| NetFlow onboarded | pattern resolves to a live index | healthy |
| NetFlow not in the customer's service scope | pattern resolves to no source | accepted coverage scope or onboarding backlog; document it |
| NetFlow was migrated to a renamed data stream | old pattern resolves to no source after prior coverage | regression; update the rule or restore the expected name |

For each actionable finding, keep enough context for the receiving team to start work:

| Field | Why it matters |
|---|---|
| instance | identifies the customer or deployment with the gap |
| rule and severity | identifies affected detection coverage and priority |
| configured patterns | shows what input the rule expects |
| matched sources and health | shows whether resolution or telemetry delivery failed |
| first seen or diff state | separates backlog from a new regression |
| disposition and owner | records accepted scope, remediation, or false positive |

The terminal fleet view is a summary. Keep the internal JSON report for exact patterns and sources;
use the redacted report for cross-team or client trend reporting.

## Continuous monitoring

```sh
deadair serve \
  --fleet /etc/deadair/fleet.json \
  --state-file /var/lib/deadair/state/fleet-state.json \
  --schema \
  --redact \
  --interval 30m
```

Default bind address is `127.0.0.1:9317`. Put it behind authenticated scraping if Prometheus is
not local to the host.

Prometheus scrapes the cached last scan. Scrape volume does not hit customer SIEM APIs.

## Redaction

Use `--redact` for:

- client-facing reports
- shared Prometheus
- screenshots
- support tickets
- demos
- any artifact that leaves the restricted SOC workspace

Redaction covers tenant, source, rule, pattern, and field names with stable digests. Stable
digests preserve trends and diffs without exposing customer identities or blind spots.

Keep unredacted reports restricted to analysts who need exact names for remediation.

## Alert routing

Route by the type of work, not by the tool.

| Signal | Suggested owner |
|---|---|
| `deadair_up == 0` | platform owner for the deadair host |
| `deadair_instance_up == 0` | tenant onboarding, credential, or network owner |
| no matching source | detection engineering or tenant onboarding, after checking credential scope |
| all matching sources stale or empty | telemetry pipeline owner, with detection engineering copied |
| impaired detections | detection engineering plus parser or pipeline owner |
| stale, empty, or low-volume sources | telemetry pipeline owner |
| schema drift | parser, integration, or content owner |
| unused telemetry | detection engineering and cost/platform owner |

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

Start with tickets or chat notifications. Page only after the first manual scan has been reviewed
and noisy findings have been fixed or suppressed correctly.

## Retention

Starting policy:

| Artifact | Suggested retention | Notes |
|---|---:|---|
| unredacted reports | 14-30 days | restricted SOC storage |
| redacted reports | 90-180 days | useful for client trend reporting |
| state files | long-lived | needed for baselines, hysteresis, lag history, and schema drift |
| exporter metrics | match normal monitoring retention | prefer `serve --redact` in shared Prometheus |

Back up state files if baseline continuity matters. Losing state is safe, but it restarts warmup
and schema history.

## Fleet sizing

Fleet scans are sequential. Cycle time is roughly:

```text
fleet scan time ~= sum(per-tenant scan time) + network/auth overhead
```

Measure your own p95:

```sh
time deadair scan --fleet /etc/deadair/fleet.json --json --out /tmp/deadair.json
```

Starting intervals:

| Tenants | If p95 tenant scan is 15s | Starting interval |
|---:|---:|---:|
| 10 | about 2.5m | 15m |
| 50 | about 12.5m | 45-60m |
| 100 | about 25m | 90-120m |

Keep `serve --interval` comfortably above observed fleet scan time. If a fleet grows too large,
split it by customer segment, region, or backend. Raise `--concurrency` only after checking SIEM
API behavior in your environment.

## Failure modes

One tenant failure does not hide the rest. Fleet reports include successful instance reports plus
an error entry for each failed instance. The process exits `2` to mark the scan incomplete.

| Failure | What happens | Operator action |
|---|---|---|
| expired or revoked credential | instance fails with 401/403 | rotate the tenant secret, then run `deadair check --fleet` |
| credential excludes expected indices | sources outside role scope appear absent and can produce no-match findings | expand the tenant role to the intended telemetry patterns, then verify a known-good rule/source pair |
| missing optional privilege | scan works, but schema or lag evidence may be unavailable | add the optional read privilege only if you need that check |
| tenant SIEM unreachable | instance is reported failed; other tenants still scan | check DNS, proxy, allowlists, VPN, and client-side availability |
| API throttling or timeouts | instance fails or sources become unknown | increase interval, lower concurrency, or split the fleet |
| planned maintenance | stale or empty findings may appear after the window | declare downtime windows instead of excluding sources |
| tenant rename | baselines restart | keep names stable or migrate the matching state file |

## Production readiness note

This repo has live Docker integration proof for Elastic, OpenSearch, mixed-backend fleet scans,
least-privilege credentials, rejected writes, and the MSSP lab. Before calling a deployment
production-proven for an MSSP, run it against real tenant SIEMs long enough to tune cadence,
downtime windows, and baseline settings from actual source behavior.
