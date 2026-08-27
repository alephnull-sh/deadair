# MSSP deployment guide

This guide covers running deadair across client SIEMs from an operator-owned host. A source is a
concrete index, data stream, or Sentinel table visible to the tenant credential. See
[Read the findings](usage.md#read-the-findings) for the evidence and triage model.

## Run the lab first

```sh
make mssp-lab
```

The lab covers the Elastic and OpenSearch Docker path. It seeds two working tenants and three failure
cases, runs `check --fleet`, runs redacted scans with schema and downtime enabled, scrapes
`serve --fleet --redact`, and writes artifacts to `integration/mssp-lab-out/`.

The generated files show the operator surfaces you will use in a real deployment:

| File | What to inspect |
|---|---|
| `check.txt` | fleet preflight, including bad credentials and an unreachable tenant |
| `fleet-summary.txt` | terminal fleet scan output |
| `fleet-redacted.json` | pseudonymized fleet report; review its findings and counts before sharing |
| `metrics.txt` | Prometheus metrics with per-instance health |
| `downtime.json` | expected downtime config |
| `state.json.*` | per-instance state files |

The lab covers the Docker workflow, config shape, redaction, partial failures, schema drift,
downtime suppression, exporter labels, and per-instance state. Validate source cadence and hosted
SIEM behavior in each customer environment.

## Deployment shape

Run deadair from a hardened host with outbound HTTPS access to each client SIEM API. Nothing is
installed in the client SIEM.

Keep every credential or workload identity scoped to the tenants it is meant to scan. Store only
secret references in the fleet file.

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
    fleet-state.json.gamma-sentinel
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
  },
  {
    "name": "gamma-sentinel",
    "backend": "sentinel",
    "azure_subscription_id": "<subscription-id>",
    "azure_resource_group": "gamma-security",
    "sentinel_workspace": "gamma-sentinel"
  }
]}
```

Sentinel fleet entries use the process's `DefaultAzureCredential`; they do not carry credentials in
the fleet file. If customers require different Azure identities, run those fleet entries in
separate deadair processes. Add `sentinel_remote_workspaces` only for literal `workspace()` targets
you intend to assess. The [Sentinel usage guide](usage.md#microsoft-sentinel) explains the mapping
format and the cross-tenant execution boundary.

Keep `name` stable. It keys metrics, per-instance state files, redacted pseudonyms, and historical
baselines. Renaming a tenant starts a new baseline unless you deliberately migrate the state file.
Names may contain Unicode, internal spaces, and ordinary punctuation, but must be portable file-name
components: no leading or trailing whitespace, path separators, control characters, Windows-reserved
`< > : " | ? *` characters, or trailing dot. Names that differ only by letter case are duplicates.

## Preflight

Run preflight after onboarding a tenant, rotating a credential, changing network paths, or
upgrading a backend.

```sh
deadair check --fleet /etc/deadair/fleet.json --timeout 90s
```

`check` verifies required read paths and reports optional schema visibility separately.

## One-shot reports

Use a pseudonymized JSON report when exact identifiers are unnecessary:

```sh
deadair scan \
  --fleet /etc/deadair/fleet.json \
  --state-file /var/lib/deadair/state/fleet-state.json \
  --schema \
  --redact \
  --json \
  --json-out /var/lib/deadair/reports/latest-redacted.json
```

Keep an unredacted internal report only where analysts need exact source and rule names:

```sh
deadair scan \
  --fleet /etc/deadair/fleet.json \
  --state-file /var/lib/deadair/state/fleet-state.json \
  --schema \
  --json \
  --json-out /var/lib/deadair/reports/latest-internal.json
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
| configured patterns or dependencies | shows what input the rule expects |
| matched sources and health | shows whether resolution or telemetry delivery failed |
| first seen or diff state | separates backlog from a new regression |
| disposition and owner | records accepted scope, remediation, or false positive |

The terminal fleet view is a summary. Keep the internal JSON report for exact patterns and sources;
use the redacted report for authorized cross-team or client trend reporting.

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

Use `--redact` before authorized sharing through:

- client-facing reports
- shared Prometheus
- screenshots
- shared issue reports

Redaction covers tenant, source, rule, pattern, field, dependency, lineage, provenance, workspace,
watchlist, template, and package identifiers with keyed HMAC pseudonyms. Generate a separate random
key file for each correlation boundary and set `DEADAIR_REDACT_KEY_FILE` to its path. Supplying the
key file also enables redaction. Reports record the non-secret key identifier, so a reporting job
can reject inputs created with different keys. Without a key file, pseudonyms are stable only for
the life of one process. Redacted fleet reports expose a fixed failure category rather than raw
backend errors.

Redaction is not declassification. Backend versions, counts, severities, timing, lag, storage
volume, and the kinds of blind spots remain visible. Review the result and share it only with an
authorized recipient.

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
| source plan incompatible | detection engineering and the Sentinel workspace owner |
| lag blind window | detection engineering and telemetry pipeline owner |
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

## Schedule fleet scans

Fleet scans are sequential. Cycle time is roughly:

```text
fleet scan time ~= sum(per-tenant scan time) + network/auth overhead
```

Measure your own p95:

```sh
time deadair scan --fleet /etc/deadair/fleet.json --json --json-out /tmp/deadair.json
```

Keep `serve --interval` comfortably above observed fleet scan time. If a fleet grows too large,
split it by customer segment, region, or backend. Raise `--concurrency` only after checking SIEM
API behavior in your environment.

Back up state files if baseline continuity matters. Losing state does not affect the backend, but
it restarts warmup and schema history.

## Failure modes

One tenant failure does not hide the rest. Fleet reports include successful instance reports plus
an error entry for each failed instance. The process exits `2` to mark the scan incomplete.

| Failure | What happens | Operator action |
|---|---|---|
| expired or revoked credential | instance fails with 401/403 | rotate the tenant secret, then run `deadair check --fleet` |
| credential excludes expected sources | sources outside role scope appear absent and can produce no-match findings | expand the tenant role to the intended sources, then verify a known-good rule/source pair |
| missing optional privilege | scan works, but schema, lag, lineage, or provenance evidence may be unavailable | add the optional read privilege only if you need that check |
| tenant SIEM unreachable | instance is reported failed; other tenants still scan | check DNS, proxy, allowlists, VPN, and client-side availability |
| API throttling or timeouts | instance fails or sources become unknown | increase interval, lower concurrency, or split the fleet |
| planned maintenance | stale or empty findings may appear after the window | declare downtime windows instead of excluding sources |
| tenant rename | baselines restart | keep names stable or migrate the matching state file |
