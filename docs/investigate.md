# Investigate a telemetry gap

Start with the source when several detections report the same problem. Save a scan so you can
inspect the evidence without sending another query to the SIEM:

```sh
deadair scan --json-out report.json --html-out report.html
deadair inspect --source logs-system.auth-default report.json
```

Run `deadair inspect report.json` without a selector to browse all saved sources and expected feeds.
Use `--source` or `--producer` to focus on one.

The source view lists its enabled consumers in severity order, the freshness observation, and a
first check based on the evidence. The HTML report has the same view. A source that has stopped
reporting points you toward the sender and collector; a missing field points you toward the mapping
and ingestion transform.

Add `--links` to include native SIEM and runbook URLs in the terminal. They're always clickable in
the HTML report when available. `inspect` reads the saved scan; it doesn't refresh the observations.

A consumer is a rule that reads the source. That relationship alone doesn't say the rule is
broken. A rule may still have another usable input, and a busy shared table may contain several
unrelated feeds. Read the rule verdict alongside the source observation.

## Watch one firewall inside a shared Sentinel table

Suppose `CommonSecurityLog` receives events from two firewalls. One stops reporting, but the other
keeps the table fresh. A table-wide age check won't catch that outage.

Add an explicit feed expectation to your existing policy. This example expects traffic from the
London edge firewall at least once every 15 minutes:

```json
{
  "version": 1,
  "gate_classes": ["dead-detection", "impaired-detection", "producer-stale", "summary-pipeline"],
  "producers": [{
    "id": "london-edge",
    "source": "CommonSecurityLog",
    "match": {
      "DeviceVendor": "Palo Alto Networks",
      "DeviceProduct": "PAN-OS",
      "DeviceName": "fw-london-01"
    },
    "max_stale": "15m",
    "basis": "ingestion_time",
    "owner": "Network operations",
    "runbook": "https://wiki.example.net/runbooks/firewall-log-delivery"
  }]
}
```

Use the values recorded in your table, and choose a threshold that matches normal delivery.
`match` accepts exact, case-sensitive `DeviceVendor`, `DeviceProduct`, and `DeviceName` values.
All configured fields must match. You can define up to 20 feeds; each uses one bounded query over
a local Analytics table. The maximum threshold is 24 hours.

Use a workspace-specific policy for these expectations. A fleet applies its policy to every
instance, so keep workspaces with different expected feeds in separate scans.

```sh
deadair scan --policy policy.json --state-file state.json --json-out report.json
deadair inspect --producer london-edge report.json
```

The producer view separates:

- **Detections requiring this producer:** the rule's parsed filter requires every identity value
  in the expectation.
- **Other table consumers:** the rule reads the table, but deadair hasn't proved that it requires
  this particular producer.

For example, a rule filtered only to `DeviceVendor == 'Palo Alto Networks'` is not a confirmed
dependency on `fw-london-01`. It may receive events from other Palo Alto devices. A quiet producer
creates its own finding; it doesn't turn every table consumer into a dead detection.

Define expectations for feeds that normally report, not for security events you hope never occur.
A firewall sending traffic every few minutes is a useful expectation. A privilege-escalation event
every hour isn't. deadair never creates feed expectations from detection predicates automatically.

### Choose the clock

`ingestion_time` is the default for producer expectations: it asks whether Azure is still receiving
the feed. Use `event_time` when the expectation is about the age of the events themselves. Both can
matter when a collector is draining an old queue.

Rule freshness follows the rule type. Scheduled rules use event time; NRT rules use ingestion
time. When both read the same table, the report keeps both observations and applies the appropriate
one to each rule.

### Schedule expected quiet periods

Add `producer:<id>` to a downtime file to suppress just that feed's alert:

```json
{"windows": [{
  "name": "firewall maintenance",
  "sources": ["producer:london-edge"],
  "days": ["sat"],
  "start": "22:00",
  "end": "23:00",
  "timezone": "Europe/London"
}]}
```

Pass it with `--downtime-file downtime.json`. Using the table name instead suppresses every
configured producer on that table. The stale observation remains visible during maintenance; only
the alert is suppressed. Maintenance isn't recovery.

## Track a summary pipeline

Sentinel rules may read an Analytics summary table populated by a summary rule over cheaper raw
storage. deadair follows that lineage and reads the latest completed run in `LASummaryLogs`.
Enable the workspace's Summary Logs diagnostic setting and grant the scanner query access to that
table. The [credential guide](credentials/sentinel.md) lists the required read actions.

`summary-pipeline` findings cover failed runs and successes that are overdue for the configured
schedule, delay, and Azure's retry allowance. Include that class in `gate_classes` if it should
fail a scan. Missing runtime records or denied access are shown as unavailable evidence, not as a
pipeline failure.

## Follow the failure through recovery

Keep the policy, scope, and state path the same between scans:

```sh
deadair scan --policy policy.json --state-file state.json --json-out before.json
# Restore the feed or fix the summary job, then scan again.
deadair scan --policy policy.json --state-file state.json --json-out after.json
deadair diff before.json after.json
```

Producer and summary-pipeline findings keep their identities between scans. Recovery needs a new,
successful observation. Summary jobs must also have a newer successful execution. A permission
failure, missing response, or removed expectation cannot clear the old failure. Changing the policy
or scan scope requires a new comparison baseline.

For ongoing checks, run `serve` with the same policy and downtime file. The exporter includes
producer and summary-pipeline assessment, failure, and suppression metrics. The
[Prometheus alert examples](../contrib/prometheus-alerts.yml) check scan availability and suppression
before alerting. Route missing evidence to the scanner's credential owner; route a quiet firewall
feed to the team that owns its delivery path.

## Add an owner and runbook to a source

Source policies accept the same optional contact fields:

```json
{"version": 1, "gate_classes": ["dead-detection", "impaired-detection", "source-degraded", "volume-low", "schema-drift"], "sources": [{
  "pattern": "logs-system.auth-*",
  "max_stale": "30m",
  "owner": "Linux platform",
  "runbook": "https://wiki.example.net/runbooks/linux-auth-logs"
}]}
```

These are report annotations, not notification destinations. deadair doesn't contact the owner or
open the runbook. Redacted reports pseudonymize owners and omit runbook and native links. Keep the
unredacted policy and reports in your restricted operations workspace.
