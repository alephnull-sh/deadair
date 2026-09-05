---
layout: default
cover: true
title: Detections that run but can't see
author: Nikhil Satyakrishna
description: A read-only look at enabled detections that run on schedule, report success, and quietly stop seeing their data, plus what native SIEM health views already cover.
date: 2026-07-16
updated: 2026-09-05
hero_image: /assets/coverage-hero.png
---

If you have run detections at any scale, you have shipped a rule that quietly stopped working and not
noticed for weeks. Enabled, running on schedule, zero hits every time, execution health green. The
whole time, the rule kept reporting success.

The distinction that matters is between a rule that runs and a rule that can see. Rule-execution
monitoring answers the first question well: did the query fire, how long did it take, did it error, did
it warn. The second question is messier. Did the rule's sources exist, were they live, did the mapped
fields still line up, and did events arrive before the lookback window moved on? "Ran successfully, 0
alerts" can still mean "the search completed over data that could not have matched."

deadair compares each enabled rule's configured inputs with the concrete indices, data streams, or
tables visible to its read-only credential. It resolves those inputs with backend-native evidence,
then checks the sources it finds. The common failures are:

- **No matching source.** Inputs that positively resolve to no aliases, indices, data streams, or
  Sentinel tables. For example, a rule copied from a NetFlow-enabled tenant still searches
  `netflow-*`, but the receiving tenant has never onboarded NetFlow.
- **All matching sources stale or empty.** The sources exist but have stopped sending data or never
  received any. A dead shipper, a broken connector, a pipeline dropping its output.
- **Missing fields.** On Elastic, a rule declares a field that the source no longer maps as
  searchable. An integration changes its ECS mapping, the field goes null, and the condition never
  matches again.
- **Ingest-lag blind windows.** For eligible Elastic and Sentinel Scheduled rules, events land too
  late to fall inside the rule's window even though the source is otherwise healthy.
- **Incompatible table plans.** A Sentinel analytics rule reads a Basic or Auxiliary table directly,
  which that rule path cannot use.

A production-shaped no-match failure is a Beats-to-Agent migration. An enabled Windows rule still
queries `winlogbeat-*`, while current events now land in
`logs-windows.sysmon_operational-default`. After the old Winlogbeat indices age out, the evidence is:

```text
configured rule pattern    winlogbeat-*
resolution method          backend resolve-index API
visible concrete sources   logs-windows.sysmon_operational-default
sources matching pattern   none
finding                    no matching source
impact                     the rule has no source to query
```

A no-match finding is not always an incident. During onboarding, a rule pack may expect NetFlow before
the SOC has chosen to collect it. The report includes the rule, configured patterns, matched sources,
and source state so the operator can distinguish accepted scope from a regression.

This disposable Elastic lab has missing, stale, late, and schema-incompatible inputs. The recording
starts with a live scan, then opens two sources to show their evidence and affected detections.

<figure class="bordered" id="elastic-demo">
  <video controls playsinline preload="none" poster="{{ '/assets/scan-lab.png' | relative_url }}?v={{ site.github.build_revision | default: 'local' }}" aria-label="Investigating missing fields and delayed events in an Elastic lab">
    <source src="{{ '/assets/scan-lab.mp4' | relative_url }}" type="video/mp4">
    <a href="{{ '/assets/scan-lab.gif' | relative_url }}">Watch the Elastic recording</a>
  </video>
  <figcaption>Live Elastic 9.4.4 scan, followed by two source investigations from the saved report. Pause at any point to read the output.</figcaption>
</figure>

## Resolving sources and affected rules

Elastic and OpenSearch resolve aliases, data streams, and indices directly. Sentinel has no equivalent
endpoint, so deadair reads each rule's KQL and checks the concrete tables it can prove through the
catalog and bounded Logs queries. It follows only functions, watchlists, and remote workspaces whose
inputs are fixed; it does not guess at runtime-selected sources.

A no-match finding requires positive empty evidence. Finding a name in KQL is not enough, and a
permission failure is not proof that a table is absent. A stale-or-empty finding includes the degraded
source names and the evidence used to judge them.

For each degraded source, the report lists the enabled rules that resolve to it. A failed connector
can then be triaged as a set of affected detections instead of an isolated freshness alert. Prebuilt
rule packages make this especially visible because many enabled rules may expect integrations the
tenant does not run.

The report can only see sources available to the monitoring role. If that role cannot see an
expected source, deadair cannot distinguish hidden from absent. Before acting on no-match findings,
check that one known-good rule and source pair appears in the report.

<span id="when-a-field-quietly-disappears"></span>
## When a live source still cannot match

Missing fields are hard to spot because the index can stay live, volume can look normal, and the rule
can keep reporting success. An integration upgrade may rename a field, change its mapping, or stop
populating it. If a rule filters on `process.command_line` and an agent update stops mapping that field,
the condition no longer matches. deadair compares the fields declared by the rule with the current
`field_caps` response for each resolved source.

Elastic's `required_fields` metadata is informational and does not affect rule execution. It is only
available when a rule populates it, and custom rules may omit it. `field_caps` shows whether a field is
mapped and searchable, but not whether recent events contain values. Broad patterns also need to be
checked per index because one backing index may expose the field while another does not. The report
records the declared dependency and the concrete sources where it is not searchable throughout.

`CommonSecurityLog` exposes another blind spot in Sentinel. Several firewalls can share the table, so
one vendor can stop sending while another keeps it fresh. A rule filtered to PAN-OS does not care that
FortiGate wrote a row two minutes ago. In a
[Sentinel thread about silent firewalls](https://www.reddit.com/r/AzureSentinel/comments/1ergp0a/),
one practical recommendation was to filter `CommonSecurityLog` by `DeviceVendor` when several
firewalls share the table.

deadair checks that slice when a rule reads one local Analytics table and uses a fixed literal
filter. A quiet slice is useful context, but it isn't automatically an outage: a rule may be looking
for a rare attack event.

For a feed that should report regularly, define a producer expectation. Give it the vendor,
product, or device values found in the table and its normal reporting interval. In the latest lab,
two synthetic firewalls sent to `CommonSecurityLog`. We stopped the London PAN-OS feed while
FortiGate kept reporting. The table stayed fresh; the London producer failed its two-minute lab
threshold. Restoring that feed cleared the producer finding in the next scan.

The producer view lists rules whose parsed filters require that exact feed, separately from other
table consumers. It doesn't label every detection on `CommonSecurityLog` as broken. The
[investigation guide](investigate.md) shows the policy and maintenance settings.

<figure class="bordered" id="sentinel-demo">
  <video controls playsinline preload="none" poster="{{ '/assets/sentinel-lab.png' | relative_url }}?v={{ site.github.build_revision | default: 'local' }}" aria-label="A Sentinel firewall feed stops and recovers inside a busy shared table">
    <source src="{{ '/assets/sentinel-lab.mp4' | relative_url }}" type="video/mp4">
    <a href="{{ '/assets/sentinel-lab.gif' | relative_url }}">Watch the Sentinel recording</a>
  </video>
  <figcaption>Saved scans from a disposable UK South workspace, using synthetic firewall events and a two-minute reporting threshold. Playback controls let you pause on failure or recovery.</figcaption>
</figure>

Sentinel has a second source problem: analytics rules cannot query Basic or Auxiliary tables directly.
A summary rule can read the lower-cost raw table, write an Analytics table, and give the detection a
usable source. deadair records that path and the latest `LASummaryLogs` run when one exists. In the
lab, the summary completed and the raw and summary counts matched for the same 20-minute bin.

## Ingest lag

The calculation below uses a fixed schedule and fixed ingest lag. A scheduled rule matches on event
time but can only see events already ingested when it runs. Batched sources such as cloud audit logs
and polled APIs can arrive after the rule's window has moved past the event, with no execution error.

Let P be the lookback (Elastic's `from`, for example `now-6m`), I the rule interval, and L the source's
lag. A run catches an event only if it fires after the event is searchable and before the window moves
past it. That leaves `P − L` minutes for a run on an `I`-minute cadence to land in.

<div class="keystat" markdown="0">
  <p class="formula">catch rate&nbsp; C(L) = clamp( (P − L) / I, 0, 1 )</p>
  <p class="note">In this fixed-schedule, fixed-lag model, while lag stays under the margin <strong>L ≤ P − I</strong>, every event is still caught. Past it, coverage falls in a straight line to zero at L = P.</p>
</div>

<details class="aside">
<summary>Where that fraction comes from</summary>
<p>A run at time <code>R</code> catches an event at <code>T</code> only if the run is inside the window (<code>T ∈ [R−P, R]</code>, equivalently <code>R ∈ [T, T+P]</code>) and after the event was ingested (<code>R ≥ T+L</code>). So a scheduled run, some multiple of <code>I</code>, has to fall in the interval <code>[T+L, T+P]</code>. That interval is <code>P − L</code> wide. Under a fixed cadence with events at all offsets relative to the schedule, the chance a run lands inside it is <code>(P − L) / I</code>, clamped to <code>[0, 1]</code>.</p>
</details>

<figure>
  <img class="theme-art-light" src="{{ '/assets/lag-curve-light.svg' | relative_url }}?v={{ site.github.build_revision | default: 'local' }}" alt="Catch rate versus ingest lag: flat at 100% up to the reliable margin, then a straight linear decline to zero at the lookback, then flat at zero">
  <img class="theme-art-dark" src="{{ '/assets/lag-curve.svg' | relative_url }}?v={{ site.github.build_revision | default: 'local' }}" alt="Catch rate versus ingest lag: flat at 100% up to the reliable margin, then a straight linear decline to zero at the lookback, then flat at zero">
  <figcaption>Fraction of events a rule catches as source ingest lag grows, for a rule with a 6-minute lookback running every 5 minutes. The line is the formula, the open points are the simulation, and the shaded area is coverage lost with no error and no alert.</figcaption>
</figure>

A [small simulation](https://github.com/alephnull-sh/deadair/blob/main/docs/assets/lagsim.py) matches
the model to within rounding, shown by the open points on the chart. A rule with `from: now-6m` running
every 5 minutes has a one-minute margin. With 3 minutes of fixed lag, it catches around **60% of its
events** in this model. Real schedulers add jitter, retries, manual runs, deduplication, timestamp
fallback, and rule-type differences.

On Elastic, deadair reads the timestamp field, `from`, interval, and paired `@timestamp` and
`event.ingested` samples. On Sentinel Scheduled rules, `queryPeriod` and `queryFrequency` provide the
same window and cadence, while `TimeGenerated` and `ingestion_time()` provide the paired sample.
Sentinel NRT rules use ingestion-time freshness instead of this Scheduled-rule calculation. If both
rule types read one table, deadair keeps both clocks and applies the appropriate one to each rule.

## The check I got wrong

I originally added a check that compared a rule's lookback with index retention. A rule looked back 90
days while ILM kept 30, so the check reported two thirds of the window as empty.

That was wrong for normally scheduled rules. They catch events as they arrive and do not need data
from days 31 through 90. Retention only loses an event when the data is deleted before the next run
reads it (`retention < interval`). The check fired on nearly every rule without finding a real coverage
problem, so I removed it.

Retention does matter for rule types whose operation depends on historical data. Elastic New Terms
rules, for example, use `history_window_start` to define their baseline. That needs a rule-type-specific
check, not a general lookback-versus-retention comparison.

<span id="existing-elastic-coverage"></span>
## What native health already covers

Elastic already has several related health views. [SIEM Readiness](https://www.elastic.co/docs/solutions/security/get-started/siem-readiness)
tracks coverage, quality, continuity, and retention. Its data rule coverage view calls out enabled
rules that are missing required integrations, and its data coverage view calls out missing log
categories. [Data Quality](https://www.elastic.co/docs/solutions/security/dashboards/data-quality-dashboard)
checks ECS mapping problems per index. [Rule monitoring](https://www.elastic.co/docs/solutions/security/detect-and-alert/monitor-rule-executions)
tracks success, failure, warnings, gaps, durations, and missing index-pattern warnings. A successful
execution means the search completed, not that it produced an alert. The
[common rule settings](https://www.elastic.co/docs/solutions/security/detect-and-alert/common-rule-settings)
document timestamp override and additional look-back for ingestion delay.

Sentinel's [`SentinelHealth`](https://learn.microsoft.com/en-us/azure/sentinel/monitor-analytics-rule-integrity)
records Scheduled and NRT rule runs, including failures and alerts generated. `LASummaryLogs` records
summary-rule runs. Neither says whether the exact table or filtered slice needed by a detection is
current.

Cross-subscription rules have another failure mode: the scanner can still read a remote workspace
after the rule creator loses access. For an installed Scheduled or NRT rule, deadair records a
matching recent `SentinelHealth` success when one exists. That check has fixture coverage; the live
lab covered two workspaces in one subscription.

For each enabled rule, deadair resolves the concrete sources, records their state and declared-field
availability, and compares source lag with rule timing. It also lists sources that no enabled rule
reads.

## Implementation and limits

deadair uses read-only credentials. It reads metadata and bounded timestamp samples rather than full
events. In the Sentinel lab, that credential could list rules and tables but could not delete them or
retrieve shared keys.

Setup and test boundaries are in the [usage](usage.md) and [validation](validation.md) guides. deadair
checks whether a rule can see the data it expects. It does not assess the rule logic.

<p style="margin-top:2rem"><a href="https://github.com/alephnull-sh/deadair">deadair on GitHub →</a></p>
