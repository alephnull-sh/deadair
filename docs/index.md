---
layout: default
cover: true
title: Detections that run but can't see
author: Nikhil Satyakrishna
description: A read-only look at enabled detections that run on schedule, report success, and quietly stop seeing their data, plus what native SIEM health views already cover.
date: 2026-07-16
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

deadair compares each enabled rule's configured inputs with the concrete indices and data streams
visible to its read-only credential. It resolves those inputs with the SIEM's own rules, then checks
the state of the sources it finds. Four failures matter:

- **No matching source.** Inputs the SIEM's native resolver positively resolves to zero aliases,
  indices, or data streams. For example,
  a rule copied from a NetFlow-enabled tenant still searches `netflow-*`, but the receiving tenant
  has never onboarded NetFlow.
- **All matching sources stale or empty.** The sources exist but have stopped sending data or never
  received any. A dead shipper, a broken connector, a pipeline dropping its output.
- **Missing fields.** The rule filters on a field the source stopped providing. An integration changes
  its ECS mapping, the field goes null, the condition never matches again.
- **Ingest-lag blind windows.** Source and fields are fine, but events land too late to fall inside
  the rule's window.

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

Here is a scan from a disposable Elastic lab. Every rule is enabled; the lab deliberately creates
missing input, stale source, missing-field, ingest-lag, and unused-telemetry conditions.

<figure class="bordered">
  <img src="{{ '/assets/scan-lab.png' | relative_url }}?v={{ site.github.build_revision | default: 'local' }}" alt="Real deadair scan of a disposable Elastic lab showing missing, stale, late, and unused telemetry">
  <figcaption>This is output from the real CLI against Elastic 9.4.4. The terminal view is a summary; the JSON report retains each rule's configured patterns and matched sources.</figcaption>
</figure>

## Resolving sources and affected rules

For each rule input, deadair calls the SIEM's native resolver so the backend handles aliases, data
streams, indices, and exclusions. It checks the state of each resolved source and records the evidence
against the rule. A no-match finding requires a positive empty resolution. Unsupported, unavailable,
remote, and ambiguous inputs remain unassessed rather than being guessed dead. A stale-or-empty
finding includes the degraded source names and health evidence.

For each degraded source, the report lists the enabled rules that resolve to it. A failed connector
can then be triaged as a set of affected detections instead of an isolated freshness alert. Prebuilt
rule packages make this especially visible because many enabled rules may expect integrations the
tenant does not run.

The report can only see indices available to the monitoring role. If that role cannot see an expected
index, deadair cannot distinguish hidden from absent. Before acting on no-match findings, check that
one known-good rule and source pair appears in the report.

## When a field quietly disappears

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

A [15-line simulation](https://github.com/alephnull-sh/deadair/blob/main/docs/assets/lagsim.py) matches
the model to within rounding, shown by the open points on the chart. A rule with `from: now-6m` running
every 5 minutes has a one-minute margin. With 3 minutes of fixed lag, it catches around **60% of its
events** in this model. Real schedulers add jitter, retries, manual runs, deduplication, timestamp
fallback, and rule-type differences.

The model applies to rules windowing on `@timestamp`. Elastic recommends overriding the timestamp with
`event.ingested`, or widening the additional look-back. deadair reads the timestamp field, `from`,
interval, and measured source lag to find rules with too little margin.

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

## Existing Elastic coverage

Elastic already has several related health views. [SIEM Readiness](https://www.elastic.co/docs/solutions/security/get-started/siem-readiness)
tracks coverage, quality, continuity, and retention. Its data rule coverage view calls out enabled
rules that are missing required integrations, and its data coverage view calls out missing log
categories. [Data Quality](https://www.elastic.co/docs/solutions/security/dashboards/data-quality-dashboard)
checks ECS mapping problems per index. [Rule monitoring](https://www.elastic.co/docs/solutions/security/detect-and-alert/monitor-rule-executions)
tracks success, failure, warnings, gaps, durations, and missing index-pattern warnings. A successful
execution means the search completed, not that it produced an alert. The
[common rule settings](https://www.elastic.co/docs/solutions/security/detect-and-alert/common-rule-settings)
document timestamp override and additional look-back for ingestion delay.

For each enabled rule, deadair resolves the concrete sources, records their state and declared-field
availability, and compares source lag with rule timing. It also lists sources that no enabled rule
reads.

## Implementation and limits

deadair runs outside the SIEM with a read-only credential. It does not read event bodies. It reads
counts, timestamps, mappings, `field_caps`, and size-0 `max(@timestamp)` and
paired `event.ingested` and `@timestamp` values from a bounded recent sample.

It currently supports Elastic Security and OpenSearch Security Analytics. Some checks depend on rule
metadata and are limited by what each SIEM exposes. deadair checks whether a rule can see the data it
expects. It does not assess the rule logic.

<p style="margin-top:2rem"><a href="https://github.com/alephnull-sh/deadair">deadair on GitHub →</a></p>
