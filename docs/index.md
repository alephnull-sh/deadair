---
layout: default
cover: true
title: Detections that run but can't see
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

Treat coverage as its own question and it is a small join, what each rule reads against the state its
sources are in. Here a source means a concrete index or data stream visible to the monitoring
credential, not an agent, connector, or upstream product. The join breaks four ways, and I keep
hitting the same four.

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

The same verdict can be harmless during onboarding: a rule pack may expect NetFlow before the SOC
has chosen to collect it. That is why the finding should carry the rule, configured patterns, matched
sources, and source state. The operator still decides whether it is accepted scope, unfinished
onboarding, or a regression.

Here is a lab scan. Every rule is enabled; the flagged ones resolve to something missing, stale, or
empty.

<figure class="bordered">
  <img src="{{ '/assets/demo-final.svg' | relative_url }}?v={{ site.github.build_revision | default: 'local' }}" alt="Static deadair scan summary showing enabled rules with no matching source, one lag-impaired rule, and unused telemetry">
  <figcaption>The terminal view is a summary; the JSON report retains each rule's configured patterns and matched sources. Missing index patterns may warn in Elastic; stale-but-existing sources are the quieter case.</figcaption>
</figure>

## Dead detections and blast radius

That scan is most of what deadair does. It asks the SIEM to resolve each rule input using native
alias, data-stream, index, and exclusion semantics, connects those results to the credential-visible
source inventory, checks matched-source state, and reports the evidence per rule. A no-match finding
requires a positive empty resolution; unsupported, unavailable, remote, and ambiguous inputs remain
unassessed rather than being guessed dead. A stale-or-empty finding keeps the degraded source names
and health evidence.

The per-rule part is what makes it useful. Plenty of tools tell you a source went quiet; few tell you
which enabled detection just died because of it. The graph also runs backwards, which is the view a SOC
wants when a source breaks. One failed connector shows up as "these nine detections just went dark,"
ranked by severity, instead of a freshness alert someone has to trace back to the affected rules by
hand. Turn on a prebuilt rule package and it gets loud fast, since a big chunk of those rules expect
integrations you do not run.

Credential scope is part of the evidence boundary. If the monitoring role cannot see an expected
index, the report cannot distinguish hidden from absent. A first deployment therefore needs one
known-good rule/source pair checked against the report before the team treats no-match findings as
coverage incidents.

## When a field quietly disappears

Of the four, this is the nastiest, because it hides best. Index alive, volume normal, rule green. But an
integration upgrade renamed a field, an agent changed its mapping, or a pipeline stopped populating a
value the rule depends on. The condition never matches, the rule returns nothing forever, and nothing
lights up. It rides a legitimate change, so nobody touched the rule; the ground under it moved. Say a
rule keys on `process.command_line` and an agent update stops mapping it. That rule is blind from the
next run onward, and every health view still shows it running clean. The catch is diffing what each
rule declares it needs against what the source's `field_caps` exposes right now.

That check is best-effort, not magic. Elastic's `required_fields` metadata is explicitly
informational and does not affect rule execution, so it is good evidence for well-authored prebuilt
rules and weaker evidence for custom rules. `field_caps` tells you whether a field is mapped and
searchable; it does not prove recent events actually contain values. And broad patterns need per-index
care, because one matching backing index can have the field while another is unmapped. So the finding
should be worded as "the rule declares this dependency, and these concrete sources do not expose it,"
not as a universal proof that the rule can never match.

## Ingest lag

This one has useful math, but it is a model. Elastic already documents timestamp override and
additional look-back as fixes for ingestion delay. A scheduled rule matches on event time but can only
see events already ingested when it runs, and batched sources like cloud audit logs and polled APIs
arrive late. An event that lands after the rule's window has slid past is missed, with no error.

Three numbers decide it. The lookback P (Elastic's `from`, e.g. `now-6m`), the interval I, and the
source's lag L. A run catches an event only if it fires after the event is searchable but before the
window slides past, which leaves a gap of `P − L` for a run every `I` minutes to land in.

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

A [15-line simulation](https://github.com/Big-Comfy/deadair/blob/main/docs/assets/lagsim.py) matches
the model to within rounding, the open points on the chart. In numbers, a rule with `from: now-6m`
every 5 minutes has a one-minute margin, so a source batching with 3 minutes of fixed lag catches
around **60% of its events** in this model. Real schedulers have jitter, retries, manual runs,
deduplication, timestamp fallback, and rule-type differences, so treat the result as exposure
estimation, not a universal truth.

This only bites rules windowing on `@timestamp`, and both vendors document the fix. Elastic's is to set
the timestamp override to `event.ingested` so the rule windows on ingest time; widening the additional
look-back is the fallback. The operational question is which rules, sources, and tenants still have a
bad margin, and that reads off metadata: timestamp field, `from`, interval, and measured source lag.

## The check I got wrong

One check I built and killed taught me the rule I hold the tool to. It sounds right. A rule looks back
90 days, the index keeps 30 (ILM deletes at 30d), so two thirds of the window is empty. I shipped it as
a blind spot and felt clever. It is wrong. A normally scheduled rule catches events as they arrive,
well inside 30 days, and never needs the 31-to-90-day-old data. Retention only costs a scheduled rule
an event when data is deleted before the next run reads it (`retention < interval`), which with days
against minutes never happens. It fired on nearly every rule, pure noise, so I pulled it.

The real exception is the tell. Rule types that are only correct if the window genuinely holds data,
like a New Terms rule whose baseline is only as deep as retention, are a property of the rule type and
its `history_window_start`, not a lookback-versus-retention comparison. The lesson I kept is that these
checks all assume something about timing, and a wrong assumption invents a false finding rather than
missing a real one. False positives are how a health tool gets muted and then uninstalled, so the tool
needs positive evidence before it says anything and stays quiet without it.

## What native tools already cover, and what they do not

Elastic ships health signals worth knowing, and the honest version of this argument has to start
there. [SIEM Readiness](https://www.elastic.co/docs/solutions/security/get-started/siem-readiness)
tracks coverage, quality, continuity, and retention. Its data rule coverage view calls out enabled
rules that are missing required integrations, and its data coverage view calls out missing log
categories. [Data Quality](https://www.elastic.co/docs/solutions/security/dashboards/data-quality-dashboard)
checks ECS mapping problems per index. [Rule monitoring](https://www.elastic.co/docs/solutions/security/detect-and-alert/monitor-rule-executions)
tracks success, failure, warnings, gaps, durations, and missing index-pattern warnings; Elastic is clear
that "succeeded" means the rule completed its search, not that it produced an alert. And
[common rule settings](https://www.elastic.co/docs/solutions/security/detect-and-alert/common-rule-settings)
already document timestamp override and additional look-back for ingestion delay.

Those views cover real parts of the problem. What I wanted was a rule dependency report I could run
outside the SIEM: for each enabled rule, resolve the concrete sources it reads, show whether those
sources are live, check whether declared fields are exposed, estimate whether ingest lag leaves enough
margin, and point out telemetry no enabled rule reads.

## Where deadair fits

You do not need a product to prove the idea. For one SIEM, pull the rule inventory, treat declared
required fields as best-effort metadata, inspect `field_caps` per concrete source, resolve patterns,
check freshness, and work out the lag. It is a handful of API calls.

I built **deadair** to make that check boring enough to run repeatedly. It runs outside the SIEM with a
read-only credential, never touches event bodies, and reports from metadata and stats: counts,
timestamps, mappings, `field_caps`, and size-0 `max(@timestamp)` / `max(event.ingested)` aggregations.
The useful parts are scheduling it, gating detection changes in CI, redacting reports, and running the
same check across Elastic and OpenSearch fleets. For an MSSP, that means one report can show which
enabled detections lost coverage when a source degrades in one tenant.

The honest limits: deadair is young, supports two backends, uses best-effort rule metadata where the
SIEM only exposes best-effort metadata, and only tells you whether a rule can see data, not whether the
rule logic is good. CI provisions the least-privilege role and proves every write is rejected against a
live cluster, so read-only is enforced, not claimed.

If you know a failure mode I have missed, the issues are open. If nothing else sticks, a rule executing
and a rule detecting are two different events. Native SIEM tooling watches a lot more than it used to;
the missing piece I care about is the per-rule dependency report you can run as an operational check.

<p style="margin-top:2rem"><a href="https://github.com/Big-Comfy/deadair">deadair on GitHub →</a></p>
