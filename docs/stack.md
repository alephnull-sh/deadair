---
layout: default
title: The detection coverage stack
description: How detsema and deadair split one question. Static analysis of rule logic before it ships, and live telemetry coverage after, with a worked example for SOC and detection engineers.
permalink: /stack/
---

# The detection coverage stack

A detection can be broken in two places. Before it ships, the logic itself can be impossible, a
predicate over a field your pipeline never emits, or a type or case mismatch that never compares
equal. After it ships, the world moves underneath it, a source goes stale, a mapping drops a field,
events start arriving late. Rule-execution monitoring reports on neither. In both cases the rule
runs, returns nothing, and reports success.

Those are two different problems, which is why this ended up as two small tools rather than one. The
first problem is static, answerable from files alone. The second is live, answerable only by asking
the SIEM what exists right now.

[detsema](https://big-comfy.github.io/detsema/) is the static half. It parses Sigma rules into a
typed representation and checks them against a declared schema of the fields your pipeline emits. It
answers whether the logic can ever match, offline, with file and line, before anything is deployed.
Anything outside its documented subset gets an explicit unsupported verdict instead of a silent
guess.

[deadair](https://big-comfy.github.io/deadair/) is the live half. It runs read-only against Elastic
Security or OpenSearch Security Analytics, resolves each enabled rule to the concrete sources it
reads, and reports which rules are blind right now and why, from disconnected patterns and starved
sources to dropped mapping fields, ingest-lag margins, and the blast radius when one source degrades.

<figure>
  <img class="theme-art-light" src="{{ '/assets/stack-diagram-light.svg' | relative_url }}?v={{ site.github.build_revision | default: 'local' }}" alt="Timeline of a rule from code to production. detsema covers authoring and CI with static checks (unknown field, type mismatch, case mismatch, unsupported construct); deadair covers CI through production with live checks (disconnected, starved, missing field, lag margin, blast radius, unused telemetry)">
  <img class="theme-art-dark" src="{{ '/assets/stack-diagram.svg' | relative_url }}?v={{ site.github.build_revision | default: 'local' }}" alt="Timeline of a rule from code to production. detsema covers authoring and CI with static checks (unknown field, type mismatch, case mismatch, unsupported construct); deadair covers CI through production with live checks (disconnected, starved, missing field, lag margin, blast radius, unused telemetry)">
  <figcaption>detsema works on the rule text and stops at the CI gate. deadair starts at the same gate with scan --rule and stays with the rule for as long as it runs.</figcaption>
</figure>

## One rule, four moments

1. **Authoring.** You write a Sigma rule keying on `process.command_line`, but the pipeline emits
   `process.commandline`. `detsema check` fails the pull request with the file, the line, and the
   unknown field. Fixed before review.
2. **Pre-deploy.** The logic is sound, but is this environment ready for it? `deadair scan --rule
   candidate.json` runs the dependency check against the live cluster before the rule is enabled. If
   the index pattern resolves to nothing here, the gate fails for the candidate only.
3. **Enabled.** The rule goes live. A scheduled `deadair scan` keeps checking that its sources stay
   live, its fields stay mapped, and its lag margin holds.
4. **Months later.** An agent upgrade drops the field from the mapping, or the connector behind the
   source dies. Nothing errors, and the rule keeps reporting success. The next scan flags the rule
   blind, and if a source broke, the report names every affected rule ranked by severity instead of
   one freshness alert someone has to trace back by hand.

## Who runs what

- **Detection engineers** wire both into detection-as-code CI. detsema gates the rule text, and
  `deadair scan --rule` gates the fit between the rule and the environment.
- **SOC and platform engineers** run deadair on a schedule or as a Prometheus exporter, so coverage
  loss shows up as a finding instead of during an incident.
- **MSSPs and multi-SIEM estates** run deadair with `--fleet` across tenants, where the same report
  reads "blind in 3 of 12 tenants," with `--redact` for client-facing output.

## What neither does

detsema never connects to a SIEM and cannot know what is live. deadair never judges rule logic and
cannot know whether a rule is well written. Neither writes anything, neither phones home, and both
stay quiet when evidence is missing, so unknown freshness or an unreadable mapping suppresses a
finding rather than paging anyone.

Both are Apache-2.0 single binaries, and both are young and open to correction. The live half is
written up in [Detections that run but can't see]({{ '/' | relative_url }}). The static half's
reports, including a differential test against Chainsaw whose finding the maintainer confirmed and
fixed for v2.16.1, are at [big-comfy.github.io/detsema](https://big-comfy.github.io/detsema/).

<p style="margin-top:2rem"><a href="https://github.com/Big-Comfy/deadair">deadair on GitHub →</a> · <a href="https://github.com/Big-Comfy/detsema">detsema on GitHub →</a></p>
