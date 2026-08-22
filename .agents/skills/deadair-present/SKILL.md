---
name: deadair-present
description: Review or change deadair terminal, HTML, docs, examples, fixtures, and demo captures so operator output stays capability-aware, believable, and plainly written.
---

# Present deadair

Start with the operator decision, not the data model. Read the current
[usage guide](../../../docs/usage.md), [validation record](../../../docs/validation.md), and the
affected renderer before changing copy or layout.

## Make output match available evidence

- Lead with the gate result and the findings that caused it. Say that `GATE FAILED` means the scan
  completed and policy gated findings; reserve failure language for exit `2` errors.
- Render backend capabilities adaptively. Omit columns and sections the backend cannot populate;
  do not fill them with repeated `unavailable`, zeroes, or `not assessed` rows.
- Show uncertainty only where it changes what the operator can conclude. Name the subject, why it
  could not be assessed, and whether it affects the gate. Never use `not assessed` as a finding or
  a marketing headline by itself.
- Do not claim `healthy`, `no blind spots`, or equivalent when input resolution or a required
  assessment is incomplete. State the narrower result the evidence supports.
- Keep stable reason codes in JSON. Translate them to short, specific language in terminal and
  HTML, with the affected rule or source and the next useful piece of evidence nearby.
- Keep informational Sentinel evidence—predicate freshness, summary runtime, health records, and
  provenance—visually distinct from gated source-health findings.

## Write and design for a working SOC

Use ordinary security-operations language, concrete nouns, and varied sentence lengths. Remove
generic headings, repeated caveats, slogan-like claims, faux precision, raw enum names, and prose
that narrates the implementation. A caveat belongs beside the feature it limits, in one pass.

Prefer a clear reading order and dense evidence over a grid of equal-looking cards. Do not repeat
the same status in the headline, summary, card, and footer. Check narrow terminals, long source
names, singular/plural wording, empty sections, partial scans, and backend-specific reports.

Each supported backend needs a complete setup journey: `setup`, credential guide, `check`, `scan`,
and a clear tested boundary. Do not let the quick start imply that the first backend shown is the
only usable path.

## Build believable fixtures

- Use synthetic but organic source, rule, and field names that resemble the data they describe.
  Keep project ownership in exact hidden markers, tags, IDs, or `[lab]` labels rather than prefixing
  every operator-visible table or index with `deadair`.
- Avoid reserved built-in table names and vendor schemas the lab does not truly reproduce.
- Give each deliberate failure one main reason. Choose timestamps, rule periods, table plans, and
  predicates so a stale slice does not accidentally create a second lag or table-wide finding.
- Prove both healthy and broken paths. A demo made only of failures looks staged and does not test
  the evidence boundary.

## Refresh public artifacts last

After code and wording settle, regenerate the terminal, JSON, HTML, stills, and motion assets from
the disposable labs. Use the intended release version so producer metadata is correct. The capture
targets and sources are in [Makefile](../../../Makefile),
[the example record](../../../docs/examples/README.md), and
[docs/assets](../../../docs/assets).

Inspect the actual terminal text, JSON, full HTML page, static image, and final animation frame.
Reject stale names, old versions, leaked identifiers, blank waits, bad crops, tiny type, duplicate
findings, or a capture that exits differently from its caption. Keep the README to one or two useful
visuals. Use a linked still or controlled video when readers need pause controls; GIF playback is
not reliably controllable. Removing an embed is not permission to delete its old public asset path.

Before handoff, search public output for machine codes, generic fixture names, `not assessed`,
unsupported columns, stale preview language, and broad claims. Keep only instances that carry real
operator meaning.
