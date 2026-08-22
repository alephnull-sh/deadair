---
name: deadair-maintain
description: Change or review deadair backends, graph logic, reports, state, redaction, or CLI behavior without weakening its read-only evidence and compatibility contracts.
---

# Maintain deadair

Read [architecture](../../../docs/architecture.md) and the relevant code path before changing
behavior. For report work, also read the checked-in
[single-report schema](../../../schemas/report-v1.schema.json) or
[fleet-report schema](../../../schemas/fleet-report-v1.schema.json). Follow
[CONTRIBUTING.md](../../../CONTRIBUTING.md) for the test boundary.

## Keep one product model

Add backend-specific resolution and evidence to the shared graph:

```text
rule -> dependency -> concrete source -> health evidence
```

Do not create a parallel verdict model for one SIEM. Backend-native features may add dependency,
lineage, provenance, or runtime evidence, but they change a finding only when the common report
model has enough authoritative evidence.

## Preserve the evidence boundary

- Production adapters are read-only. Do not add SIEM writes, phone-home behavior, usage telemetry,
  or a broader credential merely to simplify implementation.
- A disconnected finding requires a native resolver to return an assessed empty result. An
  incompatible source is also assessed evidence. Unsupported, unavailable, remote, ambiguous, or
  partial input stays explicit and cannot be converted to dead, healthy, or recovered.
- Unknown freshness does not make a rule dead. Withhold unused-telemetry conclusions when enabled
  local input coverage is incomplete.
- Required-field findings are per concrete source and require complete evidence for every relevant
  source. Source filters must not erase the resolution evidence behind a rule verdict.
- Measure ingest lag from paired event and ingestion timestamps on the same bounded event sample.
  Retain the method, sample count, p95, and maximum.
- Keep optional evidence separate from gates unless the product contract explicitly promotes it.
  A runtime hint must not silently become source-health proof.

## Preserve compatibility and secrecy

- Treat `deadair.report.v1`, `deadair.fleet-report.v1`, existing JSON fields, reason codes, and exit
  codes as released interfaces. Prefer optional additive fields. Do not rename a machine code to
  improve human wording; translate it only in terminal and HTML presentation.
- Scope backend-specific assessment inputs to that backend's identity. Adding Sentinel mappings,
  for example, must not change an Elastic or OpenSearch assessment ID. When identity inputs change,
  retain a pinned legacy non-target-backend ID test as well as tests for the new backend input.
- Preserve both logical rule identity and backend object identity. Stable findings and lifecycle
  use the logical identity.
- When a new field can contain tenant-controlled or identifier-bearing text, cover it in keyed
  redaction, sanitized errors, report schemas, JSON tests, and HTML/terminal tests.
- Keep report, fleet, state, and key-backed output replacement atomic and `0600` on POSIX.
- Exit `0` means the configured gate passed, `1` means gated findings, and `2` means the assessment
  failed or was unsafe. Never turn exit `0` into a claim that every possible blind spot was checked.

## Verify the changed boundary

Run focused package tests while editing, then `make validate` and `git diff --check`. Run the live
backend and mixed-fleet tests when adapter, graph, state, shared report, or CLI behavior changes.
The authoritative matrix and its trust boundary are in
[the integration guide](../../../integration/README.md),
[CI](../../../.github/workflows/ci.yml), and
[integration CI](../../../.github/workflows/integration.yml).

Do not regenerate examples or publish from this skill unless the task also includes presentation
or release work.
