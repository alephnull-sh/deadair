---
name: Backend RFC
about: Propose a new SIEM backend or a material backend API change
title: "Backend RFC: "
labels: enhancement
---

## Operator need

Which backend, deployment shape, and detection-coverage problem does this address? Link public API
documentation where possible.

## Compatibility target

List the exact product versions and hosted/self-managed variants in scope. Say what is explicitly
out of scope.

## Read-only API plan

List every endpoint and HTTP method the production client would call, the minimum permissions each
call needs, and how a live test will prove representative writes are rejected. Production backend
code must not create, update, or delete monitored-SIEM objects.

## Normalized model and capability gaps

Map rules, sources, schedules, lookbacks, timestamps, schema information, and unavailable inputs to
deadair's backend/report contracts. Call out any best-effort fields or unsupported checks.

## Credential and integration proof

Describe the least-privilege credential guide, synthetic fixtures, container or hosted test path,
cleanup, supported-version matrix, and failure cases. Do not attach credentials, customer exports,
or unredacted SOC artifacts.

## Report compatibility and rollout

Describe report-schema changes, preview exit criteria, dogfood evidence, documentation, and a safe
removal or fallback plan.
