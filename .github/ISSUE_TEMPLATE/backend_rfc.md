---
name: Backend RFC
about: Propose a new SIEM backend or a material backend API change
title: "Backend RFC: "
labels: enhancement
---

## What problem does this solve?

Name the backend and deployment model, then describe the detection-coverage problem. Link to public
API documentation where possible.

## Compatibility

Which exact product versions and hosted or self-managed variants are in scope? What is out of
scope?

## Read-only API

List every endpoint and HTTP method the production client would call, along with the minimum
permission for each call. Explain how a live test will show that representative writes are
rejected. Production code must not create, update, or delete anything in the monitored SIEM.

## Model and gaps

Map rules, sources, schedules, lookbacks, timestamps, schema information, and unavailable inputs to
deadair's backend and report contracts. Note any best-effort fields or unsupported checks.

## Credentials and live proof

Describe the least-privilege credential, synthetic fixtures, container or hosted test path,
cleanup, tested versions, and failure cases. Do not attach credentials, customer exports, or
unredacted SOC artifacts.

## Reports and fallback

Describe any report-schema changes, the tests and documentation needed, and how the change can be
removed or disabled safely.
