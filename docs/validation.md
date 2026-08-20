# Validation status

deadair is tested against real Elastic and OpenSearch APIs as well as unit fixtures. This page
summarizes the checks that run in the repository and the limits that still depend on each
deployment. For finding terminology and triage, see [Read the findings](usage.md#read-the-findings).

## Automated coverage

The integration matrix targets Elastic Security 8.19.19 and 9.4.4, plus OpenSearch Security
Analytics 2.19.6 and 3.7.0.

| Area | Evidence |
|---|---|
| core graph logic | unit and race tests |
| Elastic backend | live integration tests using the documented read-only role |
| OpenSearch backend | live integration tests using the documented read-only role |
| native input resolution | alias, data-stream, exclusion, empty, and unavailable outcomes |
| write safety | live tests that attempt representative writes and require the backend to reject them |
| candidate-rule checks | `scan --rule` tests, including pretty-printed JSON rules |
| fleet behavior | mixed-backend integration tests and a five-instance MSSP lab |
| reports | terminal, JSON, HTML, redacted JSON, and Prometheus output |

The MSSP lab includes healthy, failed, and unreachable tenants. It exercises partial failures,
per-instance state, schema drift, downtime suppression, redaction, and exporter labels.

## Current limits

- The version matrix does not cover every hosted service, SIEM topology, or parser convention.
- Fleet behavior is lab-tested, but production scan time and API limits depend on the number and
  size of the connected tenants.
- Low-volume and cadence checks need enough local scan history to establish a useful baseline.
- Redaction hides identifiers but does not remove sensitive counts, timing, severity, lag, or
  coverage information.
- Results are limited to the rules, sources, fields, and metadata visible to the scan credential.
  A known-good rule and source pair should be checked after changing credentials or scope.

## Verify a deployment

Create the documented read-only credential, then run:

```sh
deadair check
deadair scan --redact --json --json-out deadair-redacted.json --html-out deadair-report.html
```

When schema visibility and persistent local state are approved:

```sh
deadair scan \
  --redact \
  --schema \
  --state-file deadair-state.json \
  --json \
  --json-out deadair-redacted.json \
  --html-out deadair-report.html
```

Compare individual findings with the backend evidence. Start with one enabled rule whose expected
source is known, then check its declared input, resolved sources, document count, last-event age,
and field visibility. If that pair is wrong, resolve credential scope, space selection, or source
visibility before relying on the rest of the report.

The exporter binds to `127.0.0.1:9317` by default. Put it behind authenticated scraping before
exposing it to shared infrastructure. Review redacted output before sharing it; do not put
unredacted rule, source, field, tenant, or customer names in a public issue.
