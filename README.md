<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/banner-dark.svg">
    <img alt="deadair - SIEM detection coverage health" src="docs/assets/banner-light.svg" width="760">
  </picture>
</p>

<p align="center">
  <a href="https://github.com/Big-Comfy/deadair/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/Big-Comfy/deadair/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/Big-Comfy/deadair/releases"><img alt="Release" src="https://img.shields.io/github/v/release/Big-Comfy/deadair"></a>
  <img alt="Go 1.26" src="https://img.shields.io/badge/go-1.26-00ADD8">
  <a href="LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-blue"></a>
</p>

**deadair tells you which enabled SIEM detections cannot see the telemetry they depend on.**

It runs outside the SIEM with a read-only credential. It reads the rule inventory, reads source
freshness and schema metadata, builds a rule-to-source map, then reports coverage gaps that normal
rule execution health alone does not show.

Use it to answer three SOC questions:

- Which enabled detections are blind because their index patterns match no data, stale data, or
  empty sources?
- Which detections still run, but with reduced visibility because fields drifted or events arrive
  after the rule lookback window?
- Which log sources are being ingested but no enabled detection reads them?

No agent. No SIEM-side install. No writes to the monitored cluster. Elastic Security and
OpenSearch Security Analytics are the only supported backends today.

[Get started](#get-started) | [Findings](#findings) | [CI gates](#ci-gates) |
[Fleet and MSSP use](#fleet-and-mssp-use) | [Exporter](#exporter) |
[Supported SIEMs](#supported-siems) | [Validation](#validation) | [Docs](#docs)

## Example

This demo scans an Elastic 8.17 lab with the Elastic prebuilt rule package installed, about 500
rules enabled, and only a few seeded data streams:

<p align="center">
  <img alt="Static deadair scan output showing dead detections and unused telemetry" src="docs/assets/demo-final.svg" width="860">
</p>

`no matching source` means a rule's index patterns resolve to zero concrete indices or data streams.
For example, a rule copied from a NetFlow-enabled tenant searches `netflow-*`, but the receiving
tenant has never onboarded NetFlow. The rule stays enabled, but there is no concrete source behind the
pattern. Depending on the backend and rule settings, the run can surface as an empty search or a
missing-index warning.

In a new SIEM, this finding is usually onboarding backlog. In an established SOC, it is more often a
renamed data stream, pattern typo, removed integration, or rule copied from another environment.

Sample terminal, JSON, and HTML reports are in [docs/examples](docs/examples/).

For the longer explanation behind the check — including native Elastic overlap, ingest-lag math, and
a reproducible simulation — read [Detections that run but can't see](https://big-comfy.github.io/deadair/).

## Get started

Download a binary from the [releases page](https://github.com/Big-Comfy/deadair/releases) for
macOS, Linux, or Windows (amd64 and arm64), or install from source:

```sh
go install github.com/Big-Comfy/deadair/cmd/deadair@latest
```

Then run:

```sh
deadair setup   # print the least-privilege role and credential commands
deadair check   # verify the connection and required privileges
deadair scan    # produce the first report
```

<p align="center">
  <img alt="deadair first-run setup and check flow" src="docs/assets/onboarding.gif" width="860">
</p>

Elastic example:

```sh
export DEADAIR_ES_URL=https://es.example.internal:9200
export DEADAIR_KIBANA_URL=https://kibana.example.internal:5601
export DEADAIR_API_KEY=<read-only key>

deadair scan
deadair scan --json
deadair scan --out report.json --html-out report.html
```

OpenSearch example:

```sh
export DEADAIR_BACKEND=opensearch
export DEADAIR_OPENSEARCH_URL=https://opensearch.example.internal:9200
export DEADAIR_OPENSEARCH_USERNAME=deadair
export DEADAIR_OPENSEARCH_PASSWORD=<password>

deadair scan
```

Exit codes are stable: `0` means healthy, `1` means findings, and `2` means the scan failed.

## Findings

deadair separates detection problems from telemetry problems.

| Finding | What it means | Who usually owns it |
|---|---|---|
| no matching source (`disconnected` in JSON) | an enabled rule's index patterns match no index or data stream | detection engineering or onboarding |
| all matching sources stale or empty (`starved` in JSON) | every source the rule reads has stopped sending data or has no documents | telemetry pipeline owner |
| stale source | source has not received events within `--max-stale` | pipeline, agent, collector, or source owner |
| empty source | index or data stream exists but has zero docs | onboarding or template issue |
| missing fields | best-effort rule-declared fields are absent from source mappings | parser, integration, or content owner |
| lag blind window | events arrive after the rule's lookback margin | detection engineering and pipeline owner |
| unused telemetry | source has data, but no enabled rule reads it | detection engineering or cost owner |

Useful flags:

| Flag | Use |
|---|---|
| `--max-stale 30m` | set the quiet-period threshold for stale sources |
| `--state-file state.json` | keep scan history for volume baselines and ingest-lag checks |
| `--schema` | track `field_caps` schema drift across scans; requires `--state-file` |
| `--downtime-file downtime.json` | suppress expected maintenance windows without hiding sources |
| `--redact` | replace tenant, rule, source, pattern, and field names with stable digests |

HTML output is built into `scan`. Open the checked-in
[sample HTML report](docs/examples/sample-report.html) to inspect the full layout and findings.

## CI gates

Use `scan --rule` in detection-as-code pull requests. It checks a candidate rule against the live
environment before the rule is installed:

```sh
deadair scan --rule new-rule.json
```

Use `diff` for scheduled regression checks while you still have an existing backlog:

```sh
deadair scan --json --out today.json
deadair diff yesterday.json today.json
```

`scan --rule` fails only for the candidate rule. `diff` fails only for new dead, impaired, or
degraded findings. Both work on redacted reports because redaction is deterministic.

<p align="center">
  <img alt="deadair scan --rule and diff CI gate output" src="docs/assets/ci.gif" width="860">
</p>

## Fleet and MSSP use

`--fleet` scans more than one SIEM instance in one run. That covers MSSP client books, separate
prod/staging SIEMs, regional deployments, and post-acquisition sprawl.

```sh
deadair check --fleet fleet.json
deadair scan --fleet fleet.json
deadair serve --fleet fleet.json
```

Fleet config stores references to secrets, not the secret values:

```json
{"instances": [
  {
    "name": "acme-prod",
    "backend": "elastic",
    "es_url": "https://...",
    "kibana_url": "https://...",
    "api_key_env": "ACME_KEY"
  },
  {
    "name": "beta-corp",
    "backend": "opensearch",
    "opensearch_url": "https://...",
    "username": "deadair",
    "password_env": "BETA_PW"
  }
]}
```

Fleet scans are sequential so one deadair process does not fan out load across every customer SIEM
at once. One failed tenant is reported as failed and returns exit `2`; the successful tenants still
appear in the report. With `--state-file`, each tenant gets its own state file.

For client-facing reports or shared Prometheus, use `--redact`. Tenant names are treated as
sensitive too.

<p align="center">
  <img alt="deadair fleet scan with per-tenant summaries and cross-tenant rollups" src="docs/assets/fleet.gif" width="860">
</p>

Run the local MSSP lab when you want to exercise the operator path:

```sh
make mssp-lab
```

It boots throwaway Elastic and OpenSearch stacks, scans a five-instance fleet with working and
failing tenants, scrapes the exporter, and writes redacted artifacts under
`integration/mssp-lab-out/`.

<p align="center">
  <img alt="deadair MSSP lab showing lab context, redacted scan output, and per-instance metrics" src="docs/assets/mssp-lab.gif" width="860">
</p>

## Exporter

`deadair serve` runs scans on an interval and exposes Prometheus metrics. Scrapes read the cached
last scan, so Prometheus scrape volume does not hit the SIEM APIs.

```sh
deadair serve --interval 5m
```

By default it binds `127.0.0.1:9317`. Grafana and Alertmanager examples are in
[contrib](contrib/).

## Supported SIEMs

Only two backends are supported today:

| Backend | Version line | Status | Evidence |
|---|---|---|---|
| Elastic Security | 8.x | supported | live CI, least-privilege docs, rejected-write proof |
| OpenSearch Security Analytics | 2.x | supported | live CI, least-privilege docs, rejected-write proof |

No preview or experimental backends ship in this release. Microsoft Sentinel is the first planned
preview target. Google SecOps and other SIEMs are demand-ranked candidates. Splunk is out of
scope.

Support status terms:

| Status | Meaning |
|---|---|
| supported | backend code, credential docs, live integration proof, rejected-write proof, and stable report compatibility |
| preview | real backend proof exists, but field dogfooding is not complete |
| experimental | parser or adapter work only; no support claim |

## Validation

The supported backend claims are based on live CI against real Elastic and OpenSearch containers,
least-privilege credential docs, rejected-write tests, and the Docker-backed MSSP lab. That proves
the backend APIs and operator workflow; it does not replace field dogfooding against production
source cadence, hosted SIEM edge cases, or large real fleets.

If you want to test deadair safely, start with [Validation and dogfooding](docs/validation.md).
Use `--redact` before sharing public results. Microsoft Sentinel operators can also use the
[Sentinel design-partner issue](https://github.com/Big-Comfy/deadair/issues/3).

## Report handling

Treat reports like sensitive SOC artifacts. They name blind detections, unused telemetry, source
names, rule names, and sometimes tenant names.

- Report, HTML, and state files are written `0600` on POSIX systems.
- Credentials can come from environment variables or files. Do not pass secrets in argv.
- `--redact` keeps reports useful for sharing while hiding names behind stable digests.
- The exporter binds loopback by default. Put it behind authenticated scraping if it leaves the
  host.
- deadair has no phone-home behavior and no usage telemetry.

## Docs

- [Usage guide](docs/usage.md) - first scan, triage, CI gates, stateful checks, and fleets.
- [Best practices](docs/best-practices.md) - rollout order and alerting guidance.
- [Validation and dogfooding](docs/validation.md) - what is proven, what still needs field proof, and how to share safe results.
- [Write-up](https://big-comfy.github.io/deadair/) - why enabled rules can still lose telemetry.
- [MSSP deployment guide](docs/mssp.md) - fleet secrets, redaction, routing, retention, sizing.
- [Elastic credentials](docs/credentials/elastic.md) - least-privilege Elastic role and API key.
- [OpenSearch credentials](docs/credentials/opensearch.md) - least-privilege OpenSearch roles.
- [Architecture](docs/architecture.md) - data model, API usage, safety properties, limits.

## License

Apache-2.0. If a commercial layer ever exists, everything in this repository stays Apache-2.0.
