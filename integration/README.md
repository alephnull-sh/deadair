# Integration tests

The integration suite proves the supported backend paths against live Docker stacks:

- least-privilege credentials can scan successfully
- representative writes are rejected
- verdicts are correct on real indexed data
- schema reads and stateful checks work with the documented roles
- mixed-backend fleet scans work

These tests need Docker or a compatible container runtime.

## Elastic

```sh
make integration-up
make integration-test
make integration-down
```

The compose default is Elasticsearch and Kibana 9.4.4 with security enabled. Trusted CI runs this
same suite against 8.19.19 and 9.4.4. The suite provisions role `deadair_monitor`, creates API key
`deadair-it`, seeds live/stale/empty sources and test rules, scans with the deadair key, asserts
rejected writes, then cleans up.

## OpenSearch

```sh
make opensearch-integration-up
make opensearch-integration-test
make opensearch-integration-down
```

The compose default is OpenSearch 3.7.0 with the security plugin. Trusted CI runs the suite against
2.19.6 and 3.7.0. The suite provisions user `deadair`, maps it to
`security_analytics_read_access` and `deadair_index_monitor`, seeds detector documents as admin,
scans as the least-privilege user, and asserts rejected writes.

## Full integration pass

```sh
make integration
```

This runs Elastic, OpenSearch, and the mixed-backend fleet proof in sequence using the compose
defaults. Trusted CI runs the fleet proof with Elastic 9.4.4 and OpenSearch 3.7.0. See the
[backend support policy](../docs/support-policy.md) for the maintained major lines and the exact
tested-version source of truth.

Environment overrides:

- `ELASTIC_VERSION`
- `OPENSEARCH_VERSION`
- `DEADAIR_IT_ES_URL`
- `DEADAIR_IT_KIBANA_URL`
- `DEADAIR_IT_PASSWORD`
- `DEADAIR_IT_OPENSEARCH_URL`
- `DEADAIR_IT_OPENSEARCH_ADMIN_PASSWORD`

Defaults match the compose files. Version overrides select both Elasticsearch and Kibana for the
Elastic stack. Use versions from the trusted CI matrix when reproducing a support issue.

## MSSP lab

```sh
make mssp-lab
```

The lab starts both throwaway stacks, seeds them, runs a five-instance fleet, scrapes the exporter,
writes redacted artifacts to `integration/mssp-lab-out/`, and tears everything down.

The README and MSSP guide use [docs/assets/mssp-lab.gif](../docs/assets/mssp-lab.gif), recorded
from these generated artifacts.

Lab instances:

| Instance | Purpose |
|---|---|
| `acme-elastic` | healthy Elastic credential |
| `beta-opensearch` | healthy OpenSearch credential |
| `charlie-bad-key` | Elastic with an invalid API key |
| `delta-down` | unreachable tenant |
| `echo-bad-password` | OpenSearch with a bad password |

The lab also warms schema snapshots, changes one Elastic source, runs a second scan so schema
drift is visible, and applies an active downtime window to stale lab sources.

Generated files:

- `check.txt`
- `fleet-summary.txt`
- `fleet-baseline-redacted.json`
- `fleet-redacted.json`
- `metrics.txt`
- `downtime.json`
- generated `fleet.json`
- per-instance state files

Useful variants:

```sh
make mssp-lab
make mssp-lab-up
make mssp-lab-run
make mssp-lab-down
MSSP_LAB_OUT=/tmp/deadair-lab make mssp-lab
```

The lab validates the MSSP operator path in Docker. It does not replace dogfooding against real
client fleets.

## Notes

- Kibana can take a minute or two on first boot. The tests poll `/api/status` before failing.
- The compose passwords are for throwaway stacks only.
- Both supported backend suites run with `--schema --state-file` so field-capability permissions
  are part of the least-privilege proof.
- Do not point these tests at a cluster you care about. They seed and remove test fixtures.

## Trusted CI boundary

Live integration jobs run only on pushes to `main`, merge queues, the weekly schedule, or manual
dispatch. They do not run on the `pull_request` event, so code from an untrusted fork is never given
a live integration environment or repository secrets. Pull requests still compile and run the
secret-free unit, race, vet, formatting, static-build, module, cross-compile, and Windows checks.

## CI naming convention

CI partitions integration tests by function prefix:

- `TestElastic*`
- `TestOpenSearch*`
- `TestFleet*`

`TestMSSPLab` is intentionally separate because it writes durable lab artifacts and runs only
through `make mssp-lab`.

Any new CI integration test must use one of the CI prefixes above, or it will compile without
running in CI.
