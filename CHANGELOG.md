# Changelog

## v0.3.3 - 2026-07-05

- Added an MSSP deployment guide covering fleet secret layout, redaction defaults,
  Alertmanager routing, report/state retention, fleet sizing, and tenant failure modes.
- Documented backend support tiers (`supported`, `preview`, `experimental`) and marked Elastic
  Security and OpenSearch Security Analytics as supported and controlled-pilot-ready for MSSPs.
- `deadair check --fleet` now prints the matching fleet scan command after a successful
  preflight, and the workflow is covered by a CLI regression test.
- Added a per-instance Prometheus alert for fleet scans where one tenant fails while others
  still report.

## v0.3.2 - 2026-07-05

- Release builds for all six platforms: macOS, Linux, and Windows on amd64 and arm64.
- Windows support hardened: ANSI color enabled only under capable consoles (Windows Terminal,
  ConEmu, or a set TERM); documented that 0600 file hardening does not apply on NTFS.
- CI now runs the unit suite on Windows and cross-compiles every release target on every push.

## v0.3.1 - 2026-07-04

First public cut.

- Elastic Security and OpenSearch Security Analytics backends; read-only by construction,
  least-privilege roles proven in CI including rejected writes.
- Rule-to-source dependency graph: dead detections (disconnected/starved), impaired detections
  (truncated lookback, missing fields, ingest-lag blind windows), unused telemetry, blast radius.
- Fleet scans across tenants and mixed backends with cross-tenant rollups; per-instance metrics.
- `scan` with CI exit codes, `--rule` candidate gating, `diff` between reports, `serve`
  Prometheus exporter, `tune` baseline suggestions, `setup` onboarding.
- Volume baselines with warmup/hysteresis, downtime windows, schema-drift tracking.
- TLS private-CA support, Kibana spaces, cross-cluster patterns as a distinct remote class.
- Reports/state 0600, full-name redaction (tenants included), loopback exporter, no telemetry.
