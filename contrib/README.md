# contrib

This directory contains optional Prometheus, Grafana, and Alertmanager examples for
`deadair serve`.

deadair writes reports and exposes metrics. Your monitoring stack handles dashboards and alert
delivery.

Included examples:

- [grafana-dashboard.json](grafana-dashboard.json) — import it into Grafana and select your
  Prometheus datasource. Panels cover scan health, dead detections, unmapped detections, unused
  telemetry, source status, stale sources, volume z-scores, and blast radius.
- [prometheus-alerts.yml](prometheus-alerts.yml) — example alert rules. Tune `for:` windows and
  thresholds to your scan interval and environment.

Fleet users should route `DeadairInstanceScanFailing` by the `instance` label.

After a failed scan, report metrics retain the last successful values and `deadair_instance_up`
becomes `0`. `deadair_instance_last_success_timestamp_seconds` dates that retained report. The
bundled report-derived alerts require a successful current scan; scan-failure alerts remain active.

Metric labels can contain tenant and source names. Keep the exporter on loopback or behind an
authenticated scrape path. Use `serve --redact` when Prometheus is shared beyond the restricted
SOC workspace.
