# contrib

This directory contains optional Prometheus, Grafana, and Alertmanager examples for
`deadair serve`.

deadair itself does not ship a UI or alert delivery system. It exposes metrics; your monitoring
stack handles dashboards and routing.

Files:

- [grafana-dashboard.json](grafana-dashboard.json) - import into Grafana and select your
  Prometheus datasource. Panels cover scan health, dead detections, unmapped detections, unused
  telemetry, source status, stale sources, volume z-scores, and blast radius.
- [prometheus-alerts.yml](prometheus-alerts.yml) - example alert rules. Tune `for:` windows and
  thresholds to your scan interval and environment.

Fleet users should route `DeadairInstanceScanFailing` by the `instance` label.

Metric labels can contain tenant and source names. Keep the exporter on loopback or behind an
authenticated scrape path. Use `serve --redact` when Prometheus is shared beyond the restricted
SOC workspace.
