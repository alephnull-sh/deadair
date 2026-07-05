# contrib

Grafana and Alertmanager artifacts for `deadair serve`; deadair itself ships no dashboards or
alerting.

- [grafana-dashboard.json](grafana-dashboard.json) — import, select your Prometheus datasource.
  Panels: scan health, dead/unmapped detections, unused telemetry, sources by status, stalest
  sources, volume z-scores, blast radius.
- [prometheus-alerts.yml](prometheus-alerts.yml) — example rules; tune `for:` to your
  `--interval` and thresholds to your environment. Fleet users should route
  `DeadairInstanceScanFailing` by the `instance` label.

Metric labels contain source names. Keep the exporter on loopback or behind an authenticated
scrape path; use `serve --redact` if your Prometheus is shared beyond the SOC.
