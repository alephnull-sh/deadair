# Examples

Captured 2026-07-04 from a field trial against a live Elastic 8.17.4 docker cluster with the
full `security_detection_engine` prebuilt package installed (1,363 rules, the 520 Windows-tagged
ones enabled) and nine seeded data streams (fresh, stale, and unused). Scanned with the
least-privilege role from docs/credentials/elastic.md. Scan wall time: ~0.8s.

- [sample-scan.txt](sample-scan.txt) — terminal summary
- [sample-report.json](sample-report.json) — full `--json` report
- [sample-report.html](sample-report.html) — `--html-out` rendering

Names here are Elastic's public prebuilt rule names and generic stream names, so the samples
are unredacted. Share real reports only via `--redact`.
