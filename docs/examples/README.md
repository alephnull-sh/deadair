# Examples

These files were captured from the disposable Elastic 9.4.4 lab used by
`make record-scan-lab`. The lab creates:

- one healthy rule and source
- one rule with no matching source
- one rule whose source is stale
- one rule with a declared field missing from its source mapping
- one rule whose source has 45-minute ingest lag
- one unused source
- the least-privilege Elastic role from [credentials/elastic.md](../credentials/elastic.md)

The capture includes:

- [sample-scan.txt](sample-scan.txt) — concise operator summary
- [sample-report.json](sample-report.json) — diagnostic report with rule patterns, matched sources,
  and source evidence
- [sample-report.html](sample-report.html) — browser-readable report

The JSON and HTML record the exact deadair producer version used for the capture. Regenerate the
terminal, JSON, and HTML files together so their evidence stays comparable.

Start with the terminal summary. Use the JSON report when you need to understand a verdict. For
example, the first no-match finding contains this evidence:

| Evidence | Value |
|---|---|
| Rule | `Sysmon registry run-key modification` |
| JSON reason | `disconnected` |
| Configured patterns | `winlogbeat-sysmon-*` |
| Matched sources | none |
| Lab explanation | the disposable lab intentionally does not create the expected Sysmon source |

The finding does not mean Elasticsearch or the agent is disconnected. It means none of that rule's
configured patterns resolved to a concrete index or data stream visible to the scan credential.

Inspect the same fields in your own report with:

```sh
jq '.dead_detections[] | {name, reason, patterns, sources}' report.json
```

The source names resemble a small Elastic deployment, but the records are synthetic and contain no
production data, so this sample is not redacted. Before sharing a report from a real environment
outside your restricted SOC workspace, run the scan with `--redact` and review the result.
