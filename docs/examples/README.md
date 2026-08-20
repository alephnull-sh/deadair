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

Files:

- [sample-scan.txt](sample-scan.txt) - concise operator summary
- [sample-report.json](sample-report.json) - diagnostic report with rule patterns, matched sources, and source evidence
- [sample-report.html](sample-report.html) - browser-readable overview for human review

Start with the terminal summary, then use JSON to answer why a rule received its verdict. For
example, the first no-match finding in this sample is:

| Evidence | Value |
|---|---|
| Rule | `Lab registry persistence` |
| JSON reason | `disconnected` |
| Configured patterns | `deadair-lab-registry-*` |
| Matched sources | none |
| Lab explanation | the disposable lab intentionally does not create a matching registry source |

The finding does not mean Elasticsearch or the agent is disconnected. It means none of that rule's
configured patterns resolved to a concrete index or data stream visible to the scan credential.

Inspect the same fields in your own report with:

```sh
jq '.dead_detections[] | {name, reason, patterns, sources}' report.json
```

The sample uses synthetic lab names and contains no production data, so it is not redacted. Use
`--redact` before sharing reports from a real environment outside your restricted SOC workspace.
