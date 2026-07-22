# Examples

These files show what deadair reports look like before you point it at your own SIEM.

For a reproducible report generated entirely from the installed binary, run:

```sh
deadair demo
deadair demo --out demo-report.json --html-out demo-report.html
```

That embedded demo is deterministic and makes no network calls. The checked-in `sample-*` files
below remain a separate live-backend artifact.

They were captured from a live Elastic 8.17.4 Docker lab with:

- the Elastic prebuilt detection package installed
- about 500 Windows rules enabled
- one live data stream
- one stale data stream
- one unused data stream
- one source with 45-minute ingest lag
- the least-privilege Elastic role from [credentials/elastic.md](../credentials/elastic.md)

Files:

- [sample-scan.txt](sample-scan.txt) - concise operator summary
- [sample-report.json](sample-report.json) - diagnostic report with rule patterns, matched sources, and source evidence
- [sample-report.html](sample-report.html) - shareable overview for human review

Start with the terminal summary, then use JSON to answer why a rule received its verdict. For
example, the first no-match finding in this sample is:

| Evidence | Value |
|---|---|
| Rule | `Persistence via WMI Standard Registry Provider` |
| JSON reason | `disconnected` |
| Configured patterns | `logs-endpoint.events.registry-*`, `endgame-*` |
| Matched sources | none |
| Lab explanation | no Endpoint registry or Endgame source was seeded |

The finding does not mean Elasticsearch or the agent is disconnected. It means none of that rule's
configured patterns resolved to a concrete index or data stream visible to the scan credential.

Inspect the same fields in your own report with:

```sh
jq '.dead_detections[] | {name, reason, patterns, sources}' report.json
```

The sample uses public Elastic prebuilt rule names and generic stream names, so it is not
redacted. Use `--redact` before sharing real reports outside your restricted SOC workspace.

The JSON sample has been wrapped in the v1 additive report contract for schema validation. Its
capability block marks source resolution `partial` because the underlying live capture predates
backend-native resolution evidence; current scans populate `input_resolutions` directly.
