# Examples

These files show what deadair reports look like before you point it at your own SIEM.

They were captured from a live Elastic 8.17.4 Docker lab with:

- the Elastic prebuilt detection package installed
- about 500 Windows rules enabled
- one live data stream
- one stale data stream
- one unused data stream
- one source with 45-minute ingest lag
- the least-privilege Elastic role from [credentials/elastic.md](../credentials/elastic.md)

Files:

- [sample-scan.txt](sample-scan.txt) - terminal summary
- [sample-report.json](sample-report.json) - full JSON report
- [sample-report.html](sample-report.html) - HTML rendering

The sample uses public Elastic prebuilt rule names and generic stream names, so it is not
redacted. Use `--redact` before sharing real reports outside your restricted SOC workspace.
