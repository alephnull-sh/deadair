# Roadmap

This roadmap separates work we have committed to from ideas that still need design, evidence, and
maintainer capacity. It describes product direction, not release dates or support promises. Current
backend guarantees live in [the support policy](docs/support-policy.md).

## Committed foundation

The near-term foundation is intended to make the current product safer to change and easier to
evaluate:

- accept external pull requests behind fork-safe, credential-free validation
- validate Elastic 8.19.19 and 9.4.4 plus OpenSearch 2.19.6 and 3.7.0 in trusted live CI
- resolve native aliases, data streams, and selectors without flattening backend meaning
- add report `schema_version` and an explicit backend capability contract
- ship a credential-free demo path
- maintain contributor guidance, backend RFCs, this roadmap, and an explicit support policy
- report unsupported or unavailable backend inputs explicitly instead of treating missing evidence
  as healthy

## Directional: 31–60 days

These are candidates, not commitments. Ordering depends on evidence from the foundation and early
adopters:

- stable finding IDs and a finding lifecycle across scans
- baseline and policy controls for deciding which changes should gate
- remediation clustering and ranking
- an official GitHub Action with SARIF output
- GHCR and additional package distribution paths
- keyed HMAC redaction for controlled cross-run correlation
- signed releases with SBOM and provenance
- fleet HTML reporting

## Directional: 61–120 days

These are also candidates, not commitments:

- a public backend adapter SDK and conformance kit
- a typed dependency DAG and a Microsoft Sentinel preview
- a shared `deadair-detsema` schema and combined action workflow
- bounded tenant concurrency and per-backend API budgets
- published 10, 50, and 100 tenant benchmarks
- adopter case studies based on redacted, permission-safe evidence

Splunk remains out of scope. Other SIEM backends need a backend RFC, a real read-only integration
path, and enough design-partner evidence to justify preview work.
