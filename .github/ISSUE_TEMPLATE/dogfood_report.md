---
name: Dogfood report
about: Share a redacted validation run from a real Elastic or OpenSearch environment
---

Thanks for testing deadair. Please share redacted details only. Reports can expose blind
detections, tenant names, source names, rule names, field names, and index patterns.

**deadair version** (`deadair version`):

**Backend and version** (Elastic / OpenSearch, x.y.z):

**Environment type** (lab, test/dev SIEM, one-shot production scan, scheduled production run, fleet):

**Command shape** (remove secrets and internal hostnames):

```sh

```

**Scale**

- enabled rules:
- total rules:
- sources:
- fleet instances, if any:
- scan duration:

**Options enabled**

- `--redact`:
- `--schema`:
- `--state-file`:
- `--downtime-file`:
- `--fleet`:

**Did the findings match reality?**

What was correct?

What was noisy or wrong?

What did deadair miss?

**Redacted excerpt**

Paste the smallest useful `--redact` excerpt. Do not paste unredacted reports.

```text

```

**Operator notes**

Were the docs clear enough to get a read-only credential approved and run the scan?

What would make you more comfortable running this continuously?
