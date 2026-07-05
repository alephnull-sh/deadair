# Best practices

Guidance from building and field-testing the tool. The main risk with any monitor like this is
false positives: if it pages on things that are not real problems, people stop trusting it and
turn it off. Most of the recommendations below follow from avoiding that.

## Rollout order

1. **One-shot scan, human eyes.** Run `deadair scan` and read the report with the team before
   automating anything. Treat the first run as a coverage audit, not an alert feed: a mature
   deployment usually carries a real backlog (our demo cluster, with ~500 prebuilt rules
   enabled against nine live streams, carried 45). Triage severity-first like any detection-gap list — ticket what needs a
   source onboarded, fix the patterns that are typos, and disable the rules that are dead on
   purpose so they stop counting.
2. **Gate on regressions, not on absolutes.** Until the backlog is zero, `scan`'s exit code
   fails every run. Use `deadair diff yesterday.json today.json` in scheduled jobs — it exits 1
   only on *newly* dead/impaired/degraded — and `scan --rule` on PRs, which ignores pre-existing
   findings entirely.
3. **Then monitor continuously.** Start `serve` with a `--state-file`, let baselines warm up
   for at least the default 24h, wire the [contrib](../contrib/) alerts into Alertmanager, and
   only then route them anywhere that pages a human. Dead detections belong in the
   detection-engineering queue; source staleness belongs wherever the pipeline owners live —
   they are different on-call rotations in most orgs.

## Staying quiet correctly

- Declare maintenance in `--downtime-file` instead of excluding sources: exclusion hides the
  listing, downtime windows suppress findings while keeping the source visible and protecting
  its baseline from poisoned samples.
- Set `--max-stale` to fit the slowest *legitimate* cadence of your sources; if one source is
  much slower than the rest, prefer a downtime window over a global increase.
- Don't lower `--volume-warmup`, `--volume-hysteresis`, or `--volume-min-samples` below their
  defaults on day one. After a week, let `deadair tune` argue from your real variance.
- Enable `--schema` deliberately: additive field changes count as drift and will flag once per
  agent upgrade. It earns its keep where parser changes have burned you before.

## Credentials

- One key per deployment, holding only the documented role (`deadair setup` prints it). Never
  reuse an admin credential; the integration suite proves the least-privilege role suffices.
- Add `read_ilm` only if you want truncated-lookback checks; the scan degrades gracefully
  without it.
- Rotate keys like any monitoring credential; deadair reads them from env or file, so rotation
  is a secret-store update, not a config change.

## Fleets

- Mint a separate least-privilege credential per tenant. A fleet config with one shared admin
  key defeats the tool's own security model.
- Run `deadair check --fleet fleet.json` after onboarding a tenant or rotating a secret. It
  verifies rule inventory, source stats, and optional schema visibility per instance before a
  reporting run depends on them.
- Keep instance names stable: they key metrics, per-tenant state files, and diffs.
- For client-facing (MSSP) reporting, use `--redact`: tenant names, sources, rules, and fields
  all digest, and digests stay stable across runs so trends remain readable.
- Sequential scanning means fleet wall time ≈ tenants × per-scan time. Keep `serve --interval`
  comfortably above that product.
- One tenant failure exits `2` and is listed in the fleet report without hiding successful
  tenants. In exporter mode, use `deadair_instance_up` to route credential expiry or tenant
  reachability problems to the operator who owns that tenant.

For a fuller MSSP deployment shape, including secret paths, Alertmanager routing, report/state
retention, and sizing notes for 10/50/100 tenant fleets, see [mssp.md](mssp.md).

## Handling the artifacts

- Reports, HTML output, and state files are `0600` on purpose — they map detection blind spots.
  Store them like credentials; share only redacted variants outside the SOC.
- Keep the exporter on loopback unless the scrape path is authenticated (mTLS or a reverse
  proxy). Metric labels enumerate tenants and sources.
- `--insecure-skip-verify` is for lab clusters. In production, distribute the CA via
  `--ca-cert` / per-instance `ca_cert`.

## Knowing the limits

- deadair proves detections *can* see data — not that their logic is correct or their alerts
  are useful. Rule quality tools are a different job.
- `unknown` verdicts are silence by design; if too much of the estate is unknown, fix
  `@timestamp` mappings and read privileges rather than ignoring the column.
- Cross-cluster rules report as `remote_rules`; verify them by adding the remote cluster as its
  own fleet instance rather than trusting the local view.
