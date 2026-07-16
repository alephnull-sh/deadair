# Best practices

deadair is most useful when teams treat the first report as a coverage audit and later reports as
regression monitoring. If you wire every first-run finding straight to paging, people will ignore
the tool.

## Roll out in this order

1. Run one manual scan.

   ```sh
   deadair check
   deadair scan --out first-report.json --html-out first-report.html
   ```

   Review it with detection engineering and telemetry pipeline owners. Expect backlog in mature
   environments: disabled integrations, old rule packs, stale lab data, and sources that were
   never fully onboarded.

2. Clean up the obvious noise.

   Fix pattern typos. Disable rules that are intentionally out of scope. Ticket missing data
   sources. Move slow or scheduled sources into downtime windows where that is the real operating
   model.

3. Gate on changes, not the whole backlog.

   ```sh
   deadair scan --rule candidate-rule.json
   deadair diff yesterday.json today.json
   ```

   Use `scan --rule` in detection PRs. Use `diff` in scheduled jobs while the initial backlog is
   still open.

4. Add continuous monitoring.

   ```sh
   deadair serve --state-file /var/lib/deadair/state.json --interval 15m
   ```

   Let baselines warm up before routing alerts. Start with tickets or chat notifications, then
   page only for findings your team has agreed are actionable.

## Keep findings actionable

- Keep `--max-stale` close to the expected cadence of your sources. A global value that is too
  high hides real source outages.
- Use `--downtime-file` for maintenance or scheduled quiet periods. It suppresses expected
  findings and protects baselines while still showing the source in reports.
- Do not start by lowering `--volume-warmup`, `--volume-hysteresis`, or
  `--volume-min-samples`. After a week of history, run `deadair tune` and adjust from observed
  variance.
- Enable `--schema` where parser and integration changes have caused misses before. Expect a
  drift finding after legitimate package upgrades; triage it like a parser change, not a page.
- Treat `unknown` as a setup problem, not a healthy source. If many sources are unknown, fix
  `@timestamp` mappings and read privileges.

## Route to the right owners

| Signal | Good first owner |
|---|---|
| no matching source rules (`disconnected` in JSON) | detection engineering |
| all matching sources stale or empty (`starved` in JSON) | telemetry pipeline owner, with detection engineering copied |
| stale, empty, or low-volume sources | collector, forwarder, pipeline, or source-system owner |
| missing fields or schema drift | parser/integration owner and detection engineering |
| lag blind window | detection engineering and pipeline owner |
| unused telemetry | detection engineering and cost/platform owner |
| failed tenant scan | tenant onboarding or credential owner |

The finding class matters. A dead rule and a dead source are related, but they often belong to
different queues.

## Credentials

- Use one least-privilege credential per SIEM instance. `deadair setup` prints the required role.
- Do not use admin credentials. The integration suite proves the documented roles are enough and
  verifies representative writes are rejected.
- Prefer secret files for daemons, with mode `0600`, or your normal secret manager writing those
  files.
- Rotate deadair credentials like any other monitoring credential. Run `deadair check` after
  rotation.

## Fleets and MSSPs

- Use one credential per tenant. A shared admin credential defeats the safety model.
- Keep instance names stable. They key metrics, state files, baseline history, and redacted
  digests.
- Run `deadair check --fleet fleet.json` after onboarding or rotating any tenant.
- Use `--redact` for client-facing reports, shared Prometheus, demos, and support tickets.
- Size the interval from observed scan time. Fleet scans are sequential, so wall time is roughly
  the sum of tenant scan times.
- Route `deadair_instance_up == 0` to the person who owns that tenant's credential and network
  path. Do not let one unreachable tenant hide the rest of the fleet.

For a full MSSP deployment shape, see [mssp.md](mssp.md).

## Handle artifacts carefully

- Unredacted JSON, HTML reports, and state files are sensitive. They name blind rules and exposed
  telemetry gaps.
- POSIX builds write reports and state `0600`. On Windows, protect output directories with ACLs.
- Keep the exporter on loopback or behind authenticated scraping. Metric labels can reveal source
  and tenant names.
- Use `--redact` before sharing a report outside the restricted SOC workspace.
- Use `--ca-cert` for private CAs. Reserve `--insecure-skip-verify` for labs.

## Know the limits

- deadair proves a rule can see data. It does not prove the rule logic is correct.
- It does not evaluate events inline and it does not tune detections.
- Cross-cluster rules are listed as `remote_rules`. Scan the remote cluster as its own fleet
  instance if you want coverage proof.
- Supported backends are Elastic Security and OpenSearch Security Analytics only.
