# Integration tests

Live-backend proof: least-privilege scans work, verdicts are correct on real data, and the
deadair credential cannot write.

```sh
make integration-up     # docker compose: Elasticsearch + Kibana 8.17, security on
make integration-test   # Elastic tests only
make integration-down   # teardown, volumes removed
```

OpenSearch covers the same proof against a docker OpenSearch 2.x node with the security plugin
enabled: detector inventory, source stats, verdicts, least-privilege role setup, rejected writes.

```sh
make opensearch-integration-up
make opensearch-integration-test
make opensearch-integration-down
```

`make integration` runs Elastic and OpenSearch in sequence. Configuration via env (defaults match
the compose files): `DEADAIR_IT_ES_URL`, `DEADAIR_IT_KIBANA_URL`, `DEADAIR_IT_PASSWORD`,
`ELASTIC_VERSION`, `DEADAIR_IT_OPENSEARCH_URL`, `DEADAIR_IT_OPENSEARCH_ADMIN_PASSWORD`,
`OPENSEARCH_VERSION`.

Notes:

- Kibana takes a minute or two on first boot; the tests poll `/api/status` for
  up to 4 minutes before failing.
- The default stack is Elastic/Kibana 8.17.4. CI runs the integration job through
  the `ELASTIC_VERSION` matrix so new 8.x pins can be added without changing the
  compose file.
- The Elastic suite provisions role `deadair_monitor` and API key `deadair-it`, seeds
  `logs-deadairtest-default` / `deadairtest-stale` / `deadairtest-empty` plus
  three detection rules, and removes all of it afterwards. Don't point it at a
  cluster you care about; it is written for the throwaway compose stack.
- The OpenSearch suite runs the security plugin with HTTP TLS disabled inside the throwaway
  container, provisions user `deadair`, maps it to `security_analytics_read_access` plus
  `deadair_index_monitor`, seeds detector documents as admin, then scans and attempts writes with
  the least-privilege user.
- Both live scans run with `--schema --state-file` so `field_caps` permissions are covered by the
  least-privilege proof.
- The password in the compose file is for the throwaway stack only.

## Naming convention (CI partitioning)

CI and the Makefile partition suites by prefix: `-run TestElastic` and `-run TestOpenSearch`
boot one backend's stack each; `-run TestFleet` (make fleet-integration) boots both for the
cross-backend fleet proof. **Every integration test function must be named `TestElastic*`,
`TestOpenSearch*`, or `TestFleet*`** — any other prefix compiles but silently never runs.
