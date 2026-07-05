# Least-privilege credentials — Elastic

deadair needs exactly two capabilities: read detection-rule metadata (Kibana) and read index
stats/freshness (Elasticsearch). Nothing here grants a write.

> Status: **proven** against live Elastic 8.17.4 on 2026-07-04 by the integration suite
> (`make integration`, [integration/](../../integration/README.md)): scan succeeds with a key
> carrying only this role, and every attempted write (indexing, index create/delete, data-stream
> delete, rule create, API-key create) is rejected with 403. Re-proven in CI on every push.

## 1. Create a role

```jsonc
// POST _security/role/deadair_monitor
{
  "cluster": ["monitor"],                    // _data_stream/_stats, _cat/indices
  "indices": [
    {
      "names": ["*"],
      "privileges": ["monitor", "view_index_metadata", "read"]  // read: max(@timestamp) agg only
    }
  ],
  "applications": [
    {
      "application": "kibana-.kibana",
      // Detections API, read-only. feature_siem is the pre-8.17 privilege id,
      // feature_siemV2 the granular replacement; granting both covers 8.x.
      "privileges": ["feature_siem.read", "feature_siemV2.read"],
      "resources": ["space:default"]
    }
  ]
}
```

Scope `indices.names` tighter than `"*"` if your telemetry lives under known patterns
(e.g. `logs-*`, `winlogbeat-*`) — deadair only reports on what it can see.

Optional: add `read_ilm` to `cluster` to enable truncated-lookback checks (rules querying
further back than ILM retention keeps data). Without it, retention stays unknown and those
findings are suppressed — the scan still works.

## 2. Create an API key bound to that role

```jsonc
// POST _security/api_key
{
  "name": "deadair",
  "role_descriptors": { "deadair_monitor": { /* role body from above */ } }
}
```

Use the `encoded` value from the response:

```sh
export DEADAIR_API_KEY=<encoded>
# or, better for daemons:
echo -n '<encoded>' > /etc/deadair/api-key && chmod 0600 /etc/deadair/api-key
deadair serve --api-key-file /etc/deadair/api-key
```

## Notes

- The detection engine and Detections API ship in the **free** default distribution (verified
  2026-07-03).
- deadair never uses: document writes, index management, cluster admin, or any Kibana write
  privilege. If an audit shows it asking for more than the role above, that's a bug — report it.
